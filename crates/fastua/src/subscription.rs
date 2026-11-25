//! Subscriptions and MonitoredItems (Part 4 §5.12, §5.13).
//!
//! A session owns its subscriptions. The thread of the connection the session
//! is bound to drives them: it sleeps in `ppoll` until the next sampling or
//! publishing deadline, samples the items that are due, and answers queued
//! Publish requests. The session mutex is only contended when another
//! connection transfers a subscription.
//!
//! Hot path costs: an item whose value did not change since the last sample
//! costs one atomic load (the cell's change counter). A changed numeric value
//! is copied out of the seqlock into a preallocated ring; publishing encodes
//! the ring straight into a reused buffer. Steady state allocates nothing for
//! numeric values: queues grow once to their size, NotificationMessage and
//! retransmission buffers are recycled.

use crate::address_space::{encode_server_status, AddressSpace, NodeKind, ValueSource, ACCESS_READ};
use crate::codec::Writer;
use crate::events::{EventFilter, EventItem};
use crate::server::Limits;
use crate::types::*;
use crate::value::{self, ValueCell, ENCODED_MAX, NO_SOURCE_TS};
use std::collections::VecDeque;
use std::sync::Arc;

pub const MODE_DISABLED: u32 = 0;
pub const MODE_SAMPLING: u32 = 1;
pub const MODE_REPORTING: u32 = 2;

/// DataChangeTrigger (Part 4 §7.22.2).
pub const TRIGGER_STATUS: u32 = 0;
pub const TRIGGER_STATUS_VALUE: u32 = 1;
pub const TRIGGER_STATUS_VALUE_TIMESTAMP: u32 = 2;

/// StatusCode InfoType = DataValue | Overflow (Part 4 §7.39.1).
const OVERFLOW_BITS: u32 = 0x0480;

/// Monotonic clock in nanoseconds (vDSO, no syscall).
#[inline]
#[allow(clippy::unnecessary_cast)] // time_t / c_long are not i64 on every target
pub fn mono_ns() -> u64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer; CLOCK_MONOTONIC always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

#[inline]
fn ms_to_ns(ms: f64) -> u64 {
    (ms * 1e6) as u64
}

#[inline]
fn next_seq(s: u32) -> u32 {
    s.checked_add(1).unwrap_or(1)
}

pub mod codes {
    pub const BAD_SUBSCRIPTION_ID_INVALID: u32 = 0x8028_0000;
    pub const BAD_NO_SUBSCRIPTION: u32 = 0x8079_0000;
    pub const BAD_TOO_MANY_SUBSCRIPTIONS: u32 = 0x8077_0000;
    pub const BAD_TOO_MANY_PUBLISH_REQUESTS: u32 = 0x8078_0000;
    pub const BAD_MESSAGE_NOT_AVAILABLE: u32 = 0x807B_0000;
    pub const BAD_SEQUENCE_NUMBER_UNKNOWN: u32 = 0x807A_0000;
    pub const BAD_MONITORED_ITEM_ID_INVALID: u32 = 0x8042_0000;
    pub const BAD_MONITORING_MODE_INVALID: u32 = 0x8041_0000;
    pub const BAD_MONITORED_ITEM_FILTER_INVALID: u32 = 0x8043_0000;
    pub const BAD_MONITORED_ITEM_FILTER_UNSUPPORTED: u32 = 0x8044_0000;
    pub const BAD_FILTER_NOT_ALLOWED: u32 = 0x8045_0000;
    pub const BAD_DEADBAND_FILTER_INVALID: u32 = 0x808E_0000;
    pub const BAD_TOO_MANY_MONITORED_ITEMS: u32 = 0x80DB_0000;
    pub const GOOD_SUBSCRIPTION_TRANSFERRED: u32 = 0x002D_0000;
}
use codes::*;

// ---------------------------------------------------------------- items

/// Where an item's samples come from.
enum Source {
    /// A configured variable: change counter + seqlock.
    Cell(Arc<ValueCell>),
    /// Server_ServerStatus_CurrentTime.
    Time,
    /// Server_ServerStatus.
    Status,
    /// A value that never changes (other attributes, constant variables).
    Fixed(Variant),
    /// The node disappeared in a configuration reload.
    Gone,
}

const TAG_BITS: u8 = 0;
const TAG_VAR: u8 = 1;
const TAG_NONE: u8 = 2;

/// One queued sample: 32 bytes, `Copy`. Variable-length values (TAG_VAR)
/// keep their payload in the queue's side buffer.
#[derive(Clone, Copy)]
struct Entry {
    bits: u64,
    src: i64,
    srv: i64,
    status: u32,
    tag: u8,
}

/// Sample queue. A single entry (the default queue size of 1) stays inline
/// in the item: no separate buffer, no extra cache line per notification.
/// Invariant: `one` is only used while `many` is empty. The boxes keep the
/// rarely used buffers at 8 bytes each in the item.
#[allow(clippy::box_collection)]
struct Queue {
    one: Entry,
    has_one: bool,
    many: Option<Box<VecDeque<Entry>>>,
    /// Payloads of the TAG_VAR entries, in queue order.
    vars: Option<Box<VecDeque<Variant>>>,
}

impl Queue {
    fn new() -> Queue {
        Queue {
            one: Entry { bits: 0, src: 0, srv: 0, status: 0, tag: TAG_NONE },
            has_one: false,
            many: None,
            vars: None,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.has_one as usize + self.many.as_ref().map_or(0, |m| m.len())
    }

    #[inline]
    fn is_empty(&self) -> bool {
        !self.has_one && self.many.as_ref().is_none_or(|m| m.is_empty())
    }

    #[inline]
    fn push_back(&mut self, e: Entry, var: Option<Variant>) {
        if let Some(v) = var {
            self.vars.get_or_insert_with(Default::default).push_back(v);
        }
        if self.is_empty() {
            self.one = e;
            self.has_one = true;
        } else {
            let m = self.many.get_or_insert_with(|| Box::new(VecDeque::with_capacity(4)));
            if self.has_one {
                m.push_back(self.one);
                self.has_one = false;
            }
            m.push_back(e);
        }
    }

    #[inline]
    fn pop_front(&mut self) -> Option<Entry> {
        let e = if self.has_one {
            self.has_one = false;
            self.one
        } else {
            self.many.as_mut()?.pop_front()?
        };
        if e.tag == TAG_VAR {
            self.vars.as_mut().and_then(|v| v.pop_front());
        }
        Some(e)
    }

    #[inline]
    fn pop_back(&mut self) -> Option<Entry> {
        let e = if self.has_one {
            self.has_one = false;
            self.one
        } else {
            self.many.as_mut()?.pop_back()?
        };
        if e.tag == TAG_VAR {
            self.vars.as_mut().and_then(|v| v.pop_back());
        }
        Some(e)
    }

    #[inline]
    fn front(&self) -> Option<&Entry> {
        if self.has_one {
            Some(&self.one)
        } else {
            self.many.as_ref()?.front()
        }
    }

    /// Payload of the front entry when it is a TAG_VAR one.
    fn front_var(&self) -> Option<&Variant> {
        self.vars.as_ref()?.front()
    }

    #[inline]
    fn front_mut(&mut self) -> Option<&mut Entry> {
        if self.has_one {
            Some(&mut self.one)
        } else {
            self.many.as_mut()?.front_mut()
        }
    }

    fn clear(&mut self) {
        self.has_one = false;
        if let Some(m) = &mut self.many {
            m.clear();
        }
        if let Some(v) = &mut self.vars {
            v.clear();
        }
    }
}

/// Parsed DataChangeFilter (absent = StatusValue, no deadband).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Filter {
    pub trigger: u32,
    /// Absolute deadband, 0 = none.
    pub deadband: f64,
}

impl Default for Filter {
    fn default() -> Self {
        Filter { trigger: TRIGGER_STATUS_VALUE, deadband: 0.0 }
    }
}

/// What CreateMonitoredItems / ModifyMonitoredItems ask for.
pub struct ItemParams {
    pub client_handle: u32,
    pub sampling_ms: f64,
    pub filter: Filter,
    /// Percent deadband: `filter.deadband` is a percentage of the EURange.
    pub percent_deadband: bool,
    pub filter_present: bool,
    pub queue_size: u32,
    pub discard_oldest: bool,
}

/// Item data the sampling and publishing paths do not touch.
struct Cold {
    node: NodeId,
    attribute: u32,
    /// UserAccessLevel depends on the session's rights.
    can_write: bool,
    /// Last reported variable-length value.
    last_var: Option<Variant>,
    /// Items triggered by this one (SetTriggering).
    links: Vec<u32>,
    /// Percent deadband (0 = none), recomputed when the EURange changes.
    percent: f64,
    /// NumericRange of the reported value (`None` = whole value).
    range: Option<(usize, usize)>,
}

pub struct Item {
    pub id: u32,
    pub client_handle: u32,
    pub mode: u32,
    cold: Box<Cold>,
    /// `cold.links` is not empty.
    linked: bool,
    source: Source,
    kind: u8,
    size: u8,
    ts_src: bool,
    ts_srv: bool,
    pub sampling_ms: f64,
    group: usize,
    pub queue_size: usize,
    discard_oldest: bool,
    filter: Filter,
    /// Something has been sampled since creation / re-enable.
    sampled: bool,
    last_seq: u32,
    last_status: u32,
    last_bits: u64,
    last_src: i64,
    queue: Queue,
    /// In the subscription's `dirty` list.
    dirty: bool,
}

impl Item {
    /// Samples the source; queues the value if the filter says it changed.
    /// Returns true when something was queued.
    #[inline]
    fn sample(&mut self, space: Option<&AddressSpace>) -> bool {
        // Numeric cells: everything inline, no Variant.
        if let (Source::Cell(c), true) = (&self.source, self.size != 0) {
            let r = c.raw();
            if self.sampled && r.seq == self.last_seq {
                return false;
            }
            self.last_seq = r.seq;
            if self.sampled && !self.changed_bits(r.bits, r.status, r.source_ts) {
                return false;
            }
            self.sampled = true;
            self.last_bits = r.bits;
            self.last_status = r.status;
            self.last_src = r.source_ts;
            self.push(
                Entry { bits: r.bits, src: r.source_ts, srv: r.server_ts, status: r.status, tag: TAG_BITS },
                None,
            );
            return true;
        }
        self.sample_other(space)
    }

    #[inline(never)]
    fn sample_other(&mut self, space: Option<&AddressSpace>) -> bool {
        match &self.source {
            Source::Cell(c) => {
                let seq = c.version();
                if self.sampled && seq == self.last_seq {
                    return false;
                }
                let s = c.read();
                self.last_seq = seq;
                self.offer(s.value, s.status, s.source_ts, s.server_ts)
            }
            Source::Time => {
                let now = now_ticks();
                self.offer(Variant::DateTime(now), status::GOOD, now, now)
            }
            Source::Status => {
                let Some(space) = space else { return false };
                let now = now_ticks();
                self.offer(encode_server_status(&space.info), status::GOOD, now, now)
            }
            Source::Fixed(v) => {
                if self.sampled {
                    return false;
                }
                let v = v.clone();
                let src = if self.cold.attribute == crate::services::attr::VALUE { now_ticks() } else { NO_SOURCE_TS };
                self.offer(v, status::GOOD, src, now_ticks())
            }
            Source::Gone => {
                if self.sampled && self.last_status == status::BAD_NODE_ID_UNKNOWN {
                    return false;
                }
                self.sampled = true;
                self.last_status = status::BAD_NODE_ID_UNKNOWN;
                self.cold.last_var = None;
                let now = now_ticks();
                let e =
                    Entry { bits: 0, src: NO_SOURCE_TS, srv: now, status: status::BAD_NODE_ID_UNKNOWN, tag: TAG_NONE };
                self.push(e, None);
                true
            }
        }
    }

    #[inline]
    fn changed_bits(&self, bits: u64, st: u32, src: i64) -> bool {
        if st != self.last_status {
            return true;
        }
        match self.filter.trigger {
            TRIGGER_STATUS => false,
            t => {
                let value_changed = if self.filter.deadband > 0.0 {
                    match (value::bits_as_f64(self.kind, bits), value::bits_as_f64(self.kind, self.last_bits)) {
                        (Some(a), Some(b)) => (a - b).abs() > self.filter.deadband,
                        _ => bits != self.last_bits,
                    }
                } else {
                    bits != self.last_bits
                };
                value_changed || (t == TRIGGER_STATUS_VALUE_TIMESTAMP && src != self.last_src)
            }
        }
    }

    /// Variable-length / generated values: compare and queue.
    fn offer(&mut self, mut v: Variant, mut st: u32, src: i64, srv: i64) -> bool {
        if let Some(range) = self.cold.range {
            match crate::services::apply_range(&v, range) {
                Ok(x) => v = x,
                Err(code) => (v, st) = (Variant::Empty, code),
            }
        }
        if self.sampled {
            let same_status = st == self.last_status;
            let changed = match self.filter.trigger {
                TRIGGER_STATUS => !same_status,
                t => {
                    let value_changed = match (&self.cold.last_var, self.filter.deadband > 0.0) {
                        (Some(last), true) => match (value::variant_as_f64(&v), value::variant_as_f64(last)) {
                            (Some(a), Some(b)) => (a - b).abs() > self.filter.deadband,
                            _ => *last != v,
                        },
                        (Some(last), false) => *last != v,
                        (None, _) => true,
                    };
                    !same_status || value_changed || (t == TRIGGER_STATUS_VALUE_TIMESTAMP && src != self.last_src)
                }
            };
            if !changed {
                return false;
            }
        }
        self.sampled = true;
        self.last_status = st;
        self.last_src = src;
        self.cold.last_var = Some(v.clone());
        self.push(Entry { bits: 0, src, srv, status: st, tag: TAG_VAR }, Some(v));
        true
    }

    /// Queues a sample, applying the overflow rules (Part 4 §5.12.1.5).
    #[inline(always)]
    fn push(&mut self, e: Entry, var: Option<Variant>) {
        if self.queue_size == 1 && var.is_none() && self.queue.many.is_none() && self.queue.one.tag != TAG_VAR {
            // Default queue of one: replace in place.
            self.queue.one = e;
            self.queue.has_one = true;
            return;
        }
        self.push_slow(e, var)
    }

    #[inline(never)]
    fn push_slow(&mut self, mut e: Entry, var: Option<Variant>) {
        if self.queue.len() >= self.queue_size {
            let flag = self.queue_size > 1;
            if self.discard_oldest {
                self.queue.pop_front();
                if flag {
                    if let Some(f) = self.queue.front_mut() {
                        f.status |= OVERFLOW_BITS;
                    }
                }
            } else {
                self.queue.pop_back();
                if flag {
                    e.status |= OVERFLOW_BITS;
                }
            }
        }
        self.queue.push_back(e, var);
    }

    /// Encodes `clientHandle | DataValue` of one queued sample (`var`: the
    /// payload of a TAG_VAR entry).
    #[inline]
    fn write_entry(&self, w: &mut Writer, e: &Entry, var: Option<&Variant>) {
        w.u32(self.client_handle);
        match (e.tag, var) {
            (TAG_BITS, _) => {
                let mut buf = [0u8; ENCODED_MAX];
                let n = value::encode_raw(
                    self.kind,
                    self.size,
                    e.bits,
                    e.status,
                    e.src,
                    e.srv,
                    self.ts_src,
                    self.ts_srv,
                    &mut buf,
                );
                w.raw_prefix(&buf, n);
            }
            (TAG_VAR, Some(v)) => {
                let bad = e.status != status::GOOD;
                let src = self.ts_src && e.src != NO_SOURCE_TS;
                w.u8(0x01 | (bad as u8) << 1 | (src as u8) << 2 | (self.ts_srv as u8) << 3);
                w.variant(v);
                if bad {
                    w.u32(e.status);
                }
                if src {
                    w.i64(e.src);
                }
                if self.ts_srv {
                    w.i64(e.srv);
                }
            }
            _ => {
                w.u8(0x02 | (self.ts_srv as u8) << 3);
                w.u32(e.status);
                if self.ts_srv {
                    w.i64(e.srv);
                }
            }
        }
    }
}

/// Resolves what an item samples. `Err` is the per-item status code.
/// Event items need an Object whose EventNotifier has SubscribeToEvents.
fn check_notifier(space: &AddressSpace, node: &NodeId) -> Result<(), u32> {
    let n = space.get(node).ok_or(status::BAD_NODE_ID_UNKNOWN)?;
    match n.kind {
        NodeKind::Object { event_notifier } if event_notifier & 1 != 0 => Ok(()),
        NodeKind::Object { .. } => Err(BAD_FILTER_NOT_ALLOWED),
        _ => Err(status::BAD_ATTRIBUTE_ID_INVALID),
    }
}

/// Event queues hold at least two entries (an overflow event and the
/// newest event); 0 asks for the server default.
fn event_queue_size(l: &Limits, requested: u32) -> usize {
    let max = l.max_queue_size.max(2) as usize;
    match requested {
        0 => 1000.min(max),
        q => (q as usize).clamp(2, max),
    }
}

/// Percent deadband (Part 8, §5.3.2.2): a share of the EURange span.
fn percent_to_absolute(percent: f64, (low, high): (f64, f64)) -> f64 {
    percent / 100.0 * (high - low)
}

fn resolve(space: &AddressSpace, node: &NodeId, attribute: u32, can_write: bool) -> Result<(Source, u8, u8), u32> {
    use crate::services::attr;
    let n = space.get(node).ok_or(status::BAD_NODE_ID_UNKNOWN)?;
    if attribute == attr::VALUE {
        let NodeKind::Variable { value, access, .. } = &n.kind else {
            return Err(status::BAD_ATTRIBUTE_ID_INVALID);
        };
        if access & ACCESS_READ == 0 {
            return Err(status::BAD_NOT_READABLE);
        }
        return Ok(match value {
            ValueSource::Cell(c) => (Source::Cell(c.clone()), c.kind(), c.inline_size()),
            ValueSource::Static(v) => (Source::Fixed(v.clone()), 0, 0),
            ValueSource::CurrentTime => (Source::Time, 0, 0),
            ValueSource::ServerStatus => (Source::Status, 0, 0),
        });
    }
    // Other attributes do not change while the node exists: read once.
    let v = crate::services::attribute_value(n, attribute, can_write).ok_or(status::BAD_ATTRIBUTE_ID_INVALID)?;
    Ok((Source::Fixed(v), 0, 0))
}

// ---------------------------------------------------------------- subscriptions

/// Items sharing a sampling interval.
struct Group {
    interval_ns: u64,
    next: u64,
    items: Vec<Hot>,
    /// `items` sorted by change stamp, cut into runs of one stamp each.
    blocks: Vec<Block>,
    /// `items[always..]` have no cell: sampled on every pass.
    always: usize,
    /// `items` changed since `blocks` was built.
    stale: bool,
}

/// Items of a group whose cells share one change stamp.
struct Block {
    stamp: &'static std::sync::atomic::AtomicU32,
    /// Stamp seen at the last pass; `u64::MAX` = scan unconditionally.
    seen: u64,
    start: u32,
    end: u32,
}

impl Group {
    fn new(interval_ns: u64, next: u64, items: Vec<Hot>) -> Group {
        Group { interval_ns, next, items, blocks: Vec::new(), always: 0, stale: true }
    }

    /// Sorts the items by stamp and rebuilds the block runs (after items
    /// were added, moved or rebound; never in the steady state).
    #[cold]
    fn reindex(&mut self) {
        let key = |h: &Hot| h.cell.as_ref().map_or(usize::MAX, |c| c.stamp() as *const _ as usize);
        self.items.sort_unstable_by_key(key);
        self.blocks.clear();
        self.always = self.items.len();
        let mut i = 0;
        while i < self.items.len() {
            let Some(c) = &self.items[i].cell else {
                self.always = i;
                break;
            };
            let stamp = c.stamp();
            let start = i;
            while i < self.items.len() && self.items[i].cell.as_ref().is_some_and(|c| std::ptr::eq(c.stamp(), stamp)) {
                i += 1;
            }
            self.blocks.push(Block { stamp, seen: u64::MAX, start: start as u32, end: i as u32 });
        }
        self.stale = false;
    }
}

/// What a sampling pass touches for one item: 16 contiguous bytes, so a pass
/// over unchanged values reads this array and each cell's change counter,
/// never the (large) item.
struct Hot {
    cell: Option<Arc<ValueCell>>,
    /// Change counter seen at the last pass (odd = sample unconditionally).
    seen: u32,
    slot: u32,
}

impl Hot {
    fn new(slot: u32, source: &Source) -> Hot {
        let cell = match source {
            Source::Cell(c) => Some(c.clone()),
            _ => None,
        };
        Hot { cell, seen: 1, slot }
    }
}

/// Publishing parameters as revised by the server.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SubParams {
    pub interval_ms: f64,
    pub lifetime: u32,
    pub keepalive: u32,
    pub max_notifications: u32,
    pub priority: u8,
}

impl SubParams {
    /// Part 4 §5.13.2.2 revision rules.
    pub fn revise(
        l: &Limits,
        interval_ms: f64,
        lifetime: u32,
        keepalive: u32,
        max_notifications: u32,
        priority: u8,
    ) -> SubParams {
        let interval_ms = if interval_ms.is_finite() && interval_ms > l.min_publishing_interval_ms {
            interval_ms.min(l.max_publishing_interval_ms)
        } else {
            l.min_publishing_interval_ms
        };
        let keepalive = keepalive.clamp(1, l.max_keep_alive_count);
        // The lifetime must be at least three keep-alive periods.
        let lifetime =
            lifetime.max(keepalive.saturating_mul(3)).min(l.max_lifetime_count.max(keepalive.saturating_mul(3)));
        let cap = l.max_notifications_per_publish;
        let max_notifications = if max_notifications == 0 || max_notifications > cap { cap } else { max_notifications };
        SubParams { interval_ms, lifetime, keepalive, max_notifications, priority }
    }
}

pub struct Subscription {
    pub id: u32,
    pub params: SubParams,
    interval_ns: u64,
    pub publishing_enabled: bool,
    next_publish: u64,
    keepalive_counter: u32,
    lifetime_counter: u32,
    message_sent: bool,
    /// A message (data or keep-alive) is due and waits for a Publish request.
    pending: bool,
    /// Sequence number of the next NotificationMessage.
    seq: u32,
    items: Vec<Option<Item>>,
    free: Vec<u32>,
    by_id: FxHashMap<u32, u32>,
    next_item_id: u32,
    groups: Vec<Group>,
    /// Slots with queued samples to report, in order.
    dirty: Vec<u32>,
    links: usize,
    /// Event monitored items (EventNotifier attribute + EventFilter).
    events: Vec<EventItem>,
    retransmit: VecDeque<Sent>,
    pool: Vec<Vec<u8>>,
    generation: u64,
}

impl Subscription {
    pub fn new(id: u32, params: SubParams, enabled: bool, now: u64) -> Subscription {
        let interval_ns = ms_to_ns(params.interval_ms);
        Subscription {
            id,
            params,
            interval_ns,
            publishing_enabled: enabled,
            next_publish: now + interval_ns,
            keepalive_counter: 0,
            lifetime_counter: 0,
            message_sent: false,
            pending: false,
            seq: 1,
            items: Vec::new(),
            free: Vec::new(),
            by_id: FxHashMap::default(),
            next_item_id: 1,
            groups: Vec::new(),
            dirty: Vec::new(),
            links: 0,
            events: Vec::new(),
            retransmit: VecDeque::new(),
            pool: Vec::new(),
            generation: 0,
        }
    }

    pub fn modify(&mut self, params: SubParams, now: u64) {
        self.params = params;
        self.interval_ns = ms_to_ns(params.interval_ms);
        self.next_publish = now + self.interval_ns;
        self.lifetime_counter = 0;
    }

    /// Lifetime in milliseconds (orphan expiry).
    pub fn lifetime_ms(&self) -> f64 {
        self.params.interval_ms * self.params.lifetime as f64
    }

    /// Sequence number of the next NotificationMessage.
    pub fn sequence(&self) -> u32 {
        self.seq
    }

    pub fn item_count(&self) -> usize {
        self.by_id.len() + self.events.len()
    }

    fn event_index(&self, id: u32) -> Option<usize> {
        self.events.iter().position(|e| e.id == id)
    }

    /// Event items have something to report.
    #[inline]
    fn events_ready(&self) -> bool {
        !self.events.is_empty() && self.events.iter().any(|e| e.reportable())
    }

    /// Something to put in the next NotificationMessage.
    #[inline]
    fn has_notifications(&self) -> bool {
        !self.dirty.is_empty() || self.events_ready()
    }

    /// CreateMonitoredItems for an event item. Returns (id, revised queue size).
    pub fn create_event_item(
        &mut self,
        l: &Limits,
        space: &AddressSpace,
        node: NodeId,
        mode: u32,
        p: &ItemParams,
        filter: EventFilter,
    ) -> Result<(u32, u32), u32> {
        if mode > MODE_REPORTING {
            return Err(BAD_MONITORING_MODE_INVALID);
        }
        if self.item_count() >= l.max_monitored_items_per_subscription {
            return Err(BAD_TOO_MANY_MONITORED_ITEMS);
        }
        check_notifier(space, &node)?;
        let queue_size = event_queue_size(l, p.queue_size);
        let id = self.next_item_id;
        self.next_item_id = self.next_item_id.checked_add(1).unwrap_or(1);
        let bus = space.events.clone();
        self.events.push(EventItem::new(id, p.client_handle, mode, node, filter, queue_size, p.discard_oldest, bus));
        Ok((id, queue_size as u32))
    }

    /// ModifyMonitoredItems for an event item; `filter` replaces the old one.
    pub fn modify_event_item(
        &mut self,
        l: &Limits,
        id: u32,
        p: &ItemParams,
        filter: Option<EventFilter>,
    ) -> Result<u32, u32> {
        let i = self.event_index(id).ok_or(BAD_MONITORED_ITEM_ID_INVALID)?;
        let e = &mut self.events[i];
        let Some(filter) = filter else {
            return Err(BAD_MONITORED_ITEM_FILTER_INVALID);
        };
        let queue_size = event_queue_size(l, p.queue_size);
        e.client_handle = p.client_handle;
        e.filter = filter;
        e.resize(queue_size, p.discard_oldest);
        Ok(queue_size as u32)
    }

    /// The item is an event item.
    pub fn is_event_item(&self, id: u32) -> bool {
        self.event_index(id).is_some()
    }

    /// (server handles, client handles) of every item (GetMonitoredItems).
    pub fn handles(&self) -> (Vec<u32>, Vec<u32>) {
        let data = self.items.iter().flatten().map(|it| (it.id, it.client_handle));
        let events = self.events.iter().map(|e| (e.id, e.client_handle));
        data.chain(events).unzip()
    }

    /// Pulls new events into the event items' queues.
    #[cold]
    #[inline(never)]
    fn poll_events(&mut self) {
        for e in &mut self.events {
            e.poll();
        }
    }

    pub fn available(&self) -> impl Iterator<Item = u32> + '_ {
        self.retransmit.iter().map(|m| m.seq)
    }

    fn slot(&self, id: u32) -> Option<u32> {
        self.by_id.get(&id).copied()
    }

    pub fn item(&self, id: u32) -> Option<&Item> {
        self.slot(id).and_then(|s| self.items[s as usize].as_ref())
    }

    fn group_for(&mut self, sampling_ms: f64, now: u64) -> usize {
        let ns = ms_to_ns(sampling_ms);
        if let Some(i) = self.groups.iter().position(|g| g.interval_ns == ns) {
            return i;
        }
        // Phase-aligned with the publishing timer: when the sampling interval
        // divides the publishing interval, the last sample before a publish
        // is taken in the same tick, so a change waits at most one interval.
        let next = if ns > 0 && self.next_publish > now { now + (self.next_publish - now) % ns } else { now + ns };
        if let Some(i) = self.groups.iter().position(|g| g.items.is_empty()) {
            self.groups[i] = Group::new(ns, next, std::mem::take(&mut self.groups[i].items));
            return i;
        }
        self.groups.push(Group::new(ns, next, Vec::new()));
        self.groups.len() - 1
    }

    fn revise_item(l: &Limits, sub_interval: f64, p: &ItemParams) -> (f64, usize) {
        let sampling = if p.sampling_ms < 0.0 || p.sampling_ms.is_nan() {
            sub_interval
        } else if p.sampling_ms < l.min_sampling_interval_ms {
            l.min_sampling_interval_ms
        } else {
            p.sampling_ms.min(l.max_sampling_interval_ms)
        };
        let queue = p.queue_size.clamp(1, l.max_queue_size.max(1)) as usize;
        (sampling, queue)
    }

    /// Checks a filter against the item's data; `Err` is the item status.
    /// Validates the filter and returns it with the deadband made absolute.
    fn check_filter(
        space: &AddressSpace,
        node: &NodeId,
        attribute: u32,
        kind: u8,
        src: &Source,
        p: &ItemParams,
    ) -> Result<Filter, u32> {
        if !p.filter_present {
            return Ok(p.filter);
        }
        if attribute != crate::services::attr::VALUE {
            return Err(BAD_FILTER_NOT_ALLOWED);
        }
        if p.filter.trigger > TRIGGER_STATUS_VALUE_TIMESTAMP {
            return Err(BAD_MONITORED_ITEM_FILTER_INVALID);
        }
        let mut f = p.filter;
        if p.percent_deadband {
            // Only AnalogItems (EURange) support percent deadbands.
            let range = space.get(node).and_then(|n| n.eu_range(space)).ok_or(BAD_FILTER_NOT_ALLOWED)?;
            f.deadband = percent_to_absolute(p.filter.deadband, range);
        }
        if f.deadband != 0.0 {
            if !(f.deadband > 0.0 && f.deadband.is_finite()) {
                return Err(BAD_DEADBAND_FILTER_INVALID);
            }
            let numeric = match src {
                Source::Cell(_) => value::bits_as_f64(kind, 0).is_some(),
                Source::Fixed(v) => value::variant_as_f64(v).is_some(),
                _ => false,
            };
            if !numeric {
                return Err(BAD_FILTER_NOT_ALLOWED);
            }
        }
        Ok(f)
    }

    /// CreateMonitoredItems for one item. Returns (id, revised sampling,
    /// revised queue size) or the item's status code.
    #[allow(clippy::too_many_arguments)]
    pub fn create_item(
        &mut self,
        l: &Limits,
        space: &AddressSpace,
        node: NodeId,
        attribute: u32,
        mode: u32,
        ts: (bool, bool),
        p: &ItemParams,
        can_write: bool,
        now: u64,
    ) -> Result<(u32, f64, u32), u32> {
        self.create_item_range(l, space, node, attribute, None, mode, ts, p, can_write, now)
    }

    /// [`Self::create_item`] with a NumericRange: only those elements of the
    /// value are compared and reported.
    #[allow(clippy::too_many_arguments)]
    pub fn create_item_range(
        &mut self,
        l: &Limits,
        space: &AddressSpace,
        node: NodeId,
        attribute: u32,
        range: Option<(usize, usize)>,
        mode: u32,
        ts: (bool, bool),
        p: &ItemParams,
        can_write: bool,
        now: u64,
    ) -> Result<(u32, f64, u32), u32> {
        if mode > MODE_REPORTING {
            return Err(BAD_MONITORING_MODE_INVALID);
        }
        if self.item_count() >= l.max_monitored_items_per_subscription {
            return Err(BAD_TOO_MANY_MONITORED_ITEMS);
        }
        let (source, kind, mut size) = resolve(space, &node, attribute, can_write)?;
        if range.is_some() {
            if p.filter.deadband != 0.0 {
                // Deadbands on ranges apply per element: arrays only.
                return Err(BAD_FILTER_NOT_ALLOWED);
            }
            size = 0; // ranged values take the Variant path
        }
        let filter = Self::check_filter(space, &node, attribute, kind, &source, p)?;
        let percent = if p.percent_deadband { p.filter.deadband } else { 0.0 };
        let (sampling_ms, queue_size) = Self::revise_item(l, self.params.interval_ms, p);
        let id = self.next_item_id;
        self.next_item_id = self.next_item_id.checked_add(1).unwrap_or(1);
        let group = self.group_for(sampling_ms, now);
        let item = Item {
            id,
            client_handle: p.client_handle,
            mode,
            cold: Box::new(Cold { node, attribute, can_write, last_var: None, links: Vec::new(), percent, range }),
            linked: false,
            source,
            kind,
            size,
            ts_src: ts.0,
            ts_srv: ts.1,
            sampling_ms,
            group,
            queue_size,
            discard_oldest: p.discard_oldest,
            filter,
            sampled: false,
            last_seq: 0,
            last_status: 0,
            last_bits: 0,
            last_src: 0,
            queue: Queue::new(),
            dirty: false,
        };
        let slot = match self.free.pop() {
            Some(s) => {
                self.items[s as usize] = Some(item);
                s
            }
            None => {
                self.items.push(Some(item));
                (self.items.len() - 1) as u32
            }
        };
        self.by_id.insert(id, slot);
        let hot = Hot::new(slot, &self.items[slot as usize].as_ref().unwrap().source);
        self.groups[group].items.push(hot);
        self.groups[group].stale = true;
        self.generation = space.generation;
        // The initial value is sampled right away (Part 4 §5.12.1.2).
        if mode != MODE_DISABLED {
            self.sample_slot(slot, Some(space));
        }
        Ok((id, sampling_ms, queue_size as u32))
    }

    /// ModifyMonitoredItems for one item: (revised sampling, revised queue).
    pub fn modify_item(
        &mut self,
        l: &Limits,
        space: &AddressSpace,
        id: u32,
        ts: (bool, bool),
        p: &ItemParams,
        now: u64,
    ) -> Result<(f64, u32), u32> {
        let slot = self.slot(id).ok_or(BAD_MONITORED_ITEM_ID_INVALID)?;
        let it = self.items[slot as usize].as_ref().ok_or(BAD_MONITORED_ITEM_ID_INVALID)?;
        if it.cold.range.is_some() && p.filter.deadband != 0.0 {
            return Err(BAD_FILTER_NOT_ALLOWED);
        }
        let filter = Self::check_filter(space, &it.cold.node, it.cold.attribute, it.kind, &it.source, p)?;
        let (sampling_ms, queue_size) = Self::revise_item(l, self.params.interval_ms, p);
        let old_group = it.group;
        let new_group = if it.sampling_ms == sampling_ms { old_group } else { self.group_for(sampling_ms, now) };
        if new_group != old_group {
            let g = &mut self.groups[old_group].items;
            if let Some(i) = g.iter().position(|h| h.slot == slot) {
                let hot = g.swap_remove(i);
                self.groups[new_group].items.push(hot);
                self.groups[old_group].stale = true;
                self.groups[new_group].stale = true;
            }
        }
        let it = self.items[slot as usize].as_mut().unwrap();
        it.group = new_group;
        it.sampling_ms = sampling_ms;
        it.client_handle = p.client_handle;
        it.ts_src = ts.0;
        it.ts_srv = ts.1;
        it.filter = filter;
        it.cold.percent = if p.percent_deadband { p.filter.deadband } else { 0.0 };
        it.discard_oldest = p.discard_oldest;
        it.queue_size = queue_size;
        while it.queue.len() > queue_size {
            if it.discard_oldest {
                it.queue.pop_front();
            } else {
                it.queue.pop_back();
            }
        }
        Ok((sampling_ms, queue_size as u32))
    }

    pub fn delete_item(&mut self, id: u32) -> Result<(), u32> {
        let Some(slot) = self.by_id.remove(&id) else {
            let i = self.event_index(id).ok_or(BAD_MONITORED_ITEM_ID_INVALID)?;
            self.events.swap_remove(i);
            return Ok(());
        };
        let it = self.items[slot as usize].take().unwrap();
        let g = &mut self.groups[it.group];
        if let Some(i) = g.items.iter().position(|h| h.slot == slot) {
            g.items.swap_remove(i);
            g.stale = true;
        }
        if it.dirty {
            self.dirty.retain(|&s| s != slot);
        }
        self.links -= it.cold.links.len();
        if self.links > 0 {
            // Links pointing at the deleted item go too.
            let mut removed = 0;
            for o in self.items.iter_mut().flatten() {
                let before = o.cold.links.len();
                o.cold.links.retain(|&l| l != id);
                removed += before - o.cold.links.len();
                o.linked = !o.cold.links.is_empty();
            }
            self.links -= removed;
        }
        self.free.push(slot);
        Ok(())
    }

    pub fn set_mode(&mut self, id: u32, mode: u32, space: &AddressSpace) -> Result<(), u32> {
        if mode > MODE_REPORTING {
            return Err(BAD_MONITORING_MODE_INVALID);
        }
        let Some(slot) = self.slot(id) else {
            let i = self.event_index(id).ok_or(BAD_MONITORED_ITEM_ID_INVALID)?;
            let e = &mut self.events[i];
            e.mode = mode;
            if mode == MODE_DISABLED {
                e.clear();
            }
            return Ok(());
        };
        let it = self.items[slot as usize].as_mut().unwrap();
        let old = it.mode;
        it.mode = mode;
        if mode == MODE_DISABLED {
            it.queue.clear();
            if it.dirty {
                it.dirty = false;
                self.dirty.retain(|&s| s != slot);
            }
        } else if old == MODE_DISABLED {
            // Re-enabled: a fresh initial value.
            it.sampled = false;
            self.sample_slot(slot, Some(space));
        } else if mode == MODE_REPORTING && !it.queue.is_empty() && !it.dirty {
            it.dirty = true;
            self.dirty.push(slot);
        }
        Ok(())
    }

    /// SetTriggering: adds / removes links of `trigger`.
    pub fn link(&mut self, trigger: u32, target: u32, add: bool) -> Result<(), u32> {
        if self.slot(target).is_none() {
            return Err(BAD_MONITORED_ITEM_ID_INVALID);
        }
        let slot = self.slot(trigger).ok_or(BAD_MONITORED_ITEM_ID_INVALID)?;
        let it = self.items[slot as usize].as_mut().unwrap();
        let at = it.cold.links.iter().position(|&l| l == target);
        let r = match (add, at) {
            (true, None) => {
                it.cold.links.push(target);
                self.links += 1;
                Ok(())
            }
            (true, Some(_)) => Ok(()),
            (false, Some(i)) => {
                it.cold.links.swap_remove(i);
                self.links -= 1;
                Ok(())
            }
            (false, None) => Err(BAD_MONITORED_ITEM_ID_INVALID),
        };
        it.linked = !it.cold.links.is_empty();
        r
    }

    pub fn has_item(&self, id: u32) -> bool {
        self.by_id.contains_key(&id) || self.event_index(id).is_some()
    }

    /// Samples one item and does the reporting / triggering bookkeeping.
    #[inline(always)]
    fn sample_slot(&mut self, slot: u32, space: Option<&AddressSpace>) {
        let Some(it) = self.items[slot as usize].as_mut() else { return };
        if it.mode == MODE_DISABLED || !it.sample(space) || it.mode != MODE_REPORTING {
            return;
        }
        if !it.dirty {
            it.dirty = true;
            self.dirty.push(slot);
        }
        if it.linked {
            self.fire_links(slot);
        }
    }

    /// A reporting item queued a sample: linked items in Sampling mode
    /// report what they have queued (Part 4 §5.12.1.6).
    #[cold]
    fn fire_links(&mut self, slot: u32) {
        let links = std::mem::take(&mut self.items[slot as usize].as_mut().unwrap().cold.links);
        for &id in &links {
            if let Some(s) = self.slot(id) {
                let t = self.items[s as usize].as_mut().unwrap();
                if t.mode == MODE_SAMPLING && !t.queue.is_empty() && !t.dirty {
                    t.dirty = true;
                    self.dirty.push(s);
                }
            }
        }
        self.items[slot as usize].as_mut().unwrap().cold.links = links;
    }

    /// Re-resolves the sources after a configuration reload.
    #[cold]
    fn rebind(&mut self, space: &AddressSpace) {
        self.generation = space.generation;
        for it in self.items.iter_mut().flatten() {
            if it.cold.percent > 0.0 {
                if let Some(range) = space.get(&it.cold.node).and_then(|n| n.eu_range(space)) {
                    it.filter.deadband = percent_to_absolute(it.cold.percent, range);
                }
            }
            match resolve(space, &it.cold.node, it.cold.attribute, it.cold.can_write) {
                Ok((src, kind, size)) => {
                    let same = match (&it.source, &src) {
                        (Source::Cell(a), Source::Cell(b)) => Arc::ptr_eq(a, b),
                        (Source::Fixed(a), Source::Fixed(b)) => a == b,
                        (Source::Time, Source::Time) | (Source::Status, Source::Status) => true,
                        _ => false,
                    };
                    if !same {
                        it.source = src;
                        it.kind = kind;
                        it.size = if it.cold.range.is_some() { 0 } else { size };
                        // Compare with the last reported value on the next sample.
                        it.last_seq = it.last_seq.wrapping_add(1);
                        if !matches!(it.source, Source::Cell(_)) {
                            it.sampled = false;
                        }
                    }
                }
                Err(_) => it.source = Source::Gone,
            }
        }
        for g in &mut self.groups {
            for h in &mut g.items {
                *h = Hot::new(h.slot, &self.items[h.slot as usize].as_ref().unwrap().source);
            }
            g.stale = true;
        }
    }

    /// Samples every group whose deadline has passed.
    #[inline]
    pub fn sample_due(&mut self, now: u64, space: &AddressSpace) {
        if self.generation != space.generation {
            self.rebind(space);
        }
        if !self.events.is_empty() {
            self.poll_events();
        }
        for g in 0..self.groups.len() {
            let grp = &mut self.groups[g];
            if grp.next > now || grp.items.is_empty() {
                continue;
            }
            grp.next += grp.interval_ns;
            if grp.next <= now {
                // Fell behind (or the thread was descheduled): no catch-up burst.
                grp.next = now + grp.interval_ns;
            }
            if self.groups[g].stale {
                self.groups[g].reindex();
            }
            // Indexing (not iterating) keeps the borrow checker happy while
            // `sample_slot` updates the dirty list.
            for b in 0..self.groups[g].blocks.len() {
                let blk = &mut self.groups[g].blocks[b];
                // A block of unchanged cells: one load for up to 64 items.
                let stamp = blk.stamp.load(std::sync::atomic::Ordering::Acquire) as u64;
                if stamp == blk.seen {
                    continue;
                }
                blk.seen = stamp;
                let (start, end) = (blk.start as usize, blk.end as usize);
                for i in start..end {
                    let h = &mut self.groups[g].items[i];
                    // Ordered by the stamp load above.
                    let v = h.cell.as_ref().unwrap().version_relaxed();
                    if v == h.seen {
                        continue;
                    }
                    h.seen = v;
                    let slot = h.slot;
                    self.sample_slot(slot, Some(space));
                }
            }
            for i in self.groups[g].always..self.groups[g].items.len() {
                let slot = self.groups[g].items[i].slot;
                self.sample_slot(slot, Some(space));
            }
        }
    }

    pub fn next_deadline(&self) -> u64 {
        let mut d = self.next_publish;
        for g in &self.groups {
            if !g.items.is_empty() {
                d = d.min(g.next);
            }
        }
        d
    }

    /// Publishing timer (Part 4 §5.13.1.2 state table, condensed). Returns
    /// false when the lifetime expired.
    fn publish_timer(&mut self, now: u64, has_requests: bool) -> bool {
        if self.next_publish > now {
            return true;
        }
        self.next_publish += self.interval_ns;
        if self.next_publish <= now {
            self.next_publish = now + self.interval_ns;
        }
        if !has_requests {
            self.lifetime_counter += 1;
            if self.lifetime_counter >= self.params.lifetime {
                return false;
            }
        }
        if self.pending {
            return true;
        }
        if (self.publishing_enabled && self.has_notifications()) || !self.message_sent {
            self.pending = true;
        } else {
            self.keepalive_counter += 1;
            if self.keepalive_counter >= self.params.keepalive {
                self.pending = true;
            }
        }
        true
    }

    /// Encodes the next NotificationMessage at the end of `w`, stopping
    /// once `w` reaches `limit` bytes. Returns (notifications, more queued).
    fn build_message(&mut self, now_ticks: i64, limit: usize, w: &mut Writer) -> (u32, bool) {
        w.u32(self.seq);
        w.i64(now_ticks);
        let parts_at = w.len();
        w.i32(1);
        let max = self.params.max_notifications;
        let mut n = 0u32;
        let mut parts = 0;
        if !self.dirty.is_empty() {
            parts += 1;
            let at = w.begin_extension_object(ids::DATA_CHANGE_NOTIFICATION_ENCODING);
            let count_at = w.len();
            w.i32(0);
            let mut done = 0;
            let mut full = false;
            for k in 0..self.dirty.len() {
                let slot = self.dirty[k];
                let Some(it) = self.items[slot as usize].as_mut() else {
                    done = k + 1;
                    continue;
                };
                while let Some(&e) = it.queue.front() {
                    if n >= max || w.len() >= limit {
                        full = true;
                        break;
                    }
                    let var = if e.tag == TAG_VAR { it.queue.front_var() } else { None };
                    it.write_entry(w, &e, var);
                    it.queue.pop_front();
                    n += 1;
                }
                if full {
                    break;
                }
                it.dirty = false;
                done = k + 1;
            }
            self.dirty.drain(..done);
            w.patch_u32(count_at, n);
            w.i32(0); // diagnosticInfos
            w.end_extension_object(at);
        }
        if !self.events.is_empty() && n < max && w.len() < limit && self.events_ready() {
            parts += 1;
            n += self.write_events(w, max - n, limit);
        }
        if parts != 1 {
            w.patch_u32(parts_at, parts);
        }
        (n, self.has_notifications())
    }

    /// EventNotificationList with the reportable event items' queues.
    #[cold]
    #[inline(never)]
    fn write_events(&mut self, w: &mut Writer, max: u32, max_bytes: usize) -> u32 {
        let at = w.begin_extension_object(crate::events::EVENT_NOTIFICATION_LIST_ENCODING);
        let count_at = w.len();
        w.i32(0);
        let mut n = 0;
        for e in &mut self.events {
            if e.mode == MODE_REPORTING {
                n += e.write(w, max - n, max_bytes);
            }
        }
        w.patch_u32(count_at, n);
        w.end_extension_object(at);
        n
    }

    /// Keeps a sent message for Republish: copied out of `buf`, or, with
    /// `take`, `buf` itself is kept and replaced by a recycled buffer (no copy).
    fn keep(&mut self, seq: u32, buf: &mut Vec<u8>, start: usize, end: usize, take: bool) {
        let mut spare = self.pool.pop().unwrap_or_default();
        spare.clear();
        let (start, end) = if take {
            std::mem::swap(buf, &mut spare);
            (start, end)
        } else {
            spare.extend_from_slice(&buf[start..end]);
            (0, end - start)
        };
        self.retransmit.push_back(Sent { seq, buf: spare, start: start as u32, end: end as u32 });
    }

    pub fn acknowledge(&mut self, seq: u32) -> u32 {
        match self.retransmit.iter().position(|m| m.seq == seq) {
            Some(i) => {
                let m = self.retransmit.remove(i).unwrap();
                self.pool.push(m.buf);
                status::GOOD
            }
            None => BAD_SEQUENCE_NUMBER_UNKNOWN,
        }
    }

    pub fn republish(&self, seq: u32) -> Option<&[u8]> {
        self.retransmit.iter().find(|m| m.seq == seq).map(|m| &m.buf[m.start as usize..m.end as usize])
    }

    /// After TransferSubscriptions with sendInitialValues.
    pub fn resend_initial_values(&mut self) {
        for it in self.items.iter_mut().flatten() {
            it.sampled = false;
        }
        for g in &mut self.groups {
            g.next = 0;
            for h in &mut g.items {
                h.seen = 1;
            }
            g.stale = true;
        }
    }

    /// Sampling and publishing happen on another thread from now on.
    pub fn reset_timers(&mut self, now: u64) {
        self.next_publish = now + self.interval_ns;
        self.lifetime_counter = 0;
    }
}

// ---------------------------------------------------------------- per session

/// A NotificationMessage kept for Republish: `buf[start..end]`. `buf` may
/// be the whole response it was sent in (see [`SessionSubs::keep_sent`]).
struct Sent {
    seq: u32,
    buf: Vec<u8>,
    start: u32,
    end: u32,
}

/// A message `write_next` encoded straight into the response, to be kept
/// for Republish once the response is sent.
struct Unkept {
    sub_id: u32,
    seq: u32,
    start: usize,
    end: usize,
}

pub struct PublishRequest {
    pub request_id: u32,
    pub channel_id: u32,
    pub handle: u32,
    /// Monotonic deadline from the timeout hint, `u64::MAX` = none.
    pub deadline: u64,
    /// Acknowledgement results, in request order.
    pub acks: Vec<u32>,
}

/// Deadline of a cancelled Publish request (monotonic deadlines are > 0).
const CANCELLED: u64 = 0;

/// A StatusChangeNotification waiting for a Publish request.
struct StatusMsg {
    sub_id: u32,
    seq: u32,
    status: u32,
}

/// Subscriptions and queued Publish requests of one session.
#[derive(Default)]
pub struct SessionSubs {
    pub subs: Vec<Subscription>,
    requests: VecDeque<PublishRequest>,
    status_msgs: VecDeque<StatusMsg>,
    ack_pool: Vec<Vec<u32>>,
    unkept: Option<Unkept>,
}

/// What [`SessionSubs::write_next`] produced.
pub struct Ready {
    pub request_id: u32,
    pub handle: u32,
}

impl SessionSubs {
    pub fn find(&mut self, id: u32) -> Option<&mut Subscription> {
        self.subs.iter_mut().find(|s| s.id == id)
    }

    pub fn remove(&mut self, id: u32) -> Option<Subscription> {
        let i = self.subs.iter().position(|s| s.id == id)?;
        Some(self.subs.swap_remove(i))
    }

    /// Nothing left for a connection thread to drive.
    pub fn is_idle(&self) -> bool {
        self.subs.is_empty() && self.requests.is_empty() && self.status_msgs.is_empty()
    }

    pub fn has_requests(&self) -> bool {
        !self.requests.is_empty()
    }

    pub fn has_status_changes(&self) -> bool {
        !self.status_msgs.is_empty()
    }

    pub fn ack_buffer(&mut self) -> Vec<u32> {
        let mut v = self.ack_pool.pop().unwrap_or_default();
        v.clear();
        v
    }

    /// Processes the acknowledgements of a Publish request (on arrival).
    pub fn acknowledge(&mut self, sub_id: u32, seq: u32) -> u32 {
        match self.find(sub_id) {
            Some(s) => s.acknowledge(seq),
            None => BAD_SUBSCRIPTION_ID_INVALID,
        }
    }

    /// Queues a Publish request; the client is alive, so every lifetime
    /// counter restarts.
    pub fn queue(&mut self, l: &Limits, req: PublishRequest) -> Result<(), (u32, PublishRequest)> {
        if self.requests.len() >= l.max_publish_requests {
            return Err((BAD_TOO_MANY_PUBLISH_REQUESTS, req));
        }
        for s in &mut self.subs {
            s.lifetime_counter = 0;
        }
        self.requests.push_back(req);
        Ok(())
    }

    pub fn recycle_acks(&mut self, v: Vec<u32>) {
        if v.capacity() > 0 {
            self.ack_pool.push(v);
        }
    }

    /// Cancel: queued Publish requests with `handle` are answered with
    /// Bad_RequestCancelledByClient on the next `write_next`.
    pub fn cancel(&mut self, handle: u32) -> u32 {
        let mut n = 0;
        for i in 0..self.requests.len() {
            if self.requests[i].handle == handle && self.requests[i].deadline != CANCELLED {
                let mut r = self.requests.remove(i).unwrap();
                r.deadline = CANCELLED;
                self.requests.push_front(r);
                n += 1;
            }
        }
        n
    }

    /// Queues a StatusChangeNotification for subscription `sub_id`.
    pub fn status_change(&mut self, sub_id: u32, seq: u32, code: u32) {
        self.status_msgs.push_back(StatusMsg { sub_id, seq, status: code });
    }

    /// Runs the sampling and publishing timers that are due.
    pub fn tick(&mut self, now: u64, space: &AddressSpace) {
        let has_requests = !self.requests.is_empty();
        let mut i = 0;
        while i < self.subs.len() {
            let s = &mut self.subs[i];
            s.sample_due(now, space);
            if s.publish_timer(now, has_requests) {
                i += 1;
            } else {
                crate::log!("subscription {} expired (lifetime)", s.id);
                let s = self.subs.swap_remove(i);
                self.status_msgs.push_back(StatusMsg { sub_id: s.id, seq: s.seq, status: status::BAD_TIMEOUT });
            }
        }
    }

    /// Earliest time `tick` / `write_next` have something to do (0 = now).
    pub fn next_deadline(&self) -> u64 {
        if !self.requests.is_empty()
            && (!self.status_msgs.is_empty() || self.subs.is_empty() || self.subs.iter().any(|s| s.pending))
        {
            return 0;
        }
        let mut d = u64::MAX;
        for s in &self.subs {
            d = d.min(s.next_deadline());
        }
        for r in &self.requests {
            d = d.min(r.deadline);
        }
        d
    }

    /// Answers one queued Publish request if anything is ready: a timeout,
    /// a status change, or a subscription with a pending message. Writes the
    /// whole response body (type id onwards) into `w`.
    ///
    /// With `keep_later`, a NotificationMessage is not copied for Republish
    /// here: the caller sends the response, then hands its buffer to
    /// [`SessionSubs::keep_sent`].
    pub fn write_next(
        &mut self,
        l: &Limits,
        now: u64,
        channel_id: u32,
        max_bytes: usize,
        w: &mut Writer,
        keep_later: bool,
    ) -> Option<Ready> {
        // A message nobody kept (the caller did not send it) is dropped.
        self.unkept = None;
        // Requests from a channel the session left can no longer be answered.
        while self.requests.front().is_some_and(|r| r.channel_id != channel_id) {
            let r = self.requests.pop_front().unwrap();
            self.recycle_acks(r.acks);
        }
        let front = self.requests.front()?;
        if front.deadline <= now {
            let r = self.requests.pop_front().unwrap();
            let code =
                if r.deadline == CANCELLED { status::BAD_REQUEST_CANCELLED_BY_CLIENT } else { status::BAD_TIMEOUT };
            crate::services::write_fault(w, r.handle, code);
            return Some(self.done(r));
        }
        if let Some(m) = self.status_msgs.pop_front() {
            let r = self.requests.pop_front().unwrap();
            let ticks = coarse_now_ticks();
            crate::services::begin_raw(w, ids::PUBLISH_RESPONSE, ticks, r.handle);
            w.u32(m.sub_id);
            w.empty_array(); // availableSequenceNumbers
            w.bool(false);
            w.u32(m.seq);
            w.i64(ticks);
            w.i32(1);
            let at = w.begin_extension_object(ids::STATUS_CHANGE_NOTIFICATION_ENCODING);
            w.u32(m.status);
            w.empty_diagnostic_info();
            w.end_extension_object(at);
            write_acks(w, &r.acks);
            return Some(self.done(r));
        }
        if self.subs.is_empty() {
            let r = self.requests.pop_front().unwrap();
            crate::services::write_fault(w, r.handle, BAD_NO_SUBSCRIPTION);
            return Some(self.done(r));
        }
        // The pending subscription with the highest priority.
        let mut best: Option<usize> = None;
        for (i, s) in self.subs.iter().enumerate() {
            if s.pending && best.is_none_or(|b| s.params.priority > self.subs[b].params.priority) {
                best = Some(i);
            }
        }
        let s = &mut self.subs[best?];
        let r = self.requests.pop_front().unwrap();
        let ticks = now_ticks();
        crate::services::begin_raw(w, ids::PUBLISH_RESPONSE, ticks, r.handle);
        w.u32(s.id);
        if s.publishing_enabled && s.has_notifications() {
            if s.retransmit.len() >= l.max_retransmission_queue.max(1) {
                // The oldest unacknowledged message is no longer available.
                let m = s.retransmit.pop_front().unwrap();
                s.pool.push(m.buf);
            }
            let seq = s.seq;
            w.i32(s.retransmit.len() as i32 + 1);
            for m in &s.retransmit {
                w.u32(m.seq);
            }
            w.u32(seq);
            let more_at = w.len();
            w.bool(false);
            // Encoded in place: no copy into the response.
            let start = w.len();
            let (_, more) = s.build_message(ticks, start + max_bytes, w);
            let end = w.len();
            w.buf[more_at] = more as u8;
            s.seq = next_seq(seq);
            s.pending = more;
            if keep_later {
                self.unkept = Some(Unkept { sub_id: s.id, seq, start, end });
            } else {
                s.keep(seq, w.buf, start, end, false);
            }
        } else {
            // Keep-alive: the next sequence number, no notifications.
            w.i32(s.retransmit.len() as i32);
            for m in &s.retransmit {
                w.u32(m.seq);
            }
            w.bool(false);
            w.u32(s.seq);
            w.i64(ticks);
            w.i32(0);
            s.pending = false;
        }
        s.keepalive_counter = 0;
        s.lifetime_counter = 0;
        s.message_sent = true;
        write_acks(w, &r.acks);
        Some(self.done(r))
    }

    /// Keeps the NotificationMessage of the response in `buf`, sent by the
    /// last `write_next(.., keep_later = true)`. With `take`, `buf` itself
    /// is kept and replaced by a recycled buffer; otherwise (the response was
    /// encrypted in place) the message is copied out first, before sending.
    /// Returns whether there was a message to keep.
    pub fn keep_sent(&mut self, buf: &mut Vec<u8>, take: bool) -> bool {
        let Some(u) = self.unkept.take() else { return false };
        match self.subs.iter_mut().find(|s| s.id == u.sub_id) {
            Some(s) => {
                s.keep(u.seq, buf, u.start, u.end, take);
                true
            }
            None => false,
        }
    }

    fn done(&mut self, r: PublishRequest) -> Ready {
        let ready = Ready { request_id: r.request_id, handle: r.handle };
        self.recycle_acks(r.acks);
        ready
    }
}

fn write_acks(w: &mut Writer, acks: &[u32]) {
    w.i32(acks.len() as i32);
    for &a in acks {
        w.u32(a);
    }
    w.empty_array(); // diagnosticInfos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_rules() {
        let l = Limits::default();
        let p = SubParams::revise(&l, 0.0, 1, 0, 0, 3);
        assert_eq!(p.interval_ms, l.min_publishing_interval_ms);
        assert_eq!(p.keepalive, 1);
        assert_eq!(p.lifetime, 3, "lifetime >= 3 keep-alives");
        assert_eq!(p.max_notifications, l.max_notifications_per_publish);
        let p = SubParams::revise(&l, f64::NAN, 100, 10, 5, 0);
        assert_eq!(
            (p.interval_ms, p.lifetime, p.keepalive, p.max_notifications),
            (l.min_publishing_interval_ms, 100, 10, 5)
        );
        assert_eq!(SubParams::revise(&l, 1e12, 30, 10, 0, 0).interval_ms, l.max_publishing_interval_ms);
    }

    fn entry(bits: u64) -> Entry {
        Entry { bits, src: 0, srv: 0, status: 0, tag: TAG_BITS }
    }

    fn item(queue_size: usize, discard_oldest: bool) -> Item {
        Item {
            id: 1,
            client_handle: 1,
            mode: MODE_REPORTING,
            cold: Box::new(Cold {
                node: NodeId::NULL,
                attribute: 13,
                can_write: false,
                last_var: None,
                links: Vec::new(),
                percent: 0.0,
                range: None,
            }),
            linked: false,
            source: Source::Gone,
            kind: builtin::DOUBLE,
            size: 8,
            ts_src: false,
            ts_srv: false,
            sampling_ms: 1.0,
            group: 0,
            queue_size,
            discard_oldest,
            filter: Filter::default(),
            sampled: false,
            last_seq: 0,
            last_status: 0,
            last_bits: 0,
            last_src: 0,
            queue: Queue::new(),
            dirty: false,
        }
    }

    fn drain(it: &mut Item) -> Vec<(u64, bool)> {
        let mut v = Vec::new();
        while let Some(e) = it.queue.pop_front() {
            v.push((e.bits, e.status & OVERFLOW_BITS == OVERFLOW_BITS));
        }
        v
    }

    #[test]
    fn overflow_policies() {
        let mut it = item(3, true);
        for b in 1..=5 {
            it.push(entry(b), None);
        }
        assert_eq!(drain(&mut it), vec![(3, true), (4, false), (5, false)]);

        let mut it = item(3, false);
        for b in 1..=5 {
            it.push(entry(b), None);
        }
        assert_eq!(drain(&mut it), vec![(1, false), (2, false), (5, true)]);

        // Queue of one: the newest value replaces, no overflow bit.
        let mut it = item(1, true);
        for b in 1..=5 {
            it.push(entry(b), None);
        }
        assert_eq!(drain(&mut it), vec![(5, false)]);
    }

    #[test]
    fn variable_length_payloads_stay_in_order() {
        let mut it = item(2, true);
        it.push(Entry { tag: TAG_VAR, ..entry(0) }, Some(Variant::string("a")));
        it.push(entry(7), None);
        it.push(Entry { tag: TAG_VAR, ..entry(0) }, Some(Variant::string("b")));
        // "a" was discarded with its payload.
        assert_eq!(it.queue.front().unwrap().bits, 7);
        it.queue.pop_front();
        assert_eq!(it.queue.front_var(), Some(&Variant::string("b")));
    }
}
