//! Historical data access (Part 11): an in-memory history per Historizing
//! variable, HistoryRead (raw, modified, at time) and HistoryUpdate
//! (insert, replace, update, delete raw / modified / at time).
//!
//! Recording is a branch on a flag in [`crate::value::ValueCell::write`]
//! (never taken for variables without history) and, for historized ones, a
//! short uncontended mutex and a push into a ring that does not allocate
//! once it has grown to its capacity. Reads copy what they need under the
//! lock and encode outside of it.

use crate::codec::{DResult, Reader, Writer};
use crate::services::{begin, check_count, decode_err, session, SResult};
use crate::services::{Ctx, RequestHeader};
use crate::types::*;
use crate::value::{self, Sample};
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// AccessLevel bits (Part 3 §8.57).
pub const ACCESS_HISTORY_READ: u8 = 0x04;
pub const ACCESS_HISTORY_WRITE: u8 = 0x08;

/// Default number of values kept per variable.
pub const DEFAULT_CAPACITY: usize = 10_000;
/// Values one HistoryRead returns per node before a continuation point
/// (HistoryServerCapabilities.MaxReturnDataValues).
pub const MAX_RETURN_VALUES: usize = 10_000;

/// HistoryUpdateType (Part 11 §6.9).
pub const UPDATE_INSERT: u32 = 1;
pub const UPDATE_REPLACE: u32 = 2;
pub const UPDATE_UPDATE: u32 = 3;
pub const UPDATE_DELETE: u32 = 4;

/// Historian bits of a StatusCode (Part 4 §7.39.1, Part 11 §6.3.6), with
/// the InfoType set to DataValue (0x0400) so that clients read them.
pub const INFO_DATA_VALUE: u32 = 0x0400;
pub const CALCULATED: u32 = INFO_DATA_VALUE | 0x01;
pub const INTERPOLATED: u32 = INFO_DATA_VALUE | 0x02;
pub const PARTIAL: u32 = INFO_DATA_VALUE | 0x04;
pub const EXTRA_DATA: u32 = INFO_DATA_VALUE | 0x08;
pub const MULTI_VALUE: u32 = INFO_DATA_VALUE | 0x10;

/// A change made by HistoryUpdate (HistoryModifiedData).
#[derive(Clone, Debug, PartialEq)]
pub struct Modified {
    /// Value before the change (the new one for an insert).
    pub sample: Sample,
    pub time: i64,
    pub kind: u32,
    pub user: Arc<str>,
}

struct Store {
    /// Sorted by source timestamp; equal timestamps in arrival order.
    raw: VecDeque<Sample>,
    cap: usize,
    modified: VecDeque<Modified>,
}

pub struct History {
    kind: u8,
    store: Mutex<Store>,
}

/// Position of the first value at `ts` or later.
fn lower(raw: &VecDeque<Sample>, ts: i64) -> usize {
    raw.partition_point(|s| s.source_ts < ts)
}

/// Position after the last value at `ts` or earlier.
fn upper(raw: &VecDeque<Sample>, ts: i64) -> usize {
    raw.partition_point(|s| s.source_ts <= ts)
}

impl Store {
    fn insert(&mut self, s: Sample) {
        if self.raw.len() >= self.cap {
            self.raw.pop_front();
        }
        if self.raw.back().is_none_or(|b| b.source_ts <= s.source_ts) {
            self.raw.push_back(s);
        } else {
            let at = upper(&self.raw, s.source_ts);
            self.raw.insert(at, s);
        }
    }

    fn log(&mut self, sample: Sample, kind: u32, user: &Arc<str>, now: i64) {
        if self.modified.len() >= self.cap.max(1) {
            self.modified.pop_front();
        }
        self.modified.push_back(Modified { sample, time: now, kind, user: user.clone() });
    }
}

/// One entry of a HistoryRead result.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub sample: Sample,
    /// Set for HistoryModifiedData.
    pub modification: Option<(i64, u32, Arc<str>)>,
}

/// Where a paged read resumes: the timestamp of the next value and how many
/// values with that timestamp were already returned.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Resume {
    pub ts: i64,
    pub skip: u32,
}

/// ReadRawModifiedDetails (DateTime 0 = unspecified).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RawQuery {
    pub modified: bool,
    pub start: i64,
    pub end: i64,
    pub max: usize,
    pub bounds: bool,
}

fn bound_missing(ts: i64) -> Sample {
    Sample { value: Variant::Empty, status: status::BAD_BOUND_NOT_FOUND, source_ts: ts, server_ts: ts }
}

impl History {
    pub fn new(kind: u8, capacity: usize) -> History {
        let cap = capacity.max(1);
        History {
            kind,
            store: Mutex::new(Store { raw: VecDeque::with_capacity(cap.min(1024)), cap, modified: VecDeque::new() }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn kind(&self) -> u8 {
        self.kind
    }

    #[cold]
    pub fn set_capacity(&self, capacity: usize) {
        let mut st = self.lock();
        st.cap = capacity.max(1);
        while st.raw.len() > st.cap {
            st.raw.pop_front();
        }
        while st.modified.len() > st.cap {
            st.modified.pop_front();
        }
    }

    /// Records a write of the current value.
    #[inline]
    pub fn record(&self, s: Sample) {
        self.lock().insert(s);
    }

    pub fn len(&self) -> usize {
        self.lock().raw.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Raw or modified values (Part 11 §6.4.3), collected.
    pub fn read_raw(&self, q: &RawQuery, resume: Option<Resume>) -> Result<(Vec<Entry>, Option<Resume>), u32> {
        let mut out = Vec::new();
        let more = self.read_raw_with(q, resume, |s, m| {
            out.push(Entry { sample: s.clone(), modification: m.map(|(t, k, u)| (t, k, u.clone())) })
        })?;
        Ok((out, more))
    }

    /// Raw or modified values (Part 11 §6.4.3): `f` sees each returned
    /// sample (and its modification for modified reads) in order, under the
    /// lock, so a response is encoded without copying the values. Returns
    /// where to resume when `max` cut the result short.
    pub fn read_raw_with(
        &self,
        q: &RawQuery,
        resume: Option<Resume>,
        mut f: impl FnMut(&Sample, Option<(i64, u32, &Arc<str>)>),
    ) -> Result<Option<Resume>, u32> {
        let (s_set, e_set) = (q.start != 0, q.end != 0);
        if !s_set && !e_set {
            return Err(status::BAD_INVALID_TIMESTAMP_ARGUMENT);
        }
        if (!s_set || !e_set) && q.max == 0 {
            return Err(status::BAD_INVALID_TIMESTAMP_ARGUMENT);
        }
        let forward = if s_set && e_set { q.start <= q.end } else { s_set };
        let st = self.lock();
        // Modified values are logged in modification order: sort indexes.
        let order: Vec<usize> = if q.modified {
            let mut o: Vec<usize> = (0..st.modified.len()).collect();
            o.sort_by_key(|&i| st.modified[i].sample.source_ts);
            o
        } else {
            Vec::new()
        };
        let len = if q.modified { order.len() } else { st.raw.len() };
        let sample = |i: usize| if q.modified { &st.modified[order[i]].sample } else { &st.raw[i] };
        let ts_at = |i: usize| sample(i).source_ts;
        let pp = |pred: &dyn Fn(i64) -> bool| -> usize {
            let (mut a, mut b) = (0, len);
            while a < b {
                let m = (a + b) / 2;
                if pred(ts_at(m)) {
                    a = m + 1;
                } else {
                    b = m;
                }
            }
            a
        };
        let resumed = resume.is_some();
        let skip = resume.map_or(0, |r| r.skip as usize);
        // The first timestamp in reading order (inclusive).
        let first = resume.map_or(if s_set { q.start } else { q.end }, |r| r.ts);
        let (lo, hi) = if forward {
            let lo = pp(&|t| t < first);
            let hi = match (e_set, q.start == q.end) {
                (false, _) => len,
                (true, true) => pp(&|t| t <= q.end),
                (true, false) => pp(&|t| t < q.end),
            };
            (lo, hi.max(lo))
        } else {
            let hi = pp(&|t| t <= first);
            let lo = if s_set && e_set { pp(&|t| t <= q.end) } else { 0 };
            (lo.min(hi), hi)
        };
        let max = if q.max == 0 { MAX_RETURN_VALUES } else { q.max.min(MAX_RETURN_VALUES) };
        let bounds = q.bounds && !q.modified;

        // Emits entries until `max`; the entry after that sets `more`.
        let mut n = 0usize;
        // Values returned so far with the timestamp of the last one.
        let (mut run_ts, mut run) = (i64::MIN, 0usize);
        let mut more: Option<Resume> = None;
        let mut emit = |e: Option<usize>, ts: i64, is_value: bool| -> bool {
            if n == max {
                more = Some(if is_value {
                    // Values with this timestamp already returned, on this
                    // page and (when it started on that timestamp) before.
                    let here = if run_ts == ts { run } else { 0 };
                    let before = if resume.is_some_and(|r| r.ts == ts) { skip } else { 0 };
                    Resume { ts, skip: (here + before) as u32 }
                } else {
                    // Only the end bound is left: an empty range at the end.
                    Resume { ts: q.end, skip: 0 }
                });
                return true;
            }
            n += 1;
            if is_value {
                if run_ts == ts {
                    run += 1;
                } else {
                    (run_ts, run) = (ts, 1);
                }
            }
            match e {
                Some(i) => {
                    let m = q.modified.then(|| {
                        let m = &st.modified[order[i]];
                        (m.time, m.kind, &m.user)
                    });
                    f(sample(i), m);
                }
                None => f(&bound_missing(ts), None),
            }
            false
        };
        // Start bound: the value just outside the range on the start side,
        // unless a value sits exactly on the start time.
        if bounds && !resumed && s_set {
            let b = if forward {
                if lo < len && ts_at(lo) == q.start {
                    None
                } else {
                    Some(lo.checked_sub(1))
                }
            } else if hi > 0 && ts_at(hi - 1) == q.start {
                None
            } else {
                Some((hi < len).then_some(hi))
            };
            if let Some(i) = b {
                emit(i, i.map_or(q.start, ts_at), false);
            }
        }
        let mut skipped = 0;
        let mut value = |i: usize| -> bool {
            let ts = ts_at(i);
            if skipped < skip && ts == first {
                skipped += 1;
                return false;
            }
            emit(Some(i), ts, true)
        };
        let stopped = if forward { (lo..hi).any(&mut value) } else { (lo..hi).rev().any(&mut value) };
        if !stopped && bounds && e_set && s_set && q.start != q.end {
            let i = if forward { (hi < len).then_some(hi) } else { lo.checked_sub(1) };
            emit(i, i.map_or(q.end, ts_at), false);
        }
        Ok(more)
    }

    /// ReadAtTimeDetails: the value at each time, interpolated between the
    /// neighbouring values (sloped for numbers, stepped otherwise).
    pub fn read_at_time(&self, times: &[i64], stepped: bool) -> Vec<Sample> {
        let st = self.lock();
        let numeric = value::bits_as_f64(self.kind, 0).is_some();
        times
            .iter()
            .map(|&t| {
                let i = lower(&st.raw, t);
                if i < st.raw.len() && st.raw[i].source_ts == t {
                    return st.raw[i].clone();
                }
                let prev = i.checked_sub(1).map(|p| &st.raw[p]);
                let next = st.raw.get(i);
                match (prev, next) {
                    (Some(p), Some(n)) => {
                        let good = status::is_good(p.status) && status::is_good(n.status);
                        let code = if good { status::GOOD } else { status::UNCERTAIN_DATA_SUB_NORMAL };
                        let value = match (
                            numeric && !stepped,
                            value::variant_as_f64(&p.value),
                            value::variant_as_f64(&n.value),
                        ) {
                            (true, Some(a), Some(b)) => {
                                let f = (t - p.source_ts) as f64 / (n.source_ts - p.source_ts) as f64;
                                value::variant_from_f64(self.kind, a + (b - a) * f).unwrap_or(Variant::Empty)
                            }
                            _ => p.value.clone(),
                        };
                        Sample { value, status: code | INTERPOLATED, source_ts: t, server_ts: t }
                    }
                    // After the last value: stepped extrapolation.
                    (Some(p), None) => Sample {
                        value: p.value.clone(),
                        status: status::UNCERTAIN_DATA_SUB_NORMAL | INTERPOLATED,
                        source_ts: t,
                        server_ts: t,
                    },
                    _ => Sample { value: Variant::Empty, status: status::BAD_NO_DATA, source_ts: t, server_ts: t },
                }
            })
            .collect()
    }

    /// Raw values in `[start, end)` (both inclusive when equal), oldest
    /// first, plus the values just before and after (bounds for aggregates).
    pub fn window(&self, start: i64, end: i64) -> (Option<Sample>, Vec<Sample>, Option<Sample>) {
        let st = self.lock();
        let (a, b) = (start.min(end), start.max(end));
        let lo = lower(&st.raw, a);
        let hi = if a == b { upper(&st.raw, b) } else { lower(&st.raw, b) };
        let before = lo.checked_sub(1).map(|i| st.raw[i].clone());
        let after = st.raw.get(hi).cloned();
        (before, st.raw.range(lo..hi).cloned().collect(), after)
    }

    /// UpdateDataDetails for one value. The caller checked the type.
    pub fn update(&self, mode: u32, s: Sample, user: &Arc<str>, now: i64) -> u32 {
        let mut st = self.lock();
        let at = lower(&st.raw, s.source_ts);
        let exists = at < st.raw.len() && st.raw[at].source_ts == s.source_ts;
        match (mode, exists) {
            (UPDATE_INSERT, true) => status::BAD_ENTRY_EXISTS,
            (UPDATE_REPLACE, false) => status::BAD_NO_ENTRY_EXISTS,
            (UPDATE_REPLACE | UPDATE_UPDATE, true) => {
                let old = std::mem::replace(&mut st.raw[at], s);
                st.log(old, UPDATE_REPLACE, user, now);
                status::GOOD_ENTRY_REPLACED
            }
            (UPDATE_INSERT | UPDATE_UPDATE, false) => {
                st.log(s.clone(), UPDATE_INSERT, user, now);
                st.insert(s);
                status::GOOD_ENTRY_INSERTED
            }
            _ => status::BAD_HISTORY_OPERATION_INVALID,
        }
    }

    /// DeleteRawModifiedDetails: values in `[start, end)` (the value at
    /// `start` when both are equal). Returns how many were deleted.
    pub fn delete_raw(&self, modified: bool, start: i64, end: i64, user: &Arc<str>, now: i64) -> usize {
        let (a, b) = (start.min(end), start.max(end));
        let inside = |t: i64| if a == b { t == a } else { t >= a && t < b };
        let mut st = self.lock();
        if modified {
            let before = st.modified.len();
            st.modified.retain(|m| !inside(m.sample.source_ts));
            return before - st.modified.len();
        }
        let lo = lower(&st.raw, a);
        let hi = if a == b { upper(&st.raw, b) } else { lower(&st.raw, b) };
        let gone: Vec<Sample> = st.raw.drain(lo..hi).collect();
        let n = gone.len();
        for s in gone {
            st.log(s, UPDATE_DELETE, user, now);
        }
        n
    }

    /// DeleteAtTimeDetails for one time.
    pub fn delete_at(&self, ts: i64, user: &Arc<str>, now: i64) -> u32 {
        let mut st = self.lock();
        let at = lower(&st.raw, ts);
        if at < st.raw.len() && st.raw[at].source_ts == ts {
            let s = st.raw.remove(at).unwrap();
            st.log(s, UPDATE_DELETE, user, now);
            status::GOOD
        } else {
            status::BAD_NO_ENTRY_EXISTS
        }
    }
}

// ---------------------------------------------------------------- services

/// Continuation points carry the resume position (they hold no server
/// state, so there is nothing to release or to run out of), bound to the
/// node and the kind of read.
fn cp_encode(node: &NodeId, kind: u8, r: Resume) -> Vec<u8> {
    let mut v = Vec::with_capacity(19);
    v.extend_from_slice(b"FH");
    v.extend_from_slice(&node_hash(node).to_le_bytes());
    v.push(kind);
    v.extend_from_slice(&r.ts.to_le_bytes());
    v.extend_from_slice(&r.skip.to_le_bytes());
    v
}

fn cp_decode(node: &NodeId, kind: u8, b: &[u8]) -> Result<Resume, u32> {
    let bad = status::BAD_CONTINUATION_POINT_INVALID;
    if b.len() != 19 || &b[..2] != b"FH" || b[2..6] != node_hash(node).to_le_bytes() || b[6] != kind {
        return Err(bad);
    }
    Ok(Resume {
        ts: i64::from_le_bytes(b[7..15].try_into().unwrap()),
        skip: u32::from_le_bytes(b[15..19].try_into().unwrap()),
    })
}

fn node_hash(node: &NodeId) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    node.hash(&mut h);
    h.finish() as u32
}

const CP_RAW: u8 = 1;
const CP_MODIFIED: u8 = 2;
const CP_AT_TIME: u8 = 3;
pub(crate) const CP_PROCESSED: u8 = 4;

/// What a HistoryRead asks for.
enum Details {
    Raw(RawQuery),
    AtTime { times: Vec<i64>, stepped: bool },
    Processed(ProcessedQuery),
}

/// ReadProcessedDetails (aggregates).
#[derive(Clone, Debug, PartialEq)]
pub struct ProcessedQuery {
    pub start: i64,
    pub end: i64,
    pub interval_ms: f64,
    pub aggregates: Vec<NodeId>,
    pub config: crate::aggregates::Config,
}

fn parse_details(type_id: &NodeId, body: &[u8]) -> Result<Details, u32> {
    let mut r = Reader::new(body);
    let parse = |r: &mut Reader| -> DResult<Details> {
        Ok(match type_id.as_ns0() {
            Some(ids::READ_RAW_MODIFIED_DETAILS_ENCODING) => Details::Raw(RawQuery {
                modified: r.bool()?,
                start: r.i64()?,
                end: r.i64()?,
                max: r.u32()? as usize,
                bounds: r.bool()?,
            }),
            Some(ids::READ_AT_TIME_DETAILS_ENCODING) => {
                let times = r.array(8, |r| r.i64())?;
                let simple = r.bool()?;
                let _ = simple;
                Details::AtTime { times, stepped: false }
            }
            Some(ids::READ_PROCESSED_DETAILS_ENCODING) => {
                let start = r.i64()?;
                let end = r.i64()?;
                let interval_ms = r.f64()?;
                let aggregates = r.array(2, |r| r.node_id())?;
                let config = crate::aggregates::Config::decode(r)?;
                Details::Processed(ProcessedQuery { start, end, interval_ms, aggregates, config })
            }
            _ => return Err(crate::codec::DecodeError),
        })
    };
    match type_id.as_ns0() {
        Some(
            ids::READ_RAW_MODIFIED_DETAILS_ENCODING
            | ids::READ_AT_TIME_DETAILS_ENCODING
            | ids::READ_PROCESSED_DETAILS_ENCODING,
        ) => {
            let mut d = parse(&mut r).map_err(|_| status::BAD_HISTORY_OPERATION_INVALID)?;
            if let Details::Processed(q) = &mut d {
                q.config = q.config.revise()?;
                if q.start == 0 || q.end == 0 || q.start == q.end || q.interval_ms.is_nan() || q.interval_ms < 0.0 {
                    return Err(status::BAD_INVALID_TIMESTAMP_ARGUMENT);
                }
            }
            Ok(d)
        }
        Some(ids::READ_EVENT_DETAILS_ENCODING) => Err(status::BAD_HISTORY_OPERATION_UNSUPPORTED),
        _ => Err(status::BAD_HISTORY_OPERATION_INVALID),
    }
}

/// The history of a node, or why it has none.
fn history_of<'s>(space: &'s crate::address_space::AddressSpace, id: &NodeId, bit: u8) -> Result<&'s History, u32> {
    use crate::address_space::{NodeKind, ValueSource};
    let node = space.get(id).ok_or(status::BAD_NODE_ID_UNKNOWN)?;
    let NodeKind::Variable { access, value, .. } = &node.kind else {
        return Err(status::BAD_HISTORY_OPERATION_UNSUPPORTED);
    };
    let ValueSource::Cell(cell) = value else {
        return Err(status::BAD_HISTORY_OPERATION_UNSUPPORTED);
    };
    let h = cell.history().ok_or(status::BAD_HISTORY_OPERATION_UNSUPPORTED)?;
    if access & bit == 0 {
        return Err(if bit == ACCESS_HISTORY_READ { status::BAD_NOT_READABLE } else { status::BAD_NOT_WRITABLE });
    }
    Ok(h)
}

/// One DataValue of a history result, encoded from a stored sample.
#[inline]
fn write_sample(w: &mut Writer, s: &Sample, ts: (bool, bool), range: Option<(usize, usize)>) {
    let ranged;
    let (value, code) = match (&s.value, range) {
        (Variant::Empty, _) => (None, s.status),
        (v, Some(r)) => match crate::services::apply_range(v, r) {
            Ok(v) => {
                ranged = v;
                (Some(&ranged), s.status)
            }
            Err(c) => (None, c),
        },
        (v, None) => (Some(v), s.status),
    };
    let bad = code != status::GOOD;
    w.u8(value.is_some() as u8 | (bad as u8) << 1 | (ts.0 as u8) << 2 | (ts.1 as u8) << 3);
    if let Some(v) = value {
        w.variant(v);
    }
    if bad {
        w.u32(code);
    }
    if ts.0 {
        w.i64(s.source_ts);
    }
    if ts.1 {
        w.i64(s.server_ts);
    }
}

pub(crate) fn history_read(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let (type_id, _enc, body) = r.extension_object_raw().map_err(decode_err)?;
    let ttr = r.u32().map_err(decode_err)?;
    let ts = match ttr {
        0 => (true, false),
        1 => (false, true),
        2 => (true, true),
        _ => return Err(status::BAD_TIMESTAMPS_TO_RETURN_INVALID),
    };
    let release = r.bool().map_err(decode_err)?;
    // NodeId (2) + range (4) + encoding (6) + continuation point (4).
    let n = r.length(16).map_err(decode_err)?.unwrap_or(0);
    if n == 0 {
        return Err(status::BAD_NOTHING_TO_DO);
    }
    check_count(ctx, n)?;
    let details = parse_details(&type_id, body)?;
    if let Details::Processed(q) = &details {
        if q.aggregates.len() != n {
            return Err(status::BAD_AGGREGATE_LIST_MISMATCH);
        }
    }
    let _ = &s;
    let space = ctx.server.store.cached(ctx.space);
    begin(w, ids::HISTORY_READ_RESPONSE, h);
    w.i32(n as i32);
    let (mut body_buf, mut mods_buf) = (Vec::new(), Vec::new());
    let (body, mods) = (&mut body_buf, &mut mods_buf);
    for node_index in 0..n {
        let id = r.node_id().map_err(decode_err)?;
        let range = r.str().map_err(decode_err)?;
        let (_, enc_name) = r.qualified_name_ref().map_err(decode_err)?;
        let cp = r.bytes().map_err(decode_err)?.filter(|b| !b.is_empty());
        let range = match range.filter(|x| !x.is_empty()).map(crate::services::parse_range) {
            None => None,
            Some(Ok(r)) => Some(r),
            Some(Err(true)) => {
                w.u32(status::BAD_INDEX_RANGE_INVALID);
                w.bytes(None);
                w.null_extension_object();
                continue;
            }
            Some(Err(false)) => Some((usize::MAX, usize::MAX)),
        };
        let result = (|| -> Result<NodeResult, u32> {
            let hist = history_of(space, &id, ACCESS_HISTORY_READ)?;
            if enc_name.is_some_and(|e| !e.is_empty()) {
                return Err(status::BAD_DATA_ENCODING_UNSUPPORTED);
            }
            let kind = match &details {
                Details::Raw(q) if q.modified => CP_MODIFIED,
                Details::Raw(_) => CP_RAW,
                Details::AtTime { .. } => CP_AT_TIME,
                Details::Processed(_) => CP_PROCESSED,
            };
            let resume = cp.map(|b| cp_decode(&id, kind, b)).transpose()?;
            if release {
                return Ok((status::GOOD, None, None));
            }
            match &details {
                Details::Raw(q) => {
                    // HistoryData { DataValues } or HistoryModifiedData
                    // { DataValues, ModificationInfos }, encoded under the
                    // history lock straight from the stored samples.
                    body.clear();
                    mods.clear();
                    let mut wb = Writer::new(body);
                    let mut wm = Writer::new(mods);
                    wb.i32(0);
                    wm.i32(0);
                    let mut count = 0u32;
                    let more = hist.read_raw_with(q, resume, |s, m| {
                        count += 1;
                        write_sample(&mut wb, s, ts, range);
                        if let Some((time, kind, user)) = m {
                            wm.i64(time);
                            wm.u32(kind);
                            wm.str(Some(user));
                        }
                    })?;
                    wb.patch_u32(0, count);
                    let ty = if q.modified {
                        wm.patch_u32(0, count);
                        wb.raw(mods);
                        ids::HISTORY_MODIFIED_DATA_ENCODING
                    } else {
                        ids::HISTORY_DATA_ENCODING
                    };
                    let code = if count == 0 && more.is_none() { status::GOOD_NO_DATA } else { status::GOOD };
                    Ok((code, more.map(|m| cp_encode(&id, kind, m)), Some(ty)))
                }
                Details::AtTime { times, stepped } => {
                    let from = resume.map_or(0, |r| r.skip as usize).min(times.len());
                    let to = (from + MAX_RETURN_VALUES).min(times.len());
                    let samples = hist.read_at_time(&times[from..to], *stepped);
                    let more = (to < times.len()).then(|| cp_encode(&id, kind, Resume { ts: 0, skip: to as u32 }));
                    body.clear();
                    let mut wb = Writer::new(body);
                    wb.i32(samples.len() as i32);
                    for s in &samples {
                        write_sample(&mut wb, s, ts, range);
                    }
                    Ok((status::GOOD, more, Some(ids::HISTORY_DATA_ENCODING)))
                }
                Details::Processed(q) => {
                    use crate::aggregates as agg;
                    let a = agg::supported(&q.aggregates[node_index]).ok_or(status::BAD_AGGREGATE_NOT_SUPPORTED)?;
                    if !agg::accepts(a, hist.kind()) {
                        return Err(status::BAD_AGGREGATE_INVALID_INPUTS);
                    }
                    let total = agg::interval_count(q.start, q.end, q.interval_ms);
                    let from = resume.map_or(0, |r| r.skip as usize).min(total);
                    let to = (from + MAX_RETURN_VALUES).min(total);
                    let (before, values, after) = hist.window(q.start.min(q.end), q.start.max(q.end));
                    body.clear();
                    let mut wb = Writer::new(body);
                    wb.i32((to - from) as i32);
                    for (s, e, partial, t) in agg::intervals(q.start, q.end, q.interval_ms).skip(from).take(to - from) {
                        let a_ = values.partition_point(|x| x.source_ts < s);
                        let b_ = values.partition_point(|x| x.source_ts < e);
                        let window = agg::Window {
                            before: if a_ > 0 { values.get(a_ - 1) } else { before.as_ref() },
                            values: &values[a_..b_],
                            after: values.get(b_).or(after.as_ref()),
                        };
                        let out = agg::compute(a, hist.kind(), false, &q.config, s, e, partial, t, &window);
                        write_sample(&mut wb, &out, ts, range);
                    }
                    let more = (to < total).then(|| cp_encode(&id, kind, Resume { ts: 0, skip: to as u32 }));
                    Ok((status::GOOD, more, Some(ids::HISTORY_DATA_ENCODING)))
                }
            }
        })();
        match result {
            Err(code) => {
                w.u32(code);
                w.bytes(None);
                w.null_extension_object();
            }
            Ok((code, cp, data)) => {
                w.u32(code);
                w.bytes(cp.as_deref());
                match data {
                    None => w.null_extension_object(),
                    Some(ty) => {
                        let at = w.begin_extension_object(ty);
                        w.raw(body);
                        w.end_extension_object(at);
                    }
                }
            }
        }
    }
    w.empty_array(); // diagnosticInfos
    Ok(())
}

/// (status, continuation point, encoding id of the result in `body`).
type NodeResult = (u32, Option<Vec<u8>>, Option<u32>);

/// User name recorded in ModificationInfo.
fn user_name(identity: &str) -> Arc<str> {
    identity.strip_prefix("user:").unwrap_or(identity).into()
}

pub(crate) fn history_update(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let can_write = s.can_write.load(Ordering::Relaxed);
    let user = user_name(&s.identity.lock().unwrap_or_else(|e| e.into_inner()));
    let n = r.length(3).map_err(decode_err)?.unwrap_or(0);
    if n == 0 {
        return Err(status::BAD_NOTHING_TO_DO);
    }
    check_count(ctx, n)?;
    let space = ctx.server.store.cached(ctx.space);
    let now = now_ticks();
    begin(w, ids::HISTORY_UPDATE_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let (type_id, _enc, body) = r.extension_object_raw().map_err(decode_err)?;
        let mut b = Reader::new(body);
        let (code, ops) = (|| -> Result<(u32, Vec<u32>), u32> {
            let bad = |_| status::BAD_HISTORY_OPERATION_INVALID;
            match type_id.as_ns0() {
                Some(ids::UPDATE_DATA_DETAILS_ENCODING) => {
                    let id = b.node_id().map_err(bad)?;
                    let mode = b.u32().map_err(bad)?;
                    let values = b.array(1, |r| r.data_value()).map_err(bad)?;
                    let hist = check_update(space, &id, can_write)?;
                    if !(UPDATE_INSERT..=UPDATE_UPDATE).contains(&mode) {
                        return Err(status::BAD_HISTORY_OPERATION_INVALID);
                    }
                    let ops = values
                        .into_iter()
                        .map(|dv| {
                            let Some(src) = dv.source_timestamp else {
                                return status::BAD_INVALID_TIMESTAMP_ARGUMENT;
                            };
                            let value = dv.value.unwrap_or_default();
                            if value.type_id() != hist.kind() && !matches!(value, Variant::Empty) {
                                return status::BAD_TYPE_MISMATCH;
                            }
                            let sample = Sample {
                                value,
                                status: dv.status.unwrap_or(status::GOOD),
                                source_ts: src,
                                server_ts: dv.server_timestamp.unwrap_or(now),
                            };
                            hist.update(mode, sample, &user, now)
                        })
                        .collect();
                    Ok((status::GOOD, ops))
                }
                Some(ids::DELETE_RAW_MODIFIED_DETAILS_ENCODING) => {
                    let id = b.node_id().map_err(bad)?;
                    let modified = b.bool().map_err(bad)?;
                    let start = b.i64().map_err(bad)?;
                    let end = b.i64().map_err(bad)?;
                    let hist = check_update(space, &id, can_write)?;
                    if start == 0 || end == 0 {
                        return Err(status::BAD_INVALID_TIMESTAMP_ARGUMENT);
                    }
                    let n = hist.delete_raw(modified, start, end, &user, now);
                    Ok((if n == 0 { status::BAD_NO_DATA } else { status::GOOD }, Vec::new()))
                }
                Some(ids::DELETE_AT_TIME_DETAILS_ENCODING) => {
                    let id = b.node_id().map_err(bad)?;
                    let times = b.array(8, |r| r.i64()).map_err(bad)?;
                    let hist = check_update(space, &id, can_write)?;
                    Ok((status::GOOD, times.into_iter().map(|t| hist.delete_at(t, &user, now)).collect()))
                }
                Some(ids::UPDATE_EVENT_DETAILS_ENCODING | ids::DELETE_EVENT_DETAILS_ENCODING) => {
                    Err(status::BAD_HISTORY_OPERATION_UNSUPPORTED)
                }
                _ => Err(status::BAD_HISTORY_OPERATION_INVALID),
            }
        })()
        .unwrap_or_else(|code| (code, Vec::new()));
        w.u32(code);
        w.i32(ops.len() as i32);
        for c in ops {
            w.u32(c);
        }
        w.empty_array(); // diagnosticInfos
    }
    w.empty_array();
    Ok(())
}

fn check_update<'s>(
    space: &'s crate::address_space::AddressSpace,
    id: &NodeId,
    can_write: bool,
) -> Result<&'s History, u32> {
    let h = history_of(space, id, ACCESS_HISTORY_WRITE)?;
    if !can_write {
        return Err(status::BAD_USER_ACCESS_DENIED);
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(ts: i64, v: f64) -> Sample {
        Sample { value: Variant::Double(v), status: status::GOOD, source_ts: ts, server_ts: ts }
    }

    fn hist(points: &[(i64, f64)]) -> History {
        let h = History::new(builtin::DOUBLE, 100);
        for &(t, v) in points {
            h.record(s(t, v));
        }
        h
    }

    fn ts(e: &[Entry]) -> Vec<i64> {
        e.iter().map(|e| e.sample.source_ts).collect()
    }

    fn q(start: i64, end: i64, max: usize, bounds: bool) -> RawQuery {
        RawQuery { modified: false, start, end, max, bounds }
    }

    #[test]
    fn ring_keeps_order_and_capacity() {
        let h = History::new(builtin::DOUBLE, 3);
        for t in [10, 30, 20, 40] {
            h.record(s(t, t as f64));
        }
        let (e, _) = h.read_raw(&q(1, 100, 0, false), None).unwrap();
        assert_eq!(ts(&e), vec![20, 30, 40]);
    }

    #[test]
    fn raw_ranges_bounds_and_paging() {
        let h = hist(&[(10, 1.0), (20, 2.0), (30, 3.0), (40, 4.0), (50, 5.0)]);
        // Forward, end exclusive.
        assert_eq!(ts(&h.read_raw(&q(20, 40, 0, false), None).unwrap().0), vec![20, 30]);
        // Reverse.
        assert_eq!(ts(&h.read_raw(&q(40, 20, 0, false), None).unwrap().0), vec![40, 30]);
        // Exact time.
        assert_eq!(ts(&h.read_raw(&q(30, 30, 0, false), None).unwrap().0), vec![30]);
        // Bounds.
        assert_eq!(ts(&h.read_raw(&q(25, 45, 0, true), None).unwrap().0), vec![20, 30, 40, 50]);
        let (e, _) = h.read_raw(&q(5, 60, 0, true), None).unwrap();
        assert_eq!(ts(&e), vec![5, 10, 20, 30, 40, 50, 60]);
        assert_eq!(e[0].sample.status, status::BAD_BOUND_NOT_FOUND);
        assert_eq!(e[6].sample.status, status::BAD_BOUND_NOT_FOUND);
        // Only a start or an end.
        assert_eq!(ts(&h.read_raw(&q(25, 0, 2, false), None).unwrap().0), vec![30, 40]);
        assert_eq!(ts(&h.read_raw(&q(0, 35, 2, false), None).unwrap().0), vec![30, 20]);
        assert_eq!(h.read_raw(&q(0, 0, 2, false), None).unwrap_err(), status::BAD_INVALID_TIMESTAMP_ARGUMENT);
        assert_eq!(h.read_raw(&q(10, 0, 0, false), None).unwrap_err(), status::BAD_INVALID_TIMESTAMP_ARGUMENT);
        // Paging forward and backward, with bounds.
        for (query, want) in [
            (q(1, 100, 2, false), vec![10, 20, 30, 40, 50]),
            (q(100, 1, 2, false), vec![50, 40, 30, 20, 10]),
            (q(15, 45, 2, true), vec![10, 20, 30, 40, 50]),
            (q(45, 15, 1, true), vec![50, 40, 30, 20, 10]),
        ] {
            let mut all = Vec::new();
            let mut resume = None;
            loop {
                let (e, more) = h.read_raw(&query, resume).unwrap();
                assert!(e.len() <= query.max);
                all.extend(ts(&e));
                match more {
                    Some(m) => resume = Some(m),
                    None => break,
                }
            }
            assert_eq!(all, want, "{query:?}");
        }
    }

    #[test]
    fn paging_over_equal_timestamps() {
        let h = hist(&[(10, 1.0), (10, 2.0), (10, 3.0), (20, 4.0)]);
        let query = q(1, 100, 1, false);
        let mut values = Vec::new();
        let mut resume = None;
        loop {
            let (e, more) = h.read_raw(&query, resume).unwrap();
            values.extend(e.iter().map(|e| e.sample.value.clone()));
            match more {
                Some(m) => resume = Some(m),
                None => break,
            }
        }
        let want: Vec<Variant> = [1.0, 2.0, 3.0, 4.0].into_iter().map(Variant::Double).collect();
        assert_eq!(values, want);
    }

    #[test]
    fn at_time_interpolates() {
        let h = hist(&[(10, 1.0), (20, 3.0)]);
        let v = h.read_at_time(&[5, 10, 15, 25], false);
        assert_eq!(v[0].status, status::BAD_NO_DATA);
        assert_eq!((v[1].value.clone(), v[1].status), (Variant::Double(1.0), status::GOOD));
        assert_eq!((v[2].value.clone(), v[2].status), (Variant::Double(2.0), INTERPOLATED));
        assert_eq!(v[3].status, status::UNCERTAIN_DATA_SUB_NORMAL | INTERPOLATED);
    }

    #[test]
    fn updates_and_deletes() {
        let h = hist(&[(10, 1.0), (20, 2.0)]);
        let u: Arc<str> = "bob".into();
        assert_eq!(h.update(UPDATE_INSERT, s(10, 9.0), &u, 1), status::BAD_ENTRY_EXISTS);
        assert_eq!(h.update(UPDATE_INSERT, s(15, 1.5), &u, 1), status::GOOD_ENTRY_INSERTED);
        assert_eq!(h.update(UPDATE_REPLACE, s(30, 3.0), &u, 1), status::BAD_NO_ENTRY_EXISTS);
        assert_eq!(h.update(UPDATE_REPLACE, s(20, 2.5), &u, 2), status::GOOD_ENTRY_REPLACED);
        assert_eq!(h.update(UPDATE_UPDATE, s(30, 3.0), &u, 3), status::GOOD_ENTRY_INSERTED);
        let (e, _) = h.read_raw(&q(1, 100, 0, false), None).unwrap();
        assert_eq!(ts(&e), vec![10, 15, 20, 30]);
        assert_eq!(e[2].sample.value, Variant::Double(2.5));
        let modified = RawQuery { modified: true, ..q(1, 100, 0, false) };
        let (m, _) = h.read_raw(&modified, None).unwrap();
        assert_eq!(ts(&m), vec![15, 20, 30]);
        assert_eq!(m[1].sample.value, Variant::Double(2.0));
        assert_eq!(m[1].modification, Some((2, UPDATE_REPLACE, u.clone())));
        assert_eq!(h.delete_at(15, &u, 4), status::GOOD);
        assert_eq!(h.delete_at(15, &u, 4), status::BAD_NO_ENTRY_EXISTS);
        assert_eq!(h.delete_raw(false, 20, 100, &u, 5), 2);
        assert_eq!(ts(&h.read_raw(&q(1, 100, 0, false), None).unwrap().0), vec![10]);
        assert_eq!(h.delete_raw(true, 1, 100, &u, 6), 6);
    }
}
