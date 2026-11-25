//! Lock-free storage for the current value of a variable.
//!
//! Numeric scalars (the overwhelming majority of industrial data points) live
//! in a seqlock: readers never block and never write to shared memory, so many
//! clients reading the same node do not bounce the cache line between cores.
//! Variable-length values (String, ByteString) fall back to a short mutex.
//!
//! Cells are reference-counted and owned by the address space snapshot. On a
//! configuration reload, a node that keeps the same NodeId and data type keeps
//! the very same cell, so its value survives and in-flight writes are not lost.

use crate::history::History;
use crate::types::{builtin, status, DataValue, Variant};
use std::sync::atomic::{fence, AtomicI64, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

pub struct ValueCell {
    kind: u8,
    /// Encoded size of an inline kind, 0 for String / ByteString / Guid.
    size: u8,
    /// What a write does besides storing the value ([`HOOK_HISTORY`],
    /// [`HOOK_ALARM`]). Next to `kind`: in padding, on the cache line every
    /// write touches anyway, and one test for all hooks.
    hooks: AtomicU8,
    seq: AtomicU32,
    bits: AtomicU64,
    status: AtomicU32,
    source_ts: AtomicI64,
    server_ts: AtomicI64,
    blob: Mutex<Variant>,
    /// Change stamp shared by up to [`BLOCK`] cells: every write stores a
    /// value unique to (cell, write) into it, so a sampling pass skips a
    /// whole block of unchanged cells with one load.
    stamp: &'static AtomicU32,
    /// Position in the block (top 6 bits of every stamp this cell stores).
    lane: u32,
    /// History and alarm, allocated for the variables that have one (one
    /// pointer keeps the cell small).
    /// Set once (never replaced), freed with the cell: one load to reach it.
    extras: std::sync::atomic::AtomicPtr<Extras>,
}

impl Drop for ValueCell {
    fn drop(&mut self) {
        let p = *self.extras.get_mut();
        if !p.is_null() {
            // SAFETY: created by Box::into_raw in `extras()`, owned by the cell.
            drop(unsafe { Box::from_raw(p) });
        }
    }
}

#[derive(Default)]
struct Extras {
    /// Kept when historizing is switched off, so data survives a reload
    /// that switches it back on.
    history: OnceLock<History>,
    /// Condition evaluated on every write (variables with an Alarm).
    alarm: arc_swap::ArcSwapOption<crate::alarms::Condition>,
}

/// Writes are recorded in the history.
pub const HOOK_HISTORY: u8 = 1;
/// Writes are evaluated by an alarm condition.
pub const HOOK_ALARM: u8 = 2;

/// Cells per change stamp.
pub const BLOCK: usize = 64;

/// Allocates a change stamp. Stamps live as long as the process: cells keep
/// them across reloads and a few bytes per 64 cells are never worth freeing.
pub fn new_stamp() -> &'static AtomicU32 {
    Box::leak(Box::new(AtomicU32::new(0)))
}

/// Raw state of an inline cell: what [`encode_raw`] needs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Raw {
    pub seq: u32,
    pub bits: u64,
    pub status: u32,
    pub source_ts: i64,
    pub server_ts: i64,
}

/// One consistent copy of a cell.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub value: Variant,
    pub status: u32,
    pub source_ts: i64,
    pub server_ts: i64,
}

#[inline(always)]
fn is_inline(kind: u8) -> bool {
    matches!(kind, builtin::BOOLEAN..=builtin::DOUBLE | builtin::DATETIME)
}

#[inline(always)]
fn to_bits(v: &Variant) -> u64 {
    match *v {
        Variant::Boolean(x) => x as u64,
        Variant::SByte(x) => x as u8 as u64,
        Variant::Byte(x) => x as u64,
        Variant::Int16(x) => x as u16 as u64,
        Variant::UInt16(x) => x as u64,
        Variant::Int32(x) => x as u32 as u64,
        Variant::UInt32(x) => x as u64,
        Variant::Int64(x) => x as u64,
        Variant::UInt64(x) => x,
        Variant::Float(x) => x.to_bits() as u64,
        Variant::Double(x) => x.to_bits(),
        Variant::DateTime(x) => x as u64,
        _ => 0,
    }
}

#[inline(always)]
fn from_bits(kind: u8, b: u64) -> Variant {
    use builtin::*;
    match kind {
        BOOLEAN => Variant::Boolean(b != 0),
        SBYTE => Variant::SByte(b as u8 as i8),
        BYTE => Variant::Byte(b as u8),
        INT16 => Variant::Int16(b as u16 as i16),
        UINT16 => Variant::UInt16(b as u16),
        INT32 => Variant::Int32(b as u32 as i32),
        UINT32 => Variant::UInt32(b as u32),
        INT64 => Variant::Int64(b as i64),
        UINT64 => Variant::UInt64(b),
        FLOAT => Variant::Float(f32::from_bits(b as u32)),
        DOUBLE => Variant::Double(f64::from_bits(b)),
        DATETIME => Variant::DateTime(b as i64),
        _ => Variant::Empty,
    }
}

#[inline(always)]
fn inline_size(kind: u8) -> u8 {
    use builtin::*;
    match kind {
        BOOLEAN | SBYTE | BYTE => 1,
        INT16 | UINT16 => 2,
        INT32 | UINT32 | FLOAT => 4,
        INT64 | UINT64 | DOUBLE | DATETIME => 8,
        _ => 0,
    }
}

/// Largest DataValue [`ValueCell::encode`] produces: mask, type, 8-byte value,
/// status and two timestamps.
pub const ENCODED_MAX: usize = 1 + 1 + 8 + 4 + 8 + 8;

/// Encodes an inline value (`size` from [`ValueCell::inline_size`]) as a
/// DataValue into `out`; returns the length. A `source_ts` of
/// [`NO_SOURCE_TS`] leaves the source timestamp out.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn encode_raw(
    kind: u8,
    size: u8,
    bits: u64,
    st: u32,
    src: i64,
    srv: i64,
    source: bool,
    server: bool,
    out: &mut [u8; ENCODED_MAX],
) -> usize {
    let size = size as usize;
    let source = source && src != NO_SOURCE_TS;
    let bad = st != status::GOOD;
    out[0] = 0x01 | (bad as u8) << 1 | (source as u8) << 2 | (server as u8) << 3;
    out[1] = kind;
    // Bits are stored zero-extended little-endian: the first `size` bytes
    // are the encoding of the value.
    out[2..10].copy_from_slice(&bits.to_le_bytes());
    let mut n = 2 + size;
    out[n..n + 4].copy_from_slice(&st.to_le_bytes());
    n += 4 * bad as usize;
    out[n..n + 8].copy_from_slice(&src.to_le_bytes());
    n += 8 * source as usize;
    out[n..n + 8].copy_from_slice(&srv.to_le_bytes());
    n += 8 * server as usize;
    n
}

/// Marks a value without a source timestamp (attributes other than Value).
pub const NO_SOURCE_TS: i64 = i64::MIN;

/// Value of an inline numeric kind as f64 (deadband filters).
#[inline(always)]
pub fn bits_as_f64(kind: u8, b: u64) -> Option<f64> {
    use builtin::*;
    Some(match kind {
        SBYTE => b as u8 as i8 as f64,
        BYTE => b as u8 as f64,
        INT16 => b as u16 as i16 as f64,
        UINT16 => b as u16 as f64,
        INT32 => b as u32 as i32 as f64,
        UINT32 => b as u32 as f64,
        INT64 => b as i64 as f64,
        UINT64 => b as f64,
        FLOAT => f32::from_bits(b as u32) as f64,
        DOUBLE => f64::from_bits(b),
        _ => return None,
    })
}

/// Value of a numeric Variant as f64 (deadband filters).
pub fn variant_as_f64(v: &Variant) -> Option<f64> {
    let k = v.type_id();
    is_inline(k).then(|| bits_as_f64(k, to_bits(v))).flatten()
}

/// A numeric value of type `kind` from f64 (interpolation, aggregates);
/// integers are rounded and saturated.
pub fn variant_from_f64(kind: u8, f: f64) -> Option<Variant> {
    use builtin::*;
    let r = f.round();
    Some(match kind {
        SBYTE => Variant::SByte(r as i8),
        BYTE => Variant::Byte(r as u8),
        INT16 => Variant::Int16(r as i16),
        UINT16 => Variant::UInt16(r as u16),
        INT32 => Variant::Int32(r as i32),
        UINT32 => Variant::UInt32(r as u32),
        INT64 => Variant::Int64(r as i64),
        UINT64 => Variant::UInt64(r as u64),
        FLOAT => Variant::Float(f as f32),
        DOUBLE => Variant::Double(f),
        _ => return None,
    })
}

/// Default (zero) value of a built-in type.
pub fn default_value(kind: u8) -> Variant {
    match kind {
        builtin::STRING => Variant::String(Some("".into())),
        builtin::BYTESTRING => Variant::ByteString(Some(Box::new([]))),
        builtin::GUID => Variant::Guid([0; 16]),
        k if is_inline(k) => from_bits(k, 0),
        _ => Variant::Empty,
    }
}

impl ValueCell {
    /// A cell with a change stamp of its own.
    pub fn new(kind: u8, created: i64) -> Self {
        Self::with_stamp(kind, created, new_stamp(), 0)
    }

    /// A cell sharing `stamp` with other cells; `lane` < [`BLOCK`] tells the
    /// cells of one stamp apart.
    pub fn with_stamp(kind: u8, created: i64, stamp: &'static AtomicU32, lane: u32) -> Self {
        debug_assert!((lane as usize) < BLOCK);
        ValueCell {
            stamp,
            lane,
            kind,
            size: inline_size(kind),
            seq: AtomicU32::new(0),
            bits: AtomicU64::new(0),
            status: AtomicU32::new(status::UNCERTAIN_INITIAL_VALUE),
            source_ts: AtomicI64::new(created),
            server_ts: AtomicI64::new(created),
            blob: Mutex::new(default_value(kind)),
            hooks: AtomicU8::new(0),
            extras: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    /// Starts (`Some(capacity)`) or stops recording writes.
    #[cold]
    pub fn set_history(&self, capacity: Option<usize>) {
        match capacity {
            Some(cap) => {
                self.extras().history.get_or_init(|| History::new(self.kind, cap)).set_capacity(cap);
                self.hooks.fetch_or(HOOK_HISTORY, Ordering::Release);
            }
            None => {
                self.hooks.fetch_and(!HOOK_HISTORY, Ordering::Release);
            }
        }
    }

    /// Sets (or removes) the condition evaluated on every write.
    #[cold]
    pub fn set_alarm(&self, c: Option<std::sync::Arc<crate::alarms::Condition>>) {
        let on = c.is_some();
        if on || self.extras_get().is_some() {
            self.extras().alarm.store(c);
        }
        if on {
            self.hooks.fetch_or(HOOK_ALARM, Ordering::Release);
        } else {
            self.hooks.fetch_and(!HOOK_ALARM, Ordering::Release);
        }
    }

    /// The condition of a variable with an Alarm.
    pub fn alarm(&self) -> Option<std::sync::Arc<crate::alarms::Condition>> {
        self.extras_get()?.alarm.load_full()
    }

    #[inline]
    fn extras_get(&self) -> Option<&Extras> {
        // SAFETY: non-null pointers come from Box::into_raw and live as long
        // as the cell.
        unsafe { self.extras.load(Ordering::Acquire).as_ref() }
    }

    #[cold]
    fn extras(&self) -> &Extras {
        if let Some(x) = self.extras_get() {
            return x;
        }
        let new = Box::into_raw(Box::<Extras>::default());
        match self.extras.compare_exchange(std::ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire) {
            // SAFETY: just published, owned by the cell.
            Ok(_) => unsafe { &*new },
            Err(cur) => {
                // SAFETY: `new` was never shared; `cur` is owned by the cell.
                drop(unsafe { Box::from_raw(new) });
                unsafe { &*cur }
            }
        }
    }

    /// History of a historizing cell.
    pub fn history(&self) -> Option<&History> {
        if self.hooks.load(Ordering::Acquire) & HOOK_HISTORY != 0 {
            self.extras_get()?.history.get()
        } else {
            None
        }
    }

    /// History and alarm hooks of a write (never inlined: off the path of
    /// variables without hooks).
    #[cold]
    #[inline(never)]
    fn run_hooks(&self, hooks: u8, value: &Variant, status: u32, source_ts: i64, server_ts: i64) {
        let Some(x) = self.extras_get() else { return };
        if hooks & HOOK_HISTORY != 0 {
            if let Some(h) = x.history.get() {
                h.record(Sample { value: value.clone(), status, source_ts, server_ts });
            }
        }
        if hooks & HOOK_ALARM != 0 {
            if let Some(c) = &*x.alarm.load() {
                c.evaluate(value, status, source_ts);
            }
        }
    }

    #[inline(always)]
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// Encodes the current value as a DataValue straight into `out`, without
    /// building a `Variant`. Returns the encoded length, or `None` for the
    /// variable-length kinds (use [`ValueCell::read`]).
    #[inline(always)]
    pub fn encode(&self, source: bool, server: bool, out: &mut [u8; ENCODED_MAX]) -> Option<usize> {
        if self.size == 0 {
            return None;
        }
        let r = self.raw();
        Some(encode_raw(self.kind, self.size, r.bits, r.status, r.source_ts, r.server_ts, source, server, out))
    }

    /// Encoded size of an inline kind, 0 for String / ByteString / Guid.
    #[inline(always)]
    pub fn inline_size(&self) -> u8 {
        self.size
    }

    /// Change counter: different after every write (even for String /
    /// ByteString). One load, no shared write: what a sampling loop checks
    /// before reading anything else.
    #[inline(always)]
    pub fn version(&self) -> u32 {
        self.seq.load(Ordering::Acquire)
    }

    /// [`ValueCell::version`] without ordering: for change detection after
    /// an Acquire load of the cell's stamp (a plain load on aarch64 instead
    /// of `ldar`, which would serialise a scan).
    #[inline(always)]
    pub fn version_relaxed(&self) -> u32 {
        self.seq.load(Ordering::Relaxed)
    }

    /// The change stamp of the cell's block.
    #[inline(always)]
    pub fn stamp(&self) -> &'static AtomicU32 {
        self.stamp
    }

    /// Publishes a write: after the cell's own release store, so a reader
    /// that sees the stamp sees the new value.
    #[inline(always)]
    fn publish(&self, seq: u32) {
        self.stamp.store((self.lane << 26) | ((seq >> 1) & 0x03FF_FFFF), Ordering::Release);
    }

    /// Consistent copy of an inline cell (see [`ValueCell::inline_size`]).
    #[inline(always)]
    pub fn raw(&self) -> Raw {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let bits = self.bits.load(Ordering::Relaxed);
            let status = self.status.load(Ordering::Relaxed);
            let source_ts = self.source_ts.load(Ordering::Relaxed);
            let server_ts = self.server_ts.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == s1 {
                return Raw { seq: s1, bits, status, source_ts, server_ts };
            }
        }
    }

    /// Reads a consistent sample. Wait-free for readers unless a writer is
    /// in the middle of its (few nanoseconds long) critical section.
    #[inline]
    pub fn read(&self) -> Sample {
        if !is_inline(self.kind) {
            let blob = self.blob.lock().unwrap_or_else(|e| e.into_inner());
            return Sample {
                value: blob.clone(),
                status: self.status.load(Ordering::Relaxed),
                source_ts: self.source_ts.load(Ordering::Relaxed),
                server_ts: self.server_ts.load(Ordering::Relaxed),
            };
        }
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let bits = self.bits.load(Ordering::Relaxed);
            let st = self.status.load(Ordering::Relaxed);
            let src = self.source_ts.load(Ordering::Relaxed);
            let srv = self.server_ts.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == s1 {
                return Sample { value: from_bits(self.kind, bits), status: st, source_ts: src, server_ts: srv };
            }
        }
    }

    /// Stores a new value. The caller has already checked the type.
    #[inline]
    pub fn write(&self, value: &Variant, status: u32, source_ts: i64, server_ts: i64) {
        if !is_inline(self.kind) {
            let mut blob = self.blob.lock().unwrap_or_else(|e| e.into_inner());
            *blob = value.clone();
            self.status.store(status, Ordering::Relaxed);
            self.source_ts.store(source_ts, Ordering::Relaxed);
            self.server_ts.store(server_ts, Ordering::Relaxed);
            // Only a change counter here (readers take the mutex).
            let seq = self.seq.fetch_add(2, Ordering::Release).wrapping_add(2);
            drop(blob);
            self.publish(seq);
            let hooks = self.hooks.load(Ordering::Relaxed);
            if hooks != 0 {
                self.run_hooks(hooks, value, status, source_ts, server_ts);
            }
            return;
        }
        // Writers serialise on the odd sequence number.
        let mut s = self.seq.load(Ordering::Relaxed);
        loop {
            if s & 1 == 0 {
                match self.seq.compare_exchange_weak(s, s.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(cur) => s = cur,
                }
            } else {
                std::hint::spin_loop();
                s = self.seq.load(Ordering::Relaxed);
            }
        }
        fence(Ordering::Release);
        self.bits.store(to_bits(value), Ordering::Relaxed);
        self.status.store(status, Ordering::Relaxed);
        self.source_ts.store(source_ts, Ordering::Relaxed);
        self.server_ts.store(server_ts, Ordering::Relaxed);
        self.seq.store(s.wrapping_add(2), Ordering::Release);
        self.publish(s.wrapping_add(2));
        let hooks = self.hooks.load(Ordering::Relaxed);
        if hooks != 0 {
            self.run_hooks(hooks, value, status, source_ts, server_ts);
        }
    }

    pub fn to_data_value(&self) -> DataValue {
        let s = self.read();
        DataValue {
            value: Some(s.value),
            status: Some(s.status),
            source_timestamp: Some(s.source_ts),
            server_timestamp: Some(s.server_ts),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// `encode` must produce exactly what the generic Variant encoder does.
    #[test]
    fn encode_matches_generic_encoder() {
        use crate::codec::Writer;
        let values = [
            Variant::Boolean(true),
            Variant::SByte(-3),
            Variant::Byte(200),
            Variant::Int16(-7),
            Variant::UInt16(65000),
            Variant::Int32(-123456),
            Variant::UInt32(4_000_000_000),
            Variant::Int64(-1),
            Variant::UInt64(u64::MAX - 5),
            Variant::Float(1.5),
            Variant::Double(-2.25),
            Variant::DateTime(132_000_000_000_000_000),
        ];
        for v in values {
            let kind = v.type_id();
            for st in [status::GOOD, status::UNCERTAIN_INITIAL_VALUE] {
                let c = ValueCell::new(kind, 1);
                c.write(&v, st, 22, 33);
                for (src, srv) in [(false, false), (true, false), (false, true), (true, true)] {
                    let mut buf = [0u8; ENCODED_MAX];
                    let n = c.encode(src, srv, &mut buf).unwrap();
                    let mut want = Vec::new();
                    let mut w = Writer::new(&mut want);
                    let bad = st != status::GOOD;
                    w.u8(0x01 | (bad as u8) << 1 | (src as u8) << 2 | (srv as u8) << 3);
                    w.variant(&v);
                    if bad {
                        w.u32(st);
                    }
                    if src {
                        w.i64(22);
                    }
                    if srv {
                        w.i64(33);
                    }
                    assert_eq!(&buf[..n], &want[..], "{v:?} status {st:#x} src {src} srv {srv}");
                }
            }
        }
        assert!(ValueCell::new(builtin::STRING, 0).encode(true, true, &mut [0; ENCODED_MAX]).is_none());
    }

    #[test]
    fn write_then_read() {
        let c = ValueCell::new(builtin::INT16, 5);
        assert_eq!(c.read().value, Variant::Int16(0));
        assert_eq!(c.read().status, status::UNCERTAIN_INITIAL_VALUE);
        c.write(&Variant::Int16(-7), 0, 10, 11);
        assert_eq!(c.read(), Sample { value: Variant::Int16(-7), status: 0, source_ts: 10, server_ts: 11 });

        let s = ValueCell::new(builtin::STRING, 0);
        s.write(&Variant::string("abc"), 0, 1, 1);
        assert_eq!(s.read().value, Variant::string("abc"));
    }

    #[test]
    fn readers_never_see_torn_values() {
        let c = Arc::new(ValueCell::new(builtin::INT64, 0));
        let writers: Vec<_> = (0..2)
            .map(|w| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for i in 0..200_000i64 {
                        let v = i * 2 + w;
                        c.write(&Variant::Int64(v), 0, v, v);
                    }
                })
            })
            .collect();
        let reader = {
            let c = c.clone();
            std::thread::spawn(move || {
                for _ in 0..200_000 {
                    let s = c.read();
                    if let Variant::Int64(v) = s.value {
                        assert_eq!(v, s.source_ts);
                        assert_eq!(v, s.server_ts);
                    }
                }
            })
        };
        for w in writers {
            w.join().unwrap();
        }
        reader.join().unwrap();
    }
}

#[cfg(test)]
#[test]
fn cell_size() {
    // Hooks live behind one pointer: a bigger cell costs every write.
    assert!(std::mem::size_of::<ValueCell>() <= 88, "{}", std::mem::size_of::<ValueCell>());
}
