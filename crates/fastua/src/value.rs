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

use crate::types::{builtin, status, DataValue, Variant};
use std::sync::atomic::{fence, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

pub struct ValueCell {
    kind: u8,
    /// Encoded size of an inline kind, 0 for String / ByteString / Guid.
    size: u8,
    seq: AtomicU32,
    bits: AtomicU64,
    status: AtomicU32,
    source_ts: AtomicI64,
    server_ts: AtomicI64,
    blob: Mutex<Variant>,
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
    pub fn new(kind: u8, created: i64) -> Self {
        ValueCell {
            kind,
            size: inline_size(kind),
            seq: AtomicU32::new(0),
            bits: AtomicU64::new(0),
            status: AtomicU32::new(status::UNCERTAIN_INITIAL_VALUE),
            source_ts: AtomicI64::new(created),
            server_ts: AtomicI64::new(created),
            blob: Mutex::new(default_value(kind)),
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
            self.seq.fetch_add(2, Ordering::Release);
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
