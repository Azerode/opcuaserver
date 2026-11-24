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
    seq: AtomicU32,
    bits: AtomicU64,
    status: AtomicU32,
    source_ts: AtomicI64,
    server_ts: AtomicI64,
    blob: Mutex<Variant>,
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
