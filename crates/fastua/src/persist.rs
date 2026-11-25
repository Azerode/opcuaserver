//! History persistence across restarts (`--history-dir`).
//!
//! Writers never touch the disk: a recorded value is also pushed into the
//! history's journal (under the history lock the writer already takes, once
//! per 32 inline writes). A background thread wakes every interval, encodes
//! each journal under that lock and appends it to the variable's file, then
//! syncs it. HistoryUpdate changes, a damaged file, or a file that holds
//! more than twice the capacity make the next pass rewrite the whole file
//! (to a temporary file renamed over the old one).
//!
//! One file per historized variable, named by a hash of its namespace URI
//! and identifier (`<hex>.fh`): "FUAH", version, value kind, the key, then
//! records: tag 0 and a value (source timestamp, server timestamp, status,
//! Variant), or tag 1, a modification of HistoryUpdate (time, update type,
//! user) and its value. Appends hold values only; modifications are written
//! by the rewrite every HistoryUpdate causes. A crash loses at most the
//! last interval; a torn last record is dropped.

use crate::address_space::{AddressSpace, ValueSource};
use crate::codec::{Reader, Writer};
use crate::history::{History, Modified};
use crate::reload::Store;
use crate::types::NodeId;
use crate::value::Sample;
use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const MAGIC: &[u8; 4] = b"FUAH";
const VERSION: u8 = 2;

/// Writes the histories of a store to a directory.
pub struct Persistence {
    dir: PathBuf,
    /// Records in each file (by key), to know when to compact.
    records: HashMap<Box<str>, usize>,
    buf: Vec<u8>,
}

impl Persistence {
    pub fn open(dir: &Path) -> std::io::Result<Persistence> {
        std::fs::create_dir_all(dir)?;
        Ok(Persistence { dir: dir.to_path_buf(), records: HashMap::new(), buf: Vec::new() })
    }

    /// Restores every history not yet restored, then writes what was
    /// recorded since the last pass. Call once before serving, then every
    /// interval (see [`Persistence::spawn`]).
    pub fn pass(&mut self, space: &AddressSpace) {
        for node in &space.nodes {
            let crate::address_space::NodeKind::Variable { value: ValueSource::Cell(cell), .. } = &node.kind else {
                continue;
            };
            let Some(h) = cell.history() else { continue };
            let key = key(space, &node.id);
            let path = self.dir.join(format!("{:016x}.fh", fnv1a(key.as_bytes())));
            if !h.persisting() {
                let (restored, modified, rewrite) = read_file(&path, h.kind(), &key);
                self.records.insert(key.clone().into(), restored.len() + modified.len());
                h.start_persisting(restored, modified, rewrite);
            }
            if let Err(e) = self.write(h, &path, &key) {
                crate::log!("history persistence: {}: {e}", path.display());
                // What was taken may be missing from the file.
                h.request_rewrite();
            }
        }
    }

    fn write(&mut self, h: &History, path: &Path, key: &str) -> std::io::Result<()> {
        self.buf.clear();
        let mut w = Writer::new(&mut self.buf);
        let mut n = 0usize;
        let rewrite = h.take_for_disk(|s, m| {
            n += 1;
            match m {
                None => w.u8(0),
                Some(m) => {
                    w.u8(1);
                    w.i64(m.time);
                    w.u32(m.kind);
                    w.str(Some(&m.user));
                }
            }
            w.i64(s.source_ts);
            w.i64(s.server_ts);
            w.u32(s.status);
            w.variant(&s.value);
        });
        let records = self.records.entry(key.into()).or_default();
        if rewrite {
            let mut head = header(h.kind(), key);
            head.extend_from_slice(&self.buf);
            let tmp = path.with_extension("tmp");
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&head)?;
            f.sync_data()?;
            std::fs::rename(&tmp, path)?;
            *records = n;
        } else if n > 0 {
            let mut f = std::fs::OpenOptions::new().append(true).open(path).or_else(|_| {
                let mut f = std::fs::File::create(path)?;
                f.write_all(&header(h.kind(), key))?;
                Ok::<_, std::io::Error>(f)
            })?;
            f.write_all(&self.buf)?;
            f.sync_data()?;
            *records += n;
        }
        // Evicted values pile up in the file: compact it next pass.
        if *records > 2 * h.capacity() + 1024 {
            h.request_rewrite();
        }
        Ok(())
    }

    /// Runs [`Persistence::pass`] on the live address space every
    /// `interval`, on its own thread.
    pub fn spawn(mut self, store: Arc<Store>, interval: Duration) {
        std::thread::Builder::new()
            .name("history-persist".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                self.pass(&store.load_full());
            })
            .expect("cannot start the history persistence thread");
    }
}

/// Stable identity of a variable across restarts and namespace index
/// changes.
fn key(space: &AddressSpace, id: &NodeId) -> String {
    let (ns, ident) = match id {
        NodeId::Numeric(ns, i) => (*ns, format!("i={i}")),
        NodeId::String(ns, s) => (*ns, format!("s={s}")),
        NodeId::Guid(ns, g) => (*ns, format!("g={}", hex(g))),
        NodeId::Opaque(ns, b) => (*ns, format!("b={}", hex(b))),
    };
    let uri = space.namespaces.get(ns as usize).map_or("", |u| u);
    format!("{uri};{ident}")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// FNV-1a: stable across builds (std's hasher is not).
fn fnv1a(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325, |h, &x| (h ^ x as u64).wrapping_mul(0x0100_0000_01b3))
}

fn header(kind: u8, key: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + key.len());
    v.extend_from_slice(MAGIC);
    v.push(VERSION);
    v.push(kind);
    Writer::new(&mut v).str(Some(key));
    v
}

/// The values and modifications of a file, and whether it must be
/// rewritten (missing, of another kind or key, or with a torn record).
fn read_file(path: &Path, kind: u8, key: &str) -> (Vec<Sample>, Vec<Modified>, bool) {
    let Ok(data) = std::fs::read(path) else { return (Vec::new(), Vec::new(), true) };
    let head = header(kind, key);
    if !data.starts_with(&head) {
        if !data.is_empty() {
            crate::log!("history persistence: {} is not the history of {key}, replaced", path.display());
        }
        return (Vec::new(), Vec::new(), true);
    }
    let mut r = Reader::new(&data[head.len()..]);
    let (mut out, mut mods) = (Vec::new(), Vec::new());
    while r.remaining() > 0 {
        let rec = (|| {
            let tag = r.u8()?;
            let m = match tag {
                0 => None,
                1 => Some((r.i64()?, r.u32()?, r.str()?.unwrap_or("").into())),
                _ => return Err(crate::codec::DecodeError),
            };
            let s = Sample { source_ts: r.i64()?, server_ts: r.i64()?, status: r.u32()?, value: r.variant()? };
            Ok::<_, crate::codec::DecodeError>((s, m))
        })();
        match rec {
            Ok((s, None)) => out.push(s),
            Ok((sample, Some((time, kind, user)))) => mods.push(Modified { sample, time, kind, user }),
            Err(_) => {
                crate::log!("history persistence: {} ends with a torn record, dropped", path.display());
                return (out, mods, true);
            }
        }
    }
    (out, mods, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Variant;

    #[test]
    fn file_round_trip_and_torn_record() {
        let dir = std::env::temp_dir().join(format!("fastua-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.fh");
        let mut data = header(11, "urn:a;i=1");
        let mut w = Writer::new(&mut data);
        for t in 1..=3 {
            w.u8(0);
            w.i64(t);
            w.i64(t + 1);
            w.u32(0);
            w.variant(&Variant::Double(t as f64));
        }
        // A modification (deleted by "op").
        w.u8(1);
        w.i64(99);
        w.u32(crate::history::UPDATE_DELETE);
        w.str(Some("op"));
        w.i64(4);
        w.i64(4);
        w.u32(0);
        w.variant(&Variant::Double(4.0));
        std::fs::write(&path, &data).unwrap();
        let (v, m, rewrite) = read_file(&path, 11, "urn:a;i=1");
        assert_eq!(v.len(), 3);
        assert_eq!((m.len(), m[0].time, &*m[0].user), (1, 99, "op"));
        assert!(!rewrite);
        assert_eq!(v[2].value, Variant::Double(3.0));
        // Another kind or key: ignored and rewritten.
        assert_eq!(read_file(&path, 10, "urn:a;i=1"), (Vec::new(), Vec::new(), true));
        assert_eq!(read_file(&path, 11, "urn:a;i=2"), (Vec::new(), Vec::new(), true));
        // A torn last record is dropped.
        std::fs::write(&path, &data[..data.len() - 3]).unwrap();
        let (v, m, rewrite) = read_file(&path, 11, "urn:a;i=1");
        assert_eq!((v.len(), m.len(), rewrite), (3, 0, true));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
