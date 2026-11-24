//! Hot reload of the configuration directory.
//!
//! A dedicated thread waits for file system events (inotify on Linux, mtime
//! polling elsewhere), lets a burst of events settle, rebuilds a complete new
//! snapshot off to the side and publishes it with one atomic pointer swap.
//! Request threads keep using the snapshot they loaded until they finish the
//! request; they never take a lock and never wait for a reload.

use crate::address_space::{self, AddressSpace, NamespaceRegistry, ServerInfo};
use crate::config;
use arc_swap::ArcSwap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Quiet period after the last file event before reloading. Editors and
/// `cp` often write a file in several steps.
pub const DEBOUNCE: Duration = Duration::from_millis(50);

pub struct Store {
    space: ArcSwap<AddressSpace>,
    registry: Mutex<NamespaceRegistry>,
    info: Arc<ServerInfo>,
    generation: AtomicU64,
    dir: PathBuf,
}

impl Store {
    /// Loads the directory once. Fails if the initial configuration is invalid.
    pub fn open(dir: &Path, info: ServerInfo) -> Result<Arc<Store>, String> {
        let info = Arc::new(info);
        let mut registry = NamespaceRegistry::new(&info.application_uri);
        let configs = config::load_dir(dir)?;
        let space = address_space::build(&configs, &mut registry, None, info.clone(), 1)?;
        Ok(Arc::new(Store {
            space: ArcSwap::from_pointee(space),
            registry: Mutex::new(registry),
            info,
            generation: AtomicU64::new(1),
            dir: dir.to_path_buf(),
        }))
    }

    /// Current snapshot. Costs a couple of atomic operations.
    #[inline(always)]
    pub fn load(&self) -> arc_swap::Guard<Arc<AddressSpace>> {
        self.space.load()
    }

    #[inline]
    pub fn load_full(&self) -> Arc<AddressSpace> {
        self.space.load_full()
    }

    pub fn info(&self) -> &Arc<ServerInfo> {
        &self.info
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Rebuilds from disk. On error the current snapshot stays in place.
    pub fn reload(&self) -> Result<u64, String> {
        let configs = config::load_dir(&self.dir)?;
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let previous = self.space.load_full();
        let generation = self.generation.load(Ordering::Relaxed) + 1;
        let space = address_space::build(&configs, &mut registry, Some(&previous), self.info.clone(), generation)?;
        self.space.store(Arc::new(space));
        self.generation.store(generation, Ordering::Relaxed);
        Ok(generation)
    }

    /// Spawns the watcher thread.
    pub fn watch(self: &Arc<Self>) -> std::io::Result<std::thread::JoinHandle<()>> {
        let store = self.clone();
        // Armed before returning, so no change made after this call is missed.
        let mut watcher = Watcher::new(&store.dir);
        std::thread::Builder::new().name("fastua-reload".into()).spawn(move || loop {
            watcher.wait_for_change();
            match store.reload() {
                Ok(g) => {
                    let s = store.load();
                    crate::log!(
                        "configuration reloaded (generation {g}, {} nodes, {} namespaces)",
                        s.len(),
                        s.namespaces.len()
                    );
                }
                Err(e) => crate::log!("configuration rejected, keeping previous one: {e}"),
            }
        })
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::DEBOUNCE;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    pub struct Watcher {
        dir: PathBuf,
        fd: i32,
    }

    const MASK: u32 = libc::IN_CLOSE_WRITE
        | libc::IN_MOVED_TO
        | libc::IN_MOVED_FROM
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF
        | libc::IN_MODIFY;

    impl Watcher {
        pub fn new(dir: &Path) -> Self {
            let mut w = Watcher { dir: dir.to_path_buf(), fd: -1 };
            w.arm();
            w
        }

        /// (Re)creates the inotify instance with one watch per directory.
        /// Done after every change so new sub-directories are covered.
        fn arm(&mut self) {
            if self.fd >= 0 {
                unsafe { libc::close(self.fd) };
                self.fd = -1;
            }
            let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
            if fd < 0 {
                return;
            }
            let mut stack = vec![self.dir.clone()];
            let mut watched = 0;
            while let Some(d) = stack.pop() {
                let Ok(c) = CString::new(d.as_os_str().as_bytes()) else { continue };
                if unsafe { libc::inotify_add_watch(fd, c.as_ptr(), MASK) } >= 0 {
                    watched += 1;
                }
                if let Ok(rd) = std::fs::read_dir(&d) {
                    for e in rd.flatten() {
                        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            stack.push(e.path());
                        }
                    }
                }
            }
            if watched == 0 {
                unsafe { libc::close(fd) };
                return;
            }
            self.fd = fd;
        }

        fn poll(&self, timeout: Duration) -> bool {
            let mut p = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
            let r = unsafe { libc::poll(&mut p, 1, timeout.as_millis() as i32) };
            r > 0
        }

        fn drain(&self) {
            let mut buf = [0u8; 4096];
            unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        }

        pub fn wait_for_change(&mut self) {
            loop {
                if self.fd < 0 {
                    // Directory missing: retry until it comes back.
                    std::thread::sleep(Duration::from_millis(500));
                    self.arm();
                    if self.fd >= 0 {
                        return;
                    }
                    continue;
                }
                if !self.poll(Duration::from_secs(3600)) {
                    continue;
                }
                self.drain();
                while self.poll(DEBOUNCE) {
                    self.drain();
                }
                self.arm();
                return;
            }
        }
    }

    impl Drop for Watcher {
        fn drop(&mut self) {
            if self.fd >= 0 {
                unsafe { libc::close(self.fd) };
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::DEBOUNCE;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    /// Portable fallback: compares (path, size, mtime) of every file.
    pub struct Watcher {
        dir: PathBuf,
        last: Vec<(PathBuf, u64, Option<SystemTime>)>,
    }

    impl Watcher {
        pub fn new(dir: &Path) -> Self {
            let mut w = Watcher { dir: dir.to_path_buf(), last: Vec::new() };
            w.last = w.fingerprint();
            w
        }

        fn fingerprint(&self) -> Vec<(PathBuf, u64, Option<SystemTime>)> {
            crate::config::list_files(&self.dir)
                .unwrap_or_default()
                .into_iter()
                .map(|p| {
                    let m = std::fs::metadata(&p).ok();
                    let size = m.as_ref().map(|m| m.len()).unwrap_or(0);
                    let mtime = m.and_then(|m| m.modified().ok());
                    (p, size, mtime)
                })
                .collect()
        }

        pub fn wait_for_change(&mut self) {
            loop {
                std::thread::sleep(Duration::from_millis(250));
                let now = self.fingerprint();
                if now != self.last {
                    std::thread::sleep(DEBOUNCE);
                    self.last = self.fingerprint();
                    return;
                }
            }
        }
    }
}

pub use imp::Watcher;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeId;
    use std::time::Instant;

    fn write(dir: &Path, name: &str, uri: &str, id: u32) {
        let text = format!(
            r#"{{"Namespace":"{uri}","Subscriptions":[{{"Name":"G","Items":[{{"Name":"x","NodeId":"i={id}","Type":"Int32"}}]}}]}}"#
        );
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, text).unwrap();
        std::fs::rename(tmp, dir.join(name)).unwrap();
    }

    fn wait_until(mut f: impl FnMut() -> bool) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn hot_reload_follows_the_directory() {
        let dir = std::env::temp_dir().join(format!("fastua-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write(&dir, "a.json", "A", 1);

        let store = Store::open(&dir, ServerInfo::default()).unwrap();
        store.watch().unwrap();
        assert!(store.load().get(&NodeId::Numeric(2, 1)).is_some());

        write(&dir, "b.json", "B", 9);
        assert!(wait_until(|| store.load().get(&NodeId::Numeric(3, 9)).is_some()));

        // Broken file: previous snapshot is kept.
        std::fs::write(dir.join("c.json"), "{ not json").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(store.load().get(&NodeId::Numeric(3, 9)).is_some());
        std::fs::remove_file(dir.join("c.json")).unwrap();

        // Changing a node address.
        write(&dir, "a.json", "A", 2);
        assert!(wait_until(|| {
            let s = store.load();
            s.get(&NodeId::Numeric(2, 2)).is_some() && s.get(&NodeId::Numeric(2, 1)).is_none()
        }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
