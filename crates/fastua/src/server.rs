//! Server state shared by all connections: configuration, endpoints, sessions.

use crate::address_space::{AddressSpace, ServerInfo};
use crate::channel::Security;
use crate::codec::Writer;
use crate::crypto::{Mode, Policy};
use crate::pki::Pki;
use crate::reload::Store;
use crate::types::*;
use crate::users::{Access, Users};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const SECURITY_POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
pub const TRANSPORT_PROFILE_BINARY: &str = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";
pub const ANONYMOUS_POLICY_ID: &str = "anonymous";
pub const USERNAME_POLICY_ID: &str = "username";
pub const CERTIFICATE_POLICY_ID: &str = "certificate";

#[derive(Clone, Debug)]
pub struct Limits {
    /// Largest chunk we accept / send (bytes).
    pub buffer_size: u32,
    /// Largest reassembled request (bytes).
    pub max_message_size: u32,
    pub max_chunk_count: u32,
    pub max_sessions: usize,
    pub max_operations_per_request: usize,
    pub max_browse_continuation_points: usize,
    pub max_references_per_browse: usize,
    pub min_session_timeout_ms: f64,
    pub max_session_timeout_ms: f64,
    pub min_token_lifetime_ms: u32,
    pub max_token_lifetime_ms: u32,
    /// Time allowed between TCP connect and a valid HEL.
    pub hello_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            buffer_size: 65_535,
            max_message_size: 16 * 1024 * 1024,
            max_chunk_count: 4096,
            max_sessions: 100,
            max_operations_per_request: 10_000,
            max_browse_continuation_points: 16,
            max_references_per_browse: 1000,
            min_session_timeout_ms: 10_000.0,
            max_session_timeout_ms: 3_600_000.0,
            min_token_lifetime_ms: 10_000,
            max_token_lifetime_ms: 3_600_000,
            hello_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: String,
    pub endpoint_url: String,
    pub limits: Limits,
    /// Offered (policy, mode) pairs. (None, None) is the unsecured endpoint.
    pub endpoints: Vec<(Policy, Mode)>,
    /// Rights of anonymous users; `None` disables anonymous login.
    pub anonymous: Option<Access>,
    /// Rights of users authenticated by a trusted X.509 certificate.
    pub x509_users: Access,
    /// How long a connection thread polls its socket before sleeping (zero =
    /// never). Removes the wake-up latency at the cost of a busy core per
    /// connection while its client is idle.
    pub busy_poll: Duration,
    /// Use the io_uring transport with a shared kernel submission-polling
    /// thread (Linux). Falls back to plain sockets when unavailable.
    pub io_uring: bool,
}

impl ServerConfig {
    /// Every supported endpoint, anonymous users read-only.
    pub fn all_endpoints(listen: String, endpoint_url: String) -> ServerConfig {
        let mut endpoints = vec![(Policy::None, Mode::None)];
        for p in Policy::SECURE {
            endpoints.push((p, Mode::Sign));
            endpoints.push((p, Mode::SignAndEncrypt));
        }
        ServerConfig {
            listen,
            endpoint_url,
            limits: Limits::default(),
            endpoints,
            anonymous: Some(Access::ReadOnly),
            x509_users: Access::ReadWrite,
            busy_poll: Duration::ZERO,
            io_uring: false,
        }
    }
}

/// A paused Browse (Part 4 §5.8.2 / §7.6).
pub struct ContinuationPoint {
    pub id: [u8; 16],
    pub space: Arc<AddressSpace>,
    pub node: u32,
    pub direction: u32,
    pub ref_type: u32,
    pub include_subtypes: bool,
    pub class_mask: u32,
    pub result_mask: u32,
    pub max_refs: usize,
    /// Index into the node's reference list where browsing resumes.
    pub next_ref: usize,
}

pub struct Session {
    pub id: NodeId,
    pub token: NodeId,
    pub name: String,
    pub channel_id: AtomicU32,
    pub activated: AtomicBool,
    pub closed: AtomicBool,
    pub timeout_ms: f64,
    /// Set by every request (a plain store, no clock read on the hot path).
    pub touched: AtomicBool,
    /// Milliseconds since server start of the last activity, as seen by the
    /// once-a-second sweeper.
    pub last_seen: AtomicU64,
    pub continuation_points: Mutex<Vec<ContinuationPoint>>,
    /// Security of the channel the session was created on.
    pub security: Security,
    /// Last nonce sent to the client (CreateSession / ActivateSession).
    pub server_nonce: Mutex<Vec<u8>>,
    /// Rights of the identity given at the last ActivateSession.
    pub can_write: AtomicBool,
}

pub struct Server {
    pub store: Arc<Store>,
    pki: Arc<Pki>,
    pub users: Users,
    pub config: ServerConfig,
    started: u64,
    sessions: Mutex<FxHashMap<NodeId, Arc<Session>>>,
    next_session: AtomicU32,
    next_channel: AtomicU32,
    /// GetEndpoints / CreateSession answer, encoded once (array included).
    endpoints_encoded: Vec<u8>,
    /// FindServers answer, encoded once (array of one ApplicationDescription).
    application_encoded: Vec<u8>,
    /// Shared io_uring polling thread, when enabled and supported.
    #[cfg(target_os = "linux")]
    uring: Option<crate::uring::Shared>,
}

/// Cryptographically secure random bytes from the OS.
pub fn random_bytes(buf: &mut [u8]) {
    #[cfg(target_os = "linux")]
    {
        let mut filled = 0;
        while filled < buf.len() {
            let r = unsafe { libc::getrandom(buf[filled..].as_mut_ptr().cast(), buf.len() - filled, 0) };
            if r > 0 {
                filled += r as usize;
            } else if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
        if filled == buf.len() {
            return;
        }
    }
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("no OS random source available");
}

fn write_application_description(w: &mut Writer, info: &ServerInfo, discovery_url: &str) {
    w.string(&info.application_uri);
    w.string(&info.product_uri);
    w.text(&info.application_name);
    w.i32(0); // Server
    w.str(None); // gatewayServerUri
    w.str(None); // discoveryProfileUri
    w.string_array(&[discovery_url]);
}

impl Server {
    pub fn new(store: Arc<Store>, config: ServerConfig, pki: Arc<Pki>, users: Users) -> Arc<Server> {
        let info = store.info().clone();
        let mut endpoints_encoded = Vec::new();
        {
            let mut w = Writer::new(&mut endpoints_encoded);
            w.i32(config.endpoints.len() as i32);
            for &(policy, mode) in &config.endpoints {
                w.string(&config.endpoint_url);
                write_application_description(&mut w, &info, &config.endpoint_url);
                w.bytes(Some(&pki.cert_der));
                w.i32(mode as i32);
                w.string(policy.uri());
                // Credentials on an unsecured channel are protected with
                // Basic256Sha256 against the server certificate.
                let token_policy = if policy == Policy::None { Some(Policy::Basic256Sha256.uri()) } else { None };
                let mut tokens: Vec<(&str, i32, Option<&str>)> = Vec::new();
                if config.anonymous.is_some() {
                    tokens.push((ANONYMOUS_POLICY_ID, 0, None));
                }
                if !users.is_empty() {
                    tokens.push((USERNAME_POLICY_ID, 1, token_policy));
                }
                tokens.push((CERTIFICATE_POLICY_ID, 2, token_policy));
                w.i32(tokens.len() as i32);
                for (id, ty, sec) in tokens {
                    w.string(id);
                    w.i32(ty);
                    w.str(None);
                    w.str(None);
                    w.str(sec);
                }
                w.string(TRANSPORT_PROFILE_BINARY);
                w.u8(policy.security_level(mode));
            }
        }
        let mut application_encoded = Vec::new();
        {
            let mut w = Writer::new(&mut application_encoded);
            w.i32(1);
            write_application_description(&mut w, &info, &config.endpoint_url);
        }
        #[cfg(target_os = "linux")]
        let uring = if config.io_uring {
            match crate::uring::Shared::new() {
                Ok(u) => Some(u),
                Err(e) => {
                    crate::log!("io_uring unavailable ({e}): using plain sockets");
                    None
                }
            }
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        if config.io_uring {
            crate::log!("io_uring is Linux only: using plain sockets");
        }
        Arc::new(Server {
            store,
            pki,
            users,
            config,
            started: coarse_ms(),
            sessions: Mutex::new(FxHashMap::default()),
            next_session: AtomicU32::new(1),
            next_channel: AtomicU32::new(1),
            endpoints_encoded,
            application_encoded,
            #[cfg(target_os = "linux")]
            uring,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn uring(&self) -> Option<&crate::uring::Shared> {
        self.uring.as_ref()
    }

    /// Whether connections use the io_uring transport.
    pub fn uses_io_uring(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.uring.is_some();
        #[cfg(not(target_os = "linux"))]
        false
    }

    #[inline]
    pub fn pki(&self) -> &Pki {
        &self.pki
    }

    pub fn policy_enabled(&self, p: Policy) -> bool {
        self.config.endpoints.iter().any(|(q, _)| *q == p)
    }

    pub fn endpoint_enabled(&self, p: Policy, m: Mode) -> bool {
        self.config.endpoints.contains(&(p, m))
    }

    #[inline]
    pub fn limits(&self) -> &Limits {
        &self.config.limits
    }

    /// Milliseconds since start, from the coarse monotonic clock (a few ns,
    /// ~1-4 ms resolution): only used for session idle timeouts.
    #[inline]
    pub fn uptime_ms(&self) -> u64 {
        coarse_ms().wrapping_sub(self.started)
    }

    pub fn endpoints_encoded(&self) -> &[u8] {
        &self.endpoints_encoded
    }

    pub fn application_encoded(&self) -> &[u8] {
        &self.application_encoded
    }

    pub fn next_channel_id(&self) -> u32 {
        loop {
            let id = self.next_channel.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    pub fn create_session(
        &self,
        name: String,
        channel_id: u32,
        timeout_ms: f64,
        security: Security,
        server_nonce: Vec<u8>,
    ) -> Result<Arc<Session>, u32> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if sessions.len() >= self.limits().max_sessions {
            return Err(status::BAD_TOO_MANY_SESSIONS);
        }
        // 128 random bits as a Guid NodeId: decoded without a heap allocation
        // on every request, unlike a ByteString token.
        let mut token = [0u8; 16];
        random_bytes(&mut token);
        let session = Arc::new(Session {
            id: NodeId::Numeric(1, self.next_session.fetch_add(1, Ordering::Relaxed)),
            token: NodeId::Guid(1, token),
            name,
            channel_id: AtomicU32::new(channel_id),
            activated: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            timeout_ms,
            touched: AtomicBool::new(false),
            last_seen: AtomicU64::new(self.uptime_ms()),
            continuation_points: Mutex::new(Vec::new()),
            security,
            server_nonce: Mutex::new(server_nonce),
            can_write: AtomicBool::new(false),
        });
        sessions.insert(session.token.clone(), session.clone());
        Ok(session)
    }

    pub fn find_session(&self, token: &NodeId) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).get(token).cloned()
    }

    pub fn remove_session(&self, token: &NodeId) {
        if let Some(s) = self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(token) {
            s.closed.store(true, Ordering::Release);
        }
    }

    /// Drops sessions whose client stopped talking for longer than the timeout.
    pub fn expire_sessions(&self) {
        let now = self.uptime_ms();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, s| {
            if s.touched.swap(false, Ordering::Relaxed) {
                s.last_seen.store(now, Ordering::Relaxed);
            }
            let idle = now.saturating_sub(s.last_seen.load(Ordering::Relaxed)) as f64;
            let keep = idle <= s.timeout_ms;
            if !keep {
                s.closed.store(true, Ordering::Release);
                crate::log!("session '{}' ({}) timed out", s.name, s.id);
            }
            keep
        });
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Accepts connections forever, one thread per connection. OPC UA servers
    /// have few, long-lived clients: a dedicated thread with a blocking socket
    /// gives the lowest possible latency (no executor, no wake-up hops).
    pub fn serve(self: &Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        {
            let server = self.clone();
            std::thread::Builder::new().name("fastua-sessions".into()).spawn(move || loop {
                std::thread::sleep(Duration::from_secs(1));
                server.expire_sessions();
            })?;
        }
        for stream in listener.incoming() {
            match stream {
                Ok(s) => self.spawn_connection(s),
                Err(e) => crate::log!("accept failed: {e}"),
            }
        }
        Ok(())
    }

    fn spawn_connection(self: &Arc<Self>, stream: TcpStream) {
        let server = self.clone();
        let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let r = std::thread::Builder::new().name("fastua-conn".into()).spawn(move || {
            let _ = stream.set_nodelay(true);
            if !server.config.busy_poll.is_zero() {
                crate::net::set_kernel_busy_poll(&stream, server.config.busy_poll);
            }
            if let Err(e) = crate::channel::run(&server, stream) {
                crate::log!("connection {peer} closed: {e}");
            }
        });
        if let Err(e) = r {
            crate::log!("cannot spawn connection thread: {e}");
        }
    }
}

/// CLOCK_MONOTONIC_COARSE in milliseconds: read from the vDSO without touching
/// the TSC, ~6x cheaper than `Instant::now()`.
#[inline]
fn coarse_ms() -> u64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer; CLOCK_MONOTONIC_COARSE exists on every Linux.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut t) };
    t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000
}
