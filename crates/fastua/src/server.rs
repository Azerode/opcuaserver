//! Server state shared by all connections: configuration, endpoints, sessions.

use crate::address_space::{AddressSpace, ServerInfo};
use crate::codec::Writer;
use crate::reload::Store;
use crate::types::*;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SECURITY_POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
pub const TRANSPORT_PROFILE_BINARY: &str = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";
pub const ANONYMOUS_POLICY_ID: &str = "anonymous";

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
    /// Milliseconds since server start of the last request.
    pub last_seen: AtomicU64,
    pub continuation_points: Mutex<Vec<ContinuationPoint>>,
}

pub struct Server {
    pub store: Arc<Store>,
    pub config: ServerConfig,
    started: Instant,
    sessions: Mutex<FxHashMap<NodeId, Arc<Session>>>,
    next_session: AtomicU32,
    next_channel: AtomicU32,
    /// GetEndpoints / CreateSession answer, encoded once (array included).
    endpoints_encoded: Vec<u8>,
    /// FindServers answer, encoded once (array of one ApplicationDescription).
    application_encoded: Vec<u8>,
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
    pub fn new(store: Arc<Store>, config: ServerConfig) -> Arc<Server> {
        let info = store.info().clone();
        let mut endpoints_encoded = Vec::new();
        {
            let mut w = Writer::new(&mut endpoints_encoded);
            w.i32(1);
            w.string(&config.endpoint_url);
            write_application_description(&mut w, &info, &config.endpoint_url);
            w.bytes(None); // server certificate
            w.i32(1); // MessageSecurityMode None
            w.string(SECURITY_POLICY_NONE);
            w.i32(1);
            w.string(ANONYMOUS_POLICY_ID);
            w.i32(0); // UserTokenType Anonymous
            w.str(None);
            w.str(None);
            w.str(None);
            w.string(TRANSPORT_PROFILE_BINARY);
            w.u8(0); // securityLevel
        }
        let mut application_encoded = Vec::new();
        {
            let mut w = Writer::new(&mut application_encoded);
            w.i32(1);
            write_application_description(&mut w, &info, &config.endpoint_url);
        }
        Arc::new(Server {
            store,
            config,
            started: Instant::now(),
            sessions: Mutex::new(FxHashMap::default()),
            next_session: AtomicU32::new(1),
            next_channel: AtomicU32::new(1),
            endpoints_encoded,
            application_encoded,
        })
    }

    #[inline]
    pub fn limits(&self) -> &Limits {
        &self.config.limits
    }

    #[inline]
    pub fn uptime_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
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

    pub fn create_session(&self, name: String, channel_id: u32, timeout_ms: f64) -> Result<Arc<Session>, u32> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if sessions.len() >= self.limits().max_sessions {
            return Err(status::BAD_TOO_MANY_SESSIONS);
        }
        let mut token = [0u8; 32];
        random_bytes(&mut token);
        let session = Arc::new(Session {
            id: NodeId::Numeric(1, self.next_session.fetch_add(1, Ordering::Relaxed)),
            token: NodeId::Opaque(1, token.into()),
            name,
            channel_id: AtomicU32::new(channel_id),
            activated: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            timeout_ms,
            last_seen: AtomicU64::new(self.uptime_ms()),
            continuation_points: Mutex::new(Vec::new()),
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
            if let Err(e) = crate::channel::run(&server, stream) {
                crate::log!("connection {peer} closed: {e}");
            }
        });
        if let Err(e) = r {
            crate::log!("cannot spawn connection thread: {e}");
        }
    }
}
