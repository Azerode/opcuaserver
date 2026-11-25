//! Server state shared by all connections: configuration, endpoints, sessions.

use crate::address_space::{AddressSpace, ServerInfo};
use crate::channel::Security;
use crate::codec::Writer;
use crate::crypto::{Mode, Policy};
use crate::events::Event;
use crate::pki::Pki;
use crate::reload::Store;
use crate::subscription::{SessionSubs, Subscription};
use crate::types::*;
use crate::users::{Access, Users};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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
    pub max_subscriptions_per_session: usize,
    pub max_monitored_items_per_subscription: usize,
    /// Publish requests a session may queue.
    pub max_publish_requests: usize,
    /// Unacknowledged NotificationMessages kept per subscription for Republish.
    pub max_retransmission_queue: usize,
    pub max_queue_size: u32,
    pub max_notifications_per_publish: u32,
    pub min_publishing_interval_ms: f64,
    pub max_publishing_interval_ms: f64,
    pub min_sampling_interval_ms: f64,
    pub max_sampling_interval_ms: f64,
    pub max_keep_alive_count: u32,
    pub max_lifetime_count: u32,
    /// Events kept for HistoryRead on the Server object (0 = no event
    /// history).
    pub event_history: usize,
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
            max_subscriptions_per_session: 100,
            max_monitored_items_per_subscription: 100_000,
            max_publish_requests: 32,
            max_retransmission_queue: 64,
            max_queue_size: 10_000,
            max_notifications_per_publish: 100_000,
            min_publishing_interval_ms: 1.0,
            max_publishing_interval_ms: 3_600_000.0,
            min_sampling_interval_ms: 1.0,
            max_sampling_interval_ms: 3_600_000.0,
            max_keep_alive_count: 100_000,
            max_lifetime_count: 1_000_000,
            event_history: 0,
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
    /// At most this many connections busy-poll at once (0 = automatic:
    /// half the cores). The others sleep in `recv`: spinning on more threads
    /// than free cores steals CPU from the threads doing the work.
    pub busy_poll_threads: usize,
    /// URL of the HTTPS endpoint (`opc.https://host:port`) when HTTPS is
    /// served (see [`crate::https`]).
    pub https_url: Option<String>,
    /// Count every request per session and service (SessionDiagnostics).
    pub session_diagnostics: bool,
}

impl ServerConfig {
    /// Every supported endpoint but the deprecated ECC_nistP256 /
    /// ECC_nistP384 ones (offered only when listed), anonymous users
    /// read-only.
    pub fn all_endpoints(listen: String, endpoint_url: String) -> ServerConfig {
        let mut endpoints = vec![(Policy::None, Mode::None)];
        let ecc = crate::ecc::Suite::ALL.into_iter().map(Policy::Ecc);
        for p in Policy::SECURE.into_iter().chain(ecc) {
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
            busy_poll_threads: 0,
            https_url: None,
            session_diagnostics: false,
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
    /// CreateSession clientNonce (channel-bound ECC signatures).
    pub client_nonce: Vec<u8>,
    /// Ephemeral key sent for the next EccEncryptedSecret (ECC channels).
    pub ecdh: Mutex<Option<crate::ecc::Ephemeral>>,
    /// Rights of the identity given at the last ActivateSession.
    pub can_write: AtomicBool,
    /// User identity of the last ActivateSession ("anonymous", "user:<name>",
    /// "x509:<thumbprint>"): TransferSubscriptions requires the same one.
    pub identity: Mutex<Arc<str>>,
    /// Subscriptions and queued Publish requests, driven by the thread of
    /// the connection the session is bound to.
    pub subs: Mutex<SessionSubs>,
    /// SessionDiagnostics / SessionSecurityDiagnostics (Part 5 §12.11).
    pub diag: SessionDiag,
}

/// What a session's diagnostics report beyond its other fields.
pub struct SessionDiag {
    /// The client's ApplicationDescription, as encoded in CreateSession.
    pub client_description: Box<[u8]>,
    pub server_uri: Option<String>,
    pub endpoint_url: Option<String>,
    pub max_response: u32,
    pub connected: i64,
    /// Set by the once-a-second sweeper from the `touched` flag.
    pub last_contact: std::sync::atomic::AtomicI64,
    /// Service counters (see [`crate::diagnostics::COUNTERS`]); counted only
    /// with `--session-diagnostics`.
    pub counters: [AtomicU32; crate::diagnostics::COUNTERS],
    /// Identities of the successive ActivateSession calls.
    pub identities: Mutex<Vec<Arc<str>>>,
}

impl SessionDiag {
    pub fn new(
        client_description: &[u8],
        server_uri: Option<String>,
        endpoint_url: Option<String>,
        max_response: u32,
    ) -> SessionDiag {
        let now = now_ticks();
        SessionDiag {
            client_description: client_description.into(),
            server_uri,
            endpoint_url,
            max_response,
            connected: now,
            last_contact: std::sync::atomic::AtomicI64::new(now),
            counters: std::array::from_fn(|_| AtomicU32::new(0)),
            identities: Mutex::new(Vec::new()),
        }
    }
}

pub struct Server {
    pub store: Arc<Store>,
    pki: Arc<Pki>,
    pub users: Users,
    pub config: ServerConfig,
    started: u64,
    sessions: Mutex<FxHashMap<NodeId, Arc<Session>>>,
    /// Connections currently busy-polling; how many may (adjusted to the
    /// free cores by the load sampler) and the configured ceiling.
    spinners: AtomicUsize,
    spin_limit: AtomicUsize,
    spin_cap: usize,
    next_session: AtomicU32,
    next_channel: AtomicU32,
    /// GetEndpoints / CreateSession answer, encoded once (array included).
    endpoints_encoded: Vec<u8>,
    /// Bounds in `endpoints_encoded` of the endpoints of each transport
    /// profile (opc.tcp, https-uabinary, https-uajson), in that order.
    transports: [(usize, usize, i32); 3],
    /// FindServers answer, encoded once (array of one ApplicationDescription).
    application_encoded: Vec<u8>,
    next_subscription: AtomicU32,
    /// Subscriptions of sessions closed with deleteSubscriptions = false,
    /// kept for TransferSubscriptions until their lifetime ends.
    orphans: Mutex<Vec<Orphan>>,
}

/// A subscription whose session is gone.
pub struct Orphan {
    pub identity: Arc<str>,
    pub expires_ms: u64,
    pub sub: Subscription,
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
    /// Takes a busy-poll permit if fewer than the limit are held. A
    /// connection keeps its permit while requests keep arriving and gives it
    /// back when it goes to sleep, so the steady state costs no atomic.
    #[inline]
    pub(crate) fn acquire_spin(&self) -> bool {
        let limit = self.spin_limit.load(Ordering::Relaxed);
        let mut n = self.spinners.load(Ordering::Relaxed);
        while n < limit {
            match self.spinners.compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(now) => n = now,
            }
        }
        false
    }

    /// True when more connections spin than the sampler allows now: the
    /// caller should give its permit back. Two loads of rarely written lines.
    #[inline]
    pub(crate) fn spin_oversubscribed(&self) -> bool {
        self.spinners.load(Ordering::Relaxed) > self.spin_limit.load(Ordering::Relaxed)
    }

    /// Load sampler: busy-polling only pays when a core is free. Every 2 ms
    /// it reads the number of runnable threads (/proc/loadavg), smooths it,
    /// and sets how many connections may spin: the current spinners plus the
    /// idle cores (fewer when threads wait for a CPU), within the ceiling.
    fn sample_load(&self) {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get()) as f64;
        let mut running = 0.0f64;
        let mut buf = [0u8; 128];
        let Ok(file) = std::fs::File::open("/proc/loadavg") else {
            return; // no /proc: keep the static ceiling
        };
        loop {
            std::thread::sleep(Duration::from_millis(2));
            let Some(now) = runnable_threads(&file, &mut buf) else {
                return; // no /proc: keep the static ceiling
            };
            // Without the sampler itself.
            running = 0.75 * running + 0.25 * (now.saturating_sub(1) as f64);
            let spinners = self.spinners.load(Ordering::Relaxed) as f64;
            let limit = (spinners + (cores - running).floor()).clamp(0.0, self.spin_cap as f64);
            self.spin_limit.store(limit as usize, Ordering::Relaxed);
        }
    }

    #[inline]
    pub(crate) fn release_spin(&self) {
        self.spinners.fetch_sub(1, Ordering::Release);
    }

    pub fn new(store: Arc<Store>, mut config: ServerConfig, pki: Arc<Pki>, users: Users) -> Arc<Server> {
        let spin_cap = match config.busy_poll_threads {
            0 => std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).max(1)),
            n => n,
        };
        let info = store.info().clone();
        // EnabledFlag of ServerDiagnostics.
        info.diagnostics.counting.store(config.session_diagnostics, Ordering::Relaxed);
        // An ECC endpoint needs our certificate on its curve.
        config.endpoints.retain(|(p, _)| match p.ecc() {
            Some(s) if pki.ecc_own(s.curve).is_none() => {
                crate::log!("no {:?} certificate: {} not offered", s.curve, p.uri());
                false
            }
            _ => true,
        });
        // (url, policy, mode, transport profile)
        let mut offered: Vec<(&str, Policy, Mode, &str)> = config
            .endpoints
            .iter()
            .map(|&(p, m)| (config.endpoint_url.as_str(), p, m, TRANSPORT_PROFILE_BINARY))
            .collect();
        if let Some(url) = &config.https_url {
            offered.push((url, Policy::None, Mode::None, crate::https::TRANSPORT_PROFILE_HTTPS));
            offered.push((url, Policy::None, Mode::None, crate::https::TRANSPORT_PROFILE_HTTPS_JSON));
        }
        let mut endpoints_encoded = Vec::new();
        let mut transports = [(0usize, 0usize, 0i32); 3];
        {
            let mut w = Writer::new(&mut endpoints_encoded);
            w.i32(offered.len() as i32);
            for &(url, policy, mode, profile) in &offered {
                let t = match profile {
                    TRANSPORT_PROFILE_BINARY => 0,
                    crate::https::TRANSPORT_PROFILE_HTTPS => 1,
                    _ => 2,
                };
                if transports[t].2 == 0 {
                    transports[t].0 = w.len();
                }
                transports[t].2 += 1;
                w.string(url);
                write_application_description(&mut w, &info, &config.endpoint_url);
                w.bytes(Some(pki.certificate_for(policy)));
                w.i32(mode as i32);
                w.string(policy.uri());
                // Credentials on an unsecured channel are protected with
                // Basic256Sha256 against the server certificate.
                let token_policy = if policy == Policy::None { Some(Policy::Basic256Sha256.uri()) } else { None };
                let mut tokens: Vec<(&str, i32, Option<&str>)> = Vec::new();
                if config.anonymous.is_some() {
                    tokens.push((ANONYMOUS_POLICY_ID, 0, None));
                }
                // ECC: the password travels as an EccEncryptedSecret.
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
                w.string(profile);
                w.u8(policy.security_level(mode));
                transports[t].1 = w.len();
            }
        }
        let mut application_encoded = Vec::new();
        {
            let mut w = Writer::new(&mut application_encoded);
            w.i32(1);
            write_application_description(&mut w, &info, &config.endpoint_url);
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
            spinners: AtomicUsize::new(0),
            spin_limit: AtomicUsize::new(spin_cap),
            spin_cap,
            endpoints_encoded,
            transports,
            application_encoded,
            next_subscription: AtomicU32::new(1),
            orphans: Mutex::new(Vec::new()),
        })
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

    /// Writes the endpoints (array included) of the selected transport
    /// profiles: opc.tcp, https-uabinary, https-uajson.
    pub fn write_endpoints(&self, w: &mut Writer, select: [bool; 3]) {
        if select == [true; 3] {
            return w.raw(&self.endpoints_encoded);
        }
        let selected = || self.transports.iter().zip(select).filter(|(_, on)| *on).map(|(t, _)| *t);
        w.i32(selected().map(|t| t.2).sum());
        for (from, to, count) in selected() {
            if count > 0 {
                w.raw(&self.endpoints_encoded[from..to]);
            }
        }
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

    #[allow(clippy::too_many_arguments)]
    pub fn create_session(
        &self,
        name: String,
        channel_id: u32,
        timeout_ms: f64,
        security: Security,
        server_nonce: Vec<u8>,
        client_nonce: Vec<u8>,
        diag: SessionDiag,
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
            client_nonce,
            ecdh: Mutex::new(None),
            can_write: AtomicBool::new(false),
            identity: Mutex::new(Arc::from("")),
            subs: Mutex::new(SessionSubs::default()),
            diag,
        });
        sessions.insert(session.token.clone(), session.clone());
        drop(sessions);
        let d = &self.store.info().diagnostics;
        d.register(&session);
        crate::diagnostics::inc(&d.current_sessions);
        crate::diagnostics::inc(&d.cumulated_sessions);
        Ok(session)
    }

    pub fn find_session(&self, token: &NodeId) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).get(token).cloned()
    }

    pub fn remove_session(&self, token: &NodeId) {
        if let Some(s) = self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(token) {
            s.closed.store(true, Ordering::Release);
            crate::diagnostics::dec(&self.store.info().diagnostics.current_sessions);
        }
    }

    /// Drops sessions whose client stopped talking for longer than the timeout.
    pub fn expire_sessions(&self) {
        let now = self.uptime_ms();
        let mut expired = Vec::new();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, s| {
            if s.touched.swap(false, Ordering::Relaxed) {
                s.last_seen.store(now, Ordering::Relaxed);
                s.diag.last_contact.store(now_ticks(), Ordering::Relaxed);
            }
            let idle = now.saturating_sub(s.last_seen.load(Ordering::Relaxed)) as f64;
            let keep = idle <= s.timeout_ms;
            if !keep {
                s.closed.store(true, Ordering::Release);
                crate::log!("session '{}' ({}) timed out", s.name, s.id);
                expired.push(s.clone());
            }
            keep
        });
        drop(sessions);
        let d = &self.store.info().diagnostics;
        for s in expired {
            crate::diagnostics::dec(&d.current_sessions);
            crate::diagnostics::inc(&d.session_timeouts);
            self.session_event(crate::events::types::AUDIT_SESSION_EVENT_TYPE, &s, "Session/Timeout", true, |e| e);
        }
        let mut orphans = self.orphans.lock().unwrap_or_else(|e| e.into_inner());
        orphans.retain(|o| o.expires_ms > now);
    }

    /// Raises an AuditSessionEventType (or subtype) for `s` when someone
    /// subscribes to events. `extra` adds the subtype's fields.
    pub fn session_event(&self, type_id: u32, s: &Session, action: &str, ok: bool, extra: impl FnOnce(Event) -> Event) {
        let outcome = if ok { "succeeded" } else { "failed" };
        let message = format!("{action} of session '{}' {outcome}", s.name);
        self.audit_event(type_id, s, (NodeId::ns0(ids::SERVER), action), &message, ok, |e| {
            extra(e.with(crate::events::types::SESSION_ID, Variant::NodeId(Box::new(s.id.clone()))))
        });
    }

    /// Raises an AuditEventType (or subtype) on behalf of session `s`, when
    /// someone subscribes to events. `source` is (SourceNode, SourceName).
    pub fn audit_event(
        &self,
        type_id: u32,
        s: &Session,
        source: (NodeId, &str),
        message: &str,
        ok: bool,
        extra: impl FnOnce(Event) -> Event,
    ) {
        use crate::events::types::*;
        let space = self.store.load();
        if !space.events.active() {
            return;
        }
        let user = s.identity.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let ev = Event::new(type_id, source.0, source.1, message, if ok { 100 } else { 500 })
            .with(ACTION_TIME_STAMP, Variant::DateTime(now_ticks()))
            .with(STATUS, Variant::Boolean(ok))
            .with(SERVER_ID, Variant::string(&self.store.info().application_uri))
            .with(CLIENT_AUDIT_ENTRY_ID, Variant::String(None))
            .with(CLIENT_USER_ID, Variant::string(&user));
        space.events.emit(extra(ev));
    }

    /// Every live session (TransferSubscriptions).
    pub fn sessions(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect()
    }

    pub fn next_subscription_id(&self) -> u32 {
        loop {
            let id = self.next_subscription.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    /// Keeps the subscriptions of a closed session for TransferSubscriptions.
    pub fn orphan(&self, identity: Arc<str>, subs: Vec<Subscription>) {
        let now = self.uptime_ms();
        let mut orphans = self.orphans.lock().unwrap_or_else(|e| e.into_inner());
        for sub in subs {
            let expires_ms = now + sub.lifetime_ms() as u64;
            orphans.push(Orphan { identity: identity.clone(), expires_ms, sub });
        }
    }

    /// Takes an orphaned subscription: `Err` if it exists with another identity.
    pub fn adopt(&self, id: u32, identity: &str) -> Option<Result<Subscription, ()>> {
        let mut orphans = self.orphans.lock().unwrap_or_else(|e| e.into_inner());
        let i = orphans.iter().position(|o| o.sub.id == id)?;
        if &*orphans[i].identity != identity {
            return Some(Err(()));
        }
        Some(Ok(orphans.swap_remove(i).sub))
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
                // Timed shelves end on time (to the second).
                server.store.load().alarms.tick(crate::types::now_ticks());
            })?;
        }
        if !self.config.busy_poll.is_zero() {
            let server = self.clone();
            std::thread::Builder::new().name("fastua-load".into()).spawn(move || server.sample_load())?;
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

/// Runnable threads system-wide: 4th field of /proc/loadavg ("1/123").
fn runnable_threads(file: &std::fs::File, buf: &mut [u8; 128]) -> Option<usize> {
    use std::os::unix::fs::FileExt;
    let n = file.read_at(buf, 0).ok()?;
    let text = std::str::from_utf8(&buf[..n]).ok()?;
    text.split(' ').nth(3)?.split('/').next()?.parse().ok()
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
