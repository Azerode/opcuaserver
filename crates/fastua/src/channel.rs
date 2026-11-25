//! OPC UA TCP transport and secure channel (Part 6, §6 and §7).
//!
//! One thread drives one connection. All buffers are allocated once per
//! connection and reused for every message: steady state is allocation-free
//! for the framing layer. A single-chunk response (the common case) is built,
//! signed and encrypted in place behind a reserved header and sent with one
//! `write` syscall.

use crate::address_space::AddressSpace;
use crate::codec::{Reader, Writer};
use crate::crypto::{self, ChannelKeys, Mode, Policy, SYM_SIGNATURE_LEN};
use crate::ecc::{self, EccKeys, TAG_LEN};
use crate::pki::CertInfo;
use crate::server::{random_bytes, Server, Session};
use crate::services;
use crate::subscription::mono_ns;
use crate::types::*;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

const PROTOCOL_VERSION: u32 = 0;
/// Smallest buffer size allowed by Part 6 §7.1.2.3.
const MIN_BUFFER: u32 = 8192;
/// MSG chunk header: 12 (message header) + 4 (token id) + 8 (sequence header).
pub const MSG_HEADER_LEN: usize = 24;
/// Part of the MSG header that stays in clear text when encrypting.
const SYM_CLEAR_LEN: usize = 16;
const BAD_NONCE_INVALID: u32 = 0x8024_0000;

/// Security settings of a channel, visible to the service layer.
#[derive(Clone)]
pub struct Security {
    pub policy: Policy,
    pub mode: Mode,
    pub client_cert: Option<Arc<CertInfo>>,
    /// ECC SecureChannelEnhancements: our signature of the first
    /// OpenSecureChannel response, binding session signatures to the channel.
    pub channel_thumbprint: Option<Arc<[u8]>>,
}

impl Security {
    pub const NONE: Security =
        Security { policy: Policy::None, mode: Mode::None, client_cert: None, channel_thumbprint: None };
}

/// Symmetric keys of one security token. The RSA keys stay inline (no
/// pointer chase on the hot path); the size difference costs nothing, there
/// are two per channel.
#[allow(clippy::large_enum_variant)]
enum Keys {
    Rsa(ChannelKeys),
    Ecc(EccKeys),
}

/// A verified ECC OPN: plain text, client certificate, request signature.
type VerifiedOpn = (Vec<u8>, Arc<CertInfo>, Vec<u8>);

struct Channel {
    id: u32,
    token_id: u32,
    prev_token_id: Option<u32>,
    token_created: Instant,
    lifetime_ms: u32,
    security: Security,
    keys: Option<Keys>,
    prev_keys: Option<Keys>,
    /// ECC: input keying material, XORed with each exchange's shared secret.
    ikm: Vec<u8>,
}

impl Channel {
    /// Token and keys to secure outgoing messages: the previous token stays in
    /// use until the client has sent something with the new one.
    fn sending(&self) -> (u32, Option<&Keys>) {
        match self.prev_token_id {
            Some(prev) => (prev, self.prev_keys.as_ref()),
            None => (self.token_id, self.keys.as_ref()),
        }
    }
}

pub struct Connection<'a> {
    server: &'a Arc<Server>,
    stream: TcpStream,
    /// Size of chunks we may send (client's receive buffer).
    send_buffer: u32,
    /// Size of chunks we accept (min of ours and client's send buffer).
    recv_buffer: u32,
    client_max_message: u32,
    client_max_chunks: u32,
    channel: Option<Channel>,
    next_seq: u32,
    last_client_seq: Option<u32>,
    /// Part 6 §6.7.2.4 legacy sequence numbers (RSA): wrap below 1024.
    /// ECC policies count from 0 and wrap from u32::MAX to 0.
    legacy_seq: bool,
    hdr: [u8; 8],
    /// Receive buffer: the header and body of a chunk (and pipelined
    /// requests) arrive with one `recv` instead of two `read_exact`.
    inbuf: Box<[u8]>,
    in_start: usize,
    in_end: usize,
    /// Busy-poll period before sleeping in `recv` (zero = off).
    spin: std::time::Duration,
    rx: Vec<u8>,
    tx: Vec<u8>,
    out: Vec<u8>,
    assembly: Vec<u8>,
    assembly_chunks: u32,
    assembly_request: u32,
    session: Option<Arc<Session>>,
    space: Option<Arc<AddressSpace>>,
    /// Subscriptions driven by this connection's thread.
    conn: services::ConnState,
    /// Next sampling / publishing deadline (monotonic ns, `u64::MAX` = none).
    deadline: u64,
    slack_set: bool,
}

#[derive(Debug)]
enum Fatal {
    Io(io::Error),
    /// Send ERR with this status, then close.
    Protocol(u32, &'static str),
    /// Client closed the channel cleanly.
    Closed,
}

impl From<io::Error> for Fatal {
    fn from(e: io::Error) -> Self {
        Fatal::Io(e)
    }
}

impl From<crate::codec::DecodeError> for Fatal {
    fn from(_: crate::codec::DecodeError) -> Self {
        Fatal::Protocol(status::BAD_DECODING_ERROR, "malformed message")
    }
}

/// Crypto failures never say more than "security checks failed" to the peer.
fn checks_failed(reason: &'static str) -> Fatal {
    Fatal::Protocol(status::BAD_SECURITY_CHECKS_FAILED, reason)
}

pub fn run(server: &Arc<Server>, stream: TcpStream) -> io::Result<()> {
    let limits = server.limits().clone();
    stream.set_read_timeout(Some(limits.hello_timeout))?;
    let mut c = Connection {
        server,
        stream,
        send_buffer: limits.buffer_size,
        recv_buffer: limits.buffer_size,
        client_max_message: 0,
        client_max_chunks: 0,
        channel: None,
        next_seq: 1,
        last_client_seq: None,
        legacy_seq: true,
        hdr: [0; 8],
        inbuf: vec![0; limits.buffer_size.max(MIN_BUFFER) as usize].into_boxed_slice(),
        in_start: 0,
        in_end: 0,
        spin: server.config.busy_poll,
        rx: Vec::with_capacity(limits.buffer_size as usize),
        tx: Vec::with_capacity(limits.buffer_size as usize + 64),
        out: Vec::new(),
        assembly: Vec::new(),
        assembly_chunks: 0,
        assembly_request: 0,
        session: None,
        space: None,
        conn: services::ConnState::new(limits.max_message_size as usize),
        deadline: u64::MAX,
        slack_set: false,
    };
    match c.serve() {
        Ok(()) | Err(Fatal::Closed) => Ok(()),
        Err(Fatal::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(Fatal::Io(e)) => Err(e),
        Err(Fatal::Protocol(code, reason)) => {
            let _ = c.send_error(code, reason);
            Err(io::Error::new(io::ErrorKind::InvalidData, format!("{reason} (0x{code:08X})")))
        }
    }
}

impl<'a> Connection<'a> {
    /// Receives more bytes into `inbuf` (compacting it first if needed).
    fn fill(&mut self) -> Result<(), Fatal> {
        if self.in_start == self.in_end {
            self.in_start = 0;
            self.in_end = 0;
        } else if self.in_end == self.inbuf.len() {
            self.inbuf.copy_within(self.in_start..self.in_end, 0);
            self.in_end -= self.in_start;
            self.in_start = 0;
        }
        let n = if self.conn.sessions.is_empty() {
            crate::net::recv(&mut self.stream, &mut self.inbuf[self.in_end..], self.spin)?
        } else {
            self.recv_with_timers()?
        };
        if n == 0 {
            return Err(Fatal::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        self.in_end += n;
        Ok(())
    }

    /// Receives while running subscription timers: waits for data or the
    /// next deadline, whichever comes first.
    fn recv_with_timers(&mut self) -> Result<usize, Fatal> {
        if !self.slack_set {
            crate::net::set_timer_slack(1);
            self.slack_set = true;
        }
        loop {
            if self.conn.timers_dirty {
                self.recompute_deadline();
            }
            let mut now = mono_ns();
            if now >= self.deadline {
                self.run_timers(now)?;
                if self.conn.sessions.is_empty() {
                    return Ok(crate::net::recv(&mut self.stream, &mut self.inbuf[self.in_end..], self.spin)?);
                }
                continue;
            }
            if !self.spin.is_zero() {
                let stop = self.deadline.min(now + self.spin.as_nanos() as u64);
                loop {
                    if let Some(n) = crate::net::try_recv(&self.stream, &mut self.inbuf[self.in_end..])? {
                        return Ok(n);
                    }
                    std::hint::spin_loop();
                    now = mono_ns();
                    if now >= stop {
                        break;
                    }
                }
                if now >= self.deadline {
                    continue;
                }
            }
            if crate::net::wait_readable(&self.stream, self.deadline - now)? {
                if let Some(n) = crate::net::try_recv(&self.stream, &mut self.inbuf[self.in_end..])? {
                    return Ok(n);
                }
            }
        }
    }

    fn recompute_deadline(&mut self) {
        self.conn.timers_dirty = false;
        let mut d = u64::MAX;
        for s in &self.conn.sessions {
            d = d.min(s.subs.lock().unwrap_or_else(|e| e.into_inner()).next_deadline());
        }
        self.deadline = d;
    }

    /// Samples, runs the publishing timers and answers every Publish request
    /// that has something to carry, for each session driven here.
    fn run_timers(&mut self, now: u64) -> Result<(), Fatal> {
        let Some(ch_id) = self.channel.as_ref().map(|c| c.id) else { return Ok(()) };
        let mut sessions = std::mem::take(&mut self.conn.sessions);
        let mut space = self.space.take();
        self.server.store.cached(&mut space);
        let mut tx = std::mem::take(&mut self.tx);
        let server = self.server;
        let limits = server.limits();
        let max = self.conn.max_response;
        let mut deadline = u64::MAX;
        let mut result = Ok(());
        sessions.retain(|s| {
            if result.is_err() {
                return true;
            }
            if s.closed.load(std::sync::atomic::Ordering::Acquire)
                || s.channel_id.load(std::sync::atomic::Ordering::Acquire) != ch_id
            {
                return false;
            }
            let mut st = s.subs.lock().unwrap_or_else(|e| e.into_inner());
            st.tick(now, space.as_ref().unwrap());
            loop {
                tx.clear();
                tx.resize(MSG_HEADER_LEN, 0);
                let ready = st.write_next(limits, now, ch_id, max, &mut Writer::new(&mut tx), true);
                let Some(ready) = ready else { break };
                // The NotificationMessage stays in `tx` for Republish unless
                // sending changes `tx` (encryption in place, a fault instead).
                let intact = self.sent_intact(&tx);
                if !intact {
                    st.keep_sent(&mut tx, false);
                }
                if let Err(e) = self.send_response(ready.request_id, &mut tx, ready.handle) {
                    result = Err(e);
                    return true;
                }
                if intact {
                    st.keep_sent(&mut tx, true);
                }
            }
            deadline = deadline.min(st.next_deadline());
            !st.is_idle()
        });
        self.tx = tx;
        self.space = space;
        // Services may have added sessions while we iterated (not here: this
        // runs between requests), so a plain swap back is enough.
        self.conn.sessions = sessions;
        self.deadline = deadline;
        result
    }

    /// Reads one chunk: header into `hdr`, the rest into `rx`.
    fn read_chunk(&mut self, limit: u32) -> Result<([u8; 3], u8), Fatal> {
        while self.in_end - self.in_start < 8 {
            self.fill()?;
        }
        self.hdr.copy_from_slice(&self.inbuf[self.in_start..self.in_start + 8]);
        self.in_start += 8;
        let size = u32::from_le_bytes(self.hdr[4..8].try_into().unwrap());
        if size < 8 {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "chunk too small"));
        }
        if size > limit {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TOO_LARGE, "chunk larger than receive buffer"));
        }
        let body = size as usize - 8;
        let have = body.min(self.in_end - self.in_start);
        self.rx.clear();
        self.rx.extend_from_slice(&self.inbuf[self.in_start..self.in_start + have]);
        self.in_start += have;
        if have < body {
            // The rest of a large chunk goes straight into `rx`.
            self.rx.resize(body, 0);
            self.stream.read_exact(&mut self.rx[have..])?;
        }
        let h = self.hdr;
        Ok(([h[0], h[1], h[2]], h[3]))
    }

    fn serve(&mut self) -> Result<(), Fatal> {
        // Part 6 §7.1.2.3: the first message must be HEL.
        let (ty, chunk) = self.read_chunk(MIN_BUFFER.max(self.recv_buffer))?;
        if &ty != b"HEL" || chunk != b'F' {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "expected HEL"));
        }
        self.hello()?;
        self.stream.set_read_timeout(None)?;

        loop {
            let (ty, chunk) = self.read_chunk(self.recv_buffer)?;
            match &ty {
                b"OPN" => self.open_channel(chunk)?,
                b"MSG" => self.message(chunk)?,
                b"CLO" => {
                    self.unprotect()?;
                    return Err(Fatal::Closed);
                }
                _ => return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "unknown message type")),
            }
        }
    }

    fn hello(&mut self) -> Result<(), Fatal> {
        let mut r = Reader::new(&self.rx);
        let _version = r.u32()?; // Any client version >= ours is accepted (Part 6 §7.1.2.3).
        let client_recv = r.u32()?;
        let client_send = r.u32()?;
        let max_message = r.u32()?;
        let max_chunks = r.u32()?;
        let url = r.str()?.unwrap_or("");
        if url.len() > 4096 {
            return Err(Fatal::Protocol(status::BAD_TCP_ENDPOINT_URL_INVALID, "endpoint url too long"));
        }
        if client_recv < MIN_BUFFER || client_send < MIN_BUFFER {
            return Err(Fatal::Protocol(status::BAD_TCP_INTERNAL_ERROR, "buffer size below 8192"));
        }
        let ours = self.server.limits().buffer_size;
        self.send_buffer = ours.min(client_recv);
        self.recv_buffer = ours.min(client_send);
        self.client_max_message = max_message;
        self.client_max_chunks = max_chunks;
        // Largest NotificationMessage worth building: what the client accepts,
        // with room for the PublishResponse around it and chunk overheads.
        let ours = self.server.limits().max_message_size as usize;
        let by_size = if max_message == 0 { ours } else { ours.min(max_message as usize) };
        let chunk_body = self.send_buffer as usize - MSG_HEADER_LEN - SYM_SIGNATURE_LEN - crypto::AES_BLOCK;
        let by_chunks = if max_chunks == 0 { usize::MAX } else { max_chunks as usize * chunk_body };
        self.conn.max_response = by_size.min(by_chunks).saturating_sub(4096).max(1024);

        let limits = self.server.limits();
        self.tx.clear();
        let mut w = Writer::new(&mut self.tx);
        w.raw(b"ACKF");
        w.u32(28);
        w.u32(PROTOCOL_VERSION);
        w.u32(self.recv_buffer);
        w.u32(self.send_buffer);
        w.u32(limits.max_message_size);
        w.u32(limits.max_chunk_count);
        self.stream.write_all(&self.tx)?;
        Ok(())
    }

    fn send_error(&mut self, code: u32, reason: &str) -> io::Result<()> {
        let mut buf = Vec::with_capacity(64);
        let mut w = Writer::new(&mut buf);
        w.raw(b"ERRF");
        w.u32(0);
        w.u32(code);
        w.string(reason);
        let len = w.len() as u32;
        w.patch_u32(4, len);
        self.stream.write_all(&buf)
    }

    fn check_sequence(&mut self, seq: u32) -> Result<(), Fatal> {
        if let Some(last) = self.last_client_seq {
            // Part 6 §6.7.2.4: strictly +1, wrapping below 1024 once past
            // 2^32-1024 (legacy) or from 2^32-1 to 0.
            let ok = seq == last.wrapping_add(1) || (self.legacy_seq && last > u32::MAX - 1024 && seq < 1024);
            if !ok {
                return Err(Fatal::Protocol(status::BAD_SEQUENCE_NUMBER_INVALID, "sequence number out of order"));
            }
        }
        self.last_client_seq = Some(seq);
        Ok(())
    }

    #[inline(always)]
    fn next_sequence(&mut self) -> u32 {
        let s = self.next_seq;
        // Legacy: wrap to 1 before reaching the forbidden range near 2^32.
        self.next_seq = if self.legacy_seq && s >= u32::MAX - 1024 { 1 } else { s.wrapping_add(1) };
        s
    }

    // ------------------------------------------------------------- OPN

    fn open_channel(&mut self, chunk: u8) -> Result<(), Fatal> {
        if chunk != b'F' {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "chunked OPN not supported"));
        }
        let rx = std::mem::take(&mut self.rx);
        let result = self.open_channel_inner(&rx);
        self.rx = rx;
        result
    }

    /// Decrypts and verifies an asymmetric OPN body. Returns the plain text
    /// (sequence header + message body) and the validated client certificate.
    fn unprotect_asymmetric(
        &self,
        policy: Policy,
        rx: &[u8],
        asym_end: usize,
        sender_cert: Option<&[u8]>,
        thumbprint: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Arc<CertInfo>), Fatal> {
        let pki = self.server.pki();
        let cert = sender_cert.filter(|c| !c.is_empty()).ok_or(checks_failed("missing client certificate"))?;
        let info = pki.validate_application(cert).map_err(|code| {
            crate::log!("client certificate rejected (0x{code:08X})");
            Fatal::Protocol(code, "client certificate rejected")
        })?;
        if info.key_bits < policy.min_key_bits() || info.key_bits > policy.max_key_bits() {
            return Err(Fatal::Protocol(status::BAD_SECURITY_POLICY_REJECTED, "client key size not allowed"));
        }
        if thumbprint != Some(&pki.thumbprint[..]) {
            return Err(checks_failed("receiver certificate thumbprint mismatch"));
        }
        if let Some(ch) = &self.channel {
            if ch.security.client_cert.as_ref().map(|c| &c.der) != Some(&info.der) {
                return Err(checks_failed("certificate changed on renew"));
            }
        }

        let mut plain = Vec::with_capacity(rx.len());
        policy
            .asym_decrypt(&pki.key.decrypt, &rx[asym_end..], &mut plain)
            .map_err(|_| checks_failed("decryption failed"))?;
        let sig_len = info.key_bits / 8;
        if plain.len() < 8 + sig_len + 1 {
            return Err(checks_failed("message too short"));
        }
        let end = plain.len() - sig_len;
        let mut signed = Vec::with_capacity(8 + asym_end + end);
        signed.extend_from_slice(&self.hdr);
        signed.extend_from_slice(&rx[..asym_end]);
        signed.extend_from_slice(&plain[..end]);
        policy
            .asym_verify(&info.rsa_public_key, &signed, &plain[end..])
            .map_err(|_| checks_failed("signature invalid"))?;

        // Padding was computed against our key (the one used to encrypt).
        let extra = pki.key.size_bytes() > 256;
        let body_end = strip_padding(&plain[..end], extra).ok_or(checks_failed("padding invalid"))?;
        plain.truncate(body_end);
        Ok((plain, Arc::new(info)))
    }

    /// Verifies an ECC OPN (signed, never encrypted). Returns the plain text,
    /// the validated client certificate and the request signature.
    fn unprotect_ecc(
        &self,
        suite: ecc::Suite,
        rx: &[u8],
        asym_end: usize,
        sender_cert: Option<&[u8]>,
        thumbprint: Option<&[u8]>,
    ) -> Result<VerifiedOpn, Fatal> {
        let pki = self.server.pki();
        let own = pki.ecc_own(suite.curve).ok_or(checks_failed("no certificate for the curve"))?;
        let cert = sender_cert.filter(|c| !c.is_empty()).ok_or(checks_failed("missing client certificate"))?;
        let info = pki.validate_application(cert).map_err(|code| {
            crate::log!("client certificate rejected (0x{code:08X})");
            Fatal::Protocol(code, "client certificate rejected")
        })?;
        if info.curve != Some(suite.curve) {
            return Err(Fatal::Protocol(status::BAD_SECURITY_POLICY_REJECTED, "client key not on the policy curve"));
        }
        if thumbprint != Some(&own.thumbprint[..]) {
            return Err(checks_failed("receiver certificate thumbprint mismatch"));
        }
        if let Some(ch) = &self.channel {
            if ch.security.client_cert.as_ref().map(|c| &c.der) != Some(&info.der) {
                return Err(checks_failed("certificate changed on renew"));
            }
        }
        let sig_len = suite.signature_len();
        let end =
            rx.len().checked_sub(sig_len).filter(|&e| e >= asym_end + 8).ok_or(checks_failed("message too short"))?;
        let mut signed = Vec::with_capacity(8 + end);
        signed.extend_from_slice(&self.hdr);
        signed.extend_from_slice(&rx[..end]);
        suite.verify(&info.rsa_public_key, &signed, &rx[end..]).map_err(|_| checks_failed("signature invalid"))?;
        // The padding byte (0x00, no padding) is left in place: the decoder
        // stops at the end of the request.
        Ok((rx[asym_end..end].to_vec(), Arc::new(info), rx[end..].to_vec()))
    }

    fn open_channel_inner(&mut self, rx: &[u8]) -> Result<(), Fatal> {
        let mut r = Reader::new(rx);
        let channel_id = r.u32()?;
        let policy_uri = r.str()?.unwrap_or("");
        let sender_cert = r.bytes()?;
        let thumbprint = r.bytes()?;
        let asym_end = r.position();
        let policy = Policy::from_uri(policy_uri)
            .filter(|p| *p == Policy::None || self.server.policy_enabled(*p))
            .ok_or(Fatal::Protocol(status::BAD_SECURITY_POLICY_REJECTED, "security policy not supported"))?;
        if let Some(ch) = &self.channel {
            if ch.security.policy != policy {
                return Err(checks_failed("security policy changed on renew"));
            }
        }

        let mut request_sig = Vec::new();
        let (plain, client_cert) = match policy {
            Policy::None => (rx[asym_end..].to_vec(), None),
            Policy::Ecc(suite) => {
                let (p, c, sig) = self.unprotect_ecc(suite, rx, asym_end, sender_cert, thumbprint)?;
                request_sig = sig;
                (p, Some(c))
            }
            _ => {
                let (p, c) = self.unprotect_asymmetric(policy, rx, asym_end, sender_cert, thumbprint)?;
                (p, Some(c))
            }
        };

        let mut r = Reader::new(&plain);
        let seq = r.u32()?;
        let request_id = r.u32()?;
        // A new channel restarts the client's sequence numbering.
        if self.channel.is_none() {
            self.last_client_seq = None;
            self.legacy_seq = !policy.is_ecc();
        }
        self.check_sequence(seq)?;
        let type_id = r.node_id()?;
        if type_id.as_ns0() != Some(ids::OPEN_SECURE_CHANNEL_REQUEST) {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "OPN without OpenSecureChannelRequest"));
        }
        let header = services::RequestHeader::decode(&mut r)?;
        let _client_protocol = r.u32()?;
        let request_type = r.u32()?;
        let mode = Mode::from_u32(r.u32()?).ok_or(checks_failed("invalid security mode"))?;
        let client_nonce = r.bytes()?.unwrap_or(&[]).to_vec();
        let requested_lifetime = r.u32()?;

        let mode_ok = match policy {
            Policy::None => mode == Mode::None,
            p => mode != Mode::None && self.server.endpoint_enabled(p, mode),
        };
        if !mode_ok {
            return Err(Fatal::Protocol(status::BAD_SECURITY_POLICY_REJECTED, "security mode not supported"));
        }
        let mut server_nonce = vec![0u8; policy.nonce_len()];
        if policy != Policy::None && client_nonce.len() != policy.nonce_len() {
            return Err(Fatal::Protocol(BAD_NONCE_INVALID, "client nonce has wrong length"));
        }
        let mut ikm = Vec::new();
        let keys = match policy {
            Policy::None => None,
            Policy::Ecc(suite) => {
                // Ephemeral key agreement; the nonces are the public keys.
                let kd = || checks_failed("key derivation");
                let eph = ecc::Ephemeral::generate(suite).map_err(|_| kd())?;
                server_nonce.copy_from_slice(&eph.public);
                let secret = eph
                    .agree(suite, &client_nonce)
                    .map_err(|_| Fatal::Protocol(BAD_NONCE_INVALID, "bad client nonce"))?;
                ikm = match &self.channel {
                    Some(ch) => ch.ikm.clone(),
                    None => vec![0u8; suite.secret_len()],
                };
                Some(Keys::Ecc(
                    EccKeys::derive(suite, &mut ikm, &secret, &client_nonce, &server_nonce).map_err(|_| kd())?,
                ))
            }
            p => {
                random_bytes(&mut server_nonce);
                Some(Keys::Rsa(
                    ChannelKeys::derive(p, &client_nonce, &server_nonce)
                        .map_err(|_| checks_failed("key derivation"))?,
                ))
            }
        };

        let limits = self.server.limits();
        let lifetime = requested_lifetime.clamp(limits.min_token_lifetime_ms, limits.max_token_lifetime_ms);
        let security = Security { policy, mode, client_cert: client_cert.clone(), channel_thumbprint: None };
        let ch = match (request_type, self.channel.as_mut()) {
            (0, None) => {
                if channel_id != 0 {
                    return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "issue on unknown channel"));
                }
                self.channel = Some(Channel {
                    id: self.server.next_channel_id(),
                    token_id: 1,
                    prev_token_id: None,
                    token_created: Instant::now(),
                    lifetime_ms: lifetime,
                    security,
                    keys,
                    prev_keys: None,
                    ikm,
                });
                // ECC sequence numbers start at 0 with this response.
                if policy.is_ecc() {
                    self.next_seq = 0;
                }
                self.channel.as_ref().unwrap()
            }
            (1, Some(ch)) if ch.id == channel_id && ch.security.mode == mode => {
                ch.prev_token_id = Some(ch.token_id);
                ch.prev_keys = ch.keys.take();
                ch.keys = keys;
                ch.ikm = ikm;
                ch.token_id = ch.token_id.wrapping_add(1).max(1);
                ch.token_created = Instant::now();
                ch.lifetime_ms = lifetime;
                ch
            }
            _ => {
                return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "invalid OpenSecureChannel request"))
            }
        };
        let (id, token_id) = (ch.id, ch.token_id);
        let first = request_type == 0;

        // Response body (sequence header + OpenSecureChannelResponse).
        let seq_out = self.next_sequence();
        let mut body = Vec::with_capacity(256);
        {
            let mut w = Writer::new(&mut body);
            w.u32(seq_out);
            w.u32(request_id);
            w.node_id(&NodeId::ns0(ids::OPEN_SECURE_CHANNEL_RESPONSE));
            services::write_response_header(&mut w, header.now, header.handle, status::GOOD);
            w.u32(PROTOCOL_VERSION);
            w.u32(id);
            w.u32(token_id);
            w.i64(now_ticks());
            w.u32(lifetime);
            w.bytes(Some(&server_nonce));
        }

        self.tx.clear();
        let mut w = Writer::new(&mut self.tx);
        w.raw(b"OPNF");
        w.u32(0);
        w.u32(id);
        w.string(policy.uri());
        match &client_cert {
            None => {
                w.bytes(None);
                w.bytes(None);
                w.raw(&body);
                let len = w.len() as u32;
                w.patch_u32(4, len);
            }
            Some(client) if policy.is_ecc() => {
                let suite = policy.ecc().unwrap();
                let own =
                    self.server.pki().ecc_own(suite.curve).ok_or(checks_failed("no certificate for the curve"))?;
                w.bytes(Some(&own.cert_der));
                w.bytes(Some(&client.thumbprint));
                // No encryption: one padding byte (no padding), then the
                // signature.
                body.push(0);
                let sig_len = suite.signature_len();
                let len = (w.len() + body.len() + sig_len) as u32;
                w.patch_u32(4, len);
                w.raw(&body);
                // First exchange (SecureChannelEnhancements): the signature
                // also covers the client's request signature and becomes the
                // ChannelThumbprint.
                let sig = if first {
                    let mut signed = Vec::with_capacity(w.len() + request_sig.len());
                    signed.extend_from_slice(w.buf);
                    signed.extend_from_slice(&request_sig);
                    own.key.sign(&signed)
                } else {
                    own.key.sign(w.buf)
                };
                let sig = sig.map_err(|_| checks_failed("signing failed"))?;
                w.raw(&sig);
                debug_assert_eq!(w.buf.len() as u32, len);
                if first {
                    if let Some(ch) = self.channel.as_mut() {
                        ch.security.channel_thumbprint = Some(sig.into());
                    }
                }
            }
            Some(client) => {
                let pki = self.server.pki();
                w.bytes(Some(&pki.cert_der));
                w.bytes(Some(&client.thumbprint));
                let client_bytes = client.key_bits / 8;
                let block_in = client_bytes - policy.oaep_overhead();
                let sig_len = pki.key.size_bytes();
                let extra = client_bytes > 256;
                let (pad, _) = crypto::padding(body.len(), sig_len, block_in, extra);
                body.extend(std::iter::repeat_n((pad & 0xFF) as u8, pad + 1));
                if extra {
                    body.push((pad >> 8) as u8);
                }
                let encrypted_len = (body.len() + sig_len) / block_in * client_bytes;
                let len = (w.len() + encrypted_len) as u32;
                w.patch_u32(4, len);
                let mut signed = Vec::with_capacity(w.len() + body.len());
                signed.extend_from_slice(w.buf);
                signed.extend_from_slice(&body);
                let sig = policy.asym_sign(&pki.key.sign, &signed).map_err(|_| checks_failed("signing failed"))?;
                body.extend_from_slice(&sig);
                policy.asym_encrypt(&client.spki, &body, w.buf).map_err(|_| checks_failed("encryption failed"))?;
                debug_assert_eq!(w.buf.len() as u32, len);
            }
        }
        if self.tx.len() > self.send_buffer as usize {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TOO_LARGE, "OPN response larger than client buffer"));
        }
        self.stream.write_all(&self.tx)?;
        Ok(())
    }

    // ------------------------------------------------------------- MSG / CLO

    /// Checks channel and token, verifies and decrypts `rx` in place.
    /// Returns (request id, body start, body end) within `rx`.
    fn unprotect(&mut self) -> Result<(u32, usize, usize), Fatal> {
        let rx = &mut self.rx;
        if rx.len() < 16 {
            return Err(Fatal::Protocol(status::BAD_DECODING_ERROR, "message too short"));
        }
        let channel_id = u32::from_le_bytes(rx[0..4].try_into().unwrap());
        let token_id = u32::from_le_bytes(rx[4..8].try_into().unwrap());
        let ch =
            self.channel.as_mut().ok_or(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "no secure channel"))?;
        if ch.id != channel_id {
            return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "wrong secure channel id"));
        }
        let use_prev = if token_id == ch.token_id {
            false
        } else if Some(token_id) == ch.prev_token_id {
            true
        } else {
            return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "unknown security token"));
        };
        // Part 4 §5.5.2: the token stays valid for 125% of its lifetime.
        if !use_prev && ch.token_created.elapsed().as_millis() as u64 > ch.lifetime_ms as u64 * 5 / 4 {
            return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "security token expired"));
        }

        let mut end = rx.len();
        let encrypt = ch.security.mode == Mode::SignAndEncrypt;
        if ch.security.mode != Mode::None {
            let keys = if use_prev { ch.prev_keys.as_ref() } else { ch.keys.as_ref() };
            let keys = match keys.ok_or(checks_failed("no keys"))? {
                Keys::Rsa(k) => &k.remote,
                Keys::Ecc(k) => {
                    // AEAD: the IV is masked with the token and the last
                    // sequence number received.
                    let prev = self.last_client_seq.unwrap_or(0);
                    end = end.checked_sub(TAG_LEN).filter(|&e| e >= 16).ok_or(checks_failed("message too short"))?;
                    let (msg, tag) = rx.split_at_mut(end);
                    let ok = if encrypt {
                        let mut aad = [0u8; 16];
                        aad[..8].copy_from_slice(&self.hdr);
                        aad[8..].copy_from_slice(&msg[..8]);
                        k.remote.open(token_id, prev, &aad, &mut msg[8..], tag)
                    } else {
                        // Sign: the tag authenticates the whole chunk.
                        let aad = &mut self.out;
                        aad.clear();
                        aad.extend_from_slice(&self.hdr);
                        aad.extend_from_slice(msg);
                        k.remote.open(token_id, prev, aad, &mut [], tag)
                    };
                    ok.map_err(|_| checks_failed("authentication failed"))?;
                    return self.accept(use_prev, end);
                }
            };
            if encrypt {
                keys.decrypt(&mut rx[8..]).map_err(|_| checks_failed("decryption failed"))?;
            }
            if end < 8 + 8 + SYM_SIGNATURE_LEN {
                return Err(checks_failed("message too short"));
            }
            end -= SYM_SIGNATURE_LEN;
            if !keys.verify_parts(&[&self.hdr, &rx[..end]], &rx[end..]) {
                return Err(checks_failed("signature invalid"));
            }
            if encrypt {
                end = 8 + strip_padding(&rx[8..end], false).ok_or(checks_failed("padding invalid"))?;
            }
        }
        self.accept(use_prev, end)
    }

    /// Second half of [`Self::unprotect`], once the chunk is authentic.
    #[inline(always)]
    fn accept(&mut self, use_prev: bool, end: usize) -> Result<(u32, usize, usize), Fatal> {
        let ch = self.channel.as_mut().ok_or(checks_failed("no channel"))?;
        if !use_prev && ch.prev_token_id.is_some() {
            // The client switched to the new token: retire the old one.
            ch.prev_token_id = None;
            ch.prev_keys = None;
        }
        if end < 16 {
            return Err(Fatal::Protocol(status::BAD_DECODING_ERROR, "message too short"));
        }
        let seq = u32::from_le_bytes(self.rx[8..12].try_into().unwrap());
        let request_id = u32::from_le_bytes(self.rx[12..16].try_into().unwrap());
        self.check_sequence(seq)?;
        Ok((request_id, 16, end))
    }

    fn message(&mut self, chunk: u8) -> Result<(), Fatal> {
        let (request_id, body_at, body_end) = self.unprotect()?;
        let limits = self.server.limits();
        match chunk {
            b'F' if self.assembly_chunks == 0 => {
                let rx = std::mem::take(&mut self.rx);
                let r = self.handle_request(request_id, &rx[body_at..body_end]);
                self.rx = rx;
                r
            }
            b'C' | b'F' => {
                if self.assembly_chunks > 0 && request_id != self.assembly_request {
                    return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "interleaved chunks"));
                }
                self.assembly_chunks += 1;
                self.assembly_request = request_id;
                let max_chunks = limits.max_chunk_count;
                if (max_chunks != 0 && self.assembly_chunks > max_chunks)
                    || self.assembly.len() + body_end - body_at > limits.max_message_size as usize
                {
                    return Err(Fatal::Protocol(status::BAD_REQUEST_TOO_LARGE, "request too large"));
                }
                self.assembly.extend_from_slice(&self.rx[body_at..body_end]);
                if chunk == b'F' {
                    let body = std::mem::take(&mut self.assembly);
                    self.assembly_chunks = 0;
                    let r = self.handle_request(request_id, &body);
                    self.assembly = body;
                    self.assembly.clear();
                    if self.assembly.capacity() > 4 * limits.buffer_size as usize {
                        self.assembly.shrink_to(limits.buffer_size as usize);
                    }
                    r
                } else {
                    Ok(())
                }
            }
            b'A' => {
                self.assembly.clear();
                self.assembly_chunks = 0;
                Ok(())
            }
            _ => Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "bad chunk type")),
        }
    }

    fn handle_request(&mut self, request_id: u32, body: &[u8]) -> Result<(), Fatal> {
        let ch = self.channel.as_ref().ok_or(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "no channel"))?;
        let mut tx = std::mem::take(&mut self.tx);
        tx.clear();
        tx.resize(MSG_HEADER_LEN, 0);
        let mut r = Reader::new(body);
        let handle = {
            let mut w = Writer::new(&mut tx);
            self.conn.request_id = request_id;
            let mut ctx = services::Ctx {
                server: self.server,
                channel_id: ch.id,
                security: &ch.security,
                session: &mut self.session,
                space: &mut self.space,
                conn: &mut self.conn,
            };
            services::dispatch(&mut ctx, &mut r, &mut w)
        };
        let res = if std::mem::take(&mut self.conn.deferred) {
            Ok(())
        } else {
            let id = self.conn.reply_to.take().unwrap_or(request_id);
            self.send_response(id, &mut tx, handle)
        };
        self.tx = tx;
        res
    }

    /// Frames `tx[24..]` into one or more MSG chunks, secures and sends them.
    fn send_response(&mut self, request_id: u32, tx: &mut Vec<u8>, handle: u32) -> Result<(), Fatal> {
        let (policy, mode) =
            self.channel.as_ref().map(|c| (c.security.policy, c.security.mode)).unwrap_or((Policy::None, Mode::None));
        let max_body = match mode {
            Mode::None => self.send_buffer as usize - MSG_HEADER_LEN,
            // AEAD: a tag, no padding.
            _ if policy.is_ecc() => self.send_buffer as usize - MSG_HEADER_LEN - TAG_LEN,
            Mode::Sign => self.send_buffer as usize - MSG_HEADER_LEN - SYM_SIGNATURE_LEN,
            Mode::SignAndEncrypt => {
                let encrypted = (self.send_buffer as usize - SYM_CLEAR_LEN) / crypto::AES_BLOCK * crypto::AES_BLOCK;
                encrypted - 8 - SYM_SIGNATURE_LEN - 1
            }
        };
        let body_len = tx.len() - MSG_HEADER_LEN;
        let chunks = body_len.div_ceil(max_body).max(1);
        if self.too_big(body_len, chunks) {
            tx.truncate(MSG_HEADER_LEN);
            let mut w = Writer::new(tx);
            services::write_fault(&mut w, handle, status::BAD_RESPONSE_TOO_LARGE);
            return self.send_response(request_id, tx, handle);
        }

        if chunks == 1 {
            let seq = self.next_sequence();
            self.finish_chunk(tx, 0, b'F', seq, request_id, mode)?;
            self.stream.write_all(tx)?;
            return Ok(());
        }
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        out.reserve(body_len + chunks * (MSG_HEADER_LEN + 64));
        for (i, part) in tx[MSG_HEADER_LEN..].chunks(max_body).enumerate() {
            let kind = if i + 1 == chunks { b'F' } else { b'C' };
            let seq = self.next_sequence();
            let at = out.len();
            out.resize(at + MSG_HEADER_LEN, 0);
            out.extend_from_slice(part);
            self.finish_chunk(&mut out, at, kind, seq, request_id, mode)?;
        }
        let r = self.stream.write_all(&out);
        self.out = out;
        r?;
        Ok(())
    }

    fn too_big(&self, body_len: usize, chunks: usize) -> bool {
        (self.client_max_message != 0 && body_len > self.client_max_message as usize)
            || (self.client_max_chunks != 0 && chunks > self.client_max_chunks as usize)
    }

    /// `send_response(tx)` leaves the body of `tx` as it is: no encryption in
    /// place and no BadResponseTooLarge fault instead of it.
    fn sent_intact(&self, tx: &[u8]) -> bool {
        let (policy, mode) =
            self.channel.as_ref().map(|c| (c.security.policy, c.security.mode)).unwrap_or((Policy::None, Mode::None));
        match mode {
            Mode::SignAndEncrypt => false,
            mode => {
                let sig = match mode {
                    Mode::None => 0,
                    _ if policy.is_ecc() => TAG_LEN,
                    _ => SYM_SIGNATURE_LEN,
                };
                let max_body = self.send_buffer as usize - MSG_HEADER_LEN - sig;
                let body_len = tx.len() - MSG_HEADER_LEN;
                !self.too_big(body_len, body_len.div_ceil(max_body).max(1))
            }
        }
    }

    /// `buf[start..]` holds a reserved 24-byte header followed by the chunk
    /// body. Writes the header, then pads, signs and encrypts in place.
    #[inline]
    fn finish_chunk(
        &self,
        buf: &mut Vec<u8>,
        start: usize,
        kind: u8,
        seq: u32,
        request_id: u32,
        mode: Mode,
    ) -> Result<(), Fatal> {
        let ch = self.channel.as_ref().ok_or(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "no channel"))?;
        let (token, keys) = ch.sending();
        if let Some(Keys::Ecc(k)) = keys {
            let size = (buf.len() - start + TAG_LEN) as u32;
            write_msg_header(&mut buf[start..start + MSG_HEADER_LEN], kind, size, ch.id, token, seq, request_id);
            // The receiver masks the IV with the last sequence number it got.
            let prev = seq.wrapping_sub(1);
            let tag = if mode == Mode::SignAndEncrypt {
                let (aad, data) = buf[start..].split_at_mut(SYM_CLEAR_LEN);
                k.local.seal(token, prev, aad, data)
            } else {
                k.local.seal(token, prev, &buf[start..], &mut [])
            };
            buf.extend_from_slice(&tag.map_err(|_| checks_failed("encryption failed"))?);
            return Ok(());
        }
        let keys = match keys {
            Some(Keys::Rsa(k)) => Some(&k.local),
            _ => None,
        };
        if mode == Mode::SignAndEncrypt {
            let plain = buf.len() - start - SYM_CLEAR_LEN;
            let (pad, _) = crypto::padding(plain, SYM_SIGNATURE_LEN, crypto::AES_BLOCK, false);
            buf.extend(std::iter::repeat_n(pad as u8, pad + 1));
        }
        let sig_len = if mode == Mode::None { 0 } else { SYM_SIGNATURE_LEN };
        let size = (buf.len() - start + sig_len) as u32;
        write_msg_header(&mut buf[start..start + MSG_HEADER_LEN], kind, size, ch.id, token, seq, request_id);
        if mode != Mode::None {
            let keys = keys.ok_or(checks_failed("no keys"))?;
            let sig = keys.sign(&buf[start..]);
            buf.extend_from_slice(&sig);
            if mode == Mode::SignAndEncrypt {
                keys.encrypt(&mut buf[start + SYM_CLEAR_LEN..]).map_err(|_| checks_failed("encryption failed"))?;
            }
        }
        Ok(())
    }
}

/// Validates and removes `PaddingSize | Padding | [ExtraPaddingSize]` at the
/// end of `data`; returns the length of what precedes the padding.
pub(crate) fn strip_padding(data: &[u8], extra: bool) -> Option<usize> {
    let n = data.len();
    let tail = extra as usize;
    if n < 1 + tail {
        return None;
    }
    let lo = data[n - 1 - tail];
    let pad = if extra { (data[n - 1] as usize) << 8 | lo as usize } else { lo as usize };
    let region = pad + 1;
    if region + tail > n {
        return None;
    }
    let start = n - tail - region;
    // Constant-time-ish check: accumulate differences.
    let diff = data[start..n - tail].iter().fold(0u8, |acc, b| acc | (b ^ lo));
    (diff == 0).then_some(start)
}

#[inline(always)]
fn write_msg_header(h: &mut [u8], kind: u8, size: u32, channel: u32, token: u32, seq: u32, request_id: u32) {
    h[0..3].copy_from_slice(b"MSG");
    h[3] = kind;
    h[4..8].copy_from_slice(&size.to_le_bytes());
    h[8..12].copy_from_slice(&channel.to_le_bytes());
    h[12..16].copy_from_slice(&token.to_le_bytes());
    h[16..20].copy_from_slice(&seq.to_le_bytes());
    h[20..24].copy_from_slice(&request_id.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::strip_padding;

    #[test]
    fn padding_stripping() {
        assert_eq!(strip_padding(&[9, 9, 2, 2, 2], false), Some(2));
        assert_eq!(strip_padding(&[9, 0], false), Some(1));
        assert_eq!(strip_padding(&[9, 3, 2, 2], false), None);
        assert_eq!(strip_padding(&[5, 5], false), None);
        // Extra padding byte: pad = 0x0001 -> two low bytes + one high byte.
        assert_eq!(strip_padding(&[7, 1, 1, 0], true), Some(1));
    }
}
