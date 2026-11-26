//! HTTPS transport (`opc.https`, Part 6 §7.4, https-uabinary): each HTTP
//! POST carries one binary encoded request (type NodeId and body, no
//! secure channel framing) and its response carries the binary encoded
//! response. TLS protects the messages; the endpoint is SecurityPolicy None
//! and user tokens are protected like on the unsecured opc.tcp endpoint.
//!
//! One thread per TLS connection, HTTP/1.1 keep-alive, requests answered in
//! order. HTTP clients spread the requests of one session over several
//! connections (the OPC Foundation stack does): the connections of one
//! client identity (its TLS client certificate, or none) form one virtual
//! secure channel, so a session works on any of them, while a session
//! activated with a certificate is out of reach of the others. A Publish
//! holds its HTTP response until a notification or a keep-alive is due, so
//! clients keep Publish requests outstanding as usual; each one waits on
//! its own connection, evaluating the session's subscriptions, and the
//! session's queue answers them in order.
//!
//! TLS client certificates (Part 6 §7.4.3): the server asks for one
//! ([`ClientAuth`]). A certificate the client presents is validated against
//! the application trust list like an opc.tcp client certificate; it becomes
//! the connection's client certificate, and CreateSession must then name
//! the same certificate and its ApplicationUri.

use crate::channel::{Security, MSG_HEADER_LEN};
use crate::codec::{Reader, Writer};
use crate::json::{self, Transcoder};
use crate::server::Server;
use crate::services;
use crate::subscription::mono_ns;
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Transport profile of the HTTPS endpoint.
pub const TRANSPORT_PROFILE_HTTPS: &str = "http://opcfoundation.org/UA-Profile/Transport/https-uabinary";
/// The same URL with the JSON encoding (`Content-Type: application/json`).
pub const TRANSPORT_PROFILE_HTTPS_JSON: &str = "http://opcfoundation.org/UA-Profile/Transport/https-uajson";

/// Largest request line plus headers.
const MAX_HEAD: usize = 16 * 1024;

/// Whether HTTPS clients present a TLS client certificate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientAuth {
    /// Not asked for.
    Off,
    /// Asked for; clients without one connect as before.
    Optional,
    /// Required: the handshake fails without one.
    Required,
}

/// Accepts any client certificate during the handshake (checking only the
/// proof of possession); the trust list decides once the connection is up
/// (see [`connection`]), with the codes of the opc.tcp checks.
#[derive(Debug)]
struct AnyClient {
    provider: Arc<rustls::crypto::CryptoProvider>,
    mandatory: bool,
}

impl rustls::server::danger::ClientCertVerifier for AnyClient {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS configuration from the server's application certificate and its
/// PKCS#8 private key (DER).
pub fn tls_config(cert_der: &[u8], key_pkcs8: &[u8], clients: ClientAuth) -> Result<Arc<rustls::ServerConfig>, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let builder = match clients {
        ClientAuth::Off => builder.with_no_client_auth(),
        _ => builder
            .with_client_cert_verifier(Arc::new(AnyClient { provider, mandatory: clients == ClientAuth::Required })),
    };
    let config = builder
        .with_single_cert(
            vec![CertificateDer::from(cert_der.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8.to_vec())),
        )
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(config))
}

/// State shared by the HTTPS connections.
struct Shared {
    /// Virtual secure channel of the connections without client certificate.
    anonymous: u32,
    /// Virtual secure channel per client certificate (DER).
    by_cert: Mutex<HashMap<Vec<u8>, u32>>,
    /// Request ids, unique across connections (Publish queues are shared).
    request_ids: AtomicU32,
}

impl Shared {
    fn channel_for(&self, server: &Server, cert: &[u8]) -> u32 {
        let mut map = self.by_cert.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&id) = map.get(cert) {
            return id;
        }
        // Bounded: a client cycling through certificates gets new channels
        // without growing the map forever.
        if map.len() >= 4096 {
            map.clear();
        }
        let id = server.next_channel_id();
        map.insert(cert.to_vec(), id);
        id
    }

    fn next_request_id(&self) -> u32 {
        loop {
            let id = self.request_ids.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            if id != 0 {
                return id;
            }
        }
    }
}

/// Accepts HTTPS connections forever, one thread per connection.
pub fn serve(server: Arc<Server>, listener: TcpListener, tls: Arc<rustls::ServerConfig>) {
    let shared = Arc::new(Shared {
        anonymous: server.next_channel_id(),
        by_cert: Mutex::new(HashMap::new()),
        request_ids: AtomicU32::new(0),
    });
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                crate::log!("https accept failed: {e}");
                continue;
            }
        };
        let (server, tls, shared) = (server.clone(), tls.clone(), shared.clone());
        let r = std::thread::Builder::new().name("fastua-https".into()).spawn(move || {
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            if let Err(e) = connection(&server, &shared, stream, tls) {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    crate::log!("https connection {peer} closed: {e}");
                }
            }
        });
        if let Err(e) = r {
            crate::log!("cannot spawn https connection thread: {e}");
        }
    }
}

/// A parsed HTTP request head.
struct Head {
    post: bool,
    length: Option<usize>,
    chunked: bool,
    close: bool,
    /// The body uses the JSON encoding (https-uajson), not UA binary.
    json: bool,
}

fn read_head(r: &mut impl BufRead, line: &mut String) -> io::Result<Option<Head>> {
    let mut head = Head { post: false, length: None, chunked: false, close: false, json: false };
    let mut total = 0;
    let mut first = true;
    loop {
        line.clear();
        let n = r.read_line(line)?;
        if n == 0 {
            return if first { Ok(None) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        }
        total += n;
        if total > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP header too large"));
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if first {
            if l.is_empty() {
                continue; // stray CRLF between requests
            }
            first = false;
            let mut parts = l.split(' ');
            head.post = parts.next() == Some("POST");
            head.close = parts.nth(1) == Some("HTTP/1.0");
            continue;
        }
        if l.is_empty() {
            return Ok(Some(head));
        }
        let Some((name, value)) = l.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            head.length = Some(value.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad length"))?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = value.eq_ignore_ascii_case("chunked");
        } else if name.eq_ignore_ascii_case("connection") {
            head.close = value.eq_ignore_ascii_case("close");
        } else if name.eq_ignore_ascii_case("content-type") {
            head.json = value.as_bytes().windows(4).any(|w| w.eq_ignore_ascii_case(b"json"));
        }
    }
}

fn respond(w: &mut impl Write, code: &str, body: &[u8], close: bool) -> io::Result<()> {
    respond_as(w, code, "application/octet-stream", body, close)
}

fn respond_as(w: &mut impl Write, code: &str, content_type: &str, body: &[u8], close: bool) -> io::Result<()> {
    let mut head = Vec::with_capacity(160);
    write!(
        head,
        "HTTP/1.1 {code}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{}\r\n",
        body.len(),
        if close { "Connection: close\r\n" } else { "" }
    )?;
    w.write_all(&head)?;
    w.write_all(body)?;
    w.flush()
}

fn connection(
    server: &Arc<Server>,
    shared: &Shared,
    stream: TcpStream,
    tls: Arc<rustls::ServerConfig>,
) -> io::Result<()> {
    let limits = server.limits().clone();
    let _ = stream.set_nodelay(true);
    stream.set_read_timeout(Some(limits.hello_timeout))?;
    let conn = rustls::ServerConnection::new(tls).map_err(io::Error::other)?;
    let tls = rustls::StreamOwned::new(conn, stream);
    let mut tls = BufReader::with_capacity(64 * 1024, tls);
    let mut channel_id = shared.anonymous;
    let mut security = Security::HTTPS;
    let mut first = true;
    let mut session = None;
    let mut space = None;
    let mut conn = services::ConnState::new(limits.max_message_size as usize);
    let mut line = String::new();
    let mut body = Vec::new();
    let mut json_in = Vec::new();
    let mut tx: Vec<u8> = Vec::with_capacity(limits.buffer_size as usize);
    loop {
        let Some(head) = read_head(&mut tls, &mut line)? else { return Ok(()) };
        if std::mem::take(&mut first) {
            // The handshake is done: check the client certificate, if any.
            if let Some(certs) = tls.get_ref().conn.peer_certificates() {
                let chain: Vec<u8> = certs.iter().flat_map(|c| c.as_ref().iter().copied()).collect();
                match server.pki().validate_application(&chain) {
                    Ok(info) => {
                        security.client_cert = Some(Arc::new(info));
                        channel_id = shared.channel_for(server, &chain);
                    }
                    Err(code) => {
                        crate::log!("https client certificate rejected (0x{code:08X})");
                        respond(tls.get_mut(), "403 Forbidden", b"", true)?;
                        return Ok(());
                    }
                }
            }
        }
        // Sessions may idle longer than a HEL: from now on, wait for the
        // next request as long as the longest session timeout.
        tls.get_ref().sock.set_read_timeout(Some(Duration::from_millis(limits.max_session_timeout_ms as u64)))?;
        if !head.post {
            respond(tls.get_mut(), "405 Method Not Allowed", b"", true)?;
            return Ok(());
        }
        if head.chunked {
            respond(tls.get_mut(), "411 Length Required", b"", true)?;
            return Ok(());
        }
        let Some(len) = head.length else {
            respond(tls.get_mut(), "411 Length Required", b"", true)?;
            return Ok(());
        };
        if len > limits.max_message_size as usize {
            respond(tls.get_mut(), "413 Content Too Large", b"", true)?;
            return Ok(());
        }
        body.resize(len, 0);
        tls.read_exact(&mut body)?;
        let request_id = shared.next_request_id();

        tx.clear();
        tx.resize(MSG_HEADER_LEN, 0);
        conn.request_id = request_id;
        // The JSON encoding is transcoded to and from UA binary around the
        // service layer, which only knows the binary encoding.
        let ns = if head.json {
            server.store.cached(&mut space);
            let ns = space.clone().expect("cached");
            json_in.clear();
            if let Err(e) = Transcoder::new(&ns.namespaces).message_to_binary(&body, &mut json_in) {
                crate::log!("https json request rejected: {e}");
                respond_as(tls.get_mut(), "400 Bad Request", "text/plain", e.as_bytes(), head.close)?;
                if head.close {
                    return Ok(());
                }
                continue;
            }
            std::mem::swap(&mut body, &mut json_in);
            Some(ns)
        } else {
            None
        };
        security.json = head.json;
        let mut r = Reader::new(&body);
        let handle = {
            let mut w = Writer::new(&mut tx);
            let mut ctx = services::Ctx {
                server,
                channel_id,
                security: &security,
                session: &mut session,
                space: &mut space,
                conn: &mut conn,
            };
            services::dispatch(&mut ctx, &mut r, &mut w)
        };
        conn.reply_to = None;
        if std::mem::take(&mut conn.deferred) {
            // Publish: answer it once the session has something to send.
            wait_publish(server, channel_id, request_id, session.clone(), &mut conn, &mut space, &mut tx);
        }
        let _ = handle;
        if tx.len() - MSG_HEADER_LEN > conn.max_response {
            tx.truncate(MSG_HEADER_LEN);
            services::write_fault(&mut Writer::new(&mut tx), handle, crate::types::status::BAD_RESPONSE_TOO_LARGE);
        }
        match ns {
            None => respond(tls.get_mut(), "200 OK", &tx[MSG_HEADER_LEN..], head.close)?,
            Some(ns) => match Transcoder::new(&ns.namespaces).message_to_json(&tx[MSG_HEADER_LEN..]) {
                Ok(out) => respond_as(tls.get_mut(), "200 OK", json::CONTENT_TYPE, &out, head.close)?,
                Err(e) => {
                    crate::log!("https json response not encodable: {e}");
                    respond_as(tls.get_mut(), "500 Internal Server Error", "text/plain", e.as_bytes(), true)?;
                    return Ok(());
                }
            },
        }
        if head.close {
            return Ok(());
        }
    }
}

/// Runs the session's subscriptions until the Publish request `request_id`
/// is answered into `tx` (the session's queue answers requests in order;
/// the ones ahead of it belong to other connections).
fn wait_publish(
    server: &Arc<Server>,
    channel_id: u32,
    request_id: u32,
    session: Option<Arc<crate::server::Session>>,
    conn: &mut services::ConnState,
    space: &mut Option<Arc<crate::address_space::AddressSpace>>,
    tx: &mut Vec<u8>,
) {
    let limits = server.limits();
    let gone = |tx: &mut Vec<u8>| {
        tx.clear();
        tx.resize(MSG_HEADER_LEN, 0);
        services::write_fault(&mut Writer::new(tx), 0, crate::types::status::BAD_SESSION_CLOSED);
    };
    let Some(s) = session else { return gone(tx) };
    loop {
        let now = mono_ns();
        server.store.cached(space);
        if s.closed.load(Ordering::Acquire) || s.channel_id.load(Ordering::Acquire) != channel_id {
            return gone(tx);
        }
        let (front, deadline) = {
            let mut st = s.subs.lock().unwrap_or_else(|e| e.into_inner());
            st.tick(now, space.as_ref().unwrap());
            let front = match st.request_position(request_id, channel_id) {
                // Dropped (the session moved to another channel).
                None => return gone(tx),
                Some(p) => p == 0,
            };
            if front {
                tx.clear();
                tx.resize(MSG_HEADER_LEN, 0);
                if st.write_next(limits, now, channel_id, conn.max_response, &mut Writer::new(tx), true).is_some() {
                    // Kept for Republish (a copy: `tx` is sent after this).
                    let mut copy = tx.clone();
                    st.keep_sent(&mut copy, true);
                    return;
                }
            }
            (front, st.next_deadline())
        };
        let now = mono_ns();
        // Behind another connection's request: check again shortly after
        // the deadline, when that request has been answered.
        let wake = if front { deadline } else { deadline.max(now + 200_000) };
        if wake > now {
            std::thread::sleep(Duration::from_nanos((wake - now).min(1_000_000_000)));
        }
    }
}
