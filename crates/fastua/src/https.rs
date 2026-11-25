//! HTTPS transport (`opc.https`, Part 6 §7.4, https-uabinary): each HTTP
//! POST carries one binary encoded request (type NodeId and body, no
//! secure channel framing) and its response carries the binary encoded
//! response. TLS protects the messages; the endpoint is SecurityPolicy None
//! and user tokens are protected like on the unsecured opc.tcp endpoint.
//!
//! One thread per TLS connection, HTTP/1.1 keep-alive, requests answered in
//! order. A TLS connection is a virtual secure channel: a session is bound
//! to the connection that activated it (ActivateSession on another one
//! moves it). A Publish holds its HTTP response until a notification or a
//! keep-alive is due, so clients keep a Publish outstanding as usual; the
//! subscriptions of the connection are evaluated while it waits.

use crate::channel::{Security, MSG_HEADER_LEN};
use crate::codec::{Reader, Writer};
use crate::server::Server;
use crate::services;
use crate::subscription::mono_ns;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Transport profile of the HTTPS endpoint.
pub const TRANSPORT_PROFILE_HTTPS: &str = "http://opcfoundation.org/UA-Profile/Transport/https-uabinary";

/// Largest request line plus headers.
const MAX_HEAD: usize = 16 * 1024;

/// TLS configuration from the server's application certificate and its
/// PKCS#8 private key (DER).
pub fn tls_config(cert_der: &[u8], key_pkcs8: &[u8]) -> Result<Arc<rustls::ServerConfig>, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8.to_vec())),
        )
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(config))
}

/// Accepts HTTPS connections forever, one thread per connection.
pub fn serve(server: Arc<Server>, listener: TcpListener, tls: Arc<rustls::ServerConfig>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                crate::log!("https accept failed: {e}");
                continue;
            }
        };
        let (server, tls) = (server.clone(), tls.clone());
        let r = std::thread::Builder::new().name("fastua-https".into()).spawn(move || {
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            if let Err(e) = connection(&server, stream, tls) {
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
}

fn read_head(r: &mut impl BufRead, line: &mut String) -> io::Result<Option<Head>> {
    let mut head = Head { post: false, length: None, chunked: false, close: false };
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
        }
    }
}

fn respond(w: &mut impl Write, code: &str, body: &[u8], close: bool) -> io::Result<()> {
    let mut head = Vec::with_capacity(160);
    write!(
        head,
        "HTTP/1.1 {code}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{}\r\n",
        body.len(),
        if close { "Connection: close\r\n" } else { "" }
    )?;
    w.write_all(&head)?;
    w.write_all(body)?;
    w.flush()
}

fn connection(server: &Arc<Server>, stream: TcpStream, tls: Arc<rustls::ServerConfig>) -> io::Result<()> {
    let limits = server.limits().clone();
    let _ = stream.set_nodelay(true);
    stream.set_read_timeout(Some(limits.hello_timeout))?;
    let conn = rustls::ServerConnection::new(tls).map_err(io::Error::other)?;
    let tls = rustls::StreamOwned::new(conn, stream);
    let mut tls = BufReader::with_capacity(64 * 1024, tls);
    let channel_id = server.next_channel_id();
    let security = Security::HTTPS;
    let mut session = None;
    let mut space = None;
    let mut conn = services::ConnState::new(limits.max_message_size as usize);
    let mut line = String::new();
    let mut body = Vec::new();
    let mut tx: Vec<u8> = Vec::with_capacity(limits.buffer_size as usize);
    let mut request_id = 0u32;
    loop {
        let Some(head) = read_head(&mut tls, &mut line)? else { return Ok(()) };
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
        request_id = request_id.wrapping_add(1);

        tx.clear();
        tx.resize(MSG_HEADER_LEN, 0);
        conn.request_id = request_id;
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
            wait_publish(server, channel_id, &mut conn, &mut space, &mut tx);
        }
        let _ = handle;
        if tx.len() - MSG_HEADER_LEN > conn.max_response {
            tx.truncate(MSG_HEADER_LEN);
            services::write_fault(&mut Writer::new(&mut tx), handle, crate::types::status::BAD_RESPONSE_TOO_LARGE);
        }
        respond(tls.get_mut(), "200 OK", &tx[MSG_HEADER_LEN..], head.close)?;
        if head.close {
            return Ok(());
        }
    }
}

/// Runs the subscriptions of this connection until a Publish response is
/// written to `tx`.
fn wait_publish(
    server: &Arc<Server>,
    channel_id: u32,
    conn: &mut services::ConnState,
    space: &mut Option<Arc<crate::address_space::AddressSpace>>,
    tx: &mut Vec<u8>,
) {
    let limits = server.limits();
    loop {
        let now = mono_ns();
        server.store.cached(space);
        let mut deadline = u64::MAX;
        for s in &conn.sessions {
            if s.closed.load(std::sync::atomic::Ordering::Acquire)
                || s.channel_id.load(std::sync::atomic::Ordering::Acquire) != channel_id
            {
                continue;
            }
            let mut st = s.subs.lock().unwrap_or_else(|e| e.into_inner());
            st.tick(now, space.as_ref().unwrap());
            tx.clear();
            tx.resize(MSG_HEADER_LEN, 0);
            if st.write_next(limits, now, channel_id, conn.max_response, &mut Writer::new(tx), true).is_some() {
                // Kept for Republish (a copy: `tx` is sent after this).
                let mut copy = tx.clone();
                st.keep_sent(&mut copy, true);
                return;
            }
            deadline = deadline.min(st.next_deadline());
        }
        if deadline == u64::MAX {
            // Nothing will ever answer it (the session went away).
            tx.clear();
            tx.resize(MSG_HEADER_LEN, 0);
            services::write_fault(&mut Writer::new(tx), 0, crate::types::status::BAD_SESSION_CLOSED);
            return;
        }
        let now = mono_ns();
        if deadline > now {
            std::thread::sleep(Duration::from_nanos(deadline - now));
        }
    }
}
