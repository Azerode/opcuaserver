//! Minimal synchronous client (anonymous; SecurityPolicy None, or a secure
//! policy with mutual certificate authentication), used by the integration
//! tests and the latency benchmark. Not a general-purpose client.

use crate::codec::{Reader, Writer};
use crate::crypto::{self, ChannelKeys, Mode, Policy, PrivateKey, AES_BLOCK, SYM_SIGNATURE_LEN};
use crate::ecc::{self, EccKeys, LegacyKeys, SigningKey, TAG_LEN};
use crate::pki::CertInfo;
use crate::server::SECURITY_POLICY_NONE;
use crate::types::*;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

pub struct Client {
    stream: TcpStream,
    channel_id: u32,
    token_id: u32,
    seq: u32,
    /// Last sequence number received (ECC IV masking).
    last_rx_seq: u32,
    request_id: u32,
    handle: u32,
    pub auth_token: NodeId,
    tx: Vec<u8>,
    rx: Vec<u8>,
    /// Busy-poll for responses instead of sleeping in `recv`.
    pub spin: bool,
    /// Ask for an ephemeral ECDH key in the next requests (policy URI).
    ecdh: Option<&'static str>,
    sec: Option<Secure>,
    /// HTTPS transport (`opc.https`) instead of opc.tcp.
    https: Option<Box<Https>>,
}

/// An HTTPS connection: each request is a POST of its binary encoding.
struct Https {
    tls: std::io::BufReader<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>,
    host: String,
    line: String,
    /// TLS client certificate, sent again in CreateSession.
    cert: Option<Vec<u8>>,
}

/// Accepts exactly one server certificate (the tests pin the server's).
#[derive(Debug)]
struct Pinned {
    cert: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.cert.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
        }
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

impl Https {
    fn post(&mut self, body: &[u8]) -> io::Result<()> {
        let head = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            self.host,
            body.len()
        );
        let s = self.tls.get_mut();
        s.write_all(head.as_bytes())?;
        s.write_all(body)?;
        s.flush()
    }

    /// Reads one HTTP response into `rx`, after 16 zero bytes standing for
    /// the security and sequence headers of a MSG chunk.
    fn read(&mut self, rx: &mut Vec<u8>) -> io::Result<()> {
        use std::io::BufRead;
        let mut length = None;
        let mut status = String::new();
        loop {
            self.line.clear();
            if self.tls.read_line(&mut self.line)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let l = self.line.trim_end();
            if status.is_empty() {
                status = l.to_string();
                continue;
            }
            if l.is_empty() {
                break;
            }
            if let Some((n, v)) = l.split_once(':') {
                if n.eq_ignore_ascii_case("content-length") {
                    length = v.trim().parse::<usize>().ok();
                }
            }
        }
        if !status.contains(" 200 ") {
            return Err(invalid(&format!("HTTP: {status}")));
        }
        let n = length.ok_or_else(|| invalid("no Content-Length"))?;
        rx.clear();
        rx.resize(16 + n, 0);
        self.tls.read_exact(&mut rx[16..])
    }
}

/// Client side of a secure channel.
struct Secure {
    policy: Policy,
    mode: Mode,
    cert: Vec<u8>,
    key: ClientKey,
    server: CertInfo,
    keys: Option<ChannelKeys>,
    /// ECC: channel keys (server view: we seal with `remote`, open with
    /// `local`), IKM accumulator and ChannelThumbprint.
    ecc_keys: Option<EccKeys>,
    /// Deprecated ECC policies (server view, like `ecc_keys`).
    legacy_keys: Option<LegacyKeys>,
    ikm: Vec<u8>,
    thumbprint: Vec<u8>,
}

enum ClientKey {
    Rsa(PrivateKey),
    Ecc(SigningKey),
}

impl Secure {
    fn rsa(&self) -> &PrivateKey {
        match &self.key {
            ClientKey::Rsa(k) => k,
            ClientKey::Ecc(_) => panic!("RSA key expected"),
        }
    }

    fn ecc(&self) -> &SigningKey {
        match &self.key {
            ClientKey::Ecc(k) => k,
            ClientKey::Rsa(_) => panic!("ECC key expected"),
        }
    }
}

/// Bytes of a MSG chunk sent in clear: header (8), channel id, token id.
const SYM_CLEAR_LEN: usize = 16;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

impl Client {
    /// TCP connect + HEL/ACK + OpenSecureChannel.
    pub fn connect(addr: &str, endpoint: &str) -> io::Result<Client> {
        Self::connect_with(addr, endpoint, None)
    }

    /// Like [`Client::connect`] with a secure channel: `cert` / `key_pkcs8`
    /// are the client's certificate and private key, `server_cert` the
    /// server's certificate (its key encrypts the OpenSecureChannel request).
    pub fn connect_secure(
        addr: &str,
        endpoint: &str,
        policy: Policy,
        mode: Mode,
        cert: &[u8],
        key_pkcs8: &[u8],
        server_cert: &[u8],
    ) -> io::Result<Client> {
        let key = match policy.ecc() {
            Some(s) => {
                ClientKey::Ecc(SigningKey::from_pkcs8(s.curve, key_pkcs8).map_err(|_| invalid("bad client key"))?)
            }
            None => ClientKey::Rsa(PrivateKey::from_pkcs8(key_pkcs8).map_err(|_| invalid("bad client key"))?),
        };
        let server = crate::pki::inspect(server_cert).map_err(|_| invalid("bad server certificate"))?;
        let ikm = vec![0u8; policy.ecc().map_or(0, |s| s.secret_len())];
        let sec = Secure {
            policy,
            mode,
            cert: cert.to_vec(),
            key,
            server,
            keys: None,
            ecc_keys: None,
            legacy_keys: None,
            ikm,
            thumbprint: Vec::new(),
        };
        Self::connect_with(addr, endpoint, Some(sec))
    }

    fn connect_with(addr: &str, endpoint: &str, sec: Option<Secure>) -> io::Result<Client> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        let mut c = Client {
            stream,
            channel_id: 0,
            token_id: 0,
            // ECC sequence numbers start at 0.
            seq: if sec.as_ref().is_some_and(|s| s.policy.is_ecc()) { 0 } else { 1 },
            last_rx_seq: 0,
            request_id: 1,
            handle: 1,
            auth_token: NodeId::NULL,
            tx: Vec::with_capacity(65536),
            rx: Vec::with_capacity(65536),
            spin: false,
            ecdh: None,
            sec,
            https: None,
        };
        let mut w = Writer::new(&mut c.tx);
        w.raw(b"HELF");
        w.u32(0);
        w.u32(0);
        w.u32(65535);
        w.u32(65535);
        w.u32(0);
        w.u32(0);
        w.string(endpoint);
        let len = w.len() as u32;
        w.patch_u32(4, len);
        c.stream.write_all(&c.tx)?;
        let (ty, _) = c.read_chunk()?;
        if &ty != b"ACK" {
            return Err(invalid("expected ACK"));
        }
        c.open(0)?;
        Ok(c)
    }

    /// Connects over HTTPS (`opc.https`) to `addr`, accepting only the
    /// server certificate `server_cert` (DER).
    pub fn connect_https(addr: &str, host: &str, server_cert: &[u8]) -> io::Result<Client> {
        Self::connect_https_as(addr, host, server_cert, None)
    }

    /// Like [`Client::connect_https`], presenting `client` (certificate DER,
    /// PKCS#8 key) as TLS client certificate; CreateSession then sends it
    /// as the client certificate.
    pub fn connect_https_as(
        addr: &str,
        host: &str,
        server_cert: &[u8],
        client: Option<(&[u8], &[u8])>,
    ) -> io::Result<Client> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = Arc::new(Pinned { cert: server_cert.to_vec(), provider: provider.clone() });
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let config = match client {
            None => builder.with_no_client_auth(),
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(cert.to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
                )
                .map_err(io::Error::other)?,
        };
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| invalid("bad host name"))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        let tls = rustls::StreamOwned::new(conn, stream.try_clone()?);
        Ok(Client {
            stream,
            channel_id: 0,
            token_id: 0,
            seq: 1,
            last_rx_seq: 0,
            request_id: 1,
            handle: 1,
            auth_token: NodeId::NULL,
            tx: Vec::with_capacity(65536),
            rx: Vec::with_capacity(65536),
            spin: false,
            ecdh: None,
            sec: None,
            https: Some(Box::new(Https {
                tls: std::io::BufReader::new(tls),
                host: host.to_string(),
                line: String::new(),
                cert: client.map(|(c, _)| c.to_vec()),
            })),
        })
    }

    /// Sends MSG chunks: as they are over opc.tcp, one POST of each body
    /// over HTTPS.
    fn transmit(&mut self, tx: &[u8]) -> io::Result<()> {
        let Some(h) = &mut self.https else { return self.stream.write_all(tx) };
        let mut at = 0;
        while at + 24 <= tx.len() {
            let size = u32::from_le_bytes(tx[at + 4..at + 8].try_into().unwrap()) as usize;
            h.post(&tx[at + 24..at + size])?;
            at += size;
        }
        Ok(())
    }

    fn read_chunk(&mut self) -> io::Result<([u8; 3], u8)> {
        if let Some(h) = &mut self.https {
            h.read(&mut self.rx)?;
            return Ok((*b"MSG", b'F'));
        }
        let mut hdr = [0u8; 8];
        if self.spin {
            // Wait for data without sleeping; MSG_PEEK leaves it in the socket.
            let mut b = [0u8; 1];
            while crate::net::try_peek(&self.stream, &mut b)?.is_none() {
                std::hint::spin_loop();
            }
        }
        self.stream.read_exact(&mut hdr)?;
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if size < 8 {
            return Err(invalid("bad chunk size"));
        }
        self.rx.resize(size - 8, 0);
        self.stream.read_exact(&mut self.rx)?;
        if &hdr[0..3] == b"ERR" {
            let mut r = Reader::new(&self.rx);
            let code = r.u32().unwrap_or(0);
            return Err(invalid(&format!("server error 0x{code:08X}")));
        }
        if &hdr[0..3] == b"MSG" {
            self.unprotect(&hdr)?;
        }
        Ok(([hdr[0], hdr[1], hdr[2]], hdr[3]))
    }

    /// Decrypts / verifies a MSG chunk in `rx` (in place) and trims its
    /// padding and signature.
    fn unprotect(&mut self, hdr: &[u8; 8]) -> io::Result<()> {
        let Some(sec) = &self.sec else { return Ok(()) };
        if sec.mode == Mode::None {
            return Ok(());
        }
        let bad = || invalid("bad secured response");
        if let Some(k) = &sec.ecc_keys {
            let token = u32::from_le_bytes(self.rx[4..8].try_into().unwrap());
            let end = self.rx.len().checked_sub(TAG_LEN).filter(|&e| e >= 16).ok_or_else(bad)?;
            let (msg, tag) = self.rx.split_at_mut(end);
            if sec.mode == Mode::SignAndEncrypt {
                let mut aad = [0u8; 16];
                aad[..8].copy_from_slice(hdr);
                aad[8..].copy_from_slice(&msg[..8]);
                k.local.open(token, self.last_rx_seq, &aad, &mut msg[8..], tag).map_err(|_| bad())?;
            } else {
                let mut aad = hdr.to_vec();
                aad.extend_from_slice(msg);
                k.local.open(token, self.last_rx_seq, &aad, &mut [], tag).map_err(|_| bad())?;
            }
            self.rx.truncate(end);
            self.last_rx_seq = u32::from_le_bytes(self.rx[8..12].try_into().unwrap());
            return Ok(());
        }
        if let Some(k) = &sec.legacy_keys {
            let k = &k.local;
            if sec.mode == Mode::SignAndEncrypt {
                k.decrypt(&mut self.rx[8..]).map_err(|_| bad())?;
            }
            let end = self.rx.len().checked_sub(k.sig_len()).filter(|&e| e >= 16).ok_or_else(bad)?;
            if !k.verify_parts(&[hdr, &self.rx[..end]], &self.rx[end..]) {
                return Err(invalid("response signature invalid"));
            }
            let end = if sec.mode == Mode::SignAndEncrypt {
                8 + crate::channel::strip_padding(&self.rx[8..end], false).ok_or_else(bad)?
            } else {
                end
            };
            self.rx.truncate(end);
            return Ok(());
        }
        let keys = &sec.keys.as_ref().ok_or_else(|| invalid("no keys"))?.local;
        if sec.mode == Mode::SignAndEncrypt {
            keys.decrypt(&mut self.rx[8..]).map_err(|_| bad())?;
        }
        let end = self.rx.len().checked_sub(SYM_SIGNATURE_LEN).filter(|&e| e >= 16).ok_or_else(bad)?;
        if !keys.verify_parts(&[hdr, &self.rx[..end]], &self.rx[end..]) {
            return Err(invalid("response signature invalid"));
        }
        let end = if sec.mode == Mode::SignAndEncrypt {
            8 + crate::channel::strip_padding(&self.rx[8..end], false).ok_or_else(bad)?
        } else {
            end
        };
        self.rx.truncate(end);
        Ok(())
    }

    fn write_request_header(w: &mut Writer, token: &NodeId, handle: u32, ecdh: Option<&str>) {
        w.node_id(token);
        w.i64(now_ticks());
        w.u32(handle);
        w.u32(0);
        w.str(None);
        w.u32(10_000);
        match ecdh {
            // AdditionalParametersType asking for an ephemeral ECDH key.
            Some(uri) => {
                let at = w.begin_extension_object(17537);
                w.i32(1);
                w.u16(0);
                w.string("ECDHPolicyUri");
                w.u8(12);
                w.string(uri);
                w.end_extension_object(at);
            }
            None => w.null_extension_object(),
        }
    }

    /// OpenSecureChannel: 0 = issue, 1 = renew.
    pub fn open(&mut self, request_type: u32) -> io::Result<()> {
        let (policy, mode) = self.sec.as_ref().map(|s| (s.policy, s.mode)).unwrap_or((Policy::None, Mode::None));
        let mut client_nonce = vec![0u8; policy.nonce_len()];
        crate::server::random_bytes(&mut client_nonce);
        let eph = match policy.ecc() {
            Some(s) => {
                let e = ecc::Ephemeral::generate(s).map_err(|_| invalid("key generation"))?;
                client_nonce.copy_from_slice(&e.public);
                Some(e)
            }
            None => None,
        };
        let mut request_sig = Vec::new();
        // Sequence header + OpenSecureChannelRequest.
        let mut body = Vec::with_capacity(256);
        {
            let mut w = Writer::new(&mut body);
            w.u32(self.seq);
            w.u32(self.request_id);
            w.node_id(&NodeId::ns0(ids::OPEN_SECURE_CHANNEL_REQUEST));
            Self::write_request_header(&mut w, &NodeId::NULL, self.handle, None);
            w.u32(0);
            w.u32(request_type);
            w.u32(mode as u32);
            w.bytes(Some(&client_nonce));
            w.u32(600_000);
        }
        self.seq += 1;
        self.request_id += 1;
        self.handle += 1;

        self.tx.clear();
        let mut w = Writer::new(&mut self.tx);
        w.raw(b"OPNF");
        w.u32(0);
        w.u32(self.channel_id);
        match &self.sec {
            None => {
                w.string(SECURITY_POLICY_NONE);
                w.bytes(None);
                w.bytes(None);
                w.raw(&body);
                let len = w.len() as u32;
                w.patch_u32(4, len);
            }
            Some(sec) if policy.is_ecc() => {
                w.string(policy.uri());
                w.bytes(Some(&sec.cert));
                w.bytes(Some(&sec.server.thumbprint));
                body.push(0);
                let len = (w.len() + body.len() + policy.ecc().unwrap().signature_len()) as u32;
                w.patch_u32(4, len);
                w.raw(&body);
                let sig = sec.ecc().sign(w.buf).map_err(|_| invalid("signing failed"))?;
                w.raw(&sig);
                request_sig = sig;
            }
            Some(sec) => {
                // Mirror of the server's OPN response: pad, sign with our key,
                // encrypt with the server's.
                w.string(policy.uri());
                w.bytes(Some(&sec.cert));
                w.bytes(Some(&sec.server.thumbprint));
                let server_bytes = sec.server.key_bits / 8;
                let block_in = server_bytes - policy.oaep_overhead();
                let sig_len = sec.rsa().size_bytes();
                let extra = server_bytes > 256;
                let (pad, _) = crypto::padding(body.len(), sig_len, block_in, extra);
                body.extend(std::iter::repeat_n((pad & 0xFF) as u8, pad + 1));
                if extra {
                    body.push((pad >> 8) as u8);
                }
                let encrypted_len = (body.len() + sig_len) / block_in * server_bytes;
                let len = (w.len() + encrypted_len) as u32;
                w.patch_u32(4, len);
                let mut signed = w.buf.clone();
                signed.extend_from_slice(&body);
                let sig = policy.asym_sign(&sec.rsa().sign, &signed).map_err(|_| invalid("signing failed"))?;
                body.extend_from_slice(&sig);
                policy.asym_encrypt(&sec.server.spki, &body, w.buf).map_err(|_| invalid("encryption failed"))?;
            }
        }
        self.stream.write_all(&self.tx)?;

        let mut hdr = [0u8; 8];
        self.stream.read_exact(&mut hdr)?;
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        self.rx.resize(size.checked_sub(8).ok_or_else(|| invalid("bad chunk size"))?, 0);
        self.stream.read_exact(&mut self.rx)?;
        if &hdr[0..3] != b"OPN" {
            let code = Reader::new(&self.rx).u32().unwrap_or(0);
            return Err(invalid(&format!("expected OPN, got {:?} 0x{code:08X}", &hdr[0..3])));
        }
        let p = || invalid("bad OPN response");
        let mut r = Reader::new(&self.rx);
        self.channel_id = r.u32().map_err(|_| p())?;
        r.str().map_err(|_| p())?;
        r.bytes().map_err(|_| p())?;
        r.bytes().map_err(|_| p())?;
        let asym_end = r.position();
        let plain = match &mut self.sec {
            None => self.rx[asym_end..].to_vec(),
            Some(sec) if policy.is_ecc() => {
                let suite = policy.ecc().unwrap();
                let end = self.rx.len().checked_sub(suite.signature_len()).ok_or_else(p)?;
                let mut signed = hdr.to_vec();
                signed.extend_from_slice(&self.rx[..end]);
                let first = sec.thumbprint.is_empty() && suite.is_aead();
                if first {
                    signed.extend_from_slice(&request_sig);
                }
                suite
                    .verify(&sec.server.rsa_public_key, &signed, &self.rx[end..])
                    .map_err(|_| invalid("OPN response signature invalid"))?;
                if first {
                    sec.thumbprint = self.rx[end..].to_vec();
                }
                self.rx[asym_end..end].to_vec()
            }
            Some(sec) => {
                let mut plain = Vec::new();
                policy.asym_decrypt(&sec.rsa().decrypt, &self.rx[asym_end..], &mut plain).map_err(|_| p())?;
                let sig_len = sec.server.key_bits / 8;
                let end = plain.len().checked_sub(sig_len).ok_or_else(p)?;
                let mut signed = hdr.to_vec();
                signed.extend_from_slice(&self.rx[..asym_end]);
                signed.extend_from_slice(&plain[..end]);
                policy
                    .asym_verify(&sec.server.rsa_public_key, &signed, &plain[end..])
                    .map_err(|_| invalid("OPN response signature invalid"))?;
                let body_end =
                    crate::channel::strip_padding(&plain[..end], sec.rsa().size_bytes() > 256).ok_or_else(p)?;
                plain.truncate(body_end);
                plain
            }
        };
        let mut r = Reader::new(&plain);
        self.last_rx_seq = r.u32().map_err(|_| p())?;
        r.u32().map_err(|_| p())?;
        r.node_id().map_err(|_| p())?;
        skip_response_header(&mut r).map_err(|_| p())?;
        r.u32().map_err(|_| p())?;
        let _ch = r.u32().map_err(|_| p())?;
        self.token_id = r.u32().map_err(|_| p())?;
        r.i64().map_err(|_| p())?;
        r.u32().map_err(|_| p())?;
        let server_nonce = r.bytes().map_err(|_| p())?.unwrap_or(&[]).to_vec();
        if let Some(sec) = &mut self.sec {
            match (policy.ecc(), eph) {
                (Some(suite), Some(eph)) if !suite.is_aead() => {
                    let secret = eph.agree(suite, &server_nonce).map_err(|_| p())?;
                    let encrypt = mode == Mode::SignAndEncrypt;
                    let keys = LegacyKeys::derive(suite, &secret, &client_nonce, &server_nonce, encrypt);
                    sec.legacy_keys = Some(keys.map_err(|_| p())?);
                }
                (Some(suite), Some(eph)) => {
                    let secret = eph.agree(suite, &server_nonce).map_err(|_| p())?;
                    let keys = EccKeys::derive(suite, &mut sec.ikm, &secret, &client_nonce, &server_nonce);
                    sec.ecc_keys = Some(keys.map_err(|_| p())?);
                }
                _ => sec.keys = Some(ChannelKeys::derive(policy, &client_nonce, &server_nonce).map_err(|_| p())?),
            }
        }
        Ok(())
    }

    /// Sends a request; `body` writes everything after the request header.
    /// Returns the response body after the response type id is checked;
    /// the response header is returned undecoded at the start of `rx`.
    pub fn call(&mut self, request_type: u32, body: impl FnOnce(&mut Writer)) -> io::Result<(u32, &[u8])> {
        let mut tx = std::mem::take(&mut self.tx);
        tx.clear();
        self.push_request(&mut tx, request_type, body);
        let r = self.transmit(&tx);
        self.tx = tx;
        r?;
        self.read_response()
    }

    /// Appends one complete MSG chunk to `tx`.
    fn push_request(&mut self, tx: &mut Vec<u8>, request_type: u32, body: impl FnOnce(&mut Writer)) {
        let start = tx.len();
        tx.resize(start + 24, 0);
        let mut w = Writer::new(tx);
        w.node_id(&NodeId::ns0(request_type));
        Self::write_request_header(&mut w, &self.auth_token, self.handle, self.ecdh);
        body(&mut w);
        let mode = self.sec.as_ref().map(|s| s.mode).unwrap_or(Mode::None);
        if let Some(k) = self.sec.as_ref().and_then(|s| s.ecc_keys.as_ref()) {
            let size = (tx.len() - start + TAG_LEN) as u32;
            let h = &mut tx[start..start + 24];
            h[0..4].copy_from_slice(b"MSGF");
            h[4..8].copy_from_slice(&size.to_le_bytes());
            h[8..12].copy_from_slice(&self.channel_id.to_le_bytes());
            h[12..16].copy_from_slice(&self.token_id.to_le_bytes());
            h[16..20].copy_from_slice(&self.seq.to_le_bytes());
            h[20..24].copy_from_slice(&self.request_id.to_le_bytes());
            let prev = self.seq.wrapping_sub(1);
            let tag = if mode == Mode::SignAndEncrypt {
                let (aad, data) = tx[start..].split_at_mut(SYM_CLEAR_LEN);
                k.remote.seal(self.token_id, prev, aad, data)
            } else {
                k.remote.seal(self.token_id, prev, &tx[start..], &mut [])
            };
            tx.extend_from_slice(&tag.expect("seal"));
            self.seq = self.seq.wrapping_add(1);
            self.request_id += 1;
            self.handle += 1;
            return;
        }
        let legacy = self.sec.as_ref().and_then(|s| s.legacy_keys.as_ref());
        let sym_sig = legacy.map_or(SYM_SIGNATURE_LEN, |k| k.remote.sig_len());
        if mode == Mode::SignAndEncrypt {
            let plain = tx.len() - start - SYM_CLEAR_LEN;
            let (pad, _) = crypto::padding(plain, sym_sig, AES_BLOCK, false);
            tx.extend(std::iter::repeat_n(pad as u8, pad + 1));
        }
        let sig_len = if mode == Mode::None { 0 } else { sym_sig };
        let size = (tx.len() - start + sig_len) as u32;
        let h = &mut tx[start..start + 24];
        h[0..4].copy_from_slice(b"MSGF");
        h[4..8].copy_from_slice(&size.to_le_bytes());
        h[8..12].copy_from_slice(&self.channel_id.to_le_bytes());
        h[12..16].copy_from_slice(&self.token_id.to_le_bytes());
        h[16..20].copy_from_slice(&self.seq.to_le_bytes());
        h[20..24].copy_from_slice(&self.request_id.to_le_bytes());
        self.seq += 1;
        self.request_id += 1;
        self.handle += 1;
        if let (Some(k), true) = (legacy, mode != Mode::None) {
            let sig = k.remote.sign_parts(&[&tx[start..]]);
            tx.extend_from_slice(sig.as_ref());
            if mode == Mode::SignAndEncrypt {
                k.remote.encrypt(&mut tx[start + SYM_CLEAR_LEN..]).expect("encrypt");
            }
        } else if mode != Mode::None {
            let keys = &self.sec.as_ref().unwrap().keys.as_ref().expect("channel keys").remote;
            let sig = keys.sign(&tx[start..]);
            tx.extend_from_slice(&sig);
            if mode == Mode::SignAndEncrypt {
                keys.encrypt(&mut tx[start + SYM_CLEAR_LEN..]).expect("encrypt");
            }
        }
    }

    /// Reads one (possibly multi-chunk) response.
    fn read_response(&mut self) -> io::Result<(u32, &[u8])> {
        let mut body = Vec::new();
        loop {
            let (ty, chunk) = self.read_chunk()?;
            if &ty != b"MSG" {
                return Err(invalid("expected MSG"));
            }
            body.extend_from_slice(&self.rx[16..]);
            if chunk == b'F' {
                break;
            }
        }
        self.rx = body;
        let mut r = Reader::new(&self.rx);
        let ty = r.node_id().map_err(|_| invalid("bad type id"))?;
        let at = r.position();
        Ok((ty.as_ns0().unwrap_or(0), &self.rx[at..]))
    }

    /// Sends `n` Read requests in a single write (pipelining), then reads the
    /// `n` responses in order.
    pub fn read_pipelined(&mut self, items: &[(NodeId, u32)], n: usize) -> io::Result<Vec<Vec<DataValue>>> {
        let mut tx = Vec::new();
        for _ in 0..n {
            self.push_request(&mut tx, ids::READ_REQUEST, |w| Self::read_body(w, items));
        }
        self.transmit(&tx)?;
        (0..n).map(|_| self.parse_read_response()).collect()
    }

    fn read_body(w: &mut Writer, items: &[(NodeId, u32)]) {
        w.f64(0.0);
        w.u32(2);
        w.i32(items.len() as i32);
        for (id, a) in items {
            w.node_id(id);
            w.u32(*a);
            w.str(None);
            w.u16(0);
            w.str(None);
        }
    }

    fn parse_read_response(&mut self) -> io::Result<Vec<DataValue>> {
        let (ty, body) = self.read_response()?;
        if ty != ids::READ_RESPONSE {
            return Err(invalid(&format!("Read failed: {:08X}", service_result(body))));
        }
        let mut r = Reader::new(body);
        skip_response_header(&mut r).map_err(|_| invalid("bad header"))?;
        r.array(1, |r| r.data_value()).map_err(|_| invalid("bad results"))
    }

    /// CreateSession + ActivateSession (anonymous).
    pub fn create_session(&mut self, name: &str) -> io::Result<()> {
        self.create_session_as(name, None)
    }

    /// CreateSession + ActivateSession with a user name and password (ECC
    /// channels: an EccEncryptedSecret; others: clear text, SignAndEncrypt
    /// only), or anonymous.
    pub fn create_session_as(&mut self, name: &str, user: Option<(&str, &str)>) -> io::Result<()> {
        let ecc_suite = self.sec.as_ref().and_then(|s| s.policy.ecc());
        self.ecdh = if user.is_some() { ecc_suite.map(|s| s.uri()) } else { None };
        let mut client_nonce = [0u8; 32];
        crate::server::random_bytes(&mut client_nonce);
        let cert = match &self.sec {
            Some(s) => Some(s.cert.clone()),
            None => self.https.as_ref().and_then(|h| h.cert.clone()),
        };
        let (ty, body) = self.call(ids::CREATE_SESSION_REQUEST, |w| {
            w.string("urn:fastua:test-client");
            w.str(None);
            w.text("test client");
            w.i32(1);
            w.str(None);
            w.str(None);
            w.null_array();
            w.str(None);
            w.str(None);
            w.string(name);
            w.bytes(Some(&client_nonce));
            w.bytes(cert.as_deref());
            w.f64(60_000.0);
            w.u32(0);
        })?;
        if ty != ids::CREATE_SESSION_RESPONSE {
            return Err(invalid(&format!("CreateSession failed: {:08X}", service_result(body))));
        }
        let body = body.to_vec();
        let mut r = Reader::new(&body);
        let server_key = response_ecdh_key(&mut r).map_err(|_| invalid("bad header"))?;
        let _session_id = r.node_id().map_err(|_| invalid("bad session id"))?;
        let token = r.node_id().map_err(|_| invalid("bad token"))?;
        r.f64().map_err(|_| invalid("bad timeout"))?;
        let server_nonce = r.bytes().map_err(|_| invalid("bad nonce"))?.unwrap_or(&[]).to_vec();
        r.bytes().map_err(|_| invalid("bad certificate"))?;
        // PolicyIds of the anonymous and user name tokens the server offers on
        // our endpoint (they are server-defined strings).
        let (policy_uri, mode) = match &self.sec {
            Some(s) => (s.policy.uri(), s.mode as i32),
            None => (Policy::None.uri(), Mode::None as i32),
        };
        let endpoints = r.array(0, |r| read_endpoint(r)).map_err(|_| invalid("bad endpoints"))?;
        let token_policy = |kind: i32, default: &str| {
            let ours = endpoints.iter().filter(|e| e.0 == policy_uri && e.1 == mode);
            ours.chain(endpoints.iter())
                .flat_map(|e| e.2.iter())
                .find(|t| t.1 == kind)
                .map_or_else(|| default.to_string(), |t| t.0.clone())
        };
        let anonymous_policy = token_policy(0, "anonymous");
        let username_policy = token_policy(1, crate::server::USERNAME_POLICY_ID);

        let signature = match &self.sec {
            Some(sec) if sec.policy.ecc().is_some_and(|s| !s.is_aead()) => {
                // Deprecated policies: the RSA-style data, no algorithm.
                let suite = sec.policy.ecc().unwrap();
                r.array(0, |r| r.bytes().map(|_| ())).map_err(|_| invalid("bad software certificates"))?;
                r.str().map_err(|_| invalid("bad signature"))?;
                let server_sig = r.bytes().map_err(|_| invalid("bad signature"))?.unwrap_or(&[]).to_vec();
                suite
                    .verify(&sec.server.rsa_public_key, &[&sec.cert[..], &client_nonce].concat(), &server_sig)
                    .map_err(|_| invalid("server signature invalid"))?;
                let data = [&sec.server.der[..], &server_nonce].concat();
                Some((None, sec.ecc().sign(&data).map_err(|_| invalid("signing failed"))?))
            }
            Some(sec) if sec.policy.is_ecc() => {
                // Channel-bound signatures (SecureChannelEnhancements).
                let suite = sec.policy.ecc().unwrap();
                let bound = |first: &[u8], certs: &[&[u8]], last: &[u8]| {
                    let mut d = sec.thumbprint.clone();
                    d.extend_from_slice(first);
                    for c in certs {
                        d.extend_from_slice(&suite.certificate_hash(c));
                    }
                    d.extend_from_slice(last);
                    d
                };
                r.array(0, |r| r.bytes().map(|_| ())).map_err(|_| invalid("bad software certificates"))?;
                r.str().map_err(|_| invalid("bad signature"))?;
                let server_sig = r.bytes().map_err(|_| invalid("bad signature"))?.unwrap_or(&[]).to_vec();
                let data = bound(&client_nonce, &[&sec.server.der, &sec.cert], &server_nonce);
                suite
                    .verify(&sec.server.rsa_public_key, &data, &server_sig)
                    .map_err(|_| invalid("server signature invalid"))?;
                let data = bound(&server_nonce, &[&sec.server.der, &sec.server.der, &sec.cert], &client_nonce);
                Some((None, sec.ecc().sign(&data).map_err(|_| invalid("signing failed"))?))
            }
            Some(sec) if sec.policy != Policy::None => {
                let mut data = sec.server.der.clone();
                data.extend_from_slice(&server_nonce);
                let sig = sec.policy.asym_sign(&sec.rsa().sign, &data).map_err(|_| invalid("signing failed"))?;
                Some((Some(sec.policy.asym_signature_uri()), sig))
            }
            _ => None,
        };
        self.auth_token = token;
        let token_data = match (user, ecc_suite) {
            (None, _) => None,
            (Some((u, p)), None) => Some((u.to_string(), p.as_bytes().to_vec())),
            (Some((u, p)), Some(suite)) => {
                let (public, sig) = server_key.ok_or_else(|| invalid("no ECDHKey from the server"))?;
                let sec = self.sec.as_ref().unwrap();
                suite.verify(&sec.server.rsa_public_key, &public, &sig).map_err(|_| invalid("ECDHKey signature"))?;
                Some((u.to_string(), ecc_secret(suite, sec, &public, &server_nonce, p.as_bytes())?))
            }
        };
        let (ty, body) = self.call(ids::ACTIVATE_SESSION_REQUEST, |w| {
            match &signature {
                Some((alg, sig)) => {
                    w.str(*alg);
                    w.bytes(Some(sig));
                }
                None => {
                    w.str(None);
                    w.bytes(None);
                }
            }
            w.empty_array();
            w.empty_array();
            match &token_data {
                None => {
                    let at = w.begin_extension_object(ids::ANONYMOUS_IDENTITY_TOKEN_ENCODING);
                    w.string(&anonymous_policy);
                    w.end_extension_object(at);
                }
                Some((user, secret)) => {
                    let at = w.begin_extension_object(ids::USERNAME_IDENTITY_TOKEN_ENCODING);
                    w.string(&username_policy);
                    w.string(user);
                    w.bytes(Some(secret));
                    w.str(None);
                    w.end_extension_object(at);
                }
            }
            w.str(None);
            w.bytes(None);
        })?;
        let res = if ty != ids::ACTIVATE_SESSION_RESPONSE {
            Err(invalid(&format!("ActivateSession failed: {:08X}", service_result(body))))
        } else {
            Ok(())
        };
        self.ecdh = None;
        res
    }

    /// Sends a request without waiting for its response (see [`Client::receive`]).
    pub fn send(&mut self, request_type: u32, body: impl FnOnce(&mut Writer)) -> io::Result<()> {
        let mut tx = std::mem::take(&mut self.tx);
        tx.clear();
        self.push_request(&mut tx, request_type, body);
        let r = self.transmit(&tx);
        self.tx = tx;
        r
    }

    /// Request handle of the next request sent.
    pub fn next_handle(&self) -> u32 {
        self.handle
    }

    /// Next response: (type id, body starting with the response header).
    pub fn receive(&mut self) -> io::Result<(u32, &[u8])> {
        self.read_response()
    }

    /// CreateSubscription: (id, revised interval, lifetime, keep-alive).
    pub fn create_subscription(
        &mut self,
        interval_ms: f64,
        lifetime: u32,
        keepalive: u32,
    ) -> io::Result<(u32, f64, u32, u32)> {
        let (ty, body) = self.call(ids::CREATE_SUBSCRIPTION_REQUEST, |w| {
            w.f64(interval_ms);
            w.u32(lifetime);
            w.u32(keepalive);
            w.u32(0);
            w.bool(true);
            w.u8(0);
        })?;
        if ty != ids::CREATE_SUBSCRIPTION_RESPONSE {
            return Err(invalid(&format!("CreateSubscription failed: {:08X}", service_result(body))));
        }
        let mut r = Reader::new(body);
        let bad = |_| invalid("bad CreateSubscription response");
        skip_response_header(&mut r).map_err(bad)?;
        Ok((r.u32().map_err(bad)?, r.f64().map_err(bad)?, r.u32().map_err(bad)?, r.u32().map_err(bad)?))
    }

    /// CreateMonitoredItems on Value attributes in Reporting mode, source and
    /// server timestamps. Returns (status, item id, revised sampling, revised queue).
    pub fn monitor(&mut self, sub: u32, items: &[MonitorSpec]) -> io::Result<Vec<(u32, u32, f64, u32)>> {
        let (ty, body) = self.call(ids::CREATE_MONITORED_ITEMS_REQUEST, |w| {
            w.u32(sub);
            w.u32(2);
            w.i32(items.len() as i32);
            for it in items {
                w.node_id(&it.node);
                w.u32(it.attribute);
                w.str(it.index_range.as_deref());
                w.u16(0);
                w.str(None);
                w.u32(it.mode);
                w.u32(it.handle);
                w.f64(it.sampling_ms);
                match it.filter {
                    _ if it.event_select.is_some() => it.write_event_filter(w),
                    _ if it.aggregate.is_some() => {
                        let (start, agg, interval) = it.aggregate.unwrap();
                        let at = w.begin_extension_object(ids::AGGREGATE_FILTER_ENCODING);
                        w.i64(start);
                        w.node_id(&NodeId::ns0(agg));
                        w.f64(interval);
                        crate::aggregates::Config::default().encode(w);
                        w.end_extension_object(at);
                    }
                    None => w.null_extension_object(),
                    Some((trigger, db_type, db)) => {
                        let at = w.begin_extension_object(ids::DATA_CHANGE_FILTER_ENCODING);
                        w.u32(trigger);
                        w.u32(db_type);
                        w.f64(db);
                        w.end_extension_object(at);
                    }
                }
                w.u32(it.queue_size);
                w.bool(it.discard_oldest);
            }
        })?;
        if ty != ids::CREATE_MONITORED_ITEMS_RESPONSE {
            return Err(invalid(&format!("CreateMonitoredItems failed: {:08X}", service_result(body))));
        }
        let mut r = Reader::new(body);
        let bad = |_| invalid("bad CreateMonitoredItems response");
        skip_response_header(&mut r).map_err(bad)?;
        r.array(1, |r| {
            let v = (r.u32()?, r.u32()?, r.f64()?, r.u32()?);
            r.extension_object_raw()?;
            Ok(v)
        })
        .map_err(bad)
    }

    /// Sends a Publish request (acknowledging `acks`) without waiting.
    pub fn send_publish(&mut self, acks: &[(u32, u32)]) -> io::Result<()> {
        self.send(ids::PUBLISH_REQUEST, |w| {
            w.i32(acks.len() as i32);
            for (s, q) in acks {
                w.u32(*s);
                w.u32(*q);
            }
        })
    }

    /// Reads the next response as a PublishResponse.
    pub fn receive_publish(&mut self) -> io::Result<Publish> {
        let (ty, body) = self.read_response()?;
        parse_publish(ty, body)
    }

    /// Publish and wait for the answer.
    pub fn publish(&mut self, acks: &[(u32, u32)]) -> io::Result<Publish> {
        self.send_publish(acks)?;
        self.receive_publish()
    }

    /// Republish: the NotificationMessage, or the service fault code.
    pub fn republish(&mut self, sub: u32, seq: u32) -> io::Result<Result<Message, u32>> {
        let (ty, body) = self.call(ids::REPUBLISH_REQUEST, |w| {
            w.u32(sub);
            w.u32(seq);
        })?;
        if ty != ids::REPUBLISH_RESPONSE {
            return Ok(Err(service_result(body)));
        }
        let mut r = Reader::new(body);
        skip_response_header(&mut r).map_err(|_| invalid("bad header"))?;
        parse_message(&mut r).map(Ok).map_err(|_| invalid("bad NotificationMessage"))
    }

    /// Reads attributes; returns one DataValue per (node, attribute).
    pub fn read(&mut self, items: &[(NodeId, u32)]) -> io::Result<Vec<DataValue>> {
        let mut tx = std::mem::take(&mut self.tx);
        tx.clear();
        self.push_request(&mut tx, ids::READ_REQUEST, |w| Self::read_body(w, items));
        let r = self.transmit(&tx);
        self.tx = tx;
        r?;
        self.parse_read_response()
    }

    pub fn write(&mut self, items: &[(NodeId, Variant)]) -> io::Result<Vec<u32>> {
        let items: Vec<_> = items.iter().map(|(id, v)| (id.clone(), None, v.clone())).collect();
        self.write_ranges(&items)
    }

    /// Write of Value attributes, each with an optional NumericRange.
    pub fn write_ranges(&mut self, items: &[(NodeId, Option<&str>, Variant)]) -> io::Result<Vec<u32>> {
        let (ty, body) = self.call(ids::WRITE_REQUEST, |w| {
            w.i32(items.len() as i32);
            for (id, range, v) in items {
                w.node_id(id);
                w.u32(13);
                w.str(*range);
                w.data_value(&DataValue::value(v.clone()));
            }
        })?;
        if ty != ids::WRITE_RESPONSE {
            return Err(invalid(&format!("Write failed: {:08X}", service_result(body))));
        }
        let mut r = Reader::new(body);
        skip_response_header(&mut r).map_err(|_| invalid("bad header"))?;
        r.array(4, |r| r.u32()).map_err(|_| invalid("bad results"))
    }

    /// HistoryRead with raw `details` (an encoded *Details structure of type
    /// `details_encoding`) on several nodes, each with its continuation
    /// point. Returns per node (status, continuation point, result type,
    /// values, modification infos).
    pub fn history_read(
        &mut self,
        details_encoding: u32,
        details: &[u8],
        ttr: u32,
        release: bool,
        nodes: &[(NodeId, Option<Vec<u8>>)],
    ) -> io::Result<Result<Vec<HistoryResult>, u32>> {
        let (ty, body) = self.call(ids::HISTORY_READ_REQUEST, |w| {
            let at = w.begin_extension_object(details_encoding);
            w.raw(details);
            w.end_extension_object(at);
            w.u32(ttr);
            w.bool(release);
            w.i32(nodes.len() as i32);
            for (id, cp) in nodes {
                w.node_id(id);
                w.str(None);
                w.u16(0);
                w.str(None);
                w.bytes(cp.as_deref());
            }
        })?;
        if ty != ids::HISTORY_READ_RESPONSE {
            return Ok(Err(service_result(body)));
        }
        let mut r = Reader::new(body);
        let bad = |_| invalid("bad HistoryRead response");
        skip_response_header(&mut r).map_err(bad)?;
        let results = r
            .array(12, |r| {
                let code = r.u32()?;
                let cp = r.bytes()?.map(|b| b.to_vec());
                let (type_id, _, data) = r.extension_object_raw()?;
                let mut d = Reader::new(data);
                let ty = type_id.as_ns0().unwrap_or(0);
                if ty == ids::HISTORY_EVENT_ENCODING {
                    let events = d.array(4, |r| r.array(1, |r| r.variant()))?;
                    return Ok(HistoryResult {
                        status: code,
                        continuation_point: cp,
                        type_id: ty,
                        values: Vec::new(),
                        modifications: Vec::new(),
                        events,
                    });
                }
                let (values, mods) = match ty {
                    0 => (Vec::new(), Vec::new()),
                    _ => {
                        let values = d.array(1, |r| r.data_value())?;
                        let mods = if ty == ids::HISTORY_MODIFIED_DATA_ENCODING {
                            d.array(16, |r| {
                                Ok((r.i64()?, r.u32()?, r.string_owned()?.map(String::from).unwrap_or_default()))
                            })?
                        } else {
                            Vec::new()
                        };
                        (values, mods)
                    }
                };
                Ok(HistoryResult {
                    status: code,
                    continuation_point: cp,
                    type_id: ty,
                    values,
                    modifications: mods,
                    events: Vec::new(),
                })
            })
            .map_err(bad)?;
        Ok(Ok(results))
    }

    /// HistoryUpdate with encoded details: (encoding id, body). Returns per
    /// details (status, operation results).
    pub fn history_update(&mut self, details: &[(u32, Vec<u8>)]) -> io::Result<Result<Vec<UpdateResult>, u32>> {
        let (ty, body) = self.call(ids::HISTORY_UPDATE_REQUEST, |w| {
            w.i32(details.len() as i32);
            for (enc, d) in details {
                let at = w.begin_extension_object(*enc);
                w.raw(d);
                w.end_extension_object(at);
            }
        })?;
        if ty != ids::HISTORY_UPDATE_RESPONSE {
            return Ok(Err(service_result(body)));
        }
        let mut r = Reader::new(body);
        let bad = |_| invalid("bad HistoryUpdate response");
        skip_response_header(&mut r).map_err(bad)?;
        let results = r
            .array(12, |r| {
                let code = r.u32()?;
                let ops = r.array(4, |r| r.u32())?;
                r.array(1, |r| r.diagnostic_info())?;
                Ok((code, ops))
            })
            .map_err(bad)?;
        Ok(Ok(results))
    }

    /// Forward hierarchical browse; returns (status, continuation point, target ids).
    pub fn browse(&mut self, id: &NodeId, max: u32) -> io::Result<(u32, Option<Vec<u8>>, Vec<NodeId>)> {
        let (ty, body) = self.call(ids::BROWSE_REQUEST, |w| {
            w.node_id(&NodeId::NULL);
            w.i64(0);
            w.u32(0);
            w.u32(max);
            w.i32(1);
            w.node_id(id);
            w.u32(0);
            w.node_id(&NodeId::ns0(ids::HIERARCHICAL_REFERENCES));
            w.bool(true);
            w.u32(0);
            w.u32(0x3F);
        })?;
        if ty != ids::BROWSE_RESPONSE {
            return Err(invalid(&format!("Browse failed: {:08X}", service_result(body))));
        }
        let body = body.to_vec();
        parse_browse_results(&body)
    }

    pub fn browse_next(&mut self, cp: &[u8]) -> io::Result<(u32, Option<Vec<u8>>, Vec<NodeId>)> {
        let (ty, body) = self.call(ids::BROWSE_NEXT_REQUEST, |w| {
            w.bool(false);
            w.i32(1);
            w.bytes(Some(cp));
        })?;
        if ty != ids::BROWSE_NEXT_RESPONSE {
            return Err(invalid(&format!("BrowseNext failed: {:08X}", service_result(body))));
        }
        let body = body.to_vec();
        parse_browse_results(&body)
    }

    pub fn close(mut self) -> io::Result<()> {
        let _ = self.call(ids::CLOSE_SESSION_REQUEST, |w| w.bool(true));
        Ok(())
    }
}

fn parse_browse_results(body: &[u8]) -> io::Result<(u32, Option<Vec<u8>>, Vec<NodeId>)> {
    let bad = || invalid("bad browse result");
    let mut r = Reader::new(body);
    skip_response_header(&mut r).map_err(|_| bad())?;
    let n = r.i32().map_err(|_| bad())?;
    if n != 1 {
        return Err(bad());
    }
    let st = r.u32().map_err(|_| bad())?;
    let cp = r.bytes().map_err(|_| bad())?.map(<[u8]>::to_vec);
    let refs = r
        .array(1, |r| {
            r.node_id()?;
            r.bool()?;
            let id = r.expanded_node_id()?.node_id;
            r.qualified_name()?;
            r.localized_text()?;
            r.i32()?;
            r.expanded_node_id()?;
            Ok(id)
        })
        .map_err(|_| bad())?;
    Ok((st, cp, refs))
}

/// One HistoryUpdate result: (status, operation results).
pub type UpdateResult = (u32, Vec<u32>);

/// One node's HistoryRead result.
#[derive(Clone, Debug, PartialEq)]
pub struct HistoryResult {
    pub status: u32,
    pub continuation_point: Option<Vec<u8>>,
    /// Encoding id of the HistoryData / HistoryModifiedData (0 = none).
    pub type_id: u32,
    pub values: Vec<DataValue>,
    /// (modification time, HistoryUpdateType, user name).
    pub modifications: Vec<(i64, u32, String)>,
    /// HistoryEvent: the selected fields of each event.
    pub events: Vec<Vec<Variant>>,
}

/// EndpointDescription: (security policy URI, security mode, user token
/// policies as (policyId, token type)).
#[allow(clippy::type_complexity)]
fn read_endpoint(r: &mut Reader) -> crate::codec::DResult<(String, i32, Vec<(String, i32)>)> {
    r.str()?;
    r.str()?;
    r.str()?;
    r.localized_text()?;
    r.i32()?;
    r.str()?;
    r.str()?;
    r.skip_string_array()?;
    r.bytes()?;
    let mode = r.u32()? as i32;
    let policy = r.str()?.unwrap_or("").to_string();
    let tokens = r.array(0, |r| {
        let id = r.str()?.unwrap_or("").to_string();
        let kind = r.i32()?;
        r.str()?;
        r.str()?;
        r.str()?;
        Ok((id, kind))
    })?;
    r.str()?;
    r.u8()?;
    Ok((policy, mode, tokens))
}

/// Skips a ResponseHeader; returns the ECDHKey (public key, signature) of its
/// AdditionalHeader, if any.
#[allow(clippy::type_complexity)]
fn response_ecdh_key(r: &mut Reader) -> crate::codec::DResult<Option<(Vec<u8>, Vec<u8>)>> {
    r.i64()?;
    r.u32()?;
    r.u32()?;
    r.diagnostic_info()?;
    r.skip_string_array()?;
    let (ty, _, body) = r.extension_object_raw()?;
    if ty.as_ns0() != Some(17537) {
        return Ok(None);
    }
    let mut p = Reader::new(body);
    let n = p.length(1)?.unwrap_or(0);
    for _ in 0..n {
        let (_, name) = p.qualified_name_ref()?;
        if name == Some("ECDHKey") {
            p.u8()?; // Variant ExtensionObject
            let (_, _, key) = p.extension_object_raw()?;
            let mut k = Reader::new(key);
            let public = k.bytes()?.unwrap_or(&[]).to_vec();
            let sig = k.bytes()?.unwrap_or(&[]).to_vec();
            return Ok(Some((public, sig)));
        }
        p.variant()?;
    }
    Ok(None)
}

/// EccEncryptedSecret of `secret` for the server's ephemeral key `receiver`
/// (Part 4 §7.41.2.3).
fn ecc_secret(suite: ecc::Suite, sec: &Secure, receiver: &[u8], nonce: &[u8], secret: &[u8]) -> io::Result<Vec<u8>> {
    let e = |_| invalid("EccEncryptedSecret");
    let eph = ecc::Ephemeral::generate(suite).map_err(e)?;
    let sender = eph.public.clone();
    let mut plain = Vec::new();
    {
        let mut w = Writer::new(&mut plain);
        w.bytes(Some(nonce));
        w.bytes(Some(secret));
    }
    let m = (plain.len() + 2) % 16;
    let mut pad = if m == 0 { 0 } else { 16 - m };
    if pad + secret.len() < 16 {
        pad += 16;
    }
    plain.extend(std::iter::repeat_n(pad as u8, pad));
    plain.extend_from_slice(&(pad as u16).to_le_bytes());
    let mut out = Vec::new();
    let mut w = Writer::new(&mut out);
    w.node_id(&NodeId::ns0(17546));
    w.u8(1);
    w.u32(0); // patched
    w.string(suite.uri());
    w.bytes(Some(&sec.cert));
    w.i64(now_ticks());
    w.u16((8 + sender.len() + receiver.len()) as u16);
    w.bytes(Some(&sender));
    w.bytes(Some(receiver));
    let payload_at = w.len();
    let tag_len = if suite.is_aead() { ecc::TAG_LEN } else { 0 };
    let len = (payload_at + plain.len() + tag_len + suite.signature_len() - 9) as u32;
    w.patch_u32(5, len);
    if suite.is_aead() {
        let keys = eph.secret_keys(suite, receiver, &sender, receiver).map_err(e)?;
        let tag = keys.seal(0, 0, &out, &mut plain).map_err(e)?;
        out.extend_from_slice(&plain);
        out.extend_from_slice(&tag);
    } else {
        eph.secret_cbc(suite, receiver, &sender, receiver).map_err(e)?.encrypt(&mut plain).map_err(e)?;
        out.extend_from_slice(&plain);
    }
    let sig = sec.ecc().sign(&out).map_err(e)?;
    out.extend_from_slice(&sig);
    Ok(out)
}

pub fn skip_response_header(r: &mut Reader) -> crate::codec::DResult<u32> {
    r.i64()?;
    r.u32()?;
    let result = r.u32()?;
    r.diagnostic_info()?;
    r.skip_string_array()?;
    r.extension_object_raw()?;
    Ok(result)
}

/// ServiceResult of a (fault) response body.
pub fn service_result(body: &[u8]) -> u32 {
    let mut r = Reader::new(body);
    let _ = r.i64();
    let _ = r.u32();
    r.u32().unwrap_or(0)
}

/// A monitored item to create (see [`Client::monitor`]).
#[derive(Clone, Debug)]
pub struct MonitorSpec {
    pub node: NodeId,
    pub attribute: u32,
    pub mode: u32,
    pub handle: u32,
    pub sampling_ms: f64,
    pub queue_size: u32,
    pub discard_oldest: bool,
    /// DataChangeFilter (trigger, deadband type, deadband value).
    pub filter: Option<(u32, u32, f64)>,
    /// EventFilter select clauses (BaseEventType field names).
    pub event_select: Option<Vec<String>>,
    /// EventFilter where clause: (operator, operands) elements.
    pub event_where: Vec<(u32, Vec<FilterOperand>)>,
    /// NumericRange of the monitored value (`None` = whole value).
    pub index_range: Option<String>,
    /// AggregateFilter: (start time, aggregate function id, processing
    /// interval in ms), server default configuration.
    pub aggregate: Option<(i64, u32, f64)>,
}

/// Operand of a where clause element.
#[derive(Clone, Debug)]
pub enum FilterOperand {
    Element(u32),
    Literal(Variant),
    /// A BaseEventType field, by browse name.
    Field(String),
}

/// A field by browse path ("Severity", "ActiveState/Id") of BaseEventType,
/// or of another type given as "<ns0 id>:<path>" ("2782:ClientUserId");
/// "ConditionId" is the NodeId attribute of ConditionType (Part 9 §5.5.2).
fn write_simple_operand(w: &mut Writer, name: &str) {
    use crate::events::types::{BASE_EVENT_TYPE, CONDITION_TYPE};
    if name == "ConditionId" {
        w.node_id(&NodeId::ns0(CONDITION_TYPE));
        w.i32(0);
        w.u32(1);
        w.str(None);
        return;
    }
    let (ty, name) = match name.split_once(':').and_then(|(t, n)| Some((t.parse().ok()?, n))) {
        Some((t, n)) => (t, n),
        None => (BASE_EVENT_TYPE, name),
    };
    w.node_id(&NodeId::ns0(ty));
    w.i32(name.split('/').count() as i32);
    for part in name.split('/') {
        w.qualified_name(&QualifiedName { ns: 0, name: part.into() });
    }
    w.u32(13);
    w.str(None);
}

impl MonitorSpec {
    pub fn value(node: NodeId, handle: u32) -> MonitorSpec {
        MonitorSpec {
            node,
            attribute: 13,
            mode: 2,
            handle,
            sampling_ms: 0.0,
            queue_size: 1,
            discard_oldest: true,
            filter: None,
            event_select: None,
            event_where: Vec::new(),
            index_range: None,
            aggregate: None,
        }
    }

    /// Events of `node` (an event notifier) with the given fields.
    pub fn events(node: NodeId, handle: u32, fields: &[&str]) -> MonitorSpec {
        MonitorSpec {
            attribute: 12,
            queue_size: 0,
            event_select: Some(fields.iter().map(|f| f.to_string()).collect()),
            ..MonitorSpec::value(node, handle)
        }
    }

    /// An encoded ReadEventDetails (for [`Client::history_read`]) selecting
    /// the `event_select` fields of the events matching `event_where`.
    pub fn read_event_details(&self, max: u32, start: i64, end: i64) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.u32(max);
        w.i64(start);
        w.i64(end);
        self.write_event_filter(&mut w);
        buf
    }

    fn write_event_filter(&self, w: &mut Writer) {
        let at = w.begin_extension_object(ids::EVENT_FILTER_ENCODING);
        let select = self.event_select.as_deref().unwrap_or(&[]);
        w.i32(select.len() as i32);
        for f in select {
            write_simple_operand(w, f);
        }
        w.i32(self.event_where.len() as i32);
        for (op, operands) in &self.event_where {
            w.u32(*op);
            w.i32(operands.len() as i32);
            for o in operands {
                let x = match o {
                    FilterOperand::Element(i) => {
                        let x = w.begin_extension_object(crate::events::ELEMENT_OPERAND);
                        w.u32(*i);
                        x
                    }
                    FilterOperand::Literal(v) => {
                        let x = w.begin_extension_object(crate::events::LITERAL_OPERAND);
                        w.variant(v);
                        x
                    }
                    FilterOperand::Field(name) => {
                        let x = w.begin_extension_object(crate::events::SIMPLE_ATTRIBUTE_OPERAND);
                        write_simple_operand(w, name);
                        x
                    }
                };
                w.end_extension_object(x);
            }
        }
        w.end_extension_object(at);
    }
}

/// A NotificationMessage.
#[derive(Clone, Debug, Default)]
pub struct Message {
    pub seq: u32,
    pub publish_time: i64,
    /// DataChangeNotification items: (client handle, value).
    pub data: Vec<(u32, DataValue)>,
    /// StatusChangeNotification code.
    pub status_change: Option<u32>,
    /// EventNotificationList: (client handle, selected fields).
    pub events: Vec<(u32, Vec<Variant>)>,
}

impl Message {
    pub fn is_keep_alive(&self) -> bool {
        self.data.is_empty() && self.status_change.is_none() && self.events.is_empty()
    }
}

/// A PublishResponse (or the fault code of a failed Publish).
#[derive(Clone, Debug, Default)]
pub struct Publish {
    pub fault: u32,
    pub subscription: u32,
    pub available: Vec<u32>,
    pub more: bool,
    pub message: Message,
    pub ack_results: Vec<u32>,
}

fn parse_message(r: &mut Reader) -> crate::codec::DResult<Message> {
    let mut m = Message { seq: r.u32()?, publish_time: r.i64()?, ..Default::default() };
    let n = r.length(3)?.unwrap_or(0);
    for _ in 0..n {
        let (ty, _, body) = r.extension_object_raw()?;
        let mut b = Reader::new(body);
        match ty.as_ns0() {
            Some(ids::DATA_CHANGE_NOTIFICATION_ENCODING) => {
                let items = b.array(5, |b| Ok((b.u32()?, b.data_value()?)))?;
                m.data.extend(items);
            }
            Some(ids::STATUS_CHANGE_NOTIFICATION_ENCODING) => m.status_change = Some(b.u32()?),
            Some(crate::events::EVENT_NOTIFICATION_LIST_ENCODING) => {
                let items = b.array(8, |b| Ok((b.u32()?, b.array(1, |b| b.variant())?)))?;
                m.events.extend(items);
            }
            _ => {}
        }
    }
    Ok(m)
}

/// Parses a PublishResponse body (or records a ServiceFault).
pub fn parse_publish(ty: u32, body: &[u8]) -> io::Result<Publish> {
    if ty != ids::PUBLISH_RESPONSE {
        return Ok(Publish { fault: service_result(body), ..Default::default() });
    }
    let mut r = Reader::new(body);
    let bad = |_| invalid("bad PublishResponse");
    skip_response_header(&mut r).map_err(bad)?;
    let subscription = r.u32().map_err(bad)?;
    let available = r.array(4, |r| r.u32()).map_err(bad)?;
    let more = r.bool().map_err(bad)?;
    let message = parse_message(&mut r).map_err(bad)?;
    let ack_results = r.array(4, |r| r.u32()).map_err(bad)?;
    Ok(Publish { fault: 0, subscription, available, more, message, ack_results })
}
