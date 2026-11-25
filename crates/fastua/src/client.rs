//! Minimal synchronous client (anonymous; SecurityPolicy None, or a secure
//! policy with mutual certificate authentication), used by the integration
//! tests and the latency benchmark. Not a general-purpose client.

use crate::codec::{Reader, Writer};
use crate::crypto::{self, ChannelKeys, Mode, Policy, PrivateKey, AES_BLOCK, SYM_SIGNATURE_LEN};
use crate::pki::CertInfo;
use crate::server::SECURITY_POLICY_NONE;
use crate::types::*;
use std::io::{self, Read, Write};
use std::net::TcpStream;

pub struct Client {
    stream: TcpStream,
    channel_id: u32,
    token_id: u32,
    seq: u32,
    request_id: u32,
    handle: u32,
    pub auth_token: NodeId,
    tx: Vec<u8>,
    rx: Vec<u8>,
    /// Busy-poll for responses instead of sleeping in `recv`.
    pub spin: bool,
    sec: Option<Secure>,
}

/// Client side of a secure channel.
struct Secure {
    policy: Policy,
    mode: Mode,
    cert: Vec<u8>,
    key: PrivateKey,
    server: CertInfo,
    keys: Option<ChannelKeys>,
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
        let key = PrivateKey::from_pkcs8(key_pkcs8).map_err(|_| invalid("bad client key"))?;
        let server = crate::pki::inspect(server_cert).map_err(|_| invalid("bad server certificate"))?;
        let sec = Secure { policy, mode, cert: cert.to_vec(), key, server, keys: None };
        Self::connect_with(addr, endpoint, Some(sec))
    }

    fn connect_with(addr: &str, endpoint: &str, sec: Option<Secure>) -> io::Result<Client> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        let mut c = Client {
            stream,
            channel_id: 0,
            token_id: 0,
            seq: 1,
            request_id: 1,
            handle: 1,
            auth_token: NodeId::NULL,
            tx: Vec::with_capacity(65536),
            rx: Vec::with_capacity(65536),
            spin: false,
            sec,
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

    fn read_chunk(&mut self) -> io::Result<([u8; 3], u8)> {
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
        let keys = &sec.keys.as_ref().ok_or_else(|| invalid("no keys"))?.local;
        let bad = || invalid("bad secured response");
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

    fn write_request_header(w: &mut Writer, token: &NodeId, handle: u32) {
        w.node_id(token);
        w.i64(now_ticks());
        w.u32(handle);
        w.u32(0);
        w.str(None);
        w.u32(10_000);
        w.null_extension_object();
    }

    /// OpenSecureChannel: 0 = issue, 1 = renew.
    pub fn open(&mut self, request_type: u32) -> io::Result<()> {
        let (policy, mode) = self.sec.as_ref().map(|s| (s.policy, s.mode)).unwrap_or((Policy::None, Mode::None));
        let mut client_nonce = vec![0u8; policy.nonce_len()];
        crate::server::random_bytes(&mut client_nonce);
        // Sequence header + OpenSecureChannelRequest.
        let mut body = Vec::with_capacity(256);
        {
            let mut w = Writer::new(&mut body);
            w.u32(self.seq);
            w.u32(self.request_id);
            w.node_id(&NodeId::ns0(ids::OPEN_SECURE_CHANNEL_REQUEST));
            Self::write_request_header(&mut w, &NodeId::NULL, self.handle);
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
            Some(sec) => {
                // Mirror of the server's OPN response: pad, sign with our key,
                // encrypt with the server's.
                w.string(policy.uri());
                w.bytes(Some(&sec.cert));
                w.bytes(Some(&sec.server.thumbprint));
                let server_bytes = sec.server.key_bits / 8;
                let block_in = server_bytes - policy.oaep_overhead();
                let sig_len = sec.key.size_bytes();
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
                let sig = policy.asym_sign(&sec.key.sign, &signed).map_err(|_| invalid("signing failed"))?;
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
        let plain = match &self.sec {
            None => self.rx[asym_end..].to_vec(),
            Some(sec) => {
                let mut plain = Vec::new();
                policy.asym_decrypt(&sec.key.decrypt, &self.rx[asym_end..], &mut plain).map_err(|_| p())?;
                let sig_len = sec.server.key_bits / 8;
                let end = plain.len().checked_sub(sig_len).ok_or_else(p)?;
                let mut signed = hdr.to_vec();
                signed.extend_from_slice(&self.rx[..asym_end]);
                signed.extend_from_slice(&plain[..end]);
                policy
                    .asym_verify(&sec.server.rsa_public_key, &signed, &plain[end..])
                    .map_err(|_| invalid("OPN response signature invalid"))?;
                let body_end =
                    crate::channel::strip_padding(&plain[..end], sec.key.size_bytes() > 256).ok_or_else(p)?;
                plain.truncate(body_end);
                plain
            }
        };
        let mut r = Reader::new(&plain);
        r.u32().map_err(|_| p())?;
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
            sec.keys = Some(ChannelKeys::derive(policy, &client_nonce, &server_nonce).map_err(|_| p())?);
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
        let r = self.stream.write_all(&tx);
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
        Self::write_request_header(&mut w, &self.auth_token, self.handle);
        body(&mut w);
        let mode = self.sec.as_ref().map(|s| s.mode).unwrap_or(Mode::None);
        if mode == Mode::SignAndEncrypt {
            let plain = tx.len() - start - SYM_CLEAR_LEN;
            let (pad, _) = crypto::padding(plain, SYM_SIGNATURE_LEN, AES_BLOCK, false);
            tx.extend(std::iter::repeat_n(pad as u8, pad + 1));
        }
        let sig_len = if mode == Mode::None { 0 } else { SYM_SIGNATURE_LEN };
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
        if mode != Mode::None {
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
        self.stream.write_all(&tx)?;
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
        let mut client_nonce = [0u8; 32];
        crate::server::random_bytes(&mut client_nonce);
        let cert = self.sec.as_ref().map(|s| s.cert.clone());
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
        let mut r = Reader::new(body);
        skip_response_header(&mut r).map_err(|_| invalid("bad header"))?;
        let _session_id = r.node_id().map_err(|_| invalid("bad session id"))?;
        let token = r.node_id().map_err(|_| invalid("bad token"))?;
        r.f64().map_err(|_| invalid("bad timeout"))?;
        let server_nonce = r.bytes().map_err(|_| invalid("bad nonce"))?.unwrap_or(&[]).to_vec();
        self.auth_token = token;

        // Proof of possession of our key: sign serverCertificate || serverNonce.
        let signature = match &self.sec {
            Some(sec) if sec.policy != Policy::None => {
                let mut data = sec.server.der.clone();
                data.extend_from_slice(&server_nonce);
                let sig = sec.policy.asym_sign(&sec.key.sign, &data).map_err(|_| invalid("signing failed"))?;
                Some((sec.policy.asym_signature_uri(), sig))
            }
            _ => None,
        };
        let (ty, body) = self.call(ids::ACTIVATE_SESSION_REQUEST, |w| {
            match &signature {
                Some((alg, sig)) => {
                    w.string(alg);
                    w.bytes(Some(sig));
                }
                None => {
                    w.str(None);
                    w.bytes(None);
                }
            }
            w.empty_array();
            w.empty_array();
            let at = w.begin_extension_object(ids::ANONYMOUS_IDENTITY_TOKEN_ENCODING);
            w.string("anonymous");
            w.end_extension_object(at);
            w.str(None);
            w.bytes(None);
        })?;
        if ty != ids::ACTIVATE_SESSION_RESPONSE {
            return Err(invalid(&format!("ActivateSession failed: {:08X}", service_result(body))));
        }
        Ok(())
    }

    /// Reads attributes; returns one DataValue per (node, attribute).
    pub fn read(&mut self, items: &[(NodeId, u32)]) -> io::Result<Vec<DataValue>> {
        let mut tx = std::mem::take(&mut self.tx);
        tx.clear();
        self.push_request(&mut tx, ids::READ_REQUEST, |w| Self::read_body(w, items));
        let r = self.stream.write_all(&tx);
        self.tx = tx;
        r?;
        self.parse_read_response()
    }

    pub fn write(&mut self, items: &[(NodeId, Variant)]) -> io::Result<Vec<u32>> {
        let (ty, body) = self.call(ids::WRITE_REQUEST, |w| {
            w.i32(items.len() as i32);
            for (id, v) in items {
                w.node_id(id);
                w.u32(13);
                w.str(None);
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
