//! Minimal synchronous client (SecurityPolicy None, anonymous), used by the
//! integration tests and the latency benchmark. Not a general-purpose client.

use crate::codec::{Reader, Writer};
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
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

impl Client {
    /// TCP connect + HEL/ACK + OpenSecureChannel.
    pub fn connect(addr: &str, endpoint: &str) -> io::Result<Client> {
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
        Ok(([hdr[0], hdr[1], hdr[2]], hdr[3]))
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
        self.tx.clear();
        let mut w = Writer::new(&mut self.tx);
        w.raw(b"OPNF");
        w.u32(0);
        w.u32(self.channel_id);
        w.string(SECURITY_POLICY_NONE);
        w.bytes(None);
        w.bytes(None);
        w.u32(self.seq);
        w.u32(self.request_id);
        w.node_id(&NodeId::ns0(ids::OPEN_SECURE_CHANNEL_REQUEST));
        Self::write_request_header(&mut w, &NodeId::NULL, self.handle);
        w.u32(0);
        w.u32(request_type);
        w.u32(1);
        w.bytes(Some(&[]));
        w.u32(600_000);
        let len = w.len() as u32;
        w.patch_u32(4, len);
        self.seq += 1;
        self.request_id += 1;
        self.handle += 1;
        self.stream.write_all(&self.tx)?;
        let (ty, _) = self.read_chunk()?;
        if &ty != b"OPN" {
            return Err(invalid("expected OPN"));
        }
        let mut r = Reader::new(&self.rx);
        let p = || invalid("bad OPN response");
        self.channel_id = r.u32().map_err(|_| p())?;
        r.str().map_err(|_| p())?;
        r.bytes().map_err(|_| p())?;
        r.bytes().map_err(|_| p())?;
        r.u32().map_err(|_| p())?;
        r.u32().map_err(|_| p())?;
        r.node_id().map_err(|_| p())?;
        skip_response_header(&mut r).map_err(|_| p())?;
        r.u32().map_err(|_| p())?;
        let _ch = r.u32().map_err(|_| p())?;
        self.token_id = r.u32().map_err(|_| p())?;
        Ok(())
    }

    /// Sends a request; `body` writes everything after the request header.
    /// Returns the response body after the response type id is checked;
    /// the response header is returned undecoded at the start of `rx`.
    pub fn call(&mut self, request_type: u32, body: impl FnOnce(&mut Writer)) -> io::Result<(u32, &[u8])> {
        self.tx.clear();
        self.tx.resize(24, 0);
        let mut w = Writer::new(&mut self.tx);
        w.node_id(&NodeId::ns0(request_type));
        Self::write_request_header(&mut w, &self.auth_token, self.handle);
        body(&mut w);
        let size = self.tx.len() as u32;
        let h = &mut self.tx[..24];
        h[0..4].copy_from_slice(b"MSGF");
        h[4..8].copy_from_slice(&size.to_le_bytes());
        h[8..12].copy_from_slice(&self.channel_id.to_le_bytes());
        h[12..16].copy_from_slice(&self.token_id.to_le_bytes());
        h[16..20].copy_from_slice(&self.seq.to_le_bytes());
        h[20..24].copy_from_slice(&self.request_id.to_le_bytes());
        self.seq += 1;
        self.request_id += 1;
        self.handle += 1;
        self.stream.write_all(&self.tx)?;

        // Reassemble chunks.
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

    /// CreateSession + ActivateSession (anonymous).
    pub fn create_session(&mut self, name: &str) -> io::Result<()> {
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
            w.bytes(Some(&[0u8; 32]));
            w.bytes(None);
            w.f64(60_000.0);
            w.u32(0);
        })?;
        if ty != ids::CREATE_SESSION_RESPONSE {
            return Err(invalid(&format!("CreateSession failed: {:08X}", service_result(body))));
        }
        let mut r = Reader::new(body);
        skip_response_header(&mut r).map_err(|_| invalid("bad header"))?;
        let _session_id = r.node_id().map_err(|_| invalid("bad session id"))?;
        self.auth_token = r.node_id().map_err(|_| invalid("bad token"))?;

        let (ty, body) = self.call(ids::ACTIVATE_SESSION_REQUEST, |w| {
            w.str(None);
            w.bytes(None);
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
        let (ty, body) = self.call(ids::READ_REQUEST, |w| {
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
        })?;
        if ty != ids::READ_RESPONSE {
            return Err(invalid(&format!("Read failed: {:08X}", service_result(body))));
        }
        let mut r = Reader::new(body);
        skip_response_header(&mut r).map_err(|_| invalid("bad header"))?;
        r.array(1, |r| r.data_value()).map_err(|_| invalid("bad results"))
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
