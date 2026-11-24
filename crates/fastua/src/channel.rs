//! OPC UA TCP transport and secure channel (Part 6, §6 and §7).
//!
//! One thread drives one connection. All buffers are allocated once per
//! connection and reused for every message: steady state is allocation-free
//! for the framing layer. A single-chunk response (the common case) is built
//! in place behind a reserved header and sent with one `write` syscall.

use crate::codec::{Reader, Writer};
use crate::server::{Server, Session, SECURITY_POLICY_NONE};
use crate::services;
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

struct Channel {
    id: u32,
    token_id: u32,
    prev_token_id: Option<u32>,
    token_created: Instant,
    lifetime_ms: u32,
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
    rx: Vec<u8>,
    tx: Vec<u8>,
    out: Vec<u8>,
    assembly: Vec<u8>,
    assembly_chunks: u32,
    assembly_request: u32,
    session: Option<Arc<Session>>,
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
        rx: Vec::with_capacity(limits.buffer_size as usize),
        tx: Vec::with_capacity(limits.buffer_size as usize),
        out: Vec::new(),
        assembly: Vec::new(),
        assembly_chunks: 0,
        assembly_request: 0,
        session: None,
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
    /// Reads one chunk into `rx`; returns (message type, chunk type).
    fn read_chunk(&mut self, limit: u32) -> Result<([u8; 3], u8), Fatal> {
        let mut hdr = [0u8; 8];
        self.stream.read_exact(&mut hdr)?;
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if size < 8 {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "chunk too small"));
        }
        if size > limit {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TOO_LARGE, "chunk larger than receive buffer"));
        }
        self.rx.clear();
        self.rx.resize(size as usize - 8, 0);
        self.stream.read_exact(&mut self.rx)?;
        Ok(([hdr[0], hdr[1], hdr[2]], hdr[3]))
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
                    self.check_symmetric_header()?;
                    return Err(Fatal::Closed);
                }
                _ => return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "unknown message type")),
            }
        }
    }

    fn hello(&mut self) -> Result<(), Fatal> {
        let mut r = Reader::new(&self.rx);
        let version = r.u32()?;
        let client_recv = r.u32()?;
        let client_send = r.u32()?;
        let max_message = r.u32()?;
        let max_chunks = r.u32()?;
        let url = r.str()?.unwrap_or("");
        if url.len() > 4096 {
            return Err(Fatal::Protocol(status::BAD_TCP_ENDPOINT_URL_INVALID, "endpoint url too long"));
        }
        let _ = version; // Any client version >= ours is accepted (Part 6 §7.1.2.3).
        if client_recv < MIN_BUFFER || client_send < MIN_BUFFER {
            return Err(Fatal::Protocol(status::BAD_TCP_INTERNAL_ERROR, "buffer size below 8192"));
        }
        let ours = self.server.limits().buffer_size;
        self.send_buffer = ours.min(client_recv);
        self.recv_buffer = ours.min(client_send);
        self.client_max_message = max_message;
        self.client_max_chunks = max_chunks;

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
            // Part 6 §6.7.2.4: strictly +1, wrapping below 1024 once past 2^32-1024.
            let ok = seq == last.wrapping_add(1) || (last > u32::MAX - 1024 && seq < 1024);
            if !ok {
                return Err(Fatal::Protocol(status::BAD_SEQUENCE_NUMBER_INVALID, "sequence number out of order"));
            }
        }
        self.last_client_seq = Some(seq);
        Ok(())
    }

    fn open_channel(&mut self, chunk: u8) -> Result<(), Fatal> {
        if chunk != b'F' {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "chunked OPN not supported"));
        }
        let rx = std::mem::take(&mut self.rx);
        let result = self.open_channel_inner(&rx);
        self.rx = rx;
        result
    }

    fn open_channel_inner(&mut self, rx: &[u8]) -> Result<(), Fatal> {
        let mut r = Reader::new(rx);
        let channel_id = r.u32()?;
        let policy = r.str()?.unwrap_or("");
        let _sender_cert = r.bytes()?;
        let _thumbprint = r.bytes()?;
        let seq = r.u32()?;
        let request_id = r.u32()?;
        if policy != SECURITY_POLICY_NONE {
            return Err(Fatal::Protocol(status::BAD_SECURITY_POLICY_REJECTED, "security policy not supported yet"));
        }
        // A new channel restarts the client's sequence numbering.
        if self.channel.is_none() {
            self.last_client_seq = None;
        }
        self.check_sequence(seq)?;
        let type_id = r.node_id()?;
        if type_id.as_ns0() != Some(ids::OPEN_SECURE_CHANNEL_REQUEST) {
            return Err(Fatal::Protocol(status::BAD_TCP_MESSAGE_TYPE_INVALID, "OPN without OpenSecureChannelRequest"));
        }
        let header = services::RequestHeader::decode(&mut r)?;
        let _client_protocol = r.u32()?;
        let request_type = r.u32()?;
        let mode = r.u32()?;
        let _client_nonce = r.bytes()?;
        let requested_lifetime = r.u32()?;

        if mode != 1 {
            return Err(Fatal::Protocol(status::BAD_SECURITY_POLICY_REJECTED, "security mode not supported yet"));
        }
        let limits = self.server.limits();
        let lifetime = requested_lifetime.clamp(limits.min_token_lifetime_ms, limits.max_token_lifetime_ms);
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
                });
                self.channel.as_ref().unwrap()
            }
            (1, Some(ch)) if ch.id == channel_id => {
                ch.prev_token_id = Some(ch.token_id);
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

        let seq_out = self.next_sequence();
        self.tx.clear();
        let mut w = Writer::new(&mut self.tx);
        w.raw(b"OPNF");
        w.u32(0);
        w.u32(id);
        w.string(SECURITY_POLICY_NONE);
        w.bytes(None);
        w.bytes(None);
        w.u32(seq_out);
        w.u32(request_id);
        w.node_id(&NodeId::ns0(ids::OPEN_SECURE_CHANNEL_RESPONSE));
        services::write_response_header(&mut w, header.handle, status::GOOD);
        w.u32(PROTOCOL_VERSION);
        w.u32(id);
        w.u32(token_id);
        w.i64(now_ticks());
        w.u32(lifetime);
        w.bytes(Some(&[]));
        let len = w.len() as u32;
        w.patch_u32(4, len);
        self.stream.write_all(&self.tx)?;
        Ok(())
    }

    #[inline(always)]
    fn next_sequence(&mut self) -> u32 {
        let s = self.next_seq;
        // Wrap to 1 before reaching the forbidden range near 2^32.
        self.next_seq = if s >= u32::MAX - 1024 { 1 } else { s + 1 };
        s
    }

    /// Validates channel id + token id; returns (sequence, request id) offset reader.
    fn check_symmetric_header(&mut self) -> Result<(u32, usize), Fatal> {
        let rx = std::mem::take(&mut self.rx);
        let result = (|| {
            let mut r = Reader::new(&rx);
            let channel_id = r.u32()?;
            let token_id = r.u32()?;
            let seq = r.u32()?;
            let request_id = r.u32()?;
            let ch = self
                .channel
                .as_ref()
                .ok_or(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "no secure channel"))?;
            if ch.id != channel_id {
                return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "wrong secure channel id"));
            }
            if token_id != ch.token_id && Some(token_id) != ch.prev_token_id {
                return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "unknown security token"));
            }
            // Part 4 §5.5.2: the token stays valid for 125% of its lifetime.
            if ch.token_created.elapsed().as_millis() as u64 > ch.lifetime_ms as u64 * 5 / 4 {
                return Err(Fatal::Protocol(status::BAD_SECURE_CHANNEL_ID_INVALID, "security token expired"));
            }
            if token_id == ch.token_id {
                // Once the client uses the new token, the old one is retired.
                if let Some(ch) = self.channel.as_mut() {
                    ch.prev_token_id = None;
                }
            }
            self.check_sequence(seq)?;
            Ok((request_id, r.position()))
        })();
        self.rx = rx;
        result
    }

    fn message(&mut self, chunk: u8) -> Result<(), Fatal> {
        let (request_id, body_at) = self.check_symmetric_header()?;
        let limits = self.server.limits();
        match chunk {
            b'F' if self.assembly_chunks == 0 => {
                let rx = std::mem::take(&mut self.rx);
                let r = self.handle_request(request_id, &rx[body_at..]);
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
                    || self.assembly.len() + self.rx.len() - body_at > limits.max_message_size as usize
                {
                    return Err(Fatal::Protocol(status::BAD_REQUEST_TOO_LARGE, "request too large"));
                }
                self.assembly.extend_from_slice(&self.rx[body_at..]);
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
        let channel_id = self.channel.as_ref().map(|c| c.id).unwrap_or(0);
        let mut tx = std::mem::take(&mut self.tx);
        tx.clear();
        tx.resize(MSG_HEADER_LEN, 0);
        let mut r = Reader::new(body);
        let handle = {
            let mut w = Writer::new(&mut tx);
            let mut ctx = services::Ctx { server: self.server, channel_id, session: &mut self.session };
            services::dispatch(&mut ctx, &mut r, &mut w)
        };
        let res = self.send_response(request_id, &mut tx, handle);
        self.tx = tx;
        res
    }

    /// Frames `tx[24..]` into one or more MSG chunks and sends them.
    fn send_response(&mut self, request_id: u32, tx: &mut Vec<u8>, handle: u32) -> Result<(), Fatal> {
        let body_len = tx.len() - MSG_HEADER_LEN;
        let max_body = self.send_buffer as usize - MSG_HEADER_LEN;
        let chunks = body_len.div_ceil(max_body).max(1);
        let too_big = (self.client_max_message != 0 && body_len > self.client_max_message as usize)
            || (self.client_max_chunks != 0 && chunks > self.client_max_chunks as usize);
        if too_big {
            tx.truncate(MSG_HEADER_LEN);
            let mut w = Writer::new(tx);
            services::write_fault(&mut w, handle, status::BAD_RESPONSE_TOO_LARGE);
            return self.send_response(request_id, tx, handle);
        }
        let ch_id = self.channel.as_ref().map(|c| c.id).unwrap_or(0);
        let token = self.channel.as_ref().map(|c| c.token_id).unwrap_or(0);

        if chunks == 1 {
            let seq = self.next_sequence();
            let size = tx.len() as u32;
            write_msg_header(&mut tx[..MSG_HEADER_LEN], b'F', size, ch_id, token, seq, request_id);
            self.stream.write_all(tx)?;
            return Ok(());
        }
        self.out.clear();
        self.out.reserve(body_len + chunks * MSG_HEADER_LEN);
        for (i, part) in tx[MSG_HEADER_LEN..].chunks(max_body).enumerate() {
            let kind = if i + 1 == chunks { b'F' } else { b'C' };
            let seq = self.next_sequence();
            let at = self.out.len();
            self.out.resize(at + MSG_HEADER_LEN, 0);
            let size = (MSG_HEADER_LEN + part.len()) as u32;
            write_msg_header(&mut self.out[at..at + MSG_HEADER_LEN], kind, size, ch_id, token, seq, request_id);
            self.out.extend_from_slice(part);
        }
        self.stream.write_all(&self.out)?;
        Ok(())
    }
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
