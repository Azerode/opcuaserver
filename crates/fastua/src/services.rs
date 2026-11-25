//! Service handlers (Part 4). Responses are encoded straight into the
//! connection's transmit buffer: no intermediate response structs.

use crate::address_space::*;
use crate::channel::Security;
use crate::codec::{DResult, Reader, Writer};
use crate::crypto::{self, Mode, Policy};
use crate::server::{
    random_bytes, ContinuationPoint, Server, Session, CERTIFICATE_POLICY_ID, TRANSPORT_PROFILE_BINARY,
    USERNAME_POLICY_ID,
};
use crate::types::*;
use crate::value::ValueCell;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[path = "sub_services.rs"]
mod sub;

pub struct Ctx<'a> {
    pub server: &'a Arc<Server>,
    pub channel_id: u32,
    pub security: &'a Security,
    /// Last session used on this connection: avoids the global table lookup.
    pub session: &'a mut Option<Arc<Session>>,
    /// Address space snapshot last used on this connection (see `Store::cached`).
    pub space: &'a mut Option<Arc<AddressSpace>>,
    /// Connection-level state for services that answer later (Publish).
    pub conn: &'a mut ConnState,
}

/// What the subscription services need from the connection.
#[derive(Default)]
pub struct ConnState {
    /// Request id of the request being dispatched.
    pub request_id: u32,
    /// Set by a service that answers later (Publish): nothing to send now.
    pub deferred: bool,
    /// Set when the response written belongs to another (older) request.
    pub reply_to: Option<u32>,
    /// Sessions whose subscriptions this connection drives.
    pub sessions: Vec<Arc<Session>>,
    /// Subscription state changed: the next deadline must be recomputed.
    pub timers_dirty: bool,
    /// Largest response body the client accepts.
    pub max_response: usize,
}

impl ConnState {
    pub fn new(max_response: usize) -> ConnState {
        ConnState { max_response, ..Default::default() }
    }

    /// This connection drives `s`'s subscriptions from now on.
    pub fn drive(&mut self, s: &Arc<Session>) {
        if !self.sessions.iter().any(|x| Arc::ptr_eq(x, s)) {
            self.sessions.push(s.clone());
        }
        self.timers_dirty = true;
    }
}

pub struct RequestHeader {
    pub auth_token: NodeId,
    pub handle: u32,
    pub return_diagnostics: u32,
    pub timeout_hint: u32,
    /// The AdditionalHeader asks for an ephemeral ECDH key ("ECDHPolicyUri",
    /// EccEncryptedSecret user tokens).
    pub ecdh: bool,
    /// Coarse server clock (1-4 ms resolution, a few ns to read) when the
    /// request was decoded: the ResponseHeader timestamp.
    pub now: i64,
}

impl RequestHeader {
    pub fn decode(r: &mut Reader) -> DResult<RequestHeader> {
        // Fast path, one bounds check: Guid token (what this server issues),
        // null auditEntryId, null additionalHeader.
        if let Some(b) = r.peek::<46>() {
            if b[0] == 0x04 && b[35..39] == [0xFF; 4] && b[43..46] == [0, 0, 0] {
                let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                let auth_token = NodeId::Guid(u16::from_le_bytes([b[1], b[2]]), b[3..19].try_into().unwrap());
                let h = RequestHeader {
                    auth_token,
                    handle: u32_at(27),
                    return_diagnostics: u32_at(31),
                    timeout_hint: u32_at(39),
                    ecdh: false,
                    now: coarse_now_ticks(),
                };
                r.advance(46);
                return Ok(h);
            }
        }
        let auth_token = r.node_id()?;
        let _timestamp = r.i64()?;
        let handle = r.u32()?;
        let return_diagnostics = r.u32()?;
        let _audit = r.str()?;
        let timeout_hint = r.u32()?;
        let (additional, _, body) = r.extension_object_raw()?;
        let ecdh = additional.as_ns0() == Some(ADDITIONAL_PARAMETERS_ENCODING) && requests_ecdh(body);
        Ok(RequestHeader { auth_token, handle, return_diagnostics, timeout_hint, ecdh, now: coarse_now_ticks() })
    }
}

#[inline]
pub fn write_response_header(w: &mut Writer, now: i64, handle: u32, result: u32) {
    w.i64(now);
    w.u32(handle);
    w.u32(result);
    w.empty_diagnostic_info();
    w.null_array(); // stringTable
    w.null_extension_object();
}

const ADDITIONAL_PARAMETERS_ENCODING: u32 = 17537;
const EPHEMERAL_KEY_ENCODING: u32 = 17549;
const ECC_ENCRYPTED_SECRET: u32 = 17546;

/// AdditionalParametersType with a ("ECDHPolicyUri", ...) parameter.
fn requests_ecdh(body: &[u8]) -> bool {
    let mut r = Reader::new(body);
    let mut scan = || -> DResult<bool> {
        let n = r.length(1)?.unwrap_or(0);
        for _ in 0..n {
            let (ns, name) = r.qualified_name_ref()?;
            if ns == 0 && name == Some("ECDHPolicyUri") {
                return Ok(true);
            }
            r.variant()?;
        }
        Ok(false)
    };
    scan().unwrap_or(false)
}

/// On an ECC channel, when the client asked for it: a new ephemeral key for
/// the session's next EccEncryptedSecret, signed with our key, in the
/// ResponseHeader's AdditionalHeader (written by `begin` as null, replaced).
fn write_ecdh_key(ctx: &Ctx, h: &RequestHeader, s: &Session, w: &mut Writer) -> Result<(), u32> {
    let Policy::Ecc(suite) = ctx.security.policy else { return Ok(()) };
    if !h.ecdh {
        return Ok(());
    }
    let own = ctx.server.pki().ecc_own(suite.curve).ok_or(status::BAD_INTERNAL_ERROR)?;
    let eph = crate::ecc::Ephemeral::generate(suite).map_err(|_| status::BAD_INTERNAL_ERROR)?;
    let sig = own.key.sign(&eph.public).map_err(|_| status::BAD_INTERNAL_ERROR)?;
    let mut tail = Vec::new();
    {
        let mut t = Writer::new(&mut tail);
        let at = t.begin_extension_object(ADDITIONAL_PARAMETERS_ENCODING);
        t.i32(2);
        t.u16(0);
        t.string("ECDHPolicyUri");
        t.u8(12); // Variant String
        t.string(suite.uri());
        t.u16(0);
        t.string("ECDHKey");
        t.u8(22); // Variant ExtensionObject
        let k = t.begin_extension_object(EPHEMERAL_KEY_ENCODING);
        t.bytes(Some(&eph.public));
        t.bytes(Some(&sig));
        t.end_extension_object(k);
        t.end_extension_object(at);
    }
    // The null AdditionalHeader is the last 3 bytes `begin` wrote.
    let end = w.buf.len() - 3;
    let body = w.buf.split_off(end);
    debug_assert_eq!(body, [0, 0, 0]);
    w.buf.extend_from_slice(&tail);
    *s.ecdh.lock().unwrap_or_else(|e| e.into_inner()) = Some(eph);
    Ok(())
}

/// Decrypts an EccEncryptedSecret (Part 4 §7.41.2.3) with the session's
/// ephemeral key: signed by the client's application key, AEAD-encrypted
/// `nonce | secret | padding | padding size`.
fn decrypt_ecc_secret(ctx: &Ctx, s: &Session, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, u32> {
    let bad = status::BAD_IDENTITY_TOKEN_INVALID;
    let suite = ctx.security.policy.ecc().ok_or(bad)?;
    let client = ctx.security.client_cert.as_ref().ok_or(status::BAD_SECURITY_CHECKS_FAILED)?;
    // The ephemeral key is good for one secret.
    let eph = s.ecdh.lock().unwrap_or_else(|e| e.into_inner()).take().ok_or(bad)?;
    let mut r = Reader::new(data);
    let mut header = || -> DResult<(NodeId, u8, usize, Option<String>, u16)> {
        let ty = r.node_id()?;
        let enc = r.u8()?;
        // Length counts the bytes after itself.
        let end = r.u32()? as usize + r.position();
        let uri = r.str()?.map(str::to_string);
        r.bytes()?; // certificate: the channel's, checked by the signature
        r.i64()?; // signingTime
        let key_len = r.u16()?;
        Ok((ty, enc, end, uri, key_len))
    };
    let (ty, enc, end, uri, key_len) = header().map_err(|_| bad)?;
    if ty.as_ns0() != Some(ECC_ENCRYPTED_SECRET) || enc != 1 || uri.as_deref() != Some(suite.uri()) {
        return Err(bad);
    }
    let sig_len = suite.signature_len();
    if end != data.len() || end < r.position() + sig_len + crate::ecc::TAG_LEN {
        return Err(bad);
    }
    let signed = end - sig_len;
    suite.verify(&client.rsa_public_key, &data[..signed], &data[signed..]).map_err(|_| bad)?;
    let keys_at = r.position();
    let sender = r.bytes().map_err(|_| bad)?.unwrap_or(&[]);
    let receiver = r.bytes().map_err(|_| bad)?.unwrap_or(&[]);
    let payload_at = r.position();
    if payload_at - keys_at != key_len as usize || payload_at + crate::ecc::TAG_LEN > signed {
        return Err(bad);
    }
    if receiver != eph.public.as_slice() {
        return Err(bad);
    }
    let keys = eph.secret_keys(suite, sender, sender, receiver).map_err(|_| bad)?;
    let tag_at = signed - crate::ecc::TAG_LEN;
    let mut plain = data[payload_at..tag_at].to_vec();
    keys.open(0, 0, &data[..payload_at], &mut plain, &data[tag_at..signed]).map_err(|_| bad)?;
    // nonce | secret | padding (n bytes of n) | n (UInt16)
    let mut p = Reader::new(&plain);
    let got_nonce = p.bytes().map_err(|_| bad)?.unwrap_or(&[]);
    if aws_lc_rs::constant_time::verify_slices_are_equal(got_nonce, nonce).is_err() {
        return Err(status::BAD_SECURITY_CHECKS_FAILED);
    }
    let secret = p.bytes().map_err(|_| bad)?.unwrap_or(&[]).to_vec();
    let pad_at = p.position();
    let n = plain.len().checked_sub(2).filter(|&n| n >= pad_at).ok_or(bad)?;
    let size = u16::from_le_bytes([plain[n], plain[n + 1]]) as usize;
    if n - pad_at != size || plain[pad_at..n].iter().any(|&b| b != size as u8) {
        return Err(bad);
    }
    Ok(secret)
}

#[inline]
pub(crate) fn begin(w: &mut Writer, response_type: u32, h: &RequestHeader) {
    begin_raw(w, response_type, h.now, h.handle)
}

/// Response type id and a Good ResponseHeader.
#[inline]
pub fn begin_raw(w: &mut Writer, response_type: u32, now: i64, handle: u32) {
    // Every response type id fits the 4-byte NodeId encoding: type id and
    // ResponseHeader go out as one 32-byte block.
    debug_assert!(response_type <= 0xFFFF);
    let mut b = [0u8; 32];
    b[0] = 0x01;
    b[2..4].copy_from_slice(&(response_type as u16).to_le_bytes());
    b[4..12].copy_from_slice(&now.to_le_bytes());
    b[12..16].copy_from_slice(&handle.to_le_bytes());
    // 16..20 serviceResult Good, 20 empty DiagnosticInfo
    b[21..25].copy_from_slice(&(-1i32).to_le_bytes()); // null stringTable
                                                       // 25..28 null additionalHeader
    w.raw_prefix(&b, 28);
}

pub fn write_fault(w: &mut Writer, handle: u32, code: u32) {
    w.node_id(&NodeId::ns0(ids::SERVICE_FAULT));
    write_response_header(w, now_ticks(), handle, code);
}

pub(crate) type SResult = Result<(), u32>;

/// Decodes the request type and header, runs the service and writes either its
/// response or a ServiceFault. Returns the request handle.
pub fn dispatch(ctx: &mut Ctx, r: &mut Reader, w: &mut Writer) -> u32 {
    let start = w.len();
    let (type_id, header) = match r.node_id().and_then(|t| Ok((t, RequestHeader::decode(r)?))) {
        Ok(v) => v,
        Err(_) => {
            write_fault(w, 0, status::BAD_DECODING_ERROR);
            return 0;
        }
    };
    let handle = header.handle;
    let result = match type_id.as_ns0() {
        Some(ids::READ_REQUEST) => read(ctx, &header, r, w),
        Some(ids::WRITE_REQUEST) => write(ctx, &header, r, w),
        Some(ids::BROWSE_REQUEST) => browse(ctx, &header, r, w),
        Some(ids::BROWSE_NEXT_REQUEST) => browse_next(ctx, &header, r, w),
        Some(ids::TRANSLATE_BROWSE_PATHS_REQUEST) => translate(ctx, &header, r, w),
        Some(ids::REGISTER_NODES_REQUEST) => register_nodes(ctx, &header, r, w),
        Some(ids::UNREGISTER_NODES_REQUEST) => unregister_nodes(ctx, &header, r, w),
        Some(ids::GET_ENDPOINTS_REQUEST) => get_endpoints(ctx, &header, r, w),
        Some(ids::FIND_SERVERS_REQUEST) => find_servers(ctx, &header, r, w),
        Some(ids::CREATE_SESSION_REQUEST) => create_session(ctx, &header, r, w),
        Some(ids::ACTIVATE_SESSION_REQUEST) => activate_session(ctx, &header, r, w),
        Some(ids::CLOSE_SESSION_REQUEST) => close_session(ctx, &header, r, w),
        Some(ids::PUBLISH_REQUEST) => sub::publish(ctx, &header, r, w),
        Some(ids::REPUBLISH_REQUEST) => sub::republish(ctx, &header, r, w),
        Some(ids::CREATE_SUBSCRIPTION_REQUEST) => sub::create_subscription(ctx, &header, r, w),
        Some(ids::MODIFY_SUBSCRIPTION_REQUEST) => sub::modify_subscription(ctx, &header, r, w),
        Some(ids::SET_PUBLISHING_MODE_REQUEST) => sub::set_publishing_mode(ctx, &header, r, w),
        Some(ids::DELETE_SUBSCRIPTIONS_REQUEST) => sub::delete_subscriptions(ctx, &header, r, w),
        Some(ids::TRANSFER_SUBSCRIPTIONS_REQUEST) => sub::transfer_subscriptions(ctx, &header, r, w),
        Some(ids::CREATE_MONITORED_ITEMS_REQUEST) => sub::create_monitored_items(ctx, &header, r, w),
        Some(ids::MODIFY_MONITORED_ITEMS_REQUEST) => sub::modify_monitored_items(ctx, &header, r, w),
        Some(ids::SET_MONITORING_MODE_REQUEST) => sub::set_monitoring_mode(ctx, &header, r, w),
        Some(ids::SET_TRIGGERING_REQUEST) => sub::set_triggering(ctx, &header, r, w),
        Some(ids::DELETE_MONITORED_ITEMS_REQUEST) => sub::delete_monitored_items(ctx, &header, r, w),
        Some(ids::CALL_REQUEST) => sub::call(ctx, &header, r, w),
        Some(ids::CANCEL_REQUEST) => sub::cancel(ctx, &header, r, w),
        Some(ids::HISTORY_READ_REQUEST) => crate::history::history_read(ctx, &header, r, w),
        Some(ids::HISTORY_UPDATE_REQUEST) => crate::history::history_update(ctx, &header, r, w),
        _ => Err(status::BAD_SERVICE_UNSUPPORTED),
    };
    if let Err(code) = result {
        let session_service =
            matches!(type_id.as_ns0(), Some(ids::CREATE_SESSION_REQUEST | ids::ACTIVATE_SESSION_REQUEST));
        ctx.server.store.info().diagnostics.rejected(session_service, code);
        w.buf.truncate(start);
        write_fault(w, handle, code);
    }
    handle
}

pub(crate) fn decode_err(_: crate::codec::DecodeError) -> u32 {
    status::BAD_DECODING_ERROR
}

/// Resolves and validates the session of a request (Part 4 §5.6).
pub(crate) fn session(ctx: &mut Ctx, header: &RequestHeader, must_be_active: bool) -> Result<Arc<Session>, u32> {
    session_ref(ctx, header, must_be_active).cloned()
}

/// Like [`session`] without the reference-count round trip on the hot path.
#[inline]
pub(crate) fn session_ref<'c>(
    ctx: &'c mut Ctx,
    header: &RequestHeader,
    must_be_active: bool,
) -> Result<&'c Arc<Session>, u32> {
    if !ctx.session.as_ref().is_some_and(|s| s.token == header.auth_token) {
        let s = ctx.server.find_session(&header.auth_token).ok_or(status::BAD_SESSION_ID_INVALID)?;
        *ctx.session = Some(s);
    }
    if ctx.session.as_ref().is_some_and(|s| s.closed.load(Ordering::Acquire)) {
        *ctx.session = None;
        return Err(status::BAD_SESSION_ID_INVALID);
    }
    let s = ctx.session.as_ref().unwrap();
    if must_be_active {
        if !s.activated.load(Ordering::Acquire) {
            return Err(status::BAD_SESSION_NOT_ACTIVATED);
        }
        if s.channel_id.load(Ordering::Acquire) != ctx.channel_id {
            return Err(status::BAD_SECURE_CHANNEL_ID_INVALID);
        }
    }
    s.touched.store(true, Ordering::Relaxed);
    Ok(s)
}

pub(crate) fn check_count(ctx: &Ctx, n: usize) -> SResult {
    if n == 0 {
        return Err(status::BAD_NOTHING_TO_DO);
    }
    if n > ctx.server.limits().max_operations_per_request {
        return Err(status::BAD_TOO_MANY_OPERATIONS);
    }
    Ok(())
}

// ---------------------------------------------------------------- Discovery

fn get_endpoints(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let _url = r.str().map_err(decode_err)?;
    r.skip_string_array().map_err(decode_err)?;
    let profiles = r.array(4, |r| r.str()).map_err(decode_err)?;
    begin(w, ids::GET_ENDPOINTS_RESPONSE, h);
    let matches = profiles.is_empty() || profiles.contains(&Some(TRANSPORT_PROFILE_BINARY));
    if matches {
        w.raw(ctx.server.endpoints_encoded());
    } else {
        w.empty_array();
    }
    Ok(())
}

fn find_servers(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let _url = r.str().map_err(decode_err)?;
    r.skip_string_array().map_err(decode_err)?;
    let uris = r.array(4, |r| r.str()).map_err(decode_err)?;
    begin(w, ids::FIND_SERVERS_RESPONSE, h);
    let own = ctx.server.store.info().application_uri.as_str();
    if uris.is_empty() || uris.contains(&Some(own)) {
        w.raw(ctx.server.application_encoded());
    } else {
        w.empty_array();
    }
    Ok(())
}

// ---------------------------------------------------------------- Sessions

/// Reads an ApplicationDescription, returning its applicationUri.
fn read_application_uri(r: &mut Reader) -> DResult<Option<String>> {
    let uri = r.str()?.map(str::to_string);
    r.str()?;
    r.localized_text()?;
    r.i32()?;
    r.str()?;
    r.str()?;
    r.skip_string_array()?;
    Ok(uri)
}

const BAD_NONCE_INVALID: u32 = 0x8024_0000;
const BAD_USER_SIGNATURE_INVALID: u32 = 0x8057_0000;
const BAD_APPLICATION_SIGNATURE_INVALID: u32 = 0x8058_0000;

fn create_session(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    #[allow(clippy::type_complexity)]
    let mut parse = || -> DResult<(Option<String>, String, Vec<u8>, Option<Vec<u8>>, f64)> {
        let app_uri = read_application_uri(r)?;
        let _server_uri = r.str()?;
        let _endpoint_url = r.str()?;
        let name = r.str()?.unwrap_or("").to_string();
        let nonce = r.bytes()?.unwrap_or(&[]).to_vec();
        let cert = r.bytes()?.filter(|c| !c.is_empty()).map(<[u8]>::to_vec);
        let timeout = r.f64()?;
        let _max_response = r.u32()?;
        Ok((app_uri, name, nonce, cert, timeout))
    };
    let (app_uri, name, client_nonce, client_cert, requested_timeout) = parse().map_err(decode_err)?;
    let security = ctx.security.clone();
    let pki = ctx.server.pki();

    // Part 4 §5.6.2: checks tied to the secure channel.
    let server_signature = if security.policy == Policy::None {
        if !ctx.server.endpoint_enabled(Policy::None, Mode::None) {
            return Err(status::BAD_SECURITY_POLICY_REJECTED);
        }
        None
    } else {
        let channel_cert = security.client_cert.as_ref().ok_or(status::BAD_SECURITY_CHECKS_FAILED)?;
        if client_cert.as_deref() != Some(&channel_cert.der[..]) {
            // The session certificate must be the channel's leaf certificate.
            let leaf = client_cert.as_deref().and_then(|c| crate::pki::split_chain(c).ok()).map(|c| c[0].to_vec());
            if leaf.as_deref() != Some(&channel_cert.der[..]) {
                return Err(status::BAD_SECURITY_CHECKS_FAILED);
            }
        }
        if app_uri.is_none() || channel_cert.application_uri != app_uri {
            return Err(crate::pki::codes::BAD_CERTIFICATE_URI_INVALID);
        }
        if client_nonce.len() < crypto::NONCE_LEN {
            return Err(BAD_NONCE_INVALID);
        }
        Some(channel_cert.clone())
    };

    let limits = ctx.server.limits();
    let timeout = if requested_timeout.is_finite() && requested_timeout > 0.0 {
        requested_timeout.clamp(limits.min_session_timeout_ms, limits.max_session_timeout_ms)
    } else {
        60_000.0
    };
    let mut nonce = vec![0u8; crypto::NONCE_LEN];
    random_bytes(&mut nonce);
    let server_signature = match server_signature {
        None => None,
        Some(channel_cert) => Some(match security.policy {
            Policy::Ecc(suite) => {
                // Channel-bound (SecureChannelEnhancements): ChannelThumbprint |
                // clientNonce | H(server cert) | H(client cert) | serverNonce.
                let own = pki.ecc_own(suite.curve).ok_or(status::BAD_INTERNAL_ERROR)?;
                let data = ecc_signature_data(&security, &client_nonce, &[&own.cert_der, &channel_cert.der], &nonce)?;
                own.key.sign(&data).map_err(|_| status::BAD_INTERNAL_ERROR)?
            }
            p => {
                let mut data = channel_cert.der.clone();
                data.extend_from_slice(&client_nonce);
                p.asym_sign(&pki.key.sign, &data).map_err(|_| status::BAD_INTERNAL_ERROR)?
            }
        }),
    };
    let session = ctx.server.create_session(
        name,
        ctx.channel_id,
        timeout,
        security.clone(),
        nonce.clone(),
        client_nonce.clone(),
    )?;
    let thumbprint = client_cert.as_deref().map(|c| crate::pki::hex(&crypto::thumbprint(c)));
    let channel = ctx.channel_id;
    ctx.server.session_event(
        crate::events::types::AUDIT_CREATE_SESSION_EVENT_TYPE,
        &session,
        "Session/CreateSession",
        true,
        |e| {
            use crate::events::types::*;
            e.with(CREATE_SECURE_CHANNEL_ID, Variant::string(&channel.to_string()))
                .with(CLIENT_CERTIFICATE, Variant::ByteString(client_cert.as_deref().map(Into::into)))
                .with(CLIENT_CERTIFICATE_THUMBPRINT, Variant::String(thumbprint.map(Into::into)))
                .with(REVISED_SESSION_TIMEOUT, Variant::Double(timeout))
        },
    );

    begin(w, ids::CREATE_SESSION_RESPONSE, h);
    write_ecdh_key(ctx, h, &session, w)?;
    w.node_id(&session.id);
    w.node_id(&session.token);
    w.f64(timeout);
    w.bytes(Some(&nonce));
    w.bytes(Some(pki.certificate_for(security.policy)));
    w.raw(ctx.server.endpoints_encoded());
    w.empty_array(); // serverSoftwareCertificates
    match &server_signature {
        Some(sig) => {
            // SecureChannelEnhancements: the algorithm is left empty.
            w.str((!security.policy.is_ecc()).then(|| security.policy.asym_signature_uri()));
            w.bytes(Some(sig));
        }
        None => {
            w.str(None);
            w.bytes(None);
        }
    }
    w.u32(limits.max_message_size);
    crate::log!("session '{}' ({}) created, {:?}/{:?}", session.name, session.id, security.policy, security.mode);
    *ctx.session = Some(session);
    Ok(())
}

/// Data of a channel-bound ECC signature (SecureChannelEnhancements):
/// ChannelThumbprint | first nonce | certificate hashes | last nonce.
fn ecc_signature_data(security: &Security, first: &[u8], certs: &[&[u8]], last: &[u8]) -> Result<Vec<u8>, u32> {
    let suite = security.policy.ecc().ok_or(status::BAD_INTERNAL_ERROR)?;
    let tp = security.channel_thumbprint.as_deref().ok_or(status::BAD_SECURITY_CHECKS_FAILED)?;
    let mut data = Vec::with_capacity(tp.len() + first.len() + certs.len() * 48 + last.len());
    data.extend_from_slice(tp);
    data.extend_from_slice(first);
    for c in certs {
        data.extend_from_slice(&suite.certificate_hash(c));
    }
    data.extend_from_slice(last);
    Ok(data)
}

/// Security policy protecting a user token: the token policy's own on an
/// unsecured channel (we advertise Basic256Sha256), else the channel's.
fn token_policy(ctx: &Ctx) -> Policy {
    match ctx.security.policy {
        Policy::None => Policy::Basic256Sha256,
        p => p,
    }
}

/// Decrypts a legacy-format secret: `len(u32) | secret | serverNonce` (Part 4 §7.41.2.2).
fn decrypt_secret(ctx: &Ctx, data: &[u8], algorithm: Option<&str>, nonce: &[u8]) -> Result<Vec<u8>, u32> {
    let policy = token_policy(ctx);
    let plain = match algorithm.filter(|a| !a.is_empty()) {
        None => {
            // Clear-text passwords only travel inside an encrypted channel.
            if ctx.security.mode != Mode::SignAndEncrypt {
                return Err(status::BAD_IDENTITY_TOKEN_INVALID);
            }
            return Ok(data.to_vec());
        }
        Some(a) if a == policy.asym_encryption_uri() => {
            let mut out = Vec::new();
            policy
                .asym_decrypt(&ctx.server.pki().key.decrypt, data, &mut out)
                .map_err(|_| status::BAD_IDENTITY_TOKEN_INVALID)?;
            out
        }
        Some(_) => return Err(status::BAD_IDENTITY_TOKEN_INVALID),
    };
    if plain.len() < 4 {
        return Err(status::BAD_IDENTITY_TOKEN_INVALID);
    }
    let len = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
    if len != plain.len() - 4 || len < nonce.len() {
        return Err(status::BAD_IDENTITY_TOKEN_INVALID);
    }
    let (secret, tail) = plain[4..].split_at(len - nonce.len());
    if aws_lc_rs::constant_time::verify_slices_are_equal(tail, nonce).is_err() {
        return Err(status::BAD_IDENTITY_TOKEN_INVALID);
    }
    Ok(secret.to_vec())
}

/// ActivateSession, audited (AuditActivateSessionEventType).
fn activate_session(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let result = activate_session_inner(ctx, h, r, w);
    if let Ok(s) = session(ctx, h, false) {
        let channel = ctx.channel_id.to_string();
        ctx.server.session_event(
            crate::events::types::AUDIT_ACTIVATE_SESSION_EVENT_TYPE,
            &s,
            "Session/ActivateSession",
            result.is_ok(),
            |e| e.with(crate::events::types::ACTIVATE_SECURE_CHANNEL_ID, Variant::string(&channel)),
        );
    }
    result
}

fn activate_session_inner(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, false)?;
    #[allow(clippy::type_complexity)]
    let mut parse = || -> DResult<(Option<String>, Vec<u8>, NodeId, Vec<u8>, Option<String>, Vec<u8>)> {
        let alg = r.str()?.map(str::to_string);
        let sig = r.bytes()?.unwrap_or(&[]).to_vec();
        let n = r.length(1)?.unwrap_or(0);
        for _ in 0..n {
            r.bytes()?;
            r.bytes()?;
        }
        r.skip_string_array()?; // localeIds
        let (type_id, _enc, body) = r.extension_object_raw()?;
        let body = body.to_vec();
        let user_alg = r.str()?.map(str::to_string);
        let user_sig = r.bytes()?.unwrap_or(&[]).to_vec();
        Ok((alg, sig, type_id, body, user_alg, user_sig))
    };
    let (client_alg, client_sig, token_type, token_body, user_alg, user_sig) = parse().map_err(decode_err)?;
    let pki = ctx.server.pki();
    let nonce = s.server_nonce.lock().unwrap_or_else(|e| e.into_inner()).clone();

    // The session may only move to a channel with the same security and certificate.
    let same_cert =
        s.security.client_cert.as_ref().map(|c| &c.der) == ctx.security.client_cert.as_ref().map(|c| &c.der);
    if s.security.policy != ctx.security.policy || s.security.mode != ctx.security.mode || !same_cert {
        return Err(status::BAD_SECURITY_CHECKS_FAILED);
    }

    // Proof of possession of the client certificate's private key.
    if let Some(cert) = &ctx.security.client_cert {
        let ok = match ctx.security.policy {
            // Channel-bound; the algorithm field is ignored.
            Policy::Ecc(suite) => {
                let own = &pki.ecc_own(suite.curve).ok_or(status::BAD_INTERNAL_ERROR)?.cert_der;
                let data = ecc_signature_data(ctx.security, &nonce, &[own, own, &cert.der], &s.client_nonce)?;
                suite.verify(&cert.rsa_public_key, &data, &client_sig).is_ok()
            }
            policy => {
                let mut data = pki.cert_der.clone();
                data.extend_from_slice(&nonce);
                client_alg.as_deref() == Some(policy.asym_signature_uri())
                    && policy.asym_verify(&cert.rsa_public_key, &data, &client_sig).is_ok()
            }
        };
        if !ok {
            return Err(BAD_APPLICATION_SIGNATURE_INVALID);
        }
    }

    let mut br = Reader::new(&token_body);
    let config = &ctx.server.config;
    let (access, identity): (_, Arc<str>) = match token_type.as_ns0() {
        Some(0) | Some(ids::ANONYMOUS_IDENTITY_TOKEN_ENCODING) => {
            (config.anonymous.ok_or(status::BAD_IDENTITY_TOKEN_REJECTED)?, Arc::from("anonymous"))
        }
        Some(ids::USERNAME_IDENTITY_TOKEN_ENCODING) => {
            #[allow(clippy::type_complexity)]
            let mut parse = || -> DResult<(Option<&str>, String, Vec<u8>, Option<String>)> {
                let policy_id = br.str()?;
                let user = br.str()?.unwrap_or("").to_string();
                let password = br.bytes()?.unwrap_or(&[]).to_vec();
                let alg = br.str()?.map(str::to_string);
                Ok((policy_id, user, password, alg))
            };
            let (policy_id, user, password, alg) = parse().map_err(|_| status::BAD_IDENTITY_TOKEN_INVALID)?;
            if policy_id != Some(USERNAME_POLICY_ID) || ctx.server.users.is_empty() {
                return Err(status::BAD_IDENTITY_TOKEN_INVALID);
            }
            let password = if ctx.security.policy.is_ecc() {
                // Always an EccEncryptedSecret (the algorithm field is empty).
                decrypt_ecc_secret(ctx, &s, &password, &nonce)?
            } else {
                decrypt_secret(ctx, &password, alg.as_deref(), &nonce)?
            };
            match ctx.server.users.authenticate(&user, &password) {
                Some(a) => (a, Arc::from(format!("user:{user}"))),
                None => {
                    crate::log!("login failed for user '{user}'");
                    return Err(status::BAD_USER_ACCESS_DENIED);
                }
            }
        }
        Some(ids::X509_IDENTITY_TOKEN_ENCODING) => {
            let mut parse = || -> DResult<(Option<&str>, Vec<u8>)> {
                let policy_id = br.str()?;
                let cert = br.bytes()?.unwrap_or(&[]).to_vec();
                Ok((policy_id, cert))
            };
            let (policy_id, cert) = parse().map_err(|_| status::BAD_IDENTITY_TOKEN_INVALID)?;
            if policy_id != Some(CERTIFICATE_POLICY_ID) {
                return Err(status::BAD_IDENTITY_TOKEN_INVALID);
            }
            let info = pki.validate_user(&cert).map_err(|code| {
                crate::log!("user certificate rejected (0x{code:08X})");
                status::BAD_IDENTITY_TOKEN_REJECTED
            })?;
            let ok = match token_policy(ctx) {
                // Channel-bound, signed with a user key on the same curve.
                Policy::Ecc(suite) => {
                    let own = &pki.ecc_own(suite.curve).ok_or(status::BAD_INTERNAL_ERROR)?.cert_der;
                    let client = &ctx.security.client_cert.as_ref().ok_or(status::BAD_SECURITY_CHECKS_FAILED)?.der;
                    let data = ecc_signature_data(ctx.security, &nonce, &[own, own, client, client], &s.client_nonce)?;
                    info.curve == Some(suite.curve) && suite.verify(&info.rsa_public_key, &data, &user_sig).is_ok()
                }
                policy => {
                    let mut data = pki.cert_der.clone();
                    data.extend_from_slice(&nonce);
                    user_alg.as_deref() == Some(policy.asym_signature_uri())
                        && policy.asym_verify(&info.rsa_public_key, &data, &user_sig).is_ok()
                }
            };
            if !ok {
                return Err(BAD_USER_SIGNATURE_INVALID);
            }
            let thumb: String = info.thumbprint.iter().map(|b| format!("{b:02x}")).collect();
            (config.x509_users, Arc::from(format!("x509:{thumb}")))
        }
        _ => return Err(status::BAD_IDENTITY_TOKEN_INVALID),
    };

    // Activation may move the session to the calling channel (Part 4 §5.6.3).
    s.channel_id.store(ctx.channel_id, Ordering::Release);
    s.can_write.store(access.can_write(), Ordering::Release);
    *s.identity.lock().unwrap_or_else(|e| e.into_inner()) = identity;
    s.activated.store(true, Ordering::Release);
    if !s.subs.lock().unwrap_or_else(|e| e.into_inner()).is_idle() {
        // The subscriptions follow the session to this channel.
        ctx.conn.drive(&s);
    }

    let mut nonce = vec![0u8; crypto::NONCE_LEN];
    random_bytes(&mut nonce);
    *s.server_nonce.lock().unwrap_or_else(|e| e.into_inner()) = nonce.clone();
    begin(w, ids::ACTIVATE_SESSION_RESPONSE, h);
    write_ecdh_key(ctx, h, &s, w)?;
    w.bytes(Some(&nonce));
    w.empty_array(); // results
    w.empty_array(); // diagnosticInfos
    Ok(())
}

fn close_session(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, false)?;
    let delete_subscriptions = r.bool().map_err(decode_err)?;
    if s.channel_id.load(Ordering::Acquire) != ctx.channel_id {
        return Err(status::BAD_SECURE_CHANNEL_ID_INVALID);
    }
    ctx.server.remove_session(&s.token);
    let subs = std::mem::take(&mut s.subs.lock().unwrap_or_else(|e| e.into_inner()).subs);
    if !delete_subscriptions && !subs.is_empty() {
        // Kept for TransferSubscriptions until their lifetime ends (Part 4 §5.6.4).
        let identity = s.identity.lock().unwrap_or_else(|e| e.into_inner()).clone();
        ctx.server.orphan(identity, subs);
    }
    *ctx.session = None;
    crate::log!("session '{}' ({}) closed", s.name, s.id);
    ctx.server.session_event(crate::events::types::AUDIT_SESSION_EVENT_TYPE, &s, "Session/CloseSession", true, |e| e);
    begin(w, ids::CLOSE_SESSION_RESPONSE, h);
    Ok(())
}

// ---------------------------------------------------------------- Attributes

pub mod attr {
    pub const NODE_ID: u32 = 1;
    pub const NODE_CLASS: u32 = 2;
    pub const BROWSE_NAME: u32 = 3;
    pub const DISPLAY_NAME: u32 = 4;
    pub const DESCRIPTION: u32 = 5;
    pub const WRITE_MASK: u32 = 6;
    pub const USER_WRITE_MASK: u32 = 7;
    pub const IS_ABSTRACT: u32 = 8;
    pub const SYMMETRIC: u32 = 9;
    pub const INVERSE_NAME: u32 = 10;
    pub const CONTAINS_NO_LOOPS: u32 = 11;
    pub const EVENT_NOTIFIER: u32 = 12;
    pub const VALUE: u32 = 13;
    pub const DATA_TYPE: u32 = 14;
    pub const VALUE_RANK: u32 = 15;
    pub const ARRAY_DIMENSIONS: u32 = 16;
    pub const ACCESS_LEVEL: u32 = 17;
    pub const USER_ACCESS_LEVEL: u32 = 18;
    pub const MINIMUM_SAMPLING_INTERVAL: u32 = 19;
    pub const HISTORIZING: u32 = 20;
    pub const EXECUTABLE: u32 = 21;
    pub const USER_EXECUTABLE: u32 = 22;
    pub const ACCESS_LEVEL_EX: u32 = 27;
}

#[derive(Clone, Copy)]
struct Timestamps {
    source: bool,
    server: bool,
}

#[inline]
fn write_bad(w: &mut Writer, code: u32) {
    w.u8(0x02);
    w.u32(code);
}

/// DataValue for a non-Value attribute: only the server timestamp may apply.
#[inline]
fn write_attr(w: &mut Writer, v: &Variant, ts: Timestamps) {
    w.u8(0x01 | if ts.server { 0x08 } else { 0 });
    w.variant(v);
    if ts.server {
        w.i64(now_ticks());
    }
}

#[inline]
fn write_cell(w: &mut Writer, cell: &ValueCell, ts: Timestamps) {
    let mut buf = [0u8; crate::value::ENCODED_MAX];
    if let Some(n) = cell.encode(ts.source, ts.server, &mut buf) {
        return w.raw_prefix(&buf, n);
    }
    let s = cell.read();
    let mut mask = 0x01u8;
    if s.status != status::GOOD {
        mask |= 0x02;
    }
    if ts.source {
        mask |= 0x04;
    }
    if ts.server {
        mask |= 0x08;
    }
    w.u8(mask);
    w.variant(&s.value);
    if s.status != status::GOOD {
        w.u32(s.status);
    }
    if ts.source {
        w.i64(s.source_ts);
    }
    if ts.server {
        w.i64(s.server_ts);
    }
}

#[inline]
/// Cell values carry their own timestamps; only generated values read the
/// precise clock.
fn write_value(w: &mut Writer, space: &AddressSpace, src: &ValueSource, ts: Timestamps) {
    match src {
        ValueSource::Cell(c) => write_cell(w, c, ts),
        ValueSource::Static(v) => write_dynamic(w, v, ts, now_ticks()),
        ValueSource::CurrentTime => {
            let now = now_ticks();
            write_dynamic(w, &Variant::DateTime(now), ts, now)
        }
        ValueSource::ServerStatus => write_dynamic(w, &encode_server_status(&space.info), ts, now_ticks()),
        ValueSource::Diagnostics(i) => write_dynamic(w, &space.info.diagnostics.value(*i), ts, now_ticks()),
    }
}

#[inline]
fn write_dynamic(w: &mut Writer, v: &Variant, ts: Timestamps, now: i64) {
    let mask = 0x01 | if ts.source { 0x04 } else { 0 } | if ts.server { 0x08 } else { 0 };
    w.u8(mask);
    w.variant(v);
    if ts.source {
        w.i64(now);
    }
    if ts.server {
        w.i64(now);
    }
}

fn write_attribute(w: &mut Writer, space: &AddressSpace, node: &Node, attribute: u32, ts: Timestamps, can_write: bool) {
    if let (attr::VALUE, NodeKind::Variable { value, access, .. }) = (attribute, &node.kind) {
        if access & ACCESS_READ == 0 {
            return write_bad(w, status::BAD_NOT_READABLE);
        }
        return write_value(w, space, value, ts);
    }
    match attribute_value(node, attribute, can_write) {
        Some(v) => write_attr(w, &v, ts),
        None => write_bad(w, status::BAD_ATTRIBUTE_ID_INVALID),
    }
}

/// NumericRange (Part 4 §7.27) of one dimension: `i` or `i:j` with i < j.
/// `Err(true)`: syntax error; `Err(false)`: more dimensions than values have.
pub fn parse_range(s: &str) -> Result<(usize, usize), bool> {
    if s.contains(',') {
        let valid = s.split(',').all(|d| parse_range(d).is_ok());
        return Err(!valid);
    }
    let num = |x: &str| -> Result<usize, bool> {
        if x.is_empty() || !x.bytes().all(|b| b.is_ascii_digit()) {
            return Err(true);
        }
        x.parse().map_err(|_| true)
    };
    match s.split_once(':') {
        None => num(s).map(|i| (i, i)),
        Some((a, b)) => {
            let (a, b) = (num(a)?, num(b)?);
            if a >= b {
                return Err(true);
            }
            Ok((a, b))
        }
    }
}

/// The elements `lo..=hi` of an array, String or ByteString value.
pub fn apply_range(v: &Variant, (lo, hi): (usize, usize)) -> Result<Variant, u32> {
    let no_data = status::BAD_INDEX_RANGE_NO_DATA;
    let span = |len: usize| if lo >= len { Err(no_data) } else { Ok(lo..hi.min(len - 1) + 1) };
    Ok(match v {
        Variant::Array(a) => Variant::Array(Box::new(VariantArray {
            type_id: a.type_id,
            items: a.items[span(a.items.len())?].to_vec(),
            dims: None,
        })),
        Variant::String(Some(s)) => {
            let chars: Vec<char> = s.chars().collect();
            Variant::String(Some(chars[span(chars.len())?].iter().collect::<String>().into()))
        }
        Variant::ByteString(Some(b)) => Variant::ByteString(Some(b[span(b.len())?].into())),
        _ => return Err(no_data),
    })
}

/// Write with an index range: replaces the elements `lo..=hi` of a String
/// or ByteString cell (configured variables are scalars, so these are the
/// only values with elements). Rare: kept off the hot path.
#[cold]
fn write_range(cell: &ValueCell, range: &str, dv: &DataValue, now: i64) -> Result<(), u32> {
    let (lo, hi) = match parse_range(range) {
        Ok(r) => r,
        Err(true) => return Err(status::BAD_INDEX_RANGE_INVALID),
        Err(false) => return Err(status::BAD_INDEX_RANGE_NO_DATA),
    };
    let cur = cell.read().value;
    let new = dv.value.as_ref().ok_or(status::BAD_TYPE_MISMATCH)?;
    let value = splice_range(&cur, (lo, hi), new)?;
    cell.write(&value, dv.status.unwrap_or(status::GOOD), dv.source_timestamp.unwrap_or(now), now);
    Ok(())
}

/// `cur` with its elements `lo..=hi` replaced by those of `new`, which must
/// have exactly that many (Part 4 §5.10.4).
pub fn splice_range(cur: &Variant, (lo, hi): (usize, usize), new: &Variant) -> Result<Variant, u32> {
    fn splice<T: Clone>(cur: &[T], lo: usize, hi: usize, new: &[T]) -> Result<Vec<T>, u32> {
        if hi >= cur.len() {
            return Err(status::BAD_INDEX_RANGE_NO_DATA);
        }
        if new.len() != hi - lo + 1 {
            return Err(status::BAD_INDEX_RANGE_INVALID);
        }
        let mut out = cur.to_vec();
        out[lo..=hi].clone_from_slice(new);
        Ok(out)
    }
    match (cur, new) {
        (Variant::String(Some(c)), Variant::String(Some(n))) => {
            let c: Vec<char> = c.chars().collect();
            let n: Vec<char> = n.chars().collect();
            Ok(Variant::String(Some(splice(&c, lo, hi, &n)?.into_iter().collect::<String>().into())))
        }
        (Variant::ByteString(Some(c)), Variant::ByteString(Some(n))) => {
            Ok(Variant::ByteString(Some(splice(c, lo, hi, n)?.into())))
        }
        (Variant::String(_) | Variant::ByteString(_), _) => Err(status::BAD_TYPE_MISMATCH),
        _ => Err(status::BAD_INDEX_RANGE_NO_DATA),
    }
}

/// Read with an index range (rare: kept off the hot path).
#[cold]
fn read_range(
    w: &mut Writer,
    space: &AddressSpace,
    node: &Node,
    attribute: u32,
    range: &str,
    ts: Timestamps,
    can_write: bool,
) {
    let range = match parse_range(range) {
        Ok(r) => r,
        Err(true) => return write_bad(w, status::BAD_INDEX_RANGE_INVALID),
        Err(false) => return write_bad(w, status::BAD_INDEX_RANGE_NO_DATA),
    };
    let dv = match (attribute, &node.kind) {
        (attr::VALUE, NodeKind::Variable { value, access, .. }) => {
            if access & ACCESS_READ == 0 {
                return write_bad(w, status::BAD_NOT_READABLE);
            }
            match value {
                ValueSource::Cell(c) => c.to_data_value(),
                ValueSource::Static(v) => DataValue::value(v.clone()),
                ValueSource::CurrentTime => DataValue::value(Variant::DateTime(now_ticks())),
                ValueSource::ServerStatus => DataValue::value(encode_server_status(&space.info)),
                ValueSource::Diagnostics(i) => DataValue::value(space.info.diagnostics.value(*i)),
            }
        }
        _ => match attribute_value(node, attribute, can_write) {
            Some(v) => DataValue::value(v),
            None => return write_bad(w, status::BAD_ATTRIBUTE_ID_INVALID),
        },
    };
    let value = match dv.value.as_ref().map(|v| apply_range(v, range)) {
        Some(Ok(v)) => v,
        Some(Err(code)) => return write_bad(w, code),
        None => return write_bad(w, status::BAD_INDEX_RANGE_NO_DATA),
    };
    let now = now_ticks();
    w.data_value(&DataValue {
        value: Some(value),
        status: dv.status.filter(|&s| s != status::GOOD),
        source_timestamp: if ts.source { dv.source_timestamp } else { None },
        server_timestamp: if ts.server { Some(dv.server_timestamp.unwrap_or(now)) } else { None },
        ..Default::default()
    });
}

/// Value of an attribute other than Value; `None` if the node class does
/// not have it.
pub fn attribute_value(node: &Node, attribute: u32, can_write: bool) -> Option<Variant> {
    use attr::*;
    Some(match (attribute, &node.kind) {
        (NODE_ID, _) => Variant::NodeId(Box::new(node.id.clone())),
        (NODE_CLASS, _) => Variant::Int32(node.class() as i32),
        (BROWSE_NAME, _) => Variant::QualifiedName(Box::new(node.browse_name.clone())),
        (DISPLAY_NAME, _) => Variant::LocalizedText(Box::new(node.display_name.clone())),
        (DESCRIPTION, _) => Variant::LocalizedText(Box::new(node.description.clone()?)),
        (WRITE_MASK | USER_WRITE_MASK, _) => Variant::UInt32(0),
        (IS_ABSTRACT, NodeKind::ObjectType { is_abstract })
        | (IS_ABSTRACT, NodeKind::VariableType { is_abstract, .. })
        | (IS_ABSTRACT, NodeKind::DataType { is_abstract })
        | (IS_ABSTRACT, NodeKind::ReferenceType { is_abstract, .. }) => Variant::Boolean(*is_abstract),
        (SYMMETRIC, NodeKind::ReferenceType { symmetric, .. }) => Variant::Boolean(*symmetric),
        (INVERSE_NAME, NodeKind::ReferenceType { inverse_name: Some(n), .. }) => {
            Variant::LocalizedText(Box::new(n.clone()))
        }
        (EVENT_NOTIFIER, NodeKind::Object { event_notifier }) => Variant::Byte(*event_notifier),
        (DATA_TYPE, NodeKind::Variable { data_type, .. }) | (DATA_TYPE, NodeKind::VariableType { data_type, .. }) => {
            Variant::NodeId(Box::new(data_type.clone()))
        }
        (VALUE_RANK, NodeKind::Variable { value_rank, .. })
        | (VALUE_RANK, NodeKind::VariableType { value_rank, .. }) => Variant::Int32(*value_rank),
        (ARRAY_DIMENSIONS, NodeKind::Variable { value_rank, .. }) if *value_rank >= 1 => {
            Variant::Array(Box::new(VariantArray {
                type_id: builtin::UINT32,
                items: vec![Variant::UInt32(0); *value_rank as usize],
                dims: None,
            }))
        }
        (ACCESS_LEVEL, NodeKind::Variable { access, .. }) => Variant::Byte(*access),
        (USER_ACCESS_LEVEL, NodeKind::Variable { access, .. }) => {
            let mask = ACCESS_WRITE | crate::history::ACCESS_HISTORY_WRITE;
            Variant::Byte(if can_write { *access } else { *access & !mask })
        }
        (ACCESS_LEVEL_EX, NodeKind::Variable { access, .. }) => Variant::UInt32(*access as u32),
        (MINIMUM_SAMPLING_INTERVAL, NodeKind::Variable { .. }) => Variant::Double(0.0),
        (HISTORIZING, NodeKind::Variable { access, .. }) => {
            Variant::Boolean(access & crate::history::ACCESS_HISTORY_READ != 0)
        }
        (EXECUTABLE, NodeKind::Method { executable }) | (USER_EXECUTABLE, NodeKind::Method { executable }) => {
            Variant::Boolean(*executable)
        }
        _ => return None,
    })
}

fn read(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let can_write = session_ref(ctx, h, true)?.can_write.load(Ordering::Relaxed);
    let max_age = r.f64().map_err(decode_err)?;
    let ttr = r.u32().map_err(decode_err)?;
    if max_age.is_nan() || max_age < 0.0 {
        return Err(status::BAD_MAX_AGE_INVALID);
    }
    let ts = match ttr {
        0 => Timestamps { source: true, server: false },
        1 => Timestamps { source: false, server: true },
        2 => Timestamps { source: true, server: true },
        3 => Timestamps { source: false, server: false },
        _ => return Err(status::BAD_TIMESTAMPS_TO_RETURN_INVALID),
    };
    // Minimum encoded sizes: NodeId 2, UInt32 4, String 4, QualifiedName 6.
    let n = r.length(16).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;

    let space = ctx.server.store.cached(ctx.space);
    begin(w, ids::READ_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let (id, attribute, range, enc_name) = match r.numeric_value_id(true) {
            Some((id, attribute)) => (id, attribute, None, None),
            None => {
                let id = r.node_id().map_err(decode_err)?;
                let attribute = r.u32().map_err(decode_err)?;
                let range = r.str().map_err(decode_err)?;
                let (_, enc_name) = r.qualified_name_ref().map_err(decode_err)?;
                (id, attribute, range, enc_name)
            }
        };
        let Some(node) = space.get(&id) else {
            write_bad(w, status::BAD_NODE_ID_UNKNOWN);
            continue;
        };
        if let Some(range) = range.filter(|s| !s.is_empty()) {
            read_range(w, space, node, attribute, range, ts, can_write);
            continue;
        }
        if enc_name.is_some_and(|s| !s.is_empty()) {
            let bad = if attribute == attr::VALUE {
                status::BAD_DATA_ENCODING_UNSUPPORTED
            } else {
                status::BAD_DATA_ENCODING_INVALID
            };
            write_bad(w, bad);
            continue;
        }
        write_attribute(w, space, node, attribute, ts, can_write);
    }
    w.empty_array(); // diagnosticInfos
    Ok(())
}

fn write(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let can_write = session_ref(ctx, h, true)?.can_write.load(Ordering::Relaxed);
    let n = r.length(11).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let space = ctx.server.store.cached(ctx.space);
    let now = now_ticks(); // server timestamp of the written values
    begin(w, ids::WRITE_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let id = r.node_id().map_err(decode_err)?;
        let attribute = r.u32().map_err(decode_err)?;
        let range = r.str().map_err(decode_err)?;
        let dv = r.data_value().map_err(decode_err)?;
        let code = (|| {
            let node = space.get(&id).ok_or(status::BAD_NODE_ID_UNKNOWN)?;
            if attribute == 0 || attribute > attr::ACCESS_LEVEL_EX {
                return Err(status::BAD_ATTRIBUTE_ID_INVALID);
            }
            let NodeKind::Variable { access, value, .. } = &node.kind else {
                return Err(if attribute == attr::VALUE {
                    status::BAD_ATTRIBUTE_ID_INVALID
                } else {
                    status::BAD_NOT_WRITABLE
                });
            };
            if attribute != attr::VALUE {
                return Err(status::BAD_NOT_WRITABLE);
            }
            if access & ACCESS_WRITE == 0 {
                return Err(status::BAD_NOT_WRITABLE);
            }
            if !can_write {
                return Err(status::BAD_USER_ACCESS_DENIED);
            }
            let ValueSource::Cell(cell) = value else {
                return Err(status::BAD_NOT_WRITABLE);
            };
            if dv.server_timestamp.is_some() {
                return Err(status::BAD_WRITE_NOT_SUPPORTED);
            }
            if let Some(range) = range.filter(|s| !s.is_empty()) {
                return write_range(cell, range, &dv, now);
            }
            let v = dv.value.as_ref().ok_or(status::BAD_TYPE_MISMATCH)?;
            if matches!(v, Variant::Array(_)) || v.type_id() != cell.kind() {
                return Err(status::BAD_TYPE_MISMATCH);
            }
            if matches!(v, Variant::String(None) | Variant::ByteString(None)) {
                return Err(status::BAD_TYPE_MISMATCH);
            }
            cell.write(v, dv.status.unwrap_or(status::GOOD), dv.source_timestamp.unwrap_or(now), now);
            Ok(())
        })();
        w.u32(code.err().unwrap_or(status::GOOD));
    }
    w.empty_array();
    Ok(())
}

// ---------------------------------------------------------------- View

#[derive(Clone, Copy)]
struct BrowseSpec {
    direction: u32,
    ref_type: u32,
    include_subtypes: bool,
    class_mask: u32,
    result_mask: u32,
}

impl BrowseSpec {
    #[inline]
    fn matches(&self, space: &AddressSpace, r: &Ref) -> bool {
        let dir_ok = match self.direction {
            0 => r.forward,
            1 => !r.forward,
            _ => true,
        };
        dir_ok
            && ref_type_matches(r.type_id, self.ref_type, self.include_subtypes)
            && (self.class_mask == 0 || self.class_mask & space.node(r.target).class() as u32 != 0)
    }
}

fn write_reference(w: &mut Writer, space: &AddressSpace, r: &Ref, mask: u32) {
    let target = space.node(r.target);
    if mask & 0x01 != 0 {
        w.node_id(&NodeId::ns0(r.type_id));
    } else {
        w.node_id(&NodeId::NULL);
    }
    w.bool(mask & 0x02 != 0 && r.forward);
    w.local_expanded_node_id(&target.id);
    if mask & 0x08 != 0 {
        w.qualified_name(&target.browse_name);
    } else {
        w.u16(0);
        w.str(None);
    }
    if mask & 0x10 != 0 {
        w.localized_text(&target.display_name);
    } else {
        w.u8(0);
    }
    w.i32(if mask & 0x04 != 0 { target.class() as i32 } else { 0 });
    let td = if mask & 0x20 != 0 && matches!(target.class(), NodeClass::Object | NodeClass::Variable) {
        target.type_definition().map(|t| &space.node(t).id)
    } else {
        None
    };
    w.local_expanded_node_id(td.unwrap_or(&NodeId::NULL));
}

/// Writes references of `node` starting at `from` into `scratch`.
/// Returns (count, resume index if more matching references remain).
fn browse_refs(
    space: &AddressSpace,
    node: u32,
    spec: &BrowseSpec,
    from: usize,
    max: usize,
    scratch: &mut Vec<u8>,
) -> (usize, Option<usize>) {
    let refs = &space.node(node).refs;
    let mut w = Writer::new(scratch);
    let mut count = 0;
    for (i, r) in refs.iter().enumerate().skip(from) {
        if !spec.matches(space, r) {
            continue;
        }
        if count == max {
            return (count, Some(i));
        }
        write_reference(&mut w, space, r, spec.result_mask);
        count += 1;
    }
    (count, None)
}

/// Encodes one BrowseResult, creating a continuation point when needed.
#[allow(clippy::too_many_arguments)]
fn browse_one(
    w: &mut Writer,
    session: &Session,
    space: &Arc<AddressSpace>,
    node: u32,
    spec: BrowseSpec,
    from: usize,
    max: usize,
    scratch: &mut Vec<u8>,
    limit_cps: usize,
) {
    scratch.clear();
    let (count, more) = browse_refs(space, node, &spec, from, max, scratch);
    let mut cp_id = None;
    if let Some(next_ref) = more {
        let mut cps = session.continuation_points.lock().unwrap_or_else(|e| e.into_inner());
        if cps.len() >= limit_cps {
            write_browse_error(w, status::BAD_NO_CONTINUATION_POINTS);
            return;
        }
        let mut id = [0u8; 16];
        random_bytes(&mut id);
        cps.push(ContinuationPoint {
            id,
            space: space.clone(),
            node,
            direction: spec.direction,
            ref_type: spec.ref_type,
            include_subtypes: spec.include_subtypes,
            class_mask: spec.class_mask,
            result_mask: spec.result_mask,
            max_refs: max,
            next_ref,
        });
        cp_id = Some(id);
    }
    w.u32(status::GOOD);
    w.bytes(cp_id.as_ref().map(|c| &c[..]));
    w.i32(count as i32);
    w.raw(scratch);
}

#[inline]
fn write_browse_error(w: &mut Writer, code: u32) {
    w.u32(code);
    w.bytes(None);
    w.empty_array();
}

fn browse(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let view_id = r.node_id().map_err(decode_err)?;
    let _view_ts = r.i64().map_err(decode_err)?;
    let _view_version = r.u32().map_err(decode_err)?;
    if !view_id.is_null() {
        return Err(status::BAD_VIEW_ID_UNKNOWN);
    }
    let requested_max = r.u32().map_err(decode_err)? as usize;
    let n = r.length(17).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let limits = ctx.server.limits();
    let max = if requested_max == 0 {
        limits.max_references_per_browse
    } else {
        requested_max.min(limits.max_references_per_browse)
    };
    let space = ctx.server.store.load_full();
    let mut scratch = Vec::with_capacity(1024);
    begin(w, ids::BROWSE_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let id = r.node_id().map_err(decode_err)?;
        let direction = r.u32().map_err(decode_err)?;
        let ref_type_id = r.node_id().map_err(decode_err)?;
        let include_subtypes = r.bool().map_err(decode_err)?;
        let class_mask = r.u32().map_err(decode_err)?;
        let result_mask = r.u32().map_err(decode_err)?;
        let Some(node) = space.find(&id) else {
            write_browse_error(w, status::BAD_NODE_ID_UNKNOWN);
            continue;
        };
        if direction > 2 {
            write_browse_error(w, status::BAD_BROWSE_DIRECTION_INVALID);
            continue;
        }
        let ref_type = if ref_type_id.is_null() {
            0
        } else {
            match ref_type_id.as_ns0() {
                Some(t) if is_known_ref_type(t) => t,
                _ => {
                    write_browse_error(w, status::BAD_REFERENCE_TYPE_ID_INVALID);
                    continue;
                }
            }
        };
        let spec = BrowseSpec { direction, ref_type, include_subtypes, class_mask, result_mask };
        browse_one(w, &s, &space, node, spec, 0, max, &mut scratch, limits.max_browse_continuation_points);
    }
    w.empty_array();
    Ok(())
}

fn browse_next(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let release = r.bool().map_err(decode_err)?;
    let n = r.length(4).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let limit_cps = ctx.server.limits().max_browse_continuation_points;
    let mut scratch = Vec::with_capacity(1024);
    begin(w, ids::BROWSE_NEXT_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let id = r.bytes().map_err(decode_err)?.unwrap_or(&[]);
        let cp = {
            let mut cps = s.continuation_points.lock().unwrap_or_else(|e| e.into_inner());
            cps.iter().position(|c| c.id[..] == *id).map(|i| cps.swap_remove(i))
        };
        let Some(cp) = cp else {
            write_browse_error(w, status::BAD_CONTINUATION_POINT_INVALID);
            continue;
        };
        if release {
            write_browse_error(w, status::GOOD);
            continue;
        }
        let spec = BrowseSpec {
            direction: cp.direction,
            ref_type: cp.ref_type,
            include_subtypes: cp.include_subtypes,
            class_mask: cp.class_mask,
            result_mask: cp.result_mask,
        };
        browse_one(w, &s, &cp.space, cp.node, spec, cp.next_ref, cp.max_refs, &mut scratch, limit_cps);
    }
    w.empty_array();
    Ok(())
}

fn translate(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    session(ctx, h, true)?;
    let n = r.length(6).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let space = ctx.server.store.cached(ctx.space);
    begin(w, ids::TRANSLATE_BROWSE_PATHS_RESPONSE, h);
    w.i32(n as i32);
    let mut current: Vec<u32> = Vec::new();
    let mut next: Vec<u32> = Vec::new();
    for _ in 0..n {
        let start = r.node_id().map_err(decode_err)?;
        let elements = r
            .array(10, |r| {
                let rt = r.node_id()?;
                let inverse = r.bool()?;
                let subtypes = r.bool()?;
                let name = r.qualified_name()?;
                Ok((rt, inverse, subtypes, name))
            })
            .map_err(decode_err)?;
        let fail = |w: &mut Writer, code: u32| {
            w.u32(code);
            w.empty_array();
        };
        let Some(start) = space.find(&start) else {
            fail(w, status::BAD_NODE_ID_UNKNOWN);
            continue;
        };
        if elements.is_empty() {
            fail(w, status::BAD_NOTHING_TO_DO);
            continue;
        }
        if elements.iter().any(|e| e.3.name.is_empty()) {
            fail(w, status::BAD_BROWSE_NAME_INVALID);
            continue;
        }
        current.clear();
        current.push(start);
        let mut bad_ref = false;
        for (rt, inverse, subtypes, name) in &elements {
            let (ref_type, subtypes) = if rt.is_null() {
                (ids::REFERENCES, true)
            } else {
                match rt.as_ns0() {
                    Some(t) if is_known_ref_type(t) => (t, *subtypes),
                    _ => {
                        bad_ref = true;
                        break;
                    }
                }
            };
            next.clear();
            for &c in &current {
                for rf in &space.node(c).refs {
                    if rf.forward != *inverse
                        && ref_type_matches(rf.type_id, ref_type, subtypes)
                        && space.node(rf.target).browse_name == *name
                        && !next.contains(&rf.target)
                    {
                        next.push(rf.target);
                    }
                }
            }
            std::mem::swap(&mut current, &mut next);
            if current.is_empty() {
                break;
            }
        }
        if bad_ref {
            fail(w, status::BAD_REFERENCE_TYPE_ID_INVALID);
        } else if current.is_empty() {
            fail(w, status::BAD_NO_MATCH);
        } else {
            w.u32(status::GOOD);
            w.i32(current.len() as i32);
            for &t in &current {
                w.local_expanded_node_id(&space.node(t).id);
                w.u32(u32::MAX);
            }
        }
    }
    w.empty_array();
    Ok(())
}

fn register_nodes(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    session(ctx, h, true)?;
    let ids_in = r.array(2, |r| r.node_id()).map_err(decode_err)?;
    check_count(ctx, ids_in.len())?;
    begin(w, ids::REGISTER_NODES_RESPONSE, h);
    w.i32(ids_in.len() as i32);
    for id in &ids_in {
        w.node_id(id);
    }
    Ok(())
}

fn unregister_nodes(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    session(ctx, h, true)?;
    let n = r.array(2, |r| r.node_id()).map_err(decode_err)?.len();
    check_count(ctx, n)?;
    begin(w, ids::UNREGISTER_NODES_RESPONSE, h);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(token: &NodeId, audit: Option<&str>, extra: bool) -> Vec<u8> {
        let mut b = Vec::new();
        let mut w = Writer::new(&mut b);
        w.node_id(token);
        w.i64(123);
        w.u32(0xDEAD_BEEF);
        w.u32(7);
        w.str(audit);
        w.u32(5000);
        if extra {
            w.node_id(&NodeId::ns0(1));
            w.u8(1);
            w.bytes(Some(&[1, 2, 3]));
        } else {
            w.null_extension_object();
        }
        w.u8(0xAA);
        b
    }

    /// The fixed-layout fast path and the generic decoder agree, and the
    /// fast path is not taken for other layouts.
    #[test]
    fn request_header_fast_path() {
        let guid = NodeId::Guid(1, [9; 16]);
        for (token, audit, extra) in [
            (&guid, None, false),
            (&guid, Some("audit"), false),
            (&guid, None, true),
            (&NodeId::Opaque(1, vec![1; 32].into()), None, false),
            (&NodeId::Numeric(1, 2), None, false),
        ] {
            let b = header(token, audit, extra);
            let mut r = Reader::new(&b);
            let h = RequestHeader::decode(&mut r).unwrap();
            assert_eq!(&h.auth_token, token);
            assert_eq!((h.handle, h.return_diagnostics, h.timeout_hint), (0xDEAD_BEEF, 7, 5000));
            assert_eq!(r.u8().unwrap(), 0xAA, "decoder stops at the end of the header");
        }
        let b = header(&guid, None, false);
        assert!(RequestHeader::decode(&mut Reader::new(&b[..40])).is_err());
    }
}
