//! Service handlers (Part 4). Responses are encoded straight into the
//! connection's transmit buffer: no intermediate response structs.

use crate::address_space::*;
use crate::codec::{DResult, Reader, Writer};
use crate::server::{random_bytes, ContinuationPoint, Server, Session, ANONYMOUS_POLICY_ID, TRANSPORT_PROFILE_BINARY};
use crate::types::*;
use crate::value::ValueCell;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub struct Ctx<'a> {
    pub server: &'a Arc<Server>,
    pub channel_id: u32,
    /// Last session used on this connection: avoids the global table lookup.
    pub session: &'a mut Option<Arc<Session>>,
}

pub struct RequestHeader {
    pub auth_token: NodeId,
    pub handle: u32,
    pub return_diagnostics: u32,
    pub timeout_hint: u32,
}

impl RequestHeader {
    pub fn decode(r: &mut Reader) -> DResult<RequestHeader> {
        let auth_token = r.node_id()?;
        let _timestamp = r.i64()?;
        let handle = r.u32()?;
        let return_diagnostics = r.u32()?;
        let _audit = r.str()?;
        let timeout_hint = r.u32()?;
        let _additional = r.extension_object_raw()?;
        Ok(RequestHeader { auth_token, handle, return_diagnostics, timeout_hint })
    }
}

#[inline]
pub fn write_response_header(w: &mut Writer, handle: u32, result: u32) {
    w.i64(now_ticks());
    w.u32(handle);
    w.u32(result);
    w.empty_diagnostic_info();
    w.null_array(); // stringTable
    w.null_extension_object();
}

#[inline]
fn begin(w: &mut Writer, response_type: u32, handle: u32) {
    w.node_id(&NodeId::ns0(response_type));
    write_response_header(w, handle, status::GOOD);
}

pub fn write_fault(w: &mut Writer, handle: u32, code: u32) {
    w.node_id(&NodeId::ns0(ids::SERVICE_FAULT));
    write_response_header(w, handle, code);
}

type SResult = Result<(), u32>;

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
        _ => Err(status::BAD_SERVICE_UNSUPPORTED),
    };
    if let Err(code) = result {
        w.buf.truncate(start);
        write_fault(w, handle, code);
    }
    handle
}

fn decode_err(_: crate::codec::DecodeError) -> u32 {
    status::BAD_DECODING_ERROR
}

/// Resolves and validates the session of a request (Part 4 §5.6).
fn session(ctx: &mut Ctx, header: &RequestHeader, must_be_active: bool) -> Result<Arc<Session>, u32> {
    let s = match ctx.session.as_ref() {
        Some(s) if s.token == header.auth_token => s.clone(),
        _ => {
            let s = ctx.server.find_session(&header.auth_token).ok_or(status::BAD_SESSION_ID_INVALID)?;
            *ctx.session = Some(s.clone());
            s
        }
    };
    if s.closed.load(Ordering::Acquire) {
        *ctx.session = None;
        return Err(status::BAD_SESSION_ID_INVALID);
    }
    if must_be_active {
        if !s.activated.load(Ordering::Acquire) {
            return Err(status::BAD_SESSION_NOT_ACTIVATED);
        }
        if s.channel_id.load(Ordering::Acquire) != ctx.channel_id {
            return Err(status::BAD_SECURE_CHANNEL_ID_INVALID);
        }
    }
    s.last_seen.store(ctx.server.uptime_ms(), Ordering::Relaxed);
    Ok(s)
}

fn check_count(ctx: &Ctx, n: usize) -> SResult {
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
    begin(w, ids::GET_ENDPOINTS_RESPONSE, h.handle);
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
    begin(w, ids::FIND_SERVERS_RESPONSE, h.handle);
    let own = ctx.server.store.info().application_uri.as_str();
    if uris.is_empty() || uris.contains(&Some(own)) {
        w.raw(ctx.server.application_encoded());
    } else {
        w.empty_array();
    }
    Ok(())
}

// ---------------------------------------------------------------- Sessions

fn skip_application_description(r: &mut Reader) -> DResult<()> {
    r.str()?;
    r.str()?;
    r.localized_text()?;
    r.i32()?;
    r.str()?;
    r.str()?;
    r.skip_string_array()
}

fn create_session(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let mut parse = || -> DResult<(String, f64)> {
        skip_application_description(r)?;
        let _server_uri = r.str()?;
        let _endpoint_url = r.str()?;
        let name = r.str()?.unwrap_or("").to_string();
        let _client_nonce = r.bytes()?;
        let _client_cert = r.bytes()?;
        let timeout = r.f64()?;
        let _max_response = r.u32()?;
        Ok((name, timeout))
    };
    let (name, requested_timeout) = parse().map_err(decode_err)?;
    let limits = ctx.server.limits();
    let timeout = if requested_timeout.is_finite() && requested_timeout > 0.0 {
        requested_timeout.clamp(limits.min_session_timeout_ms, limits.max_session_timeout_ms)
    } else {
        60_000.0
    };
    let session = ctx.server.create_session(name, ctx.channel_id, timeout)?;
    let mut nonce = [0u8; 32];
    random_bytes(&mut nonce);

    begin(w, ids::CREATE_SESSION_RESPONSE, h.handle);
    w.node_id(&session.id);
    w.node_id(&session.token);
    w.f64(timeout);
    w.bytes(Some(&nonce));
    w.bytes(None); // server certificate
    w.raw(ctx.server.endpoints_encoded());
    w.empty_array(); // serverSoftwareCertificates
    w.str(None); // signature algorithm
    w.bytes(None); // signature
    w.u32(limits.max_message_size);
    crate::log!("session '{}' ({}) created", session.name, session.id);
    *ctx.session = Some(session);
    Ok(())
}

fn activate_session(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, false)?;
    let mut parse = || -> DResult<(NodeId, Option<String>)> {
        r.str()?; // client signature algorithm
        r.bytes()?; // client signature
        let n = r.length(1)?.unwrap_or(0);
        for _ in 0..n {
            r.bytes()?;
            r.bytes()?;
        }
        r.skip_string_array()?; // localeIds
        let (type_id, enc, body) = r.extension_object_raw()?;
        let policy = if enc == 1 { Reader::new(body).str()?.map(str::to_string) } else { None };
        Ok((type_id, policy))
    };
    let (token_type, policy) = parse().map_err(decode_err)?;

    // Only anonymous identities are accepted until encrypted channels land:
    // a password over SecurityPolicy None would travel in clear text.
    let anonymous = match token_type.as_ns0() {
        Some(0) => true,
        Some(ids::ANONYMOUS_IDENTITY_TOKEN_ENCODING) => {
            policy.as_deref().is_none_or(|p| p == ANONYMOUS_POLICY_ID || p.is_empty())
        }
        Some(ids::USERNAME_IDENTITY_TOKEN_ENCODING) | Some(ids::X509_IDENTITY_TOKEN_ENCODING) => {
            return Err(status::BAD_IDENTITY_TOKEN_REJECTED)
        }
        _ => false,
    };
    if !anonymous {
        return Err(status::BAD_IDENTITY_TOKEN_INVALID);
    }
    // Activation may move the session to the calling channel (Part 4 §5.6.3).
    s.channel_id.store(ctx.channel_id, Ordering::Release);
    s.activated.store(true, Ordering::Release);

    let mut nonce = [0u8; 32];
    random_bytes(&mut nonce);
    begin(w, ids::ACTIVATE_SESSION_RESPONSE, h.handle);
    w.bytes(Some(&nonce));
    w.empty_array(); // results
    w.empty_array(); // diagnosticInfos
    Ok(())
}

fn close_session(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, false)?;
    let _delete_subscriptions = r.bool().map_err(decode_err)?;
    if s.channel_id.load(Ordering::Acquire) != ctx.channel_id {
        return Err(status::BAD_SECURE_CHANNEL_ID_INVALID);
    }
    ctx.server.remove_session(&s.token);
    *ctx.session = None;
    crate::log!("session '{}' ({}) closed", s.name, s.id);
    begin(w, ids::CLOSE_SESSION_RESPONSE, h.handle);
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
fn write_attr(w: &mut Writer, v: &Variant, ts: Timestamps, now: i64) {
    w.u8(0x01 | if ts.server { 0x08 } else { 0 });
    w.variant(v);
    if ts.server {
        w.i64(now);
    }
}

#[inline]
fn write_cell(w: &mut Writer, cell: &ValueCell, ts: Timestamps) {
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
fn write_value(w: &mut Writer, space: &AddressSpace, src: &ValueSource, ts: Timestamps, now: i64) {
    match src {
        ValueSource::Cell(c) => write_cell(w, c, ts),
        ValueSource::Static(v) => write_dynamic(w, v, ts, now),
        ValueSource::CurrentTime => write_dynamic(w, &Variant::DateTime(now), ts, now),
        ValueSource::ServerStatus => write_dynamic(w, &encode_server_status(&space.info), ts, now),
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

fn write_attribute(w: &mut Writer, space: &AddressSpace, node: &Node, attribute: u32, ts: Timestamps, now: i64) {
    use attr::*;
    let v = match (attribute, &node.kind) {
        (VALUE, NodeKind::Variable { value, access, .. }) => {
            if access & ACCESS_READ == 0 {
                return write_bad(w, status::BAD_NOT_READABLE);
            }
            return write_value(w, space, value, ts, now);
        }
        (NODE_ID, _) => Variant::NodeId(Box::new(node.id.clone())),
        (NODE_CLASS, _) => Variant::Int32(node.class() as i32),
        (BROWSE_NAME, _) => Variant::QualifiedName(Box::new(node.browse_name.clone())),
        (DISPLAY_NAME, _) => Variant::LocalizedText(Box::new(node.display_name.clone())),
        (DESCRIPTION, _) => match &node.description {
            Some(d) => Variant::LocalizedText(Box::new(d.clone())),
            None => return write_bad(w, status::BAD_ATTRIBUTE_ID_INVALID),
        },
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
        (ACCESS_LEVEL | USER_ACCESS_LEVEL, NodeKind::Variable { access, .. }) => Variant::Byte(*access),
        (ACCESS_LEVEL_EX, NodeKind::Variable { access, .. }) => Variant::UInt32(*access as u32),
        (MINIMUM_SAMPLING_INTERVAL, NodeKind::Variable { .. }) => Variant::Double(0.0),
        (HISTORIZING, NodeKind::Variable { .. }) => Variant::Boolean(false),
        _ => return write_bad(w, status::BAD_ATTRIBUTE_ID_INVALID),
    };
    write_attr(w, &v, ts, now);
}

fn read(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    session(ctx, h, true)?;
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

    let space = ctx.server.store.load();
    let now = now_ticks();
    begin(w, ids::READ_RESPONSE, h.handle);
    w.i32(n as i32);
    for _ in 0..n {
        let id = r.node_id().map_err(decode_err)?;
        let attribute = r.u32().map_err(decode_err)?;
        let range = r.str().map_err(decode_err)?;
        let enc = r.qualified_name().map_err(decode_err)?;
        let Some(node) = space.get(&id) else {
            write_bad(w, status::BAD_NODE_ID_UNKNOWN);
            continue;
        };
        if range.is_some_and(|s| !s.is_empty()) {
            // Index ranges are only meaningful on arrays / strings; the
            // configured variables are scalars.
            write_bad(w, status::BAD_INDEX_RANGE_INVALID);
            continue;
        }
        if !enc.name.is_empty() {
            let bad = if attribute == attr::VALUE {
                status::BAD_DATA_ENCODING_UNSUPPORTED
            } else {
                status::BAD_DATA_ENCODING_INVALID
            };
            write_bad(w, bad);
            continue;
        }
        write_attribute(w, &space, node, attribute, ts, now);
    }
    w.empty_array(); // diagnosticInfos
    Ok(())
}

fn write(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    session(ctx, h, true)?;
    let n = r.length(11).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let space = ctx.server.store.load();
    let now = now_ticks();
    begin(w, ids::WRITE_RESPONSE, h.handle);
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
            if range.is_some_and(|s| !s.is_empty()) {
                return Err(status::BAD_INDEX_RANGE_INVALID);
            }
            let ValueSource::Cell(cell) = value else {
                return Err(status::BAD_NOT_WRITABLE);
            };
            if dv.server_timestamp.is_some() {
                return Err(status::BAD_WRITE_NOT_SUPPORTED);
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
    begin(w, ids::BROWSE_RESPONSE, h.handle);
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
    begin(w, ids::BROWSE_NEXT_RESPONSE, h.handle);
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
    let space = ctx.server.store.load();
    begin(w, ids::TRANSLATE_BROWSE_PATHS_RESPONSE, h.handle);
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
    begin(w, ids::REGISTER_NODES_RESPONSE, h.handle);
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
    begin(w, ids::UNREGISTER_NODES_RESPONSE, h.handle);
    Ok(())
}
