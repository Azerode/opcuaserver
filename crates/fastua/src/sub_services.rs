//! Subscription and MonitoredItem service handlers (Part 4 §5.12, §5.13).
//! The state machines live in [`crate::subscription`].

use super::*;
use crate::events::{codes::BAD_EVENT_FILTER_INVALID, EventFilter, FilterResult};
use crate::subscription::{codes::*, mono_ns, Filter, ItemParams, PublishRequest, SubParams, Subscription};
use std::sync::MutexGuard;

fn lock(s: &Session) -> MutexGuard<'_, crate::subscription::SessionSubs> {
    s.subs.lock().unwrap_or_else(|e| e.into_inner())
}

fn timestamps(ttr: u32) -> Result<(bool, bool), u32> {
    match ttr {
        0 => Ok((true, false)),
        1 => Ok((false, true)),
        2 => Ok((true, true)),
        3 => Ok((false, false)),
        _ => Err(status::BAD_TIMESTAMPS_TO_RETURN_INVALID),
    }
}

fn read_ids(ctx: &Ctx, r: &mut Reader) -> Result<Vec<u32>, u32> {
    let ids = r.array(4, |r| r.u32()).map_err(decode_err)?;
    check_count(ctx, ids.len())?;
    Ok(ids)
}

fn write_codes(w: &mut Writer, codes: impl ExactSizeIterator<Item = u32>) {
    w.i32(codes.len() as i32);
    for c in codes {
        w.u32(c);
    }
    w.empty_array(); // diagnosticInfos
}

// ---------------------------------------------------------------- Subscription set

pub(super) fn create_subscription(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let mut parse = || -> DResult<(f64, u32, u32, u32, bool, u8)> {
        Ok((r.f64()?, r.u32()?, r.u32()?, r.u32()?, r.bool()?, r.u8()?))
    };
    let (interval, lifetime, keepalive, max_notif, enabled, priority) = parse().map_err(decode_err)?;
    let l = ctx.server.limits();
    let params = SubParams::revise(l, interval, lifetime, keepalive, max_notif, priority);
    let mut st = lock(&s);
    if st.subs.len() >= l.max_subscriptions_per_session {
        return Err(BAD_TOO_MANY_SUBSCRIPTIONS);
    }
    let id = ctx.server.next_subscription_id();
    st.subs.push(Subscription::new(id, params, enabled, mono_ns()));
    drop(st);
    ctx.conn.drive(&s);
    begin(w, ids::CREATE_SUBSCRIPTION_RESPONSE, h);
    w.u32(id);
    w.f64(params.interval_ms);
    w.u32(params.lifetime);
    w.u32(params.keepalive);
    Ok(())
}

pub(super) fn modify_subscription(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let mut parse = || -> DResult<(u32, f64, u32, u32, u32, u8)> {
        Ok((r.u32()?, r.f64()?, r.u32()?, r.u32()?, r.u32()?, r.u8()?))
    };
    let (id, interval, lifetime, keepalive, max_notif, priority) = parse().map_err(decode_err)?;
    let params = SubParams::revise(ctx.server.limits(), interval, lifetime, keepalive, max_notif, priority);
    lock(&s).find(id).ok_or(BAD_SUBSCRIPTION_ID_INVALID)?.modify(params, mono_ns());
    ctx.conn.timers_dirty = true;
    begin(w, ids::MODIFY_SUBSCRIPTION_RESPONSE, h);
    w.f64(params.interval_ms);
    w.u32(params.lifetime);
    w.u32(params.keepalive);
    Ok(())
}

pub(super) fn set_publishing_mode(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let enabled = r.bool().map_err(decode_err)?;
    let ids = read_ids(ctx, r)?;
    let mut st = lock(&s);
    let codes: Vec<u32> = ids
        .iter()
        .map(|&id| match st.find(id) {
            Some(sub) => {
                sub.publishing_enabled = enabled;
                status::GOOD
            }
            None => BAD_SUBSCRIPTION_ID_INVALID,
        })
        .collect();
    drop(st);
    ctx.conn.timers_dirty = true;
    begin(w, ids::SET_PUBLISHING_MODE_RESPONSE, h);
    write_codes(w, codes.into_iter());
    Ok(())
}

pub(super) fn delete_subscriptions(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let ids = read_ids(ctx, r)?;
    let mut st = lock(&s);
    let codes: Vec<u32> = ids
        .iter()
        .map(|&id| if st.remove(id).is_some() { status::GOOD } else { BAD_SUBSCRIPTION_ID_INVALID })
        .collect();
    drop(st);
    // Queued Publish requests of a session left without subscriptions are
    // answered with Bad_NoSubscription by the connection's next tick.
    ctx.conn.timers_dirty = true;
    begin(w, ids::DELETE_SUBSCRIPTIONS_RESPONSE, h);
    write_codes(w, codes.into_iter());
    Ok(())
}

pub(super) fn transfer_subscriptions(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let ids = read_ids(ctx, r)?;
    let send_initial = r.bool().map_err(decode_err)?;
    let identity = s.identity.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let now = mono_ns();
    begin(w, ids::TRANSFER_SUBSCRIPTIONS_RESPONSE, h);
    w.i32(ids.len() as i32);
    for &id in &ids {
        if let Some(sub) = lock(&s).find(id) {
            // Already ours.
            w.u32(status::GOOD);
            let avail: Vec<u32> = sub.available().collect();
            w.i32(avail.len() as i32);
            avail.iter().for_each(|&q| w.u32(q));
            continue;
        }
        let mut found: Option<Result<Subscription, ()>> = None;
        for other in ctx.server.sessions() {
            if Arc::ptr_eq(&other, &s) {
                continue;
            }
            let mut os = lock(&other);
            if os.subs.iter().any(|x| x.id == id) {
                if *other.identity.lock().unwrap_or_else(|e| e.into_inner()) != identity {
                    found = Some(Err(()));
                } else {
                    let sub = os.remove(id).unwrap();
                    // The old session learns where its subscription went.
                    os.status_change(id, sub.sequence(), GOOD_SUBSCRIPTION_TRANSFERRED);
                    found = Some(Ok(sub));
                }
                break;
            }
        }
        if found.is_none() {
            found = ctx.server.adopt(id, &identity);
        }
        match found {
            Some(Ok(mut sub)) => {
                if send_initial {
                    sub.resend_initial_values();
                }
                sub.reset_timers(now);
                w.u32(status::GOOD);
                let avail: Vec<u32> = sub.available().collect();
                w.i32(avail.len() as i32);
                avail.iter().for_each(|&q| w.u32(q));
                lock(&s).subs.push(sub);
                crate::log!("subscription {id} transferred to session {}", s.id);
            }
            Some(Err(())) => {
                w.u32(status::BAD_USER_ACCESS_DENIED);
                w.empty_array();
            }
            None => {
                w.u32(BAD_SUBSCRIPTION_ID_INVALID);
                w.empty_array();
            }
        }
    }
    w.empty_array(); // diagnosticInfos
    ctx.conn.drive(&s);
    Ok(())
}

// ---------------------------------------------------------------- Publish

pub(super) fn publish(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session_ref(ctx, h, true)?.clone();
    let n = r.length(8).map_err(decode_err)?.unwrap_or(0);
    let l = ctx.server.limits();
    let mut st = lock(&s);
    if st.subs.is_empty() && !st.has_status_changes() {
        return Err(BAD_NO_SUBSCRIPTION);
    }
    // Acknowledgements are processed on arrival (Part 4 §5.13.5.2).
    let mut acks = st.ack_buffer();
    for _ in 0..n {
        let (Ok(sub), Ok(seq)) = (r.u32(), r.u32()) else {
            st.recycle_acks(acks);
            return Err(status::BAD_DECODING_ERROR);
        };
        let code = st.acknowledge(sub, seq);
        acks.push(code);
    }
    let now = mono_ns();
    let deadline = match h.timeout_hint {
        0 => u64::MAX,
        t => now + t as u64 * 1_000_000,
    };
    let req = PublishRequest {
        request_id: ctx.conn.request_id,
        channel_id: ctx.channel_id,
        handle: h.handle,
        deadline,
        acks,
    };
    if let Err((code, req)) = st.queue(l, req) {
        st.recycle_acks(req.acks);
        return Err(code);
    }
    // A late subscription is answered right away, otherwise the request
    // waits for the next publishing cycle.
    match st.write_next(l, now, ctx.channel_id, ctx.conn.max_response, w, false) {
        Some(ready) if ready.request_id != ctx.conn.request_id => ctx.conn.reply_to = Some(ready.request_id),
        Some(_) => {}
        None => ctx.conn.deferred = true,
    }
    drop(st);
    ctx.conn.drive(&s);
    Ok(())
}

pub(super) fn republish(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let id = r.u32().map_err(decode_err)?;
    let seq = r.u32().map_err(decode_err)?;
    let mut st = lock(&s);
    let sub = st.find(id).ok_or(BAD_SUBSCRIPTION_ID_INVALID)?;
    let msg = sub.republish(seq).ok_or(BAD_MESSAGE_NOT_AVAILABLE)?;
    begin(w, ids::REPUBLISH_RESPONSE, h);
    w.raw(msg);
    Ok(())
}

// ---------------------------------------------------------------- MonitoredItem set

/// Filters other than DataChangeFilter.
enum Special {
    None,
    /// A parsed EventFilter and its per clause results.
    Events(EventFilter, FilterResult),
    Aggregate(crate::subscription::AggSpec),
}

/// AggregateFilterResult.
fn write_aggregate_result(w: &mut Writer, (start, interval, config): crate::subscription::AggRevised) {
    let at = w.begin_extension_object(ids::AGGREGATE_FILTER_RESULT_ENCODING);
    w.i64(start);
    w.f64(interval);
    config.encode(w);
    w.end_extension_object(at);
}

/// MonitoringParameters; `Err` is a per-item status for an unusable filter.
fn read_parameters(r: &mut Reader) -> DResult<Result<(ItemParams, Special), u32>> {
    let client_handle = r.u32()?;
    let sampling_ms = r.f64()?;
    let (type_id, enc, body) = r.extension_object_raw()?;
    let queue_size = r.u32()?;
    let discard_oldest = r.bool()?;
    let mut p = ItemParams {
        client_handle,
        sampling_ms,
        filter: Filter::default(),
        percent_deadband: false,
        filter_present: false,
        queue_size,
        discard_oldest,
    };
    match type_id.as_ns0() {
        Some(0) if enc == 0 => {}
        Some(ids::DATA_CHANGE_FILTER_ENCODING) if enc == 1 => {
            let mut b = Reader::new(body);
            let (Ok(trigger), Ok(deadband_type), Ok(deadband)) = (b.u32(), b.u32(), b.f64()) else {
                return Ok(Err(BAD_MONITORED_ITEM_FILTER_INVALID));
            };
            p.filter_present = true;
            p.filter.trigger = trigger;
            match deadband_type {
                0 => {}
                1 => p.filter.deadband = if deadband == 0.0 { 0.0 } else { deadband },
                2 => {
                    if !(0.0..=100.0).contains(&deadband) {
                        return Ok(Err(BAD_DEADBAND_FILTER_INVALID));
                    }
                    p.percent_deadband = true;
                    p.filter.deadband = deadband;
                }
                _ => return Ok(Err(BAD_DEADBAND_FILTER_INVALID)),
            }
            if deadband_type == 1 && !(deadband >= 0.0 && deadband.is_finite()) {
                return Ok(Err(BAD_DEADBAND_FILTER_INVALID));
            }
        }
        Some(ids::EVENT_FILTER_ENCODING) if enc == 1 => {
            let Ok(ef) = crate::events::parse_filter(body) else {
                return Ok(Err(BAD_EVENT_FILTER_INVALID));
            };
            p.filter_present = true;
            return Ok(Ok((p, Special::Events(ef.0, ef.1))));
        }
        Some(ids::AGGREGATE_FILTER_ENCODING) if enc == 1 => {
            let mut b = Reader::new(body);
            let spec = (|| {
                Ok::<_, crate::codec::DecodeError>(crate::subscription::AggSpec {
                    start: b.i64()?,
                    aggregate: b.node_id()?.as_ns0().unwrap_or(0),
                    interval_ms: b.f64()?,
                    config: crate::aggregates::Config::decode(&mut b)?,
                })
            })();
            let Ok(spec) = spec else { return Ok(Err(BAD_MONITORED_ITEM_FILTER_INVALID)) };
            p.filter_present = true;
            return Ok(Ok((p, Special::Aggregate(spec))));
        }
        _ => return Ok(Err(BAD_MONITORED_ITEM_FILTER_INVALID)),
    }
    Ok(Ok((p, Special::None)))
}

pub(super) fn create_monitored_items(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let can_write = s.can_write.load(Ordering::Relaxed);
    let sub_id = r.u32().map_err(decode_err)?;
    let ts = timestamps(r.u32().map_err(decode_err)?)?;
    // ReadValueId (2+4+4+6) + mode + parameters (4+8+3+4+1).
    let n = r.length(36).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let l = ctx.server.limits();
    let space = ctx.server.store.cached(ctx.space);
    let now = mono_ns();
    let mut st = lock(&s);
    let sub = st.find(sub_id).ok_or(BAD_SUBSCRIPTION_ID_INVALID)?;
    begin(w, ids::CREATE_MONITORED_ITEMS_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let node = r.node_id().map_err(decode_err)?;
        let attribute = r.u32().map_err(decode_err)?;
        let range = r.str().map_err(decode_err)?;
        let (_, enc_name) = r.qualified_name_ref().map_err(decode_err)?;
        let mode = r.u32().map_err(decode_err)?;
        let params = read_parameters(r).map_err(decode_err)?;
        let mut filter_result = None;
        let mut agg_result = None;
        let result = params.and_then(|(p, special)| {
            if let Special::Aggregate(spec) = special {
                let (r, revised) =
                    sub.create_aggregate_item(l, space, node, attribute, mode, ts, &p, &spec, can_write, now)?;
                agg_result = Some(revised);
                return Ok(r);
            }
            if let Special::Events(filter, fr) = special {
                if attribute != attr::EVENT_NOTIFIER {
                    return Err(BAD_FILTER_NOT_ALLOWED);
                }
                let good = fr.is_good() && filter.select_len() > 0;
                filter_result = Some(fr);
                if !good {
                    return Err(BAD_EVENT_FILTER_INVALID);
                }
                return sub.create_event_item(l, space, node, mode, &p, filter).map(|(id, q)| (id, 0.0, q));
            }
            let range = match range.filter(|x| !x.is_empty()).map(crate::services::parse_range) {
                None => None,
                Some(Ok(r)) => Some(r),
                Some(Err(true)) => return Err(status::BAD_INDEX_RANGE_INVALID),
                // More dimensions than the (one-dimensional) values have.
                Some(Err(false)) => Some((usize::MAX, usize::MAX)),
            };
            if enc_name.is_some_and(|x| !x.is_empty()) {
                return Err(if attribute == attr::VALUE {
                    status::BAD_DATA_ENCODING_UNSUPPORTED
                } else {
                    status::BAD_DATA_ENCODING_INVALID
                });
            }
            sub.create_item_range(l, space, node, attribute, range, mode, ts, &p, can_write, now)
        });
        match result {
            Ok((id, sampling, queue)) => {
                w.u32(status::GOOD);
                w.u32(id);
                w.f64(sampling);
                w.u32(queue);
            }
            Err(code) => {
                w.u32(code);
                w.u32(0);
                w.f64(0.0);
                w.u32(0);
            }
        }
        match (filter_result, agg_result) {
            (Some(fr), _) => fr.write(w),
            (None, Some(a)) => write_aggregate_result(w, a),
            (None, None) => w.null_extension_object(),
        }
    }
    w.empty_array(); // diagnosticInfos
    drop(st);
    ctx.conn.drive(&s);
    Ok(())
}

pub(super) fn modify_monitored_items(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let sub_id = r.u32().map_err(decode_err)?;
    let ts = timestamps(r.u32().map_err(decode_err)?)?;
    let n = r.length(24).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let l = ctx.server.limits();
    let space = ctx.server.store.cached(ctx.space);
    let now = mono_ns();
    let mut st = lock(&s);
    let sub = st.find(sub_id).ok_or(BAD_SUBSCRIPTION_ID_INVALID)?;
    begin(w, ids::MODIFY_MONITORED_ITEMS_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let id = r.u32().map_err(decode_err)?;
        let params = read_parameters(r).map_err(decode_err)?;
        let mut filter_result = None;
        let mut agg_result = None;
        let result = params.and_then(|(p, special)| {
            if sub.is_aggregate_item(id) {
                let Special::Aggregate(spec) = special else { return Err(BAD_FILTER_NOT_ALLOWED) };
                let (r, revised) = sub.modify_aggregate_item(l, space, id, ts, &p, &spec, now)?;
                agg_result = Some(revised);
                return Ok(r);
            }
            if sub.is_event_item(id) {
                let filter = match special {
                    Special::Events(f, fr) => {
                        let good = fr.is_good() && f.select_len() > 0;
                        filter_result = Some(fr);
                        if !good {
                            return Err(BAD_EVENT_FILTER_INVALID);
                        }
                        Some(f)
                    }
                    Special::None => None,
                    Special::Aggregate(_) => return Err(BAD_FILTER_NOT_ALLOWED),
                };
                return sub.modify_event_item(l, id, &p, filter).map(|q| (0.0, q));
            }
            if !matches!(special, Special::None) {
                return Err(BAD_FILTER_NOT_ALLOWED);
            }
            sub.modify_item(l, space, id, ts, &p, now)
        });
        match result {
            Ok((sampling, queue)) => {
                w.u32(status::GOOD);
                w.f64(sampling);
                w.u32(queue);
            }
            Err(code) => {
                w.u32(code);
                w.f64(0.0);
                w.u32(0);
            }
        }
        match (filter_result, agg_result) {
            (Some(fr), _) => fr.write(w),
            (None, Some(a)) => write_aggregate_result(w, a),
            (None, None) => w.null_extension_object(),
        }
    }
    w.empty_array();
    drop(st);
    ctx.conn.timers_dirty = true;
    Ok(())
}

pub(super) fn set_monitoring_mode(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let sub_id = r.u32().map_err(decode_err)?;
    let mode = r.u32().map_err(decode_err)?;
    let ids = read_ids(ctx, r)?;
    if mode > crate::subscription::MODE_REPORTING {
        return Err(BAD_MONITORING_MODE_INVALID);
    }
    let space = ctx.server.store.cached(ctx.space);
    let mut st = lock(&s);
    let sub = st.find(sub_id).ok_or(BAD_SUBSCRIPTION_ID_INVALID)?;
    let codes: Vec<u32> = ids.iter().map(|&id| sub.set_mode(id, mode, space).err().unwrap_or(status::GOOD)).collect();
    drop(st);
    ctx.conn.timers_dirty = true;
    begin(w, ids::SET_MONITORING_MODE_RESPONSE, h);
    write_codes(w, codes.into_iter());
    Ok(())
}

pub(super) fn set_triggering(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let sub_id = r.u32().map_err(decode_err)?;
    let trigger = r.u32().map_err(decode_err)?;
    let add = r.array(4, |r| r.u32()).map_err(decode_err)?;
    let remove = r.array(4, |r| r.u32()).map_err(decode_err)?;
    if add.is_empty() && remove.is_empty() {
        return Err(status::BAD_NOTHING_TO_DO);
    }
    if add.len() + remove.len() > ctx.server.limits().max_operations_per_request {
        return Err(status::BAD_TOO_MANY_OPERATIONS);
    }
    let mut st = lock(&s);
    let sub = st.find(sub_id).ok_or(BAD_SUBSCRIPTION_ID_INVALID)?;
    if !sub.has_item(trigger) {
        return Err(BAD_MONITORED_ITEM_ID_INVALID);
    }
    // Removals first (Part 4 §5.12.5.2).
    let removed: Vec<u32> =
        remove.iter().map(|&id| sub.link(trigger, id, false).err().unwrap_or(status::GOOD)).collect();
    let added: Vec<u32> = add.iter().map(|&id| sub.link(trigger, id, true).err().unwrap_or(status::GOOD)).collect();
    drop(st);
    begin(w, ids::SET_TRIGGERING_RESPONSE, h);
    write_codes(w, added.into_iter());
    write_codes(w, removed.into_iter());
    Ok(())
}

pub(super) fn delete_monitored_items(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let sub_id = r.u32().map_err(decode_err)?;
    let ids = read_ids(ctx, r)?;
    let mut st = lock(&s);
    let sub = st.find(sub_id).ok_or(BAD_SUBSCRIPTION_ID_INVALID)?;
    let codes: Vec<u32> = ids.iter().map(|&id| sub.delete_item(id).err().unwrap_or(status::GOOD)).collect();
    drop(st);
    ctx.conn.timers_dirty = true;
    begin(w, ids::DELETE_MONITORED_ITEMS_RESPONSE, h);
    write_codes(w, codes.into_iter());
    Ok(())
}

// ---------------------------------------------------------------- Cancel, Call

/// Cancel (Part 4 §5.6.5): queued Publish requests with the handle are
/// answered with Bad_RequestCancelledByClient.
pub(super) fn cancel(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let handle = r.u32().map_err(decode_err)?;
    let count = lock(&s).cancel(handle);
    if count > 0 {
        ctx.conn.drive(&s);
    }
    begin(w, ids::CANCEL_RESPONSE, h);
    w.u32(count);
    Ok(())
}

pub const BAD_METHOD_INVALID: u32 = 0x8075_0000;
pub const BAD_ARGUMENTS_MISSING: u32 = 0x8076_0000;
pub const BAD_TOO_MANY_ARGUMENTS: u32 = 0x80E5_0000;
pub const BAD_INVALID_ARGUMENT: u32 = 0x80AB_0000;

/// Result of one method call: outputs, or (status, input argument results).
type CallResult = Result<Vec<Variant>, (u32, Vec<u32>)>;

/// Call (Part 4 §5.11.2) with the Server methods (Part 5 §9).
pub(super) fn call(ctx: &mut Ctx, h: &RequestHeader, r: &mut Reader, w: &mut Writer) -> SResult {
    let s = session(ctx, h, true)?;
    let n = r.length(5).map_err(decode_err)?.unwrap_or(0);
    check_count(ctx, n)?;
    let space = ctx.server.store.cached(ctx.space);
    let mut resend = false;
    begin(w, ids::CALL_RESPONSE, h);
    w.i32(n as i32);
    for _ in 0..n {
        let object = r.node_id().map_err(decode_err)?;
        let method = r.node_id().map_err(decode_err)?;
        let args = r.array(1, |r| r.variant()).map_err(decode_err)?;
        match call_method(&s, space, &object, &method, &args, &mut resend) {
            Ok(outputs) => {
                w.u32(status::GOOD);
                w.empty_array(); // inputArgumentResults
                w.empty_array(); // inputArgumentDiagnosticInfos
                w.i32(outputs.len() as i32);
                for v in &outputs {
                    w.variant(v);
                }
            }
            Err((code, arg_results)) => {
                w.u32(code);
                write_codes(w, arg_results.into_iter());
                w.empty_array(); // outputArguments
            }
        }
    }
    w.empty_array(); // diagnosticInfos
    if resend {
        ctx.conn.drive(&s);
    }
    Ok(())
}

fn call_method(
    s: &Session,
    space: &AddressSpace,
    object: &NodeId,
    method: &NodeId,
    args: &[Variant],
    resend: &mut bool,
) -> CallResult {
    let fail = |code| Err((code, Vec::new()));
    let Some(o) = space.find(object) else { return fail(status::BAD_NODE_ID_UNKNOWN) };
    let Some(m) = space.find(method) else { return fail(BAD_METHOD_INVALID) };
    if !matches!(space.node(m).kind, NodeKind::Method { .. })
        || !space.node(o).refs.iter().any(|r| r.forward && r.type_id == ids::HAS_COMPONENT && r.target == m)
    {
        return fail(BAD_METHOD_INVALID);
    }
    match method.as_ns0() {
        Some(ids::SERVER_GET_MONITORED_ITEMS) | Some(ids::SERVER_RESEND_DATA) => {
            let id = subscription_argument(args)?;
            let mut st = lock(s);
            let Some(sub) = st.find(id) else { return fail(BAD_SUBSCRIPTION_ID_INVALID) };
            if method.as_ns0() == Some(ids::SERVER_RESEND_DATA) {
                sub.resend_initial_values();
                *resend = true;
                return Ok(Vec::new());
            }
            let (server, client) = sub.handles();
            let array = |v: Vec<u32>| {
                Variant::Array(Box::new(VariantArray {
                    type_id: builtin::UINT32,
                    items: v.into_iter().map(Variant::UInt32).collect(),
                    dims: None,
                }))
            };
            Ok(vec![array(server), array(client)])
        }
        _ => fail(BAD_METHOD_INVALID),
    }
}

/// The single UInt32 SubscriptionId argument.
fn subscription_argument(args: &[Variant]) -> Result<u32, (u32, Vec<u32>)> {
    match args {
        [] => Err((BAD_ARGUMENTS_MISSING, Vec::new())),
        [Variant::UInt32(id)] => Ok(*id),
        [_] => Err((BAD_INVALID_ARGUMENT, vec![status::BAD_TYPE_MISMATCH])),
        _ => Err((BAD_TOO_MANY_ARGUMENTS, Vec::new())),
    }
}
