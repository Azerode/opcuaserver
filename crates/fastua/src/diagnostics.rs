//! Server diagnostics counters (Part 5 §6.3.3, ServerDiagnosticsSummary).
//!
//! Plain relaxed atomics, touched only when a session or subscription is
//! created or ends and when a request is rejected: never on a successful
//! Read, Write or Publish. Values are encoded when a client reads them.

use crate::codec::Writer;
use crate::types::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Binary encoding of ServerDiagnosticsSummaryDataType.
pub const SUMMARY_ENCODING: u32 = 861;
/// Server_ServerDiagnostics_ServerDiagnosticsSummary.
pub const SUMMARY_NODE: u32 = 2275;

/// Counters, in the order of the ServerDiagnosticsSummaryDataType fields.
#[derive(Debug, Default)]
pub struct Diagnostics {
    pub server_views: AtomicU32,
    pub current_sessions: AtomicU32,
    pub cumulated_sessions: AtomicU32,
    pub security_rejected_sessions: AtomicU32,
    pub rejected_sessions: AtomicU32,
    pub session_timeouts: AtomicU32,
    pub session_aborts: AtomicU32,
    pub current_subscriptions: AtomicU32,
    pub cumulated_subscriptions: AtomicU32,
    pub publishing_intervals: AtomicU32,
    pub security_rejected_requests: AtomicU32,
    pub rejected_requests: AtomicU32,
    /// Live sessions, for the session and subscription diagnostics arrays.
    pub sessions: Mutex<Vec<Weak<crate::server::Session>>>,
    /// Service counters per session are kept (`--session-diagnostics`,
    /// ServerDiagnostics.EnabledFlag).
    pub counting: AtomicBool,
}

/// Services counted in SessionDiagnosticsDataType, in field order.
const SERVICES: [u32; 28] = [
    ids::READ_REQUEST,
    ids::HISTORY_READ_REQUEST,
    ids::WRITE_REQUEST,
    ids::HISTORY_UPDATE_REQUEST,
    ids::CALL_REQUEST,
    ids::CREATE_MONITORED_ITEMS_REQUEST,
    ids::MODIFY_MONITORED_ITEMS_REQUEST,
    ids::SET_MONITORING_MODE_REQUEST,
    ids::SET_TRIGGERING_REQUEST,
    ids::DELETE_MONITORED_ITEMS_REQUEST,
    ids::CREATE_SUBSCRIPTION_REQUEST,
    ids::MODIFY_SUBSCRIPTION_REQUEST,
    ids::SET_PUBLISHING_MODE_REQUEST,
    ids::PUBLISH_REQUEST,
    ids::REPUBLISH_REQUEST,
    ids::TRANSFER_SUBSCRIPTIONS_REQUEST,
    ids::DELETE_SUBSCRIPTIONS_REQUEST,
    488, // AddNodes
    494, // AddReferences
    500, // DeleteNodes
    506, // DeleteReferences
    ids::BROWSE_REQUEST,
    ids::BROWSE_NEXT_REQUEST,
    ids::TRANSLATE_BROWSE_PATHS_REQUEST,
    615, // QueryFirst
    621, // QueryNext
    ids::REGISTER_NODES_REQUEST,
    ids::UNREGISTER_NODES_REQUEST,
];

/// Per session: (total, errors) per service of [`SERVICES`], then
/// TotalRequestCount (total, errors), then UnauthorizedRequestCount.
pub const COUNTERS: usize = 2 * SERVICES.len() + 3;
pub const TOTAL_REQUESTS: usize = 2 * SERVICES.len();
pub const UNAUTHORIZED_REQUESTS: usize = 2 * SERVICES.len() + 2;

/// Slot of a request type in [`SERVICES`].
pub fn service_slot(request_type: u32) -> Option<usize> {
    SERVICES.iter().position(|&t| t == request_type)
}

/// `ValueSource::Diagnostics` indexes of the arrays.
pub const SESSIONS_ARRAY: u8 = u8::MAX - 1;
pub const SECURITY_ARRAY: u8 = u8::MAX - 2;
pub const SUBSCRIPTIONS_ARRAY: u8 = u8::MAX - 3;
/// `ValueSource::Diagnostics` index of EnabledFlag.
pub const ENABLED_FLAG: u8 = u8::MAX - 4;
/// Binary encodings of the array elements.
const SESSION_DIAGNOSTICS_ENCODING: u32 = 867;
const SESSION_SECURITY_DIAGNOSTICS_ENCODING: u32 = 870;
const SUBSCRIPTION_DIAGNOSTICS_ENCODING: u32 = 876;

/// Node ids of the summary's children, in field order.
pub const FIELD_NODES: [u32; 12] = [2276, 2277, 2278, 2279, 3705, 2281, 2282, 2285, 2286, 2284, 2287, 2288];

#[inline]
pub fn inc(c: &AtomicU32) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn dec(c: &AtomicU32) {
    // Never wraps below zero, even if a decrement races ahead.
    // (A plain CAS loop: `fetch_update` is deprecated on recent toolchains and
    // its replacement `try_update` is missing on older ones.)
    let mut v = c.load(Ordering::Relaxed);
    while v > 0 {
        match c.compare_exchange_weak(v, v - 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(now) => v = now,
        }
    }
}

/// Status codes counted as security rejections.
pub fn is_security_error(code: u32) -> bool {
    matches!(
        code & 0xFFFF_0000,
        // BadCertificate* (0x8012..0x801C) and BadSecurityChecksFailed (0x8013)
        0x8012_0000
            ..=0x801C_0000
            | status::BAD_USER_ACCESS_DENIED
            | status::BAD_IDENTITY_TOKEN_INVALID
            | status::BAD_IDENTITY_TOKEN_REJECTED
            | status::BAD_SECURE_CHANNEL_ID_INVALID
            | 0x8024_0000 // BadNonceInvalid
            | 0x8055_0000 // BadSecurityPolicyRejected
            | 0x8057_0000 // BadUserSignatureInvalid
            | 0x8058_0000 // BadApplicationSignatureInvalid
    )
}

impl Diagnostics {
    fn fields(&self) -> [&AtomicU32; 12] {
        [
            &self.server_views,
            &self.current_sessions,
            &self.cumulated_sessions,
            &self.security_rejected_sessions,
            &self.rejected_sessions,
            &self.session_timeouts,
            &self.session_aborts,
            &self.current_subscriptions,
            &self.cumulated_subscriptions,
            &self.publishing_intervals,
            &self.security_rejected_requests,
            &self.rejected_requests,
        ]
    }

    /// Value of field `i`, of the whole summary for [`SUMMARY`], or of a
    /// diagnostics array.
    pub fn value(&self, i: u8) -> Variant {
        match i {
            SUMMARY => return self.summary(),
            SESSIONS_ARRAY | SECURITY_ARRAY | SUBSCRIPTIONS_ARRAY => return self.array(i),
            ENABLED_FLAG => return Variant::Boolean(self.counting.load(Ordering::Relaxed)),
            _ => {}
        }
        Variant::UInt32(self.get(i as usize))
    }

    fn get(&self, i: usize) -> u32 {
        // Every live subscription runs at its own publishing interval.
        if i == 9 {
            return self.current_subscriptions.load(Ordering::Relaxed);
        }
        self.fields()[i].load(Ordering::Relaxed)
    }

    /// The ServerDiagnosticsSummaryDataType structure.
    pub fn summary(&self) -> Variant {
        let mut body = Vec::with_capacity(48);
        for i in 0..12 {
            body.extend_from_slice(&self.get(i).to_le_bytes());
        }
        Variant::ExtensionObject(Box::new(ExtensionObject {
            type_id: NodeId::ns0(SUMMARY_ENCODING),
            encoding: 1,
            body: body.into(),
        }))
    }

    /// Tracks a new session for the diagnostics arrays.
    pub fn register(&self, s: &Arc<crate::server::Session>) {
        let mut v = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        v.retain(|w| w.upgrade().is_some_and(|s| !s.closed.load(Ordering::Relaxed)));
        v.push(Arc::downgrade(s));
    }

    fn live(&self) -> Vec<Arc<crate::server::Session>> {
        let v = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        v.iter().filter_map(Weak::upgrade).filter(|s| !s.closed.load(Ordering::Relaxed)).collect()
    }

    /// SessionDiagnosticsArray, SessionSecurityDiagnosticsArray or
    /// SubscriptionDiagnosticsArray, encoded when read.
    fn array(&self, which: u8) -> Variant {
        let mut items = Vec::new();
        for s in self.live() {
            match which {
                SESSIONS_ARRAY => items.push(encoded(SESSION_DIAGNOSTICS_ENCODING, |w| session_diagnostics(w, &s))),
                SECURITY_ARRAY => {
                    items.push(encoded(SESSION_SECURITY_DIAGNOSTICS_ENCODING, |w| security_diagnostics(w, &s)))
                }
                _ => {
                    let subs = s.subs.lock().unwrap_or_else(|e| e.into_inner());
                    for sub in &subs.subs {
                        items.push(encoded(SUBSCRIPTION_DIAGNOSTICS_ENCODING, |w| {
                            w.node_id(&s.id);
                            sub.write_diagnostics(w);
                        }));
                    }
                }
            }
        }
        Variant::Array(Box::new(VariantArray { type_id: builtin::EXTENSIONOBJECT, items, dims: None }))
    }

    /// Rejected request accounting (Part 5 §12.9): CreateSession and
    /// ActivateSession failures count as rejected sessions.
    pub fn rejected(&self, session_service: bool, code: u32) {
        let security = is_security_error(code);
        if session_service {
            inc(&self.rejected_sessions);
            if security {
                inc(&self.security_rejected_sessions);
            }
        } else {
            inc(&self.rejected_requests);
            if security {
                inc(&self.security_rejected_requests);
            }
        }
    }
}

/// `ValueSource::Diagnostics` index of the whole summary.
pub const SUMMARY: u8 = u8::MAX;

fn encoded(encoding: u32, f: impl FnOnce(&mut Writer)) -> Variant {
    let mut body = Vec::with_capacity(256);
    f(&mut Writer::new(&mut body));
    Variant::ExtensionObject(Box::new(ExtensionObject {
        type_id: NodeId::ns0(encoding),
        encoding: 1,
        body: body.into(),
    }))
}

/// SessionDiagnosticsDataType (Part 5 §12.11).
fn session_diagnostics(w: &mut Writer, s: &crate::server::Session) {
    let d = &s.diag;
    w.node_id(&s.id);
    w.string(&s.name);
    if d.client_description.is_empty() {
        // A null ApplicationDescription (in-process sessions).
        w.str(None);
        w.str(None);
        w.u8(0);
        w.i32(0);
        w.str(None);
        w.str(None);
        w.i32(-1);
    } else {
        w.raw(&d.client_description);
    }
    w.str(d.server_uri.as_deref());
    w.str(d.endpoint_url.as_deref());
    w.empty_array(); // LocaleIds
    w.f64(s.timeout_ms);
    w.u32(d.max_response);
    w.i64(d.connected);
    w.i64(d.last_contact.load(Ordering::Relaxed));
    let (subs, items, queued) = {
        let st = s.subs.lock().unwrap_or_else(|e| e.into_inner());
        let items: usize = st.subs.iter().map(|x| x.item_count()).sum();
        (st.subs.len(), items, st.queued_requests())
    };
    w.u32(subs as u32);
    w.u32(items as u32);
    w.u32(queued as u32);
    let c = |i: usize| d.counters[i].load(Ordering::Relaxed);
    w.u32(c(TOTAL_REQUESTS));
    w.u32(c(TOTAL_REQUESTS + 1));
    w.u32(c(UNAUTHORIZED_REQUESTS));
    for i in 0..SERVICES.len() {
        w.u32(c(2 * i));
        w.u32(c(2 * i + 1));
    }
}

/// SessionSecurityDiagnosticsDataType (Part 5 §12.12).
fn security_diagnostics(w: &mut Writer, s: &crate::server::Session) {
    let identity = s.identity.lock().unwrap_or_else(|e| e.into_inner()).clone();
    w.node_id(&s.id);
    w.string(&identity);
    let history = s.diag.identities.lock().unwrap_or_else(|e| e.into_inner()).clone();
    w.i32(history.len() as i32);
    for h in &history {
        w.string(h);
    }
    let mechanism = match identity.split(':').next() {
        Some("user") => "UserName",
        Some("x509") => "X509Certificate",
        _ => "Anonymous",
    };
    w.string(mechanism);
    w.string("UA Binary");
    w.string(if s.security.https {
        crate::https::TRANSPORT_PROFILE_HTTPS
    } else {
        crate::server::TRANSPORT_PROFILE_BINARY
    });
    w.i32(s.security.mode as i32);
    w.string(s.security.policy.uri());
    w.bytes(s.security.client_cert.as_ref().map(|c| &c.der[..]));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_layout() {
        let d = Diagnostics::default();
        inc(&d.cumulated_sessions);
        inc(&d.current_subscriptions);
        dec(&d.current_sessions);
        let Variant::ExtensionObject(x) = d.summary() else { panic!() };
        assert_eq!(x.body.len(), 48);
        assert_eq!(&x.body[8..12], &1u32.to_le_bytes()); // CumulatedSessionCount
        assert_eq!(&x.body[4..8], &0u32.to_le_bytes()); // no wrap below zero
        assert_eq!(d.value(9), Variant::UInt32(1)); // PublishingIntervalCount
        assert!(is_security_error(status::BAD_SECURITY_CHECKS_FAILED));
        assert!(!is_security_error(status::BAD_NODE_ID_UNKNOWN));
    }
}
