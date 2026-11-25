//! Server diagnostics counters (Part 5 §6.3.3, ServerDiagnosticsSummary).
//!
//! Plain relaxed atomics, touched only when a session or subscription is
//! created or ends and when a request is rejected: never on a successful
//! Read, Write or Publish. Values are encoded when a client reads them.

use crate::types::*;
use std::sync::atomic::{AtomicU32, Ordering};

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
}

/// Node ids of the summary's children, in field order.
pub const FIELD_NODES: [u32; 12] = [2276, 2277, 2278, 2279, 3705, 2281, 2282, 2285, 2286, 2284, 2287, 2288];

#[inline]
pub fn inc(c: &AtomicU32) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn dec(c: &AtomicU32) {
    // Never wraps below zero, even if a decrement races ahead.
    let _ = c.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
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

    /// Value of field `i`, or of the whole summary for [`SUMMARY`].
    pub fn value(&self, i: u8) -> Variant {
        if i == SUMMARY {
            return self.summary();
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
