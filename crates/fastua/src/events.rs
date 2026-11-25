//! Events (Part 3 §6.4, Part 4 §7.22.3, Part 5 §6.4).
//!
//! The server raises events (session audit, configuration reloads) on an
//! [`EventBus`] shared by every address space snapshot. Event monitored items
//! keep a cursor into the bus and pull new events when their subscription is
//! serviced: emitting costs one lock and nothing at all while nobody
//! subscribes, and subscriptions without event items never look at the bus.

use crate::codec::{DResult, Reader, Writer};
use crate::types::*;
use std::cmp::Ordering as Cmp;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Event types and their field declarations (ns 0 ids).
pub mod types {
    pub const BASE_EVENT_TYPE: u32 = 2041;
    pub const AUDIT_EVENT_TYPE: u32 = 2052;
    pub const AUDIT_SECURITY_EVENT_TYPE: u32 = 2058;
    pub const AUDIT_SESSION_EVENT_TYPE: u32 = 2069;
    pub const AUDIT_CREATE_SESSION_EVENT_TYPE: u32 = 2071;
    pub const AUDIT_ACTIVATE_SESSION_EVENT_TYPE: u32 = 2075;
    pub const SYSTEM_EVENT_TYPE: u32 = 2130;
    pub const BASE_MODEL_CHANGE_EVENT_TYPE: u32 = 2132;
    pub const EVENT_QUEUE_OVERFLOW_EVENT_TYPE: u32 = 3035;

    pub const EVENT_ID: u32 = 2042;
    pub const EVENT_TYPE: u32 = 2043;
    pub const SOURCE_NODE: u32 = 2044;
    pub const SOURCE_NAME: u32 = 2045;
    pub const TIME: u32 = 2046;
    pub const RECEIVE_TIME: u32 = 2047;
    pub const MESSAGE: u32 = 2050;
    pub const SEVERITY: u32 = 2051;
    pub const ACTION_TIME_STAMP: u32 = 2053;
    pub const STATUS: u32 = 2054;
    pub const SERVER_ID: u32 = 2055;
    pub const CLIENT_AUDIT_ENTRY_ID: u32 = 2056;
    pub const CLIENT_USER_ID: u32 = 2057;
    pub const SESSION_ID: u32 = 2070;
    pub const CREATE_SECURE_CHANNEL_ID: u32 = 2072;
    pub const CLIENT_CERTIFICATE: u32 = 2073;
    pub const CLIENT_CERTIFICATE_THUMBPRINT: u32 = 2746;
    pub const REVISED_SESSION_TIMEOUT: u32 = 2074;
    pub const ACTIVATE_SECURE_CHANNEL_ID: u32 = 11485;

    /// Duration data type.
    pub const DURATION: u32 = 290;

    // Conditions and alarms (Part 9).
    pub const CONDITION_TYPE: u32 = 2782;
    pub const ACKNOWLEDGEABLE_CONDITION_TYPE: u32 = 2881;
    pub const ALARM_CONDITION_TYPE: u32 = 2915;
    pub const LIMIT_ALARM_TYPE: u32 = 2955;
    pub const EXCLUSIVE_LIMIT_ALARM_TYPE: u32 = 9341;
    pub const DISCRETE_ALARM_TYPE: u32 = 10523;
    pub const OFF_NORMAL_ALARM_TYPE: u32 = 10637;
    pub const REFRESH_START_EVENT_TYPE: u32 = 2787;
    pub const REFRESH_END_EVENT_TYPE: u32 = 2788;

    pub const CONDITION_CLASS_ID: u32 = 11112;
    pub const CONDITION_CLASS_NAME: u32 = 11113;
    pub const CONDITION_NAME: u32 = 9009;
    pub const BRANCH_ID: u32 = 9010;
    pub const RETAIN: u32 = 3874;
    pub const ENABLED_STATE: u32 = 9011;
    pub const ENABLED_STATE_ID: u32 = 9012;
    pub const ENABLED_STATE_TRANSITION_TIME: u32 = 9016;
    pub const QUALITY: u32 = 9020;
    pub const QUALITY_SOURCE_TIMESTAMP: u32 = 9021;
    pub const LAST_SEVERITY: u32 = 9022;
    pub const LAST_SEVERITY_SOURCE_TIMESTAMP: u32 = 9023;
    pub const COMMENT: u32 = 9024;
    pub const COMMENT_SOURCE_TIMESTAMP: u32 = 9025;
    pub const CONDITION_CLIENT_USER_ID: u32 = 9026;
    pub const ACKED_STATE: u32 = 9093;
    pub const ACKED_STATE_ID: u32 = 9094;
    pub const ACKED_STATE_TRANSITION_TIME: u32 = 9098;
    pub const CONFIRMED_STATE: u32 = 9102;
    pub const CONFIRMED_STATE_ID: u32 = 9103;
    pub const CONFIRMED_STATE_TRANSITION_TIME: u32 = 9107;
    pub const ACTIVE_STATE: u32 = 9160;
    pub const ACTIVE_STATE_ID: u32 = 9161;
    pub const ACTIVE_STATE_EFFECTIVE_DISPLAY_NAME: u32 = 9164;
    pub const ACTIVE_STATE_TRANSITION_TIME: u32 = 9165;
    pub const INPUT_NODE: u32 = 11120;
    pub const SUPPRESSED_OR_SHELVED: u32 = 9215;
    pub const HIGH_HIGH_LIMIT: u32 = 11124;
    pub const HIGH_LIMIT: u32 = 11125;
    pub const LOW_LIMIT: u32 = 11126;
    pub const LOW_LOW_LIMIT: u32 = 11127;
    pub const LIMIT_STATE: u32 = 9455;
    pub const LIMIT_STATE_CURRENT_STATE: u32 = 9456;
    pub const LIMIT_STATE_CURRENT_STATE_ID: u32 = 9457;
    pub const NORMAL_STATE: u32 = 11158;
    /// Not a field declaration: the NodeId of a condition (ConditionId),
    /// selected with the NodeId attribute and an empty browse path.
    pub const CONDITION_ID: u32 = u32::MAX - 1;
}
use types::*;

pub struct EventTypeDef {
    pub id: u32,
    pub name: &'static str,
    pub parent: u32,
    pub is_abstract: bool,
    /// (declaration id, browse name, data type, value rank)
    pub fields: &'static [(u32, &'static str, u32, i32)],
}

pub const EVENT_TYPES: &[EventTypeDef] = &[
    EventTypeDef {
        id: BASE_EVENT_TYPE,
        name: "BaseEventType",
        parent: crate::types::ids::BASE_OBJECT_TYPE,
        is_abstract: true,
        fields: &[
            (EVENT_ID, "EventId", 15, -1),
            (EVENT_TYPE, "EventType", 17, -1),
            (SOURCE_NODE, "SourceNode", 17, -1),
            (SOURCE_NAME, "SourceName", 12, -1),
            (TIME, "Time", crate::types::ids::UTC_TIME, -1),
            (RECEIVE_TIME, "ReceiveTime", crate::types::ids::UTC_TIME, -1),
            (MESSAGE, "Message", 21, -1),
            (SEVERITY, "Severity", 5, -1),
        ],
    },
    EventTypeDef {
        id: AUDIT_EVENT_TYPE,
        name: "AuditEventType",
        parent: BASE_EVENT_TYPE,
        is_abstract: true,
        fields: &[
            (ACTION_TIME_STAMP, "ActionTimeStamp", crate::types::ids::UTC_TIME, -1),
            (STATUS, "Status", 1, -1),
            (SERVER_ID, "ServerId", 12, -1),
            (CLIENT_AUDIT_ENTRY_ID, "ClientAuditEntryId", 12, -1),
            (CLIENT_USER_ID, "ClientUserId", 12, -1),
        ],
    },
    EventTypeDef {
        id: AUDIT_SECURITY_EVENT_TYPE,
        name: "AuditSecurityEventType",
        parent: AUDIT_EVENT_TYPE,
        is_abstract: true,
        fields: &[],
    },
    EventTypeDef {
        id: AUDIT_SESSION_EVENT_TYPE,
        name: "AuditSessionEventType",
        parent: AUDIT_SECURITY_EVENT_TYPE,
        is_abstract: true,
        fields: &[(SESSION_ID, "SessionId", 17, -1)],
    },
    EventTypeDef {
        id: AUDIT_CREATE_SESSION_EVENT_TYPE,
        name: "AuditCreateSessionEventType",
        parent: AUDIT_SESSION_EVENT_TYPE,
        is_abstract: true,
        fields: &[
            (CREATE_SECURE_CHANNEL_ID, "SecureChannelId", 12, -1),
            (CLIENT_CERTIFICATE, "ClientCertificate", 15, -1),
            (CLIENT_CERTIFICATE_THUMBPRINT, "ClientCertificateThumbprint", 12, -1),
            (REVISED_SESSION_TIMEOUT, "RevisedSessionTimeout", DURATION, -1),
        ],
    },
    EventTypeDef {
        id: AUDIT_ACTIVATE_SESSION_EVENT_TYPE,
        name: "AuditActivateSessionEventType",
        parent: AUDIT_SESSION_EVENT_TYPE,
        is_abstract: true,
        fields: &[(ACTIVATE_SECURE_CHANNEL_ID, "SecureChannelId", 12, -1)],
    },
    EventTypeDef {
        id: SYSTEM_EVENT_TYPE,
        name: "SystemEventType",
        parent: BASE_EVENT_TYPE,
        is_abstract: true,
        fields: &[],
    },
    EventTypeDef {
        id: BASE_MODEL_CHANGE_EVENT_TYPE,
        name: "BaseModelChangeEventType",
        parent: BASE_EVENT_TYPE,
        is_abstract: true,
        fields: &[],
    },
    EventTypeDef {
        id: EVENT_QUEUE_OVERFLOW_EVENT_TYPE,
        name: "EventQueueOverflowEventType",
        parent: BASE_EVENT_TYPE,
        is_abstract: true,
        fields: &[],
    },
    EventTypeDef {
        id: REFRESH_START_EVENT_TYPE,
        name: "RefreshStartEventType",
        parent: SYSTEM_EVENT_TYPE,
        is_abstract: true,
        fields: &[],
    },
    EventTypeDef {
        id: REFRESH_END_EVENT_TYPE,
        name: "RefreshEndEventType",
        parent: SYSTEM_EVENT_TYPE,
        is_abstract: true,
        fields: &[],
    },
    // Fields with a `/` are children of the field before it (data type 0:
    // an Object, such as a state machine).
    EventTypeDef {
        id: CONDITION_TYPE,
        name: "ConditionType",
        parent: BASE_EVENT_TYPE,
        is_abstract: true,
        fields: &[
            (CONDITION_CLASS_ID, "ConditionClassId", 17, -1),
            (CONDITION_CLASS_NAME, "ConditionClassName", 21, -1),
            (CONDITION_NAME, "ConditionName", 12, -1),
            (BRANCH_ID, "BranchId", 17, -1),
            (RETAIN, "Retain", 1, -1),
            (ENABLED_STATE, "EnabledState", 21, -1),
            (ENABLED_STATE_ID, "EnabledState/Id", 1, -1),
            (ENABLED_STATE_TRANSITION_TIME, "EnabledState/TransitionTime", crate::types::ids::UTC_TIME, -1),
            (QUALITY, "Quality", 19, -1),
            (QUALITY_SOURCE_TIMESTAMP, "Quality/SourceTimestamp", crate::types::ids::UTC_TIME, -1),
            (LAST_SEVERITY, "LastSeverity", 5, -1),
            (LAST_SEVERITY_SOURCE_TIMESTAMP, "LastSeverity/SourceTimestamp", crate::types::ids::UTC_TIME, -1),
            (COMMENT, "Comment", 21, -1),
            (COMMENT_SOURCE_TIMESTAMP, "Comment/SourceTimestamp", crate::types::ids::UTC_TIME, -1),
            (CONDITION_CLIENT_USER_ID, "ClientUserId", 12, -1),
        ],
    },
    EventTypeDef {
        id: ACKNOWLEDGEABLE_CONDITION_TYPE,
        name: "AcknowledgeableConditionType",
        parent: CONDITION_TYPE,
        is_abstract: false,
        fields: &[
            (ACKED_STATE, "AckedState", 21, -1),
            (ACKED_STATE_ID, "AckedState/Id", 1, -1),
            (ACKED_STATE_TRANSITION_TIME, "AckedState/TransitionTime", crate::types::ids::UTC_TIME, -1),
            (CONFIRMED_STATE, "ConfirmedState", 21, -1),
            (CONFIRMED_STATE_ID, "ConfirmedState/Id", 1, -1),
            (CONFIRMED_STATE_TRANSITION_TIME, "ConfirmedState/TransitionTime", crate::types::ids::UTC_TIME, -1),
        ],
    },
    EventTypeDef {
        id: ALARM_CONDITION_TYPE,
        name: "AlarmConditionType",
        parent: ACKNOWLEDGEABLE_CONDITION_TYPE,
        is_abstract: false,
        fields: &[
            (ACTIVE_STATE, "ActiveState", 21, -1),
            (ACTIVE_STATE_ID, "ActiveState/Id", 1, -1),
            (ACTIVE_STATE_EFFECTIVE_DISPLAY_NAME, "ActiveState/EffectiveDisplayName", 21, -1),
            (ACTIVE_STATE_TRANSITION_TIME, "ActiveState/TransitionTime", crate::types::ids::UTC_TIME, -1),
            (INPUT_NODE, "InputNode", 17, -1),
            (SUPPRESSED_OR_SHELVED, "SuppressedOrShelved", 1, -1),
        ],
    },
    EventTypeDef {
        id: LIMIT_ALARM_TYPE,
        name: "LimitAlarmType",
        parent: ALARM_CONDITION_TYPE,
        is_abstract: false,
        fields: &[
            (HIGH_HIGH_LIMIT, "HighHighLimit", 11, -1),
            (HIGH_LIMIT, "HighLimit", 11, -1),
            (LOW_LIMIT, "LowLimit", 11, -1),
            (LOW_LOW_LIMIT, "LowLowLimit", 11, -1),
        ],
    },
    EventTypeDef {
        id: EXCLUSIVE_LIMIT_ALARM_TYPE,
        name: "ExclusiveLimitAlarmType",
        parent: LIMIT_ALARM_TYPE,
        is_abstract: false,
        fields: &[
            (LIMIT_STATE, "LimitState", 0, -1),
            (LIMIT_STATE_CURRENT_STATE, "LimitState/CurrentState", 21, -1),
            (LIMIT_STATE_CURRENT_STATE_ID, "LimitState/CurrentState/Id", 17, -1),
        ],
    },
    EventTypeDef {
        id: DISCRETE_ALARM_TYPE,
        name: "DiscreteAlarmType",
        parent: ALARM_CONDITION_TYPE,
        is_abstract: false,
        fields: &[],
    },
    EventTypeDef {
        id: OFF_NORMAL_ALARM_TYPE,
        name: "OffNormalAlarmType",
        parent: DISCRETE_ALARM_TYPE,
        is_abstract: false,
        fields: &[(NORMAL_STATE, "NormalState", 17, -1)],
    },
];

fn def(id: u32) -> Option<&'static EventTypeDef> {
    EVENT_TYPES.iter().find(|t| t.id == id)
}

/// `t` is `of` or one of its subtypes.
pub fn is_subtype(mut t: u32, of: u32) -> bool {
    loop {
        if t == of {
            return true;
        }
        match def(t) {
            Some(d) if d.id != BASE_EVENT_TYPE => t = d.parent,
            _ => return false,
        }
    }
}

/// Field named `name` of events of type `t`: declared on `t`, a supertype
/// or, like the instance-based lookup of other stacks, a subtype (the value
/// is then null for events of `t` that are not of that subtype).
fn field(t: u32, name: &str) -> Option<u32> {
    declared(t, name).or_else(|| {
        EVENT_TYPES
            .iter()
            .filter(|d| is_subtype(d.id, t))
            .find_map(|d| d.fields.iter().find(|f| f.1 == name).map(|f| f.0))
    })
}

/// Field declaration named `name` on `t` or one of its supertypes.
fn declared(mut t: u32, name: &str) -> Option<u32> {
    loop {
        let d = def(t)?;
        if let Some(f) = d.fields.iter().find(|f| f.1 == name) {
            return Some(f.0);
        }
        if d.id == BASE_EVENT_TYPE {
            return None;
        }
        t = d.parent;
    }
}

// ---------------------------------------------------------------- events

pub struct Event {
    pub type_id: u32,
    /// (field declaration, value)
    pub fields: Vec<(u32, Variant)>,
    /// Only for one subscription (and one of its items, 0 = all): events of
    /// a ConditionRefresh.
    pub target: Option<(u32, u32)>,
}

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Event {
    /// An event with the BaseEventType fields set.
    pub fn new(type_id: u32, source: NodeId, source_name: &str, message: &str, severity: u16) -> Event {
        let n = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = now_ticks();
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&n.to_le_bytes());
        id[8..].copy_from_slice(&(now as u64 ^ salt()).to_le_bytes());
        Event {
            type_id,
            fields: vec![
                (EVENT_ID, Variant::ByteString(Some(id.into()))),
                (EVENT_TYPE, Variant::NodeId(Box::new(NodeId::ns0(type_id)))),
                (SOURCE_NODE, Variant::NodeId(Box::new(source))),
                (SOURCE_NAME, Variant::string(source_name)),
                (TIME, Variant::DateTime(now)),
                (RECEIVE_TIME, Variant::DateTime(now)),
                (MESSAGE, Variant::LocalizedText(Box::new(LocalizedText::new(message)))),
                (SEVERITY, Variant::UInt16(severity)),
            ],
            target: None,
        }
    }

    /// The EventId (16 bytes) of an event built by [`Event::new`].
    pub fn event_id(&self) -> &[u8] {
        match self.get(EVENT_ID) {
            Some(Variant::ByteString(Some(b))) => b,
            _ => &[],
        }
    }

    pub fn with(mut self, decl: u32, v: Variant) -> Event {
        self.fields.push((decl, v));
        self
    }

    pub fn get(&self, decl: u32) -> Option<&Variant> {
        self.fields.iter().find(|f| f.0 == decl).map(|f| &f.1)
    }
}

/// Distinguishes the EventIds of two server runs.
fn salt() -> u64 {
    static SALT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SALT.get_or_init(|| {
        let mut b = [0u8; 8];
        crate::server::random_bytes(&mut b);
        u64::from_le_bytes(b)
    })
}

/// Events kept for subscriptions that have not pulled them yet.
const RING: usize = 4096;

#[derive(Default)]
pub struct EventBus {
    /// Number of events ever emitted.
    head: AtomicU64,
    ring: Mutex<VecDeque<Arc<Event>>>,
    subscribers: AtomicUsize,
}

impl EventBus {
    /// Someone listens: worth building an event.
    #[inline]
    pub fn active(&self) -> bool {
        self.subscribers.load(Ordering::Relaxed) > 0
    }

    #[inline]
    pub fn head(&self) -> u64 {
        self.head.load(Ordering::Acquire)
    }

    pub fn emit(&self, ev: Event) {
        if !self.active() {
            return;
        }
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() == RING {
            ring.pop_front();
        }
        ring.push_back(Arc::new(ev));
        self.head.fetch_add(1, Ordering::Release);
    }

    /// Calls `f` for every event after `cursor`; returns the new cursor and
    /// whether events were lost (the reader fell more than [`RING`] behind).
    fn since(&self, cursor: u64, mut f: impl FnMut(&Event)) -> (u64, bool) {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let head = self.head.load(Ordering::Relaxed);
        let first = head - ring.len() as u64;
        for ev in ring.iter().skip(cursor.saturating_sub(first) as usize) {
            f(ev);
        }
        (head, cursor < first)
    }
}

// ---------------------------------------------------------------- filters

pub mod codes {
    pub const BAD_EVENT_FILTER_INVALID: u32 = 0x8047_0000;
    pub const BAD_FILTER_OPERAND_INVALID: u32 = 0x8049_0000;
    pub const BAD_TYPE_DEFINITION_INVALID: u32 = 0x8063_0000;
    pub const BAD_FILTER_OPERATOR_INVALID: u32 = 0x80C1_0000;
    pub const BAD_FILTER_OPERATOR_UNSUPPORTED: u32 = 0x80C2_0000;
    pub const BAD_FILTER_OPERAND_COUNT_MISMATCH: u32 = 0x80C3_0000;
    pub const BAD_FILTER_ELEMENT_INVALID: u32 = 0x80C4_0000;
}
use codes::*;

pub const EVENT_FILTER_RESULT_ENCODING: u32 = 736;
pub const EVENT_NOTIFICATION_LIST_ENCODING: u32 = 916;
/// Binary encodings of the FilterOperand subtypes.
pub const ELEMENT_OPERAND: u32 = 594;
pub const LITERAL_OPERAND: u32 = 597;
pub const ATTRIBUTE_OPERAND: u32 = 600;
pub const SIMPLE_ATTRIBUTE_OPERAND: u32 = 603;

/// Filter operators (Part 4 §7.7.3).
mod op {
    pub const EQUALS: u32 = 0;
    pub const IS_NULL: u32 = 1;
    pub const GREATER_THAN: u32 = 2;
    pub const LESS_THAN: u32 = 3;
    pub const GREATER_THAN_OR_EQUAL: u32 = 4;
    pub const LESS_THAN_OR_EQUAL: u32 = 5;
    pub const LIKE: u32 = 6;
    pub const NOT: u32 = 7;
    pub const BETWEEN: u32 = 8;
    pub const IN_LIST: u32 = 9;
    pub const AND: u32 = 10;
    pub const OR: u32 = 11;
    pub const CAST: u32 = 12;
    pub const IN_VIEW: u32 = 13;
    pub const OF_TYPE: u32 = 14;
    pub const RELATED_TO: u32 = 15;
    pub const BITWISE_AND: u32 = 16;
    pub const BITWISE_OR: u32 = 17;
}

/// A resolved SimpleAttributeOperand: the value of field `decl` for events
/// of type `type_id` (or a subtype), null otherwise. `decl == 0`: always null.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Field {
    type_id: u32,
    decl: u32,
}

impl Field {
    #[inline]
    fn value<'e>(&self, ev: &'e Event) -> Option<&'e Variant> {
        if self.decl == 0 || !is_subtype(ev.type_id, self.type_id) {
            return None;
        }
        ev.get(self.decl)
    }
}

#[derive(Debug, PartialEq)]
enum Operand {
    Element(usize),
    Literal(Variant),
    Field(Field),
}

#[derive(Debug, PartialEq)]
struct Element {
    op: u32,
    operands: Vec<Operand>,
}

#[derive(Debug, Default, PartialEq)]
pub struct EventFilter {
    select: Vec<Field>,
    where_: Vec<Element>,
}

/// Per clause / element status codes, encoded as an EventFilterResult.
#[derive(Debug, Default)]
pub struct FilterResult {
    pub select: Vec<u32>,
    /// (element status, operand statuses)
    pub elements: Vec<(u32, Vec<u32>)>,
}

impl FilterResult {
    pub fn is_good(&self) -> bool {
        self.select.iter().all(|&s| s == status::GOOD) && self.elements.iter().all(|e| e.0 == status::GOOD)
    }

    pub fn write(&self, w: &mut Writer) {
        let at = w.begin_extension_object(EVENT_FILTER_RESULT_ENCODING);
        w.i32(self.select.len() as i32);
        for &s in &self.select {
            w.u32(s);
        }
        w.empty_array(); // selectClauseDiagnosticInfos
        w.i32(self.elements.len() as i32);
        for (s, ops) in &self.elements {
            w.u32(*s);
            w.i32(ops.len() as i32);
            for &o in ops {
                w.u32(o);
            }
            w.empty_array(); // operandDiagnosticInfos
        }
        w.empty_array(); // elementDiagnosticInfos
        w.end_extension_object(at);
    }
}

/// SimpleAttributeOperand body.
fn read_simple_operand(r: &mut Reader) -> DResult<Result<Field, u32>> {
    let type_def = r.node_id()?;
    let path = r.array(3, |r| r.qualified_name())?;
    let attribute = r.u32()?;
    let _index_range = r.str()?;
    let type_id = match type_def {
        NodeId::Numeric(0, 0) => BASE_EVENT_TYPE,
        NodeId::Numeric(0, t) if def(t).is_some() => t,
        _ => return Ok(Err(BAD_TYPE_DEFINITION_INVALID)),
    };
    if path.iter().any(|q| q.name.is_empty()) {
        return Ok(Err(status::BAD_BROWSE_NAME_INVALID));
    }
    let decl = match (attribute, &path[..]) {
        // The NodeId of the event (ConditionId): null for plain events.
        (crate::services::attr::NODE_ID, []) => CONDITION_ID,
        (crate::services::attr::VALUE, []) => 0,
        (crate::services::attr::VALUE, [q]) if q.ns == 0 => field(type_id, &q.name).unwrap_or(0),
        // Nested fields ("ActiveState/Id"), all in namespace 0.
        (crate::services::attr::VALUE, p) if p.iter().all(|q| q.ns == 0) => {
            let name: Vec<&str> = p.iter().map(|q| &*q.name).collect();
            field(type_id, &name.join("/")).unwrap_or(0)
        }
        // Unknown fields are reported as null values (Part 4 §7.22.3).
        (crate::services::attr::VALUE, _) => 0,
        _ => return Ok(Err(status::BAD_ATTRIBUTE_ID_INVALID)),
    };
    Ok(Ok(Field { type_id, decl }))
}

fn operand_count_ok(op: u32, n: usize) -> bool {
    match op {
        op::IS_NULL | op::NOT | op::OF_TYPE => n == 1,
        op::BETWEEN => n == 3,
        op::IN_LIST => n >= 2,
        _ => n == 2,
    }
}

/// Parses and validates an EventFilter body. `Err` only for undecodable input.
pub fn parse_filter(body: &[u8]) -> DResult<(EventFilter, FilterResult)> {
    let mut r = Reader::new(body);
    let mut filter = EventFilter::default();
    let mut result = FilterResult::default();
    let n = r.length(13)?.unwrap_or(0);
    for _ in 0..n {
        match read_simple_operand(&mut r)? {
            Ok(f) => {
                filter.select.push(f);
                result.select.push(status::GOOD);
            }
            Err(code) => {
                filter.select.push(Field { type_id: BASE_EVENT_TYPE, decl: 0 });
                result.select.push(code);
            }
        }
    }
    let count = r.length(8)?.unwrap_or(0);
    for i in 0..count {
        let op = r.u32()?;
        let nops = r.length(3)?.unwrap_or(0);
        let mut operands = Vec::with_capacity(nops);
        let mut op_codes = Vec::with_capacity(nops);
        for _ in 0..nops {
            let (type_id, enc, ob) = r.extension_object_raw()?;
            let mut b = Reader::new(ob);
            let parsed = match (type_id.as_ns0(), enc) {
                (Some(ELEMENT_OPERAND), 1) => {
                    let idx = b.u32()? as usize;
                    // Only forward references: no cycles, bounded recursion.
                    if idx > i && idx < count {
                        Ok(Operand::Element(idx))
                    } else {
                        Err(BAD_FILTER_OPERAND_INVALID)
                    }
                }
                (Some(LITERAL_OPERAND), 1) => Ok(Operand::Literal(b.variant()?)),
                (Some(SIMPLE_ATTRIBUTE_OPERAND), 1) => read_simple_operand(&mut b)?.map(Operand::Field),
                (Some(ATTRIBUTE_OPERAND), 1) => Err(BAD_FILTER_OPERAND_INVALID),
                _ => Err(BAD_FILTER_OPERAND_INVALID),
            };
            match parsed {
                Ok(o) => {
                    operands.push(o);
                    op_codes.push(status::GOOD);
                }
                Err(c) => {
                    operands.push(Operand::Literal(Variant::Empty));
                    op_codes.push(c);
                }
            }
        }
        let mut code = match op {
            op::CAST | op::IN_VIEW | op::RELATED_TO => BAD_FILTER_OPERATOR_UNSUPPORTED,
            o if o > op::BITWISE_OR => BAD_FILTER_OPERATOR_INVALID,
            o if !operand_count_ok(o, nops) => BAD_FILTER_OPERAND_COUNT_MISMATCH,
            _ if op_codes.iter().any(|&c| c != status::GOOD) => BAD_FILTER_OPERAND_INVALID,
            _ => status::GOOD,
        };
        if code == status::GOOD && op == op::OF_TYPE && !matches!(&operands[0], Operand::Literal(Variant::NodeId(_))) {
            code = BAD_FILTER_OPERAND_INVALID;
        }
        filter.where_.push(Element { op, operands });
        result.elements.push((code, op_codes));
    }
    if filter.select.is_empty() {
        // Nothing to report: the filter is useless (Part 4 §7.22.3).
        result.select.clear();
    }
    Ok((filter, result))
}

/// Comparison of two operand values with numeric widening.
fn compare(a: &Variant, b: &Variant) -> Option<Cmp> {
    if let (Some(x), Some(y)) = (as_number(a), as_number(b)) {
        return x.partial_cmp(&y);
    }
    match (a, b) {
        (Variant::Boolean(x), Variant::Boolean(y)) => Some(x.cmp(y)),
        (Variant::DateTime(x), Variant::DateTime(y)) => Some(x.cmp(y)),
        (Variant::StatusCode(x), Variant::StatusCode(y)) => Some(x.cmp(y)),
        _ => match (as_str(a), as_str(b)) {
            (Some(x), Some(y)) => Some(x.cmp(y)),
            _ => (a == b).then_some(Cmp::Equal),
        },
    }
}

fn as_number(v: &Variant) -> Option<f64> {
    match v {
        Variant::Boolean(_) => None,
        _ => crate::value::variant_as_f64(v),
    }
}

fn as_integer(v: &Variant) -> Option<i64> {
    Some(match *v {
        Variant::SByte(x) => x as i64,
        Variant::Byte(x) => x as i64,
        Variant::Int16(x) => x as i64,
        Variant::UInt16(x) => x as i64,
        Variant::Int32(x) => x as i64,
        Variant::UInt32(x) => x as i64,
        Variant::Int64(x) => x,
        Variant::UInt64(x) => x as i64,
        _ => return None,
    })
}

fn as_str(v: &Variant) -> Option<&str> {
    match v {
        Variant::String(Some(s)) => Some(s),
        Variant::LocalizedText(t) => t.text.as_deref(),
        Variant::QualifiedName(q) => Some(&q.name),
        _ => None,
    }
}

/// SQL LIKE with `%` (any run), `_` (one character) and `[..]` / `[^..]` sets.
fn like(s: &[char], p: &[char]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some('%') => (0..=s.len()).any(|i| like(&s[i..], &p[1..])),
        Some('_') => !s.is_empty() && like(&s[1..], &p[1..]),
        Some('[') => {
            let Some(end) = p.iter().position(|&c| c == ']') else {
                return !s.is_empty() && s[0] == '[' && like(&s[1..], &p[1..]);
            };
            let Some(&c) = s.first() else { return false };
            let (neg, set) = match p[1..end].split_first() {
                Some(('^', rest)) => (true, rest),
                _ => (false, &p[1..end]),
            };
            let mut hit = false;
            let mut i = 0;
            while i < set.len() {
                if i + 2 < set.len() && set[i + 1] == '-' {
                    hit |= set[i] <= c && c <= set[i + 2];
                    i += 3;
                } else {
                    hit |= set[i] == c;
                    i += 1;
                }
            }
            hit != neg && like(&s[1..], &p[end + 1..])
        }
        Some(&c) => s.first() == Some(&c) && like(&s[1..], &p[1..]),
    }
}

impl EventFilter {
    pub fn select_len(&self) -> usize {
        self.select.len()
    }

    /// The where clause accepts `ev`.
    pub fn matches(&self, ev: &Event) -> bool {
        self.where_.is_empty() || self.eval(0, ev) == Some(Variant::Boolean(true))
    }

    fn operand(&self, o: &Operand, ev: &Event) -> Option<Variant> {
        match o {
            Operand::Element(i) => self.eval(*i, ev),
            Operand::Literal(Variant::Empty) => None,
            Operand::Literal(v) => Some(v.clone()),
            Operand::Field(f) => f.value(ev).cloned(),
        }
    }

    /// Value of element `i`; `None` is null. Booleans use SQL's three-valued
    /// logic through `None`.
    fn eval(&self, i: usize, ev: &Event) -> Option<Variant> {
        let e = self.where_.get(i)?;
        let arg = |k: usize| self.operand(&e.operands[k], ev);
        let b = |x: bool| Some(Variant::Boolean(x));
        let truth = |v: Option<Variant>| match v {
            Some(Variant::Boolean(x)) => Some(x),
            _ => None,
        };
        match e.op {
            op::IS_NULL => b(arg(0).is_none()),
            op::NOT => truth(arg(0)).map(|x| Variant::Boolean(!x)),
            op::AND => match (truth(arg(0)), truth(arg(1))) {
                (Some(false), _) | (_, Some(false)) => b(false),
                (Some(true), Some(true)) => b(true),
                _ => None,
            },
            op::OR => match (truth(arg(0)), truth(arg(1))) {
                (Some(true), _) | (_, Some(true)) => b(true),
                (Some(false), Some(false)) => b(false),
                _ => None,
            },
            op::EQUALS | op::GREATER_THAN | op::LESS_THAN | op::GREATER_THAN_OR_EQUAL | op::LESS_THAN_OR_EQUAL => {
                let c = compare(&arg(0)?, &arg(1)?);
                b(match e.op {
                    op::EQUALS => c == Some(Cmp::Equal),
                    op::GREATER_THAN => c == Some(Cmp::Greater),
                    op::LESS_THAN => c == Some(Cmp::Less),
                    op::GREATER_THAN_OR_EQUAL => matches!(c, Some(Cmp::Greater | Cmp::Equal)),
                    _ => matches!(c, Some(Cmp::Less | Cmp::Equal)),
                })
            }
            op::BETWEEN => {
                let v = arg(0)?;
                b(matches!(compare(&v, &arg(1)?), Some(Cmp::Greater | Cmp::Equal))
                    && matches!(compare(&v, &arg(2)?), Some(Cmp::Less | Cmp::Equal)))
            }
            op::IN_LIST => {
                let v = arg(0)?;
                b((1..e.operands.len()).any(|k| arg(k).is_some_and(|x| compare(&v, &x) == Some(Cmp::Equal))))
            }
            op::LIKE => {
                let (v, p) = (arg(0)?, arg(1)?);
                let (s, p) = (as_str(&v)?, as_str(&p)?);
                b(like(&s.chars().collect::<Vec<_>>(), &p.chars().collect::<Vec<_>>()))
            }
            op::OF_TYPE => match &e.operands[0] {
                Operand::Literal(Variant::NodeId(t)) => {
                    b(matches!(**t, NodeId::Numeric(0, t) if is_subtype(ev.type_id, t)))
                }
                _ => None,
            },
            op::BITWISE_AND | op::BITWISE_OR => {
                let (x, y) = (as_integer(&arg(0)?)?, as_integer(&arg(1)?)?);
                Some(Variant::Int64(if e.op == op::BITWISE_AND { x & y } else { x | y }))
            }
            _ => None,
        }
    }

    /// The selected fields of `ev`.
    fn fields(&self, ev: &Event) -> Box<[Variant]> {
        self.select.iter().map(|f| f.value(ev).cloned().unwrap_or_default()).collect()
    }
}

// ---------------------------------------------------------------- monitored items

pub struct EventItem {
    pub id: u32,
    /// Id of the subscription holding the item (targeted events).
    pub subscription: u32,
    pub client_handle: u32,
    pub mode: u32,
    pub node: NodeId,
    pub filter: EventFilter,
    pub queue_size: usize,
    pub discard_oldest: bool,
    queue: VecDeque<Box<[Variant]>>,
    /// An EventQueueOverflow event is in the queue.
    overflowed: bool,
    cursor: u64,
    bus: Arc<EventBus>,
}

impl EventItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u32,
        client_handle: u32,
        mode: u32,
        node: NodeId,
        filter: EventFilter,
        queue_size: usize,
        discard_oldest: bool,
        bus: Arc<EventBus>,
    ) -> EventItem {
        bus.subscribers.fetch_add(1, Ordering::Relaxed);
        let cursor = bus.head();
        EventItem {
            id,
            subscription: 0,
            client_handle,
            mode,
            node,
            filter,
            queue_size,
            discard_oldest,
            queue: VecDeque::new(),
            overflowed: false,
            cursor,
            bus,
        }
    }

    /// Events wait to be reported.
    #[inline]
    pub fn reportable(&self) -> bool {
        self.mode == crate::subscription::MODE_REPORTING && !self.queue.is_empty()
    }

    pub fn clear(&mut self) {
        self.queue.clear();
        self.overflowed = false;
    }

    pub fn resize(&mut self, queue_size: usize, discard_oldest: bool) {
        self.queue_size = queue_size;
        self.discard_oldest = discard_oldest;
        while self.queue.len() > queue_size {
            if discard_oldest {
                self.queue.pop_front();
            } else {
                self.queue.pop_back();
            }
        }
    }

    /// Pulls new events from the bus. Returns true when something was queued.
    pub fn poll(&mut self) -> bool {
        if self.bus.head() == self.cursor {
            return false;
        }
        let bus = self.bus.clone();
        let mut queued = false;
        let enabled = self.mode != crate::subscription::MODE_DISABLED;
        let (cursor, lost) = bus.since(self.cursor, |ev| {
            let for_me = ev.target.is_none_or(|(s, i)| s == self.subscription && (i == 0 || i == self.id));
            // RefreshStart / RefreshEnd frame a ConditionRefresh whatever the
            // where clause (a client filtering on ConditionType needs them).
            let framing = ev.target.is_some()
                && matches!(ev.type_id, types::REFRESH_START_EVENT_TYPE | types::REFRESH_END_EVENT_TYPE);
            if enabled && for_me && (framing || self.filter.matches(ev)) {
                let f = self.filter.fields(ev);
                self.push(f);
                queued = true;
            }
        });
        self.cursor = cursor;
        if lost && enabled {
            self.overflow();
        }
        queued
    }

    /// Queues one event. A full queue gets an EventQueueOverflowEventType
    /// event (Part 4 §5.12.1.5): at the oldest position when discarding the
    /// oldest, else replacing the newest. It is never discarded itself.
    fn push(&mut self, fields: Box<[Variant]>) {
        if self.queue.len() < self.queue_size {
            self.queue.push_back(fields);
            return;
        }
        if self.discard_oldest {
            if self.overflowed {
                self.queue.remove(1);
            } else {
                // Room for the overflow event and the new one.
                self.queue.pop_front();
                self.queue.pop_front();
                self.overflowed = true;
                let f = self.overflow_fields();
                self.queue.push_front(f);
            }
            self.queue.push_back(fields);
        } else if !self.overflowed {
            self.queue.pop_back();
            self.overflowed = true;
            let f = self.overflow_fields();
            self.queue.push_back(f);
        }
    }

    /// Events were lost before reaching the queue.
    fn overflow(&mut self) {
        if self.overflowed {
            return;
        }
        self.overflowed = true;
        let f = self.overflow_fields();
        let full = self.queue.len() >= self.queue_size;
        if self.discard_oldest {
            if full {
                self.queue.pop_front();
            }
            self.queue.push_front(f);
        } else {
            if full {
                self.queue.pop_back();
            }
            self.queue.push_back(f);
        }
    }

    fn overflow_fields(&self) -> Box<[Variant]> {
        let ev = Event::new(EVENT_QUEUE_OVERFLOW_EVENT_TYPE, self.node.clone(), "", "Event queue overflow", 1);
        self.filter.fields(&ev)
    }

    /// Writes queued events as EventFieldLists, at most `max` of them while
    /// the message stays under `max_bytes`. Returns how many were written.
    pub fn write(&mut self, w: &mut Writer, max: u32, max_bytes: usize) -> u32 {
        let mut n = 0;
        while n < max && w.len() < max_bytes {
            let Some(f) = self.queue.pop_front() else { break };
            if self.discard_oldest {
                // The overflow event, if any, was at the front.
                self.overflowed = false;
            }
            w.u32(self.client_handle);
            w.i32(f.len() as i32);
            for v in f.iter() {
                w.variant(v);
            }
            n += 1;
        }
        if self.queue.is_empty() {
            self.overflowed = false;
        }
        n
    }
}

impl Drop for EventItem {
    fn drop(&mut self) {
        self.bus.subscribers.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple(w: &mut Writer, type_id: u32, name: &str) {
        w.node_id(&NodeId::ns0(type_id));
        w.i32(1);
        w.qualified_name(&QualifiedName { ns: 0, name: name.into() });
        w.u32(13);
        w.str(None);
    }

    fn filter(selects: &[&str], where_: impl FnOnce(&mut Writer)) -> (EventFilter, FilterResult) {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.i32(selects.len() as i32);
        for s in selects {
            simple(&mut w, BASE_EVENT_TYPE, s);
        }
        where_(&mut w);
        parse_filter(&buf).unwrap()
    }

    fn element(w: &mut Writer, op: u32, ops: &[&dyn Fn(&mut Writer)]) {
        w.u32(op);
        w.i32(ops.len() as i32);
        for o in ops {
            o(w);
        }
    }

    fn lit(v: Variant) -> impl Fn(&mut Writer) {
        move |w: &mut Writer| {
            let at = w.begin_extension_object(LITERAL_OPERAND);
            w.variant(&v);
            w.end_extension_object(at);
        }
    }

    fn fld(name: &'static str) -> impl Fn(&mut Writer) {
        move |w: &mut Writer| {
            let at = w.begin_extension_object(SIMPLE_ATTRIBUTE_OPERAND);
            simple(w, BASE_EVENT_TYPE, name);
            w.end_extension_object(at);
        }
    }

    fn elem(i: u32) -> impl Fn(&mut Writer) {
        move |w: &mut Writer| {
            let at = w.begin_extension_object(ELEMENT_OPERAND);
            w.u32(i);
            w.end_extension_object(at);
        }
    }

    fn ev(severity: u16) -> Event {
        Event::new(BASE_MODEL_CHANGE_EVENT_TYPE, NodeId::ns0(2253), "Server", "reloaded", severity)
    }

    #[test]
    fn select_clauses() {
        let (f, r) = filter(&["Severity", "Message", "Nope", "SessionId"], |w| w.i32(0));
        assert!(r.is_good());
        let e = ev(300);
        let fields = f.fields(&e);
        assert_eq!(fields[0], Variant::UInt16(300));
        assert_eq!(fields[1], Variant::LocalizedText(Box::new(LocalizedText::new("reloaded"))));
        assert_eq!(fields[2], Variant::Empty);
        // SessionId (AuditSessionEventType) is null for other events.
        assert_eq!(fields[3], Variant::Empty);
        assert_eq!(field(BASE_EVENT_TYPE, "SessionId"), Some(SESSION_ID));
        assert!(is_subtype(AUDIT_CREATE_SESSION_EVENT_TYPE, AUDIT_EVENT_TYPE));
        assert!(!is_subtype(SYSTEM_EVENT_TYPE, AUDIT_EVENT_TYPE));
        assert_eq!(field(AUDIT_CREATE_SESSION_EVENT_TYPE, "SessionId"), Some(SESSION_ID));
        assert_eq!(field(AUDIT_CREATE_SESSION_EVENT_TYPE, "EventId"), Some(EVENT_ID));
    }

    #[test]
    fn where_clauses() {
        // Severity >= 500 AND OfType(BaseModelChangeEventType)
        let (f, r) = filter(&["Severity"], |w| {
            w.i32(3);
            element(w, op::AND, &[&elem(1), &elem(2)]);
            element(w, op::GREATER_THAN_OR_EQUAL, &[&fld("Severity"), &lit(Variant::Int32(500))]);
            element(w, op::OF_TYPE, &[&lit(Variant::NodeId(Box::new(NodeId::ns0(BASE_MODEL_CHANGE_EVENT_TYPE))))]);
        });
        assert!(r.is_good(), "{r:?}");
        assert!(f.matches(&ev(700)));
        assert!(!f.matches(&ev(100)));
        let mut other = ev(900);
        other.type_id = SYSTEM_EVENT_TYPE;
        assert!(!f.matches(&other));

        let (f, _) = filter(&["Severity"], |w| {
            w.i32(1);
            element(w, op::LIKE, &[&fld("SourceName"), &lit(Variant::string("Ser_e%"))]);
        });
        assert!(f.matches(&ev(1)));
        let (f, _) = filter(&["Severity"], |w| {
            w.i32(1);
            element(w, op::IN_LIST, &[&fld("Severity"), &lit(Variant::UInt32(1)), &lit(Variant::Double(7.0))]);
        });
        assert!(f.matches(&ev(7)));
        assert!(!f.matches(&ev(8)));
    }

    #[test]
    fn invalid_where_clauses() {
        let (_, r) = filter(&["Severity"], |w| {
            w.i32(4);
            element(w, op::EQUALS, &[&fld("Severity")]);
            element(w, op::RELATED_TO, &[&lit(Variant::Int32(1)), &lit(Variant::Int32(1))]);
            element(w, 99, &[]);
            element(w, op::NOT, &[&elem(0)]);
        });
        let codes: Vec<u32> = r.elements.iter().map(|e| e.0).collect();
        assert_eq!(
            codes,
            vec![
                BAD_FILTER_OPERAND_COUNT_MISMATCH,
                BAD_FILTER_OPERATOR_UNSUPPORTED,
                BAD_FILTER_OPERATOR_INVALID,
                BAD_FILTER_OPERAND_INVALID
            ]
        );
    }

    #[test]
    fn like_patterns() {
        let m = |s: &str, p: &str| like(&s.chars().collect::<Vec<_>>(), &p.chars().collect::<Vec<_>>());
        assert!(m("Session/CreateSession", "Session/%"));
        assert!(m("abc", "a_c"));
        assert!(m("abc", "[a-c]bc"));
        assert!(!m("abc", "[^a]bc"));
        assert!(!m("abc", "ab"));
    }

    #[test]
    fn bus_and_overflow() {
        let bus = Arc::new(EventBus::default());
        bus.emit(ev(1)); // nobody listens: dropped
        assert_eq!(bus.head(), 0);
        let (f, _) = filter(&["Severity", "EventType"], |w| w.i32(0));
        let mut it =
            EventItem::new(1, 7, crate::subscription::MODE_REPORTING, NodeId::ns0(2253), f, 2, true, bus.clone());
        assert!(bus.active());
        for s in 1..=3 {
            bus.emit(ev(s));
        }
        assert!(it.poll());
        // Oldest discarded, overflow event at the oldest position.
        let sev: Vec<Variant> = it.queue.iter().map(|f| f[0].clone()).collect();
        assert_eq!(sev, vec![Variant::UInt16(1), Variant::UInt16(3)]);
        assert_eq!(it.queue[0][1], Variant::NodeId(Box::new(NodeId::ns0(EVENT_QUEUE_OVERFLOW_EVENT_TYPE))));
        drop(it);
        assert!(!bus.active());
    }
}
