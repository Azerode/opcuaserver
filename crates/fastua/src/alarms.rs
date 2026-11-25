//! Alarms and conditions (Part 9): limit alarms (ExclusiveLimitAlarmType)
//! and off-normal alarms (OffNormalAlarmType) on configured variables.
//!
//! A condition is evaluated by the write of its variable (a hook that
//! variables without an alarm never run, see [`crate::value::ValueCell`]).
//! Every state change raises a condition event on the [`EventBus`]; the
//! condition methods (Enable, Disable, AddComment, Acknowledge, Confirm,
//! ConditionRefresh, ConditionRefresh2) go through the Call service.

use crate::events::types::*;
use crate::events::{Event, EventBus};
use crate::types::*;
use std::sync::{Arc, Mutex};

/// Types and methods of namespace 0 used by conditions.
pub mod types {
    pub const STATE_VARIABLE_TYPE: u32 = 2755;
    pub const FINITE_STATE_VARIABLE_TYPE: u32 = 2760;
    pub const TWO_STATE_VARIABLE_TYPE: u32 = 8995;
    pub const CONDITION_VARIABLE_TYPE: u32 = 9002;
    pub const STATE_MACHINE_TYPE: u32 = 2299;
    pub const FINITE_STATE_MACHINE_TYPE: u32 = 2771;
    pub const EXCLUSIVE_LIMIT_STATE_MACHINE_TYPE: u32 = 9318;
    pub const SHELVED_STATE_MACHINE_TYPE: u32 = 2929;
    pub const TRANSITION_VARIABLE_TYPE: u32 = 2762;
    pub const FINITE_TRANSITION_VARIABLE_TYPE: u32 = 2767;
    pub const BASE_CONDITION_CLASS_TYPE: u32 = 11163;
    pub const PROCESS_CONDITION_CLASS_TYPE: u32 = 11164;

    pub const ENABLE: u32 = 9027;
    pub const DISABLE: u32 = 9028;
    pub const ADD_COMMENT: u32 = 9029;
    pub const CONDITION_REFRESH: u32 = 3875;
    pub const CONDITION_REFRESH2: u32 = 12912;
    pub const ACKNOWLEDGE: u32 = 9111;
    pub const CONFIRM: u32 = 9113;

    /// ShelvedStateMachineType: states, transitions and methods (with the
    /// 1.05 variants taking a comment, and the instance declarations of
    /// AlarmConditionType.ShelvingState).
    pub const UNSHELVED: u32 = 2930;
    pub const TIMED_SHELVED: u32 = 2932;
    pub const ONE_SHOT_SHELVED: u32 = 2933;
    pub const UNSHELVED_TO_TIMED_SHELVED: u32 = 2935;
    pub const UNSHELVED_TO_ONE_SHOT_SHELVED: u32 = 2936;
    pub const TIMED_SHELVED_TO_UNSHELVED: u32 = 2940;
    pub const TIMED_SHELVED_TO_ONE_SHOT_SHELVED: u32 = 2942;
    pub const ONE_SHOT_SHELVED_TO_UNSHELVED: u32 = 2943;
    pub const ONE_SHOT_SHELVED_TO_TIMED_SHELVED: u32 = 2945;
    pub const UNSHELVE: u32 = 2947;
    pub const ONE_SHOT_SHELVE: u32 = 2948;
    pub const TIMED_SHELVE: u32 = 2949;
    pub const TIMED_SHELVE2: u32 = 24756;
    pub const UNSHELVE2: u32 = 24758;
    pub const ONE_SHOT_SHELVE2: u32 = 24760;
    pub const ALARM_UNSHELVE: u32 = 9211;
    pub const ALARM_ONE_SHOT_SHELVE: u32 = 9212;
    pub const ALARM_TIMED_SHELVE: u32 = 9213;
    /// AlarmConditionType methods (Part 9 §5.8.2, 1.04+).
    pub const SILENCE: u32 = 16402;
    pub const SUPPRESS: u32 = 16403;
    pub const SUPPRESS2: u32 = 24316;
    pub const UNSUPPRESS: u32 = 17868;
    pub const UNSUPPRESS2: u32 = 24318;
    pub const REMOVE_FROM_SERVICE: u32 = 17869;
    pub const REMOVE_FROM_SERVICE2: u32 = 24320;
    pub const PLACE_IN_SERVICE: u32 = 17870;
    pub const PLACE_IN_SERVICE2: u32 = 24322;
    pub const RESET: u32 = 18199;
    pub const RESET2: u32 = 24324;
    /// DialogConditionType.Respond / Respond2.
    pub const RESPOND: u32 = 9069;
    pub const RESPOND2: u32 = 24312;

    /// States of ExclusiveLimitStateMachineType.
    pub const HIGH_HIGH: u32 = 9329;
    pub const HIGH: u32 = 9331;
    pub const LOW: u32 = 9333;
    pub const LOW_LOW: u32 = 9335;
}
use types::*;

pub mod codes {
    pub const BAD_EVENT_ID_UNKNOWN: u32 = 0x809A_0000;
    pub const BAD_CONDITION_ALREADY_ENABLED: u32 = 0x80CC_0000;
    pub const BAD_CONDITION_ALREADY_DISABLED: u32 = 0x8098_0000;
    pub const BAD_CONDITION_DISABLED: u32 = 0x8099_0000;
    pub const BAD_CONDITION_BRANCH_ALREADY_ACKED: u32 = 0x80CF_0000;
    pub const BAD_CONDITION_BRANCH_ALREADY_CONFIRMED: u32 = 0x80D0_0000;
    pub const BAD_METHOD_INVALID: u32 = 0x8075_0000;
    pub const BAD_ARGUMENTS_MISSING: u32 = 0x8076_0000;
    pub const BAD_TOO_MANY_ARGUMENTS: u32 = 0x80E5_0000;
    pub const BAD_INVALID_ARGUMENT: u32 = 0x80AB_0000;
    pub const BAD_CONDITION_ALREADY_SHELVED: u32 = 0x80D1_0000;
    pub const BAD_CONDITION_NOT_SHELVED: u32 = 0x80D2_0000;
    pub const BAD_SHELVING_TIME_OUT_OF_RANGE: u32 = 0x80D3_0000;
    pub const BAD_INVALID_STATE: u32 = 0x80AF_0000;
    pub const BAD_DIALOG_NOT_ACTIVE: u32 = 0x80CD_0000;
    pub const BAD_DIALOG_RESPONSE_INVALID: u32 = 0x80CE_0000;
}
use codes::*;

/// What raises the alarm.
#[derive(Clone, Debug, PartialEq)]
pub enum AlarmKind {
    /// ExclusiveLimitAlarmType: the most severe limit crossed.
    Limit { low_low: Option<f64>, low: Option<f64>, high: Option<f64>, high_high: Option<f64> },
    /// OffNormalAlarmType: active while the value differs from `normal`.
    OffNormal { normal: f64 },
    /// DialogConditionType: a question is pending while the value is
    /// negative; Respond writes the selected option index into the variable.
    Dialog { prompt: String, options: Vec<String>, default: i32, ok: i32, cancel: i32 },
}

/// The `Alarm` section of a configured item.
#[derive(Clone, Debug, PartialEq)]
pub struct AlarmConfig {
    pub kind: AlarmKind,
    pub severity: u16,
    pub message: Option<String>,
    /// Hysteresis: a limit state is left only once the value is this far
    /// back on the normal side.
    pub deadband: f64,
    /// Longest TimedShelve (ms), `None` = no limit (MaxTimeShelved).
    pub max_time_shelved_ms: Option<f64>,
    /// Stays active once triggered until Reset (LatchedState).
    pub latching: bool,
}

impl AlarmConfig {
    pub fn type_id(&self) -> u32 {
        match self.kind {
            AlarmKind::Limit { .. } => EXCLUSIVE_LIMIT_ALARM_TYPE,
            AlarmKind::OffNormal { .. } => OFF_NORMAL_ALARM_TYPE,
            AlarmKind::Dialog { .. } => DIALOG_CONDITION_TYPE,
        }
    }

    pub fn is_dialog(&self) -> bool {
        matches!(self.kind, AlarmKind::Dialog { .. })
    }

    /// Browse name suffix of the condition object.
    pub fn suffix(&self) -> &'static str {
        if self.is_dialog() {
            "Dialog"
        } else {
            "Alarm"
        }
    }
}

/// Limit states, by increasing severity on each side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Normal,
    High,
    HighHigh,
    Low,
    LowLow,
    /// Off-normal.
    Off,
}

impl Level {
    fn state(self) -> Option<(u32, &'static str)> {
        Some(match self {
            Level::HighHigh => (HIGH_HIGH, "HighHigh"),
            Level::High => (HIGH, "High"),
            Level::Low => (LOW, "Low"),
            Level::LowLow => (LOW_LOW, "LowLow"),
            _ => return None,
        })
    }
}

/// ShelvingState (Part 9 §5.8.10).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Shelving {
    Unshelved,
    /// Until this time (DateTime ticks).
    Timed(i64),
    OneShot,
}

impl Shelving {
    fn state(self) -> (u32, &'static str) {
        match self {
            Shelving::Unshelved => (UNSHELVED, "Unshelved"),
            Shelving::Timed(_) => (TIMED_SHELVED, "TimedShelved"),
            Shelving::OneShot => (ONE_SHOT_SHELVED, "OneShotShelved"),
        }
    }

    /// The transition from `self` to `to`.
    fn transition(self, to: Shelving) -> (u32, &'static str) {
        use Shelving::*;
        match (self, to) {
            (Unshelved, Timed(_)) => (UNSHELVED_TO_TIMED_SHELVED, "UnshelvedToTimedShelved"),
            (Unshelved, OneShot) => (UNSHELVED_TO_ONE_SHOT_SHELVED, "UnshelvedToOneShotShelved"),
            (Timed(_), OneShot) => (TIMED_SHELVED_TO_ONE_SHOT_SHELVED, "TimedShelvedToOneShotShelved"),
            (OneShot, Timed(_)) => (ONE_SHOT_SHELVED_TO_TIMED_SHELVED, "OneShotShelvedToTimedShelved"),
            (OneShot, _) => (ONE_SHOT_SHELVED_TO_UNSHELVED, "OneShotShelvedToUnshelved"),
            _ => (TIMED_SHELVED_TO_UNSHELVED, "TimedShelvedToUnshelved"),
        }
    }
}

/// A shelving method call.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ShelveRequest {
    /// TimedShelve, for this many milliseconds.
    Timed(f64),
    OneShot,
    Unshelve,
}

/// Branches kept per condition; the oldest goes first.
const MAX_BRANCHES: usize = 64;

/// An earlier occurrence still to be acknowledged or confirmed (Part 9
/// §4.4, §5.5.2): it keeps its state and has its own BranchId and events.
#[derive(Clone, Debug)]
struct Branch {
    id: NodeId,
    st: State,
}

static BRANCH_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Clone, Debug)]
struct State {
    enabled: bool,
    level: Level,
    acked: bool,
    confirmed: bool,
    quality: u32,
    /// Source timestamp of the last evaluated value.
    quality_ts: i64,
    last_severity: u16,
    severity: u16,
    comment: String,
    comment_ts: i64,
    user: String,
    enabled_ts: i64,
    active_ts: i64,
    acked_ts: i64,
    confirmed_ts: i64,
    /// EventId of the last event (Acknowledge, Confirm and AddComment
    /// name it).
    event_id: Box<[u8]>,
    message: String,
    shelving: Shelving,
    /// SuppressedState, OutOfServiceState, SilenceState, LatchedState:
    /// (value, transition time).
    suppressed: (bool, i64),
    out_of_service: (bool, i64),
    silenced: (bool, i64),
    latched: (bool, i64),
    /// Last shelving transition (id, name, time); id 0 = none yet.
    shelving_transition: (u32, &'static str, i64),
    branches: Vec<Branch>,
    /// DialogConditionType.LastResponse.
    last_response: i32,
}

impl State {
    fn active(&self) -> bool {
        self.level != Level::Normal || self.latched.0
    }

    /// SuppressedOrShelved (Part 9 §5.8.2).
    fn suppressed_or_shelved(&self) -> bool {
        self.shelving != Shelving::Unshelved || self.suppressed.0 || self.out_of_service.0
    }

    fn retain(&self) -> bool {
        self.enabled && (self.active() || !self.acked || !self.confirmed)
    }

    /// A branch is kept until acknowledged and confirmed.
    fn retain_branch(&self) -> bool {
        self.enabled && (!self.acked || !self.confirmed)
    }

    fn set_shelving(&mut self, to: Shelving, now: i64) {
        let (id, name) = self.shelving.transition(to);
        self.shelving = to;
        self.shelving_transition = (id, name, now);
    }
}

pub struct Condition {
    pub id: NodeId,
    pub source: NodeId,
    pub source_name: String,
    cfg: Mutex<AlarmConfig>,
    st: Mutex<State>,
    bus: Arc<EventBus>,
}

fn two_state(on: bool, yes: &str, no: &str) -> Variant {
    Variant::LocalizedText(Box::new(LocalizedText::new(if on { yes } else { no })))
}

fn text(s: &str) -> Variant {
    Variant::LocalizedText(Box::new(LocalizedText::new(s)))
}

impl Condition {
    pub fn new(id: NodeId, source: NodeId, source_name: &str, cfg: AlarmConfig, bus: Arc<EventBus>) -> Condition {
        let now = now_ticks();
        let st = State {
            enabled: true,
            level: Level::Normal,
            acked: true,
            confirmed: true,
            quality: status::GOOD,
            quality_ts: now,
            last_severity: cfg.severity,
            severity: cfg.severity,
            comment: String::new(),
            comment_ts: now,
            user: String::new(),
            enabled_ts: now,
            active_ts: now,
            acked_ts: now,
            confirmed_ts: now,
            event_id: Box::new([]),
            message: String::new(),
            shelving: Shelving::Unshelved,
            suppressed: (false, now),
            out_of_service: (false, now),
            silenced: (false, now),
            latched: (false, now),
            shelving_transition: (0, "", now),
            branches: Vec::new(),
            last_response: -1,
        };
        Condition { id, source, source_name: source_name.to_string(), cfg: Mutex::new(cfg), st: Mutex::new(st), bus }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn config(&self) -> AlarmConfig {
        self.cfg.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// New limits or severity from a configuration reload.
    pub fn set_config(&self, cfg: AlarmConfig) {
        *self.cfg.lock().unwrap_or_else(|e| e.into_inner()) = cfg;
    }

    pub fn type_id(&self) -> u32 {
        self.config().type_id()
    }

    /// The condition's state (or a branch's, with its BranchId) as an event
    /// (a new EventId unless `keep_id`).
    fn event(&self, st: &mut State, cfg: &AlarmConfig, keep_id: bool, branch: Option<&NodeId>) -> Event {
        let mut ev = Event::new(cfg.type_id(), self.source.clone(), &self.source_name, &st.message, st.severity);
        if keep_id && !st.event_id.is_empty() {
            for f in &mut ev.fields {
                if f.0 == EVENT_ID {
                    f.1 = Variant::ByteString(Some(st.event_id.clone()));
                }
            }
        } else {
            st.event_id = ev.event_id().into();
        }
        let active = st.active();
        let ev = ev
            .with(CONDITION_ID, Variant::NodeId(Box::new(self.id.clone())))
            .with(CONDITION_CLASS_ID, Variant::NodeId(Box::new(NodeId::ns0(PROCESS_CONDITION_CLASS_TYPE))))
            .with(CONDITION_CLASS_NAME, text("ProcessConditionClassType"))
            .with(CONDITION_NAME, Variant::string(&format!("{}{}", self.source_name, cfg.suffix())))
            .with(BRANCH_ID, Variant::NodeId(Box::new(branch.cloned().unwrap_or(NodeId::NULL))))
            .with(RETAIN, Variant::Boolean(if branch.is_some() { st.retain_branch() } else { st.retain() }))
            .with(ENABLED_STATE, two_state(st.enabled, "Enabled", "Disabled"))
            .with(ENABLED_STATE_ID, Variant::Boolean(st.enabled))
            .with(ENABLED_STATE_TRANSITION_TIME, Variant::DateTime(st.enabled_ts))
            .with(QUALITY, Variant::StatusCode(st.quality))
            .with(QUALITY_SOURCE_TIMESTAMP, Variant::DateTime(st.quality_ts))
            .with(LAST_SEVERITY, Variant::UInt16(st.last_severity))
            .with(LAST_SEVERITY_SOURCE_TIMESTAMP, Variant::DateTime(st.quality_ts))
            .with(COMMENT, text(&st.comment))
            .with(COMMENT_SOURCE_TIMESTAMP, Variant::DateTime(st.comment_ts))
            .with(CONDITION_CLIENT_USER_ID, Variant::string(&st.user))
            // Clients that select every field on BaseEventType (asyncua)
            // resolve "ClientUserId" to the AuditEventType declaration.
            .with(CLIENT_USER_ID, Variant::string(&st.user));
        if let AlarmKind::Dialog { prompt, options, default, ok, cancel } = &cfg.kind {
            let set = options.iter().map(|o| text(o)).collect();
            return ev
                .with(DIALOG_STATE, two_state(active, "Active", "Inactive"))
                .with(DIALOG_STATE_ID, Variant::Boolean(active))
                .with(DIALOG_STATE_TRANSITION_TIME, Variant::DateTime(st.active_ts))
                .with(PROMPT, text(prompt))
                .with(
                    RESPONSE_OPTION_SET,
                    Variant::Array(Box::new(VariantArray { type_id: builtin::LOCALIZEDTEXT, items: set, dims: None })),
                )
                .with(DEFAULT_RESPONSE, Variant::Int32(*default))
                .with(OK_RESPONSE, Variant::Int32(*ok))
                .with(CANCEL_RESPONSE, Variant::Int32(*cancel))
                .with(LAST_RESPONSE, Variant::Int32(st.last_response));
        }
        let ev = ev
            .with(ACKED_STATE, two_state(st.acked, "Acknowledged", "Unacknowledged"))
            .with(ACKED_STATE_ID, Variant::Boolean(st.acked))
            .with(ACKED_STATE_TRANSITION_TIME, Variant::DateTime(st.acked_ts))
            .with(CONFIRMED_STATE, two_state(st.confirmed, "Confirmed", "Unconfirmed"))
            .with(CONFIRMED_STATE_ID, Variant::Boolean(st.confirmed))
            .with(CONFIRMED_STATE_TRANSITION_TIME, Variant::DateTime(st.confirmed_ts))
            .with(ACTIVE_STATE, two_state(active, "Active", "Inactive"))
            .with(ACTIVE_STATE_ID, Variant::Boolean(active))
            .with(ACTIVE_STATE_TRANSITION_TIME, Variant::DateTime(st.active_ts))
            .with(INPUT_NODE, Variant::NodeId(Box::new(self.source.clone())))
            .with(SUPPRESSED_OR_SHELVED, Variant::Boolean(st.suppressed_or_shelved()))
            .with(SUPPRESSED_STATE, two_state(st.suppressed.0, "Suppressed", "Unsuppressed"))
            .with(SUPPRESSED_STATE_ID, Variant::Boolean(st.suppressed.0))
            .with(SUPPRESSED_STATE_TRANSITION_TIME, Variant::DateTime(st.suppressed.1))
            .with(OUT_OF_SERVICE_STATE, two_state(st.out_of_service.0, "Out of Service", "In Service"))
            .with(OUT_OF_SERVICE_STATE_ID, Variant::Boolean(st.out_of_service.0))
            .with(OUT_OF_SERVICE_STATE_TRANSITION_TIME, Variant::DateTime(st.out_of_service.1))
            .with(SILENCE_STATE, two_state(st.silenced.0, "Silenced", "Not Silenced"))
            .with(SILENCE_STATE_ID, Variant::Boolean(st.silenced.0))
            .with(SILENCE_STATE_TRANSITION_TIME, Variant::DateTime(st.silenced.1));
        let ev = if cfg.latching {
            ev.with(LATCHED_STATE, two_state(st.latched.0, "Latched", "Unlatched"))
                .with(LATCHED_STATE_ID, Variant::Boolean(st.latched.0))
                .with(LATCHED_STATE_TRANSITION_TIME, Variant::DateTime(st.latched.1))
        } else {
            ev
        };
        let (state_id, state_name) = st.shelving.state();
        let unshelve_ms = match st.shelving {
            Shelving::Timed(until) => (until - now_ticks()).max(0) as f64 / 10_000.0,
            _ => 0.0,
        };
        let mut ev = ev
            .with(SHELVING_STATE_CURRENT_STATE, text(state_name))
            .with(SHELVING_STATE_CURRENT_STATE_ID, Variant::NodeId(Box::new(NodeId::ns0(state_id))))
            .with(SHELVING_STATE_UNSHELVE_TIME, Variant::Double(unshelve_ms));
        let (tid, tname, tts) = st.shelving_transition;
        if tid != 0 {
            ev = ev
                .with(SHELVING_STATE_LAST_TRANSITION, text(tname))
                .with(SHELVING_STATE_LAST_TRANSITION_ID, Variant::NodeId(Box::new(NodeId::ns0(tid))))
                .with(SHELVING_STATE_LAST_TRANSITION_TIME, Variant::DateTime(tts));
        }
        if let Some(ms) = cfg.max_time_shelved_ms {
            ev = ev.with(MAX_TIME_SHELVED, Variant::Double(ms));
        }
        let effective = match st.level.state() {
            Some((_, name)) => format!("{name} active"),
            None if active => "Active".into(),
            None => "Inactive".into(),
        };
        let ev = ev.with(ACTIVE_STATE_EFFECTIVE_DISPLAY_NAME, text(&effective));
        match &cfg.kind {
            AlarmKind::Limit { low_low, low, high, high_high } => {
                let mut ev = ev;
                for (decl, v) in
                    [(HIGH_HIGH_LIMIT, high_high), (HIGH_LIMIT, high), (LOW_LIMIT, low), (LOW_LOW_LIMIT, low_low)]
                {
                    if let Some(v) = v {
                        ev = ev.with(decl, Variant::Double(*v));
                    }
                }
                match st.level.state() {
                    Some((id, name)) => ev
                        .with(LIMIT_STATE_CURRENT_STATE, text(name))
                        .with(LIMIT_STATE_CURRENT_STATE_ID, Variant::NodeId(Box::new(NodeId::ns0(id)))),
                    None => ev
                        .with(LIMIT_STATE_CURRENT_STATE, text(""))
                        .with(LIMIT_STATE_CURRENT_STATE_ID, Variant::NodeId(Box::new(NodeId::NULL))),
                }
            }
            AlarmKind::OffNormal { .. } => ev.with(NORMAL_STATE, Variant::NodeId(Box::new(self.source.clone()))),
            AlarmKind::Dialog { .. } => ev, // returned above
        }
    }

    fn emit(&self, st: &mut State, cfg: &AlarmConfig) {
        st.last_severity = st.severity;
        let ev = self.event(st, cfg, false, None);
        if st.enabled {
            self.bus.emit(ev);
        }
    }

    /// Level of `f` given the current level (deadband applied when moving
    /// back towards normal).
    fn level_of(cfg: &AlarmConfig, f: f64, cur: Level) -> Level {
        match &cfg.kind {
            AlarmKind::Dialog { .. } => {
                if f < 0.0 {
                    Level::Off
                } else {
                    Level::Normal
                }
            }
            AlarmKind::OffNormal { normal } => {
                if f != *normal {
                    Level::Off
                } else {
                    Level::Normal
                }
            }
            AlarmKind::Limit { low_low, low, high, high_high } => {
                let db = cfg.deadband;
                let above = |l: &Option<f64>, keep: bool| l.is_some_and(|l| f >= l || (keep && f > l - db));
                let below = |l: &Option<f64>, keep: bool| l.is_some_and(|l| f <= l || (keep && f < l + db));
                if above(high_high, cur == Level::HighHigh) {
                    Level::HighHigh
                } else if above(high, matches!(cur, Level::High | Level::HighHigh)) {
                    Level::High
                } else if below(low_low, cur == Level::LowLow) {
                    Level::LowLow
                } else if below(low, matches!(cur, Level::Low | Level::LowLow)) {
                    Level::Low
                } else {
                    Level::Normal
                }
            }
        }
    }

    /// Evaluates a new value of the source variable.
    pub fn evaluate(&self, value: &Variant, code: u32, source_ts: i64) {
        let f = match value {
            Variant::Boolean(b) => *b as u8 as f64,
            v => match crate::value::variant_as_f64(v) {
                Some(f) => f,
                None => return,
            },
        };
        let cfg = self.config();
        let mut st = self.lock();
        let quality = code & 0xFFFF_0000;
        let quality_changed = quality != st.quality;
        st.quality = quality;
        st.quality_ts = source_ts;
        // A bad value says nothing about the process: keep the state.
        let level = if status::is_good(code) || code & 0xC000_0000 == 0x4000_0000 {
            Self::level_of(&cfg, f, st.level)
        } else {
            st.level
        };
        if level == st.level && !quality_changed {
            return;
        }
        if let AlarmKind::Dialog { prompt, options, .. } = &cfg.kind {
            let was = st.level;
            st.level = level;
            st.severity = cfg.severity;
            if level != was {
                st.active_ts = now_ticks();
            }
            st.message = if level == Level::Off {
                prompt.clone()
            } else {
                // Answered (Respond, or the application wrote the answer).
                st.last_response = f as i32;
                let answer = options.get(f as usize).map_or("", String::as_str);
                format!("{}: {answer}", cfg.message.as_deref().unwrap_or(prompt))
            };
            self.emit(&mut st, &cfg);
            return;
        }
        let was = st.level;
        let now = now_ticks();
        let rank = |l: Level| match l {
            Level::Normal => 0,
            Level::High | Level::Low | Level::Off => 1,
            Level::HighHigh | Level::LowLow => 2,
        };
        let new_occurrence =
            level != was && (rank(level) > rank(was) || (rank(level) > 0 && rank(was) > 0 && rank(level) >= rank(was)));
        if was == Level::Normal && level != Level::Normal && st.enabled && (!st.acked || !st.confirmed) {
            // Active again while the previous occurrence still waits for
            // its operator: that occurrence becomes a branch. (A more
            // severe limit is the same occurrence.)
            self.branch(&mut st, &cfg);
        }
        st.level = level;
        if new_occurrence {
            // A new occurrence sounds again.
            st.silenced = (false, now);
            if cfg.latching && !st.latched.0 {
                st.latched = (true, now);
            }
        }
        if level == Level::Normal && was != Level::Normal && st.shelving == Shelving::OneShot {
            // A one-shot shelve lasts until the alarm returns to normal.
            st.set_shelving(Shelving::Unshelved, now);
        }
        if level != was {
            st.active_ts = now;
            if new_occurrence {
                // Newly active or more severe: to be acknowledged again.
                st.acked = false;
                st.confirmed = false;
                st.acked_ts = now;
                st.confirmed_ts = now;
            }
        }
        st.severity = cfg.severity;
        st.message = match (&cfg.message, level.state(), level) {
            (Some(m), _, Level::Normal) => format!("{m}: back to normal"),
            (Some(m), Some((_, name)), _) => format!("{m}: {name}"),
            (Some(m), None, _) => m.clone(),
            (None, _, Level::Normal) => format!("{} back to normal", self.source_name),
            (None, Some((_, name)), _) => format!("{} {name} limit", self.source_name),
            (None, None, _) => format!("{} off normal", self.source_name),
        };
        self.emit(&mut st, &cfg);
    }

    /// Copies the current state into a new branch and reports it.
    fn branch(&self, st: &mut State, cfg: &AlarmConfig) {
        let ns = self.id.namespace();
        let id = NodeId::String(
            ns,
            format!("__branch/{}", BRANCH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)).into(),
        );
        let branches = std::mem::take(&mut st.branches);
        let mut b = st.clone();
        st.branches = branches;
        let ev = self.event(&mut b, cfg, false, Some(&id));
        if st.branches.len() >= MAX_BRANCHES {
            st.branches.remove(0);
        }
        st.branches.push(Branch { id, st: b });
        self.bus.emit(ev);
    }

    /// Retained conditions and their branches are reported by
    /// ConditionRefresh.
    fn refresh_events(&self, target: (u32, u32), out: &mut Vec<Event>) {
        let cfg = self.config();
        let mut st = self.lock();
        let st = &mut *st;
        if st.retain() {
            let mut ev = self.event(st, &cfg, true, None);
            ev.target = Some(target);
            out.push(ev);
        }
        for b in &mut st.branches {
            if b.st.retain_branch() {
                let mut ev = self.event(&mut b.st, &cfg, true, Some(&b.id));
                ev.target = Some(target);
                out.push(ev);
            }
        }
    }

    /// Applies `f` to the state (or the branch) whose last event is
    /// `event_id`, and reports the result. A branch acknowledged and
    /// confirmed is reported once more (Retain false) and deleted.
    fn on_event(&self, event_id: &[u8], user: &str, f: impl FnOnce(&mut State) -> Result<(), u32>) -> Result<(), u32> {
        let cfg = self.config();
        let mut st = self.lock();
        if !st.enabled {
            return Err(BAD_CONDITION_DISABLED);
        }
        if !st.event_id.is_empty() && *st.event_id == *event_id {
            f(&mut st)?;
            st.user = user.to_string();
            self.emit(&mut st, &cfg);
            return Ok(());
        }
        let i = st.branches.iter().position(|b| *b.st.event_id == *event_id).ok_or(BAD_EVENT_ID_UNKNOWN)?;
        let b = &mut st.branches[i];
        f(&mut b.st)?;
        b.st.user = user.to_string();
        b.st.last_severity = b.st.severity;
        let ev = self.event(&mut b.st, &cfg, false, Some(&b.id));
        if !b.st.retain_branch() {
            st.branches.remove(i);
        }
        self.bus.emit(ev);
        Ok(())
    }

    /// TimedShelve, OneShotShelve, Unshelve (and their 1.05 variants with a
    /// comment).
    pub fn shelve(&self, req: ShelveRequest, comment: &str, user: &str) -> Result<(), u32> {
        let cfg = self.config();
        let mut st = self.lock();
        if !st.enabled {
            return Err(BAD_CONDITION_DISABLED);
        }
        let now = now_ticks();
        let to = match (st.shelving, req) {
            (Shelving::Unshelved, ShelveRequest::Unshelve) => return Err(BAD_CONDITION_NOT_SHELVED),
            (Shelving::Timed(_), ShelveRequest::Timed(_)) | (Shelving::OneShot, ShelveRequest::OneShot) => {
                return Err(BAD_CONDITION_ALREADY_SHELVED)
            }
            (_, ShelveRequest::Timed(ms)) => {
                if !(ms > 0.0 && ms.is_finite()) || cfg.max_time_shelved_ms.is_some_and(|m| ms > m) {
                    return Err(BAD_SHELVING_TIME_OUT_OF_RANGE);
                }
                Shelving::Timed(now.saturating_add((ms * 10_000.0) as i64))
            }
            (_, ShelveRequest::OneShot) => Shelving::OneShot,
            (_, ShelveRequest::Unshelve) => Shelving::Unshelved,
        };
        st.set_shelving(to, now);
        st.user = user.to_string();
        if !comment.is_empty() {
            st.comment = comment.to_string();
            st.comment_ts = now;
        }
        st.message = match to {
            Shelving::Unshelved => format!("{}Alarm unshelved", self.source_name),
            Shelving::OneShot => format!("{}Alarm shelved until it returns to normal", self.source_name),
            Shelving::Timed(_) => format!("{}Alarm shelved", self.source_name),
        };
        self.emit(&mut st, &cfg);
        Ok(())
    }

    /// Respond / Respond2: checks the answer (the caller then writes it into
    /// the variable, which closes the dialog and reports it).
    pub fn respond(&self, selected: i32, comment: &str, user: &str) -> Result<(), u32> {
        let cfg = self.config();
        let AlarmKind::Dialog { options, .. } = &cfg.kind else { return Err(BAD_METHOD_INVALID) };
        let mut st = self.lock();
        if !st.enabled {
            return Err(BAD_CONDITION_DISABLED);
        }
        if st.level != Level::Off {
            return Err(BAD_DIALOG_NOT_ACTIVE);
        }
        if selected < 0 || selected as usize >= options.len() {
            return Err(BAD_DIALOG_RESPONSE_INVALID);
        }
        st.user = user.to_string();
        if !comment.is_empty() {
            st.comment = comment.to_string();
            st.comment_ts = now_ticks();
        }
        Ok(())
    }

    /// Suppress / Unsuppress, RemoveFromService / PlaceInService, Silence
    /// and Reset (Part 9 §5.8.2). Setting a state it is already in changes
    /// nothing and reports nothing.
    pub fn set_state(&self, method: u32, comment: &str, user: &str) -> Result<(), u32> {
        let cfg = self.config();
        let mut st = self.lock();
        if !st.enabled {
            return Err(BAD_CONDITION_DISABLED);
        }
        let now = now_ticks();
        let name = &self.source_name;
        let (slot, on, message) = match method {
            SUPPRESS | SUPPRESS2 => (&mut st.suppressed, true, format!("{name}Alarm suppressed")),
            UNSUPPRESS | UNSUPPRESS2 => (&mut st.suppressed, false, format!("{name}Alarm unsuppressed")),
            REMOVE_FROM_SERVICE | REMOVE_FROM_SERVICE2 => {
                (&mut st.out_of_service, true, format!("{name}Alarm removed from service"))
            }
            PLACE_IN_SERVICE | PLACE_IN_SERVICE2 => {
                (&mut st.out_of_service, false, format!("{name}Alarm placed in service"))
            }
            SILENCE => (&mut st.silenced, true, format!("{name}Alarm silenced")),
            _ => {
                // Reset: only a latched alarm whose cause has cleared.
                if !st.latched.0 || st.level != Level::Normal {
                    return Err(BAD_INVALID_STATE);
                }
                (&mut st.latched, false, format!("{name}Alarm reset"))
            }
        };
        if slot.0 == on {
            return Ok(());
        }
        *slot = (on, now);
        st.message = message;
        st.user = user.to_string();
        if !comment.is_empty() {
            st.comment = comment.to_string();
            st.comment_ts = now;
        }
        self.emit(&mut st, &cfg);
        Ok(())
    }

    /// (suppressed, out of service, silenced, latched) for tests.
    pub fn states(&self) -> (bool, bool, bool, bool) {
        let st = self.lock();
        (st.suppressed.0, st.out_of_service.0, st.silenced.0, st.latched.0)
    }

    /// Ends an expired TimedShelve.
    fn tick(&self, now: i64) {
        let cfg = self.config();
        let mut st = self.lock();
        if let Shelving::Timed(until) = st.shelving {
            if until <= now {
                st.set_shelving(Shelving::Unshelved, now);
                st.message = format!("{}Alarm shelving time expired", self.source_name);
                self.emit(&mut st, &cfg);
            }
        }
    }

    pub fn enable(&self, on: bool, user: &str) -> Result<(), u32> {
        let cfg = self.config();
        let mut st = self.lock();
        if st.enabled == on {
            return Err(if on { BAD_CONDITION_ALREADY_ENABLED } else { BAD_CONDITION_ALREADY_DISABLED });
        }
        st.enabled = on;
        st.enabled_ts = now_ticks();
        st.user = user.to_string();
        st.message = format!("{}Alarm {}", self.source_name, if on { "enabled" } else { "disabled" });
        // The disabling event is reported (with Retain false) before the
        // condition goes quiet.
        st.last_severity = st.severity;
        let ev = self.event(&mut st, &cfg, false, None);
        if !on {
            // A disabled condition has no branches (Part 9 §5.5.4).
            st.branches.clear();
        }
        self.bus.emit(ev);
        Ok(())
    }

    pub fn add_comment(&self, event_id: &[u8], comment: &str, user: &str) -> Result<(), u32> {
        self.on_event(event_id, user, |st| {
            st.comment = comment.to_string();
            st.comment_ts = now_ticks();
            Ok(())
        })
    }

    pub fn acknowledge(&self, event_id: &[u8], comment: &str, user: &str) -> Result<(), u32> {
        self.on_event(event_id, user, |st| {
            if st.acked {
                return Err(BAD_CONDITION_BRANCH_ALREADY_ACKED);
            }
            st.acked = true;
            st.acked_ts = now_ticks();
            if !comment.is_empty() {
                st.comment = comment.to_string();
                st.comment_ts = st.acked_ts;
            }
            Ok(())
        })
    }

    pub fn confirm(&self, event_id: &[u8], comment: &str, user: &str) -> Result<(), u32> {
        self.on_event(event_id, user, |st| {
            if st.confirmed {
                return Err(BAD_CONDITION_BRANCH_ALREADY_CONFIRMED);
            }
            st.confirmed = true;
            st.confirmed_ts = now_ticks();
            if !comment.is_empty() {
                st.comment = comment.to_string();
                st.comment_ts = st.confirmed_ts;
            }
            Ok(())
        })
    }

    /// Branches waiting for acknowledgement or confirmation.
    pub fn branch_count(&self) -> usize {
        self.lock().branches.len()
    }

    /// The condition is shelved.
    pub fn shelved(&self) -> bool {
        self.lock().shelving != Shelving::Unshelved
    }

    /// (active, acked, confirmed, enabled) for tests and diagnostics.
    pub fn summary(&self) -> (bool, bool, bool, bool) {
        let st = self.lock();
        (st.active(), st.acked, st.confirmed, st.enabled)
    }
}

/// Conditions by ConditionId, shared by every address space snapshot so that
/// their state survives configuration reloads.
#[derive(Default)]
pub struct Alarms {
    map: Mutex<FxHashMap<NodeId, Arc<Condition>>>,
}

impl Alarms {
    fn lock(&self) -> std::sync::MutexGuard<'_, FxHashMap<NodeId, Arc<Condition>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The condition `id`, created or reconfigured. Returns it and whether
    /// it is new.
    pub fn upsert(
        &self,
        id: NodeId,
        source: NodeId,
        source_name: &str,
        cfg: AlarmConfig,
        bus: &Arc<EventBus>,
    ) -> (Arc<Condition>, bool) {
        let mut map = self.lock();
        if let Some(c) = map.get(&id) {
            if c.type_id() == cfg.type_id() && c.source == source {
                c.set_config(cfg);
                return (c.clone(), false);
            }
        }
        let c = Arc::new(Condition::new(id.clone(), source, source_name, cfg, bus.clone()));
        map.insert(id, c.clone());
        (c, true)
    }

    /// Drops the conditions not in `keep`.
    pub fn retain(&self, keep: &[NodeId]) {
        let keep: std::collections::HashSet<&NodeId, FxBuild> = keep.iter().collect();
        self.lock().retain(|id, _| keep.contains(id));
    }

    pub fn get(&self, id: &NodeId) -> Option<Arc<Condition>> {
        self.lock().get(id).cloned()
    }

    /// Ends expired TimedShelves (called every second).
    pub fn tick(&self, now: i64) {
        let conds: Vec<Arc<Condition>> = self.lock().values().cloned().collect();
        for c in conds {
            c.tick(now);
        }
    }

    /// ConditionRefresh (Part 9 §5.5.7): RefreshStart, every retained
    /// condition, RefreshEnd, for one subscription (or one of its items).
    pub fn refresh(&self, bus: &EventBus, target: (u32, u32)) {
        let server = NodeId::ns0(ids::SERVER);
        let mut start = Event::new(REFRESH_START_EVENT_TYPE, server.clone(), "Server", "", 100);
        start.target = Some(target);
        bus.emit(start);
        let conds: Vec<Arc<Condition>> = self.lock().values().cloned().collect();
        let mut events = Vec::new();
        for c in conds {
            c.refresh_events(target, &mut events);
        }
        for ev in events {
            bus.emit(ev);
        }
        let mut end = Event::new(REFRESH_END_EVENT_TYPE, server, "Server", "", 100);
        end.target = Some(target);
        bus.emit(end);
    }
}

/// NodeId suffix of a condition's ShelvingState object.
pub const SHELVING_STATE_SUFFIX: &str = "/ShelvingState";

/// Method result: outputs, or (status, per argument results).
pub type MethodResult = Result<Vec<Variant>, (u32, Vec<u32>)>;

/// The session calling a condition method.
pub struct Caller<'a> {
    /// Identity recorded as ClientUserId.
    pub user: &'a str,
    /// Enable / Disable need write rights.
    pub can_write: bool,
    /// Checks that a subscription (and event item) belongs to the session
    /// (ConditionRefresh, ConditionRefresh2).
    pub refresh: &'a mut dyn FnMut(u32, Option<u32>) -> Result<(), u32>,
    /// Writes a value into a variable (the answer of a dialog).
    pub write: &'a mut dyn FnMut(&NodeId, Variant),
}

/// A condition method of the Call service, `None` for other methods.
pub fn call(
    alarms: &Alarms,
    bus: &EventBus,
    object: &NodeId,
    method: &NodeId,
    args: &[Variant],
    caller: Caller<'_>,
) -> Option<MethodResult> {
    let Caller { user, can_write, refresh, write } = caller;
    let m = method.as_ns0()?;
    let shelving = [
        TIMED_SHELVE,
        ONE_SHOT_SHELVE,
        UNSHELVE,
        TIMED_SHELVE2,
        ONE_SHOT_SHELVE2,
        UNSHELVE2,
        ALARM_TIMED_SHELVE,
        ALARM_ONE_SHOT_SHELVE,
        ALARM_UNSHELVE,
    ];
    let states = [
        SILENCE,
        SUPPRESS,
        SUPPRESS2,
        UNSUPPRESS,
        UNSUPPRESS2,
        REMOVE_FROM_SERVICE,
        REMOVE_FROM_SERVICE2,
        PLACE_IN_SERVICE,
        PLACE_IN_SERVICE2,
        RESET,
        RESET2,
    ];
    if ![ENABLE, DISABLE, ADD_COMMENT, ACKNOWLEDGE, CONFIRM, CONDITION_REFRESH, CONDITION_REFRESH2].contains(&m)
        && !shelving.contains(&m)
        && !states.contains(&m)
        && !matches!(m, RESPOND | RESPOND2)
    {
        return None;
    }
    let fail = |code| Some(Err((code, Vec::new())));
    if shelving.contains(&m) {
        // Called on the condition's ShelvingState object (or the condition).
        let cond = match object {
            NodeId::String(ns, s) => match s.strip_suffix(SHELVING_STATE_SUFFIX) {
                Some(c) => NodeId::String(*ns, c.into()),
                None => object.clone(),
            },
            _ => object.clone(),
        };
        let Some(c) = alarms.get(&cond) else {
            return fail(if object.as_ns0().is_some() { BAD_METHOD_INVALID } else { status::BAD_NODE_ID_UNKNOWN });
        };
        let timed = matches!(m, TIMED_SHELVE | TIMED_SHELVE2 | ALARM_TIMED_SHELVE);
        let with_comment = matches!(m, TIMED_SHELVE2 | ONE_SHOT_SHELVE2 | UNSHELVE2);
        let want = timed as usize + with_comment as usize;
        if args.len() < want {
            return fail(BAD_ARGUMENTS_MISSING);
        }
        if args.len() > want {
            return fail(BAD_TOO_MANY_ARGUMENTS);
        }
        let mut results = vec![status::GOOD; want];
        let ms = if timed {
            match &args[0] {
                Variant::Double(x) => *x,
                _ => {
                    results[0] = status::BAD_TYPE_MISMATCH;
                    return Some(Err((BAD_INVALID_ARGUMENT, results)));
                }
            }
        } else {
            0.0
        };
        let comment = if with_comment {
            match &args[want - 1] {
                Variant::LocalizedText(t) => t.text.as_deref().unwrap_or(""),
                Variant::Empty => "",
                _ => {
                    results[want - 1] = status::BAD_TYPE_MISMATCH;
                    return Some(Err((BAD_INVALID_ARGUMENT, results)));
                }
            }
        } else {
            ""
        };
        let req = match m {
            TIMED_SHELVE | TIMED_SHELVE2 | ALARM_TIMED_SHELVE => ShelveRequest::Timed(ms),
            ONE_SHOT_SHELVE | ONE_SHOT_SHELVE2 | ALARM_ONE_SHOT_SHELVE => ShelveRequest::OneShot,
            _ => ShelveRequest::Unshelve,
        };
        return Some(c.shelve(req, comment, user).map(|_| Vec::new()).map_err(|code| (code, Vec::new())));
    }
    if matches!(m, CONDITION_REFRESH | CONDITION_REFRESH2) {
        if object.as_ns0() != Some(CONDITION_TYPE) {
            return fail(BAD_METHOD_INVALID);
        }
        let want = if m == CONDITION_REFRESH { 1 } else { 2 };
        if args.len() < want {
            return fail(BAD_ARGUMENTS_MISSING);
        }
        if args.len() > want {
            return fail(BAD_TOO_MANY_ARGUMENTS);
        }
        let id = |v: &Variant| match v {
            Variant::UInt32(x) => Ok(*x),
            _ => Err(()),
        };
        let (sub, item) = match (id(&args[0]), args.get(1).map(id)) {
            (Ok(s), None) => (s, None),
            (Ok(s), Some(Ok(i))) => (s, Some(i)),
            (Err(_), _) => return Some(Err((BAD_INVALID_ARGUMENT, vec![status::BAD_TYPE_MISMATCH]))),
            (_, Some(Err(_))) => {
                return Some(Err((BAD_INVALID_ARGUMENT, vec![status::GOOD, status::BAD_TYPE_MISMATCH])))
            }
        };
        if let Err(code) = refresh(sub, item) {
            return fail(code);
        }
        alarms.refresh(bus, (sub, item.unwrap_or(0)));
        return Some(Ok(Vec::new()));
    }
    let Some(c) = alarms.get(object) else {
        return fail(if object.as_ns0().is_some() { BAD_METHOD_INVALID } else { status::BAD_NODE_ID_UNKNOWN });
    };
    if matches!(m, RESPOND | RESPOND2) {
        let want = if m == RESPOND { 1 } else { 2 };
        if args.len() < want {
            return fail(BAD_ARGUMENTS_MISSING);
        }
        if args.len() > want {
            return fail(BAD_TOO_MANY_ARGUMENTS);
        }
        let mut results = vec![status::GOOD; want];
        let Variant::Int32(selected) = args[0] else {
            results[0] = status::BAD_TYPE_MISMATCH;
            return Some(Err((BAD_INVALID_ARGUMENT, results)));
        };
        let comment = match args.get(1) {
            None | Some(Variant::Empty) => "",
            Some(Variant::LocalizedText(t)) => t.text.as_deref().unwrap_or(""),
            Some(_) => {
                results[1] = status::BAD_TYPE_MISMATCH;
                return Some(Err((BAD_INVALID_ARGUMENT, results)));
            }
        };
        if let Err(code) = c.respond(selected, comment, user) {
            return fail(code);
        }
        write(&c.source, Variant::Int32(selected));
        return Some(Ok(Vec::new()));
    }
    if states.contains(&m) {
        let with_comment = matches!(m, SUPPRESS2 | UNSUPPRESS2 | REMOVE_FROM_SERVICE2 | PLACE_IN_SERVICE2 | RESET2);
        let want = with_comment as usize;
        if args.len() < want {
            return fail(BAD_ARGUMENTS_MISSING);
        }
        if args.len() > want {
            return fail(BAD_TOO_MANY_ARGUMENTS);
        }
        let comment = match args.first() {
            None | Some(Variant::Empty) => "",
            Some(Variant::LocalizedText(t)) => t.text.as_deref().unwrap_or(""),
            Some(_) => return Some(Err((BAD_INVALID_ARGUMENT, vec![status::BAD_TYPE_MISMATCH]))),
        };
        // Taking an alarm out of the operator's view needs write rights.
        if !matches!(m, SILENCE | RESET | RESET2) && !can_write {
            return fail(status::BAD_USER_ACCESS_DENIED);
        }
        return Some(c.set_state(m, comment, user).map(|_| Vec::new()).map_err(|code| (code, Vec::new())));
    }
    let result = match m {
        ENABLE | DISABLE => {
            if !args.is_empty() {
                return fail(BAD_TOO_MANY_ARGUMENTS);
            }
            if !can_write {
                return fail(status::BAD_USER_ACCESS_DENIED);
            }
            c.enable(m == ENABLE, user)
        }
        _ => {
            if args.len() < 2 {
                return fail(BAD_ARGUMENTS_MISSING);
            }
            if args.len() > 2 {
                return fail(BAD_TOO_MANY_ARGUMENTS);
            }
            let event_id = match &args[0] {
                Variant::ByteString(Some(b)) => &b[..],
                _ => return Some(Err((BAD_INVALID_ARGUMENT, vec![status::BAD_TYPE_MISMATCH, status::GOOD]))),
            };
            let comment = match &args[1] {
                Variant::LocalizedText(t) => t.text.as_deref().unwrap_or(""),
                Variant::Empty => "",
                _ => return Some(Err((BAD_INVALID_ARGUMENT, vec![status::GOOD, status::BAD_TYPE_MISMATCH]))),
            };
            match m {
                ADD_COMMENT => c.add_comment(event_id, comment, user),
                ACKNOWLEDGE => c.acknowledge(event_id, comment, user),
                _ => c.confirm(event_id, comment, user),
            }
        }
    };
    Some(result.map(|_| Vec::new()).map_err(|code| (code, Vec::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> AlarmConfig {
        AlarmConfig {
            kind: AlarmKind::Limit { low_low: Some(0.0), low: Some(10.0), high: Some(80.0), high_high: Some(95.0) },
            severity: 700,
            message: None,
            deadband: 2.0,
            max_time_shelved_ms: Some(60_000.0),
            latching: false,
        }
    }

    #[test]
    fn levels_with_deadband() {
        let c = limits();
        let l = |f, cur| Condition::level_of(&c, f, cur);
        assert_eq!(l(50.0, Level::Normal), Level::Normal);
        assert_eq!(l(85.0, Level::Normal), Level::High);
        assert_eq!(l(99.0, Level::High), Level::HighHigh);
        assert_eq!(l(94.0, Level::HighHigh), Level::HighHigh); // within the deadband
        assert_eq!(l(92.0, Level::HighHigh), Level::High);
        assert_eq!(l(79.0, Level::High), Level::High);
        assert_eq!(l(77.0, Level::High), Level::Normal);
        assert_eq!(l(5.0, Level::Normal), Level::Low);
        assert_eq!(l(-1.0, Level::Low), Level::LowLow);
        let off = AlarmConfig { kind: AlarmKind::OffNormal { normal: 0.0 }, ..limits() };
        assert_eq!(Condition::level_of(&off, 1.0, Level::Normal), Level::Off);
    }

    #[test]
    fn acknowledge_flow() {
        let bus = Arc::new(EventBus::default());
        let c = Condition::new(NodeId::Numeric(2, 1000), NodeId::Numeric(2, 1), "Temp", limits(), bus);
        c.evaluate(&Variant::Double(50.0), status::GOOD, 1);
        assert_eq!(c.summary(), (false, true, true, true));
        c.evaluate(&Variant::Double(90.0), status::GOOD, 2);
        assert_eq!(c.summary(), (true, false, false, true));
        let id = c.lock().event_id.clone();
        assert_eq!(c.acknowledge(b"nope", "", "bob"), Err(BAD_EVENT_ID_UNKNOWN));
        assert_eq!(c.acknowledge(&id, "seen", "bob"), Ok(()));
        let id = c.lock().event_id.clone();
        assert_eq!(c.acknowledge(&id, "", "bob"), Err(BAD_CONDITION_BRANCH_ALREADY_ACKED));
        assert_eq!(c.confirm(&id, "", "bob"), Ok(()));
        assert_eq!(c.summary(), (true, true, true, true));
        // Back to normal: no longer retained.
        c.evaluate(&Variant::Double(50.0), status::GOOD, 3);
        assert!(!c.lock().retain());
        assert_eq!(c.enable(true, "bob"), Err(BAD_CONDITION_ALREADY_ENABLED));
        assert_eq!(c.enable(false, "bob"), Ok(()));
        let id = c.lock().event_id.clone();
        assert_eq!(c.add_comment(&id, "x", "bob"), Err(BAD_CONDITION_DISABLED));
    }

    #[test]
    fn shelving() {
        let bus = Arc::new(EventBus::default());
        let c = Condition::new(NodeId::Numeric(2, 1000), NodeId::Numeric(2, 1), "Temp", limits(), bus);
        use ShelveRequest::*;
        assert_eq!(c.shelve(Unshelve, "", "bob"), Err(BAD_CONDITION_NOT_SHELVED));
        assert_eq!(c.shelve(Timed(0.0), "", "bob"), Err(BAD_SHELVING_TIME_OUT_OF_RANGE));
        assert_eq!(c.shelve(Timed(120_000.0), "", "bob"), Err(BAD_SHELVING_TIME_OUT_OF_RANGE));
        assert_eq!(c.shelve(Timed(1_000.0), "maintenance", "bob"), Ok(()));
        assert!(c.shelved());
        assert_eq!(c.shelve(Timed(1_000.0), "", "bob"), Err(BAD_CONDITION_ALREADY_SHELVED));
        let now = now_ticks();
        c.tick(now);
        assert!(c.shelved());
        c.tick(now + 20_000_000);
        assert!(!c.shelved());
        assert_eq!(c.lock().shelving_transition.0, TIMED_SHELVED_TO_UNSHELVED);
        // One-shot: until the alarm returns to normal.
        assert_eq!(c.shelve(OneShot, "", "bob"), Ok(()));
        assert_eq!(c.shelve(OneShot, "", "bob"), Err(BAD_CONDITION_ALREADY_SHELVED));
        c.evaluate(&Variant::Double(90.0), status::GOOD, 1);
        assert!(c.shelved());
        c.evaluate(&Variant::Double(50.0), status::GOOD, 2);
        assert!(!c.shelved());
        assert_eq!(c.lock().shelving_transition.0, ONE_SHOT_SHELVED_TO_UNSHELVED);
    }

    #[test]
    fn branches() {
        let bus = Arc::new(EventBus::default());
        let c = Condition::new(NodeId::Numeric(2, 1000), NodeId::Numeric(2, 1), "Temp", limits(), bus);
        c.evaluate(&Variant::Double(90.0), status::GOOD, 1); // High, unacked
        let first = c.lock().event_id.clone();
        c.evaluate(&Variant::Double(50.0), status::GOOD, 2); // normal, still unacked
        assert_eq!(c.branch_count(), 0);
        c.evaluate(&Variant::Double(90.0), status::GOOD, 3); // active again
        assert_eq!(c.branch_count(), 1);
        let (branch_event, branch_id) = {
            let st = c.lock();
            (st.branches[0].st.event_id.clone(), st.branches[0].id.clone())
        };
        assert_ne!(branch_id, NodeId::NULL);
        assert_eq!(c.acknowledge(&first, "", "bob"), Err(BAD_EVENT_ID_UNKNOWN));
        // The branch is acknowledged on its own; the condition stays unacked.
        assert_eq!(c.acknowledge(&branch_event, "old one", "bob"), Ok(()));
        assert_eq!(c.summary(), (true, false, false, true));
        assert_eq!(c.branch_count(), 1);
        let branch_event = c.lock().branches[0].st.event_id.clone();
        assert_eq!(c.acknowledge(&branch_event, "", "bob"), Err(BAD_CONDITION_BRANCH_ALREADY_ACKED));
        assert_eq!(c.confirm(&branch_event, "", "bob"), Ok(()));
        assert_eq!(c.branch_count(), 0);
        // ConditionRefresh reports the condition and its branches.
        c.evaluate(&Variant::Double(99.0), status::GOOD, 4); // HighHigh: same occurrence
        assert_eq!(c.branch_count(), 0);
        c.evaluate(&Variant::Double(50.0), status::GOOD, 5);
        c.evaluate(&Variant::Double(5.0), status::GOOD, 6); // Low: a new occurrence
        let mut evs = Vec::new();
        c.refresh_events((1, 0), &mut evs);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].get(BRANCH_ID), Some(&Variant::NodeId(Box::new(NodeId::NULL))));
        assert_ne!(evs[1].get(BRANCH_ID), Some(&Variant::NodeId(Box::new(NodeId::NULL))));
        assert_eq!(c.enable(false, "bob"), Ok(()));
        assert_eq!(c.branch_count(), 0);
    }

    #[test]
    fn suppression_service_silence_latch() {
        let bus = Arc::new(EventBus::default());
        let cfg = AlarmConfig { latching: true, ..limits() };
        let c = Condition::new(NodeId::Numeric(2, 1000), NodeId::Numeric(2, 1), "Temp", cfg, bus);
        assert_eq!(c.set_state(SUPPRESS2, "night", "bob"), Ok(()));
        assert_eq!(c.set_state(REMOVE_FROM_SERVICE, "", "bob"), Ok(()));
        assert_eq!(c.states(), (true, true, false, false));
        assert!(c.lock().suppressed_or_shelved());
        assert_eq!(c.set_state(UNSUPPRESS, "", "bob"), Ok(()));
        assert_eq!(c.set_state(PLACE_IN_SERVICE2, "", "bob"), Ok(()));
        assert!(!c.lock().suppressed_or_shelved());
        // Latched: stays active after the value returns to normal, until Reset.
        c.evaluate(&Variant::Double(90.0), status::GOOD, 1);
        assert_eq!(c.set_state(SILENCE, "", "bob"), Ok(()));
        assert_eq!(c.states(), (false, false, true, true));
        assert_eq!(c.set_state(RESET, "", "bob"), Err(BAD_INVALID_STATE)); // still high
        c.evaluate(&Variant::Double(50.0), status::GOOD, 2);
        assert!(c.summary().0);
        assert_eq!(c.set_state(RESET2, "ok", "bob"), Ok(()));
        assert!(!c.summary().0);
        assert_eq!(c.set_state(RESET, "", "bob"), Err(BAD_INVALID_STATE));
        // A new occurrence is no longer silenced.
        c.evaluate(&Variant::Double(90.0), status::GOOD, 3);
        assert_eq!(c.states(), (false, false, false, true));
    }
}
