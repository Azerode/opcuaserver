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
    pub const BASE_CONDITION_CLASS_TYPE: u32 = 11163;
    pub const PROCESS_CONDITION_CLASS_TYPE: u32 = 11164;

    pub const ENABLE: u32 = 9027;
    pub const DISABLE: u32 = 9028;
    pub const ADD_COMMENT: u32 = 9029;
    pub const CONDITION_REFRESH: u32 = 3875;
    pub const CONDITION_REFRESH2: u32 = 12912;
    pub const ACKNOWLEDGE: u32 = 9111;
    pub const CONFIRM: u32 = 9113;

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
}
use codes::*;

/// What raises the alarm.
#[derive(Clone, Debug, PartialEq)]
pub enum AlarmKind {
    /// ExclusiveLimitAlarmType: the most severe limit crossed.
    Limit { low_low: Option<f64>, low: Option<f64>, high: Option<f64>, high_high: Option<f64> },
    /// OffNormalAlarmType: active while the value differs from `normal`.
    OffNormal { normal: f64 },
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
}

impl AlarmConfig {
    pub fn type_id(&self) -> u32 {
        match self.kind {
            AlarmKind::Limit { .. } => EXCLUSIVE_LIMIT_ALARM_TYPE,
            AlarmKind::OffNormal { .. } => OFF_NORMAL_ALARM_TYPE,
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
}

impl State {
    fn active(&self) -> bool {
        self.level != Level::Normal
    }

    fn retain(&self) -> bool {
        self.enabled && (self.active() || !self.acked || !self.confirmed)
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

    /// The condition's state as an event (a new EventId unless `keep_id`).
    fn event(&self, st: &mut State, cfg: &AlarmConfig, keep_id: bool) -> Event {
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
            .with(CONDITION_NAME, Variant::string(&format!("{}Alarm", self.source_name)))
            .with(BRANCH_ID, Variant::NodeId(Box::new(NodeId::NULL)))
            .with(RETAIN, Variant::Boolean(st.retain()))
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
            .with(CLIENT_USER_ID, Variant::string(&st.user))
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
            .with(SUPPRESSED_OR_SHELVED, Variant::Boolean(false));
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
        }
    }

    fn emit(&self, st: &mut State, cfg: &AlarmConfig) {
        st.last_severity = st.severity;
        let ev = self.event(st, cfg, false);
        if st.enabled {
            self.bus.emit(ev);
        }
    }

    /// Level of `f` given the current level (deadband applied when moving
    /// back towards normal).
    fn level_of(cfg: &AlarmConfig, f: f64, cur: Level) -> Level {
        match &cfg.kind {
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
        let was = st.level;
        st.level = level;
        let now = now_ticks();
        let rank = |l: Level| match l {
            Level::Normal => 0,
            Level::High | Level::Low | Level::Off => 1,
            Level::HighHigh | Level::LowLow => 2,
        };
        if level != was {
            st.active_ts = now;
            if rank(level) > rank(was) || (rank(level) > 0 && rank(was) > 0 && level != was && rank(level) >= rank(was))
            {
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

    /// Retained conditions are reported by ConditionRefresh.
    fn refresh_event(&self, target: (u32, u32)) -> Option<Event> {
        let cfg = self.config();
        let mut st = self.lock();
        if !st.retain() {
            return None;
        }
        let mut ev = self.event(&mut st, &cfg, true);
        ev.target = Some(target);
        Some(ev)
    }

    fn check_event_id(st: &State, id: &[u8]) -> Result<(), u32> {
        if st.event_id.is_empty() || *st.event_id != *id {
            return Err(BAD_EVENT_ID_UNKNOWN);
        }
        Ok(())
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
        let ev = self.event(&mut st, &cfg, false);
        self.bus.emit(ev);
        Ok(())
    }

    pub fn add_comment(&self, event_id: &[u8], comment: &str, user: &str) -> Result<(), u32> {
        let cfg = self.config();
        let mut st = self.lock();
        if !st.enabled {
            return Err(BAD_CONDITION_DISABLED);
        }
        Self::check_event_id(&st, event_id)?;
        st.comment = comment.to_string();
        st.comment_ts = now_ticks();
        st.user = user.to_string();
        self.emit(&mut st, &cfg);
        Ok(())
    }

    pub fn acknowledge(&self, event_id: &[u8], comment: &str, user: &str) -> Result<(), u32> {
        let cfg = self.config();
        let mut st = self.lock();
        if !st.enabled {
            return Err(BAD_CONDITION_DISABLED);
        }
        Self::check_event_id(&st, event_id)?;
        if st.acked {
            return Err(BAD_CONDITION_BRANCH_ALREADY_ACKED);
        }
        st.acked = true;
        st.acked_ts = now_ticks();
        if !comment.is_empty() {
            st.comment = comment.to_string();
            st.comment_ts = st.acked_ts;
        }
        st.user = user.to_string();
        self.emit(&mut st, &cfg);
        Ok(())
    }

    pub fn confirm(&self, event_id: &[u8], comment: &str, user: &str) -> Result<(), u32> {
        let cfg = self.config();
        let mut st = self.lock();
        if !st.enabled {
            return Err(BAD_CONDITION_DISABLED);
        }
        Self::check_event_id(&st, event_id)?;
        if st.confirmed {
            return Err(BAD_CONDITION_BRANCH_ALREADY_CONFIRMED);
        }
        st.confirmed = true;
        st.confirmed_ts = now_ticks();
        if !comment.is_empty() {
            st.comment = comment.to_string();
            st.comment_ts = st.confirmed_ts;
        }
        st.user = user.to_string();
        self.emit(&mut st, &cfg);
        Ok(())
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

    /// ConditionRefresh (Part 9 §5.5.7): RefreshStart, every retained
    /// condition, RefreshEnd, for one subscription (or one of its items).
    pub fn refresh(&self, bus: &EventBus, target: (u32, u32)) {
        let server = NodeId::ns0(ids::SERVER);
        let mut start = Event::new(REFRESH_START_EVENT_TYPE, server.clone(), "Server", "", 100);
        start.target = Some(target);
        bus.emit(start);
        let conds: Vec<Arc<Condition>> = self.lock().values().cloned().collect();
        for c in conds {
            if let Some(ev) = c.refresh_event(target) {
                bus.emit(ev);
            }
        }
        let mut end = Event::new(REFRESH_END_EVENT_TYPE, server, "Server", "", 100);
        end.target = Some(target);
        bus.emit(end);
    }
}

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
    let Caller { user, can_write, refresh } = caller;
    let m = method.as_ns0()?;
    if ![ENABLE, DISABLE, ADD_COMMENT, ACKNOWLEDGE, CONFIRM, CONDITION_REFRESH, CONDITION_REFRESH2].contains(&m) {
        return None;
    }
    let fail = |code| Some(Err((code, Vec::new())));
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
}
