//! Alarms and conditions: limit and off-normal alarms raised by writes, the
//! condition methods (Acknowledge, Confirm, AddComment, Enable, Disable) and
//! ConditionRefresh over a loopback connection.

use fastua::address_space::ServerInfo;
use fastua::alarms::codes::*;
use fastua::alarms::types::*;
use fastua::client::{Client, MonitorSpec};
use fastua::events::types::*;
use fastua::pki::Pki;
use fastua::reload::Store;
use fastua::server::{Limits, Server, ServerConfig};
use fastua::subscription::codes::*;
use fastua::types::*;
use fastua::users::{Access, Users};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const PLANT: &str = r#"{ "Name": "Plant", "Namespace": "urn:plant",
  "Subscriptions": [ { "Name": "DATA", "Items": [
    { "Name": "Temp", "NodeId": "ns=3;i=1", "Type": "System.Double",
      "Alarm": { "LowLow": 0, "Low": 10, "High": 80, "HighHigh": 95, "Severity": 700, "Deadband": 2 } },
    { "Name": "Valve", "NodeId": "ns=3;i=2", "Type": "System.Boolean",
      "Alarm": { "Normal": false, "Severity": 300, "Message": "Valve open" } } ] } ] }"#;

fn start(name: &str) -> (String, PathBuf) {
    let dir = std::env::temp_dir().join(format!("fastua-al-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    std::fs::write(dir.join("cfg/p.json"), PLANT).unwrap();
    let store = Store::open(&dir.join("cfg"), ServerInfo::default()).unwrap();
    store.watch().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut config = ServerConfig::all_endpoints(addr.clone(), format!("opc.tcp://{addr}"));
    config.limits = Limits::default();
    config.anonymous = Some(Access::ReadWrite);
    let pki = Pki::open(&dir.join("pki"), "urn:test:fastua", "localhost", false).unwrap();
    let server = Server::new(store, config, pki, Users::default());
    std::thread::spawn(move || server.serve(listener));
    (addr, dir)
}

const SERVER: NodeId = NodeId::Numeric(0, 2253);
const FIELDS: [&str; 11] = [
    "EventType",
    "Message",
    "Severity",
    "ConditionId",
    "EventId",
    "ActiveState/Id",
    "AckedState/Id",
    "Retain",
    "LimitState/CurrentState",
    "EnabledState/Id",
    "ClientUserId",
];

fn text(v: &Variant) -> String {
    match v {
        Variant::String(Some(s)) => s.to_string(),
        Variant::LocalizedText(t) => t.text.as_deref().unwrap_or("").to_string(),
        other => format!("{other:?}"),
    }
}

/// Publishes until `n` events arrived (or 5 s passed).
fn collect(c: &mut Client, n: usize) -> Vec<Vec<Variant>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut acks = Vec::new();
    while out.len() < n && Instant::now() < deadline {
        let p = c.publish(&acks).unwrap();
        acks.clear();
        if !p.message.is_keep_alive() {
            acks.push((p.subscription, p.message.seq));
        }
        out.extend(p.message.events.into_iter().map(|e| e.1));
    }
    out
}

/// Call with one object/method pair: (status, input argument results).
fn call(c: &mut Client, object: &NodeId, method: u32, args: &[Variant]) -> (u32, Vec<u32>) {
    use fastua::codec::Reader;
    let (ty, body) = c
        .call(ids::CALL_REQUEST, |w| {
            w.i32(1);
            w.node_id(object);
            w.node_id(&NodeId::ns0(method));
            w.i32(args.len() as i32);
            for a in args {
                w.variant(a);
            }
        })
        .unwrap();
    assert_eq!(ty, ids::CALL_RESPONSE);
    let mut r = Reader::new(body);
    fastua::client::skip_response_header(&mut r).unwrap();
    let mut out = r
        .array(1, |r| {
            let code = r.u32()?;
            let args = r.array(4, |r| r.u32())?;
            r.array(1, |r| r.diagnostic_info())?;
            r.array(1, |r| r.variant())?;
            Ok((code, args))
        })
        .unwrap();
    out.pop().unwrap()
}

fn comment(s: &str) -> Variant {
    Variant::LocalizedText(Box::new(LocalizedText::new(s)))
}

fn is_type(e: &[Variant], t: u32) -> bool {
    e[0] == Variant::NodeId(Box::new(NodeId::ns0(t)))
}

#[test]
fn limit_alarm_acknowledge_and_refresh() {
    let (addr, dir) = start("limit");
    let mut c = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
    c.create_session("operator").unwrap();
    let ns = 2; // the only configured namespace
    let temp = NodeId::Numeric(ns, 1);
    let valve = NodeId::Numeric(ns, 2);
    let temp_alarm = NodeId::String(ns, "__alarm/i=1".into());
    let name = c.read(&[(temp_alarm.clone(), 3)]).unwrap();
    assert_eq!(name[0].value, Some(Variant::QualifiedName(Box::new(QualifiedName { ns, name: "TempAlarm".into() }))));

    let (sub, ..) = c.create_subscription(20.0, 300, 10).unwrap();
    let r = c.monitor(sub, &[MonitorSpec::events(SERVER, 1, &FIELDS)]).unwrap();
    assert_eq!(r[0].0, status::GOOD);
    let item = r[0].1;

    // Normal value: no event. High: active, unacknowledged.
    assert_eq!(c.write(&[(temp.clone(), Variant::Double(50.0))]).unwrap(), vec![status::GOOD]);
    assert_eq!(c.write(&[(temp.clone(), Variant::Double(85.0))]).unwrap(), vec![status::GOOD]);
    let ev = collect(&mut c, 1);
    assert_eq!(ev.len(), 1, "{ev:?}");
    let e = &ev[0];
    assert!(is_type(e, EXCLUSIVE_LIMIT_ALARM_TYPE), "{e:?}");
    assert_eq!(e[2], Variant::UInt16(700));
    assert_eq!(e[3], Variant::NodeId(Box::new(temp_alarm.clone())));
    assert_eq!((&e[5], &e[6], &e[7]), (&Variant::Boolean(true), &Variant::Boolean(false), &Variant::Boolean(true)));
    assert_eq!(text(&e[8]), "High");
    let event_id = e[4].clone();

    // Within the deadband of High: nothing; HighHigh: a new event.
    c.write(&[(temp.clone(), Variant::Double(79.0))]).unwrap();
    c.write(&[(temp.clone(), Variant::Double(97.0))]).unwrap();
    let ev = collect(&mut c, 1);
    assert_eq!(ev.len(), 1);
    assert_eq!(text(&ev[0][8]), "HighHigh");
    assert_ne!(ev[0][4], event_id);
    // The old EventId is no longer the condition's.
    assert_eq!(call(&mut c, &temp_alarm, ACKNOWLEDGE, &[event_id, comment("late")]).0, BAD_EVENT_ID_UNKNOWN);
    let event_id = ev[0][4].clone();
    assert_eq!(call(&mut c, &temp_alarm, ACKNOWLEDGE, &[event_id.clone(), comment("seen")]).0, status::GOOD);
    let ev = collect(&mut c, 1);
    assert_eq!(ev[0][6], Variant::Boolean(true));
    assert_eq!(text(&ev[0][10]), "anonymous");
    assert_eq!(
        call(&mut c, &temp_alarm, ACKNOWLEDGE, &[ev[0][4].clone(), comment("")]).0,
        BAD_CONDITION_BRANCH_ALREADY_ACKED
    );
    assert_eq!(call(&mut c, &temp_alarm, ACKNOWLEDGE, std::slice::from_ref(&event_id)).0, BAD_ARGUMENTS_MISSING);
    let (code, args) = call(&mut c, &temp_alarm, ACKNOWLEDGE, &[Variant::UInt32(1), comment("")]);
    assert_eq!((code, args), (BAD_INVALID_ARGUMENT, vec![status::BAD_TYPE_MISMATCH, status::GOOD]));
    assert_eq!(call(&mut c, &temp_alarm, CONFIRM, &[ev[0][4].clone(), comment("ok")]).0, status::GOOD);
    collect(&mut c, 1);

    // Off-normal alarm with its configured message.
    c.write(&[(valve.clone(), Variant::Boolean(true))]).unwrap();
    let ev = collect(&mut c, 1);
    assert!(is_type(&ev[0], OFF_NORMAL_ALARM_TYPE));
    assert_eq!(text(&ev[0][1]), "Valve open");

    // ConditionRefresh: start, both retained conditions, end, to this item.
    assert_eq!(call(&mut c, &NodeId::ns0(CONDITION_TYPE), CONDITION_REFRESH, &[Variant::UInt32(sub)]).0, status::GOOD);
    let ev = collect(&mut c, 4);
    assert_eq!(ev.len(), 4, "{ev:?}");
    assert!(is_type(&ev[0], REFRESH_START_EVENT_TYPE));
    assert!(is_type(&ev[3], REFRESH_END_EVENT_TYPE));
    let mut ids: Vec<String> = ev[1..3].iter().map(|e| format!("{:?}", e[3])).collect();
    ids.sort();
    assert!(ids[0].contains("i=1") && ids[1].contains("i=2"), "{ids:?}");
    let r2 = [Variant::UInt32(sub), Variant::UInt32(item)];
    assert_eq!(call(&mut c, &NodeId::ns0(CONDITION_TYPE), CONDITION_REFRESH2, &r2).0, status::GOOD);
    assert_eq!(collect(&mut c, 4).len(), 4);
    let bad = [Variant::UInt32(sub), Variant::UInt32(item + 100)];
    assert_eq!(call(&mut c, &NodeId::ns0(CONDITION_TYPE), CONDITION_REFRESH2, &bad).0, BAD_MONITORED_ITEM_ID_INVALID);
    assert_eq!(
        call(&mut c, &NodeId::ns0(CONDITION_TYPE), CONDITION_REFRESH, &[Variant::UInt32(sub + 100)]).0,
        BAD_SUBSCRIPTION_ID_INVALID
    );

    // Disable: one last event (not retained), then methods are refused.
    assert_eq!(call(&mut c, &temp_alarm, DISABLE, &[]).0, status::GOOD);
    let ev = collect(&mut c, 1);
    assert_eq!((&ev[0][7], &ev[0][9]), (&Variant::Boolean(false), &Variant::Boolean(false)));
    assert_eq!(call(&mut c, &temp_alarm, DISABLE, &[]).0, BAD_CONDITION_ALREADY_DISABLED);
    assert_eq!(call(&mut c, &temp_alarm, ADD_COMMENT, &[ev[0][4].clone(), comment("x")]).0, BAD_CONDITION_DISABLED);
    c.write(&[(temp.clone(), Variant::Double(5.0))]).unwrap();
    assert_eq!(call(&mut c, &temp_alarm, ENABLE, &[]).0, status::GOOD);
    let ev = collect(&mut c, 1);
    assert_eq!(text(&ev[0][8]), "Low");
    // Methods on a node that is not a condition.
    assert_eq!(call(&mut c, &temp, ENABLE, &[]).0, BAD_METHOD_INVALID);
    assert_eq!(call(&mut c, &NodeId::Numeric(ns, 999), ENABLE, &[]).0, status::BAD_NODE_ID_UNKNOWN);

    // A reload keeps the condition state and applies the new configuration.
    std::fs::write(dir.join("cfg/p.json"), PLANT.replace("700", "900")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ev = Vec::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        c.write(&[(temp.clone(), Variant::Double(50.0))]).unwrap();
        c.write(&[(temp.clone(), Variant::Double(5.0))]).unwrap();
        ev = collect(&mut c, 2).into_iter().filter(|e| is_type(e, EXCLUSIVE_LIMIT_ALARM_TYPE)).collect();
        if ev.iter().any(|e| e[2] == Variant::UInt16(900)) {
            break;
        }
    }
    let last = ev.last().expect("events after reload");
    assert_eq!(last[2], Variant::UInt16(900));
    assert_eq!(text(&last[8]), "Low");
    let _ = std::fs::remove_dir_all(&dir);
}
