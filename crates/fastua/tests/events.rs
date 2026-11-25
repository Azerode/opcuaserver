//! Events: EventFilter select / where clauses and server-generated events
//! (session audit, configuration reloads) over a loopback connection.

use fastua::address_space::ServerInfo;
use fastua::client::{Client, FilterOperand, MonitorSpec};
use fastua::events::codes::BAD_EVENT_FILTER_INVALID;
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

const MACHINE: &str = r#"{ "Name": "Press", "Namespace": "urn:press",
  "Subscriptions": [ { "Name": "DATA", "Items": [
    { "Name": "Speed", "NodeId": "ns=7;i=1", "Type": "System.Double" } ] } ] }"#;

fn start(name: &str) -> (String, PathBuf) {
    let dir = std::env::temp_dir().join(format!("fastua-ev-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    std::fs::write(dir.join("cfg/m.json"), MACHINE).unwrap();
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

fn client(addr: &str, name: &str) -> Client {
    let mut c = Client::connect(addr, &format!("opc.tcp://{addr}")).unwrap();
    c.create_session(name).unwrap();
    c
}

const SERVER: NodeId = NodeId::Numeric(0, 2253);

fn text(v: &Variant) -> String {
    match v {
        Variant::String(Some(s)) => s.to_string(),
        Variant::LocalizedText(t) => t.text.as_deref().unwrap_or("").to_string(),
        Variant::NodeId(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

/// Publishes until `n` events arrived for `handle` (or 5 s passed); returns
/// the events of every handle.
fn collect(c: &mut Client, handle: u32, n: usize) -> Vec<(u32, Vec<Variant>)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out: Vec<(u32, Vec<Variant>)> = Vec::new();
    let mut acks = Vec::new();
    while out.iter().filter(|e| e.0 == handle).count() < n && Instant::now() < deadline {
        let p = c.publish(&acks).unwrap();
        assert_eq!(p.fault, 0);
        acks.clear();
        if !p.message.is_keep_alive() {
            acks.push((p.subscription, p.message.seq));
        }
        out.extend(p.message.events);
    }
    out
}

fn of(events: &[(u32, Vec<Variant>)], handle: u32) -> Vec<Vec<Variant>> {
    events.iter().filter(|e| e.0 == handle).map(|e| e.1.clone()).collect()
}

#[test]
fn session_and_reload_events() {
    let (addr, dir) = start("audit");
    let mut c = client(&addr, "watcher");
    assert_eq!(c.read(&[(SERVER, 12)]).unwrap()[0].value, Some(Variant::Byte(1)));
    let (sub, ..) = c.create_subscription(20.0, 300, 10).unwrap();
    let fields = ["EventType", "SourceName", "Severity", "Message", "SessionId", "ClientUserId", "Status"];
    let all = MonitorSpec::events(SERVER, 1, &fields);
    // Only session creations.
    let mut created = MonitorSpec::events(SERVER, 2, &["SourceName", "RevisedSessionTimeout"]);
    created.event_where = vec![(
        14, // OfType
        vec![FilterOperand::Literal(Variant::NodeId(Box::new(NodeId::ns0(AUDIT_CREATE_SESSION_EVENT_TYPE))))],
    )];
    // Severity >= 500: failures and system events only.
    let mut severe = MonitorSpec::events(SERVER, 3, &["Message"]);
    severe.event_where =
        vec![(4, vec![FilterOperand::Field("Severity".into()), FilterOperand::Literal(Variant::UInt16(500))])];
    let r = c.monitor(sub, &[all, created, severe]).unwrap();
    assert!(r.iter().all(|x| x.0 == status::GOOD), "{r:?}");
    assert_eq!(r[0].3, 1000); // queue size 0 -> server default

    let other = client(&addr, "worker");
    other.close().unwrap();
    // A rejected configuration, then a valid one.
    std::fs::write(dir.join("cfg/m.json"), "{ broken").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    std::fs::write(dir.join("cfg/m.json"), MACHINE).unwrap();

    let received = collect(&mut c, 1, 5);
    let events = of(&received, 1);
    let names: Vec<String> = events.iter().map(|e| text(&e[1])).collect();
    assert_eq!(
        names,
        vec!["Session/CreateSession", "Session/ActivateSession", "Session/CloseSession", "Server", "Server"]
    );
    assert_eq!(text(&events[0][0]), NodeId::ns0(AUDIT_CREATE_SESSION_EVENT_TYPE).to_string());
    assert_eq!(events[1][5], Variant::string("anonymous"));
    assert_eq!(events[1][6], Variant::Boolean(true));
    assert!(matches!(events[0][4], Variant::NodeId(_)));
    assert_eq!(text(&events[3][0]), NodeId::ns0(SYSTEM_EVENT_TYPE).to_string());
    assert_eq!(events[3][2], Variant::UInt16(700));
    assert!(text(&events[3][3]).contains("rejected"));
    assert_eq!(text(&events[4][0]), NodeId::ns0(BASE_MODEL_CHANGE_EVENT_TYPE).to_string());
    // Fields that BaseModelChangeEventType does not have are null.
    assert_eq!(events[4][4], Variant::Empty);

    let created = of(&received, 2);
    assert_eq!(created.len(), 1);
    assert_eq!(created[0][0], Variant::string("Session/CreateSession"));
    assert!(matches!(created[0][1], Variant::Double(t) if t > 0.0));
    let severe = of(&received, 3);
    assert_eq!(severe.len(), 1);
    assert!(text(&severe[0][0]).contains("rejected"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_event_items() {
    let (addr, dir) = start("invalid");
    let mut c = client(&addr, "x");
    let (sub, ..) = c.create_subscription(50.0, 300, 10).unwrap();
    let variable = MonitorSpec::events(NodeId::Numeric(2, 1), 1, &["Message"]);
    let folder = MonitorSpec::events(NodeId::ns0(85), 2, &["Message"]);
    let empty = MonitorSpec::events(SERVER, 3, &[]);
    let mut unsupported = MonitorSpec::events(SERVER, 4, &["Message"]);
    unsupported.event_where = vec![(15, vec![FilterOperand::Element(1), FilterOperand::Element(1)])];
    let mut on_value = MonitorSpec::events(SERVER, 5, &["Message"]);
    on_value.attribute = 13;
    let r = c.monitor(sub, &[variable, folder, empty, unsupported, on_value]).unwrap();
    let codes: Vec<u32> = r.iter().map(|x| x.0).collect();
    assert_eq!(
        codes,
        vec![
            status::BAD_ATTRIBUTE_ID_INVALID,
            BAD_FILTER_NOT_ALLOWED,
            BAD_EVENT_FILTER_INVALID,
            BAD_EVENT_FILTER_INVALID,
            BAD_FILTER_NOT_ALLOWED
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}
