//! Full protocol round trips against a real server on a loopback socket.

use fastua::address_space::ServerInfo;
use fastua::client::Client;
use fastua::pki::Pki;
use fastua::reload::Store;
use fastua::server::{Limits, Server, ServerConfig};
use fastua::types::*;
use fastua::users::{Access, Users};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn start(dir: &std::path::Path, limits: Limits) -> String {
    start_with(dir, limits, std::time::Duration::ZERO)
}

fn start_with(dir: &std::path::Path, limits: Limits, busy_poll: std::time::Duration) -> String {
    start_full(dir, limits, busy_poll, false)
}

fn start_full(dir: &std::path::Path, limits: Limits, busy_poll: std::time::Duration, io_uring: bool) -> String {
    let store = Store::open(dir, ServerInfo::default()).unwrap();
    store.watch().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut config = ServerConfig::all_endpoints(addr.clone(), format!("opc.tcp://{addr}"));
    config.limits = limits;
    config.anonymous = Some(Access::ReadWrite);
    config.busy_poll = busy_poll;
    config.io_uring = io_uring;
    let pki = Pki::open(&dir.join("pki"), "urn:test:fastua", "localhost", false).unwrap();
    let server = Server::new(store, config, pki, Users::default());
    std::thread::spawn(move || server.serve(listener));
    addr
}

fn temp_config(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fastua-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("m.json"), body).unwrap();
    dir
}

const MACHINE: &str = r#"{ "Name": "Press", "Namespace": "urn:press",
  "Subscriptions": [ { "Name": "DATA", "Items": [
    { "Name": "Speed", "NodeId": "ns=7;i=1", "Type": "System.Double" },
    { "Name": "Count", "NodeId": "ns=7;i=2", "Type": "System.Int32" },
    { "Name": "Label", "NodeId": "ns=7;s=Label", "Type": "String" },
    { "Name": "Locked", "NodeId": "ns=7;i=3", "Type": "Boolean", "Writable": false } ] } ] }"#;

#[test]
fn session_read_write_browse() {
    let dir = temp_config("rw", MACHINE);
    let addr = start(&dir, Limits::default());
    let mut c = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
    c.create_session("e2e").unwrap();

    // Namespace array: ns 2 is the configured URI.
    let dv = c.read(&[(NodeId::ns0(ids::SERVER_NAMESPACE_ARRAY), 13)]).unwrap();
    let Some(Variant::Array(a)) = &dv[0].value else { panic!("{dv:?}") };
    assert_eq!(a.items[2], Variant::string("urn:press"));

    let speed = NodeId::Numeric(2, 1);
    let label = NodeId::String(2, "Label".into());
    let res = c
        .write(&[
            (speed.clone(), Variant::Double(12.5)),
            (NodeId::Numeric(2, 2), Variant::Double(1.0)),
            (label.clone(), Variant::string("hello")),
            (NodeId::Numeric(2, 3), Variant::Boolean(true)),
            (NodeId::Numeric(2, 99), Variant::Int32(1)),
        ])
        .unwrap();
    assert_eq!(
        res,
        vec![
            status::GOOD,
            status::BAD_TYPE_MISMATCH,
            status::GOOD,
            status::BAD_NOT_WRITABLE,
            status::BAD_NODE_ID_UNKNOWN
        ]
    );
    let dv = c.read(&[(speed.clone(), 13), (label, 13), (speed.clone(), 14), (speed.clone(), 3), (speed, 99)]).unwrap();
    assert_eq!(dv[0].value, Some(Variant::Double(12.5)));
    assert!(dv[0].source_timestamp.is_some() && dv[0].server_timestamp.is_some());
    assert_eq!(dv[1].value, Some(Variant::string("hello")));
    assert_eq!(dv[2].value, Some(Variant::NodeId(Box::new(NodeId::ns0(11)))));
    assert_eq!(dv[3].value, Some(Variant::QualifiedName(Box::new(QualifiedName { ns: 2, name: "Speed".into() }))));
    assert_eq!(dv[4].status, Some(status::BAD_ATTRIBUTE_ID_INVALID));

    // Browse with one reference per call, then follow continuation points.
    let (st, mut cp, mut refs) = c.browse(&NodeId::ns0(ids::OBJECTS_FOLDER), 1).unwrap();
    assert_eq!(st, status::GOOD);
    while let Some(p) = cp {
        let (st, next, more) = c.browse_next(&p).unwrap();
        assert_eq!(st, status::GOOD);
        refs.extend(more);
        cp = next;
    }
    assert!(refs.contains(&NodeId::ns0(ids::SERVER)));
    assert!(refs.contains(&NodeId::String(2, "__folder/Press".into())));
    c.close().unwrap();
}

#[test]
fn requests_without_session_are_rejected() {
    let dir = temp_config("nosession", MACHINE);
    let addr = start(&dir, Limits::default());
    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    let (ty, body) = c
        .call(ids::READ_REQUEST, |w| {
            w.f64(0.0);
            w.u32(0);
            w.i32(0);
        })
        .unwrap();
    assert_eq!(ty, ids::SERVICE_FAULT);
    assert_eq!(fastua::client::service_result(body), status::BAD_SESSION_ID_INVALID);
    // Unknown service.
    let (ty, body) = c.call(999_999, |_| {}).unwrap();
    assert_eq!(ty, ids::SERVICE_FAULT);
    assert_eq!(fastua::client::service_result(body), status::BAD_SERVICE_UNSUPPORTED);
}

#[test]
fn large_response_is_chunked() {
    let dir = temp_config("chunks", MACHINE);
    let addr = start(&dir, Limits::default());
    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    c.create_session("chunks").unwrap();
    let items: Vec<_> = (0..3000).map(|_| (NodeId::ns0(ids::SERVER_SERVER_STATUS), 13)).collect();
    let dv = c.read(&items).unwrap();
    assert_eq!(dv.len(), 3000);
    assert!(dv.iter().all(|d| matches!(d.value, Some(Variant::ExtensionObject(_)))));
}

#[test]
fn renew_channel_keeps_session() {
    let dir = temp_config("renew", MACHINE);
    let addr = start(&dir, Limits::default());
    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    c.create_session("renew").unwrap();
    c.open(1).unwrap();
    let dv = c.read(&[(NodeId::ns0(ids::SERVER_SERVER_STATUS_STATE), 13)]).unwrap();
    assert_eq!(dv[0].value, Some(Variant::Int32(0)));
}

#[test]
fn hot_reload_is_visible_to_connected_clients() {
    let dir = temp_config("reload", MACHINE);
    let addr = start(&dir, Limits::default());
    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    c.create_session("reload").unwrap();
    assert_eq!(c.write(&[(NodeId::Numeric(2, 2), Variant::Int32(77))]).unwrap(), vec![status::GOOD]);

    let updated = MACHINE.replace(r#""ns=7;i=3""#, r#""ns=7;i=30""#);
    let tmp = dir.join(".m.json.tmp");
    std::fs::write(&tmp, updated).unwrap();
    std::fs::rename(&tmp, dir.join("m.json")).unwrap();

    let t = Instant::now();
    loop {
        let dv =
            c.read(&[(NodeId::Numeric(2, 30), 1), (NodeId::Numeric(2, 3), 1), (NodeId::Numeric(2, 2), 13)]).unwrap();
        if dv[0].status.is_none() {
            assert_eq!(dv[1].status, Some(status::BAD_NODE_ID_UNKNOWN));
            assert_eq!(dv[2].value, Some(Variant::Int32(77)), "value survives reload");
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "reload not observed");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Many requests in one TCP write: the receive buffer holds several chunks
/// at once; every response must come back, in order, with the right value.
/// Runs with and without busy polling.
#[test]
fn pipelined_requests_and_busy_poll() {
    // io_uring falls back to plain sockets where the kernel refuses it, so
    // these cases pass on every machine.
    for (name, spin, uring) in
        [("pipe", 0u64, false), ("spin", 200, false), ("uring", 0, true), ("uring-spin", 200, true)]
    {
        let dir = temp_config(name, MACHINE);
        let addr = start_full(&dir, Limits::default(), std::time::Duration::from_micros(spin), uring);
        let mut c = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
        c.create_session("pipe").unwrap();
        let ns = 2;
        assert_eq!(c.write(&[(NodeId::Numeric(ns, 2), Variant::Int32(41))]).unwrap(), vec![status::GOOD]);
        for n in [1usize, 2, 50, 700] {
            let all = c.read_pipelined(&[(NodeId::Numeric(ns, 2), 13)], n).unwrap();
            // (Large responses also exercise partial sends on the io_uring path.)
            assert_eq!(all.len(), n);
            for dv in all {
                assert_eq!(dv[0].value, Some(Variant::Int32(41)), "{name} x{n}");
            }
        }
        // Normal request/response still works after the pipelined bursts.
        assert_eq!(c.read(&[(NodeId::Numeric(ns, 2), 13)]).unwrap()[0].value, Some(Variant::Int32(41)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
