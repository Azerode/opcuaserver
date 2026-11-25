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
    let store = Store::open(dir, ServerInfo::default()).unwrap();
    store.watch().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut config = ServerConfig::all_endpoints(addr.clone(), format!("opc.tcp://{addr}"));
    config.limits = limits;
    config.anonymous = Some(Access::ReadWrite);
    config.busy_poll = busy_poll;
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
    for (name, spin) in [("pipe", 0u64), ("spin", 200)] {
        let dir = temp_config(name, MACHINE);
        let addr = start_with(&dir, Limits::default(), std::time::Duration::from_micros(spin));
        let mut c = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
        c.create_session("pipe").unwrap();
        let ns = 2;
        assert_eq!(c.write(&[(NodeId::Numeric(ns, 2), Variant::Int32(41))]).unwrap(), vec![status::GOOD]);
        for n in [1usize, 2, 50, 700] {
            let all = c.read_pipelined(&[(NodeId::Numeric(ns, 2), 13)], n).unwrap();
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

/// Mutual certificate authentication on every policy and mode: session,
/// read, write and a multi-chunk response, through the test client's own
/// implementation of the secure channel.
#[test]
fn secure_channels_end_to_end() {
    use fastua::crypto::{Mode, Policy};
    let dir = temp_config("secure", MACHINE);
    let addr = start(&dir, Limits::default());
    let (cert, key) = fastua::pki::generate_self_signed("urn:fastua:test-client", "localhost").unwrap();
    let trusted = dir.join("pki/trusted/certs");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::write(trusted.join("client.der"), &cert).unwrap();
    let server_cert = std::fs::read(dir.join("pki/own/certs/fastua.der")).unwrap();
    let url = format!("opc.tcp://{addr}");
    for policy in Policy::SECURE {
        for mode in [Mode::Sign, Mode::SignAndEncrypt] {
            let mut c = Client::connect_secure(&addr, &url, policy, mode, &cert, &key, &server_cert).unwrap();
            c.create_session("secure").unwrap();
            let id = NodeId::Numeric(2, 2);
            assert_eq!(c.write(&[(id.clone(), Variant::Int32(7))]).unwrap(), vec![status::GOOD], "{policy:?} {mode:?}");
            assert_eq!(c.read(&[(id.clone(), 13)]).unwrap()[0].value, Some(Variant::Int32(7)));
            let many = vec![(id.clone(), 13); 3000];
            assert_eq!(c.read(&many).unwrap().len(), 3000, "multi-chunk {policy:?} {mode:?}");
            let all = c.read_pipelined(&[(id, 13)], 20).unwrap();
            assert_eq!(all.len(), 20);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every ECC AEAD policy and mode: channel-bound session signatures, read,
/// write, multi-chunk responses, pipelining and a token renewal (IKM chaining).
#[test]
fn ecc_channels_end_to_end() {
    use fastua::crypto::{Mode, Policy};
    use fastua::ecc::{Curve, Suite};
    let dir = temp_config("ecc", MACHINE);
    let addr = start(&dir, Limits::default());
    let trusted = dir.join("pki/trusted/certs");
    std::fs::create_dir_all(&trusted).unwrap();
    let url = format!("opc.tcp://{addr}");
    for curve in [Curve::NistP256, Curve::NistP384, Curve::Curve25519] {
        let (cert, key) = fastua::pki::generate_self_signed_ecc(curve, "urn:fastua:test-client", "localhost").unwrap();
        std::fs::write(trusted.join(format!("client-{curve:?}.der")), &cert).unwrap();
        let name = match curve {
            Curve::NistP256 => "nistP256",
            Curve::NistP384 => "nistP384",
            Curve::Curve25519 => "curve25519",
        };
        let server_cert = std::fs::read(dir.join(format!("pki/own/certs/fastua_{name}.der"))).unwrap();
        for suite in Suite::ALL.into_iter().filter(|s| s.curve == curve) {
            let policy = Policy::Ecc(suite);
            for mode in [Mode::Sign, Mode::SignAndEncrypt] {
                let mut c = Client::connect_secure(&addr, &url, policy, mode, &cert, &key, &server_cert)
                    .unwrap_or_else(|e| panic!("{suite:?} {mode:?}: {e}"));
                c.create_session("ecc").unwrap_or_else(|e| panic!("{suite:?} {mode:?}: {e}"));
                let id = NodeId::Numeric(2, 2);
                assert_eq!(
                    c.write(&[(id.clone(), Variant::Int32(9))]).unwrap(),
                    vec![status::GOOD],
                    "{suite:?} {mode:?}"
                );
                assert_eq!(c.read(&[(id.clone(), 13)]).unwrap()[0].value, Some(Variant::Int32(9)));
                let many = vec![(id.clone(), 13); 3000];
                assert_eq!(c.read(&many).unwrap().len(), 3000, "multi-chunk {suite:?} {mode:?}");
                c.open(1).unwrap_or_else(|e| panic!("renew {suite:?} {mode:?}: {e}"));
                let all = c.read_pipelined(&[(id, 13)], 20).unwrap();
                assert_eq!(all.len(), 20);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// User name / password on ECC endpoints: the password travels as an
/// EccEncryptedSecret for the ephemeral key the server sent in CreateSession.
#[test]
fn ecc_user_name_login() {
    use fastua::crypto::{Mode, Policy};
    use fastua::ecc::{Curve, Suite};
    let dir = temp_config("ecc-user", MACHINE);
    let users = std::env::temp_dir().join(format!("fastua-ecc-users-{}.json", std::process::id()));
    std::fs::write(
        &users,
        format!(
            r#"{{ "users": [ {{ "name": "operator", "password": "{}", "write": true }} ] }}"#,
            fastua::users::hash_password("s3cret")
        ),
    )
    .unwrap();
    let store = Store::open(&dir, ServerInfo::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut config = ServerConfig::all_endpoints(addr.clone(), format!("opc.tcp://{addr}"));
    config.anonymous = None;
    let pki = Pki::open(&dir.join("pki"), "urn:test:fastua", "localhost", false).unwrap();
    let server = Server::new(store, config, pki, Users::load(&users).unwrap());
    std::thread::spawn(move || server.serve(listener));
    let trusted = dir.join("pki/trusted/certs");
    std::fs::create_dir_all(&trusted).unwrap();
    let url = format!("opc.tcp://{addr}");
    for suite in Suite::ALL {
        let (cert, key) =
            fastua::pki::generate_self_signed_ecc(suite.curve, "urn:fastua:test-client", "localhost").unwrap();
        std::fs::write(trusted.join(format!("client-{suite:?}.der")), &cert).unwrap();
        let name = match suite.curve {
            Curve::NistP256 => "nistP256",
            Curve::NistP384 => "nistP384",
            Curve::Curve25519 => "curve25519",
        };
        let server_cert = std::fs::read(dir.join(format!("pki/own/certs/fastua_{name}.der"))).unwrap();
        for mode in [Mode::Sign, Mode::SignAndEncrypt] {
            let policy = Policy::Ecc(suite);
            let connect = || Client::connect_secure(&addr, &url, policy, mode, &cert, &key, &server_cert).unwrap();
            let mut c = connect();
            c.create_session_as("ecc-user", Some(("operator", "s3cret")))
                .unwrap_or_else(|e| panic!("{suite:?} {mode:?}: {e}"));
            let id = NodeId::Numeric(2, 2);
            assert_eq!(c.write(&[(id, Variant::Int32(5))]).unwrap(), vec![status::GOOD], "{suite:?} {mode:?}");
            // Wrong password, and anonymous (disabled) are refused.
            let err = connect().create_session_as("ecc-user", Some(("operator", "nope"))).unwrap_err();
            assert!(err.to_string().contains("801F0000"), "{err}"); // BadUserAccessDenied
            assert!(connect().create_session("anon").is_err());
        }
    }
    let _ = std::fs::remove_file(&users);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn server_diagnostics_summary() {
    let dir = temp_config("diagnostics", MACHINE);
    let addr = start(&dir, Limits::default());
    let read = |c: &mut Client, id: u32| c.read(&[(NodeId::ns0(id), 13)]).unwrap().remove(0).value.unwrap_or_default();
    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    c.create_session("diag").unwrap();
    assert_eq!(read(&mut c, 2277), Variant::UInt32(1)); // CurrentSessionCount
    assert_eq!(read(&mut c, 2278), Variant::UInt32(1)); // CumulatedSessionCount
    let (ty, _) = c.call(999_999, |_| {}).unwrap();
    assert_eq!(ty, ids::SERVICE_FAULT);
    assert_eq!(read(&mut c, 2288), Variant::UInt32(1)); // RejectedRequestsCount
    c.create_subscription(100.0, 30, 10).unwrap();
    assert_eq!(read(&mut c, 2285), Variant::UInt32(1)); // CurrentSubscriptionCount
    let Variant::ExtensionObject(x) = read(&mut c, 2275) else { panic!("summary is a structure") };
    assert_eq!(x.type_id, NodeId::ns0(861));
    let field = |i: usize| u32::from_le_bytes(x.body[i * 4..i * 4 + 4].try_into().unwrap());
    assert_eq!((field(1), field(2), field(7), field(8), field(11)), (1, 1, 1, 1, 1));
    c.close().unwrap();

    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    c.create_session("diag2").unwrap();
    assert_eq!(read(&mut c, 2277), Variant::UInt32(1));
    assert_eq!(read(&mut c, 2278), Variant::UInt32(2));
    assert_eq!(read(&mut c, 2285), Variant::UInt32(0)); // deleted with its session
    assert_eq!(read(&mut c, 2286), Variant::UInt32(1));
}

#[test]
fn session_diagnostics_arrays() {
    use fastua::codec::Reader;
    let dir = temp_config("sessdiag", MACHINE);
    let store = Store::open(&dir, ServerInfo::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut config = ServerConfig::all_endpoints(addr.clone(), format!("opc.tcp://{addr}"));
    config.anonymous = Some(Access::ReadWrite);
    config.session_diagnostics = true;
    let pki = Pki::open(&dir.join("pki"), "urn:test:fastua", "localhost", false).unwrap();
    let server = Server::new(store, config, pki, Users::default());
    std::thread::spawn(move || server.serve(listener));

    let read = |c: &mut Client, id: u32| c.read(&[(NodeId::ns0(id), 13)]).unwrap().remove(0).value.unwrap_or_default();
    let objects = |v: Variant| match v {
        Variant::Array(a) => a
            .items
            .into_iter()
            .map(|x| match x {
                Variant::ExtensionObject(x) => *x,
                other => panic!("not a structure: {other:?}"),
            })
            .collect::<Vec<_>>(),
        other => panic!("not an array: {other:?}"),
    };
    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    c.create_session("sd").unwrap();
    assert_eq!(read(&mut c, 2294), Variant::Boolean(true)); // EnabledFlag
    c.create_subscription(100.0, 30, 10).unwrap();

    let sessions = objects(read(&mut c, 3707));
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].type_id, NodeId::ns0(867));
    let mut r = Reader::new(&sessions[0].body);
    let id = r.node_id().unwrap();
    assert_eq!(r.str().unwrap(), Some("sd"));
    // ClientDescription, as the client sent it.
    assert_eq!(r.str().unwrap(), Some("urn:fastua:test-client"));
    r.str().unwrap();
    r.localized_text().unwrap();
    r.i32().unwrap();
    r.str().unwrap();
    r.str().unwrap();
    r.skip_string_array().unwrap();
    r.str().unwrap(); // ServerUri
    r.str().unwrap(); // EndpointUrl (the test client sends none)
    r.skip_string_array().unwrap(); // LocaleIds
    r.f64().unwrap(); // ActualSessionTimeout
    r.u32().unwrap(); // MaxResponseMessageSize
    let connected = r.i64().unwrap();
    assert!(connected > 0 && r.i64().unwrap() >= connected); // ClientLastContactTime
    assert_eq!(r.u32().unwrap(), 1); // CurrentSubscriptionsCount
    assert_eq!(r.u32().unwrap(), 0); // CurrentMonitoredItemsCount
    r.u32().unwrap(); // CurrentPublishRequestsInQueue
    let total = r.u32().unwrap(); // TotalRequestCount.TotalCount
    assert!(total >= 3, "{total} requests counted"); // Activate, Read, CreateSubscription
    r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), 0); // UnauthorizedRequestCount

    let security = objects(read(&mut c, 3708));
    assert_eq!((security.len(), security[0].type_id.clone()), (1, NodeId::ns0(870)));
    assert_eq!(Reader::new(&security[0].body).node_id().unwrap(), id);

    let subs = objects(read(&mut c, 2290));
    assert_eq!((subs.len(), subs[0].type_id.clone()), (1, NodeId::ns0(876)));
    let mut r = Reader::new(&subs[0].body);
    assert_eq!(r.node_id().unwrap(), id);
    r.u32().unwrap(); // SubscriptionId
    r.u8().unwrap();
    assert_eq!(r.f64().unwrap(), 100.0); // PublishingInterval
    c.close().unwrap();

    let mut c = Client::connect(&addr, "opc.tcp://x").unwrap();
    c.create_session("sd2").unwrap();
    assert_eq!(objects(read(&mut c, 3707)).len(), 1);
    assert!(objects(read(&mut c, 2290)).is_empty());
}
