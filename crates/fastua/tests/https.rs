//! HTTPS transport (opc.https, https-uabinary): sessions, services and
//! Publish over TLS, and GetEndpoints filtering by transport profile.

use fastua::address_space::ServerInfo;
use fastua::client::{Client, MonitorSpec};
use fastua::codec::Reader;
use fastua::crypto::Policy;
use fastua::pki::Pki;
use fastua::reload::Store;
use fastua::server::{Limits, Server, ServerConfig, TRANSPORT_PROFILE_BINARY};
use fastua::types::*;
use fastua::users::{Access, Users};
use std::net::TcpListener;
use std::path::PathBuf;

const MACHINE: &str = r#"{ "Name": "Press", "Namespace": "urn:press",
  "Subscriptions": [ { "Name": "DATA", "Items": [
    { "Name": "Force", "NodeId": "ns=4;i=1", "Type": "Double" } ] } ] }"#;

const FORCE: NodeId = NodeId::Numeric(2, 1);

/// (opc.tcp address, HTTPS address, server certificate, directory)
fn start(name: &str) -> (String, String, Vec<u8>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("fastua-https-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    std::fs::write(dir.join("cfg/m.json"), MACHINE).unwrap();
    let store = Store::open(&dir.join("cfg"), ServerInfo::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let https_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let https_addr = https_listener.local_addr().unwrap().to_string();
    let mut config = ServerConfig::all_endpoints(addr.clone(), format!("opc.tcp://{addr}"));
    config.limits = Limits::default();
    config.anonymous = Some(Access::ReadWrite);
    config.https_url = Some(format!("opc.https://{https_addr}"));
    let pki = Pki::open(&dir.join("pki"), "urn:test:fastua", "localhost", false).unwrap();
    let cert = pki.certificate_for(Policy::None).to_vec();
    let key = std::fs::read(dir.join("pki/own/private/fastua.pk8")).unwrap();
    let tls = fastua::https::tls_config(&cert, &key, fastua::https::ClientAuth::Optional).unwrap();
    let server = Server::new(store, config, pki, Users::default());
    let s = server.clone();
    std::thread::spawn(move || fastua::https::serve(s, https_listener, tls));
    std::thread::spawn(move || server.serve(listener));
    (addr, https_addr, cert, dir)
}

/// GetEndpoints with profile filter: (url, transport profile) of each.
fn endpoints(c: &mut Client, profiles: &[&str]) -> Vec<(String, String)> {
    let (ty, body) = c
        .call(ids::GET_ENDPOINTS_REQUEST, |w| {
            w.str(None);
            w.i32(0);
            w.i32(profiles.len() as i32);
            for p in profiles {
                w.string(p);
            }
        })
        .unwrap();
    assert_eq!(ty, ids::GET_ENDPOINTS_RESPONSE);
    let mut r = Reader::new(body);
    fastua::client::skip_response_header(&mut r).unwrap();
    r.array(0, |r| {
        let url = r.str()?.unwrap_or("").to_string();
        r.str()?;
        r.str()?;
        r.localized_text()?;
        r.i32()?;
        r.str()?;
        r.str()?;
        r.skip_string_array()?;
        r.bytes()?;
        r.u32()?;
        r.str()?;
        r.array(0, |r| {
            r.str()?;
            r.i32()?;
            r.str()?;
            r.str()?;
            r.str()?;
            Ok(())
        })?;
        let profile = r.str()?.unwrap_or("").to_string();
        r.u8()?;
        Ok((url, profile))
    })
    .unwrap()
}

#[test]
#[ignore]
fn latency_https_vs_tcp() {
    let (addr, https_addr, cert, _dir) = start("latency");
    let mut h = Client::connect_https(&https_addr, "localhost", &cert).unwrap();
    h.create_session("h").unwrap();
    let mut t = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
    t.create_session("t").unwrap();
    for (name, c) in [("https", &mut h), ("tcp", &mut t)] {
        for _ in 0..1000 {
            c.read(&[(FORCE, 13)]).unwrap();
        }
        let n = 20000;
        let s = std::time::Instant::now();
        for _ in 0..n {
            c.read(&[(FORCE, 13)]).unwrap();
        }
        println!("{name} read rtt {:.1} us", s.elapsed().as_secs_f64() * 1e6 / n as f64);
    }
}

#[test]
fn services_over_https() {
    let (addr, https_addr, cert, dir) = start("services");
    let mut c = Client::connect_https(&https_addr, "localhost", &cert).unwrap();

    // Every endpoint, or one transport.
    let all = endpoints(&mut c, &[]);
    let https: Vec<_> = all.iter().filter(|e| e.1 == fastua::https::TRANSPORT_PROFILE_HTTPS).collect();
    assert_eq!(https.len(), 1);
    assert_eq!(https[0].0, format!("opc.https://{https_addr}"));
    let only = endpoints(&mut c, &[fastua::https::TRANSPORT_PROFILE_HTTPS]);
    assert_eq!(only.len(), 1);
    let tcp = endpoints(&mut c, &[TRANSPORT_PROFILE_BINARY]);
    assert_eq!(tcp.len(), all.len() - 1);
    assert!(tcp.iter().all(|e| e.1 == TRANSPORT_PROFILE_BINARY));

    c.create_session("https").unwrap();
    assert_eq!(c.write(&[(FORCE, Variant::Double(4.5))]).unwrap(), vec![status::GOOD]);
    let v = c.read(&[(FORCE, 13)]).unwrap();
    assert_eq!(v[0].value, Some(Variant::Double(4.5)));

    // Publish holds its response until a notification is due.
    let (sub, ..) = c.create_subscription(10.0, 300, 10).unwrap();
    assert_eq!(c.monitor(sub, &[MonitorSpec::value(FORCE, 7)]).unwrap()[0].0, status::GOOD);
    let p = c.publish(&[]).unwrap();
    assert_eq!(p.message.data.len(), 1);
    assert_eq!(p.message.data[0].1.value, Some(Variant::Double(4.5)));
    // A second connection: writes reach the subscription of the first.
    let mut c2 = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
    c2.create_session("tcp").unwrap();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        c2.write(&[(FORCE, Variant::Double(9.0))]).unwrap();
    });
    let p = c.publish(&[(p.subscription, p.message.seq)]).unwrap();
    writer.join().unwrap();
    assert_eq!(p.message.data[0].1.value, Some(Variant::Double(9.0)));
    let _ = std::fs::remove_dir_all(dir);
}

/// TLS client certificates: checked against the application trust list,
/// then the session's certificate and ApplicationUri.
#[test]
fn client_certificates() {
    let (_, https_addr, cert, dir) = start("client-certs");
    let (mine, key) = fastua::pki::generate_self_signed("urn:fastua:test-client", "localhost").unwrap();
    let connect = |c: &[u8], k: &[u8]| Client::connect_https_as(&https_addr, "localhost", &cert, Some((c, k))).unwrap();

    // Not trusted: the connection is refused (403) at the first request.
    assert!(connect(&mine, &key).create_session("untrusted").is_err());

    let trusted = dir.join("pki/trusted/certs");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::write(trusted.join("client.der"), &mine).unwrap();
    let mut c = connect(&mine, &key);
    c.create_session("tls-client").unwrap();
    assert_eq!(c.read(&[(FORCE, 13)]).unwrap().len(), 1);

    // Trusted, but CreateSession names another ApplicationUri.
    let (other, other_key) = fastua::pki::generate_self_signed("urn:other", "localhost").unwrap();
    std::fs::write(trusted.join("other.der"), &other).unwrap();
    let err = connect(&other, &other_key).create_session("other").unwrap_err();
    assert!(err.to_string().contains("80170000"), "{err}"); // BadCertificateUriInvalid

    // Without a certificate (optional): as before.
    let mut c = Client::connect_https(&https_addr, "localhost", &cert).unwrap();
    c.create_session("anonymous").unwrap();
    let _ = std::fs::remove_dir_all(dir);
}
