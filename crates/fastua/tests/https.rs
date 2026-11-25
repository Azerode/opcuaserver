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
    assert_eq!(tcp.len(), all.len() - 2);
    let json = endpoints(&mut c, &[fastua::https::TRANSPORT_PROFILE_HTTPS_JSON]);
    assert_eq!(json.len(), 1);
    assert_eq!(json[0].0, https[0].0);
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

/// https-uajson: the same services with JSON bodies, transcoded around
/// the binary service layer.
#[test]
fn json_encoding() {
    let (addr, https_addr, cert, dir) = start("json");
    let mut c = Client::connect_https(&https_addr, "localhost", &cert).unwrap();
    let call = |c: &mut Client, json: String| -> serde_json::Value {
        let out = c.call_json(&json).unwrap();
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"))
    };

    // GetEndpoints, sessionless: the type id may be the DataType or its
    // binary encoding.
    let v = call(
        &mut c,
        r#"{"TypeId":"i=426","Body":{"RequestHeader":{},"ProfileUris":
        ["http://opcfoundation.org/UA-Profile/Transport/https-uajson"]}}"#
            .into(),
    );
    assert_eq!(v["TypeId"], "i=429", "{v}"); // GetEndpointsResponse
    let e = &v["Body"]["Endpoints"];
    assert_eq!(e.as_array().unwrap().len(), 1, "{v}");
    assert_eq!(e[0]["EndpointUrl"], format!("opc.https://{https_addr}"));
    assert_eq!(e[0]["SecurityMode"], 1);
    assert!(e[0]["ServerCertificate"].as_str().unwrap().len() > 100);

    let v = call(
        &mut c,
        format!(
            r#"{{"TypeId":"i=459","Body":{{"RequestHeader":{{"Timestamp":"2026-01-01T00:00:00Z","RequestHandle":7}},
        "ClientDescription":{{"ApplicationUri":"urn:json","ApplicationName":{{"Text":"json"}},"ApplicationType":1}},
        "EndpointUrl":"opc.https://{https_addr}","SessionName":"json","RequestedSessionTimeout":60000,"MaxResponseMessageSize":0}}}}"#
        ),
    );
    assert_eq!(v["TypeId"], "i=462", "{v}"); // CreateSessionResponse
    let h = &v["Body"]["ResponseHeader"];
    assert_eq!(h["RequestHandle"], 7);
    assert!(h.get("ServiceResult").is_none(), "Good is omitted: {v}");
    let token = v["Body"]["AuthenticationToken"].as_str().unwrap().to_string();
    assert_eq!(v["Body"]["RevisedSessionTimeout"], 60000.0);

    let v = call(
        &mut c,
        format!(
            r#"{{"TypeId":"i=465","Body":{{"RequestHeader":{{"AuthenticationToken":"{token}"}},
        "UserIdentityToken":{{"TypeId":"i=319","Body":{{"PolicyId":"anonymous"}}}}}}}}"#
        ),
    );
    assert_eq!(v["TypeId"], "i=468", "{v}"); // ActivateSessionResponse

    // Write then Read the Double, by namespace URI.
    let v = call(
        &mut c,
        format!(
            r#"{{"TypeId":"i=673","Body":{{"RequestHeader":{{"AuthenticationToken":"{token}"}},
        "NodesToWrite":[{{"NodeId":"nsu=urn:press;i=1","AttributeId":13,"Value":{{"UaType":11,"Value":2.5}}}}]}}}}"#
        ),
    );
    assert_eq!(v["TypeId"], "i=674", "{v}");
    let w = v["Body"]["Results"].as_array().unwrap();
    assert!(w.len() == 1 && w[0].get("Code").is_none_or(|c| c == 0), "{v}");
    let v = call(
        &mut c,
        format!(
            r#"{{"TypeId":"i=629","Body":{{"RequestHeader":{{"AuthenticationToken":"{token}"}},
        "TimestampsToReturn":2,"NodesToRead":[{{"NodeId":"nsu=urn:press;i=1","AttributeId":13}},
        {{"NodeId":"i=2256","AttributeId":13}},{{"NodeId":"i=2255","AttributeId":13}}]}}}}"#
        ),
    );
    assert_eq!(v["TypeId"], "i=632", "{v}"); // ReadResponse
    let r = &v["Body"]["Results"];
    // A DataValue carries its Variant's fields inline.
    assert_eq!((&r[0]["UaType"], &r[0]["Value"]), (&serde_json::json!(11), &serde_json::json!(2.5)), "{v}");
    assert!(r[0]["ServerTimestamp"].as_str().unwrap().ends_with('Z'), "{v}");
    // ServerStatus: an ExtensionObject with its JSON body.
    assert_eq!(r[1]["UaType"], 22, "{v}");
    assert_eq!(r[1]["Value"]["TypeId"], "i=862", "{v}");
    assert!(r[1]["Value"]["Body"]["StartTime"].is_string(), "{v}");
    // NamespaceArray: a String array.
    let ns = r[2]["Value"].as_array().unwrap();
    assert_eq!(ns[0], "http://opcfoundation.org/UA/");
    assert!(ns.iter().any(|n| n == "urn:press"), "{v}");

    // The binary client sees what JSON wrote.
    let mut b = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
    b.create_session("tcp").unwrap();
    assert_eq!(b.read(&[(FORCE, 13)]).unwrap()[0].value, Some(Variant::Double(2.5)));

    // A service error: a ServiceFault in JSON.
    let v = call(
        &mut c,
        r#"{"TypeId":"i=629","Body":{"RequestHeader":{"AuthenticationToken":"i=1"},
        "NodesToRead":[{"NodeId":"i=2256","AttributeId":13}]}}"#
            .into(),
    );
    assert_eq!(v["TypeId"], "i=395", "{v}"); // ServiceFault
    assert!(v["Body"]["ResponseHeader"]["ServiceResult"]["Code"].as_u64().unwrap() != 0, "{v}");

    // Not JSON, or an unknown type: 400.
    let err = c.call_json("{").unwrap_err();
    assert!(err.to_string().contains("400"), "{err}");
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
