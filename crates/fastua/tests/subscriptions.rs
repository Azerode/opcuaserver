//! Subscriptions and MonitoredItems over a real loopback connection.

use fastua::address_space::ServerInfo;
use fastua::client::{Client, MonitorSpec, Publish};
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
    { "Name": "Speed", "NodeId": "ns=7;i=1", "Type": "System.Double" },
    { "Name": "Count", "NodeId": "ns=7;i=2", "Type": "System.Int32" },
    { "Name": "Label", "NodeId": "ns=7;s=Label", "Type": "String" },
    { "Name": "Level", "NodeId": "ns=7;i=3", "Type": "Double", "EURange": { "Low": -50, "High": 150 } } ] } ] }"#;

fn start(name: &str) -> (String, PathBuf) {
    let dir = std::env::temp_dir().join(format!("fastua-sub-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("m.json"), MACHINE).unwrap();
    let store = Store::open(&dir, ServerInfo::default()).unwrap();
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

fn client(addr: &str) -> Client {
    let mut c = Client::connect(addr, &format!("opc.tcp://{addr}")).unwrap();
    c.create_session("sub").unwrap();
    c
}

const SPEED: NodeId = NodeId::Numeric(2, 1);
const COUNT: NodeId = NodeId::Numeric(2, 2);
const LEVEL: NodeId = NodeId::Numeric(2, 3);

/// Publishes until a message with data (or a status change) arrives.
fn next_data(c: &mut Client, acks: &[(u32, u32)]) -> Publish {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut acks = acks.to_vec();
    loop {
        let p = c.publish(&acks).unwrap();
        assert_eq!(p.fault, 0, "publish fault {:08X}", p.fault);
        if !p.message.is_keep_alive() {
            return p;
        }
        acks.clear();
        assert!(Instant::now() < deadline, "no notification");
    }
}

#[test]
fn data_changes_keep_alive_ack_and_republish() {
    let (addr, _dir) = start("basic");
    let mut c = client(&addr);
    let (sub, interval, lifetime, keepalive) = c.create_subscription(5.0, 300, 10).unwrap();
    assert_eq!((interval, lifetime, keepalive), (5.0, 300, 10));

    let mut attr_item = MonitorSpec::value(SPEED, 3);
    attr_item.attribute = 3; // BrowseName
    let r = c
        .monitor(
            sub,
            &[
                MonitorSpec::value(SPEED, 1),
                MonitorSpec::value(NodeId::String(2, "Label".into()), 2),
                attr_item,
                MonitorSpec::value(NodeId::Numeric(2, 99), 4),
            ],
        )
        .unwrap();
    assert_eq!(r[0].0, status::GOOD);
    assert_eq!(r[0].2, 1.0, "sampling 0 is revised to the server minimum");
    assert_eq!(r[0].3, 1);
    assert_eq!(r[1].0, status::GOOD);
    assert_eq!(r[2].0, status::GOOD);
    assert_eq!(r[3].0, status::BAD_NODE_ID_UNKNOWN);

    // Initial values of the three valid items.
    let p = next_data(&mut c, &[]);
    assert_eq!(p.subscription, sub);
    assert_eq!(p.message.seq, 1);
    assert_eq!(p.available, vec![1]);
    let mut handles: Vec<u32> = p.message.data.iter().map(|(h, _)| *h).collect();
    handles.sort();
    assert_eq!(handles, vec![1, 2, 3]);
    let speed = &p.message.data.iter().find(|(h, _)| *h == 1).unwrap().1;
    assert_eq!(speed.status, Some(status::UNCERTAIN_INITIAL_VALUE));
    assert!(speed.source_timestamp.is_some() && speed.server_timestamp.is_some());
    let name = &p.message.data.iter().find(|(h, _)| *h == 3).unwrap().1;
    assert!(matches!(name.value, Some(Variant::QualifiedName(_))));
    assert_eq!(name.source_timestamp, None, "no source timestamp on non-Value attributes");

    // Nothing changes: keep-alives carry the next sequence number.
    let p = c.publish(&[(sub, 1)]).unwrap();
    assert_eq!(p.ack_results, vec![status::GOOD]);
    assert!(p.message.is_keep_alive());
    assert_eq!(p.message.seq, 2);
    assert!(p.available.is_empty());

    c.write(&[(SPEED, Variant::Double(12.5)), (NodeId::String(2, "Label".into()), Variant::string("x"))]).unwrap();
    let p = next_data(&mut c, &[]);
    assert_eq!(p.message.seq, 2);
    let mut got: Vec<(u32, Option<Variant>)> = p.message.data.iter().map(|(h, d)| (*h, d.value.clone())).collect();
    got.sort_by_key(|g| g.0);
    assert_eq!(got, vec![(1, Some(Variant::Double(12.5))), (2, Some(Variant::string("x")))]);
    assert_eq!(p.message.data[0].1.status, None, "Good status is not encoded");

    // Republish returns the same message until it is acknowledged.
    let m = c.republish(sub, 2).unwrap().unwrap();
    assert_eq!(m.seq, 2);
    assert_eq!(m.data.len(), 2);
    assert_eq!(c.republish(sub, 1).unwrap().unwrap_err(), BAD_MESSAGE_NOT_AVAILABLE);
    assert_eq!(c.republish(sub + 1000, 2).unwrap().unwrap_err(), BAD_SUBSCRIPTION_ID_INVALID);
    let p = c.publish(&[(sub, 2), (sub, 77), (sub + 1000, 1)]).unwrap();
    assert_eq!(p.ack_results, vec![status::GOOD, BAD_SEQUENCE_NUMBER_UNKNOWN, BAD_SUBSCRIPTION_ID_INVALID]);
    assert_eq!(c.republish(sub, 2).unwrap().unwrap_err(), BAD_MESSAGE_NOT_AVAILABLE);

    // Writing the same value again is not a change (trigger StatusValue).
    c.write(&[(SPEED, Variant::Double(12.5))]).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let p = c.publish(&[]).unwrap();
    assert!(p.message.is_keep_alive(), "{p:?}");
}

#[test]
fn queue_overflow_and_deadband() {
    let (addr, _dir) = start("queue");
    let mut c = client(&addr);
    // Long publishing interval: samples accumulate in the queue.
    let (sub, ..) = c.create_subscription(400.0, 300, 10).unwrap();
    let mut q = MonitorSpec::value(SPEED, 1);
    q.queue_size = 3;
    q.sampling_ms = 1.0;
    let mut db = MonitorSpec::value(COUNT, 2);
    db.filter = Some((1, 1, 5.0)); // StatusValue, absolute deadband 5
    let r = c.monitor(sub, &[q, db]).unwrap();
    assert_eq!(r[0].3, 3);
    assert_eq!(r[1].0, status::GOOD);
    for i in 1..=5 {
        c.write(&[(SPEED, Variant::Double(i as f64)), (COUNT, Variant::Int32(i * 2))]).unwrap();
        std::thread::sleep(Duration::from_millis(15));
    }
    let p = next_data(&mut c, &[]);
    let speeds: Vec<&fastua::types::DataValue> =
        p.message.data.iter().filter(|(h, _)| *h == 1).map(|(_, d)| d).collect();
    let values: Vec<Option<Variant>> = speeds.iter().map(|d| d.value.clone()).collect();
    assert_eq!(values, vec![Some(Variant::Double(3.0)), Some(Variant::Double(4.0)), Some(Variant::Double(5.0))]);
    // Oldest discarded: the new oldest carries the Overflow bit.
    assert_eq!(speeds[0].status.unwrap_or(0) & 0x0480, 0x0480);
    assert_eq!(speeds[1].status, None);
    // Count (queue of 1): 2 is reported because the status changed
    // (UncertainInitialValue -> Good), then only |delta| > 5: 8, not 10.
    let counts: Vec<Option<Variant>> =
        p.message.data.iter().filter(|(h, _)| *h == 2).map(|(_, d)| d.value.clone()).collect();
    assert_eq!(counts, vec![Some(Variant::Int32(8))]);

    // Invalid filters.
    let mut bad = MonitorSpec::value(NodeId::String(2, "Label".into()), 3);
    bad.filter = Some((1, 1, 1.0));
    let mut pct = MonitorSpec::value(SPEED, 4);
    pct.filter = Some((1, 2, 10.0));
    let mut neg = MonitorSpec::value(SPEED, 5);
    neg.filter = Some((1, 1, -1.0));
    let r = c.monitor(sub, &[bad, pct, neg]).unwrap();
    assert_eq!(r[0].0, BAD_FILTER_NOT_ALLOWED);
    // Percent deadband without EURange.
    assert_eq!(r[1].0, BAD_FILTER_NOT_ALLOWED);
    assert_eq!(r[2].0, BAD_DEADBAND_FILTER_INVALID);
}

#[test]
fn percent_deadband_uses_eu_range() {
    let (addr, _dir) = start("percent");
    let mut c = client(&addr);
    // The EURange property of the AnalogItem.
    let range = c.read(&[(NodeId::String(2, "__prop/i=3/EURange".into()), 13)]).unwrap();
    assert_eq!(range[0].value, Some(fastua::address_space::range_value(-50.0, 150.0)));

    let (sub, ..) = c.create_subscription(10.0, 300, 10).unwrap();
    let mut pct = MonitorSpec::value(LEVEL, 1);
    pct.filter = Some((1, 2, 10.0)); // 10 % of 200 = 20
    pct.sampling_ms = 1.0;
    let mut over = MonitorSpec::value(LEVEL, 2);
    over.filter = Some((1, 2, 150.0));
    let r = c.monitor(sub, &[pct, over]).unwrap();
    assert_eq!(r[0].0, status::GOOD);
    assert_eq!(r[1].0, BAD_DEADBAND_FILTER_INVALID);
    let mut seen = Vec::new();
    let mut acks = Vec::new();
    for v in [5.0, 15.0, 30.0, 45.0, 51.0] {
        c.write(&[(LEVEL, Variant::Double(v))]).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        loop {
            let p = c.publish(&acks).unwrap();
            acks.clear();
            if p.message.is_keep_alive() {
                break;
            }
            acks.push((p.subscription, p.message.seq));
            seen.extend(p.message.data.iter().filter_map(|(_, d)| d.value.clone()));
            if !p.more {
                break;
            }
        }
    }
    // 5 replaces the initial value (queue of 1), then only |delta| > 20.
    let want: Vec<Variant> = [5.0, 30.0, 51.0].into_iter().map(Variant::Double).collect();
    assert_eq!(seen, want);
}

#[test]
fn triggering_and_monitoring_mode() {
    let (addr, _dir) = start("trigger");
    let mut c = client(&addr);
    let (sub, ..) = c.create_subscription(5.0, 300, 10).unwrap();
    let mut sampled = MonitorSpec::value(COUNT, 2);
    sampled.mode = 1; // Sampling
    let r = c.monitor(sub, &[MonitorSpec::value(SPEED, 1), sampled]).unwrap();
    let (trigger, linked) = (r[0].1, r[1].1);
    let p = next_data(&mut c, &[]);
    assert_eq!(p.message.data.len(), 1, "Sampling items do not report");

    let (ty, _) = c
        .call(ids::SET_TRIGGERING_REQUEST, |w| {
            w.u32(sub);
            w.u32(trigger);
            w.i32(2);
            w.u32(linked);
            w.u32(9999);
            w.i32(0);
        })
        .unwrap();
    assert_eq!(ty, ids::SET_TRIGGERING_RESPONSE);

    c.write(&[(COUNT, Variant::Int32(7))]).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    assert!(c.publish(&[]).unwrap().message.is_keep_alive());
    // The triggering item reports: the linked item reports its queue too.
    c.write(&[(SPEED, Variant::Double(1.0))]).unwrap();
    let p = next_data(&mut c, &[]);
    let mut handles: Vec<u32> = p.message.data.iter().map(|(h, _)| *h).collect();
    handles.sort();
    assert_eq!(handles, vec![1, 2]);

    // Disable the trigger: nothing more.
    let (ty, body) = c
        .call(ids::SET_MONITORING_MODE_REQUEST, |w| {
            w.u32(sub);
            w.u32(0);
            w.i32(2);
            w.u32(trigger);
            w.u32(4242);
        })
        .unwrap();
    assert_eq!(ty, ids::SET_MONITORING_MODE_RESPONSE);
    let mut r = fastua::codec::Reader::new(body);
    fastua::client::skip_response_header(&mut r).unwrap();
    assert_eq!(r.array(4, |r| r.u32()).unwrap(), vec![status::GOOD, BAD_MONITORED_ITEM_ID_INVALID]);
    c.write(&[(SPEED, Variant::Double(2.0))]).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    assert!(c.publish(&[]).unwrap().message.is_keep_alive());
}

#[test]
fn delete_lifetime_and_publish_errors() {
    let (addr, _dir) = start("delete");
    let mut c = client(&addr);
    let p = c.publish(&[]).unwrap();
    assert_eq!(p.fault, BAD_NO_SUBSCRIPTION);

    // A queued Publish is answered Bad_NoSubscription once the last
    // subscription is deleted.
    let (sub, ..) = c.create_subscription(1000.0, 300, 100).unwrap();
    c.send_publish(&[]).unwrap(); // first cycle: keep-alive after 1 s
    c.send_publish(&[]).unwrap();
    c.send(ids::DELETE_SUBSCRIPTIONS_REQUEST, |w| {
        w.i32(2);
        w.u32(sub);
        w.u32(sub + 1);
    })
    .unwrap();
    let mut faults = 0;
    let mut deleted = false;
    for _ in 0..3 {
        let (ty, body) = c.receive().unwrap();
        if ty == ids::DELETE_SUBSCRIPTIONS_RESPONSE {
            let mut r = fastua::codec::Reader::new(body);
            fastua::client::skip_response_header(&mut r).unwrap();
            assert_eq!(r.array(4, |r| r.u32()).unwrap(), vec![status::GOOD, BAD_SUBSCRIPTION_ID_INVALID]);
            deleted = true;
        } else {
            assert_eq!(fastua::client::service_result(body), BAD_NO_SUBSCRIPTION);
            faults += 1;
        }
    }
    assert!(deleted);
    assert_eq!(faults, 2);

    // Lifetime: 3 cycles of 5 ms without any Publish request.
    let (sub, _, lifetime, _) = c.create_subscription(5.0, 3, 1).unwrap();
    assert_eq!(lifetime, 3);
    std::thread::sleep(Duration::from_millis(60));
    let p = c.publish(&[]).unwrap();
    assert_eq!(p.subscription, sub);
    assert_eq!(p.message.status_change, Some(status::BAD_TIMEOUT));
    assert_eq!(c.publish(&[]).unwrap().fault, BAD_NO_SUBSCRIPTION);
}

#[test]
fn transfer_to_another_session() {
    let (addr, _dir) = start("transfer");
    let mut a = client(&addr);
    let (sub, ..) = a.create_subscription(5.0, 3000, 10).unwrap();
    a.monitor(sub, &[MonitorSpec::value(SPEED, 1)]).unwrap();
    next_data(&mut a, &[]);

    let mut b = client(&addr);
    let (ty, body) = b
        .call(ids::TRANSFER_SUBSCRIPTIONS_REQUEST, |w| {
            w.i32(2);
            w.u32(sub);
            w.u32(55555);
            w.bool(true);
        })
        .unwrap();
    assert_eq!(ty, ids::TRANSFER_SUBSCRIPTIONS_RESPONSE);
    let mut r = fastua::codec::Reader::new(body);
    fastua::client::skip_response_header(&mut r).unwrap();
    let res = r.array(8, |r| Ok((r.u32()?, r.array(4, |r| r.u32())?))).unwrap();
    assert_eq!(res[0], (status::GOOD, vec![1]));
    assert_eq!(res[1].0, BAD_SUBSCRIPTION_ID_INVALID);

    // The old session is told; the new one gets the initial values again.
    let p = a.publish(&[]).unwrap();
    assert_eq!(p.subscription, sub);
    assert_eq!(p.message.status_change, Some(GOOD_SUBSCRIPTION_TRANSFERRED));
    let p = next_data(&mut b, &[]);
    assert_eq!(p.subscription, sub);
    assert_eq!(p.message.data[0].0, 1);
    b.write(&[(SPEED, Variant::Double(3.0))]).unwrap();
    let p = next_data(&mut b, &[]);
    assert_eq!(p.message.data[0].1.value, Some(Variant::Double(3.0)));
}

#[test]
fn notifications_follow_hot_reload() {
    let (addr, dir) = start("reload");
    let mut c = client(&addr);
    let (sub, ..) = c.create_subscription(5.0, 3000, 10).unwrap();
    c.monitor(sub, &[MonitorSpec::value(COUNT, 1)]).unwrap();
    next_data(&mut c, &[]);
    // Count disappears from the configuration.
    std::fs::write(
        dir.join("m.json"),
        r#"{ "Name": "Press", "Namespace": "urn:press", "Subscriptions": [ { "Name": "DATA", "Items": [
        { "Name": "Speed", "NodeId": "ns=7;i=1", "Type": "System.Double" } ] } ] }"#,
    )
    .unwrap();
    let p = next_data(&mut c, &[]);
    assert_eq!(p.message.data[0].1.status, Some(status::BAD_NODE_ID_UNKNOWN));
}
