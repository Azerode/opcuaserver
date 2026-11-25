//! Historical access (HistoryRead / HistoryUpdate) over a real connection.

use fastua::address_space::ServerInfo;
use fastua::client::Client;
use fastua::codec::Writer;
use fastua::history::{UPDATE_INSERT, UPDATE_REPLACE, UPDATE_UPDATE};
use fastua::pki::Pki;
use fastua::reload::Store;
use fastua::server::{Limits, Server, ServerConfig};
use fastua::types::*;
use fastua::users::{Access, Users};
use std::net::TcpListener;
use std::path::PathBuf;

const MACHINE: &str = r#"{ "Name": "Oven", "Namespace": "urn:oven",
  "Subscriptions": [ { "Name": "DATA", "Items": [
    { "Name": "Temp", "NodeId": "ns=7;i=1", "Type": "Double", "Historizing": true, "HistoryCapacity": 100 },
    { "Name": "Mode", "NodeId": "ns=7;s=Mode", "Type": "String", "Historizing": true },
    { "Name": "Fixed", "NodeId": "ns=7;i=2", "Type": "Int32", "Historizing": true, "Writable": false },
    { "Name": "Plain", "NodeId": "ns=7;i=3", "Type": "Double" } ] } ] }"#;

const TEMP: NodeId = NodeId::Numeric(2, 1);
const FIXED: NodeId = NodeId::Numeric(2, 2);
const PLAIN: NodeId = NodeId::Numeric(2, 3);

fn start(name: &str) -> (String, PathBuf) {
    let dir = std::env::temp_dir().join(format!("fastua-hist-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("m.json"), MACHINE).unwrap();
    let store = Store::open(&dir, ServerInfo::default()).unwrap();
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
    c.create_session("hist").unwrap();
    c
}

fn encode(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut buf = Vec::new();
    f(&mut Writer::new(&mut buf));
    buf
}

fn raw(modified: bool, start: i64, end: i64, max: u32, bounds: bool) -> Vec<u8> {
    encode(|w| {
        w.bool(modified);
        w.i64(start);
        w.i64(end);
        w.u32(max);
        w.bool(bounds);
    })
}

fn update(node: &NodeId, mode: u32, values: &[(i64, f64)]) -> (u32, Vec<u8>) {
    let body = encode(|w| {
        w.node_id(node);
        w.u32(mode);
        w.i32(values.len() as i32);
        for &(t, v) in values {
            w.data_value(&DataValue { source_timestamp: Some(t), ..DataValue::value(Variant::Double(v)) });
        }
    });
    (ids::UPDATE_DATA_DETAILS_ENCODING, body)
}

fn times(v: &[DataValue]) -> Vec<i64> {
    v.iter().map(|d| d.source_timestamp.unwrap()).collect()
}

const T0: i64 = 133_000_000_000_000_000;
const S: i64 = 10_000_000; // one second in ticks

#[test]
fn writes_are_recorded_and_read_back() {
    let (addr, _dir) = start("record");
    let mut c = client(&addr);
    // Attributes.
    let v = c.read(&[(TEMP, 20), (TEMP, 17), (PLAIN, 20), (FIXED, 17)]).unwrap();
    assert_eq!(v[0].value, Some(Variant::Boolean(true)));
    assert_eq!(v[1].value, Some(Variant::Byte(0x0F)));
    assert_eq!(v[2].value, Some(Variant::Boolean(false)));
    assert_eq!(v[3].value, Some(Variant::Byte(0x05)));

    for x in [1.0, 2.0, 3.0] {
        assert_eq!(c.write(&[(TEMP, Variant::Double(x))]).unwrap(), vec![status::GOOD]);
    }
    c.write(&[(NodeId::String(2, "Mode".into()), Variant::string("auto"))]).unwrap();
    let r = c
        .history_read(
            ids::READ_RAW_MODIFIED_DETAILS_ENCODING,
            &raw(false, 1, now_ticks() + S, 0, false),
            2,
            false,
            &[(TEMP, None), (NodeId::String(2, "Mode".into()), None), (PLAIN, None), (NodeId::Numeric(2, 99), None)],
        )
        .unwrap()
        .unwrap();
    assert_eq!(r[0].status, status::GOOD);
    assert_eq!(r[0].type_id, ids::HISTORY_DATA_ENCODING);
    let vals: Vec<_> = r[0].values.iter().map(|d| d.value.clone().unwrap()).collect();
    assert_eq!(vals, vec![Variant::Double(1.0), Variant::Double(2.0), Variant::Double(3.0)]);
    assert!(r[0].values[0].server_timestamp.is_some());
    assert_eq!(r[1].values[0].value, Some(Variant::string("auto")));
    assert_eq!(r[2].status, status::BAD_HISTORY_OPERATION_UNSUPPORTED);
    assert_eq!(r[3].status, status::BAD_NODE_ID_UNKNOWN);

    // Bad requests.
    let fault = c
        .history_read(ids::READ_RAW_MODIFIED_DETAILS_ENCODING, &raw(false, 1, 2, 0, false), 3, false, &[(TEMP, None)])
        .unwrap();
    assert_eq!(fault, Err(status::BAD_TIMESTAMPS_TO_RETURN_INVALID));
    let r = c
        .history_read(ids::READ_RAW_MODIFIED_DETAILS_ENCODING, &raw(false, 0, 0, 0, false), 2, false, &[(TEMP, None)])
        .unwrap()
        .unwrap();
    assert_eq!(r[0].status, status::BAD_INVALID_TIMESTAMP_ARGUMENT);
    let fault = c.history_read(ids::READ_EVENT_DETAILS_ENCODING, &[], 2, false, &[(TEMP, None)]).unwrap();
    assert_eq!(fault, Err(status::BAD_HISTORY_OPERATION_UNSUPPORTED));
}

#[test]
fn update_delete_paging_and_at_time() {
    let (addr, _dir) = start("update");
    let mut c = client(&addr);
    let pts: Vec<(i64, f64)> = (0..10).map(|i| (T0 + i * S, i as f64)).collect();
    let r = c.history_update(&[update(&TEMP, UPDATE_INSERT, &pts)]).unwrap().unwrap();
    assert_eq!(r[0].0, status::GOOD);
    assert!(r[0].1.iter().all(|&x| x == status::GOOD_ENTRY_INSERTED));
    let r = c
        .history_update(&[
            update(&TEMP, UPDATE_INSERT, &[(T0, 9.0)]),
            update(&TEMP, UPDATE_REPLACE, &[(T0 + 3 * S, 30.0), (T0 + 100 * S, 1.0)]),
            update(&TEMP, UPDATE_UPDATE, &[(T0 + 20 * S, 20.0)]),
            update(&FIXED, UPDATE_INSERT, &[(T0, 1.0)]),
            update(&PLAIN, UPDATE_INSERT, &[(T0, 1.0)]),
        ])
        .unwrap()
        .unwrap();
    assert_eq!(r[0].1, vec![status::BAD_ENTRY_EXISTS]);
    assert_eq!(r[1].1, vec![status::GOOD_ENTRY_REPLACED, status::BAD_NO_ENTRY_EXISTS]);
    assert_eq!(r[2].1, vec![status::GOOD_ENTRY_INSERTED]);
    assert_eq!(r[3].0, status::BAD_NOT_WRITABLE);
    assert_eq!(r[4].0, status::BAD_HISTORY_OPERATION_UNSUPPORTED);

    // Paged read with bounds: 3 values per call.
    let details = raw(false, T0 + S / 2, T0 + 5 * S + S / 2, 3, true);
    let mut all = Vec::new();
    let mut cp = None;
    loop {
        let r = c
            .history_read(ids::READ_RAW_MODIFIED_DETAILS_ENCODING, &details, 0, false, &[(TEMP, cp.clone())])
            .unwrap()
            .unwrap();
        assert!(r[0].values.len() <= 3);
        assert!(r[0].values.iter().all(|v| v.server_timestamp.is_none()));
        all.extend(r[0].values.clone());
        cp = r[0].continuation_point.clone();
        if cp.is_none() {
            break;
        }
    }
    let want: Vec<i64> = (0..=6).map(|i| T0 + i * S).collect();
    assert_eq!(times(&all), want);
    assert_eq!(all[3].value, Some(Variant::Double(30.0)));

    // Releasing a continuation point; a foreign one is rejected.
    let r =
        c.history_read(ids::READ_RAW_MODIFIED_DETAILS_ENCODING, &details, 0, false, &[(TEMP, None)]).unwrap().unwrap();
    let cp = r[0].continuation_point.clone().unwrap();
    let r = c
        .history_read(ids::READ_RAW_MODIFIED_DETAILS_ENCODING, &details, 0, true, &[(TEMP, Some(cp.clone()))])
        .unwrap()
        .unwrap();
    assert_eq!((r[0].status, r[0].values.len()), (status::GOOD, 0));
    let r = c
        .history_read(ids::READ_RAW_MODIFIED_DETAILS_ENCODING, &details, 0, false, &[(FIXED, Some(cp))])
        .unwrap()
        .unwrap();
    assert_eq!(r[0].status, status::BAD_CONTINUATION_POINT_INVALID);

    // Modified values.
    let r = c
        .history_read(
            ids::READ_RAW_MODIFIED_DETAILS_ENCODING,
            &raw(true, T0 + 2 * S, T0 + 30 * S, 0, false),
            0,
            false,
            &[(TEMP, None)],
        )
        .unwrap()
        .unwrap();
    assert_eq!(r[0].type_id, ids::HISTORY_MODIFIED_DATA_ENCODING);
    // Inserts (2..10, 20) and the replace at 3 (logged with the old value).
    let mut want: Vec<i64> = (2..10).map(|i| T0 + i * S).chain([T0 + 3 * S, T0 + 20 * S]).collect();
    want.sort();
    assert_eq!(times(&r[0].values), want);
    let replaced = r[0].modifications.iter().position(|m| m.1 == UPDATE_REPLACE).unwrap();
    assert_eq!(r[0].values[replaced].value, Some(Variant::Double(3.0)));

    // At time: exact, interpolated, before the first value.
    let at = encode(|w| {
        w.i32(3);
        w.i64(T0 + 4 * S);
        w.i64(T0 + 4 * S + S / 2);
        w.i64(T0 - S);
        w.bool(true);
    });
    let r = c.history_read(ids::READ_AT_TIME_DETAILS_ENCODING, &at, 0, false, &[(TEMP, None)]).unwrap().unwrap();
    let v = &r[0].values;
    assert_eq!(v[0].value, Some(Variant::Double(4.0)));
    assert_eq!((v[1].value.clone(), v[1].status), (Some(Variant::Double(4.5)), Some(0x0402)));
    assert_eq!(v[2].status, Some(status::BAD_NO_DATA));

    // Delete a range and single times.
    let del = encode(|w| {
        w.node_id(&TEMP);
        w.bool(false);
        w.i64(T0 + 5 * S);
        w.i64(T0 + 30 * S);
    });
    let at = encode(|w| {
        w.node_id(&TEMP);
        w.i32(2);
        w.i64(T0);
        w.i64(T0 + S / 3);
    });
    let r = c
        .history_update(&[(ids::DELETE_RAW_MODIFIED_DETAILS_ENCODING, del), (ids::DELETE_AT_TIME_DETAILS_ENCODING, at)])
        .unwrap()
        .unwrap();
    assert_eq!(r[0].0, status::GOOD);
    assert_eq!(r[1].1, vec![status::GOOD, status::BAD_NO_ENTRY_EXISTS]);
    let r = c
        .history_read(
            ids::READ_RAW_MODIFIED_DETAILS_ENCODING,
            &raw(false, 1, T0 + 100 * S, 0, false),
            0,
            false,
            &[(TEMP, None)],
        )
        .unwrap()
        .unwrap();
    assert_eq!(times(&r[0].values), (1..5).map(|i| T0 + i * S).collect::<Vec<_>>());
}

fn processed(start: i64, end: i64, interval_ms: f64, aggs: &[u32]) -> Vec<u8> {
    encode(|w| {
        w.i64(start);
        w.i64(end);
        w.f64(interval_ms);
        w.i32(aggs.len() as i32);
        for &a in aggs {
            w.node_id(&NodeId::ns0(a));
        }
        // AggregateConfiguration: server defaults.
        w.bool(true);
        w.bool(true);
        w.u8(100);
        w.u8(100);
        w.bool(false);
    })
}

#[test]
fn processed_history_and_aggregate_functions() {
    let (addr, _dir) = start("processed");
    let mut c = client(&addr);
    let pts: Vec<(i64, f64)> = (0..10).map(|i| (T0 + i * S, i as f64)).collect();
    c.history_update(&[update(&TEMP, UPDATE_INSERT, &pts)]).unwrap().unwrap();
    let mode = NodeId::String(2, "Mode".into());
    c.write(&[(mode.clone(), Variant::string("auto"))]).unwrap();

    let read = |c: &mut Client, aggs: &[u32], nodes: &[NodeId]| {
        let nodes: Vec<_> = nodes.iter().map(|n| (n.clone(), None)).collect();
        c.history_read(
            ids::READ_PROCESSED_DETAILS_ENCODING,
            &processed(T0, T0 + 10 * S, 5000.0, aggs),
            0,
            false,
            &nodes,
        )
        .unwrap()
    };
    // Average (2342), Count (2352), Maximum (2347) per 5 s interval.
    let r = read(&mut c, &[2342, 2352, 2347], &[TEMP, TEMP, TEMP]).unwrap();
    let values = |i: usize| r[i].values.iter().map(|d| d.value.clone().unwrap()).collect::<Vec<_>>();
    assert_eq!(values(0), vec![Variant::Double(2.0), Variant::Double(7.0)]);
    assert_eq!(values(1), vec![Variant::Int32(5), Variant::Int32(5)]);
    assert_eq!(values(2), vec![Variant::Double(4.0), Variant::Double(9.0)]);
    assert_eq!(times(&r[0].values), vec![T0, T0 + 5 * S]);
    assert_eq!(r[0].values[0].status, Some(fastua::history::CALCULATED));

    // Errors.
    assert_eq!(read(&mut c, &[2342], &[TEMP, TEMP]), Err(status::BAD_AGGREGATE_LIST_MISMATCH));
    let r = read(&mut c, &[9999, 2342, 2352], &[TEMP, mode.clone(), mode.clone()]).unwrap();
    assert_eq!(r[0].status, status::BAD_AGGREGATE_NOT_SUPPORTED);
    assert_eq!(r[1].status, status::BAD_AGGREGATE_INVALID_INPUTS);
    assert_eq!(r[2].status, status::GOOD);

    // The functions are listed under ServerCapabilities.AggregateFunctions.
    let (_, _, targets) = c.browse(&NodeId::ns0(2997), 0).unwrap();
    assert!(targets.contains(&NodeId::ns0(2342)) && targets.len() >= 30, "{targets:?}");
    let (_, _, targets) = c.browse(&NodeId::ns0(ids::HISTORY_AGGREGATE_FUNCTIONS), 0).unwrap();
    assert!(targets.contains(&NodeId::ns0(2343)));
}

#[test]
fn aggregate_filter_on_monitored_items() {
    use fastua::client::MonitorSpec;
    let (addr, _dir) = start("aggfilter");
    let mut c = client(&addr);
    let (sub, ..) = c.create_subscription(20.0, 300, 10).unwrap();
    let agg = |node: NodeId, handle: u32, f: u32| MonitorSpec {
        aggregate: Some((0, f, 200.0)),
        queue_size: 10,
        ..MonitorSpec::value(node, handle)
    };
    let r = c.monitor(sub, &[agg(TEMP, 1, 2342), agg(PLAIN, 2, 2342), agg(TEMP, 3, 9999), agg(TEMP, 4, 2352)]).unwrap();
    let codes: Vec<u32> = r.iter().map(|x| x.0).collect();
    assert_eq!(
        codes,
        vec![status::GOOD, 0x8044_0000, status::BAD_AGGREGATE_NOT_SUPPORTED, status::GOOD],
        "{codes:08X?}"
    );
    assert!(r[0].2 <= 20.0 + 1e-9, "sampling {}", r[0].2);
    // Write during a few intervals; collect the averages and counts.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
    let (mut avgs, mut counts) = (Vec::new(), Vec::new());
    let mut acks = Vec::new();
    let mut x = 0.0;
    while std::time::Instant::now() < deadline {
        x += 1.0;
        c.write(&[(TEMP, Variant::Double(x))]).unwrap();
        let p = c.publish(&acks).unwrap();
        acks = vec![(sub, p.message.seq)];
        for (h, dv) in &p.message.data {
            match h {
                1 => avgs.push(dv.clone()),
                4 => counts.push(dv.clone()),
                _ => {}
            }
        }
    }
    assert!(avgs.len() >= 3, "{avgs:?}");
    // Intervals follow each other 200 ms apart, values are Calculated.
    let ts: Vec<i64> = avgs.iter().map(|d| d.source_timestamp.unwrap()).collect();
    assert!(ts.windows(2).all(|w| w[1] - w[0] == 2_000_000), "{ts:?}");
    let good: Vec<_> = avgs.iter().filter(|d| d.status == Some(fastua::history::CALCULATED)).collect();
    assert!(good.len() >= 2, "{avgs:?}");
    assert!(counts.iter().any(|d| matches!(d.value, Some(Variant::Int32(n)) if n > 0)), "{counts:?}");
}
