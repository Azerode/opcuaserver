//! Latency benchmark.
//!
//! `cargo run --release --example bench`
//!
//! 1. Service layer only: decode a Read request, look the node up, read the
//!    seqlock, encode the response. This is the CPU cost the server adds.
//! 2. Full round trip over loopback TCP with a blocking client (includes the
//!    kernel network stack on both sides, which dominates).
//! 3. Secure channels: server-side crypto per Read and round trips.
//! 4. Subscriptions: engine cost per item, write -> notification latency.

use fastua::address_space::ServerInfo;
use fastua::channel::Security;
use fastua::client::Client;
use fastua::codec::{Reader, Writer};
use fastua::crypto::{ChannelKeys, Mode, Policy};
use fastua::pki::Pki;
use fastua::reload::Store;
use fastua::server::{Server, ServerConfig};
use fastua::services;
use fastua::types::*;
use fastua::users::Users;
use std::hint::black_box;
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::time::Instant;

fn percentile(sorted: &[u64], p: f64) -> u64 {
    sorted[((sorted.len() as f64 - 1.0) * p) as usize]
}

fn coarse_ticks() -> i64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut t) };
    t.tv_sec * 10_000_000 + t.tv_nsec / 100
}

fn main() {
    let dir = std::env::temp_dir().join(format!("fastua-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let items: Vec<String> =
        (0..10_000).map(|i| format!(r#"{{"Name":"v{i}","NodeId":"i={i}","Type":"Double"}}"#)).collect();
    std::fs::write(
        dir.join("bench.json"),
        format!(r#"{{"Namespace":"urn:bench","Subscriptions":[{{"Name":"G","Items":[{}]}}]}}"#, items.join(",")),
    )
    .unwrap();

    let store = Store::open(&dir, ServerInfo::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let pki = Pki::open(&dir.join("pki"), "urn:bench", "localhost", false).unwrap();
    let mut config = ServerConfig::all_endpoints(addr.clone(), format!("opc.tcp://{addr}"));
    config.anonymous = Some(fastua::users::Access::ReadWrite);
    let spin_config = {
        let mut c = config.clone();
        c.busy_poll = std::time::Duration::from_micros(200);
        c
    };
    let server = Server::new(store.clone(), config, pki.clone(), Users::default());

    // ---- 0. clock costs (one precise read per request is unavoidable)
    for (name, f) in [("now_ticks (CLOCK_REALTIME)", now_ticks as fn() -> i64), ("coarse clock", coarse_ticks)] {
        let n = 5_000_000;
        let mut best = f64::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            for _ in 0..n {
                black_box(f());
            }
            best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
        }
        println!("clock          {name:<27} {best:>5.1} ns");
    }

    // ---- 1. service layer
    let session = server.create_session("bench".into(), 1, 60_000.0, Security::NONE, vec![], vec![]).unwrap();
    session.activated.store(true, Ordering::Release);
    for batch in [1usize, 10, 100] {
        let mut req = Vec::new();
        {
            let mut w = Writer::new(&mut req);
            w.node_id(&NodeId::ns0(ids::READ_REQUEST));
            w.node_id(&session.token);
            w.i64(0);
            w.u32(1);
            w.u32(0);
            w.str(None);
            w.u32(0);
            w.null_extension_object();
            w.f64(0.0);
            w.u32(2);
            w.i32(batch as i32);
            for i in 0..batch {
                w.node_id(&NodeId::Numeric(2, (i * 97 % 10_000) as u32));
                w.u32(13);
                w.str(None);
                w.u16(0);
                w.str(None);
            }
        }
        let mut cache = Some(session.clone());
        let mut space = None;
        let mut conn = services::ConnState::new(1 << 20);
        let mut out = Vec::with_capacity(65536);
        let iters = 2_000_000 / batch;
        for _ in 0..iters / 10 {
            out.clear();
            let mut ctx = services::Ctx {
                server: &server,
                channel_id: 1,
                security: &Security::NONE,
                session: &mut cache,
                space: &mut space,
                conn: &mut conn,
            };
            services::dispatch(&mut ctx, &mut Reader::new(&req), &mut Writer::new(&mut out));
        }
        // Best of 7 runs: the minimum filters out scheduler / VM noise.
        let mut ns = f64::MAX;
        for _ in 0..7 {
            let t = Instant::now();
            for _ in 0..iters {
                out.clear();
                let mut ctx = services::Ctx {
                    server: &server,
                    channel_id: 1,
                    security: &Security::NONE,
                    session: &mut cache,
                    space: &mut space,
                    conn: &mut conn,
                };
                black_box(services::dispatch(&mut ctx, &mut Reader::new(black_box(&req)), &mut Writer::new(&mut out)));
            }
            ns = ns.min(t.elapsed().as_nanos() as f64 / iters as f64);
        }
        println!("service layer  Read x{batch:<4} {ns:>9.0} ns/request  {:>6.1} ns/value", ns / batch as f64);
    }

    // ---- 2. loopback round trip (client and server threads on the same host)
    {
        let server = server.clone();
        std::thread::spawn(move || server.serve(listener));
    }
    let spin_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let spin_addr = spin_listener.local_addr().unwrap().to_string();
    {
        let server = Server::new(store.clone(), spin_config, pki.clone(), Users::default());
        std::thread::spawn(move || server.serve(spin_listener));
    }
    loopback("server blocking, client blocking ", &addr, false);
    loopback("server busy-poll, client blocking", &spin_addr, false);
    loopback("server busy-poll, client busy-poll", &spin_addr, true);

    // ---- 3. secure channels (mutual certificate authentication)
    let (client_cert, client_key) = fastua::pki::generate_self_signed("urn:fastua:test-client", "localhost").unwrap();
    let trusted = dir.join("pki/trusted/certs");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::write(trusted.join("bench-client.der"), &client_cert).unwrap();
    let mut combos = vec![(Policy::None, Mode::None)];
    let ecc = fastua::ecc::Suite::ALL.into_iter().map(Policy::Ecc);
    for p in Policy::SECURE.into_iter().chain(ecc) {
        combos.push((p, Mode::Sign));
        combos.push((p, Mode::SignAndEncrypt));
    }
    let mut ecc_clients = Vec::new();
    for curve in [fastua::ecc::Curve::NistP256, fastua::ecc::Curve::NistP384, fastua::ecc::Curve::Curve25519] {
        let (cert, key) = fastua::pki::generate_self_signed_ecc(curve, "urn:fastua:test-client", "localhost").unwrap();
        std::fs::write(trusted.join(format!("bench-client-{curve:?}.der")), &cert).unwrap();
        ecc_clients.push((curve, cert, key));
    }
    for (policy, mode) in combos {
        let name = match policy {
            Policy::Ecc(s) => format!("{}/{mode:?}", s.uri().rsplit_once('#').unwrap().1),
            _ => format!("{policy:?}/{mode:?}"),
        };
        let server_cert = pki.certificate_for(policy).to_vec();
        let (client_cert, client_key) = match policy.ecc() {
            Some(s) => {
                let (_, c, k) = ecc_clients.iter().find(|(c, _, _)| *c == s.curve).unwrap();
                (c.clone(), k.clone())
            }
            None => (client_cert.clone(), client_key.clone()),
        };
        println!(
            "secure crypto  {name:<42} {:>6.0} ns/Read (server: verify+decrypt request, sign+encrypt response)",
            sym_cost(policy, mode)
        );
        for (label, a, spin) in [("blocking ", &addr, false), ("busy-poll", &spin_addr, true)] {
            let mut c = if policy == Policy::None {
                Client::connect(a, &format!("opc.tcp://{a}")).unwrap()
            } else {
                Client::connect_secure(
                    a,
                    &format!("opc.tcp://{a}"),
                    policy,
                    mode,
                    &client_cert,
                    &client_key,
                    &server_cert,
                )
                .unwrap()
            };
            c.spin = spin;
            c.create_session("bench").unwrap();
            let (p50, p99) = round_trips(&mut c, 30_000);
            println!("secure loopback {name:<41} {label}  p50 {p50:>6.1} us  p99 {p99:>6.1} us");
        }
    }

    // ---- 4. subscriptions
    subscription_engine(&store);
    event_engine(&store);
    history_engine();
    let fast_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fast_addr = fast_listener.local_addr().unwrap().to_string();
    {
        let mut c = ServerConfig::all_endpoints(fast_addr.clone(), format!("opc.tcp://{fast_addr}"));
        c.anonymous = Some(fastua::users::Access::ReadWrite);
        c.busy_poll = std::time::Duration::from_micros(200);
        c.limits.min_publishing_interval_ms = 0.1;
        c.limits.min_sampling_interval_ms = 0.1;
        let server = Server::new(store.clone(), c, pki.clone(), Users::default());
        std::thread::spawn(move || server.serve(fast_listener));
    }
    notify_latency("interval 1 ms,   blocking ", &addr, 1.0, false);
    notify_latency("interval 1 ms,   busy-poll", &spin_addr, 1.0, true);
    notify_latency("interval 0.1 ms, busy-poll", &fast_addr, 0.1, true);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cost of the subscription engine on 10 000 Double items: a sampling pass
/// over unchanged values, and sample + queue + encode of changed values.
fn subscription_engine(store: &Store) {
    use fastua::address_space::{NodeKind, ValueSource};
    use fastua::server::Limits;
    use fastua::subscription::{ItemParams, PublishRequest, SessionSubs, SubParams, Subscription};
    let space = store.load_full();
    let n = 10_000u32;
    let l = Limits::default();
    let cells: Vec<_> = (0..n)
        .map(|i| match &space.get(&NodeId::Numeric(2, i)).unwrap().kind {
            NodeKind::Variable { value: ValueSource::Cell(c), .. } => c.clone(),
            _ => unreachable!(),
        })
        .collect();
    let mut st = SessionSubs::default();
    let mut sub = Subscription::new(1, SubParams::revise(&l, 1.0, 1_000_000, 10, 0, 0), true, 0);
    for i in 0..n {
        let p = ItemParams {
            client_handle: i,
            sampling_ms: 1.0,
            filter: Default::default(),
            percent_deadband: false,
            filter_present: false,
            queue_size: 1,
            discard_oldest: true,
        };
        sub.create_item(&l, &space, NodeId::Numeric(2, i), 13, 2, (true, true), &p, true, 0).unwrap();
    }
    st.subs.push(sub);
    let mut out = Vec::with_capacity(1 << 20);
    let mut now = 0u64;
    let mut seq = None;
    // `every`: write one value in `every` (0 = none).
    let mut cycle = |st: &mut SessionSubs, every: usize, round: u64| -> u64 {
        if every > 0 {
            for c in cells.iter().skip(round as usize % every).step_by(every) {
                c.write(&Variant::Double(round as f64), status::GOOD, 1, 2);
            }
        }
        let mut acks = st.ack_buffer();
        if let Some(q) = seq.take() {
            acks.push(st.acknowledge(1, q));
        }
        let _ = st.queue(&l, PublishRequest { request_id: 1, channel_id: 1, handle: 1, deadline: u64::MAX, acks });
        now += 1_000_000;
        let t = Instant::now();
        st.tick(now, &space);
        out.clear();
        st.write_next(&l, now, 1, 64 << 20, &mut Writer::new(&mut out), true);
        // Kept for Republish as the connection thread does after sending.
        let kept = st.keep_sent(&mut out, true);
        let ns = t.elapsed().as_nanos() as u64;
        if kept {
            seq = Some(st.subs[0].sequence().wrapping_sub(1));
        }
        ns
    };
    for (label, every) in
        [("unchanged values (sampling pass)", 0), ("1 % changed (per item)", 100), ("changed values (notification)", 1)]
    {
        let mut best = u64::MAX;
        for round in 0..200 {
            best = best.min(cycle(&mut st, every, round + 1));
        }
        println!("subscription   {label:<34} {:>6.2} ns/item", best as f64 / n as f64);
    }
}

/// Server event -> EventFieldList: emit, where clause, select clauses and
/// encoding, per event (batches of 1000 between two publishes).
/// Cost of a write with and without history, and of a raw history read.
fn history_engine() {
    use fastua::history::RawQuery;
    use fastua::value::ValueCell;
    let n = 2_000_000;
    // Source timestamps keep increasing across runs (in-order history).
    let clock = std::cell::Cell::new(0i64);
    let run = |c: &ValueCell| {
        let mut best = f64::MAX;
        for _ in 0..7 {
            let t = Instant::now();
            for i in 0..n {
                let ts = clock.get() + 1;
                clock.set(ts);
                c.write(black_box(&Variant::Double(i as f64)), status::GOOD, ts, 2);
            }
            best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
        }
        best
    };
    let plain = ValueCell::new(builtin::DOUBLE, 0);
    let hist = ValueCell::new(builtin::DOUBLE, 0);
    hist.set_history(Some(10_000));
    println!("history        write, no history  {:>6.1} ns", run(&plain));
    println!("history        write, historized  {:>6.1} ns", run(&hist));
    // With --history-dir: the journal is emptied by the persistence thread
    // every second; here every 100 000 writes, outside the timing.
    let persisted = ValueCell::new(builtin::DOUBLE, 0);
    persisted.set_history(Some(10_000));
    persisted.history().unwrap().start_persisting(Vec::new(), Vec::new(), false);
    let mut best = f64::MAX;
    for _ in 0..7 {
        let mut ns = 0;
        for _ in 0..20 {
            let t = Instant::now();
            for i in 0..100_000 {
                let ts = clock.get() + 1;
                clock.set(ts);
                persisted.write(black_box(&Variant::Double(i as f64)), status::GOOD, ts, 2);
            }
            ns += t.elapsed().as_nanos();
            persisted.history().unwrap().take_for_disk(|s, _| {
                black_box(s);
            });
        }
        best = best.min(ns as f64 / 2_000_000.0);
    }
    println!("history        write, persisted   {best:>6.1} ns");
    let h = hist.history().unwrap();
    let last = clock.get();
    let mut out = Vec::with_capacity(1 << 20);
    for count in [1usize, 100, 1000] {
        let q = RawQuery { modified: false, start: last - count as i64 + 1, end: last + 1, max: 0, bounds: false };
        let iters = 200_000 / count;
        let mut best = f64::MAX;
        for _ in 0..7 {
            let t = Instant::now();
            for _ in 0..iters {
                // As the service does: encode each DataValue under the lock.
                out.clear();
                let mut w = Writer::new(&mut out);
                black_box(h.read_raw_with(black_box(&q), None, |s, _| {
                    w.u8(0x0D);
                    w.variant(&s.value);
                    w.i64(s.source_ts);
                    w.i64(s.server_ts);
                }))
                .unwrap();
            }
            best = best.min(t.elapsed().as_nanos() as f64 / iters as f64);
        }
        println!("history        read raw x{count:<5}    {best:>8.0} ns  {:>6.1} ns/value", best / count as f64);
    }
    aggregates_engine(h, last);
}

/// Processed reads as the service computes them: one window, then every
/// interval of 100 values.
fn aggregates_engine(h: &fastua::history::History, last: i64) {
    use fastua::aggregates::{compute, intervals, Config, Window};
    let n = 10_000i64;
    let (start, end) = (last - n + 1, last + 1);
    let cfg = Config::default();
    let mut best = f64::MAX;
    for _ in 0..7 {
        let t = Instant::now();
        black_box(h.window_with(start, end, |w| w.values.len()));
        best = best.min(t.elapsed().as_nanos() as f64);
    }
    println!("aggregates     window       10000 values                  {:>6.1} ns/value", best / n as f64);
    for (name, agg) in [("Average", 2342u32), ("TimeAverage", 2343), ("Minimum", 2346), ("StdDev", 11426)] {
        let mut best = f64::MAX;
        for _ in 0..7 {
            let t = Instant::now();
            h.window_with(start, end, |all| {
                let values = all.values;
                for (s, e, partial, ts) in intervals(start, end, 0.01) {
                    let a = values.partition_point(|x| x.source_ts < s);
                    let b = values.partition_point(|x| x.source_ts < e);
                    let w = Window {
                        before: if a > 0 { values.get(a - 1) } else { all.before },
                        values: &values[a..b],
                        after: values.get(b).or(all.after),
                    };
                    black_box(compute(agg, h.kind(), false, &cfg, s, e, partial, ts, &w));
                }
            });
            best = best.min(t.elapsed().as_nanos() as f64);
        }
        println!("aggregates     {name:<12} 10000 values / 100 intervals  {:>6.1} ns/value", best / n as f64);
    }
}

fn event_engine(store: &Store) {
    use fastua::events::{types::*, Event, LITERAL_OPERAND, SIMPLE_ATTRIBUTE_OPERAND};
    use fastua::server::Limits;
    use fastua::subscription::{ItemParams, PublishRequest, SessionSubs, SubParams, Subscription};
    let space = store.load_full();
    let l = Limits::default();
    // Select EventId, EventType, SourceName, Time, Message, Severity where Severity >= 100.
    let mut body = Vec::new();
    let mut w = Writer::new(&mut body);
    let field = |w: &mut Writer, name: &str| {
        w.node_id(&NodeId::ns0(BASE_EVENT_TYPE));
        w.i32(1);
        w.qualified_name(&QualifiedName { ns: 0, name: name.into() });
        w.u32(13);
        w.str(None);
    };
    let fields = ["EventId", "EventType", "SourceName", "Time", "Message", "Severity"];
    w.i32(fields.len() as i32);
    for f in fields {
        field(&mut w, f);
    }
    w.i32(1);
    w.u32(4); // GreaterThanOrEqual
    w.i32(2);
    let at = w.begin_extension_object(SIMPLE_ATTRIBUTE_OPERAND);
    field(&mut w, "Severity");
    w.end_extension_object(at);
    let at = w.begin_extension_object(LITERAL_OPERAND);
    w.variant(&Variant::UInt16(100));
    w.end_extension_object(at);
    let (filter, _) = fastua::events::parse_filter(&body).unwrap();
    let mut st = SessionSubs::default();
    let mut sub = Subscription::new(1, SubParams::revise(&l, 1.0, 1_000_000, 10, 0, 0), true, 0);
    let p = ItemParams {
        client_handle: 1,
        sampling_ms: 0.0,
        filter: Default::default(),
        percent_deadband: false,
        filter_present: true,
        queue_size: 10_000,
        discard_oldest: true,
    };
    sub.create_event_item(&l, &space, NodeId::ns0(2253), 2, &p, filter).unwrap();
    st.subs.push(sub);
    let n = 1000;
    let mut out = Vec::with_capacity(1 << 20);
    let mut best = u64::MAX;
    let mut now = 0;
    for _ in 0..50 {
        let t = Instant::now();
        for i in 0..n {
            let ev = Event::new(BASE_MODEL_CHANGE_EVENT_TYPE, NodeId::ns0(2253), "Server", "reloaded", 100 + i as u16);
            space.events.emit(ev);
        }
        let acks = st.ack_buffer();
        let _ = st.queue(&l, PublishRequest { request_id: 1, channel_id: 1, handle: 1, deadline: u64::MAX, acks });
        now += 1_000_000;
        st.tick(now, &space);
        out.clear();
        st.write_next(&l, now, 1, 64 << 20, &mut Writer::new(&mut out), true);
        assert!(out.len() > n * 50);
        st.keep_sent(&mut out, true);
        best = best.min(t.elapsed().as_nanos() as u64);
        let seq = st.subs[0].sequence().wrapping_sub(1);
        st.acknowledge(1, seq);
    }
    println!("events         {:<34} {:>6.0} ns/event", "emit -> EventFieldList (6 fields)", best as f64 / n as f64);
}

/// Time from a Write by one client to the DataChangeNotification received by
/// another (publishing and sampling interval `interval_ms`).
fn notify_latency(label: &str, addr: &str, interval_ms: f64, spin: bool) {
    use fastua::client::MonitorSpec;
    let url = format!("opc.tcp://{addr}");
    let mut writer = Client::connect(addr, &url).unwrap();
    writer.create_session("writer").unwrap();
    let mut c = Client::connect(addr, &url).unwrap();
    c.create_session("subscriber").unwrap();
    writer.spin = spin;
    c.spin = spin;
    let node = NodeId::Numeric(2, 7);
    let (sub, ..) = c.create_subscription(interval_ms, 100_000, 100_000).unwrap();
    let mut spec = MonitorSpec::value(node.clone(), 1);
    spec.sampling_ms = interval_ms;
    c.monitor(sub, &[spec]).unwrap();
    for _ in 0..3 {
        c.send_publish(&[]).unwrap();
    }
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let n = 400;
    let mut samples = Vec::with_capacity(n);
    for i in 0..n + 20 {
        // Random phase relative to the server's timers.
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let pause = std::time::Duration::from_nanos(rng % (interval_ms * 1e6) as u64);
        let until = Instant::now() + pause;
        while Instant::now() < until {
            std::hint::spin_loop();
        }
        let v = -(i as f64) - 1.0;
        let t = Instant::now();
        writer.write(&[(node.clone(), Variant::Double(v))]).unwrap();
        loop {
            let p = c.receive_publish().unwrap();
            let acks: Vec<(u32, u32)> = if p.message.data.is_empty() { vec![] } else { vec![(sub, p.message.seq)] };
            c.send_publish(&acks).unwrap();
            if p.message.data.iter().any(|(_, d)| d.value == Some(Variant::Double(v))) {
                break;
            }
        }
        if i >= 20 {
            samples.push(t.elapsed().as_nanos() as u64);
        }
    }
    samples.sort_unstable();
    println!(
        "subscription   write -> notification  {label}  p50 {:>7.1} us  p99 {:>7.1} us",
        percentile(&samples, 0.5) as f64 / 1000.0,
        percentile(&samples, 0.99) as f64 / 1000.0
    );
}

/// Server-side symmetric crypto of one Read x1 exchange (sizes of a real
/// request and response chunk), best of 5.
fn sym_cost(policy: Policy, mode: Mode) -> f64 {
    if mode == Mode::None {
        return 0.0;
    }
    if let Policy::Ecc(suite) = policy {
        return aead_cost(suite, mode);
    }
    let keys = ChannelKeys::derive(policy, &[7; 32], &[9; 32]).unwrap();
    let (req_len, resp_len) = (128usize, 96usize); // encrypted part: multiples of 16
    let mut req = vec![0x5Au8; 8 + req_len + 32];
    let mut resp = vec![0xA5u8; 8 + resp_len];
    let n = 200_000;
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            if mode == Mode::SignAndEncrypt {
                keys.remote.decrypt(&mut req[8..8 + req_len]).unwrap();
            }
            black_box(keys.remote.verify_parts(&[&req[..8], &req[8..8 + req_len]], &req[8 + req_len..]));
            resp.truncate(8 + resp_len);
            let sig = keys.local.sign(&resp);
            resp.extend_from_slice(&sig);
            if mode == Mode::SignAndEncrypt {
                keys.local.encrypt(&mut resp[8..8 + resp_len + 32]).unwrap();
            }
            black_box(&resp);
        }
        best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
    }
    best
}

/// [`sym_cost`] for an ECC AEAD policy: open the request, seal the response.
fn aead_cost(suite: fastua::ecc::Suite, mode: Mode) -> f64 {
    let mut ikm = vec![0u8; suite.secret_len()];
    let secret = vec![3u8; suite.secret_len()];
    let keys = fastua::ecc::EccKeys::derive(suite, &mut ikm, &secret, &[7; 32], &[9; 32]).unwrap();
    let (req_len, resp_len) = (128usize, 96usize);
    let mut req = vec![0x5Au8; 16 + req_len];
    let mut resp = vec![0xA5u8; 16 + resp_len];
    // A valid request to open, sealed once by the "client" side.
    let mut client = vec![0u8; suite.secret_len()];
    let ck = fastua::ecc::EccKeys::derive(suite, &mut client, &secret, &[7; 32], &[9; 32]).unwrap();
    let (aad, data) = req.split_at_mut(16);
    let tag = if mode == Mode::SignAndEncrypt {
        ck.remote.seal(1, 41, aad, data).unwrap()
    } else {
        ck.remote.seal(1, 41, &req, &mut []).unwrap()
    };
    let sealed = req.clone();
    let n = 200_000;
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            req.copy_from_slice(&sealed);
            if mode == Mode::SignAndEncrypt {
                let (aad, data) = req.split_at_mut(16);
                keys.remote.open(1, 41, aad, data, &tag).unwrap();
            } else {
                keys.remote.open(1, 41, &req, &mut [], &tag).unwrap();
            }
            let t = if mode == Mode::SignAndEncrypt {
                let (aad, data) = resp.split_at_mut(16);
                keys.local.seal(1, 42, aad, data).unwrap()
            } else {
                keys.local.seal(1, 42, &resp, &mut []).unwrap()
            };
            black_box((&req, &resp, t));
        }
        best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
    }
    best
}

fn round_trips(c: &mut Client, n: usize) -> (f64, f64) {
    let node = [(NodeId::Numeric(2, 42), 13)];
    for _ in 0..2_000 {
        c.read(&node).unwrap();
    }
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        black_box(c.read(&node).unwrap());
        samples.push(t.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    (percentile(&samples, 0.5) as f64 / 1000.0, percentile(&samples, 0.99) as f64 / 1000.0)
}

fn loopback(label: &str, addr: &str, client_spin: bool) {
    let mut c = Client::connect(addr, &format!("opc.tcp://{addr}")).unwrap();
    c.spin = client_spin;
    c.create_session("bench").unwrap();
    let node = [(NodeId::Numeric(2, 42), 13)];
    for _ in 0..2_000 {
        c.read(&node).unwrap();
    }
    let n = 50_000;
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        black_box(c.read(&node).unwrap());
        samples.push(t.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    println!(
        "loopback TCP   Read x1  {label}  p50 {:>6.1} us  p99 {:>6.1} us  p99.9 {:>6.1} us",
        percentile(&samples, 0.5) as f64 / 1000.0,
        percentile(&samples, 0.99) as f64 / 1000.0,
        percentile(&samples, 0.999) as f64 / 1000.0
    );
}
