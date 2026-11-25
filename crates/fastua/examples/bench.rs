//! Latency benchmark.
//!
//! `cargo run --release --example bench`
//!
//! 1. Service layer only: decode a Read request, look the node up, read the
//!    seqlock, encode the response. This is the CPU cost the server adds.
//! 2. Full round trip over loopback TCP with a blocking client (includes the
//!    kernel network stack on both sides, which dominates).

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
    let session = server.create_session("bench".into(), 1, 60_000.0, Security::NONE, vec![]).unwrap();
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
        let server = Server::new(store, spin_config, pki.clone(), Users::default());
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
    let server_cert = pki.cert_der.clone();
    let mut combos = vec![(Policy::None, Mode::None)];
    for p in Policy::SECURE {
        combos.push((p, Mode::Sign));
        combos.push((p, Mode::SignAndEncrypt));
    }
    for (policy, mode) in combos {
        let name = format!("{policy:?}/{mode:?}");
        println!(
            "secure crypto  {name:<36} {:>6.0} ns/Read (server: verify+decrypt request, sign+encrypt response)",
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
            println!("secure loopback {name:<35} {label}  p50 {p50:>6.1} us  p99 {p99:>6.1} us");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Server-side symmetric crypto of one Read x1 exchange (sizes of a real
/// request and response chunk), best of 5.
fn sym_cost(policy: Policy, mode: Mode) -> f64 {
    if mode == Mode::None {
        return 0.0;
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
