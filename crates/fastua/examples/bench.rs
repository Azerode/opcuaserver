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
    let server = Server::new(store, config, pki, Users::default());

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

    // ---- 2. loopback round trip
    {
        let server = server.clone();
        std::thread::spawn(move || server.serve(listener));
    }
    let mut c = Client::connect(&addr, &format!("opc.tcp://{addr}")).unwrap();
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
        "loopback TCP   Read x1    p50 {:>6.1} us  p99 {:>6.1} us  p99.9 {:>6.1} us",
        percentile(&samples, 0.5) as f64 / 1000.0,
        percentile(&samples, 0.99) as f64 / 1000.0,
        percentile(&samples, 0.999) as f64 / 1000.0
    );
    let _ = std::fs::remove_dir_all(&dir);
}
