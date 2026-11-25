//! Load client of the comparative benchmark (tests/compare/README.md).
//!
//! The same client measures any OPC UA server holding 100 writable Int32
//! variables `ns=<ns>;i=1..100`:
//!
//!   compare run <addr> <ns> <rsa server cert> <ecc server cert> <out.tsv>
//!   compare report <name>=<a.tsv> <name>=<b.tsv> ...
//!
//! `run` writes one `metric<TAB>value` line per measurement (latencies in
//! microseconds, throughputs in requests per second); `report` prints them
//! side by side as a Markdown table.
use fastua::client::Client;
use fastua::crypto::{Mode, Policy};
use fastua::ecc::{Curve, Suite};
use fastua::types::{NodeId, Variant};
use std::io::Write;
use std::time::{Duration, Instant};

struct Target {
    addr: String,
    ns: u16,
    rsa_cert: Vec<u8>,
    ecc_cert: Vec<u8>,
    rsa_client: (Vec<u8>, Vec<u8>),
    ecc_client: (Vec<u8>, Vec<u8>),
}

#[derive(Clone, Copy)]
enum Sec {
    None,
    Rsa,
    Ecc,
}

impl Sec {
    fn name(self) -> &'static str {
        match self {
            Sec::None => "None",
            Sec::Rsa => "Basic256Sha256 SignAndEncrypt",
            Sec::Ecc => "ECC_nistP256_AesGcm SignAndEncrypt",
        }
    }
}

impl Target {
    fn connect(&self, sec: Sec, spin: bool) -> Client {
        let url = format!("opc.tcp://{}", self.addr);
        let p256 = Suite::ALL[0];
        let mut c = match sec {
            Sec::None => Client::connect(&self.addr, &url),
            Sec::Rsa => Client::connect_secure(
                &self.addr,
                &url,
                Policy::Basic256Sha256,
                Mode::SignAndEncrypt,
                &self.rsa_client.0,
                &self.rsa_client.1,
                &self.rsa_cert,
            ),
            Sec::Ecc => Client::connect_secure(
                &self.addr,
                &url,
                Policy::Ecc(p256),
                Mode::SignAndEncrypt,
                &self.ecc_client.0,
                &self.ecc_client.1,
                &self.ecc_cert,
            ),
        }
        .unwrap_or_else(|e| panic!("{}: connect failed: {e}", sec.name()));
        c.spin = spin;
        c.create_session("compare").unwrap_or_else(|e| panic!("{}: session failed: {e}", sec.name()));
        c
    }

    fn items(&self, n: u32) -> Vec<(NodeId, u32)> {
        (1..=n).map(|i| (NodeId::Numeric(self.ns, i), 13)).collect()
    }
}

/// p50 and p99 of `n` timed calls of `f` (after `n / 10` warm-up calls), in µs.
fn latency(n: usize, mut f: impl FnMut(usize)) -> (f64, f64) {
    for i in 0..n / 10 {
        f(i);
    }
    let mut t = Vec::with_capacity(n);
    for i in 0..n {
        let s = Instant::now();
        f(i);
        t.push(s.elapsed().as_nanos() as u64);
    }
    t.sort_unstable();
    (t[n / 2] as f64 / 1000.0, t[n * 99 / 100] as f64 / 1000.0)
}

fn run(args: &[String]) {
    let [addr, ns, rsa, ecc, out] = args else {
        panic!("usage: compare run <addr> <ns> <rsa server cert> <ecc server cert> <out.tsv>")
    };
    let rsa_client = fastua::pki::generate_self_signed("urn:fastua:test-client", "localhost").unwrap();
    let ecc_client =
        fastua::pki::generate_self_signed_ecc(Curve::NistP256, "urn:fastua:test-client", "localhost").unwrap();
    let t = Target {
        addr: addr.clone(),
        ns: ns.parse().expect("namespace index"),
        rsa_cert: std::fs::read(rsa).expect("rsa server cert"),
        ecc_cert: std::fs::read(ecc).expect("ecc server cert"),
        rsa_client,
        ecc_client,
    };
    let mut rows: Vec<(String, f64)> = Vec::new();
    let mut put = |k: String, v: f64| {
        println!("{k:<62} {v:>12.1}");
        rows.push((k, v));
    };
    let one = t.items(1);
    let hundred = t.items(100);

    for sec in [Sec::None, Sec::Rsa, Sec::Ecc] {
        let s = sec.name();
        // Connection + secure channel + session setup.
        let (p50, _) = latency(20, |_| {
            let c = t.connect(sec, false);
            c.close().unwrap();
        });
        put(format!("{s} | connect + session, p50 (us)"), p50);
        for spin in [false, true] {
            let mode = if spin { "busy-poll client" } else { "blocking client" };
            let mut c = t.connect(sec, spin);
            let v = c.read(&one).unwrap();
            assert!(v[0].value.is_some() && v[0].status.unwrap_or(0) < 0x8000_0000, "{s}: bad read {v:?}");
            let (p50, p99) = latency(20_000, |_| {
                c.read(&one).unwrap();
            });
            put(format!("{s} | Read 1 value, {mode}, p50 (us)"), p50);
            put(format!("{s} | Read 1 value, {mode}, p99 (us)"), p99);
            if !spin {
                continue;
            }
            let (p50, p99) = latency(5_000, |_| {
                c.read(&hundred).unwrap();
            });
            put(format!("{s} | Read 100 values, p50 (us)"), p50);
            put(format!("{s} | Read 100 values, p99 (us)"), p99);
            let node = one[0].0.clone();
            let (p50, p99) = latency(20_000, |i| {
                let r = c.write(&[(node.clone(), Variant::Int32(i as i32))]).unwrap();
                assert_eq!(r[0], 0, "{s}: write failed");
            });
            put(format!("{s} | Write 1 value, p50 (us)"), p50);
            put(format!("{s} | Write 1 value, p99 (us)"), p99);
            // Pipelined: 64 Read requests in flight.
            let start = Instant::now();
            let mut n = 0;
            while start.elapsed() < Duration::from_secs(2) {
                c.read_pipelined(&one, 64).unwrap();
                n += 64;
            }
            put(format!("{s} | Read 1 value, 64 pipelined (req/s)"), n as f64 / start.elapsed().as_secs_f64());
        }
    }

    // Several clients at once (one connection + session each, blocking).
    let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
    for clients in [1, cores, 4 * cores] {
        let t = &t;
        let one = &one;
        let total: u64 = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..clients)
                .map(|_| {
                    sc.spawn(move || {
                        let mut c = t.connect(Sec::None, false);
                        let start = Instant::now();
                        let mut n = 0u64;
                        while start.elapsed() < Duration::from_secs(2) {
                            c.read(one).unwrap();
                            n += 1;
                        }
                        n
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum()
        });
        put(format!("None | {clients} clients, Read 1 value (req/s)"), total as f64 / 2.0);
    }

    let mut f = std::fs::File::create(out).expect("output file");
    for (k, v) in rows {
        writeln!(f, "{k}\t{v}").unwrap();
    }
}

fn report(args: &[String]) {
    let runs: Vec<(String, Vec<(String, f64)>)> = args
        .iter()
        .map(|a| {
            let (name, path) = a.split_once('=').expect("<name>=<file.tsv>");
            let text = std::fs::read_to_string(path).unwrap_or_default();
            let rows = text
                .lines()
                .filter_map(|l| l.split_once('\t'))
                .map(|(k, v)| (k.to_string(), v.parse().unwrap_or(f64::NAN)))
                .collect();
            (name.to_string(), rows)
        })
        .collect();
    let Some((_, first)) = runs.iter().find(|(_, r)| !r.is_empty()) else {
        println!("no results");
        return;
    };
    let names: Vec<&str> = runs.iter().map(|(n, _)| n.as_str()).collect();
    println!("| Measure | {} | {} / {} |", names.join(" | "), names[0], names[names.len() - 1]);
    println!("|---|{}---|", "---|".repeat(names.len()));
    for (k, _) in first {
        let vals: Vec<f64> =
            runs.iter().map(|(_, r)| r.iter().find(|(m, _)| m == k).map_or(f64::NAN, |(_, v)| *v)).collect();
        let (a, b) = (vals[0], vals[vals.len() - 1]);
        // "x times better" for the first column, whatever the unit.
        let gain = if k.ends_with("(req/s)") { a / b } else { b / a };
        let cells: Vec<String> = vals.iter().map(|v| format!("{v:.1}")).collect();
        println!("| {k} | {} | {gain:.2}x |", cells.join(" | "));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("report") => report(&args[1..]),
        _ => eprintln!("usage: compare run ... | compare report ..."),
    }
}
