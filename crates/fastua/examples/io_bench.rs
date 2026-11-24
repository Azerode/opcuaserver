//! Transport comparison: blocking thread-per-connection vs io_uring.
//!
//! `cargo run --release --example io_bench`
//!
//! Both servers run the exact same work per request: parse the 24-byte MSG
//! chunk header, run the real service layer (`services::dispatch`) on a Read
//! request, frame the response. Only the I/O model differs:
//!
//! - `blocking`: one OS thread per connection, blocking `read`/`write`.
//! - `io_uring`: one thread per core, each with its own ring and its own
//!   SO_REUSEPORT listener; recv/send/accept are submitted to the ring.
//!
//! Clients are closed-loop (send, wait for answer, repeat), each on its own
//! thread with a blocking socket, so the figures are round-trip latencies.

use fastua::address_space::ServerInfo;
use fastua::codec::{Reader, Writer};
use fastua::reload::Store;
use fastua::server::{Limits, Server, ServerConfig, Session};
use fastua::services;
use fastua::types::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HDR: usize = 24;

/// Runs one request chunk (`chunk` = full MSG chunk) and appends the framed response to `out`.
#[inline]
fn handle(server: &Arc<Server>, cache: &mut Option<Arc<Session>>, chunk: &[u8], out: &mut Vec<u8>) {
    let at = out.len();
    out.resize(at + HDR, 0);
    {
        let mut w = Writer::new(out);
        let mut ctx = services::Ctx { server, channel_id: 1, session: cache };
        services::dispatch(&mut ctx, &mut Reader::new(&chunk[HDR..]), &mut w);
    }
    let size = (out.len() - at) as u32;
    let h = &mut out[at..at + HDR];
    h[..4].copy_from_slice(b"MSGF");
    h[4..8].copy_from_slice(&size.to_le_bytes());
    h[8..24].copy_from_slice(&chunk[8..24]);
}

fn read_request(token: &NodeId, nodes: usize) -> Vec<u8> {
    let mut buf = vec![0u8; HDR];
    let mut w = Writer::new(&mut buf);
    w.node_id(&NodeId::ns0(ids::READ_REQUEST));
    w.node_id(token);
    w.i64(0);
    w.u32(1);
    w.u32(0);
    w.str(None);
    w.u32(0);
    w.null_extension_object();
    w.f64(0.0);
    w.u32(2);
    w.i32(nodes as i32);
    for i in 0..nodes {
        w.node_id(&NodeId::Numeric(2, i as u32 * 7));
        w.u32(13);
        w.str(None);
        w.u16(0);
        w.str(None);
    }
    let size = buf.len() as u32;
    buf[..4].copy_from_slice(b"MSGF");
    buf[4..8].copy_from_slice(&size.to_le_bytes());
    buf
}

// ------------------------------------------------------------------ blocking

fn blocking_server(server: Arc<Server>, listener: TcpListener) {
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let server = server.clone();
            std::thread::spawn(move || {
                let mut s = s;
                s.set_nodelay(true).unwrap();
                let mut cache = None;
                let mut rx = vec![0u8; 65536];
                let mut tx = Vec::with_capacity(65536);
                loop {
                    if s.read_exact(&mut rx[..8]).is_err() {
                        return;
                    }
                    let size = u32::from_le_bytes(rx[4..8].try_into().unwrap()) as usize;
                    if size > rx.len() || s.read_exact(&mut rx[8..size]).is_err() {
                        return;
                    }
                    tx.clear();
                    handle(&server, &mut cache, &rx[..size], &mut tx);
                    if s.write_all(&tx).is_err() {
                        return;
                    }
                }
            });
        }
    });
}

// ------------------------------------------------------------------ io_uring

#[cfg(target_os = "linux")]
mod uring {
    use super::*;
    use io_uring::{opcode, types, IoUring};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};

    struct Conn {
        fd: RawFd,
        rx: Vec<u8>,
        filled: usize,
        tx: Vec<u8>,
        sent: usize,
        cache: Option<Arc<Session>>,
    }

    const OP_ACCEPT: u64 = 0;
    const OP_RECV: u64 = 1;
    const OP_SEND: u64 = 2;

    fn reuseport_listener(addr: &str) -> TcpListener {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            let one: libc::c_int = 1;
            for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
                libc::setsockopt(fd, libc::SOL_SOCKET, opt, (&one as *const i32).cast(), 4);
            }
            let sa: std::net::SocketAddrV4 = addr.parse().unwrap();
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: sa.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(sa.ip().octets()) },
                sin_zero: [0; 8],
            };
            assert_eq!(libc::bind(fd, (&raw as *const libc::sockaddr_in).cast(), 16), 0, "bind");
            assert_eq!(libc::listen(fd, 1024), 0);
            TcpListener::from_raw_fd(fd)
        }
    }

    pub fn server(server: Arc<Server>, addr: &str, threads: usize) {
        for _ in 0..threads {
            let listener = reuseport_listener(addr);
            let server = server.clone();
            std::thread::spawn(move || run(server, listener));
        }
    }

    fn run(server: Arc<Server>, listener: TcpListener) {
        // Tuned for latency: completions run in this thread only, at submit time.
        let mut ring = IoUring::builder()
            .setup_single_issuer()
            .setup_defer_taskrun()
            .setup_coop_taskrun()
            .build(1024)
            .or_else(|_| IoUring::new(1024))
            .unwrap();
        let lfd = listener.as_raw_fd();
        let mut conns: Vec<Option<Conn>> = Vec::new();
        let push = |ring: &mut IoUring, e: io_uring::squeue::Entry| unsafe {
            while ring.submission().push(&e).is_err() {
                ring.submit().unwrap();
            }
        };
        let accept = opcode::Accept::new(types::Fd(lfd), std::ptr::null_mut(), std::ptr::null_mut())
            .build()
            .user_data(OP_ACCEPT);
        push(&mut ring, accept.clone());
        loop {
            ring.submit_and_wait(1).unwrap();
            let done: Vec<(u64, i32)> = ring.completion().map(|c| (c.user_data(), c.result())).collect();
            for (ud, res) in done {
                let op = ud & 3;
                let idx = (ud >> 2) as usize;
                match op {
                    OP_ACCEPT => {
                        if res >= 0 {
                            let fd = res;
                            let one: libc::c_int = 1;
                            unsafe {
                                libc::setsockopt(
                                    fd,
                                    libc::IPPROTO_TCP,
                                    libc::TCP_NODELAY,
                                    (&one as *const i32).cast(),
                                    4,
                                )
                            };
                            let slot = conns.iter().position(Option::is_none).unwrap_or_else(|| {
                                conns.push(None);
                                conns.len() - 1
                            });
                            conns[slot] = Some(Conn {
                                fd,
                                rx: vec![0u8; 65536],
                                filled: 0,
                                tx: Vec::with_capacity(65536),
                                sent: 0,
                                cache: None,
                            });
                            let c = conns[slot].as_mut().unwrap();
                            let e = opcode::Recv::new(types::Fd(fd), c.rx.as_mut_ptr(), c.rx.len() as u32)
                                .build()
                                .user_data(((slot as u64) << 2) | OP_RECV);
                            push(&mut ring, e);
                        }
                        push(&mut ring, accept.clone());
                    }
                    OP_RECV => {
                        let Some(c) = conns[idx].as_mut() else { continue };
                        if res <= 0 {
                            unsafe { libc::close(c.fd) };
                            conns[idx] = None;
                            continue;
                        }
                        c.filled += res as usize;
                        // Process every complete chunk.
                        let mut start = 0;
                        c.tx.clear();
                        while c.filled - start >= 8 {
                            let size = u32::from_le_bytes(c.rx[start + 4..start + 8].try_into().unwrap()) as usize;
                            if c.filled - start < size {
                                break;
                            }
                            handle(&server, &mut c.cache, &c.rx[start..start + size], &mut c.tx);
                            start += size;
                        }
                        c.rx.copy_within(start..c.filled, 0);
                        c.filled -= start;
                        let e = if c.tx.is_empty() {
                            let (ptr, len) = (c.rx[c.filled..].as_mut_ptr(), (c.rx.len() - c.filled) as u32);
                            opcode::Recv::new(types::Fd(c.fd), ptr, len)
                                .build()
                                .user_data(((idx as u64) << 2) | OP_RECV)
                        } else {
                            c.sent = 0;
                            opcode::Send::new(types::Fd(c.fd), c.tx.as_ptr(), c.tx.len() as u32)
                                .build()
                                .user_data(((idx as u64) << 2) | OP_SEND)
                        };
                        push(&mut ring, e);
                    }
                    _ => {
                        let Some(c) = conns[idx].as_mut() else { continue };
                        if res <= 0 {
                            unsafe { libc::close(c.fd) };
                            conns[idx] = None;
                            continue;
                        }
                        c.sent += res as usize;
                        let e = if c.sent < c.tx.len() {
                            opcode::Send::new(types::Fd(c.fd), c.tx[c.sent..].as_ptr(), (c.tx.len() - c.sent) as u32)
                                .build()
                                .user_data(((idx as u64) << 2) | OP_SEND)
                        } else {
                            let (ptr, len) = (c.rx[c.filled..].as_mut_ptr(), (c.rx.len() - c.filled) as u32);
                            opcode::Recv::new(types::Fd(c.fd), ptr, len)
                                .build()
                                .user_data(((idx as u64) << 2) | OP_RECV)
                        };
                        push(&mut ring, e);
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ clients

struct Result {
    p50: f64,
    p99: f64,
    p999: f64,
    rps: f64,
}

fn load(addr: &str, clients: usize, request: &[u8], duration: Duration) -> Result {
    let stop = Arc::new(AtomicBool::new(false));
    let handles: Vec<_> = (0..clients)
        .map(|_| {
            let addr = addr.to_string();
            let req = request.to_vec();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(&addr).unwrap();
                s.set_nodelay(true).unwrap();
                let mut buf = vec![0u8; 65536];
                let mut samples = Vec::with_capacity(1 << 16);
                let mut warm = 200;
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    s.write_all(&req).unwrap();
                    s.read_exact(&mut buf[..8]).unwrap();
                    let size = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
                    s.read_exact(&mut buf[8..size]).unwrap();
                    if warm > 0 {
                        warm -= 1;
                    } else {
                        samples.push(t.elapsed().as_nanos() as u32);
                    }
                }
                samples
            })
        })
        .collect();
    std::thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);
    let mut all: Vec<u32> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    all.sort_unstable();
    let pct = |p: f64| all[((all.len() - 1) as f64 * p) as usize] as f64 / 1000.0;
    Result { p50: pct(0.5), p99: pct(0.99), p999: pct(0.999), rps: all.len() as f64 / duration.as_secs_f64() }
}

fn main() {
    let dir = std::env::temp_dir().join(format!("fastua-iobench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let items: Vec<String> =
        (0..1000).map(|i| format!(r#"{{"Name":"v{i}","NodeId":"i={}","Type":"Double"}}"#, i * 7)).collect();
    std::fs::write(
        dir.join("b.json"),
        format!(r#"{{"Namespace":"urn:b","Subscriptions":[{{"Name":"G","Items":[{}]}}]}}"#, items.join(",")),
    )
    .unwrap();
    let store = Store::open(&dir, ServerInfo::default()).unwrap();
    let server = Server::new(
        store,
        ServerConfig { listen: String::new(), endpoint_url: "opc.tcp://bench".into(), limits: Limits::default() },
    );
    let session = server.create_session("bench".into(), 1, 3_600_000.0).unwrap();
    session.activated.store(true, Ordering::Release);

    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let secs: u64 = std::env::var("IO_BENCH_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let duration = Duration::from_secs(secs);

    let blocking_addr = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap().to_string();
        blocking_server(server.clone(), l);
        a
    };
    #[cfg(target_os = "linux")]
    let uring_addr = {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let a = format!("127.0.0.1:{port}");
        uring::server(server.clone(), &a, cores);
        std::thread::sleep(Duration::from_millis(100));
        a
    };

    println!("{cores} cores, {secs} s per run, closed-loop clients, Read request");
    println!(
        "{:<10} {:>7} {:>6} {:>10} {:>10} {:>10} {:>12}",
        "server", "clients", "nodes", "p50 us", "p99 us", "p99.9 us", "req/s"
    );
    for nodes in [1usize, 50] {
        let req = read_request(&session.token, nodes);
        for clients in [1usize, 4, 16, 64, 256] {
            let mut runs: Vec<(&str, &str)> = vec![("blocking", &blocking_addr)];
            #[cfg(target_os = "linux")]
            runs.push(("io_uring", &uring_addr));
            for (name, addr) in runs {
                let r = load(addr, clients, &req, duration);
                println!(
                    "{name:<10} {clients:>7} {nodes:>6} {:>10.1} {:>10.1} {:>10.1} {:>12.0}",
                    r.p50, r.p99, r.p999, r.rps
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
