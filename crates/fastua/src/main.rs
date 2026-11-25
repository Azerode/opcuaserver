use fastua::address_space::ServerInfo;
use fastua::crypto::{Mode, Policy};
use fastua::pki::Pki;
use fastua::reload::Store;
use fastua::server::{Server, ServerConfig};
use fastua::users::{hash_password, Access, Users};
use std::net::TcpListener;
use std::path::PathBuf;

const USAGE: &str = "usage: fastua [options]
       fastua hash-password            read a password on stdin, print its hash for the users file

  --config DIR            directory of namespace files, watched for changes (default: config/machines)
  --listen ADDR:PORT      address to bind (default: 0.0.0.0:4840)
  --endpoint URL          endpoint URL advertised to clients (default: opc.tcp://<hostname>:<port>)
  --application-uri URI   ApplicationUri of this server (default: urn:<hostname>:fastua)
  --pki DIR               certificate store (default: pki); a self-signed certificate is created if missing
  --endpoints LIST        comma-separated endpoints to offer (default: all):
                            none, basic256sha256-sign, basic256sha256-encrypt,
                            aes128-sign, aes128-encrypt, aes256-sign, aes256-encrypt
  --users FILE            users file enabling user name / password login
  --anonymous off|read|write   rights of anonymous users (default: read)
  --x509-users read|write      rights of users with a trusted certificate (default: write)
  --trust-all-clients     accept any client certificate (development only)
  --busy-poll US          poll each connection for US microseconds before sleeping
                          (lower latency, one busy core per active connection; default: off)
  --min-publishing-interval MS   fastest subscription publishing interval (default: 1, minimum 0.05)
  --min-sampling-interval MS     fastest monitored item sampling interval (default: 1, minimum 0.05)";

fn fail(msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(2)
}

fn parse_endpoints(list: &str) -> Vec<(Policy, Mode)> {
    list.split(',')
        .map(|e| match e.trim().to_ascii_lowercase().as_str() {
            "none" => (Policy::None, Mode::None),
            "basic256sha256-sign" => (Policy::Basic256Sha256, Mode::Sign),
            "basic256sha256-encrypt" => (Policy::Basic256Sha256, Mode::SignAndEncrypt),
            "aes128-sign" => (Policy::Aes128Sha256RsaOaep, Mode::Sign),
            "aes128-encrypt" => (Policy::Aes128Sha256RsaOaep, Mode::SignAndEncrypt),
            "aes256-sign" => (Policy::Aes256Sha256RsaPss, Mode::Sign),
            "aes256-encrypt" => (Policy::Aes256Sha256RsaPss, Mode::SignAndEncrypt),
            other => fail(format!("unknown endpoint '{other}'\n\n{USAGE}")),
        })
        .collect()
}

fn parse_access(v: &str, allow_off: bool) -> Option<Access> {
    match v {
        "off" if allow_off => None,
        "read" => Some(Access::ReadOnly),
        "write" => Some(Access::ReadWrite),
        _ => fail(format!("invalid access '{v}'\n\n{USAGE}")),
    }
}

fn main() {
    let mut config_dir = PathBuf::from("config/machines");
    let mut pki_dir = PathBuf::from("pki");
    let mut listen = "0.0.0.0:4840".to_string();
    let mut endpoint: Option<String> = None;
    let mut app_uri: Option<String> = None;
    let mut endpoints: Option<Vec<(Policy, Mode)>> = None;
    let mut users_file: Option<PathBuf> = None;
    let mut anonymous = Some(Access::ReadOnly);
    let mut x509_users = Access::ReadWrite;
    let mut trust_all = false;
    let mut busy_poll = std::time::Duration::ZERO;
    let mut min_publishing: Option<f64> = None;
    let mut min_sampling: Option<f64> = None;

    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(String::as_str) == Some("hash-password") {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).expect("cannot read stdin");
        println!("{}", hash_password(line.trim_end_matches(['\r', '\n'])));
        return;
    }
    while let Some(a) = args.next() {
        let mut value =
            |name: &str| args.next().unwrap_or_else(|| fail(format!("missing value for {name}\n\n{USAGE}")));
        match a.as_str() {
            "--config" => config_dir = PathBuf::from(value("--config")),
            "--pki" => pki_dir = PathBuf::from(value("--pki")),
            "--listen" => listen = value("--listen"),
            "--endpoint" => endpoint = Some(value("--endpoint")),
            "--application-uri" => app_uri = Some(value("--application-uri")),
            "--endpoints" => endpoints = Some(parse_endpoints(&value("--endpoints"))),
            "--users" => users_file = Some(PathBuf::from(value("--users"))),
            "--anonymous" => anonymous = parse_access(&value("--anonymous"), true),
            "--x509-users" => x509_users = parse_access(&value("--x509-users"), false).unwrap(),
            "--trust-all-clients" => trust_all = true,
            "--busy-poll" => {
                let v = value("--busy-poll");
                let us: u64 = v.parse().unwrap_or_else(|_| fail(format!("invalid --busy-poll '{v}'\n\n{USAGE}")));
                busy_poll = std::time::Duration::from_micros(us);
            }
            "--min-publishing-interval" | "--min-sampling-interval" => {
                let v = value(&a);
                let ms: f64 = v
                    .parse()
                    .ok()
                    .filter(|m: &f64| m.is_finite() && *m >= 0.05)
                    .unwrap_or_else(|| fail(format!("invalid {a} '{v}' (milliseconds, at least 0.05)\n\n{USAGE}")));
                if a == "--min-publishing-interval" {
                    min_publishing = Some(ms);
                } else {
                    min_sampling = Some(ms);
                }
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            other => fail(format!("unknown argument '{other}'\n\n{USAGE}")),
        }
    }

    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into());
    let port = listen.rsplit(':').next().unwrap_or("4840");
    let endpoint = endpoint.unwrap_or_else(|| format!("opc.tcp://{hostname}:{port}"));
    let mut limits = fastua::server::Limits::default();
    if let Some(ms) = min_publishing {
        limits.min_publishing_interval_ms = ms;
    }
    if let Some(ms) = min_sampling {
        limits.min_sampling_interval_ms = ms;
    }
    let info = ServerInfo {
        application_uri: app_uri.unwrap_or_else(|| format!("urn:{hostname}:fastua")),
        limits: limits.clone(),
        ..ServerInfo::default()
    };

    let pki = Pki::open(&pki_dir, &info.application_uri, &hostname, trust_all)
        .unwrap_or_else(|e| fail(format!("cannot open PKI: {e}")));
    if trust_all {
        fastua::log!("WARNING: --trust-all-clients accepts any client certificate");
    }
    let users = match &users_file {
        Some(f) => Users::load(f).unwrap_or_else(|e| fail(format!("cannot load users: {e}"))),
        None => Users::default(),
    };

    let store = Store::open(&config_dir, info).unwrap_or_else(|e| fail(format!("cannot load configuration: {e}")));
    {
        let s = store.load();
        fastua::log!("loaded {} nodes in {} namespaces from {}", s.len(), s.namespaces.len(), config_dir.display());
        for (i, ns) in s.namespaces.iter().enumerate() {
            fastua::log!("  ns={i} {ns}");
        }
    }
    if let Err(e) = store.watch() {
        fail(format!("cannot watch {}: {e}", config_dir.display()));
    }

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| fail(format!("cannot listen on {listen}: {e}")));
    let mut config = ServerConfig::all_endpoints(listen.clone(), endpoint.clone());
    if let Some(e) = endpoints {
        config.endpoints = e;
    }
    config.anonymous = anonymous;
    config.x509_users = x509_users;
    config.busy_poll = busy_poll;
    config.limits = limits;
    if !busy_poll.is_zero() {
        fastua::log!("busy-polling connections for {} us before sleeping", busy_poll.as_micros());
    }
    for (p, m) in &config.endpoints {
        fastua::log!("endpoint {endpoint} {p:?} {m:?}");
    }
    fastua::log!("listening on {listen}");
    let server = Server::new(store, config, pki, users);
    if let Err(e) = server.serve(listener) {
        fail(format!("server stopped: {e}"));
    }
}
