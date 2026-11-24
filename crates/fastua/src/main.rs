use fastua::address_space::ServerInfo;
use fastua::reload::Store;
use fastua::server::{Limits, Server, ServerConfig};
use std::net::TcpListener;
use std::path::PathBuf;

const USAGE: &str = "usage: fastua [--config DIR] [--listen ADDR:PORT] [--endpoint URL] [--application-uri URI]

  --config DIR          directory of namespace files, watched for changes (default: config/machines)
  --listen ADDR:PORT    address to bind (default: 0.0.0.0:4840)
  --endpoint URL        endpoint URL advertised to clients (default: opc.tcp://<hostname>:<port>)
  --application-uri URI ApplicationUri of this server (default: urn:<hostname>:fastua)";

fn main() {
    let mut config_dir = PathBuf::from("config/machines");
    let mut listen = "0.0.0.0:4840".to_string();
    let mut endpoint: Option<String> = None;
    let mut app_uri: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |name: &str| {
            args.next().unwrap_or_else(|| {
                eprintln!("missing value for {name}\n\n{USAGE}");
                std::process::exit(2)
            })
        };
        match a.as_str() {
            "--config" => config_dir = PathBuf::from(value("--config")),
            "--listen" => listen = value("--listen"),
            "--endpoint" => endpoint = Some(value("--endpoint")),
            "--application-uri" => app_uri = Some(value("--application-uri")),
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            other => {
                eprintln!("unknown argument '{other}'\n\n{USAGE}");
                std::process::exit(2);
            }
        }
    }

    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into());
    let port = listen.rsplit(':').next().unwrap_or("4840");
    let endpoint = endpoint.unwrap_or_else(|| format!("opc.tcp://{hostname}:{port}"));

    let info = ServerInfo {
        application_uri: app_uri.unwrap_or_else(|| format!("urn:{hostname}:fastua")),
        ..ServerInfo::default()
    };

    let store = match Store::open(&config_dir, info) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot load configuration: {e}");
            std::process::exit(1);
        }
    };
    {
        let s = store.load();
        fastua::log!("loaded {} nodes in {} namespaces from {}", s.len(), s.namespaces.len(), config_dir.display());
        for (i, ns) in s.namespaces.iter().enumerate() {
            fastua::log!("  ns={i} {ns}");
        }
    }
    if let Err(e) = store.watch() {
        eprintln!("cannot watch {}: {e}", config_dir.display());
        std::process::exit(1);
    }

    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot listen on {listen}: {e}");
            std::process::exit(1);
        }
    };
    fastua::log!("listening on {listen}, endpoint {endpoint}");
    let server = Server::new(store, ServerConfig { listen, endpoint_url: endpoint, limits: Limits::default() });
    if let Err(e) = server.serve(listener) {
        eprintln!("server stopped: {e}");
        std::process::exit(1);
    }
}
