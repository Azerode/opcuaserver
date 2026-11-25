//! fastua: an ultra-light, ultra-fast OPC UA server.

pub mod address_space;
pub mod aggregates;
pub mod channel;
pub mod client;
pub mod codec;
pub mod config;
pub mod crypto;
pub mod events;
pub mod history;
pub mod net;
pub mod pki;
pub mod reload;
pub mod server;
pub mod services;
pub mod subscription;
pub mod types;
pub mod users;
pub mod value;

/// Minimal logger: timestamped line on stderr. Never used on the hot path.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        eprintln!("[{}.{:03}] {}", d.as_secs(), d.subsec_millis(), format_args!($($arg)*));
    }};
}
