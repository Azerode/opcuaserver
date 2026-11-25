//! User authentication and authorisation.
//!
//! Users are listed in a JSON file; passwords are stored as salted
//! PBKDF2-HMAC-SHA256 hashes (`fastua hash-password` produces them):
//!
//! ```json
//! { "users": [ { "name": "operator", "password": "pbkdf2-sha256$600000$<salt b64>$<hash b64>", "write": true } ] }
//! ```

use aws_lc_rs::pbkdf2;
use serde::Deserialize;
use std::num::NonZeroU32;
use std::path::Path;

pub const DEFAULT_ITERATIONS: u32 = 600_000;

/// What an authenticated identity may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

impl Access {
    pub fn can_write(self) -> bool {
        self == Access::ReadWrite
    }
}

#[derive(Deserialize)]
struct RawFile {
    users: Vec<RawUser>,
}

#[derive(Deserialize)]
struct RawUser {
    name: String,
    password: String,
    #[serde(default)]
    write: bool,
}

struct User {
    name: String,
    iterations: NonZeroU32,
    salt: Vec<u8>,
    hash: Vec<u8>,
    access: Access,
}

#[derive(Default)]
pub struct Users {
    users: Vec<User>,
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Produces a storable hash for `password`.
pub fn hash_password(password: &str) -> String {
    let mut salt = [0u8; 16];
    crate::server::random_bytes(&mut salt);
    let mut hash = [0u8; 32];
    let it = NonZeroU32::new(DEFAULT_ITERATIONS).unwrap();
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, it, &salt, password.as_bytes(), &mut hash);
    format!("pbkdf2-sha256${DEFAULT_ITERATIONS}${}${}", b64(&salt), b64(&hash))
}

impl Users {
    pub fn load(path: &Path) -> Result<Users, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let raw: RawFile = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut users = Vec::with_capacity(raw.users.len());
        for u in raw.users {
            let bad = || format!("{}: user '{}': password must be a pbkdf2-sha256 hash", path.display(), u.name);
            let parts: Vec<&str> = u.password.split('$').collect();
            if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
                return Err(bad());
            }
            let iterations = parts[1].parse::<u32>().ok().and_then(NonZeroU32::new).ok_or_else(bad)?;
            let salt = crate::types::decode_base64(parts[2]).ok_or_else(bad)?;
            let hash = crate::types::decode_base64(parts[3]).ok_or_else(bad)?;
            if hash.len() != 32 {
                return Err(bad());
            }
            let access = if u.write { Access::ReadWrite } else { Access::ReadOnly };
            users.push(User { name: u.name, iterations, salt, hash, access });
        }
        Ok(Users { users })
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Constant-time password check. Unknown users cost the same as known ones.
    pub fn authenticate(&self, name: &str, password: &[u8]) -> Option<Access> {
        let user = self.users.iter().find(|u| u.name == name);
        let (it, salt, hash) = match user {
            Some(u) => (u.iterations, u.salt.as_slice(), u.hash.as_slice()),
            None => (NonZeroU32::new(DEFAULT_ITERATIONS).unwrap(), &[0u8; 16][..], &[0u8; 32][..]),
        };
        let ok = pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, it, salt, password, hash).is_ok();
        match user {
            Some(u) if ok => Some(u.access),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let dir = std::env::temp_dir().join(format!("fastua-users-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("users.json");
        let h = hash_password("s3cret");
        std::fs::write(
            &file,
            format!(r#"{{"users":[{{"name":"op","password":"{h}","write":true}},{{"name":"ro","password":"{h}"}}]}}"#),
        )
        .unwrap();
        let users = Users::load(&file).unwrap();
        assert_eq!(users.authenticate("op", b"s3cret"), Some(Access::ReadWrite));
        assert_eq!(users.authenticate("ro", b"s3cret"), Some(Access::ReadOnly));
        assert_eq!(users.authenticate("op", b"wrong"), None);
        assert_eq!(users.authenticate("nobody", b"s3cret"), None);
        std::fs::write(&file, r#"{"users":[{"name":"x","password":"plain"}]}"#).unwrap();
        assert!(Users::load(&file).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
