//! API key generation / verification and brute-force protection.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const KEY_PREFIX: &str = "msmcp_";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a new random API key: `msmcp_` + 64 hex chars (256 bits).
pub fn generate_api_key() -> Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| format!("random generator failed: {e}"))?;
    Ok(format!("{KEY_PREFIX}{}", to_hex(&buf)))
}

pub fn sha256_hex(s: &str) -> String {
    to_hex(&Sha256::digest(s.as_bytes()))
}

/// Constant-time comparison of the provided key against the stored SHA-256 hex digest.
pub fn verify(provided: &str, expected_sha256_hex: &str) -> bool {
    if expected_sha256_hex.len() != 64 {
        return false;
    }
    let got = sha256_hex(provided.trim());
    let a = got.as_bytes();
    let b = expected_sha256_hex.to_ascii_lowercase();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the key from `Authorization: Bearer <key>` or `X-API-Key: <key>`.
pub fn extract_key(authorization: Option<&str>, x_api_key: Option<&str>) -> Option<String> {
    if let Some(h) = authorization {
        let h = h.trim();
        let lower = h.to_ascii_lowercase();
        if lower.starts_with("bearer ") {
            let k = h[7..].trim();
            if !k.is_empty() {
                return Some(k.to_string());
            }
        }
    }
    x_api_key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty())
}

struct Entry {
    failures: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

/// Bans an IP for 15 minutes after 10 failed authentications within 10 minutes.
pub struct RateLimiter {
    inner: Mutex<HashMap<IpAddr, Entry>>,
}

const MAX_FAILURES: u32 = 10;
const WINDOW: Duration = Duration::from_secs(600);
const BAN: Duration = Duration::from_secs(900);

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter { inner: Mutex::new(HashMap::new()) }
    }

    /// Remaining ban time in seconds, if the IP is currently banned.
    pub fn banned(&self, ip: IpAddr) -> Option<u64> {
        let map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let until = map.get(&ip)?.banned_until?;
        let now = Instant::now();
        if until > now {
            Some((until - now).as_secs() + 1)
        } else {
            None
        }
    }

    /// Record a failure; returns true when this failure triggered a ban.
    pub fn failure(&self, ip: IpAddr) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if map.len() > 10_000 {
            map.retain(|_, e| e.banned_until.map(|u| u > now).unwrap_or(false));
        }
        let e = map.entry(ip).or_insert(Entry { failures: 0, window_start: now, banned_until: None });
        if now.duration_since(e.window_start) > WINDOW {
            e.failures = 0;
            e.window_start = now;
        }
        e.failures += 1;
        if e.failures >= MAX_FAILURES {
            e.banned_until = Some(now + BAN);
            e.failures = 0;
            e.window_start = now;
            return true;
        }
        false
    }

    pub fn success(&self, ip: IpAddr) {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let k = generate_api_key().unwrap();
        assert!(k.starts_with(KEY_PREFIX));
        assert_eq!(k.len(), KEY_PREFIX.len() + 64);
        let h = sha256_hex(&k);
        assert!(verify(&k, &h));
        assert!(!verify("msmcp_wrong", &h));
        assert!(!verify(&k, ""));
    }

    #[test]
    fn extracts_bearer_and_header() {
        assert_eq!(extract_key(Some("Bearer abc"), None).as_deref(), Some("abc"));
        assert_eq!(extract_key(Some("bearer  abc "), None).as_deref(), Some("abc"));
        assert_eq!(extract_key(None, Some("xyz")).as_deref(), Some("xyz"));
        assert_eq!(extract_key(Some("Basic abc"), None), None);
    }

    #[test]
    fn bans_after_repeated_failures() {
        let rl = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_FAILURES - 1 {
            assert!(!rl.failure(ip));
        }
        assert!(rl.failure(ip));
        assert!(rl.banned(ip).is_some());
    }
}
