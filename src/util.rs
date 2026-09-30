use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub fn new_guid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn is_guid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS random number generator failed");
    buf
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Random string drawn uniformly from `alphabet` (rejection sampling, no modulo bias).
fn random_string(alphabet: &[u8], len: usize) -> String {
    let limit = 256 - (256 % alphabet.len());
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for b in random_bytes(len * 2) {
            if (b as usize) < limit && out.len() < len {
                out.push(alphabet[b as usize % alphabet.len()] as char);
            }
        }
    }
    out
}

/// A client secret shaped like Entra's: 40 characters, `Q~` at positions 4-5,
/// drawn from the same alphabet. Around 200 bits of entropy.
pub fn generate_client_secret() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~.-";
    const DIGITS: &[u8] = b"0123456789";
    format!(
        "{}{}Q~{}",
        random_string(ALPHABET, 3),
        random_string(DIGITS, 1),
        random_string(ALPHABET, 34)
    )
}

/// Fold an identifier for case-insensitive lookup and uniqueness (UPNs, tenant
/// domains, group names). Uses full Unicode `to_lowercase`, not
/// `to_ascii_lowercase`: a UPN may contain non-ASCII, and folding must be the
/// same on every engine and must not depend on the database's locale or collation.
pub fn fold(value: &str) -> String {
    value.trim().to_lowercase()
}
