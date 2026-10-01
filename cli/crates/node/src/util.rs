//! Small shared helpers: errors with exit codes, randomness, base64url, `lp`, ULIDs.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::fmt;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

/// Process exit codes (CONTRACT §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Usage = 2,
    Auth = 3,
    Network = 4,
    Internal = 10,
}

#[derive(Debug)]
pub struct Error {
    pub exit: Exit,
    pub msg: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub fn usage(msg: impl Into<String>) -> Error {
    Error { exit: Exit::Usage, msg: msg.into() }
}
pub fn auth(msg: impl Into<String>) -> Error {
    Error { exit: Exit::Auth, msg: msg.into() }
}
pub fn net(msg: impl Into<String>) -> Error {
    Error { exit: Exit::Network, msg: msg.into() }
}
pub fn internal(msg: impl Into<String>) -> Error {
    Error { exit: Exit::Internal, msg: msg.into() }
}

/// `.ctx("what")` on io / serde errors → internal error with context.
pub trait Ctx<T> {
    fn ctx(self, what: &str) -> Result<T>;
}
impl<T, E: fmt::Display> Ctx<T> for std::result::Result<T, E> {
    fn ctx(self, what: &str) -> Result<T> {
        self.map_err(|e| internal(format!("{what}: {e}")))
    }
}

pub fn rand_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    moochy_proto::crypto::fill_random(&mut b).map_err(|_| internal("os random"))?;
    Ok(b)
}

/// Uniform-ish random u64 (for jitter only, not for secrets).
pub fn rand_u64() -> u64 {
    rand_bytes::<8>().map_or(0, u64::from_le_bytes)
}

pub fn b64e(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn b64d(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

pub fn b64d32(s: &str) -> Option<[u8; 32]> {
    b64d(s)?.try_into().ok()
}

/// Constant-time byte comparison (keys, tokens, MACs).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    a.ct_eq(b).into()
}

/// `lp(a, b, …)`: each field prefixed with its u32 big-endian length (CONTRACT §1).
pub fn lp(fields: &[&[u8]]) -> Vec<u8> {
    let cap = fields.iter().fold(0usize, |a, f| a.saturating_add(f.len()).saturating_add(4));
    let mut out = Vec::with_capacity(cap);
    for f in fields {
        let len = u32::try_from(f.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// Dev/test clock offset (`MOOCHY_DEV_CLOCK_SKEW_MS`, honoured only with `MOOCHY_INSECURE_DEV=1`).
static SKEW_MS: std::sync::LazyLock<i64> = std::sync::LazyLock::new(|| {
    if std::env::var("MOOCHY_INSECURE_DEV").as_deref() != Ok("1") {
        return 0;
    }
    std::env::var("MOOCHY_DEV_CLOCK_SKEW_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
});

/// Node clock in Unix ms (the dev skew above included).
pub fn now_ms() -> u64 {
    let real = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    real.checked_add_signed(*SKEW_MS).unwrap_or(real)
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// New ULID (48-bit ms timestamp + 80 random bits), canonical 26-char form.
pub fn ulid() -> Result<String> {
    let r = rand_bytes::<10>()?;
    let mut v = u128::from(now_ms() & 0xFFFF_FFFF_FFFF) << 80;
    for (i, b) in r.iter().enumerate() {
        v |= u128::from(*b) << (72usize.saturating_sub(i.saturating_mul(8)));
    }
    Ok(ulid_encode(v))
}

fn ulid_encode(v: u128) -> String {
    (0..26u32)
        .map(|i| {
            let shift = 125u32.saturating_sub(i.saturating_mul(5));
            let idx = usize::try_from((v >> shift) & 0x1F).unwrap_or(0);
            char::from(CROCKFORD.get(idx).copied().unwrap_or(b'0'))
        })
        .collect()
}

/// Canonical ULID string → 16 bytes (big-endian).
pub fn ulid_bytes(s: &str) -> Option<[u8; 16]> {
    let s = s.as_bytes();
    if s.len() != 26 || *s.first()? > b'7' {
        return None;
    }
    let mut v: u128 = 0;
    for c in s {
        let d = CROCKFORD.iter().position(|x| x == c)?;
        v = (v << 5) | u128::try_from(d).ok()?;
    }
    Some(v.to_be_bytes())
}

pub fn ulid_from_bytes(b: &[u8; 16]) -> String {
    ulid_encode(u128::from_be_bytes(*b))
}

fn bad_char(c: char) -> bool {
    c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// Escape control, bidi and zero-width characters in a server-provided string (CONTRACT §11).
pub fn clean(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(bad_char) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut o = String::with_capacity(s.len().saturating_add(16));
    for c in s.chars() {
        if bad_char(c) {
            let _ = write!(o, "\\u{{{:x}}}", u32::from(c));
        } else {
            o.push(c);
        }
    }
    std::borrow::Cow::Owned(o)
}

/// [`clean`] every string (keys included) of a JSON value.
pub fn clean_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => Value::String(clean(s).into_owned()),
        Value::Array(a) => Value::Array(a.iter().map(clean_value).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (clean(k).into_owned(), clean_value(v))).collect()),
        x => x.clone(),
    }
}

/// Print one JSON event line to stdout (strings sanitized).
pub fn emit(v: &serde_json::Value) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", clean_value(v));
    let _ = out.flush();
}

/// Structured log line to stderr (never content: callers pass codes and ids only).
pub fn log(level: &str, msg: &str, fields: &serde_json::Value) {
    let mut line = serde_json::json!({"level": level, "msg": msg, "t_ms": now_ms()});
    if let (Some(obj), Some(extra)) = (line.as_object_mut(), fields.as_object()) {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    eprintln!("{}", clean_value(&line));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_roundtrip() {
        let u = ulid().unwrap();
        assert_eq!(u.len(), 26);
        let b = ulid_bytes(&u).unwrap();
        assert_eq!(ulid_from_bytes(&b), u);
        assert!(ulid_bytes("8ZZZZZZZZZZZZZZZZZZZZZZZZZ").is_none());
        assert!(ulid_bytes("01ARZ3NDEKTSV4RRFFQ69G5FAU").is_none()); // 'U' excluded
        assert_eq!(ulid_from_bytes(&ulid_bytes("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()), "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn cleans_terminal_escapes() {
        assert_eq!(clean("alice"), "alice");
        assert_eq!(clean("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(clean("x\u{9b}y\u{202e}z"), "x\\u{9b}y\\u{202e}z");
    }

    #[test]
    fn lp_encoding() {
        assert_eq!(lp(&[b"ab", b""]), vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0]);
    }
}
