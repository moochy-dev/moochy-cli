//! Encodings shared by every message: `lp`, labels, base64url, ids (CONTRACT §1–2).

use crate::Error;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Domain-separation labels (CONTRACT §2). Always used as the first `lp` field.
pub mod label {
    pub const AUTH: &[u8] = b"moochy/v1/auth";
    pub const DEVICE_START: &[u8] = b"moochy/v1/device-start";
    pub const REQ: &[u8] = b"moochy/v1/req";
    pub const RESP: &[u8] = b"moochy/v1/resp";
    pub const WRAP: &[u8] = b"moochy/v1/wrap";
    pub const TASK: &[u8] = b"moochy/v1/task";
    pub const SALT: &[u8] = b"moochy/v1/salt";
    pub const REQ_COMMIT: &[u8] = b"moochy/v1/req-commit";
    pub const RESP_COMMIT: &[u8] = b"moochy/v1/resp-commit";
    pub const PROVIDER_REQ: &[u8] = b"moochy/v1/provider-req";
    pub const RECEIPT: &[u8] = b"moochy/v1/receipt";
    pub const PROJECTION: &[u8] = b"moochy/v1/projection";
    pub const RESP_PROGRESS: &[u8] = b"moochy/v1/resp-progress";
    pub const DISPUTE: &[u8] = b"moochy/v1/dispute";
    pub const DETAIL: &[u8] = b"moochy/v1/detail";
    /// Key log (spec/KEYLOG.md §3). Builders/verifiers: `moochy_keylog::entry`, `::receipts`.
    pub const KEYLOG: &[u8] = b"moochy/v1/keylog";
    pub const KEYLOG_SIG: &[u8] = b"moochy/v1/keylog-sig";
    pub const KEY_POP: &[u8] = b"moochy/v1/key-pop";
    pub const RECEIPT_LOG: &[u8] = b"moochy/v1/receipt-log";
    pub const ALL: [&[u8]; 19] = [
        AUTH, DEVICE_START, REQ, RESP, WRAP, TASK, SALT, REQ_COMMIT, RESP_COMMIT, PROVIDER_REQ,
        RECEIPT, PROJECTION, RESP_PROGRESS, DISPUTE, DETAIL, KEYLOG, KEYLOG_SIG, KEY_POP, RECEIPT_LOG,
    ];
}

/// `lp(a, b, …)` = concatenation of `u32_be(len(x)) || x`. Fails only if a field exceeds `u32::MAX`.
pub fn lp(fields: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let mut n = 0usize;
    for f in fields {
        n = n.checked_add(f.len()).and_then(|n| n.checked_add(4)).ok_or(Error::TooLarge)?;
    }
    let mut out = Vec::with_capacity(n);
    for f in fields {
        let len = u32::try_from(f.len()).map_err(|_| Error::TooLarge)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(f);
    }
    Ok(out)
}

/// Integers inside `lp` are `u64_be` unless the contract says `u32`.
#[must_use]
pub fn u64be(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}

#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// [`b64`] appended to `out` in place (no temporary `String`).
pub(crate) fn b64_extend(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let start = out.len();
    let end = base64::encoded_len(bytes.len(), false).and_then(|n| start.checked_add(n)).ok_or(Error::TooLarge)?;
    out.resize(end, 0);
    let dst = out.get_mut(start..).ok_or(Error::Malformed)?;
    URL_SAFE_NO_PAD.encode_slice(bytes, dst).map_err(|_| Error::Malformed)?;
    Ok(())
}

/// Strict base64url-no-pad: rejects padding, `+/`, whitespace and non-canonical trailing bits.
pub fn unb64(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::Malformed)
}

// ---------- byte newtypes (JSON = base64url-no-pad) ----------

/// Fixed-size public bytes: hashes, salts, public keys, signatures, wraps.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct B<const N: usize>(pub [u8; N]);

pub type Sig = B<64>;

impl<const N: usize> fmt::Debug for B<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64(&self.0))
    }
}
impl<const N: usize> From<[u8; N]> for B<N> {
    fn from(a: [u8; N]) -> Self {
        Self(a)
    }
}
impl<const N: usize> Serialize for B<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64(&self.0))
    }
}
impl<'de, const N: usize> Deserialize<'de> for B<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = d.deserialize_str(StrV(|s: &str| {
            // Bound before decoding: N bytes encode to exactly ceil(4N/3) chars.
            if s.len() > N.saturating_mul(2).saturating_add(4) {
                return Err(Error::Malformed);
            }
            unb64(s)
        }))?;
        <[u8; N]>::try_from(v).map(B).map_err(|_| de::Error::custom("wrong length"))
    }
}

/// Variable-size bytes (route header, sealed detail, receipt bytes, body).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Blob(pub Vec<u8>);

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}
impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64(&self.0))
    }
}
impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(StrV(unb64)).map(Blob)
    }
}

/// Visitor that maps a JSON string through `f`.
struct StrV<F>(F);
impl<T, F: FnOnce(&str) -> Result<T, Error>> Visitor<'_> for StrV<F> {
    type Value = T;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<T, E> {
        (self.0)(s).map_err(E::custom)
    }
}

// ---------- ULID ids ----------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 128-bit ULID: 48-bit ms timestamp || 80 random bits. Text form: canonical 26-char uppercase Crockford.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ulid(pub [u8; 16]);

impl Ulid {
    /// New ULID for `now_ms` with OS randomness.
    pub fn new(now_ms: u64) -> Result<Self, Error> {
        if now_ms >> 48 != 0 {
            return Err(Error::Malformed);
        }
        let mut b = [0u8; 16];
        crate::crypto::fill_random(&mut b)?;
        let ts = now_ms.to_be_bytes();
        b[..6].copy_from_slice(&ts[2..]);
        Ok(Self(b))
    }

    /// Milliseconds since the Unix epoch encoded in the id.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        let [a, b, c, d, e, f, ..] = self.0;
        u64::from_be_bytes([0, 0, a, b, c, d, e, f])
    }

    /// Strict canonical parse: exactly 26 chars of uppercase Crockford base32, first char ≤ '7'.
    pub fn parse(s: &str) -> Result<Self, Error> {
        let s = s.as_bytes();
        if s.len() != 26 {
            return Err(Error::Malformed);
        }
        let mut v: u128 = 0;
        for &c in s {
            let d = CROCKFORD.iter().position(|&x| x == c).ok_or(Error::Malformed)?;
            v = v.checked_mul(32).and_then(|v| v.checked_add(d as u128)).ok_or(Error::Malformed)?;
        }
        Ok(Self(v.to_be_bytes()))
    }

    #[must_use]
    pub fn encode(&self) -> [u8; 26] {
        let v = u128::from_be_bytes(self.0);
        let mut out = [0u8; 26];
        for (i, o) in out.iter_mut().enumerate() {
            // i ≤ 25 → shift ≤ 125; the mask keeps the index < 32.
            let shift = 125u32.saturating_sub(5u32.saturating_mul(u32::try_from(i).unwrap_or(0)));
            *o = CROCKFORD.get(((v >> shift) & 31) as usize).copied().unwrap_or(b'0');
        }
        out
    }
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = self.encode();
        f.write_str(std::str::from_utf8(&e).map_err(|_| fmt::Error)?)
    }
}
impl fmt::Debug for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub Ulid);
        impl $name {
            pub const PREFIX: &'static str = $prefix;
            pub fn new(now_ms: u64) -> Result<Self, Error> {
                Ulid::new(now_ms).map(Self)
            }
            /// Exact text form; this is what goes inside `lp` and JSON.
            #[must_use]
            pub fn text(&self) -> String {
                format!("{}{}", $prefix, self.0)
            }
        }
        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Error> {
                s.strip_prefix($prefix).ok_or(Error::Malformed).and_then(Ulid::parse).map(Self)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_str(StrV(|s: &str| s.parse()))
            }
        }
    };
}

id_type!(
    /// Task id: bare ULID, created by the Gateway. Binary form (16 B) goes in frame headers.
    TaskId, ""
);
id_type!(DeviceId, "d_");
id_type!(UserId, "u_");
id_type!(RepoId, "r_");
id_type!(PledgeId, "p_");

impl TaskId {
    /// ±`window_ms` freshness check of the embedded timestamp (plan 03 §7.2 rule 4).
    #[must_use]
    pub fn is_fresh(&self, now_ms: u64, window_ms: u64) -> bool {
        self.0.timestamp_ms().abs_diff(now_ms) <= window_ms
    }

    /// Worker admission by time (plan 03 §7.2 rule 4 + CONTRACT D18): within ±10 minutes of
    /// `now_ms` AND not earlier than this process's start (`boot_ms`), so a restart can never
    /// re-open the replay window. The in-memory served set covers the rest of the window.
    #[must_use]
    pub fn admissible(&self, now_ms: u64, boot_ms: u64) -> bool {
        self.is_fresh(now_ms, FRESHNESS_MS) && self.0.timestamp_ms() >= boot_ms
    }
}

/// Task-id freshness window (plan 03 §16): ±10 minutes.
pub const FRESHNESS_MS: u64 = 600_000;
