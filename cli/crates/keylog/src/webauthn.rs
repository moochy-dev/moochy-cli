//! Passkey owner keys, `webauthn-es256` (spec/KEYLOG.md §4a), identical to Go's
//! `relay/internal/tlog/webauthn.go`: the canonical COSE EC2 P-256 key, the
//! assertion wire form, and the assertion check (strict clientDataJSON, rpIdHash,
//! UP+UV, sign counter, strict low-S DER, ECDSA P-256 via ring).

use crate::{Error, entry::unlp, state::Code};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use sha2::{Digest, Sha256};

pub const ALG: &str = "webauthn-es256";
pub const LABEL_EMAIL_PROOF: &[u8] = b"moochy/v1/email-proof";
/// Canonical CTAP2 COSE_Key `{1:2, 3:-7, -1:1, -2:x, -3:y}`.
pub const COSE_LEN: usize = 77;
const COSE_PREFIX: [u8; 10] = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
const COSE_Y: [u8; 3] = [0x22, 0x58, 0x20];
const MAX_AUTH_DATA: usize = 256;
const MAX_CLIENT_DATA: usize = 768;
const MAX_DER: usize = 72;

/// P-256 group order n, and n/2 (low-S bound), big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// The uncompressed point `04 ‖ x ‖ y` of a canonical COSE key; refuses any other
/// encoding and points not on P-256.
pub fn parse_cose(b: &[u8]) -> Result<[u8; 65], Error> {
    let bad = Error::Format("COSE key is not the canonical EC2 P-256 encoding");
    let (Some(pre), Some(x), Some(ytag), Some(y)) =
        (b.get(..10), b.get(10..42), b.get(42..45), b.get(45..))
    else {
        return Err(bad);
    };
    if b.len() != COSE_LEN || pre != COSE_PREFIX || ytag != COSE_Y {
        return Err(bad);
    }
    let mut point = [4u8; 65];
    point.get_mut(1..33).ok_or(bad.clone())?.copy_from_slice(x);
    point.get_mut(33..).ok_or(bad.clone())?.copy_from_slice(y);
    if on_curve(&point) {
        Ok(point)
    } else {
        Err(bad)
    }
}

/// The point of a COSE key [`parse_cose`] already accepted (no re-validation).
#[must_use]
pub fn point_of(cose: &[u8; COSE_LEN]) -> [u8; 65] {
    let mut point = [4u8; 65];
    for (i, b) in point.iter_mut().enumerate().skip(1) {
        // x = cose[10..42], y = cose[45..77]
        *b = cose
            .get(if i <= 32 {
                i.saturating_add(9)
            } else {
                i.saturating_add(12)
            })
            .copied()
            .unwrap_or(0);
    }
    point
}

/// ring validates an ECDH peer key fully (on the curve, coordinates < p); a
/// throwaway agreement is the public way to ask it. Rare: OWNER_KEY_* entries only.
fn on_curve(point: &[u8; 65]) -> bool {
    use ring::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
    let Ok(k) = EphemeralPrivateKey::generate(&ECDH_P256, &ring::rand::SystemRandom::new()) else {
        return false; // fail closed
    };
    agree_ephemeral(k, &UnparsedPublicKey::new(&ECDH_P256, point), |_| ()).is_ok()
}

/// One WebAuthn `get()` result; wire form `lp(authenticatorData, clientDataJSON, signatureDER)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assertion<'a> {
    pub auth_data: &'a [u8],
    pub client_data_json: &'a [u8],
    pub signature: &'a [u8],
}

impl<'a> Assertion<'a> {
    /// Splits and bounds the wire form.
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        let [auth_data, client_data_json, signature] = unlp::<3>(b)?;
        if !(37..=MAX_AUTH_DATA).contains(&auth_data.len())
            || !(1..=MAX_CLIENT_DATA).contains(&client_data_json.len())
            || !(8..=MAX_DER).contains(&signature.len())
        {
            return Err(Error::Format("assertion field sizes"));
        }
        Ok(Self {
            auth_data,
            client_data_json,
            signature,
        })
    }

    /// The authenticator's sign counter (authData[33..37]).
    #[must_use]
    pub fn counter(&self) -> u32 {
        self.auth_data
            .get(33..37)
            .and_then(|c| <[u8; 4]>::try_from(c).ok())
            .map_or(0, u32::from_be_bytes)
    }
}

/// What the check needs from an OWNER_KEY_ADDED (webauthn-es256).
#[derive(Clone, Copy, Debug)]
pub struct Passkey<'a> {
    /// `04 ‖ x ‖ y`.
    pub point: &'a [u8; 65],
    pub rp_id: &'a str,
    /// The logged comma-separated origins.
    pub origins: &'a str,
}

/// Checks `a` by `k` over challenge SHA-256(`msg`) and returns its sign counter.
/// `prev` is the last counter seen for the credential: the new one must be strictly
/// greater, unless both are 0 (authenticators without a counter).
pub fn verify_assertion(
    k: &Passkey<'_>,
    msg: &[u8],
    a: &Assertion<'_>,
    prev: u32,
) -> Result<u32, Code> {
    check_client_data(a.client_data_json, &Sha256::digest(msg).into(), k.origins)?;
    let ad = a.auth_data;
    if ad.get(..32) != Some(&Sha256::digest(k.rp_id.as_bytes())[..]) {
        return Err(Code::WebAuthnRp);
    }
    let flags = ad.get(32).copied().unwrap_or(0);
    if flags & 0x01 == 0
        || flags & 0x04 == 0
        || flags & 0x40 != 0
        || (flags & 0x80 == 0) != (ad.len() == 37)
    {
        return Err(Code::WebAuthnFlags);
    }
    let ctr = a.counter();
    if !(ctr == 0 && prev == 0) && ctr <= prev {
        return Err(Code::Counter);
    }
    let s = parse_der(a.signature).ok_or(Code::WebAuthnFormat)?;
    if s > HALF_N {
        return Err(Code::HighS);
    }
    let mut signed = Vec::with_capacity(ad.len().saturating_add(32));
    signed.extend_from_slice(ad);
    signed.extend_from_slice(&Sha256::digest(a.client_data_json));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &k.point[..])
        .verify(&signed, a.signature)
        .map_err(|_| Code::BadSig)?;
    Ok(ctr)
}

/// Strict DER `SEQUENCE { INTEGER r, INTEGER s }`: minimal, positive, both in
/// [1, n−1]. Returns s (32 bytes, big-endian).
fn parse_der(sig: &[u8]) -> Option<[u8; 32]> {
    let (&[0x30, len], mut rest) = sig.split_first_chunk::<2>()? else {
        return None;
    };
    if len > 0x7f || usize::from(len) != rest.len() {
        return None;
    }
    let mut s = [0u8; 32];
    for _ in 0..2 {
        let (&[0x02, n], tail) = rest.split_first_chunk::<2>()? else {
            return None;
        };
        let n = usize::from(n);
        if !(1..=33).contains(&n) {
            return None;
        }
        let (v, tail) = tail.split_at_checked(n)?;
        let (&first, more) = v.split_first()?;
        if first & 0x80 != 0 || (first == 0 && more.first().is_some_and(|b| b & 0x80 == 0)) {
            return None; // negative or non-minimal
        }
        let mag = if first == 0 { more } else { v };
        let mut x = [0u8; 32];
        x.get_mut(32usize.checked_sub(mag.len())?..)?
            .copy_from_slice(mag);
        if x == [0; 32] || x >= N {
            return None;
        }
        s = x;
        rest = tail;
    }
    rest.is_empty().then_some(s)
}

fn b64url(b: &[u8; 32]) -> [u8; 43] {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = [0u8; 43];
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut o = out.iter_mut();
    let mut put = |v: u32| {
        if let (Some(slot), Some(&c)) = (o.next(), A.get((v & 63) as usize)) {
            *slot = c;
        }
    };
    for &byte in b {
        bits = (bits << 8 | u32::from(byte)) & 0xffff;
        nbits = nbits.saturating_add(8);
        while nbits >= 6 {
            nbits = nbits.saturating_sub(6);
            put(bits >> nbits);
        }
    }
    put(bits << (6u32.saturating_sub(nbits)));
    out
}

/// clientDataJSON: UTF-8, one JSON object, no duplicate key at any level, depth ≤ 4,
/// no U+FFFD (lone surrogates); type, challenge, origin, crossOrigin, topOrigin.
fn check_client_data(b: &[u8], challenge: &[u8; 32], origins: &str) -> Result<(), Code> {
    let top = Json { b, i: 0 }.document().ok_or(Code::WebAuthnFormat)?;
    let get = |k: &str| top.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    if get("type") != Some(&Val::Str("webauthn.get".into())) {
        return Err(Code::WebAuthnType);
    }
    match get("challenge") {
        Some(Val::Str(c)) if c.as_bytes() == b64url(challenge) => {}
        _ => return Err(Code::WebAuthnChallenge),
    }
    match get("origin") {
        Some(Val::Str(o)) if origins.split(',').any(|a| a == o) => {}
        _ => return Err(Code::WebAuthnOrigin),
    }
    if get("crossOrigin").is_some_and(|v| *v != Val::Bool(false)) || get("topOrigin").is_some() {
        return Err(Code::WebAuthnOrigin);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Val {
    Str(String),
    Bool(bool),
    Other,
}

/// A strict RFC 8259 reader, same acceptance as Go's json.Decoder token stream.
struct Json<'a> {
    b: &'a [u8],
    i: usize,
}

const MAX_DEPTH: usize = 4;

impl Json<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i = self.i.saturating_add(1);
        Some(c)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i = self.i.saturating_add(1);
        }
    }
    fn eat(&mut self, c: u8) -> Option<()> {
        self.ws();
        (self.bump()? == c).then_some(())
    }

    /// The top-level object's members; nothing but whitespace after it.
    fn document(mut self) -> Option<Vec<(String, Val)>> {
        std::str::from_utf8(self.b).ok()?;
        let top = self.object(1)?;
        self.ws();
        (self.i == self.b.len()).then_some(top)
    }

    fn object(&mut self, depth: usize) -> Option<Vec<(String, Val)>> {
        self.eat(b'{')?;
        let mut m: Vec<(String, Val)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Some(m);
        }
        loop {
            self.ws();
            let k = self.string()?;
            if m.iter().any(|(key, _)| *key == k) {
                return None;
            }
            self.eat(b':')?;
            let v = self.value(depth)?;
            m.push((k, v));
            self.ws();
            match self.bump()? {
                b',' => {}
                b'}' => return Some(m),
                _ => return None,
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<Val> {
        self.ws();
        match self.peek()? {
            b'{' | b'[' if depth >= MAX_DEPTH => None,
            b'{' => self.object(depth.saturating_add(1)).map(|_| Val::Other),
            b'[' => {
                self.bump();
                self.ws();
                if self.peek() == Some(b']') {
                    self.bump();
                    return Some(Val::Other);
                }
                loop {
                    self.value(depth.saturating_add(1))?;
                    self.ws();
                    match self.bump()? {
                        b',' => {}
                        b']' => return Some(Val::Other),
                        _ => return None,
                    }
                }
            }
            b'"' => self.string().map(Val::Str),
            b't' => self.lit(b"true").map(|()| Val::Bool(true)),
            b'f' => self.lit(b"false").map(|()| Val::Bool(false)),
            b'n' => self.lit(b"null").map(|()| Val::Other),
            _ => self.number().map(|()| Val::Other),
        }
    }

    fn lit(&mut self, w: &[u8]) -> Option<()> {
        let end = self.i.checked_add(w.len())?;
        (self.b.get(self.i..end)? == w).then(|| self.i = end)
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i = self.i.saturating_add(1);
        }
        self.i.saturating_sub(start)
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`
    fn number(&mut self) -> Option<()> {
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek()? {
            b'0' => {
                self.bump();
            }
            b'1'..=b'9' => {
                self.digits();
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.bump();
            (self.digits() > 0).then_some(())?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            (self.digits() > 0).then_some(())?;
        }
        Some(())
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..4 {
            v = v << 4 | char::from(self.bump()?).to_digit(16)?;
        }
        Some(v)
    }

    /// A string with its escapes decoded; refuses control characters, bad escapes,
    /// lone surrogates and U+FFFD (Go decodes the former to the latter).
    fn string(&mut self) -> Option<String> {
        (self.bump()? == b'"').then_some(())?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self
                .peek()
                .is_some_and(|c| c != b'"' && c != b'\\' && c >= 0x20)
            {
                self.i = self.i.saturating_add(1);
            }
            out.push_str(std::str::from_utf8(self.b.get(start..self.i)?).ok()?);
            match self.bump()? {
                b'"' => break,
                b'\\' => {
                    let c = match self.bump()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                self.lit(b"\\u")?;
                                let lo = self.hex4()?;
                                (0xdc00..0xe000).contains(&lo).then_some(())?;
                                0x10000 | (hi & 0x3ff) << 10 | (lo & 0x3ff)
                            } else {
                                hi
                            };
                            char::from_u32(cp)?
                        }
                        _ => return None,
                    };
                    out.push(c);
                }
                _ => return None, // control character
            }
        }
        (!out.contains('\u{fffd}')).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_matches_rfc4648() {
        let mut h = [0u8; 32];
        h[0] = 0xfb;
        h[31] = 0xff;
        // python3: base64.urlsafe_b64encode(bytes([0xfb] + [0] * 30 + [0xff]))
        assert_eq!(&b64url(&h), b"-wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8");
        h[31] = 0xfe;
        h[30] = 0xbf;
        assert_eq!(&b64url(&h)[39..], b"Av_4");
    }

    #[test]
    fn strict_json() {
        let ok = |s: &str| {
            Json {
                b: s.as_bytes(),
                i: 0,
            }
            .document()
            .is_some()
        };
        assert!(ok(r#"{"a":"😀","b":[1,-0.5e+3,{}],"c":null} "#));
        for bad in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"a":01}"#,
            r#"{"a":1.}"#,
            r#"{"a":"\ud800"}"#,
            r#"{"\udc00":1}"#,
            r#"{"a":"\x"}"#,
            "{\"a\":\"\t\"}",
            r#"{"a":1,}"#,
            r#"{"a":[1,]}"#,
            r#"{"a":{"b":{"c":{"d":{}}}}}"#,
            r#"{"a":{"b":{"c":{"d":[]}}}}"#,
            "{} {}",
            r#"{"a":"�"}"#,
            "",
        ] {
            assert!(!ok(bad), "{bad}");
        }
        assert!(ok(r#"{"a":{"b":{"c":{"d":1}}}}"#)); // depth 4
    }
}
