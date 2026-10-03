//! Provider-key redaction (CONTRACT §23, A291): defence in depth for every byte that leaves
//! the donor's machine (sealed frames, receipts, journal, logs, CLI output). The root fix is
//! upstream (provider error text is never forwarded, [`crate::provider::Failure::public_message`]);
//! this catches what a provider echoes anywhere else.
//!
//! A secret is matched in its raw, URL-encoded, hex (both cases) and base64 (standard and
//! URL alphabets, padded or not, at the three byte alignments) forms. Any run of at least 8
//! bytes that is a prefix or a suffix of one of those forms is replaced by [`MARK`], extended
//! over as much of the form as the text matches. The raw form's public prefix (`sk-ant-api03-`,
//! `sk-proj-`, `xai-`: every key of that provider shares it) is not a match on its own, so model
//! text about key formats survives; once the secret part matches, the prefix goes too.
//!
//! Cost: one bit test per byte (first two bytes of every needle in a 64 Ki-bit table), an
//! 8-byte compare only on a hit; nothing is copied when nothing matches.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use std::borrow::Cow;
use zeroize::Zeroize;

/// What a redacted run becomes (ASCII, JSON-string-safe, SSE-safe).
pub const MARK: &[u8] = b"[redacted]";
/// Shortest run that counts as a leak, and the needle length.
const MIN: usize = 8;
/// Secrets shorter than this are not redacted (they would match ordinary text).
const MIN_SECRET: usize = 12;

struct Form {
    bytes: Vec<u8>,
    /// Where the first needle starts (after the raw form's public prefix).
    head: usize,
}

impl Drop for Form {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Redacts a fixed set of secrets (one adapter's API key or auth header value).
pub struct Redactor {
    forms: Vec<Form>,
    /// Bit `(b0 << 8) | b1` set when some needle starts with bytes `b0 b1`.
    first2: Box<[u64; 1024]>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor").field("forms", &self.forms.len()).finish_non_exhaustive()
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self { forms: Vec::new(), first2: Box::new([0; 1024]) }
    }
}

/// Length of a key's public prefix: up to the last `-` or `_` among its first 16 bytes, when
/// at least 8 bytes of secret follow.
fn public_prefix(s: &[u8]) -> usize {
    let p = s.iter().take(16).rposition(|&b| b == b'-' || b == b'_').map_or(0, |i| i.saturating_add(1));
    if s.len().saturating_sub(p) >= MIN { p } else { 0 }
}

fn url_encode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.extend_from_slice(hex(&[b], true).as_slice());
        }
    }
    out
}

fn hex(s: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut out = Vec::with_capacity(s.len().saturating_mul(2));
    for &b in s {
        for n in [b >> 4, b & 15] {
            out.push(digits.get(usize::from(n)).copied().unwrap_or(b'0'));
        }
    }
    out
}

impl Redactor {
    /// `secrets`: the values to hide; empty and short ones (< 12 bytes) are ignored.
    pub fn new(secrets: &[&[u8]]) -> Self {
        let mut r = Self::default();
        for s in secrets.iter().filter(|s| s.len() >= MIN_SECRET) {
            let p = public_prefix(s);
            r.add(s.to_vec(), p);
            let mut u = url_encode(s);
            if u.as_slice() != *s {
                let up = url_encode(s.get(..p).unwrap_or_default()).len();
                r.add(std::mem::take(&mut u), up);
            }
            u.zeroize();
            r.add(hex(s, false), 0);
            r.add(hex(s, true), 0);
            // Base64 at each byte alignment: the characters that depend only on the secret
            // (the first and last 4 may mix in neighbouring bytes or padding).
            for off in 0..3usize {
                let mut buf = vec![0u8; off];
                buf.extend_from_slice(s);
                for engine in [&STANDARD, &URL_SAFE] {
                    let mut e = engine.encode(&buf).into_bytes();
                    if let Some(inner) = e.get(4..e.len().saturating_sub(4)) {
                        r.add(inner.to_vec(), 0);
                    }
                    e.zeroize();
                }
                buf.zeroize();
            }
        }
        r
    }

    fn add(&mut self, bytes: Vec<u8>, head: usize) {
        let mut f = Form { bytes, head };
        if f.bytes.len() < MIN.saturating_add(f.head) || self.forms.iter().any(|g| g.bytes == f.bytes) {
            f.bytes.zeroize();
            return;
        }
        let tail = f.bytes.len().saturating_sub(MIN);
        for at in [f.head, tail] {
            if let (Some(&a), Some(&b)) = (f.bytes.get(at), f.bytes.get(at.saturating_add(1))) {
                let k = (usize::from(a) << 8) | usize::from(b);
                if let Some(w) = self.first2.get_mut(k >> 6) {
                    *w |= 1u64 << (k & 63);
                }
            }
        }
        self.forms.push(f);
    }

    /// Nothing to redact.
    pub fn is_empty(&self) -> bool {
        self.forms.is_empty()
    }

    /// The run `[start, end)` of `b` around a needle match at `i`, if any.
    fn match_at(&self, b: &[u8], i: usize, floor: usize) -> Option<(usize, usize)> {
        let w = b.get(i..i.checked_add(MIN)?)?;
        let mut best: Option<(usize, usize)> = None;
        for f in &self.forms {
            let tail = f.bytes.len().saturating_sub(MIN);
            for at in [f.head, tail] {
                if f.bytes.get(at..at.saturating_add(MIN)) != Some(w) {
                    continue;
                }
                // Extend backwards (not below `floor`, the end of the previous run) and forwards.
                let (mut s, mut j) = (i, at);
                while s > floor && j > 0 && b.get(s.saturating_sub(1)) == f.bytes.get(j.saturating_sub(1)) {
                    s = s.saturating_sub(1);
                    j = j.saturating_sub(1);
                }
                let (mut e, mut k) = (i.saturating_add(MIN), at.saturating_add(MIN));
                while k < f.bytes.len() && b.get(e).is_some() && b.get(e) == f.bytes.get(k) {
                    e = e.saturating_add(1);
                    k = k.saturating_add(1);
                }
                if best.is_none_or(|(bs, be)| e.saturating_sub(s) > be.saturating_sub(bs)) {
                    best = Some((s, e));
                }
            }
        }
        best
    }

    /// `b` with every leaked run replaced by [`MARK`]; borrowed (no copy) when clean.
    pub fn redact<'a>(&self, b: &'a [u8]) -> Cow<'a, [u8]> {
        if self.forms.is_empty() || b.len() < MIN {
            return Cow::Borrowed(b);
        }
        let mut out: Option<Vec<u8>> = None;
        let (mut copied, mut i) = (0usize, 0usize);
        while i.saturating_add(MIN) <= b.len() {
            let hit = match (b.get(i), b.get(i.saturating_add(1))) {
                (Some(&x), Some(&y)) => {
                    let k = (usize::from(x) << 8) | usize::from(y);
                    self.first2.get(k >> 6).is_some_and(|w| w & (1u64 << (k & 63)) != 0)
                }
                _ => false,
            };
            if let Some((s, e)) = hit.then(|| self.match_at(b, i, copied)).flatten() {
                let o = out.get_or_insert_with(|| Vec::with_capacity(b.len()));
                o.extend_from_slice(b.get(copied..s).unwrap_or_default());
                o.extend_from_slice(MARK);
                copied = e;
                i = e;
            } else {
                i = i.saturating_add(1);
            }
        }
        match out {
            None => Cow::Borrowed(b),
            Some(mut o) => {
                o.extend_from_slice(b.get(copied..).unwrap_or_default());
                Cow::Owned(o)
            }
        }
    }

    /// [`Self::redact`] for text (every form is ASCII, so the result stays UTF-8).
    pub fn redact_str<'a>(&self, s: &'a str) -> Cow<'a, str> {
        match self.redact(s.as_bytes()) {
            Cow::Borrowed(_) => Cow::Borrowed(s),
            Cow::Owned(v) => Cow::Owned(String::from_utf8(v).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())),
        }
    }

    /// Does `b` hold a leaked run?
    pub fn leaks(&self, b: &[u8]) -> bool {
        matches!(self.redact(b), Cow::Owned(_))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const KEY: &str = "sk-ant-api03-CANARY291-0123456789abcdefABCDEF";

    fn r() -> Redactor {
        Redactor::new(&[KEY.as_bytes()])
    }

    fn clean(r: &Redactor, b: &[u8]) -> String {
        String::from_utf8(r.redact(b).into_owned()).unwrap()
    }

    #[test]
    fn raw_key_in_json_and_sse() {
        let r = r();
        let sse = format!("event: error\ndata: {{\"type\":\"error\",\"error\":{{\"type\":\"overloaded_error\",\"message\":\"overloaded for key {KEY}\"}}}}\n\n");
        let out = clean(&r, sse.as_bytes());
        assert!(!out.contains("CANARY291"), "{out}");
        assert!(out.contains("overloaded for key [redacted]\"}}\n\n"), "{out}");
        assert_eq!(clean(&r, format!("x-api-key {KEY}: malformed").as_bytes()), "x-api-key [redacted]: malformed");
        assert_eq!(clean(&r, format!("Bearer {KEY}").as_bytes()), "Bearer [redacted]");
    }

    #[test]
    fn partial_prefixes_and_suffixes() {
        let r = r();
        // ≥ 8 bytes of the secret part, with or without the public prefix.
        assert_eq!(clean(&r, b"key sk-ant-api03-CANARY29 cut"), "key [redacted] cut");
        assert_eq!(clean(&r, b"...CANARY291-012 cut"), "...[redacted] cut");
        assert_eq!(clean(&r, &KEY.as_bytes()[KEY.len() - 8..]), "[redacted]");
        assert_eq!(clean(&r, format!("tail={}!", &KEY[KEY.len() - 12..]).as_bytes()), "tail=[redacted]!");
        // The public prefix alone, or fewer than 8 secret bytes, is not a leak.
        for ok in ["keys look like sk-ant-api03-…", "sk-ant-api03-CANARY2", "ABCDEF", "plain text with no key"] {
            assert_eq!(clean(&r, ok.as_bytes()), ok);
            assert!(matches!(r.redact(ok.as_bytes()), Cow::Borrowed(_)));
        }
    }

    #[test]
    fn encodings() {
        let k = KEY.as_bytes();
        let weird = "sk-ant-api03-a/b+c=d e%f&g?h#i0123456789";
        let r = Redactor::new(&[k, weird.as_bytes()]);
        // Whole forms: nothing but the mark is left.
        for f in [hex(k, false), hex(k, true), url_encode(weird.as_bytes())] {
            let text = [b"<".as_slice(), &f, b">"].concat();
            assert_eq!(clean(&r, &text), "<[redacted]>", "{}", String::from_utf8_lossy(&f));
        }
        // Base64 of the key inside a larger blob, at every alignment and alphabet: none of the
        // key-only characters (what A291's scanner looks for) survive.
        let mut scan = Vec::new();
        for off in 0..3 {
            let mut b = vec![0u8; off];
            b.extend_from_slice(k);
            for e in [&STANDARD, &URL_SAFE] {
                let x = e.encode(&b);
                scan.push(x[4..x.len() - 4].to_owned());
            }
        }
        for off in 0..3 {
            let mut b = vec![b'p'; off];
            b.extend_from_slice(b":");
            b.extend_from_slice(k);
            b.extend_from_slice(b":tail");
            for e in [&STANDARD, &URL_SAFE, &base64::engine::general_purpose::STANDARD_NO_PAD] {
                let out = clean(&r, e.encode(&b).as_bytes());
                assert!(out.contains("[redacted]"), "{out}");
                for f in &scan {
                    assert!(!out.contains(f.as_str()), "{out} still holds {f}");
                }
            }
        }
        assert!(!r.is_empty() && Redactor::new(&[b"short"]).is_empty());
    }

    #[test]
    fn several_runs_and_no_copy_when_clean() {
        let r = r();
        let text = format!("a {KEY} b {KEY} c");
        assert_eq!(clean(&r, text.as_bytes()), "a [redacted] b [redacted] c");
        let big = "lorem ipsum ".repeat(2000);
        assert!(matches!(r.redact(big.as_bytes()), Cow::Borrowed(_)));
        assert_eq!(r.redact_str(&text), "a [redacted] b [redacted] c");
    }
}
