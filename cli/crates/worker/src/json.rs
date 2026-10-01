//! Strict JSON for every security or money decision (CONTRACT §1, parser-differential rule).
//!
//! One pass builds a flat tape of [`Node`]s indexing into the source bytes: no per-value
//! allocation, and the tape `Vec` is reused across documents (the SSE hot path parses
//! every event into the same tape). Rejected: invalid UTF-8, duplicate object keys
//! (compared after unescaping), lone surrogates, raw control characters, integers
//! outside i64, floats outside f64, nesting deeper than 64, trailing bytes.
//!
//! Re-serialization ([`write`], [`write_patched`]) emits only the validated tree, minified,
//! so no byte that another parser could read differently is ever forwarded.

use std::borrow::Cow;
use std::fmt;

/// Maximum container nesting (root container = depth 1).
pub const MAX_DEPTH: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Null,
    Bool,
    Num,
    Str,
    Arr,
    Obj,
}

/// One tape entry. Containers are followed by their children; object children alternate
/// key (a `Str` node) and value.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    kind: Kind,
    /// `Str`: contains escapes. `Bool`: the value. `Num`: integer syntax (no `.`/exponent).
    flag: bool,
    /// Scalars: first byte of the raw text (strings: after the opening quote).
    a: u32,
    /// Scalars: end of the raw text (strings: the closing quote). Containers: tape index
    /// of the next sibling.
    b: u32,
}

const NULL_NODE: Node = Node { kind: Kind::Null, flag: false, a: 0, b: 0 };

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub pos: usize,
    pub what: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.pos, self.what)
    }
}

impl std::error::Error for Error {}

/// Parse `src` into `tape` (cleared first). The returned [`Doc`] borrows both.
pub fn parse<'a>(src: &'a [u8], tape: &'a mut Vec<Node>) -> Result<Doc<'a>, Error> {
    let text = std::str::from_utf8(src).map_err(|e| Error { pos: e.valid_up_to(), what: "invalid UTF-8" })?;
    if u32::try_from(src.len()).is_err() {
        return Err(Error { pos: 0, what: "document too large" });
    }
    tape.clear();
    let mut p = Parser { s: src, t: text, pos: 0, tape };
    p.ws();
    p.value(0)?;
    p.ws();
    if p.pos != src.len() {
        return p.err("trailing bytes after JSON value");
    }
    Ok(Doc { src: text, nodes: tape.as_slice() })
}

struct Parser<'s, 't> {
    s: &'s [u8],
    t: &'s str,
    pos: usize,
    tape: &'t mut Vec<Node>,
}

#[allow(clippy::cast_possible_truncation)] // every position is <= src.len(), checked to fit u32
fn p32(x: usize) -> u32 {
    x as u32
}

impl Parser<'_, '_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn err<T>(&self, what: &'static str) -> Result<T, Error> {
        Err(Error { pos: self.pos, what })
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.bump();
        }
    }

    fn value(&mut self, depth: u32) -> Result<(), Error> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string(),
            Some(b't') => self.lit(b"true", Kind::Bool, true),
            Some(b'f') => self.lit(b"false", Kind::Bool, false),
            Some(b'n') => self.lit(b"null", Kind::Null, false),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.err("unexpected byte"),
            None => self.err("unexpected end of input"),
        }
    }

    fn lit(&mut self, word: &[u8], kind: Kind, flag: bool) -> Result<(), Error> {
        let end = self.pos.saturating_add(word.len());
        if self.s.get(self.pos..end) != Some(word) {
            return self.err("invalid literal");
        }
        self.tape.push(Node { kind, flag, a: p32(self.pos), b: p32(end) });
        self.pos = end;
        Ok(())
    }

    fn open(&mut self, kind: Kind, depth: u32) -> Result<(usize, u32), Error> {
        let d = depth.saturating_add(1);
        if d > MAX_DEPTH {
            return self.err("nesting deeper than 64");
        }
        let idx = self.tape.len();
        self.tape.push(Node { kind, flag: false, a: p32(self.pos), b: 0 });
        self.bump();
        self.ws();
        Ok((idx, d))
    }

    fn close(&mut self, idx: usize) {
        let next = p32(self.tape.len());
        if let Some(n) = self.tape.get_mut(idx) {
            n.b = next;
        }
    }

    fn array(&mut self, depth: u32) -> Result<(), Error> {
        let (idx, d) = self.open(Kind::Arr, depth)?;
        if self.peek() == Some(b']') {
            self.bump();
        } else {
            loop {
                self.value(d)?;
                self.ws();
                match self.peek() {
                    Some(b',') => {
                        self.bump();
                        self.ws();
                    }
                    Some(b']') => {
                        self.bump();
                        break;
                    }
                    _ => return self.err("expected ',' or ']'"),
                }
            }
        }
        self.close(idx);
        Ok(())
    }

    fn object(&mut self, depth: u32) -> Result<(), Error> {
        let start = self.pos;
        let (idx, d) = self.open(Kind::Obj, depth)?;
        if self.peek() == Some(b'}') {
            self.bump();
            self.close(idx);
            return Ok(());
        }
        loop {
            if self.peek() != Some(b'"') {
                return self.err("expected object key");
            }
            self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return self.err("expected ':'");
            }
            self.bump();
            self.ws();
            self.value(d)?;
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                    self.ws();
                }
                Some(b'}') => {
                    self.bump();
                    break;
                }
                _ => return self.err("expected ',' or '}'"),
            }
        }
        self.close(idx);
        let obj = Val { doc: Doc { src: self.t, nodes: self.tape.as_slice() }, i: idx };
        if has_duplicate_keys(obj) {
            return Err(Error { pos: start, what: "duplicate object key" });
        }
        Ok(())
    }

    fn string(&mut self) -> Result<(), Error> {
        self.bump();
        let start = self.pos;
        let mut esc = false;
        loop {
            match self.peek() {
                None => return self.err("unterminated string"),
                Some(b'"') => break,
                Some(b'\\') => {
                    esc = true;
                    self.bump();
                    self.escape()?;
                }
                Some(0..=0x1f) => return self.err("control character in string"),
                Some(_) => self.bump(),
            }
        }
        self.tape.push(Node { kind: Kind::Str, flag: esc, a: p32(start), b: p32(self.pos) });
        self.bump();
        Ok(())
    }

    fn escape(&mut self) -> Result<(), Error> {
        match self.peek() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                self.bump();
                Ok(())
            }
            Some(b'u') => {
                self.bump();
                let cu = self.hex4()?;
                if (0xD800..=0xDBFF).contains(&cu) {
                    if self.peek() != Some(b'\\') || self.s.get(self.pos.saturating_add(1)) != Some(&b'u') {
                        return self.err("lone surrogate");
                    }
                    self.pos = self.pos.saturating_add(2);
                    if !(0xDC00..=0xDFFF).contains(&self.hex4()?) {
                        return self.err("lone surrogate");
                    }
                } else if (0xDC00..=0xDFFF).contains(&cu) {
                    return self.err("lone surrogate");
                }
                Ok(())
            }
            _ => self.err("invalid escape"),
        }
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let Some(d) = self.peek().and_then(|c| char::from(c).to_digit(16)) else {
                return self.err("invalid \\u escape");
            };
            v = v.wrapping_shl(4) | d;
            self.bump();
        }
        Ok(v)
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while let Some(b'0'..=b'9') = self.peek() {
            self.bump();
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<(), Error> {
        let start = self.pos;
        let mut int = true;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return self.err("invalid number"),
        }
        if self.peek() == Some(b'.') {
            int = false;
            self.bump();
            if self.digits() == 0 {
                return self.err("invalid number");
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            int = false;
            self.bump();
            if let Some(b'+' | b'-') = self.peek() {
                self.bump();
            }
            if self.digits() == 0 {
                return self.err("invalid number");
            }
        }
        let text = self.t.get(start..self.pos).unwrap_or("");
        let ok = if int { text.parse::<i64>().is_ok() } else { text.parse::<f64>().is_ok_and(f64::is_finite) };
        if !ok {
            return Err(Error { pos: start, what: if int { "integer outside i64" } else { "number outside f64" } });
        }
        self.tape.push(Node { kind: Kind::Num, flag: int, a: p32(start), b: p32(self.pos) });
        Ok(())
    }
}

fn has_duplicate_keys(obj: Val<'_>) -> bool {
    const PAIRWISE_MAX: usize = 16;
    let mut outer = obj.entries();
    if outer.clone().nth(PAIRWISE_MAX).is_none() {
        while let Some((k1, _)) = outer.next() {
            if outer.clone().any(|(k2, _)| k1.key_eq(k2)) {
                return true;
            }
        }
        return false;
    }
    let mut keys: Vec<Cow<'_, str>> = obj.entries().map(|(k, _)| k.as_str().unwrap_or_default()).collect();
    keys.sort_unstable();
    keys.windows(2).any(|w| w.first() == w.get(1))
}

/// A parsed document: the source text plus its tape.
#[derive(Clone, Copy)]
pub struct Doc<'a> {
    src: &'a str,
    nodes: &'a [Node],
}

impl<'a> Doc<'a> {
    pub fn root(self) -> Val<'a> {
        Val { doc: self, i: 0 }
    }

    pub(crate) fn at(self, i: usize) -> Val<'a> {
        Val { doc: self, i }
    }
}

/// A view of one value inside a [`Doc`]. `Copy`, no allocation.
#[derive(Clone, Copy)]
pub struct Val<'a> {
    doc: Doc<'a>,
    i: usize,
}

impl<'a> Val<'a> {
    fn node(self) -> Node {
        self.doc.nodes.get(self.i).copied().unwrap_or(NULL_NODE)
    }

    pub(crate) fn index(self) -> usize {
        self.i
    }

    pub fn kind(self) -> Kind {
        self.node().kind
    }

    fn next(self) -> usize {
        let n = self.node();
        match n.kind {
            Kind::Arr | Kind::Obj => n.b as usize,
            _ => self.i.saturating_add(1),
        }
    }

    /// Raw source text of a scalar (strings: between the quotes, still escaped). Empty for containers.
    pub fn raw(self) -> &'a str {
        let n = self.node();
        match n.kind {
            Kind::Arr | Kind::Obj => "",
            _ => self.doc.src.get(n.a as usize..n.b as usize).unwrap_or(""),
        }
    }

    pub fn as_str(self) -> Option<Cow<'a, str>> {
        let n = self.node();
        if n.kind != Kind::Str {
            return None;
        }
        Some(if n.flag { Cow::Owned(unescape(self.raw())) } else { Cow::Borrowed(self.raw()) })
    }

    /// String equality without allocating when the string has no escapes.
    pub fn is_str(self, s: &str) -> bool {
        let n = self.node();
        n.kind == Kind::Str && if n.flag { unescape(self.raw()) == s } else { self.raw() == s }
    }

    fn key_eq(self, other: Val<'_>) -> bool {
        if !self.node().flag && !other.node().flag {
            return self.raw() == other.raw();
        }
        self.as_str() == other.as_str()
    }

    pub fn as_bool(self) -> Option<bool> {
        let n = self.node();
        (n.kind == Kind::Bool).then_some(n.flag)
    }

    pub fn is_null(self) -> bool {
        self.kind() == Kind::Null
    }

    /// True for numbers written without fraction or exponent.
    pub fn is_int(self) -> bool {
        let n = self.node();
        n.kind == Kind::Num && n.flag
    }

    pub fn as_i64(self) -> Option<i64> {
        if self.is_int() { self.raw().parse().ok() } else { None }
    }

    pub fn as_u64(self) -> Option<u64> {
        self.as_i64().and_then(|v| u64::try_from(v).ok())
    }

    pub fn as_f64(self) -> Option<f64> {
        if self.kind() == Kind::Num { self.raw().parse().ok() } else { None }
    }

    /// Object member lookup (keys are unique, so this is unambiguous).
    pub fn get(self, key: &str) -> Option<Val<'a>> {
        self.entries().find(|(k, _)| k.is_str(key)).map(|(_, v)| v)
    }

    pub fn entries(self) -> Entries<'a> {
        let (i, end) = if self.kind() == Kind::Obj { (self.i.saturating_add(1), self.next()) } else { (0, 0) };
        Entries { doc: self.doc, i, end }
    }

    pub fn items(self) -> Items<'a> {
        let (i, end) = if self.kind() == Kind::Arr { (self.i.saturating_add(1), self.next()) } else { (0, 0) };
        Items { doc: self.doc, i, end }
    }
}

#[derive(Clone)]
pub struct Entries<'a> {
    doc: Doc<'a>,
    i: usize,
    end: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = (Val<'a>, Val<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.end {
            return None;
        }
        let k = Val { doc: self.doc, i: self.i };
        let v = Val { doc: self.doc, i: self.i.saturating_add(1) };
        self.i = v.next();
        Some((k, v))
    }
}

#[derive(Clone)]
pub struct Items<'a> {
    doc: Doc<'a>,
    i: usize,
    end: usize,
}

impl<'a> Iterator for Items<'a> {
    type Item = Val<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.end {
            return None;
        }
        let v = Val { doc: self.doc, i: self.i };
        self.i = v.next();
        Some(v)
    }
}

/// Decode the escaped contents of an already-validated JSON string.
fn unescape(raw: &str) -> String {
    fn hex(it: &mut std::str::Chars<'_>) -> u16 {
        (0..4).fold(0u16, |v, _| v.wrapping_shl(4) | it.next().and_then(|c| c.to_digit(16)).and_then(|d| u16::try_from(d).ok()).unwrap_or(0))
    }
    let mut out = String::with_capacity(raw.len());
    let mut it = raw.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let e = match it.next() {
            Some('n') => '\n',
            Some('r') => '\r',
            Some('t') => '\t',
            Some('b') => '\u{8}',
            Some('f') => '\u{c}',
            Some('u') => {
                let hi = hex(&mut it);
                let lo = (0xD800..=0xDBFF).contains(&hi).then(|| {
                    it.next();
                    it.next();
                    hex(&mut it)
                });
                char::decode_utf16(std::iter::once(hi).chain(lo)).next().and_then(Result::ok).unwrap_or('\u{FFFD}')
            }
            Some(other) => other,
            None => break,
        };
        out.push(e);
    }
    out
}

/// Append `s` as a JSON string literal.
pub fn push_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0..=0x1f => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'));
                out.push(HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0'));
            }
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

/// Minified re-serialization of a validated value.
pub fn write(v: Val<'_>, out: &mut Vec<u8>) {
    match v.kind() {
        Kind::Null | Kind::Bool | Kind::Num => out.extend_from_slice(v.raw().as_bytes()),
        Kind::Str => {
            out.push(b'"');
            out.extend_from_slice(v.raw().as_bytes());
            out.push(b'"');
        }
        Kind::Arr => {
            out.push(b'[');
            for (n, item) in v.items().enumerate() {
                if n > 0 {
                    out.push(b',');
                }
                write(item, out);
            }
            out.push(b']');
        }
        Kind::Obj => write_obj(Some(v), &[], 0, out),
    }
}

/// A value to set at an object path (creating intermediate objects). `json` must be one
/// encoded JSON value produced by this crate.
pub struct Patch<'p> {
    pub path: &'p [&'p str],
    pub json: &'p [u8],
}

/// [`write`] with `patches` applied: existing members are replaced in place, missing ones
/// are appended at the end of their object.
pub fn write_patched(root: Val<'_>, patches: &[Patch<'_>], out: &mut Vec<u8>) {
    if root.kind() == Kind::Obj {
        let all: Vec<&Patch<'_>> = patches.iter().filter(|p| !p.path.is_empty()).collect();
        write_obj(Some(root), &all, 0, out);
    } else {
        write(root, out);
    }
}

fn write_obj<'p>(v: Option<Val<'_>>, patches: &[&Patch<'p>], depth: usize, out: &mut Vec<u8>) {
    let seg = |p: &Patch<'p>| -> &'p str { p.path.get(depth).copied().unwrap_or("") };
    let leaf = |p: &Patch<'_>| p.path.len() == depth.saturating_add(1);
    out.push(b'{');
    let mut first = true;
    let mut comma = |out: &mut Vec<u8>| {
        if !std::mem::replace(&mut first, false) {
            out.push(b',');
        }
    };
    if let Some(v) = v {
        for (k, val) in v.entries() {
            comma(out);
            out.push(b'"');
            out.extend_from_slice(k.raw().as_bytes());
            out.extend_from_slice(b"\":");
            let here: Vec<&Patch<'p>> = patches.iter().copied().filter(|p| k.is_str(seg(p))).collect();
            if here.is_empty() {
                write(val, out);
            } else if let Some(p) = here.iter().find(|p| leaf(p)) {
                out.extend_from_slice(p.json);
            } else {
                write_obj((val.kind() == Kind::Obj).then_some(val), &here, depth.saturating_add(1), out);
            }
        }
    }
    let mut done: Vec<&str> = Vec::new();
    for p in patches {
        let name = seg(p);
        if done.contains(&name) || v.is_some_and(|v| v.get(name).is_some()) {
            continue;
        }
        done.push(name);
        comma(out);
        push_str(out, name);
        out.push(b':');
        let here: Vec<&Patch<'p>> = patches.iter().copied().filter(|q| seg(q) == name).collect();
        if let Some(p) = here.iter().find(|p| leaf(p)) {
            out.extend_from_slice(p.json);
        } else {
            write_obj(None, &here, depth.saturating_add(1), out);
        }
    }
    out.push(b'}');
}

/// A parsed document that owns its bytes (for state kept across calls).
pub struct OwnedDoc {
    src: String,
    nodes: Vec<Node>,
}

impl OwnedDoc {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut nodes = Vec::new();
        parse(bytes, &mut nodes)?;
        let src = String::from_utf8(bytes.to_vec()).map_err(|_| Error { pos: 0, what: "invalid UTF-8" })?;
        Ok(Self { src, nodes })
    }

    pub fn doc(&self) -> Doc<'_> {
        Doc { src: &self.src, nodes: &self.nodes }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::format_collect)]
mod tests {
    use super::*;

    fn ok(s: &str) -> String {
        let mut t = Vec::new();
        let d = parse(s.as_bytes(), &mut t).unwrap();
        let mut out = Vec::new();
        write(d.root(), &mut out);
        String::from_utf8(out).unwrap()
    }

    fn bad(s: &[u8]) -> &'static str {
        let mut t = Vec::new();
        parse(s, &mut t).err().unwrap().what
    }

    #[test]
    fn accepts_and_minifies() {
        assert_eq!(ok(r#" { "a" : [1, -2.5e3, true, null, "x\"y\u00e9"], "b":{} } "#), r#"{"a":[1,-2.5e3,true,null,"x\"y\u00e9"],"b":{}}"#);
        assert_eq!(ok("\"\\ud83d\\ude00\""), "\"\\ud83d\\ude00\"");
        assert_eq!(ok("9223372036854775807"), "9223372036854775807");
    }

    #[test]
    fn rejects() {
        assert_eq!(bad(br#"{"a":1,"a":2}"#), "duplicate object key");
        assert_eq!(bad(br#"{"a":1,"\u0061":2}"#), "duplicate object key");
        let many: String = (0..40).map(|i| format!("\"k{i}\":0,")).collect();
        assert_eq!(bad(format!("{{{many}\"k7\":1}}").as_bytes()), "duplicate object key");
        assert_eq!(bad(b"\"\\ud800\""), "lone surrogate");
        assert_eq!(bad(b"\"\\udc00\""), "lone surrogate");
        assert_eq!(bad(b"\"\\ud800\\u0041\""), "lone surrogate");
        assert_eq!(bad(b"\"\xff\""), "invalid UTF-8");
        assert_eq!(bad(b"\"a\x01\""), "control character in string");
        assert_eq!(bad(b"9223372036854775808"), "integer outside i64");
        assert_eq!(bad(b"1e400"), "number outside f64");
        assert_eq!(bad(b"01"), "trailing bytes after JSON value");
        assert_eq!(bad(b"1."), "invalid number");
        assert_eq!(bad(b"[1,]"), "unexpected byte");
        assert_eq!(bad(b"{} {}"), "trailing bytes after JSON value");
        assert_eq!(bad(b"\"\\x\""), "invalid escape");
        assert_eq!(bad(b""), "unexpected end of input");
        let deep = "[".repeat(65) + &"]".repeat(65);
        assert_eq!(bad(deep.as_bytes()), "nesting deeper than 64");
        let ok64 = "[".repeat(64) + &"]".repeat(64);
        assert_eq!(ok(&ok64), ok64);
    }

    #[test]
    fn views() {
        let mut t = Vec::new();
        let d = parse(br#"{"s":"a\nb","n":42,"o":{"k":[1,2,3]},"neg":-1}"#, &mut t).unwrap();
        let r = d.root();
        assert_eq!(r.get("s").unwrap().as_str().unwrap(), "a\nb");
        assert_eq!(r.get("n").unwrap().as_u64(), Some(42));
        assert_eq!(r.get("neg").unwrap().as_u64(), None);
        assert_eq!(r.get("o").unwrap().get("k").unwrap().items().count(), 3);
        assert!(r.get("missing").is_none());
        assert_eq!(r.entries().count(), 4);
    }

    #[test]
    fn patches() {
        let mut t = Vec::new();
        let d = parse(br#"{"model":"x","metadata":{"user_id":"u","k":1},"stream":true}"#, &mut t).unwrap();
        let mut out = Vec::new();
        write_patched(
            d.root(),
            &[
                Patch { path: &["model"], json: br#""y""# },
                Patch { path: &["metadata", "user_id"], json: br#""p""# },
                Patch { path: &["provider", "max_price", "prompt"], json: b"1" },
                Patch { path: &["provider", "allow_fallbacks"], json: b"false" },
                Patch { path: &["store"], json: b"false" },
            ],
            &mut out,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"model":"y","metadata":{"user_id":"p","k":1},"stream":true,"provider":{"max_price":{"prompt":1},"allow_fallbacks":false},"store":false}"#
        );
    }

    #[test]
    fn push_str_escapes() {
        let mut out = Vec::new();
        push_str(&mut out, "a\"\\\u{1}é");
        assert_eq!(String::from_utf8(out).unwrap(), "\"a\\\"\\\\\\u0001é\"");
    }
}
