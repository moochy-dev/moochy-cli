//! Parser-differential-safe JSON (CONTRACT §1).
//!
//! [`check`] walks the document once with serde_json's tokenizer and rejects: duplicate object
//! keys (at any depth), nesting deeper than [`MAX_DEPTH`], integers outside i64, non-finite or
//! out-of-range floats, invalid UTF-8, lone surrogates in `\u` escapes, and trailing data.
//! Only bytes that passed [`check`] are handed to serde for typed decoding ([`parse`]).

use crate::Error;
use serde::de::{DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

pub const MAX_DEPTH: usize = 64;

/// Validate `bytes` against the parser-differential rule.
pub fn check(bytes: &[u8]) -> Result<(), Error> {
    integer_literals_fit_i64(bytes)?;
    let mut de = serde_json::Deserializer::from_slice(bytes);
    Check { depth: 0 }.deserialize(&mut de).map_err(|_| Error::Json)?;
    de.end().map_err(|_| Error::Json)
}

/// [`check`] then decode into `T`. Shape errors (missing/unknown/wrong-typed fields) → `Malformed`.
pub fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    check(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| Error::Malformed)
}

/// [`check`] then decode into a generic tree (duplicates already excluded, so no last-key-wins).
pub fn parse_value(bytes: &[u8]) -> Result<serde_json::Value, Error> {
    parse(bytes)
}

/// serde_json turns integer literals beyond i64/u64 into floats; the contract wants every
/// integer literal (no `.`/`e`) to fit i64. One linear pass over the bytes outside strings.
fn integer_literals_fit_i64(b: &[u8]) -> Result<(), Error> {
    let (mut i, mut in_str, mut esc) = (0usize, false, false);
    while let Some(&c) = b.get(i) {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, b'\\') => esc = true,
                (false, b'"') => in_str = false,
                _ => {}
            }
            i = i.saturating_add(1);
        } else if c == b'"' {
            in_str = true;
            i = i.saturating_add(1);
        } else if c == b'-' || c.is_ascii_digit() {
            let len = b.get(i..).unwrap_or_default().iter().take_while(|x| x.is_ascii_digit() || b"+-.eE".contains(x)).count();
            let tok = b.get(i..i.saturating_add(len)).unwrap_or_default();
            if !tok.iter().any(|x| b".eE".contains(x)) {
                std::str::from_utf8(tok).ok().and_then(|t| t.parse::<i64>().ok()).ok_or(Error::Json)?;
            }
            i = i.saturating_add(len.max(1));
        } else {
            i = i.saturating_add(1);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Check {
    depth: usize,
}

impl Check {
    fn deeper<E: serde::de::Error>(self) -> Result<Self, E> {
        match self.depth.checked_add(1) {
            Some(depth) if depth <= MAX_DEPTH => Ok(Self { depth }),
            _ => Err(E::custom("too deep")),
        }
    }
}

impl<'de> DeserializeSeed<'de> for Check {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Check {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict JSON")
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<(), E> {
        if i64::try_from(v).is_ok() { Ok(()) } else { Err(E::custom("integer out of i64 range")) }
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<(), E> {
        if v.is_finite() { Ok(()) } else { Err(E::custom("non-finite number")) }
    }
    // serde_json decodes escapes (and rejects lone surrogates) before calling these.
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let inner = self.deeper()?;
        while seq.next_element_seed(inner)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let inner = self.deeper()?;
        let mut keys = HashSet::new();
        while let Some(k) = map.next_key::<String>()? {
            if !keys.insert(k) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            map.next_value_seed(inner)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let ok: &[&[u8]] = &[
            b"{}",
            b"[]",
            br#"{"a":1,"b":{"a":2}}"#,
            br#"{"a":-9223372036854775808,"b":9223372036854775807}"#,
            br#"{"a":1.5e300,"s":"\ud83d\ude00"}"#,
            b" {\"a\" : [1, 2, null, true] } \n",
        ];
        for b in ok {
            check(b).unwrap_or_else(|e| panic!("{e} {}", String::from_utf8_lossy(b)));
        }
        let bad: &[&[u8]] = &[
            br#"{"a":1,"a":2}"#,
            br#"{"x":{"a":1,"a":1}}"#,
            br#"[{"a":1,"\u0061":2}]"#,
            br#"{"a":9223372036854775808}"#,
            br#"{"a":-9223372036854775809}"#,
            br#"{"a":18446744073709551616}"#,
            b"[1,-99999999999999999999]",
            br#"{"a":1e400}"#,
            br#"{"a":"\ud800"}"#,
            br#"{"a":"\udc00x"}"#,
            br#"{"\ud800":1}"#,
            b"{\"a\":\"\xff\"}",
            b"{} {}",
            b"{\"a\":1,}",
            b"NaN",
            b"",
        ];
        for b in bad {
            assert_eq!(check(b), Err(Error::Json), "{}", String::from_utf8_lossy(b));
        }
        let deep_ok = format!("{}{}", "[".repeat(64), "]".repeat(64));
        check(deep_ok.as_bytes()).unwrap();
        let deep_bad = format!("{}{}", "[".repeat(65), "]".repeat(65));
        assert_eq!(check(deep_bad.as_bytes()), Err(Error::Json));
        let deep_obj = format!("{}1{}", "{\"a\":".repeat(65), "}".repeat(65));
        assert_eq!(check(deep_obj.as_bytes()), Err(Error::Json));
    }
}
