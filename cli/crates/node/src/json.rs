//! Strict JSON (CONTRACT §1 parser-differential rule): rejects duplicate keys, invalid UTF-8,
//! lone surrogates, integers outside i64, non-finite numbers, and nesting deeper than 64.

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub const MAX_DEPTH: u32 = 64;

pub fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = Seed(0).deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

/// Strict parse straight into an object.
pub fn parse_object(bytes: &[u8]) -> Result<Map<String, Value>, String> {
    match parse(bytes)? {
        Value::Object(m) => Ok(m),
        _ => Err("expected a JSON object".into()),
    }
}

struct Seed(u32);

impl Seed {
    fn deeper<E: serde::de::Error>(&self) -> Result<u32, E> {
        let d = self.0.saturating_add(1);
        if d > MAX_DEPTH { Err(E::custom("nesting deeper than 64")) } else { Ok(d) }
    }
}

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }
    fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
        Ok(Value::from(n))
    }
    fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Value, E> {
        i64::try_from(n).map(Value::from).map_err(|_| E::custom("integer outside i64"))
    }
    fn visit_f64<E: serde::de::Error>(self, f: f64) -> Result<Value, E> {
        Number::from_f64(f).map(Value::Number).ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_owned()))
    }
    fn visit_string<E>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let d = self.deeper()?;
        let mut v = Vec::new();
        while let Some(x) = a.next_element_seed(Seed(d))? {
            v.push(x);
        }
        Ok(Value::Array(v))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let d = self.deeper()?;
        let mut m = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if m.contains_key(&k) {
                return Err(A::Error::custom("duplicate object key"));
            }
            let v = a.next_value_seed(Seed(d))?;
            m.insert(k, v);
        }
        Ok(Value::Object(m))
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn strict_rules() {
        assert!(parse(br#"{"a":1,"b":[true,null,"x",1.5]}"#).is_ok());
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse(b"{\"a\":1,\"\\u0061\":2}").is_err(), "escaped duplicate");
        assert!(parse(br#"{"x":{"a":1,"a":1}}"#).is_err(), "nested duplicate");
        assert!(parse(br#""\ud800""#).is_err(), "lone surrogate");
        assert!(parse(br#""\udc00x""#).is_err(), "lone trailing surrogate");
        assert!(parse(b"\"\\ud83d\\ude00\"").is_ok(), "valid pair");
        assert!(parse(b"\"\xff\"").is_err(), "invalid utf-8");
        assert!(parse(b"9223372036854775807").is_ok());
        assert!(parse(b"9223372036854775808").is_err());
        assert!(parse(b"1e400").is_err());
        assert!(parse(b"{} x").is_err(), "trailing garbage");
        let deep_ok = format!("{}{}", "[".repeat(64), "]".repeat(64));
        assert!(parse(deep_ok.as_bytes()).is_ok());
        let deep = format!("{}{}", "[".repeat(65), "]".repeat(65));
        assert!(parse(deep.as_bytes()).is_err());
    }
}
