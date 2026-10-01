//! Parser differential (CONTRACT §1): everything our strict parser accepts, and its canonical
//! re-serialization, must read as the *same* tree in a lenient parser of the kind providers use
//! (serde_json: last key wins, big numbers kept as text). Invariant: equal trees, no panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::json::{self, Kind, Val};
use serde_json::Value;

fn same(a: Val<'_>, b: &Value) -> bool {
    match (a.kind(), b) {
        (Kind::Null, Value::Null) => true,
        (Kind::Bool, Value::Bool(x)) => a.as_bool() == Some(*x),
        // Same number by value (the canonical writer normalises integer spelling).
        (Kind::Num, Value::Number(n)) => match (a.as_i64(), n.as_i64()) {
            (Some(x), Some(y)) => x == y,
            _ => n.as_f64().is_some_and(|f| a.as_f64() == Some(f)),
        },
        (Kind::Str, Value::String(s)) => a.as_str().as_deref() == Some(s.as_str()),
        (Kind::Arr, Value::Array(v)) => a.items().count() == v.len() && a.items().zip(v).all(|(x, y)| same(x, y)),
        (Kind::Obj, Value::Object(m)) => a.entries().count() == m.len() && a.entries().all(|(k, x)| m.get(&*k.as_str().unwrap()).is_some_and(|y| same(x, y))),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut t = Vec::new();
    let Ok(doc) = json::parse(data, &mut t) else { return };
    let lenient: Value = serde_json::from_slice(data).expect("strictly accepted input must parse leniently");
    assert!(same(doc.root(), &lenient), "lenient parser reads a different tree");
    let mut canon = Vec::new();
    json::write(doc.root(), &mut canon);
    let again: Value = serde_json::from_slice(&canon).expect("canonical output must parse leniently");
    let mut t2 = Vec::new();
    let doc2 = json::parse(&canon, &mut t2).expect("canonical output must stay strict");
    assert!(same(doc2.root(), &again), "canonical output reads differently");
    assert!(same(doc2.root(), &lenient), "canonical output changed the tree");
});
