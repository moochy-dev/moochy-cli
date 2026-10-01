//! Strict JSON: no panic; accepted input → canonical write is a fixed point and every string
//! decodes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::json;

fuzz_target!(|data: &[u8]| {
    let (mut t1, mut t2) = (Vec::new(), Vec::new());
    let Ok(doc) = json::parse(data, &mut t1) else { return };
    let mut a = Vec::new();
    json::write(doc.root(), &mut a);
    let doc2 = json::parse(&a, &mut t2).expect("canonical output must parse");
    let mut b = Vec::new();
    json::write(doc2.root(), &mut b);
    assert_eq!(a, b);
});
