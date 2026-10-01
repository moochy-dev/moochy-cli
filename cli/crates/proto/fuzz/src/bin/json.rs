//! libFuzzer target: the strict JSON parser and everything built on it (route header, inner
//! payload, receipt, projection, catalog, route facts of provider bodies). Invariants: no panic /
//! ASan report / timeout; anything `json::check` accepts is also valid JSON to serde_json; every
//! typed parse goes through the strict check (a duplicate key is never accepted downstream).
#![no_main]

use libfuzzer_sys::fuzz_target;
use moochy_proto::msg::{Catalog, Dialect, InnerPayload, Projection, Receipt, RouteHeader};
use moochy_proto::{json, money};

fuzz_target!(|data: &[u8]| {
    let strict = json::check(data).is_ok();
    if strict {
        assert!(json::parse_value(data).is_ok(), "strict-accepted bytes must form a JSON value");
    }
    // Typed parses: never accepted unless the strict check accepted.
    let typed = [
        RouteHeader::parse(data).is_ok(),
        InnerPayload::parse(data).is_ok(),
        Catalog::parse(data).is_ok(),
        json::parse::<Receipt>(data).is_ok(),
        json::parse::<Projection>(data).is_ok(),
        money::body_facts(Dialect::AnthropicMessages, data).is_ok(),
        money::body_facts(Dialect::OpenAiChat, data).is_ok(),
    ];
    assert!(strict || typed.iter().all(|ok| !ok), "a typed parse accepted bytes the strict check refused");
});
