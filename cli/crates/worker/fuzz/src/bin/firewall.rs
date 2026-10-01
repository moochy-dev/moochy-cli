//! Firewall: analyze + prepare on arbitrary bodies for every provider. Invariants: no panic;
//! an accepted body re-serializes to strict JSON whose facts are unchanged by a second pass.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::firewall::{self, MaxPrice, Request};
use moochy_worker::{Provider, json};
use moochy_worker_fuzz::{CAT, split};

fuzz_target!(|data: &[u8]| {
    let Some((d, policy, body)) = split(data) else { return };
    let headers = [("anthropic-version", "2023-06-01"), ("anthropic-beta", "interleaved-thinking-2025-05-14")];
    let hs = if d == moochy_worker::Dialect::AnthropicMessages { &headers[..] } else { &[][..] };
    let Ok(facts) = firewall::analyze(d, body, hs, &policy, &CAT) else { return };
    // The Gateway's pool normalisation never turns an accepted body into a refused one.
    let pooled = firewall::pool_compatible(d, body, hs).expect("accepted body must normalise");
    let ph: Vec<(&str, &str)> = pooled.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let again = firewall::analyze(d, &pooled.body, &ph, &policy, &CAT).expect("normalised body must stay accepted");
    assert_eq!((again.model, again.max_tokens, again.effort, again.stream, again.flags), (facts.model.clone(), facts.max_tokens, facts.effort, facts.stream, facts.flags));
    for p in [Provider::Anthropic, Provider::OpenRouter, Provider::DeepSeek, Provider::OpenAi, Provider::XAi] {
        let r = Request {
            provider: p,
            dialect: d,
            body,
            headers: hs,
            policy: &policy,
            catalog: &CAT,
            provider_model_id: "model-1",
            user_pseudonym: "ps",
            max_price: Some(MaxPrice { prompt_uusd_per_mtok: 1, completion_uusd_per_mtok: 2 }),
        };
        if let Ok(out) = firewall::prepare(&r) {
            let mut t = Vec::new();
            json::parse(&out.body, &mut t).expect("mutated body must be strict JSON");
            assert_eq!(out.facts, facts);
        }
    }
});
