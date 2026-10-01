//! Request validator child: arbitrary wire requests, and arbitrary compressed payloads inside
//! a valid wire request. Invariants: no panic, exit code 0/2, a framed response for every
//! well-formed request.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::firewall::{Policy, Route};
use moochy_worker::validate::{self, ValidateRequest};
use moochy_worker::{Dialect, Effort, Flags, Provider};
use moochy_worker_fuzz::CAT;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let mut out = Vec::new();
    if sel & 1 == 0 {
        let code = validate::child_main(rest, &mut out);
        assert!(code == 0 || code == 2);
        return;
    }
    let route = Route {
        dialect: Dialect::AnthropicMessages,
        model_aliases: &["m"],
        effort: Effort::High,
        max_tokens: 16,
        est_input_tokens: 40,
        cache_ttl: moochy_worker::firewall::CacheTtl::None,
        stream: true,
        flags: Flags::NONE,
    };
    let mut wire = Vec::new();
    validate::encode_request(
        &ValidateRequest {
            provider: Provider::Anthropic,
            dialect: Dialect::AnthropicMessages,
            policy: Policy::PERMISSIVE,
            catalog: CAT,
            provider_model_id: "m-1",
            user_pseudonym: "ps",
            max_price: None,
            route,
            payload: rest,
        },
        &mut wire,
    );
    assert_eq!(validate::child_main(&wire[..], &mut out), 0, "well-formed request must get a response");
    let len = u32::from_be_bytes(out[..4].try_into().unwrap()) as usize;
    assert_eq!(len + 4, out.len());
});
