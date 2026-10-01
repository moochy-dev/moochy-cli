//! Request validator (CONTRACT §15.2): in-process rules, real single-use child processes,
//! and the added latency per request.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_precision_loss, clippy::panic)]

use std::fmt::Write as _;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moochy_worker::firewall::{self, CacheTtl, Catalog, Level, Policy, RejectCode, Route};
use moochy_worker::validate::{self, ValidateError, ValidateRequest, Validator, ValidatorLimits};
use moochy_worker::{Dialect, Effort, Flags, Provider};

const CAT: Catalog = Catalog { default_effort: Effort::High, max_output: 64_000, max_image_tokens: 1600, max_page_tokens: 3000 };
const POL: Policy = Policy { level: Level::Strict, flags: Flags::NONE, max_effort: Effort::Max };
const DEV: &str = "d_01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ALIASES: &[&str] = &["anthropic/claude-sonnet-5.5", "claude-sonnet-5-5"];

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn inner(body: &str, extra: &str) -> String {
    format!(
        r#"{{"v":1,"body_b64":"{}","body_sha256":"{}","headers":{{"anthropic-version":"2023-06-01"}},"S":"{}","gateway_device":"{DEV}","task_sig":"{}"{extra}}}"#,
        b64(body.as_bytes()),
        b64(&[7; 32]),
        b64(&[1; 32]),
        b64(&[9; 64])
    )
}

fn zst(b: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
}

fn body(text: &str) -> String {
    format!(r#"{{"model":"claude-sonnet-5-5","max_tokens":1000,"stream":true,"messages":[{{"role":"user","content":{}}}]}}"#, serde_str(text))
}

fn serde_str(s: &str) -> String {
    let mut v = Vec::new();
    moochy_worker::json::push_str(&mut v, s);
    String::from_utf8(v).unwrap()
}

/// A route that matches `body` exactly (what an honest Gateway computes).
fn route_for(b: &str) -> Route<'static> {
    let f = firewall::analyze(Dialect::AnthropicMessages, b.as_bytes(), &[], &Policy::PERMISSIVE, &CAT).unwrap();
    Route {
        dialect: Dialect::AnthropicMessages,
        model_aliases: ALIASES,
        effort: f.effort,
        max_tokens: f.max_tokens,
        est_input_tokens: f.est_input_tokens,
        cache_ttl: f.cache_ttl,
        stream: f.stream,
        flags: f.flags,
    }
}

fn req<'a>(payload: &'a [u8], route: Route<'a>) -> ValidateRequest<'a> {
    ValidateRequest {
        provider: Provider::Anthropic,
        dialect: Dialect::AnthropicMessages,
        policy: POL,
        catalog: CAT,
        provider_model_id: "claude-sonnet-5-5-20260101",
        user_pseudonym: "ps_1",
        max_price: None,
        route,
        payload,
    }
}

#[test]
fn accepts_and_returns_canonical_body() {
    let b = body("hi there");
    let payload = zst(inner(&b, "").as_bytes());
    let v = validate::validate_in_process(&req(&payload, route_for(&b))).unwrap();
    assert_eq!((v.s, v.task_sig, v.body_sha256), ([1; 32], [9; 64], [7; 32]));
    assert_eq!(v.gateway_device, DEV);
    assert_eq!(v.headers, vec![("anthropic-version".to_owned(), "2023-06-01".to_owned())]);
    assert_eq!(&v.body[..], b.as_bytes(), "original body for body_sha256 / req_commit");
    let canon = std::str::from_utf8(&v.prepared.body).unwrap();
    assert!(canon.contains(r#""model":"claude-sonnet-5-5-20260101""#) && canon.contains(r#""metadata":{"user_id":"ps_1"}"#), "{canon}");
    assert_eq!(v.prepared.headers, vec![("anthropic-version", "2023-06-01".to_owned())]);
    // Interop: the C encoder (moochy-proto's compressor) at several levels.
    for level in [1, 3, 19] {
        let c = zstd::bulk::compress(inner(&b, "").as_bytes(), level).unwrap();
        assert!(validate::validate_in_process(&req(&c, route_for(&b))).is_ok(), "level {level}");
    }
}

#[test]
fn refusals_and_bad_envelopes() {
    let b = body("hi");
    let good_route = route_for(&b);
    // Firewall and route refusals carry their code.
    let fw = r#"{"model":"claude-sonnet-5-5","max_tokens":1000,"messages":[],"mcp_servers":[]}"#;
    let p = zst(inner(fw, "").as_bytes());
    match validate::validate_in_process(&req(&p, good_route)) {
        Err(ValidateError::Refused(r)) => assert_eq!((r.code, r.path.as_str()), (RejectCode::Firewall, "mcp_servers")),
        other => panic!("{other:?}"),
    }
    let p = zst(inner(&b, "").as_bytes());
    let lying = Route { max_tokens: 10, ..good_route };
    match validate::validate_in_process(&req(&p, lying)) {
        Err(e @ ValidateError::Refused(_)) => assert_eq!(e.nack(), ("route_mismatch", false)),
        other => panic!("{other:?}"),
    }

    let bomb = zst(&vec![b' '; (32 << 20) + 1]);
    assert!(bomb.len() < 1 << 20, "a tiny frame that expands past the cap");
    let mut two_frames = zst(inner(&b, "").as_bytes());
    two_frames.extend(zst(b"{}"));
    let mut big_window = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xA0]; // window 2^30
    big_window.extend([0x01, 0x00, 0x00]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("not zstd", b"hello".to_vec()),
        ("bomb", bomb),
        ("two frames", two_frames),
        ("window", big_window),
        ("truncated", zst(inner(&b, "").as_bytes())[..20].to_vec()),
        ("unknown member", zst(inner(&b, r#","extra":1"#).as_bytes())),
        ("dup key", zst(inner(&b, r#","v":1"#).as_bytes())),
        ("v2", zst(inner(&b, "").replace(r#""v":1"#, r#""v":2"#).as_bytes())),
        ("padding", zst(inner(&b, "").replace(&b64(&[1; 32]), &format!("{}=", b64(&[1; 32]))).as_bytes())),
        ("short S", zst(inner(&b, "").replace(&b64(&[1; 32]), &b64(&[1; 31])).as_bytes())),
        ("device", zst(inner(&b, "").replace(DEV, "d_nope").as_bytes())),
        ("header case", zst(inner(&b, "").replace("anthropic-version", "Anthropic-Version").as_bytes())),
        ("not json", zst(b"{\"v\":1,")),
    ];
    for (name, payload) in cases {
        match validate::validate_in_process(&req(&payload, good_route)) {
            Err(e @ ValidateError::BadEnvelope(_)) => assert_eq!(e.nack(), ("bad_envelope", false), "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

const BIN: &str = env!("CARGO_BIN_EXE_moochy-validate");

fn spawner(program: &'static str, args: &'static [&'static str]) -> validate::Spawner {
    Arc::new(move || {
        tokio::process::Command::new(program).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true).spawn()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn child_process_round_trips() {
    let v = Validator::new(spawner(BIN, &[]), ValidatorLimits::default());
    assert_eq!(v.prewarm().unwrap(), 2);
    let b = body("hello from a child");
    let p = zst(inner(&b, "").as_bytes());
    let ok = v.validate(&req(&p, route_for(&b))).await.unwrap();
    assert_eq!(&ok.body[..], b.as_bytes());
    let fw = r#"{"model":"claude-sonnet-5-5","max_tokens":1000,"messages":[],"container":"c"}"#;
    let p = zst(inner(fw, "").as_bytes());
    assert!(matches!(v.validate(&req(&p, route_for(&b))).await, Err(ValidateError::Refused(_))));
    assert!(matches!(v.validate(&req(b"junk", route_for(&b))).await, Err(ValidateError::BadEnvelope(_))));
    // Each request used its own child: the pool keeps being refilled.
    for _ in 0..10 {
        let p = zst(inner(&b, "").as_bytes());
        v.validate(&req(&p, route_for(&b))).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn child_failures_are_retryable() {
    let b = body("x");
    let p = zst(inner(&b, "").as_bytes());
    for (prog, args) in [("/bin/true", &[][..]), ("/bin/false", &[][..]), ("/bin/echo", &["garbage"][..]), ("/bin/sleep", &["30"][..])] {
        let v = Validator::new(spawner(prog, args), ValidatorLimits { deadline: Duration::from_millis(500), warm: 1 });
        let t = Instant::now();
        let e = v.validate(&req(&p, route_for(&b))).await.unwrap_err();
        assert!(matches!(e, ValidateError::Child(_)), "{prog}: {e:?}");
        assert_eq!(e.nack(), ("busy", true), "{prog}");
        assert!(t.elapsed() < Duration::from_secs(2), "{prog}");
    }
}

/// CONTRACT §15.2 target: < 1 ms added per request with a warm child.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn added_latency_per_request() {
    let turn = "Please refactor this function and explain the change. ".repeat(40);
    let mut msgs = String::new();
    while msgs.len() < 100_000 {
        let _ = write!(msgs, r#",{{"role":"user","content":{}}}"#, serde_str(&turn));
    }
    let b = format!(r#"{{"model":"claude-sonnet-5-5","max_tokens":1000,"stream":true,"messages":[{{"role":"user","content":"x"}}{msgs}]}}"#);
    let p = zstd::bulk::compress(inner(&b, "").as_bytes(), 3).unwrap();
    let r = req(&p, route_for(&b));
    let v = Validator::new(spawner(BIN, &[]), ValidatorLimits::default());
    v.prewarm().unwrap();
    let (mut child, mut inproc) = (Vec::new(), Vec::new());
    for _ in 0..200 {
        let t = Instant::now();
        validate::validate_in_process(&r).unwrap();
        inproc.push(t.elapsed());
        // Let the replacement child finish spawning (a request every few ms, as in practice).
        tokio::time::sleep(Duration::from_millis(3)).await;
        let t = Instant::now();
        v.validate(&r).await.unwrap();
        child.push(t.elapsed());
    }
    child.sort();
    inproc.sort();
    let pct = |v: &[Duration], q: usize| v[(v.len() * q / 100).min(v.len() - 1)];
    let added50 = pct(&child, 50).saturating_sub(pct(&inproc, 50));
    let added99 = pct(&child, 99).saturating_sub(pct(&inproc, 99));
    println!(
        "validate {} B body ({} B zstd): in-process p50 {:?} p99 {:?}; child p50 {:?} p99 {:?}; added p50 {:?} p99 {:?}",
        b.len(),
        p.len(),
        pct(&inproc, 50),
        pct(&inproc, 99),
        pct(&child, 50),
        pct(&child, 99),
        added50,
        added99
    );
    if !cfg!(debug_assertions) {
        assert!(added50 < Duration::from_millis(1), "added p50 {added50:?}");
    }
}

#[test]
fn ttl_and_types_roundtrip() {
    // Facts survive the wire (non-default values).
    let b = r#"{"model":"claude-sonnet-5-5","max_tokens":77,"stream":false,"output_config":{"effort":"low"},"messages":[{"role":"user","content":[{"type":"text","text":"a","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}"#;
    let p = zst(inner(b, "").as_bytes());
    let v = validate::validate_in_process(&req(&p, route_for(b))).unwrap();
    let f = &v.prepared.facts;
    assert_eq!((f.max_tokens, f.effort, f.cache_ttl, f.stream), (77, Effort::Low, CacheTtl::H1, false));
}
