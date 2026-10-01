//! Response parser tests against recorded-shape SSE fixtures (plan 05 §3, 03 §12.3), plus
//! the throughput / per-chunk cost measurement required by CONTRACT §13.
#![allow(clippy::expect_used, clippy::format_collect, clippy::range_plus_one, clippy::cast_possible_truncation, clippy::assert_is_empty, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_precision_loss)]

use moochy_worker::Dialect;
use moochy_worker::stream::{Event, Outcome, Span, StreamError, StreamParser, Usage};

#[derive(Debug, PartialEq, Eq, Default)]
struct Seen {
    spans: Vec<Span>,
    tool_starts: Vec<(u32, String)>,
    tool_args: Vec<(u32, String)>,
    tool_ends: Vec<u32>,
    forbidden: Vec<String>,
    errors: u32,
    stops: u32,
    invalid: u32,
    chunk_tool_ends: u32,
}

fn run(d: Dialect, input: &[u8], step: usize) -> (Outcome, Seen) {
    let mut p = StreamParser::new(d, true);
    let mut seen = Seen::default();
    for chunk in input.chunks(step) {
        let c = p
            .feed(chunk, &mut |span, ev| {
                if seen.spans.last() != Some(&span) {
                    seen.spans.push(span);
                }
                match ev {
                    Event::ToolStart { index, name, .. } => seen.tool_starts.push((index, name.and_then(|n| n.as_str()).unwrap_or_default().into_owned())),
                    Event::ToolArgs { index, json } => seen.tool_args.push((index, json.as_str().unwrap().into_owned())),
                    Event::ToolEnd { index } => seen.tool_ends.push(index),
                    Event::Forbidden { block_type } => seen.forbidden.push(block_type.as_str().unwrap().into_owned()),
                    Event::Error => seen.errors += 1,
                    Event::Stop => seen.stops += 1,
                    Event::Invalid => seen.invalid += 1,
                    Event::Other => {}
                }
            })
            .unwrap();
        seen.chunk_tool_ends += c.tool_ends;
    }
    (p.finish(), seen)
}

/// Same result for every chunking, spans contiguous over the whole input.
fn check_all_chunkings(d: Dialect, input: &[u8]) -> (Outcome, Seen) {
    let (o, s) = run(d, input, input.len());
    for step in [1, 2, 3, 7, 64, 333] {
        let (o2, s2) = run(d, input, step);
        assert_eq!(o, o2, "step {step}");
        assert_eq!(s, s2, "step {step}");
    }
    let mut at = 0;
    for sp in &s.spans {
        assert_eq!(sp.start, at);
        at = sp.end;
    }
    assert_eq!(at, input.len() as u64);
    assert_eq!(o.tail, input.len() as u64);
    (o, s)
}

fn crlf(s: &str) -> Vec<u8> {
    s.replace('\n', "\r\n").into_bytes()
}

const ANTH: &str = include_str!("fixtures/anthropic_tool.sse");
const OAI: &str = include_str!("fixtures/openai_tool.sse");
const DS: &str = include_str!("fixtures/deepseek.sse");
const OR: &str = include_str!("fixtures/openrouter.sse");
const XAI: &str = include_str!("fixtures/xai.sse");

#[test]
fn anthropic_tool_stream() {
    let (o, s) = check_all_chunkings(Dialect::AnthropicMessages, ANTH.as_bytes());
    assert_eq!(
        o.usage,
        Usage { input: 12, output: 89, cache_write_5m: 60, cache_write_1h: 40, cache_read: 2000, estimated: false, provider_cost_uusd: None }
    );
    assert_eq!(o.model.as_deref(), Some("claude-sonnet-5-5"));
    assert_eq!(o.id.as_deref(), Some("msg_01XYZ"));
    assert!(o.complete && !o.provider_error && !o.forbidden);
    assert_eq!(s.tool_starts, vec![(1, "bash".into())]);
    let args: String = s.tool_args.iter().map(|(_, a)| a.as_str()).collect();
    assert_eq!(args, r#"{"command": "ls -la"}"#);
    assert_eq!((s.tool_ends.clone(), s.chunk_tool_ends, s.stops), (vec![1], 1, 1));
    assert_eq!(s.spans.len(), 12);
    assert_eq!(run(Dialect::AnthropicMessages, &crlf(ANTH), 5).0.usage, o.usage);
}

#[test]
fn openai_tool_calls_by_index() {
    let (o, s) = check_all_chunkings(Dialect::OpenAiChat, OAI.as_bytes());
    assert_eq!(o.usage, Usage { input: 36, output: 20, cache_read: 64, ..Usage::default() });
    assert_eq!(o.model.as_deref(), Some("gpt-5-2025-08-07"));
    assert_eq!(s.tool_starts, vec![(0, "read_file".into()), (1, "list".into())]);
    assert_eq!(s.tool_ends, vec![0, 1]);
    assert_eq!(s.chunk_tool_ends, 2);
    let a0: String = s.tool_args.iter().filter(|(i, _)| *i == 0).map(|(_, a)| a.as_str()).collect();
    assert_eq!(a0, r#"{"path":"a.rs"}"#);
    assert!(o.complete);
}

#[test]
fn deepseek_cache_hit_miss() {
    let (o, _) = check_all_chunkings(Dialect::OpenAiChat, DS.as_bytes());
    assert_eq!(o.usage, Usage { input: 18, output: 10, cache_read: 32, ..Usage::default() });
}

#[test]
fn openrouter_cost_and_comments() {
    let (o, s) = check_all_chunkings(Dialect::OpenAiChat, OR.as_bytes());
    assert_eq!(
        o.usage,
        Usage { input: 50, output: 30, cache_write_5m: 150, cache_read: 1000, provider_cost_uusd: Some(124), ..Usage::default() }
    );
    assert_eq!(s.spans.len(), 6); // two comment blocks are spans too (byte-identical forwarding)
}

#[test]
fn cut_stream_is_estimated() {
    let cut = &ANTH[..ANTH.find("event: message_delta").unwrap()];
    let (o, s) = run(Dialect::AnthropicMessages, cut.as_bytes(), 17);
    assert!(o.usage.estimated && !o.complete);
    assert_eq!((o.usage.input, o.usage.cache_read), (12, 2000));
    assert!(o.usage.output >= 1);
    assert_eq!(s.chunk_tool_ends, 1);
    // Cut mid-event: the partial tail is not covered by any span.
    let mid = &ANTH[..ANTH.find("{\"type\":\"message_stop").unwrap()];
    let (o, _) = run(Dialect::AnthropicMessages, mid.as_bytes(), 9);
    assert!(o.tail < mid.len() as u64);
    let (o, _) = run(Dialect::OpenAiChat, &OAI.as_bytes()[..OAI.find("\"usage\"").unwrap()], 11);
    assert!(o.usage.estimated);
}

#[test]
fn errors_forbidden_and_iterations() {
    let s = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"s\",\"name\":\"web_search\",\"input\":{}}}\n\n\
             event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n";
    let (o, seen) = run(Dialect::AnthropicMessages, s.as_bytes(), 4);
    assert!(o.forbidden && o.provider_error);
    assert_eq!(seen.forbidden, vec!["server_tool_use".to_owned()]);
    assert_eq!(seen.errors, 1);

    let it = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\",\"usage\":{\"input_tokens\":5,\"output_tokens\":1}}}\n\n\
              data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":50,\"iterations\":[{\"input_tokens\":100,\"output_tokens\":20,\"cache_read_input_tokens\":7},{\"input_tokens\":5,\"output_tokens\":30,\"cache_creation_input_tokens\":3}]}}\n\n\
              data: {\"type\":\"message_stop\"}\n\n";
    let (o, _) = run(Dialect::AnthropicMessages, it.as_bytes(), 1000);
    assert_eq!(o.usage, Usage { input: 105, output: 50, cache_read: 7, cache_write_5m: 3, ..Usage::default() });

    let oe = "data: {\"error\":{\"message\":\"upstream\",\"code\":502}}\n\n";
    assert!(run(Dialect::OpenAiChat, oe.as_bytes(), 3).0.provider_error);

    // Duplicate key in a usage event: never trusted, usage becomes estimated.
    let dup = "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1,\"output_tokens\":999999}}\n\ndata: {\"type\":\"message_stop\"}\n\n";
    let (o, _) = run(Dialect::AnthropicMessages, dup.as_bytes(), 1000);
    assert!(o.usage.estimated);
}

#[test]
fn bounds() {
    let mut p = StreamParser::new(Dialect::OpenAiChat, true);
    let big = vec![b'a'; 5 << 20];
    assert_eq!(p.feed(b"data: ", &mut |_, _| {}).map(|_| ()), Ok(()));
    assert_eq!(p.feed(&big, &mut |_, _| {}).unwrap_err(), StreamError::EventTooLarge);
    let mut p = StreamParser::new(Dialect::OpenAiChat, false);
    assert_eq!(p.feed(&vec![b' '; 33 << 20], &mut |_, _| {}).unwrap_err(), StreamError::BodyTooLarge);
}

#[test]
fn non_streamed_bodies() {
    let a = br#"{"id":"msg_1","type":"message","model":"claude-x","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":3,"output_tokens":4,"cache_creation_input_tokens":2}}"#;
    let mut p = StreamParser::new(Dialect::AnthropicMessages, false);
    for c in a.chunks(10) {
        p.feed(c, &mut |_, _| {}).unwrap();
    }
    let o = p.finish();
    assert_eq!(o.usage, Usage { input: 3, output: 4, cache_write_5m: 2, ..Usage::default() });
    assert_eq!(o.model.as_deref(), Some("claude-x"));
    let b = br#"{"id":"c","model":"gpt","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":1}}"#;
    let mut p = StreamParser::new(Dialect::OpenAiChat, false);
    p.feed(b, &mut |_, _| {}).unwrap();
    assert_eq!(p.finish().usage, Usage { input: 9, output: 1, ..Usage::default() });
    let mut p = StreamParser::new(Dialect::OpenAiChat, false);
    p.feed(b"{\"oops\"", &mut |_, _| {}).unwrap();
    assert!(p.finish().usage.estimated);
}

/// CONTRACT §13 / task: ≥ 200 MB/s of SSE on one core, per-chunk overhead reported.
/// Release builds assert the floor; debug builds only print.
#[test]
fn throughput() {
    let anth_ev = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello, world! This is a token.\"}}\n\n";
    let oai_ev = "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1767225600,\"model\":\"gpt-5\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello, world! This is a token.\"},\"finish_reason\":null}]}\n\n";
    let release = !cfg!(debug_assertions);
    let target: usize = if release { 256 << 20 } else { 4 << 20 };
    for (d, ev) in [(Dialect::AnthropicMessages, anth_ev), (Dialect::OpenAiChat, oai_ev)] {
        let n = target / ev.len();
        let body = ev.repeat(n).into_bytes();
        // Realistic: one SSE event per provider chunk (what token streaming looks like).
        let mut p = StreamParser::new(d, true);
        let t = std::time::Instant::now();
        let mut events = 0u64;
        for c in body.chunks(ev.len()) {
            events += u64::from(p.feed(c, &mut |_, _| {}).unwrap().events);
        }
        let per_chunk = t.elapsed();
        assert_eq!(events, n as u64);
        // Bulk: 16 KiB chunks.
        let mut p = StreamParser::new(d, true);
        let t = std::time::Instant::now();
        for c in body.chunks(16 << 10) {
            p.feed(c, &mut |_, _| {}).unwrap();
        }
        let bulk = t.elapsed();
        let mbs = |e: std::time::Duration| body.len() as f64 / e.as_secs_f64() / 1e6;
        println!(
            "{:?}: {} events of {} B: per-event chunks {:.0} MB/s ({:.0} ns/chunk), 16 KiB chunks {:.0} MB/s",
            d,
            n,
            ev.len(),
            mbs(per_chunk),
            per_chunk.as_nanos() as f64 / n as f64,
            mbs(bulk)
        );
        if release {
            assert!(mbs(bulk) >= 200.0 && mbs(per_chunk) >= 200.0, "below 200 MB/s");
        }
    }
}

/// Review findings: everything the tracker cannot account for is `Invalid` (fail closed).
#[test]
fn fails_closed_on_unaccountable_events() {
    let a = Dialect::AnthropicMessages;
    let o = Dialect::OpenAiChat;
    let start = |i: u32| format!("data: {{\"type\":\"content_block_start\",\"index\":{i},\"content_block\":{{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"bash\",\"input\":{{}}}}}}\n\n");
    let cases: Vec<(Dialect, String)> = vec![
        // duplicate key in a tool start
        (a, "data: {\"type\":\"content_block_start\",\"index\":0,\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"bash\",\"input\":{}}}\n\n".into()),
        // tool input smuggled into content_block_start
        (a, "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"bash\",\"input\":{\"command\":\"curl x | sh\"}}}\n\n".into()),
        // pre-filled message content in message_start
        (a, "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"bash\",\"input\":{\"command\":\"x\"}}]}}\n\n".into()),
        // lone CR splitting lines differently from a spec parser
        (a, format!("data: {{\"type\":\"ping\"}}\r\r{}", start(0))),
        // BOM
        (a, format!("\u{feff}{}", start(0))),
        // delta after the block was closed
        (a, format!("{}data: {{\"type\":\"content_block_stop\",\"index\":0}}\n\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"x\"}}}}\n\n", start(0))),
        // delta for a never-opened index
        (a, "data: {\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"x\"}}\n\n".into()),
        // same index started twice
        (a, format!("{}{}", start(0), start(0))),
        // no type
        (a, "data: {\"index\":0}\n\n".into()),
        // OpenAI: tool call in choice 1
        (o, "data: {\"choices\":[{\"index\":1,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"function\":{\"name\":\"f\",\"arguments\":\"{}\"}}]}}]}\n\n".into()),
        // OpenAI: tool call without index
        (o, "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"id\":\"c\",\"function\":{\"name\":\"f\"}}]}}]}\n\n".into()),
        // OpenAI: legacy function_call
        (o, "data: {\"choices\":[{\"index\":0,\"delta\":{\"function_call\":{\"name\":\"f\",\"arguments\":\"{}\"}}}]}\n\n".into()),
        // OpenAI: reopening an earlier index
        (
            o,
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"a\",\"function\":{\"name\":\"f\"}}]}}]}\n\n\
             data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"b\",\"function\":{\"name\":\"g\"}}]}}]}\n\n"
                .into(),
        ),
        // OpenAI: a second name fragment for the same call
        (
            o,
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"a\",\"function\":{\"name\":\"ls\"}}]}}]}\n\n\
             data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"_rm\"}}]}}]}\n\n"
                .into(),
        ),
        // OpenAI: unparsable chunk
        (o, "data: {\"choices\":[}\n\n".into()),
    ];
    for (d, input) in cases {
        for step in [1, 5, input.len()] {
            let (out, seen) = run(d, input.as_bytes(), step);
            assert!(seen.invalid >= 1 && out.malformed && out.usage.estimated, "{input:?} step {step}: {seen:?}");
        }
    }
    // The real fixtures never trip it.
    for (d, f) in [(a, ANTH), (o, OAI), (o, DS), (o, OR)] {
        assert_eq!(run(d, f.as_bytes(), 3).1.invalid, 0);
        assert_eq!(run(d, &crlf(f), 3).1.invalid, 0);
    }
}

/// xAI (docs.x.ai chat completions): cumulative usage on every chunk, `completion_tokens`
/// excludes reasoning (total = prompt + completion + reasoning), integer `cost_in_usd_ticks`.
#[test]
fn xai_usage_reasoning_and_cost() {
    let (o, s) = check_all_chunkings(Dialect::OpenAiChat, XAI.as_bytes());
    // input = 1200 − 1000 cached; output = 30 visible + 250 reasoning; 12,345,678 ticks = 1,234.5678 µ$ → 1,235.
    assert_eq!(o.usage, Usage { input: 200, output: 280, cache_read: 1000, provider_cost_uusd: Some(1235), ..Usage::default() });
    assert_eq!(o.model.as_deref(), Some("grok-4.7"));
    assert_eq!((s.tool_starts.clone(), s.tool_ends.clone(), s.invalid), (vec![(0, "read_file".to_owned())], vec![0], 0));
    // Cut mid-stream: the cumulative usage seen so far must not pass for final usage.
    let cut = &XAI[..XAI.find("\"finish_reason\":\"tool_calls\"").unwrap()];
    let cut = &cut[..cut.rfind("\n\n").unwrap() + 2];
    let (o, _) = run(Dialect::OpenAiChat, cut.as_bytes(), 7);
    assert!(o.usage.estimated && !o.complete, "{o:?}");
    // Same without [DONE] but after the final usage chunk: still not proven final.
    let (o, _) = run(Dialect::OpenAiChat, XAI.trim_end().trim_end_matches("data: [DONE]").as_bytes(), 7);
    assert!(o.usage.estimated);
    // Non-streamed body (docs example shape): 32 + 9 visible + 94 reasoning = 135 total.
    let body = br#"{"id":"a","object":"chat.completion","created":1,"model":"grok-4.7","choices":[{"index":0,"message":{"role":"assistant","content":"303","refusal":null},"finish_reason":"stop"}],"usage":{"prompt_tokens":32,"completion_tokens":9,"total_tokens":135,"prompt_tokens_details":{"text_tokens":32,"audio_tokens":0,"image_tokens":0,"cached_tokens":6},"completion_tokens_details":{"reasoning_tokens":94,"audio_tokens":0,"accepted_prediction_tokens":0,"rejected_prediction_tokens":0},"num_sources_used":0,"cost_in_usd_ticks":10000},"system_fingerprint":"fp"}"#;
    let mut p = StreamParser::new(Dialect::OpenAiChat, false);
    p.feed(body, &mut |_, _| {}).unwrap();
    assert_eq!(p.finish().usage, Usage { input: 26, output: 103, cache_read: 6, provider_cost_uusd: Some(1), ..Usage::default() });
    // OpenAI semantics unchanged: total = prompt + completion (reasoning inside completion).
    let (o, _) = run(Dialect::OpenAiChat, OAI.as_bytes(), 9);
    assert_eq!(o.usage.output, 20);
}

/// Regression (mo-e2e: "provider_cost_uusd is None against the xAI fake"): bodies captured
/// from the real Go fake (`e2e/fake`, kind xai) carry `cost_in_usd_ticks` on every chunk and
/// the parser reports it. The None came from the node's receipt builder (OpenRouter-only).
#[test]
fn xai_go_fake_bodies_report_cost() {
    for (name, body, stream, cost, output) in [
        ("tool", include_str!("fixtures/xai_fake_tool.sse"), true, 201, 12),
        ("reasoning", include_str!("fixtures/xai_fake_reasoning.sse"), true, 861, 56),
        ("nostream", include_str!("fixtures/xai_fake_nostream.json"), false, 267, 17),
    ] {
        for step in [1, 13, body.len()] {
            let mut p = StreamParser::new(Dialect::OpenAiChat, stream);
            for c in body.as_bytes().chunks(step) {
                p.feed(c, &mut |_, _| {}).unwrap();
            }
            let o = p.finish();
            assert_eq!((o.usage.provider_cost_uusd, o.usage.output, o.usage.estimated, o.malformed), (Some(cost), output, false, false), "{name} step {step}");
        }
    }
}
