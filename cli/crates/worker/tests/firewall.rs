//! Table-driven firewall tests (plan 06 §7): every deny, nested content, strict JSON,
//! huge inputs, header allowlist, route facts, safe mutations.
#![allow(clippy::panic, clippy::format_push_string, clippy::needless_raw_string_hashes, clippy::expect_used, clippy::format_collect, clippy::range_plus_one, clippy::cast_possible_truncation, clippy::assert_is_empty, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::too_many_lines, clippy::cast_precision_loss)]

use moochy_worker::firewall::{self, Catalog, CacheTtl, Level, MaxPrice, Policy, RejectCode, Request, Route};
use moochy_worker::{Dialect, Effort, Flags, Provider};

const CAT: Catalog = Catalog { default_effort: Effort::High, max_output: 64_000, max_image_tokens: 1600, max_page_tokens: 3000 };

fn policy(flags: Flags) -> Policy {
    Policy { level: Level::Strict, flags, max_effort: Effort::High }
}

fn analyze(d: Dialect, body: &str, headers: &[(&str, &str)], p: Policy) -> Result<firewall::Facts, firewall::Reject> {
    firewall::analyze(d, body.as_bytes(), headers, &p, &CAT)
}

/// Anthropic body with `content` as the first user message and `extra` top-level members.
fn anth(content: &str, extra: &str) -> String {
    format!(r#"{{"model":"anthropic/claude-sonnet-5.5","max_tokens":1000,"messages":[{{"role":"user","content":{content}}}]{extra}}}"#)
}

fn oai(content: &str, extra: &str) -> String {
    format!(r#"{{"model":"openai/gpt-5","max_completion_tokens":1000,"messages":[{{"role":"user","content":{content}}}]{extra}}}"#)
}

const CLAUDE_CODE_LIKE: &str = r#"{
  "model": "claude-sonnet-5-5", "max_tokens": 32000, "stream": true, "temperature": 1,
  "system": [{"type":"text","text":"You are Claude Code.","cache_control":{"type":"ephemeral"}}],
  "metadata": {"user_id": "client-chosen"},
  "messages": [
    {"role":"user","content":[{"type":"text","text":"list files"}]},
    {"role":"assistant","content":[
      {"type":"thinking","thinking":"I should run ls","signature":"sig"},
      {"type":"redacted_thinking","data":"opaque"},
      {"type":"text","text":"Running ls."},
      {"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls","nested":{"a":[1,{"b":null}]}}}]},
    {"role":"user","content":[
      {"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"a.rs\nb.rs"}],"is_error":false},
      {"type":"text","text":"thanks","cache_control":{"type":"ephemeral","ttl":"1h"}}]}
  ],
  "tools": [
    {"name":"Bash","description":"Run a command","input_schema":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}},
    {"type":"bash_20250124","name":"bash"},
    {"type":"text_editor_20250728","name":"str_replace_based_edit_tool","max_characters":10000},
    {"type":"computer_20250124","name":"computer","display_width_px":1024,"display_height_px":768}
  ],
  "tool_choice": {"type":"auto","disable_parallel_tool_use":false},
  "thinking": {"type":"enabled","budget_tokens":4096},
  "output_config": {"effort":"medium"}
}"#;

#[test]
fn anthropic_allows_real_client_traffic() {
    let h = [("anthropic-version", "2023-06-01"), ("anthropic-beta", "claude-code-20250219, interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14")];
    let f = analyze(Dialect::AnthropicMessages, CLAUDE_CODE_LIKE, &h, policy(Flags::NONE)).unwrap();
    assert_eq!(f.model, "claude-sonnet-5-5");
    assert_eq!(f.max_tokens, 32_000);
    assert_eq!(f.effort, Effort::Medium);
    assert_eq!(f.cache_ttl, CacheTtl::H1);
    assert!(f.stream);
    assert_eq!(f.flags, Flags::NONE);
    assert_eq!(f.est_input_tokens, (CLAUDE_CODE_LIKE.len() as u64).div_ceil(3));
}

#[test]
fn anthropic_denies() {
    let img = |src: &str| format!(r#"[{{"type":"image","source":{src}}}]"#);
    let images = policy(Flags::IMAGES.with(Flags::DOCUMENTS));
    let cases: Vec<(String, Policy, &str, &str)> = vec![
        (anth(r#""hi""#, r#","mcp_servers":[{"type":"url","url":"https://x","name":"x"}]"#), images, "mcp_servers", "arbitrary servers"),
        (anth(r#""hi""#, r#","tools":[{"type":"web_search_20250305","name":"web_search"}]"#), images, "tools[0].type", "server-executed"),
        (anth(r#""hi""#, r#","tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]"#), images, "tools[0].type", "server-executed"),
        (anth(r#""hi""#, r#","tools":[{"type":"code_execution_20250825","name":"code_execution"}]"#), images, "tools[0].type", "server-executed"),
        (anth(r#""hi""#, r#","tools":[{"type":"mcp_toolset","mcp_server_name":"x"}]"#), images, "tools[0].type", "MCP"),
        (anth(r#""hi""#, r#","tools":[{"type":"bash_20250124","name":"rm"}]"#), images, "tools[0].name", "not allowed"),
        (anth(r#""hi""#, r#","tools":[{"name":"x"}]"#), images, "tools[0].input_schema", "required"),
        (anth(&img(r#"{"type":"file","file_id":"file_1"}"#), ""), images, "messages[0].content[0].source.type", "file store"),
        (anth(&img(r#"{"type":"url","url":"https://x/y.png"}"#), ""), images, "messages[0].content[0].source.type", "fetch URLs"),
        (anth(&img(r#"{"type":"base64","media_type":"image/png","data":"AA=="}"#), ""), policy(Flags::NONE), "messages[0].content[0]", "`images` opt-in"),
        (anth(&img(r#"{"type":"base64","media_type":"image/svg+xml","data":"AA=="}"#), ""), images, "messages[0].content[0].source.media_type", "not allowed"),
        (
            anth(r#"[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"url","url":"u"}}]}]"#, ""),
            images,
            "messages[0].content[0].content[0].source.type",
            "fetch URLs",
        ),
        (
            anth(r#"[{"type":"tool_result","tool_use_id":"t","content":[{"type":"document","source":{"type":"file","file_id":"f"}}]}]"#, ""),
            images,
            "messages[0].content[0].content[0].source.type",
            "file store",
        ),
        (
            anth(r#"[{"type":"tool_result","tool_use_id":"t","content":[{"type":"tool_use","id":"x","name":"y","input":{}}]}]"#, ""),
            images,
            "messages[0].content[0].content[0].type",
            "not allowed",
        ),
        (anth(r#"[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBE"}}]"#, ""), images, "source.data", "page count"),
        (anth(r#"[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"x"}}]"#, ""), policy(Flags::IMAGES), "messages[0].content[0]", "`documents` opt-in"),
        (anth(r#"[{"type":"server_tool_use","id":"s","name":"web_search","input":{}}]"#, ""), images, "messages[0].content[0].type", "server-side"),
        (anth(r#"[{"type":"web_search_tool_result","tool_use_id":"s","content":[]}]"#, ""), images, "messages[0].content[0].type", "server-side"),
        (anth(r#"[{"type":"mcp_tool_use","id":"m","name":"x","server_name":"s","input":{}}]"#, ""), images, "messages[0].content[0].type", "MCP"),
        (anth(r#"[{"type":"container_upload","file_id":"f"}]"#, ""), images, "messages[0].content[0].type", "containers"),
        (anth(r#"[{"type":"search_result","source":"s","title":"t","content":[]}]"#, ""), images, "messages[0].content[0].type", "not allowed"),
        (anth(r#"[{"type":"text","text":"x","citations":[]}]"#, ""), images, "messages[0].content[0].citations", "is not allowed"),
        (anth(r#"[{"text":"x"}]"#, ""), images, "messages[0].content[0].type", "required"),
        (anth(r#"[{"type":"text","text":"x","cache_control":{"type":"persistent"}}]"#, ""), images, "cache_control.type", "not allowed"),
        (anth(r#""hi""#, r#","foo":1"#), images, "foo", "is not allowed"),
        (anth(r#""hi""#, r#","container":"c"#), images, "", ""),
        (anth(r#""hi""#, r#","container":"c""#), images, "container", "execution"),
        (anth(r#""hi""#, r#","context_management":{"edits":[{"type":"compact_20260112"}]}"#), images, "context_management.edits[0].type", "not allowed"),
        (anth(r#""hi""#, r#","speed":"fast""#), images, "speed", "`fast` opt-in"),
        (anth(r#""hi""#, r#","service_tier":"auto""#), images, "service_tier", "donor's call"),
        (anth(r#""hi""#, r#","inference_geo":"us""#), images, "inference_geo", "donor's call"),
        (anth(r#""hi""#, r#","provider":{"order":["x"]}"#), images, "provider", "Worker"),
        (anth(r#""hi""#, r#","output_config":{"effort":"max"}"#), images, "effort", "exceeds"),
        (anth(r#""hi""#, r#","thinking":{"type":"enabled"}"#), images, "thinking.budget_tokens", "required"),
        (anth(r#""hi""#, r#","stream":"yes""#), images, "stream", "boolean"),
        (anth(r#""hi""#, r#","top_k":-1"#), images, "top_k", "non-negative"),
        (r#"{"model":"m","messages":[]}"#.into(), images, "max_tokens", "required"),
        (r#"{"model":"m","max_tokens":0,"messages":[]}"#.into(), images, "max_tokens", "between"),
        (r#"{"model":"m","max_tokens":64001,"messages":[]}"#.into(), images, "max_tokens", "between"),
        (r#"{"model":"","max_tokens":1,"messages":[]}"#.into(), images, "model", "non-empty"),
        (r#"{"model":"m","max_tokens":1,"messages":[{"role":"developer","content":"x"}]}"#.into(), images, "messages[0].role", "not allowed"),
        (r#"{"model":"m","model":"m","max_tokens":1,"messages":[]}"#.into(), images, "", "duplicate object key"),
        (r#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"text","text":"a","type":"image"}]}]}"#.into(), images, "", "duplicate"),
        (r#"["not an object"]"#.into(), images, "", "must be an object"),
    ];
    for (body, p, path, reason) in cases {
        if path.is_empty() && reason.is_empty() {
            assert!(analyze(Dialect::AnthropicMessages, &body, &[], p).is_err(), "{body}");
            continue;
        }
        let e = analyze(Dialect::AnthropicMessages, &body, &[], p).expect_err(&body);
        assert_eq!(e.code, RejectCode::Firewall, "{body}");
        assert!(e.path.ends_with(path), "path {:?} !~ {path:?} for {body}", e.path);
        assert!(e.to_string().contains(reason), "{e} !~ {reason:?} for {body}");
    }
}

#[test]
fn anthropic_gated_features_set_flags() {
    let all = policy(Flags::IMAGES.with(Flags::DOCUMENTS).with(Flags::FAST).with(Flags::LONG_CONTEXT));
    let body = anth(
        r#"[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAAAAAAAAAA"}},{"type":"document","source":{"type":"text","media_type":"text/plain","data":"doc"}}]"#,
        r#","speed":"fast""#,
    );
    let f = analyze(Dialect::AnthropicMessages, &body, &[("anthropic-beta", "context-1m-2025-08-07")], all).unwrap();
    assert_eq!(f.flags, Flags::IMAGES.with(Flags::DOCUMENTS).with(Flags::FAST).with(Flags::LONG_CONTEXT));
    assert_eq!(f.images, 1);
    assert_eq!(f.text_bytes, body.len() as u64 - 12);
    assert_eq!(f.est_input_tokens, f.text_bytes.div_ceil(3) + 1600);

    let tier = anth(r#""hi""#, r#","service_tier":"standard_only","inference_geo":"global""#);
    let f = firewall::analyze(Dialect::AnthropicMessages, tier.as_bytes(), &[], &Policy::PERMISSIVE, &CAT).unwrap();
    assert_eq!(f.flags, Flags::SERVICE_TIER.with(Flags::INFERENCE_GEO), "gated features are recorded for the route header");
    // F20: a regional value is billed at a premium the catalog does not price.
    let us = anth(r#""hi""#, r#","inference_geo":"us""#);
    let e = firewall::analyze(Dialect::AnthropicMessages, us.as_bytes(), &[], &Policy::PERMISSIVE, &CAT).unwrap_err();
    assert!(e.to_string().contains("premium"), "{e}");

    let paranoid = Policy { level: Level::Paranoid, ..all };
    let e = analyze(Dialect::AnthropicMessages, &body, &[], paranoid).unwrap_err();
    assert!(e.to_string().contains("paranoid"), "{e}");
    let big = r#"{"model":"m","max_tokens":20000,"messages":[]}"#;
    assert!(analyze(Dialect::AnthropicMessages, big, &[], all).is_ok());
    assert!(analyze(Dialect::AnthropicMessages, big, &[], paranoid).is_err());
}

#[test]
fn headers_allowlist() {
    let body = anth(r#""hi""#, "");
    let ok = |h: &[(&str, &str)]| analyze(Dialect::AnthropicMessages, &body, h, policy(Flags::NONE));
    assert!(ok(&[("Anthropic-Version", "2023-06-01")]).is_ok());
    for (h, path) in [
        (vec![("anthropic-version", "2024-01-01")], "header anthropic-version"),
        (vec![("anthropic-beta", "files-api-2025-04-14")], "header anthropic-beta"),
        (vec![("anthropic-beta", "code-execution-2025-08-25")], "header anthropic-beta"),
        (vec![("anthropic-beta", "mcp-client-2025-04-04")], "header anthropic-beta"),
        (vec![("anthropic-beta", "context-1m-2025-08-07")], "header anthropic-beta"),
        (vec![("anthropic-beta", "oauth-2025-04-20")], "header anthropic-beta"),
        (vec![("x-api-key", "sk-steal")], "header x-api-key"),
        (vec![("anthropic-beta", "a"), ("anthropic-beta", "b")], "header anthropic-beta"),
    ] {
        let e = ok(&h).unwrap_err();
        assert_eq!(e.path, path, "{h:?}");
    }
    let e = analyze(Dialect::OpenAiChat, &oai(r#""hi""#, ""), &[("anthropic-version", "2023-06-01")], policy(Flags::NONE)).unwrap_err();
    assert_eq!(e.path, "header anthropic-version");
}

#[test]
fn openai_allows_and_denies() {
    let ok = oai(
        r#"[{"type":"text","text":"what is this"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA","detail":"low"}}]"#,
        r#","stream":true,"stream_options":{"include_usage":false},"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"tool_choice":"auto","reasoning_effort":"low","n":1,"response_format":{"type":"json_schema","json_schema":{"name":"x","schema":{}}}"#,
    );
    let f = analyze(Dialect::OpenAiChat, &ok, &[], policy(Flags::IMAGES)).unwrap();
    assert_eq!((f.max_tokens, f.effort, f.images, f.stream), (1000, Effort::Low, 1, true));
    let hist = r#"{"model":"m","max_tokens":5,"messages":[{"role":"system","content":"s"},{"role":"developer","content":[{"type":"text","text":"d"}]},{"role":"user","content":"u"},
        {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"r"}]}"#;
    assert_eq!(analyze(Dialect::OpenAiChat, hist, &[], policy(Flags::NONE)).unwrap().effort, Effort::High);

    let images = policy(Flags::IMAGES);
    for (body, path, reason) in [
        (oai(r#""hi""#, r#","n":2"#), "n", "multiplies output"),
        (oai(r#""hi""#, r#","web_search_options":{}"#), "web_search_options", "web search"),
        (oai(r#""hi""#, r#","tools":[{"type":"web_search"}]"#), "tools[0].type", "hosted tools"),
        (oai(r#""hi""#, r#","tools":[{"type":"code_interpreter"}]"#), "tools[0].type", "hosted tools"),
        (oai(r#""hi""#, r#","tools":[{"type":"mcp","server_url":"x"}]"#), "tools[0].type", "MCP"),
        (oai(r#""hi""#, r#","audio":{"voice":"x"}"#), "audio", "audio"),
        (oai(r#""hi""#, r#","modalities":["text","audio"]"#), "modalities[1]", "not allowed"),
        (oai(r#""hi""#, r#","prediction":{"type":"content","content":"x"}"#), "prediction", "billed as output"),
        (oai(r#""hi""#, r#","service_tier":"flex""#), "service_tier", "donor's call"),
        (oai(r#""hi""#, r#","metadata":{"a":"b"}"#), "metadata", "stored"),
        (oai(r#""hi""#, r#","models":["a","b"]"#), "models", "fallback"),
        (oai(r#""hi""#, r#","route":"fallback""#), "route", "fallback"),
        (oai(r#""hi""#, r#","plugins":[{"id":"web"}]"#), "plugins", "plugins"),
        (oai(r#""hi""#, r#","provider":{"allow_fallbacks":true}"#), "provider", "Worker"),
        (oai(r#""hi""#, r#","usage":{"include":true}"#), "usage", "Worker"),
        (oai(r#""hi""#, r#","max_tokens":5"#), "max_completion_tokens", "together"),
        (oai(r#""hi""#, r#","reasoning_effort":"xhigh""#), "effort", "exceeds"),
        (oai(r#""hi""#, r#","functions":[]"#), "functions", "legacy"),
        (oai(r#""hi""#, r#","bogus":true"#), "bogus", "is not allowed"),
        (oai(r#"[{"type":"image_url","image_url":{"url":"https://evil/x.png"}}]"#, ""), "messages[0].content[0].image_url.url", "data:image/"),
        (oai(r#"[{"type":"input_audio","input_audio":{}}]"#, ""), "messages[0].content[0].type", "audio"),
        (oai(r#"[{"type":"file","file":{"file_id":"f"}}]"#, ""), "messages[0].content[0].type", "file store"),
        (r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#.into(), "max_tokens", "required"),
        (r#"{"model":"m","max_tokens":1,"messages":[{"role":"function","name":"f","content":"x"}]}"#.into(), "messages[0].role", "legacy"),
        (r#"{"model":"m","max_tokens":1,"messages":[{"content":"x"}]}"#.into(), "messages[0].role", "required"),
    ] {
        let e = analyze(Dialect::OpenAiChat, &body, &[], images).expect_err(&body);
        assert!(e.path.ends_with(path), "path {:?} !~ {path:?} for {body}", e.path);
        assert!(e.to_string().contains(reason), "{e} !~ {reason:?}");
    }
}

#[test]
fn strict_json_and_bounds() {
    let p = policy(Flags::NONE);
    let deep = format!(r#"{{"model":"m","max_tokens":1,"messages":[{{"role":"user","content":[{{"type":"tool_use","id":"i","name":"n","input":{}{}}}]}}]}}"#, "[".repeat(64), "]".repeat(64));
    assert!(analyze(Dialect::AnthropicMessages, &deep, &[], p).unwrap_err().to_string().contains("nesting deeper than 64"));
    let lone = anth(r#""\ud800""#, "");
    assert!(analyze(Dialect::AnthropicMessages, &lone, &[], p).unwrap_err().to_string().contains("lone surrogate"));
    let mut bad_utf8 = anth(r#""xx""#, "").into_bytes();
    let i = bad_utf8.iter().position(|&b| b == b'x').unwrap();
    bad_utf8[i] = 0xff;
    assert!(firewall::analyze(Dialect::AnthropicMessages, &bad_utf8, &[], &p, &CAT).unwrap_err().to_string().contains("UTF-8"));
    let big_int = r#"{"model":"m","max_tokens":99999999999999999999,"messages":[]}"#;
    assert!(analyze(Dialect::AnthropicMessages, big_int, &[], p).unwrap_err().to_string().contains("i64"));
    let huge = anth(&format!("\"{}\"", "a".repeat(firewall::MAX_BODY)), "");
    assert!(analyze(Dialect::AnthropicMessages, &huge, &[], p).unwrap_err().to_string().contains("32 MiB"));
    // Many keys (sorted duplicate check) and a long message list stay fast and correct.
    let many: String = (0..5000).map(|i| format!(r#","k{i}":{i}"#)).collect();
    let body = anth(&format!(r#"[{{"type":"tool_use","id":"i","name":"n","input":{{"a":0{many},"k77":1}}}}]"#), "");
    assert!(analyze(Dialect::AnthropicMessages, &body, &[], p).unwrap_err().to_string().contains("duplicate"));
    let msgs: String = (0..20_000).map(|_| r#",{"role":"user","content":"hello there"}"#).collect();
    let body = format!(r#"{{"model":"m","max_tokens":1,"messages":[{{"role":"user","content":"x"}}{msgs}]}}"#);
    let t = std::time::Instant::now();
    assert!(analyze(Dialect::AnthropicMessages, &body, &[], p).is_ok());
    assert!(t.elapsed().as_millis() < 2000);
}

#[test]
fn never_panics_on_mutated_input() {
    let base = CLAUDE_CODE_LIKE.as_bytes();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let all = policy(Flags::IMAGES.with(Flags::DOCUMENTS));
    for _ in 0..20_000 {
        let mut b = base.to_vec();
        for _ in 0..(next() % 4 + 1) {
            let i = (next() as usize) % b.len();
            match next() % 3 {
                0 => b[i] = (next() & 0xff) as u8,
                1 => {
                    b.remove(i);
                }
                _ => b.insert(i, b"{}[]\",:\\0e-"[(next() % 11) as usize]),
            }
        }
        let _ = firewall::analyze(Dialect::AnthropicMessages, &b, &[], &all, &CAT);
        let _ = firewall::analyze(Dialect::OpenAiChat, &b, &[], &all, &CAT);
    }
}

fn req<'a>(provider: Provider, dialect: Dialect, body: &'a str, p: &'a Policy, mp: Option<MaxPrice>) -> Request<'a> {
    Request {
        provider,
        dialect,
        body: body.as_bytes(),
        headers: &[],
        policy: p,
        catalog: &CAT,
        provider_model_id: "vendor-model-1",
        user_pseudonym: "ps_abc",
        max_price: mp,
    }
}

#[test]
fn safe_mutations() {
    let p = policy(Flags::NONE);
    let mp = Some(MaxPrice { prompt_uusd_per_mtok: 3_000_000, completion_uusd_per_mtok: 15_250_000 });
    let a = r#"{ "model" : "anthropic/x", "max_tokens":10, "metadata":{"user_id":"client"}, "messages":[{"role":"user","content":"hé\n"}] }"#;
    let out = firewall::prepare(&req(Provider::Anthropic, Dialect::AnthropicMessages, a, &p, None)).unwrap();
    assert_eq!(
        std::str::from_utf8(&out.body).unwrap(),
        r#"{"model":"vendor-model-1","max_tokens":10,"metadata":{"user_id":"ps_abc"},"messages":[{"role":"user","content":"hé\n"}]}"#
    );
    assert_eq!(out.headers, vec![("anthropic-version", "2023-06-01".to_owned())]);
    assert_eq!(out.facts.model, "anthropic/x");

    let o = r#"{"model":"openai/gpt-5","max_tokens":10,"stream":true,"store":true,"messages":[{"role":"user","content":"x"}]}"#;
    let out = firewall::prepare(&req(Provider::OpenAi, Dialect::OpenAiChat, o, &p, None)).unwrap();
    assert_eq!(
        std::str::from_utf8(&out.body).unwrap(),
        r#"{"model":"vendor-model-1","max_tokens":10,"stream":true,"store":false,"messages":[{"role":"user","content":"x"}],"stream_options":{"include_usage":true},"safety_identifier":"ps_abc"}"#
    );
    assert!(out.headers.is_empty());

    let out = firewall::prepare(&req(Provider::OpenRouter, Dialect::OpenAiChat, o, &p, mp)).unwrap();
    assert_eq!(
        std::str::from_utf8(&out.body).unwrap(),
        r#"{"model":"vendor-model-1","max_tokens":10,"stream":true,"store":true,"messages":[{"role":"user","content":"x"}],"stream_options":{"include_usage":true},"user":"ps_abc","usage":{"include":true},"provider":{"max_price":{"prompt":3,"completion":15.25},"allow_fallbacks":false}}"#
    );
    let out = firewall::prepare(&req(Provider::OpenRouter, Dialect::AnthropicMessages, a, &p, mp)).unwrap();
    assert!(std::str::from_utf8(&out.body).unwrap().ends_with(r#""provider":{"max_price":{"prompt":3,"completion":15.25},"allow_fallbacks":false}}"#));
    let out = firewall::prepare(&req(Provider::DeepSeek, Dialect::OpenAiChat, o, &p, None)).unwrap();
    assert_eq!(
        std::str::from_utf8(&out.body).unwrap(),
        r#"{"model":"vendor-model-1","max_tokens":10,"stream":true,"store":true,"messages":[{"role":"user","content":"x"}],"stream_options":{"include_usage":true}}"#
    );

    let e = firewall::prepare(&req(Provider::OpenRouter, Dialect::OpenAiChat, o, &p, None)).unwrap_err();
    assert_eq!(e.code.nack(), ("model_unavailable", true));
    let e = firewall::prepare(&req(Provider::Anthropic, Dialect::OpenAiChat, o, &p, None)).unwrap_err();
    assert_eq!(e.code, RejectCode::Unsupported);
    let e = firewall::prepare(&req(Provider::Anthropic, Dialect::AnthropicMessages, r#"{"mcp_servers":[]}"#, &p, None)).unwrap_err();
    assert_eq!(e.code.nack(), ("firewall", false));
}

#[test]
fn route_check() {
    let f = analyze(Dialect::AnthropicMessages, CLAUDE_CODE_LIKE, &[], policy(Flags::NONE)).unwrap();
    let aliases = ["anthropic/claude-sonnet-5.5", "claude-sonnet-5-5"];
    let good = Route {
        dialect: Dialect::AnthropicMessages,
        model_aliases: &aliases,
        effort: Effort::Medium,
        max_tokens: 32_000,
        est_input_tokens: f.est_input_tokens,
        cache_ttl: CacheTtl::H1,
        stream: true,
        flags: Flags::NONE,
    };
    f.check_route(Dialect::AnthropicMessages, &good).unwrap();
    let other = ["anthropic/claude-haiku-4.5"];
    for (r, field) in [
        (Route { dialect: Dialect::OpenAiChat, ..good }, "route.dialect"),
        (Route { model_aliases: &other, ..good }, "route.model"),
        (Route { effort: Effort::Low, ..good }, "route.effort"),
        (Route { max_tokens: 1, ..good }, "route.max_tokens"),
        (Route { est_input_tokens: 1, ..good }, "route.est_input_tokens"),
        (Route { cache_ttl: CacheTtl::M5, ..good }, "route.cache_ttl"),
        (Route { stream: false, ..good }, "route.stream"),
        (Route { flags: Flags::IMAGES, ..good }, "route.flags"),
    ] {
        let e = f.check_route(Dialect::AnthropicMessages, &r).unwrap_err();
        assert_eq!((e.code, e.path.as_str()), (RejectCode::RouteMismatch, field));
        assert_eq!(e.code.nack(), ("route_mismatch", false));
    }
}

/// CONTRACT §13 (Assign → Ack ≤ 1 ms): firewall + facts + mutations on a ~100 KB agent body.
#[test]
fn prepare_latency_100kb() {
    let turn = r#",{"role":"assistant","content":[{"type":"text","text":"Reading the file now."},{"type":"tool_use","id":"toolu_x","name":"Bash","input":{"command":"cat src/main.rs"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_x","content":"fn main() {\n    println!(\"hello\");\n}\n// padding padding padding padding padding padding padding padding padding padding"}]}"#;
    let body = CLAUDE_CODE_LIKE.replacen(
        r#"{"role":"user","content":[{"type":"text","text":"list files"}]}"#,
        &format!(r#"{{"role":"user","content":[{{"type":"text","text":"list files"}}]}}{}"#, turn.repeat(100_000 / turn.len())),
        1,
    );
    assert!(body.len() > 95_000);
    let p = policy(Flags::NONE);
    let r = req(Provider::Anthropic, Dialect::AnthropicMessages, &body, &p, None);
    let mut best = std::time::Duration::MAX;
    for _ in 0..50 {
        let t = std::time::Instant::now();
        let out = firewall::prepare(&r).unwrap();
        best = best.min(t.elapsed());
        assert!(out.body.len() > 90_000);
    }
    println!("prepare({} B): best {best:?}", body.len());
    if !cfg!(debug_assertions) {
        assert!(best < std::time::Duration::from_millis(1));
    }
}

/// xAI (Grok): OpenAI-compatible chat only; live search, deferred, server-side tools,
/// file references, URL images and undocumented fields refused.
#[test]
fn xai_adapter_rules() {
    let p = policy(Flags::IMAGES);
    let x = |body: &str| firewall::prepare(&req(Provider::XAi, Dialect::OpenAiChat, body, &p, None));
    let ok = r#"{"model":"xai/grok-4.7","max_completion_tokens":256,"stream":true,"reasoning_effort":"low","prompt_cache_key":"conv-1","messages":[{"role":"system","content":"s"},{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA","detail":"high"}}]}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}]}"#;
    let out = x(ok).unwrap();
    let body = std::str::from_utf8(&out.body).unwrap();
    assert!(body.contains(r#""model":"vendor-model-1""#) && body.contains(r#""stream_options":{"include_usage":true}"#));
    assert!(body.contains(r#""safety_identifier":"ps_abc""#) && !body.contains("store"), "{body}");
    for (extra, path, reason) in [
        (r#","search_parameters":{"mode":"on"}"#, "search_parameters", "live search"),
        (r#","web_search_options":{"search_context_size":"high"}"#, "web_search_options", "web search"),
        (r#","deferred":true"#, "deferred", "deferred"),
        (r#","service_tier":"priority""#, "service_tier", "donor's call"),
        (r#","n":2"#, "n", "multiplies output"),
        (r#","tools":[{"type":"web_search"}]"#, "tools[0].type", "hosted tools"),
        (r#","tools":[{"type":"x_search"}]"#, "tools[0].type", "not allowed"),
        (r#","tools":[{"type":"code_execution"}]"#, "tools[0].type", "not allowed"),
        (r#","tools":[{"type":"mcp","server_url":"https://x"}]"#, "tools[0].type", "MCP"),
        (r#","store":false"#, "store", "xAI"),
        (r#","logit_bias":{"1":1}"#, "logit_bias", "xAI"),
        (r#","verbosity":"low""#, "verbosity", "xAI"),
    ] {
        let e = x(&oai(r#""hi""#, extra)).expect_err(extra);
        assert_eq!(e.code, RejectCode::Firewall);
        assert!(e.path.ends_with(path) && e.to_string().contains(reason), "{extra}: {e}");
    }
    for content in [
        r#"[{"type":"image_url","image_url":{"url":"https://x/y.png"}}]"#,
        r#"[{"type":"input_file","file_url":"https://x/doc.pdf"}]"#,
        r#"[{"type":"input_file","file_id":"file-abc"}]"#,
        r#"[{"type":"file","file":{"file_id":"file-abc"}}]"#,
    ] {
        assert!(x(&oai(content, "")).is_err(), "{content}");
    }
    // No Anthropic-compatible endpoint: not served, retry elsewhere.
    let e = firewall::prepare(&req(Provider::XAi, Dialect::AnthropicMessages, &anth(r#""hi""#, ""), &p, None)).unwrap_err();
    assert_eq!(e.code.nack(), ("model_unavailable", true));
}

fn pdf_b64(pages: usize) -> String {
    use base64::Engine as _;
    let mut pdf = String::from("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n");
    pdf.push_str(&format!("2 0 obj << /Type /Pages /Count {pages} >> endobj\n"));
    for i in 0..pages {
        pdf.push_str(&format!("{} 0 obj << /Type /Page /Parent 2 0 R >> endobj\n", i + 3));
    }
    pdf.push_str("%%EOF");
    base64::engine::general_purpose::STANDARD.encode(pdf)
}

/// CONTRACT R3: PDFs need the `documents` flag, ≤ 100 pages; pages × max_page_tokens in the estimate.
#[test]
fn r3_pdf_documents() {
    let doc = |b64: &str| format!(r#"[{{"type":"document","source":{{"type":"base64","media_type":"application/pdf","data":"{b64}"}}}}]"#);
    let docs = policy(Flags::DOCUMENTS);
    let body = anth(&doc(&pdf_b64(3)), "");
    let f = analyze(Dialect::AnthropicMessages, &body, &[], docs).unwrap();
    assert_eq!((f.pages, f.flags), (3, Flags::DOCUMENTS));
    assert_eq!(f.text_bytes, body.len() as u64 - pdf_b64(3).len() as u64, "PDF bytes are not text");
    assert_eq!(f.est_input_tokens, f.text_bytes.div_ceil(3) + 3 * 3000);
    // Nested in a tool_result: counted the same way, across documents.
    let nested = anth(&format!(r#"[{{"type":"tool_result","tool_use_id":"t","content":{}}}]"#, doc(&pdf_b64(98))), "");
    let two = nested.replacen("\"content\":[{\"role\"", "x", 0);
    assert_eq!(analyze(Dialect::AnthropicMessages, &two, &[], docs).unwrap().pages, 98);
    let over = anth(&format!(r#"[{}, {}]"#, &doc(&pdf_b64(60))[1..doc(&pdf_b64(60)).len() - 1], &doc(&pdf_b64(41))[1..doc(&pdf_b64(41)).len() - 1]), "");
    assert!(analyze(Dialect::AnthropicMessages, &over, &[], docs).unwrap_err().to_string().contains("100 pages"));
    // Refusals: no flag, paranoid, not base64, not a PDF, uncountable, wrong media type.
    assert!(analyze(Dialect::AnthropicMessages, &body, &[], policy(Flags::NONE)).unwrap_err().to_string().contains("`documents` opt-in"));
    assert!(analyze(Dialect::AnthropicMessages, &body, &[], Policy { level: Level::Paranoid, ..docs }).is_err());
    assert!(analyze(Dialect::AnthropicMessages, &anth(&doc("not base64!"), ""), &[], docs).unwrap_err().to_string().contains("base64"));
    use base64::Engine as _;
    let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    assert!(analyze(Dialect::AnthropicMessages, &anth(&doc(&enc(b"hello")), ""), &[], docs).is_err());
    assert!(analyze(Dialect::AnthropicMessages, &anth(&doc(&enc(b"%PDF-1.7 << /Type /ObjStm >>")), ""), &[], docs).is_err());
    let png = anth(&doc(&pdf_b64(1)).replace("application/pdf", "image/png"), "");
    assert!(analyze(Dialect::AnthropicMessages, &png, &[], docs).is_err());
    // The Gateway (PERMISSIVE) and the Worker compute the same facts.
    assert_eq!(firewall::analyze(Dialect::AnthropicMessages, body.as_bytes(), &[], &Policy::PERMISSIVE, &CAT).unwrap(), f);
}

/// T-07-087: recorded real-client corpus (Claude Code 2.1.287 against a local recorder;
/// structure kept, prose and local data redacted to same-length placeholders).
#[test]
fn recorded_claude_code_corpus() {
    let cat = Catalog { default_effort: Effort::High, max_output: 128_000, max_image_tokens: 1600, max_page_tokens: 3000 };
    let all = policy(Flags::NONE);
    for (name, body, hdrs) in [
        ("first-turn", &include_bytes!("fixtures/clients/claude-code-2.1.287-first-turn.json")[..], &include_bytes!("fixtures/clients/claude-code-2.1.287-first-turn.headers.json")[..]),
        ("tool-turn1", include_bytes!("fixtures/clients/claude-code-2.1.287-tool-turn1.json"), include_bytes!("fixtures/clients/claude-code-2.1.287-tool-turn1.headers.json")),
        ("tool-turn2", include_bytes!("fixtures/clients/claude-code-2.1.287-tool-turn2.json"), include_bytes!("fixtures/clients/claude-code-2.1.287-tool-turn2.headers.json")),
    ] {
        let mut tape = Vec::new();
        let h = moochy_worker::json::parse(hdrs, &mut tape).unwrap().root();
        let headers: Vec<(String, String)> =
            h.entries().filter(|(k, _)| !k.is_str("_path")).map(|(k, v)| (k.as_str().unwrap().into_owned(), v.as_str().unwrap().into_owned())).collect();
        let hs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        // As sent by Claude Code: refused only for the classifier and unvetted betas/headers.
        let raw = firewall::analyze(Dialect::AnthropicMessages, body, &hs, &all, &cat).unwrap_err();
        assert!(raw.path == "safeguards" || raw.path.starts_with("header"), "{name}: {raw}");
        // Gateway normalisation: accepted by the Worker's firewall.
        let pooled = firewall::pool_compatible(Dialect::AnthropicMessages, body, &hs).unwrap();
        assert!(pooled.stripped.iter().any(|s| s.contains("dangerous-tool-use")), "{name}: {:?}", pooled.stripped);
        assert!(pooled.stripped.iter().any(|s| s == "header anthropic-dangerous-direct-browser-access"));
        assert_eq!(pooled.stripped.iter().any(|s| s == "safeguards"), name != "tool-turn2", "{name}");
        let ph: Vec<(&str, &str)> = pooled.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let f = firewall::analyze(Dialect::AnthropicMessages, &pooled.body, &ph, &all, &cat).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((f.max_tokens, f.effort, f.stream), (128_000, Effort::Medium, true), "{name}");
        for p in [Provider::Anthropic, Provider::OpenRouter, Provider::DeepSeek] {
            let r = Request {
                provider: p,
                dialect: Dialect::AnthropicMessages,
                body: &pooled.body,
                headers: &ph,
                policy: &all,
                catalog: &cat,
                provider_model_id: "claude-sonnet-5-5",
                user_pseudonym: "ps_1",
                max_price: Some(MaxPrice { prompt_uusd_per_mtok: 3_000_000, completion_uusd_per_mtok: 15_000_000 }),
            };
            let out = firewall::prepare(&r).unwrap_or_else(|e| panic!("{name} via {p:?}: {e}"));
            assert!(!std::str::from_utf8(&out.body).unwrap().contains("safeguards"));
        }
    }
    // Per-turn effort raises the effective effort (cost bound) and is checked against the pledge.
    let b = br#"{"model":"m","max_tokens":10,"output_config":{"effort":"low"},"messages":[{"role":"user","content":"x"},{"role":"system","content":"y","output_config":{"effort":"high"}}]}"#;
    assert_eq!(firewall::analyze(Dialect::AnthropicMessages, b, &[], &all, &CAT).unwrap().effort, Effort::High);
    let low = Policy { max_effort: Effort::Medium, ..all };
    assert!(firewall::analyze(Dialect::AnthropicMessages, b, &[], &low, &CAT).unwrap_err().to_string().contains("exceeds"));
    // System turns are text only.
    let img = br#"{"model":"m","max_tokens":10,"messages":[{"role":"system","content":[{"type":"tool_use","id":"t","name":"x","input":{}}]}]}"#;
    assert!(firewall::analyze(Dialect::AnthropicMessages, img, &[], &all, &CAT).is_err());
    // Context editing: only the content-removing edits.
    let ctx = |t: &str| format!(r#"{{"model":"m","max_tokens":10,"messages":[],"context_management":{{"edits":[{{"type":"{t}"}}]}}}}"#);
    assert!(firewall::analyze(Dialect::AnthropicMessages, ctx("clear_thinking_20251015").as_bytes(), &[], &all, &CAT).is_ok());
    assert!(firewall::analyze(Dialect::AnthropicMessages, ctx("clear_tool_uses_20250919").as_bytes(), &[], &all, &CAT).is_ok());
    assert!(firewall::analyze(Dialect::AnthropicMessages, ctx("compact_20260101").as_bytes(), &[], &all, &CAT).is_err());
}

/// CONTRACT §13 row 1: the E22 100 KB request (one long prompt string) through `analyze`
/// (Gateway) and `prepare` (Worker). Release builds assert a floor; debug builds only print.
#[test]
fn request_throughput() {
    let prompt = "The quick brown fox jumps over the lazy dog. ".repeat(2300);
    let body = anth(&format!("{prompt:?}"), r#","stream":true"#);
    let p = policy(Flags::NONE);
    let release = !cfg!(debug_assertions);
    let n = if release { 2000 } else { 20 };
    let t = std::time::Instant::now();
    for _ in 0..n {
        analyze(Dialect::AnthropicMessages, &body, &[], p).unwrap();
    }
    let an = t.elapsed() / n;
    let req = Request {
        provider: Provider::Anthropic,
        dialect: Dialect::AnthropicMessages,
        body: body.as_bytes(),
        headers: &[],
        policy: &p,
        catalog: &CAT,
        provider_model_id: "claude-sonnet-5-5",
        user_pseudonym: "ps_1",
        max_price: None,
    };
    let t = std::time::Instant::now();
    for _ in 0..n {
        firewall::prepare(&req).unwrap();
    }
    let pr = t.elapsed() / n;
    let mbs = |d: std::time::Duration| body.len() as f64 / d.as_secs_f64() / 1e6;
    println!("{} B request: analyze {an:?} ({:.0} MB/s), prepare {pr:?} ({:.0} MB/s)", body.len(), mbs(an), mbs(pr));
    if release {
        assert!(an < std::time::Duration::from_micros(60) && pr < std::time::Duration::from_micros(80), "100 KB request too slow");
    }
}
