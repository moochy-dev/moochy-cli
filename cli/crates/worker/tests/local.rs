//! Local inference servers (Ollama, llama.cpp; LM Studio and vLLM by their documented shape):
//! recorded fixtures, host vetting, firewall rules, re-emission, and an opt-in live test.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, clippy::too_many_lines)]

use moochy_worker::firewall::{self, Catalog, Level, Policy, RejectCode, Request};
use moochy_worker::provider::{self, Adapter, AdapterConfig, LocalHost, Limits};
use moochy_worker::stream::{Event, Outcome, StreamParser, Usage};
use moochy_worker::{Dialect, Effort, Flags, Provider, reemit};
use zeroize::Zeroizing;

const O: Dialect = Dialect::OpenAiChat;

fn parse(input: &[u8], stream: bool) -> (Outcome, Vec<String>) {
    let mut p = StreamParser::new(O, stream);
    let mut ev = Vec::new();
    for c in input.chunks(37) {
        p.feed(c, &mut |_, e| match e {
            Event::ToolStart { index, name, .. } => ev.push(format!("start {index} {}", name.and_then(moochy_worker::json::Val::as_str).unwrap())),
            Event::ToolArgs { json, .. } => ev.push(format!("args {}", json.as_str().unwrap())),
            Event::ToolEnd { index } => ev.push(format!("end {index}")),
            Event::Invalid => ev.push("INVALID".into()),
            _ => {}
        })
        .unwrap();
    }
    (p.finish(), ev)
}

fn u(input: u64, output: u64, cache_read: u64) -> Usage {
    Usage { input, output, cache_read, ..Usage::default() }
}

#[test]
fn recorded_usage_per_server() {
    for (name, body, stream, want) in [
        ("ollama_stream_text_usage", &include_bytes!("fixtures/local/ollama_stream_text_usage.sse")[..], true, u(35, 7, 0)),
        ("ollama_stream_tool", include_bytes!("fixtures/local/ollama_stream_tool.sse"), true, u(137, 20, 18)),
        ("ollama_stream_length", include_bytes!("fixtures/local/ollama_stream_length.sse"), true, u(14, 8, 24)),
        ("ollama_body_text", include_bytes!("fixtures/local/ollama_body_text.json"), false, u(1, 7, 34)),
        ("ollama_body_tool", include_bytes!("fixtures/local/ollama_body_tool.json"), false, u(1, 20, 154)),
        ("ollama_reasoning_stream", include_bytes!("fixtures/local/ollama_reasoning_stream.sse"), true, u(19, 300, 0)),
        ("ollama_reasoning_body", include_bytes!("fixtures/local/ollama_reasoning_body.json"), false, u(1, 300, 18)),
        ("llamacpp_stream_text_usage", include_bytes!("fixtures/local/llamacpp_stream_text_usage.sse"), true, u(35, 7, 0)),
        ("llamacpp_stream_tool", include_bytes!("fixtures/local/llamacpp_stream_tool.sse"), true, u(158, 20, 18)),
        ("llamacpp_stream_length", include_bytes!("fixtures/local/llamacpp_stream_length.sse"), true, u(14, 8, 24)),
        ("llamacpp_body_text", include_bytes!("fixtures/local/llamacpp_body_text.json"), false, u(1, 7, 34)),
        ("llamacpp_body_tool", include_bytes!("fixtures/local/llamacpp_body_tool.json"), false, u(1, 20, 175)),
        ("llamacpp_reasoning_stream", include_bytes!("fixtures/local/llamacpp_reasoning_stream.sse"), true, u(17, 300, 0)),
        ("llamacpp_reasoning_body", include_bytes!("fixtures/local/llamacpp_reasoning_body.json"), false, u(1, 300, 16)),
        // No usage object: llama.cpp's cumulative `timings` give the exact counts.
        ("llamacpp_stream_text_nousage", include_bytes!("fixtures/local/llamacpp_stream_text_nousage.sse"), true, u(1, 7, 34)),
    ] {
        let (o, ev) = parse(body, stream);
        assert_eq!(o.usage, want, "{name}");
        assert!(o.complete && !o.malformed && !ev.contains(&"INVALID".to_owned()), "{name}: {o:?}");
    }
    // Ollama without include_usage sends neither usage nor timings: conservative estimate, flagged.
    let (o, _) = parse(include_bytes!("fixtures/local/ollama_stream_text_nousage.sse"), true);
    assert!(o.usage.estimated && o.usage.output >= 1, "{o:?}");
}

#[test]
fn recorded_tool_calls() {
    let (_, ev) = parse(include_bytes!("fixtures/local/ollama_stream_tool.sse"), true);
    assert_eq!(ev, ["start 0 get_weather", "args {\"city\":\"Paris\"}", "end 0"]);
    let (_, ev) = parse(include_bytes!("fixtures/local/llamacpp_stream_tool.sse"), true);
    assert_eq!(ev.first().unwrap(), "start 0 get_weather");
    assert_eq!(ev.last().unwrap(), "end 0");
    let args: String = ev.iter().filter_map(|e| e.strip_prefix("args ")).collect();
    assert_eq!(args, "{\"city\": \"Paris\"}");
    for (name, body) in [
        ("ollama", &include_bytes!("fixtures/local/ollama_body_tool.json")[..]),
        ("llamacpp", include_bytes!("fixtures/local/llamacpp_body_tool.json")),
    ] {
        let calls = moochy_worker::inspect::response_tool_calls(O, body).unwrap();
        assert_eq!(calls.len(), 1, "{name}");
        assert_eq!(calls[0].0, "get_weather");
    }
}

/// Every recorded local response re-emits canonically with the same semantics.
#[test]
fn recorded_reemission_is_lossless() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let stream = std::path::Path::new(&name).extension().is_some_and(|x| x.eq_ignore_ascii_case("sse"));
        if !stream && !std::path::Path::new(&name).extension().is_some_and(|x| x.eq_ignore_ascii_case("json")) {
            continue;
        }
        let b = std::fs::read(&p).unwrap();
        let out = reemit::reemit(O, stream, &b).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (a, ea) = parse(&b, stream);
        let (z, ez) = parse(&out, stream);
        assert_eq!((a.usage, a.model, a.complete), (z.usage, z.model, z.complete), "{name}");
        assert_eq!(ea, ez, "{name}");
        n += 1;
    }
    assert_eq!(n, 16);
}

#[test]
fn host_vetting() {
    use LocalHost::{Lan, Loopback, Unvetted};
    for (url, want) in [
        ("http://127.0.0.1:11434", Ok(Loopback)),
        ("http://127.1.2.3:1234/", Ok(Loopback)),
        ("http://[::1]:8000", Ok(Loopback)),
        ("http://192.168.1.20:11434", Ok(Lan)),
        ("http://10.0.0.5:8080", Ok(Lan)),
        ("http://172.16.4.2:1234", Ok(Lan)),
        ("http://100.101.102.103:11434", Ok(Lan)), // Tailscale / CGNAT
        ("http://[fd12:3456::1]:8000", Ok(Lan)),
        ("http://[::ffff:192.168.1.20]:11434", Ok(Lan)),
    ] {
        assert_eq!(provider::check_local_base_url(url, false).map_err(|e| e.0), want, "{url}");
    }
    for url in [
        "http://169.254.169.254",        // cloud metadata
        "http://[fe80::1]:11434",        // link-local
        "http://0.0.0.0:11434",          // unspecified
        "http://224.0.0.1:1234",         // multicast
        "http://255.255.255.255",        // broadcast
        "http://[::ffff:169.254.169.254]", // mapped metadata
        "http://8.8.8.8:11434",          // public
        "http://gpu-box.local:11434",    // host name (DNS rebinding)
        "http://localhost:11434",        // host name
        "http://127.0.0.1:11434/v1",     // path
        "http://127.0.0.1:0",            // port 0
        "ftp://127.0.0.1",
        "http://user@127.0.0.1",
    ] {
        assert!(provider::check_local_base_url(url, false).is_err(), "{url}");
    }
    // --allow-unvetted-host (dev): public IPs and names over https (§17.3: plain HTTP off the
    // LAN is refused even in dev), never metadata/link-local.
    assert!(provider::check_local_base_url("http://gpu-box.local:11434", true).is_err());
    assert_eq!(provider::check_local_base_url("https://gpu-box.local:11434", true).map_err(|e| e.0), Ok(Unvetted));
    assert_eq!(provider::check_local_base_url("https://203.0.113.9:8000", true).map_err(|e| e.0), Ok(Unvetted));
    assert!(provider::check_local_base_url("http://169.254.169.254", true).is_err());
    assert!(provider::check_local_base_url("http://evil_host:1", true).is_err());
}

#[test]
fn adapter_rules() {
    let cfg = |base: Option<&str>, key: &str| AdapterConfig {
        provider: Provider::Local,
        api_key: Zeroizing::new(key.into()),
        base_url: base.map(str::to_owned),
        insecure_dev: false,
        dev_root: None,
        limits: Limits::local(),
    };
    assert!(Adapter::new(&cfg(Some("http://127.0.0.1:11434"), "")).is_ok(), "no key, no insecure_dev needed");
    assert!(Adapter::new(&cfg(Some("http://192.168.1.20:1234"), "lm-studio")).is_ok());
    assert!(Adapter::new(&cfg(None, "")).is_err(), "base URL required");
    assert!(Adapter::new(&cfg(Some("http://gpu-box.local:11434"), "")).is_err());
    assert!(Adapter::new_local(&cfg(Some("http://gpu-box.local:11434"), ""), true).is_err(), "plain HTTP off the LAN");
    assert!(Adapter::new_local(&cfg(Some("https://gpu-box.local:11434"), ""), true).is_ok());
    assert!(Provider::Local.serves(O) && !Provider::Local.serves(Dialect::AnthropicMessages));
    assert!(Limits::local().headers > Limits::default().headers);
}

const CAT: Catalog = Catalog { default_effort: Effort::None, max_output: 8192, max_image_tokens: 0, max_page_tokens: 0 };
const POL: Policy = Policy { level: Level::Strict, flags: Flags::NONE, max_effort: Effort::Max };

fn prep(body: &str, model: &str) -> Result<firewall::Prepared, firewall::Reject> {
    firewall::prepare(&Request {
        provider: Provider::Local,
        dialect: O,
        body: body.as_bytes(),
        headers: &[],
        policy: &POL,
        catalog: &CAT,
        provider_model_id: model,
        user_pseudonym: "ps_1",
        max_price: None,
    })
}

#[test]
fn firewall_rules() {
    let b = r#"{"model":"local/qwen2.5-0.5b","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let out = prep(b, "qwen2.5:0.5b").unwrap();
    assert_eq!(
        std::str::from_utf8(&out.body).unwrap(),
        r#"{"model":"qwen2.5:0.5b","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}],"stream_options":{"include_usage":true}}"#,
        "model mapping + usage forced, nothing else (no end-user id)"
    );
    for model in ["gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", "deepseek-v3.1:cloud", "kimi-k2-cloud"] {
        let e = prep(b, model).unwrap_err();
        assert_eq!(e.code, RejectCode::Unsupported, "{model}");
        assert!(e.to_string().contains("cloud"));
    }
    for (extra, path) in [
        (r#","store":true"#, "store"),
        (r#","verbosity":"low""#, "verbosity"),
        (r#","web_search_options":{}"#, "web_search_options"),
        (r#","chat_template_kwargs":{"enable_thinking":true}"#, "chat_template_kwargs"),
        (r#","tools":[{"type":"web_search"}]"#, "tools[0].type"),
    ] {
        let e = prep(&b.replacen("]}", &format!("]{extra}}}"), 1), "qwen2.5:0.5b").unwrap_err();
        assert!(e.path.ends_with(path), "{extra}: {e}");
    }
}

/// Opt-in: real servers. `MOOCHY_LOCAL_SERVERS="ollama=http://127.0.0.1:21434=qwen2.5:0.5b;…"`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MOOCHY_LOCAL_SERVERS (running Ollama / llama.cpp servers)"]
async fn live_local_servers() {
    let spec = std::env::var("MOOCHY_LOCAL_SERVERS").unwrap();
    for entry in spec.split(';').filter(|e| !e.is_empty()) {
        let mut it = entry.splitn(3, '=');
        let (name, url, model) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
        let a = Adapter::new(&AdapterConfig {
            provider: Provider::Local,
            api_key: Zeroizing::new(String::new()),
            base_url: Some(url.into()),
            insecure_dev: false,
            dev_root: None,
            limits: Limits::local(),
        })
        .unwrap();
        a.warm().await.unwrap();
        for (body, tool) in [
            (r#"{"model":"local/m","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"Say hi."}]}"#, false),
            (
                r#"{"model":"local/m","max_tokens":80,"stream":true,"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}],"messages":[{"role":"user","content":"What is the weather in Paris? Use the tool."}]}"#,
                true,
            ),
        ] {
            let p = prep(body, model).unwrap();
            let mut r = a.send(O, p.body, &p.headers).await.unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut parser = StreamParser::new(O, true);
            let mut ev = Vec::new();
            let mut canon = reemit::Reemitter::new(O, true);
            let mut out = Vec::new();
            while let Some(c) = r.next().await.unwrap() {
                parser
                    .feed(&c, &mut |_, e| {
                        if let Event::ToolEnd { .. } = e {
                            ev.push("end");
                        }
                    })
                    .unwrap();
                canon.push(&c, &mut out).unwrap_or_else(|e| panic!("{name}: reemit {e}"));
            }
            canon.finish(&mut out).unwrap();
            let o = parser.finish();
            assert!(o.complete && !o.malformed && !o.usage.estimated && o.usage.output > 0, "{name}: {o:?}");
            if tool {
                assert_eq!(ev, ["end"], "{name}: one tool call");
            }
            println!("{name} tool={tool}: {:?} model={:?}", o.usage, o.model);
        }
    }
}
