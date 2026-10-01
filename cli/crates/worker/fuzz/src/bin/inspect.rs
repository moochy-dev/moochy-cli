//! Tool-call inspection, text tripwire, terminal cleaning, PDF page counting and cost math on
//! arbitrary input. Invariants: no panic; clean_text is idempotent and leaves no controls.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::{Dialect, clean_text, firewall, inspect, stream};

const REQ: &[u8] = br#"{"tools":[{"name":"bash","type":"bash_20250124"},{"name":"edit","input_schema":{"type":"object","required":["p"],"properties":{"p":{"type":"string"},"n":{"type":"integer"},"e":{"enum":["a",1]},"x":{"anyOf":[{"type":"string"},{"type":"array","items":{"type":"number"}}]}},"additionalProperties":false}}]}"#;

fuzz_target!(|data: &[u8]| {
    let ts = inspect::ToolSet::from_request(Dialect::AnthropicMessages, REQ).expect("static request");
    let _ = ts.check_call("edit", data);
    let _ = ts.check_call("bash", data);
    let _ = inspect::response_tool_calls(Dialect::AnthropicMessages, data);
    let _ = inspect::response_tool_calls(Dialect::OpenAiChat, data);
    let _ = firewall::pdf_pages(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = inspect::scan_text(s);
        // Streaming text tripwire: the rules found over any split include the one-shot rule.
        let mut sc = inspect::TextScanner::new();
        let mid = (0..=s.len() / 2).rev().find(|i| s.is_char_boundary(*i)).unwrap_or(0);
        let _ = sc.push(&s[..mid]);
        let _ = sc.push(&s[mid..]);
        if s.len() <= 256 {
            if let Some(r) = inspect::scan_text(&s.replace('`', " ")) {
                assert!(sc.reported().contains(&r), "split text missed {r}");
            }
        }
        let c = clean_text(s);
        assert_eq!(clean_text(&c), c, "clean_text must be idempotent");
        assert!(!c.chars().any(|ch| matches!(ch, '\u{1b}' | '\u{7f}'..='\u{9f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')));
        if s.len() < 64 {
            let _ = stream::decimal_to_uusd_ceil(s);
        }
    }
});
