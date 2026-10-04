//! Failures → provider-native error shapes (03 §10.3).

use crate::engine::{Dialect, Failure};
use bytes::Bytes;
use serde_json::{Value, json};

/// `(HTTP status, Anthropic error type)` for a failure code.
pub fn classify(f: &Failure) -> (u16, &'static str) {
    match f.code.as_str() {
        "rate_limited" => (429, "rate_limit_error"),
        "firewall" | "route_mismatch" | "over_task_cap" | "invalid_request" => (400, "invalid_request_error"),
        "unauthorized" => (401, "authentication_error"),
        "quota_exceeded" | "forbidden" => (403, "permission_error"),
        "model_not_in_pool" | "not_found" => (404, "not_found_error"),
        "too_large" => (413, "request_too_large"),
        "bad_envelope" | "unauthorized_task" | "internal" | "not_wired" | "not_logged_in" => (500, "api_error"),
        _ if f.retryable => (529, "overloaded_error"),
        _ => (400, "invalid_request_error"),
    }
}

fn message(f: &Failure) -> String {
    if let Some(d) = &f.detail {
        return d.clone();
    }
    // Plain words first (docs/brand/VOICE.md), then the machine code for agents and scripts.
    let text = match f.code.as_str() {
        "over_task_cap" => "this request could cost more than the donors' limit per request; lower max_tokens",
        // M5: also refused before anything is spent: the request reserves what max_tokens could
        // cost, which can be more than a limit has left (the relay names no limit, 03 §10.3).
        "quota_exceeded" => "this request could cost more than what is left of a monthly, weekly or daily limit (yours for this project, or a donation's): lower max_tokens, or wait for the limit to start again",
        "model_not_in_pool" => "no donor serves this model to this project right now (its donations may be paused, waiting for approval, or at their limit); `moochy status` lists the models",
        "firewall" => "request refused by the safety checks",
        "route_mismatch" => "the route header does not match the request body",
        "rate_limited" => "the donor's provider is rate limited; retry later",
        "bad_envelope" => "the response failed authentication (possible tampering); retry",
        code => return format!("moochy: {code}{}", f.relay.as_deref().map(|r| format!(": the server says: {r}")).unwrap_or_default()),
    };
    match f.relay.as_deref() {
        Some(r) => format!("moochy: {text}; the server says: {r} ({})", f.code),
        None => format!("moochy: {text} ({})", f.code),
    }
}

/// The relay's own detail of a relay-side failure (protocol §15.3): UTF-8 text, at most about 300
/// characters, without control or invisible characters. `None` when empty or not UTF-8.
pub fn relay_detail(b: &[u8]) -> Option<Box<String>> {
    let s: String = std::str::from_utf8(b).ok()?.chars().filter(|c| !c.is_control()).take(300).collect();
    let s = crate::util::sanitize_text(s.trim()).into_owned();
    (!s.is_empty()).then(|| Box::new(s))
}

/// Status + JSON body in the dialect's shape.
pub fn error_body(d: Dialect, f: &Failure) -> (u16, Value) {
    let (status, ty) = classify(f);
    let msg = message(f);
    let body = match d {
        Dialect::Anthropic => json!({"type":"error","error":{"type":ty,"message":msg}}),
        Dialect::OpenAi | Dialect::OpenAiResponses => {
            let oty = if status >= 500 { "server_error" } else { ty };
            // OpenAI has no 529.
            json!({"error":{"message":msg,"type":oty,"param":f.param,"code":f.code}})
        }
    };
    let status = if d.is_openai() && status == 529 { 503 } else { status };
    (status, body)
}

/// Mid-stream error event (after headers were sent).
pub fn sse_error(d: Dialect, f: &Failure) -> Bytes {
    let (_, body) = error_body(d, f);
    Bytes::from(match d {
        Dialect::Anthropic => format!("event: error\ndata: {body}\n\n"),
        Dialect::OpenAi => format!("data: {body}\n\n"),
        // Responses streams: an `error` event (Codex reads `code` and `message`).
        Dialect::OpenAiResponses => {
            let e = body.get("error").cloned().unwrap_or_default();
            format!("event: error\ndata: {}\n\n", json!({"type":"error","code":e.get("code"),"message":e.get("message"),"param":e.get("param")}))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping() {
        let f = |c: &str, r: bool| Failure::new(c, r, None);
        assert_eq!(error_body(Dialect::Anthropic, &f("rate_limited", true)).0, 429);
        assert_eq!(error_body(Dialect::Anthropic, &f("overloaded", true)).0, 529);
        assert_eq!(error_body(Dialect::OpenAi, &f("overloaded", true)).0, 503);
        assert_eq!(error_body(Dialect::Anthropic, &f("firewall", false)).0, 400);
        assert_eq!(error_body(Dialect::Anthropic, &f("quota_exceeded", false)).0, 403);
        assert_eq!(error_body(Dialect::Anthropic, &f("model_not_in_pool", false)).0, 404);
        assert_eq!(error_body(Dialect::Anthropic, &f("bad_envelope", true)).0, 500);
        let (_, b) = error_body(Dialect::Anthropic, &f("over_task_cap", false));
        assert_eq!(b["error"]["type"], "invalid_request_error");
        assert!(b["error"]["message"].as_str().unwrap().contains("limit per request"));
        assert!(sse_error(Dialect::Anthropic, &f("overloaded", true)).starts_with(b"event: error\n"));
        let (_, b) = error_body(Dialect::OpenAi, &f("quota_exceeded", false));
        assert!(b["error"]["message"].as_str().unwrap().contains("could cost more than what is left"), "{b}");
        let (_, b) = error_body(Dialect::Anthropic, &f("model_not_in_pool", false));
        assert!(b["error"]["message"].as_str().unwrap().contains("paused"), "{b}");
        // Protocol §15.3: the relay's plain detail follows ours, cleaned and capped.
        let relay = relay_detail(b"a donation's daily limit is used up;\x1b[2J it starts again at 2026-10-05 00:00 UTC\n");
        assert_eq!(relay.as_deref().map(String::as_str), Some("a donation's daily limit is used up;[2J it starts again at 2026-10-05 00:00 UTC"));
        let q = Failure { relay, ..f("quota_exceeded", false) };
        let m = error_body(Dialect::Anthropic, &q).1["error"]["message"].as_str().unwrap().to_owned();
        assert!(m.contains("could cost more than what is left") && m.ends_with("starts again at 2026-10-05 00:00 UTC (quota_exceeded)"), "{m}");
        assert_eq!(relay_detail(&[b'x'; 2000]).map(|r| r.len()), Some(300));
        assert_eq!((relay_detail(b""), relay_detail(b"\xff\xfe")), (None, None), "empty or not UTF-8: nothing");
    }
}
