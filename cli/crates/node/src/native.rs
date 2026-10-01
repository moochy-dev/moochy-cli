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
    match f.code.as_str() {
        "over_task_cap" => "moochy: this request's worst-case cost exceeds the donors' per-task cap".into(),
        "quota_exceeded" => "moochy: this repo's member quota or pool budget is exhausted".into(),
        "firewall" => "moochy: request refused by the donor pool's firewall".into(),
        "route_mismatch" => "moochy: route header does not match the request body".into(),
        "rate_limited" => "moochy: donor rate limited, retry later".into(),
        "bad_envelope" => "moochy: response failed authentication (possible tampering); retry".into(),
        code => format!("moochy: {code}"),
    }
}

/// Status + JSON body in the dialect's shape.
pub fn error_body(d: Dialect, f: &Failure) -> (u16, Value) {
    let (status, ty) = classify(f);
    let msg = message(f);
    let body = match d {
        Dialect::Anthropic => json!({"type":"error","error":{"type":ty,"message":msg}}),
        Dialect::OpenAi => {
            let oty = if status >= 500 { "server_error" } else { ty };
            // OpenAI has no 529.
            json!({"error":{"message":msg,"type":oty,"param":null,"code":f.code}})
        }
    };
    let status = if d == Dialect::OpenAi && status == 529 { 503 } else { status };
    (status, body)
}

/// Mid-stream error event (after headers were sent).
pub fn sse_error(d: Dialect, f: &Failure) -> Bytes {
    let (_, body) = error_body(d, f);
    Bytes::from(match d {
        Dialect::Anthropic => format!("event: error\ndata: {body}\n\n"),
        Dialect::OpenAi => format!("data: {body}\n\n"),
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
        assert!(b["error"]["message"].as_str().unwrap().contains("per-task cap"));
        assert!(sse_error(Dialect::Anthropic, &f("overloaded", true)).starts_with(b"event: error\n"));
    }
}
