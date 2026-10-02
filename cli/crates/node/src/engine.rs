//! Glue between the doors and the protocol crates: the signed price catalog, Gateway-side route
//! facts (`moochy_worker::firewall::analyze` with `Policy::PERMISSIVE`, so the Worker's
//! recomputation matches bit for bit), the route header, sealed refusal details (CONTRACT §3
//! `moochy/v1/detail`), and the offline stub responses used by `up --offline`.

use crate::util::lp;
use bytes::Bytes;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use moochy_proto::money::CatalogEntry;
use moochy_proto::msg::{self, RouteHeader};
use moochy_worker::firewall::{self, Facts, Policy};
use moochy_worker::{Effort, Flags};
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Anthropic,
    OpenAi,
    /// OpenAI Responses (`POST /v1/responses`, Codex; CONTRACT §18.6, worker RESPONSES.md).
    OpenAiResponses,
}

impl Dialect {
    pub fn wire(self) -> &'static str {
        self.worker().as_str()
    }
    pub fn from_wire(s: &str) -> Option<Self> {
        match moochy_worker::Dialect::parse(s)? {
            moochy_worker::Dialect::AnthropicMessages => Some(Self::Anthropic),
            moochy_worker::Dialect::OpenAiChat => Some(Self::OpenAi),
            moochy_worker::Dialect::OpenAiResponses => Some(Self::OpenAiResponses),
        }
    }
    pub fn worker(self) -> moochy_worker::Dialect {
        match self {
            Self::Anthropic => moochy_worker::Dialect::AnthropicMessages,
            Self::OpenAi => moochy_worker::Dialect::OpenAiChat,
            Self::OpenAiResponses => moochy_worker::Dialect::OpenAiResponses,
        }
    }
    pub fn proto(self) -> msg::Dialect {
        match self {
            Self::Anthropic => msg::Dialect::AnthropicMessages,
            Self::OpenAi => msg::Dialect::OpenAiChat,
            Self::OpenAiResponses => msg::Dialect::OpenAiResponses,
        }
    }
    /// The OpenAI error and stream shapes (Chat Completions and Responses).
    pub fn is_openai(self) -> bool {
        matches!(self, Self::OpenAi | Self::OpenAiResponses)
    }
}

/// A failure as carried by `Failed` / `Nack` (03 §10.2), plus an unsealed detail.
#[derive(Clone, Debug)]
pub struct Failure {
    pub code: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    /// Human detail (already unsealed). Never logged: it may name fields of the request.
    pub detail: Option<String>,
    /// The request field a firewall refusal names (OpenAI's `error.param`). Boxed: `Failure`
    /// travels in `Result::Err` on hot paths (clippy::result_large_err).
    #[allow(clippy::box_collection)]
    pub param: Option<Box<String>>,
}

impl Failure {
    pub fn new(code: &str, retryable: bool, detail: impl Into<Option<String>>) -> Self {
        Self { code: code.into(), retryable, retry_after_ms: None, detail: detail.into(), param: None }
    }
}

// ------------------------------------------------------------------------------- catalog

pub const MAX_ENTRIES: usize = 10_000;

/// The price catalog pushed by the relay (`CatalogUpdate`). ponytail: relay-asserted until the
/// key log carries `CATALOG` entries (D14); then verify `sig` against the logged catalog key.
#[derive(Debug, Default)]
pub struct Catalog {
    pub version: u64,
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    /// Strict parse: duplicate keys etc. refused (CONTRACT §1), each entry `deny_unknown_fields`.
    /// Top-level fields other than `version` / `entries` (e.g. `effective_at`) are ignored.
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        let mut m = crate::json::parse_object(b)?;
        let version = m.get("version").and_then(Value::as_u64).filter(|v| *v > 0).ok_or("catalog: bad version")?;
        let Some(Value::Array(es)) = m.remove("entries") else { return Err("catalog: no entries".into()) };
        if es.len() > MAX_ENTRIES {
            return Err("catalog: too many entries".into());
        }
        let entries = es.into_iter().map(serde_json::from_value).collect::<Result<Vec<CatalogEntry>, _>>().map_err(|e| format!("catalog entry: {e}"))?;
        Ok(Self { version, entries })
    }

    /// Entry for a model as a client names it: public slug, provider model id, or alias.
    pub fn resolve(&self, model: &str) -> Option<&CatalogEntry> {
        self.entries
            .iter()
            .find(|e| e.model == model)
            .or_else(|| self.entries.iter().find(|e| e.provider_model_id == model || e.aliases.iter().any(|a| a == model)))
    }

    pub fn entry(&self, model: &str, provider: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.model == model && e.provider == provider)
    }

    /// Offline (`up --offline`) catalog: one stub model served in both dialects.
    pub fn stub() -> Arc<Self> {
        let e = CatalogEntry {
            model: STUB_MODEL.into(),
            provider: "anthropic".into(),
            provider_model_id: STUB_MODEL.into(),
            aliases: Vec::new(),
            dialects: vec![msg::Dialect::AnthropicMessages, msg::Dialect::OpenAiChat],
            input: 0,
            out: 0,
            cache_write_5m: 0,
            cache_write_1h: 0,
            cache_read: 0,
            max_image_tokens: 1600,
            max_page_tokens: 3000,
            fast_multiplier: 1,
            default_effort: "medium".into(),
            max_output: 64_000,
            source: "stub".into(),
        };
        Arc::new(Self { version: 1, entries: vec![e] })
    }
}

/// The firewall's view of a catalog entry; `None` when the entry is unusable (fail closed).
pub fn fw_catalog(e: &CatalogEntry) -> Option<firewall::Catalog> {
    Some(firewall::Catalog { default_effort: Effort::parse(&e.default_effort)?, max_output: e.max_output.into(), max_image_tokens: e.max_image_tokens, max_page_tokens: e.max_page_tokens })
}

pub fn cache_ttl(t: firewall::CacheTtl) -> msg::CacheTtl {
    match t {
        firewall::CacheTtl::None => msg::CacheTtl::None,
        firewall::CacheTtl::M5 => msg::CacheTtl::M5,
        firewall::CacheTtl::H1 => msg::CacheTtl::H1,
    }
}

pub fn cache_ttl_w(t: msg::CacheTtl) -> firewall::CacheTtl {
    match t {
        msg::CacheTtl::None => firewall::CacheTtl::None,
        msg::CacheTtl::M5 => firewall::CacheTtl::M5,
        msg::CacheTtl::H1 => firewall::CacheTtl::H1,
    }
}

/// Gateway route facts: the same `analyze` the Worker runs, gated only by the permissive policy.
pub fn analyze(e: &CatalogEntry, d: Dialect, body: &[u8], headers: &[(String, String)]) -> Result<Facts, Failure> {
    let cat = fw_catalog(e).ok_or_else(|| Failure::new("model_not_in_pool", false, format!("moochy: catalog entry for `{}` is unusable", e.model)))?;
    let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    firewall::analyze(d.worker(), body, &h, &Policy::PERMISSIVE, &cat).map_err(|r| Failure {
        param: (!r.path.is_empty()).then(|| Box::new(r.path.clone())),
        ..Failure::new("firewall", false, format!("moochy: {r} (refused before leaving this machine)"))
    })
}

/// Route header (03 §7.1) for a body analysed against catalog entry `e`.
pub fn route_header(e: &CatalogEntry, d: Dialect, f: &Facts, repo_id: &str, affinity: [u8; 16]) -> Result<RouteHeader, Failure> {
    let bad = |w: &str| Failure::new("invalid_request", false, format!("moochy: {w}"));
    Ok(RouteHeader {
        repo_id: repo_id.parse().map_err(|_| Failure::new("internal", true, "moochy: bad repo id from relay".to_owned()))?,
        dialect: d.proto(),
        model: e.model.clone(),
        effort: f.effort.as_str().into(),
        max_tokens: u32::try_from(f.max_tokens).map_err(|_| bad("max_tokens too large"))?,
        est_input_tokens: f.est_input_tokens,
        cache_ttl: cache_ttl(f.cache_ttl),
        stream: f.stream,
        affinity: moochy_proto::B(affinity),
        flags: f.flags.names().into_iter().map(str::to_owned).collect(),
    })
}

/// Route flags as the firewall's set (unknown names fail closed).
pub fn route_flags(r: &RouteHeader) -> Option<Flags> {
    Flags::parse(r.flags.iter().map(String::as_str)).ok()
}

// -------------------------------------------------------------------------- sealed detail

const LABEL_DETAIL: &[u8] = b"moochy/v1/detail";
pub const MAX_DETAIL: usize = 1024;

fn k_det(ck: &[u8; 32], r: &[u8; 32], task: &str, worker: &str, attempt: u32) -> Option<zeroize::Zeroizing<[u8; 32]>> {
    let info = lp(&[LABEL_DETAIL, task.as_bytes(), worker.as_bytes(), &u64::from(attempt).to_be_bytes()]);
    let mut k = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(r), ck).expand(&info, k.as_mut()).ok()?;
    Some(k)
}

fn det_aad(task16: &[u8; 16], attempt: u32, code: &str) -> Vec<u8> {
    lp(&[LABEL_DETAIL, task16, &u64::from(attempt).to_be_bytes(), code.as_bytes()])
}

/// Identifies one attempt for detail sealing.
pub struct DetailCtx<'a> {
    pub ck: &'a [u8; 32],
    pub r: &'a [u8; 32],
    pub task: &'a str,
    pub task16: &'a [u8; 16],
    pub worker: &'a str,
    pub attempt: u32,
}

/// `sealed_detail = AEAD(K_det, nonce = 0^12, aad = lp(label, task_id_16B, u64(attempt), code), detail ≤ 1 KiB)`.
pub fn seal_detail(c: &DetailCtx<'_>, code: &str, detail: &str) -> Vec<u8> {
    let mut end = detail.len().min(MAX_DETAIL);
    while !detail.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let Some(k) = k_det(c.ck, c.r, c.task, c.worker, c.attempt) else { return Vec::new() };
    let pt = detail.get(..end).unwrap_or_default().as_bytes();
    ChaCha20Poly1305::new(k.as_ref().into())
        .encrypt(&Nonce::default(), Payload { msg: pt, aad: &det_aad(c.task16, c.attempt, code) })
        .unwrap_or_default()
}

pub fn open_detail(c: &DetailCtx<'_>, code: &str, sealed: &[u8]) -> Option<String> {
    if sealed.is_empty() || sealed.len() > MAX_DETAIL.saturating_add(16) {
        return None;
    }
    let k = k_det(c.ck, c.r, c.task, c.worker, c.attempt)?;
    let pt = ChaCha20Poly1305::new(k.as_ref().into()).decrypt(&Nonce::default(), Payload { msg: sealed, aad: &det_aad(c.task16, c.attempt, code) }).ok()?;
    String::from_utf8(pt).ok().map(|s| crate::util::clean(&s).into_owned())
}

// ---------------------------------------------------------------------------- offline stub

pub const STUB_MODEL: &str = "moochy/stub";

/// Canned provider bytes for `up --offline` (smoke tests of the doors; no provider call).
pub fn stub_body(d: Dialect, stream: bool, model: &str, text: &str) -> Bytes {
    let s = match (d, stream) {
        (Dialect::Anthropic, false) => json!({"id":"msg_stub","type":"message","role":"assistant","model":model,
            "content":[{"type":"text","text":text}],"stop_reason":"end_turn","stop_sequence":null,
            "usage":{"input_tokens":1,"output_tokens":4}})
        .to_string(),
        (Dialect::Anthropic, true) => {
            let ev = |name: &str, v: &Value| format!("event: {name}\ndata: {v}\n\n");
            [
                ev("message_start", &json!({"type":"message_start","message":{"id":"msg_stub","type":"message","role":"assistant",
                    "model":model,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}})),
                ev("content_block_start", &json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
                ev("content_block_delta", &json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}})),
                ev("content_block_stop", &json!({"type":"content_block_stop","index":0})),
                ev("message_delta", &json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":4}})),
                ev("message_stop", &json!({"type":"message_stop"})),
            ]
            .concat()
        }
        (Dialect::OpenAi, false) => json!({"id":"chatcmpl-stub","object":"chat.completion","created":0,"model":model,
            "choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":1,"completion_tokens":4,"total_tokens":5}})
        .to_string(),
        (Dialect::OpenAi, true) => {
            let c = |delta: &Value, fin: &Value| {
                format!("data: {}\n\n", json!({"id":"chatcmpl-stub","object":"chat.completion.chunk","created":0,"model":model,
                    "choices":[{"index":0,"delta":delta,"finish_reason":fin}]}))
            };
            [c(&json!({"role":"assistant","content":""}), &Value::Null), c(&json!({"content":text}), &Value::Null), c(&json!({}), &json!("stop")), "data: [DONE]\n\n".into()]
                .concat()
        }
        (Dialect::OpenAiResponses, false) => json!({"id":"resp_stub","object":"response","status":"completed","model":model,
            "output":[{"type":"message","id":"msg_stub","status":"completed","role":"assistant","content":[{"type":"output_text","text":text,"annotations":[]}]}],
            "usage":{"input_tokens":1,"output_tokens":4,"total_tokens":5}})
        .to_string(),
        (Dialect::OpenAiResponses, true) => {
            let life = |ty: &str, status: &str, usage: &Value| {
                format!("event: {ty}\ndata: {}\n\n", json!({"type":ty,"response":{"id":"resp_stub","object":"response","status":status,"model":model,"usage":usage}}))
            };
            [life("response.created", "in_progress", &Value::Null), responses_message(0, "msg_stub", text), life("response.completed", "completed", &json!({"input_tokens":1,"output_tokens":4,"total_tokens":5}))].concat()
        }
    };
    Bytes::from(s)
}

/// A whole Responses message item carrying `text`, as streamed events at `output_index`
/// (`output_item.added` → `content_part.added` → `output_text.delta` → `output_text.done` →
/// `content_part.done` → `output_item.done`, worker RESPONSES.md): the `[moochy]` notice that
/// replaces a blocked tool call, the tripwire warning, and the offline stub.
pub fn responses_message(output_index: u32, id: &str, text: &str) -> String {
    let ev = |v: Value| format!("event: {}\ndata: {v}\n\n", v.get("type").and_then(Value::as_str).unwrap_or_default());
    let part = |t: &str| json!({"type":"output_text","text":t,"annotations":[]});
    let at = |ty: &str| json!({"type":ty,"item_id":id,"output_index":output_index,"content_index":0});
    let with = |mut v: Value, k: &str, x: Value| {
        if let Some(o) = v.as_object_mut() {
            o.insert(k.into(), x);
        }
        v
    };
    [
        ev(json!({"type":"response.output_item.added","output_index":output_index,"item":{"type":"message","id":id,"status":"in_progress","role":"assistant","content":[]}})),
        ev(with(at("response.content_part.added"), "part", part(""))),
        ev(with(at("response.output_text.delta"), "delta", json!(text))),
        ev(with(at("response.output_text.done"), "text", json!(text))),
        ev(with(at("response.content_part.done"), "part", part(text))),
        ev(json!({"type":"response.output_item.done","output_index":output_index,"item":{"type":"message","id":id,"status":"completed","role":"assistant","content":[part(text)]}})),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_roundtrip_and_binding() {
        let (ck, r, t16) = ([1u8; 32], [2u8; 32], [3u8; 16]);
        let c = DetailCtx { ck: &ck, r: &r, task: "01ARZ3NDEKTSV4RRFFQ69G5FAV", task16: &t16, worker: "d_x", attempt: 1 };
        let s = seal_detail(&c, "firewall", "field `mcp_servers` is not allowed");
        assert_eq!(open_detail(&c, "firewall", &s).as_deref(), Some("field `mcp_servers` is not allowed"));
        assert!(open_detail(&c, "route_mismatch", &s).is_none(), "code bound in AAD");
        let c2 = DetailCtx { attempt: 2, ..c };
        assert!(open_detail(&c2, "firewall", &s).is_none(), "attempt bound in key");
        let long = "é".repeat(800);
        assert!(open_detail(&c, "x", &seal_detail(&c, "x", &long)).unwrap().len() <= MAX_DETAIL);
    }

    #[test]
    fn responses_stateful_fields_refused_before_sealing() {
        let raw = br#"{"version":3,"effective_at":"2026-01-01T00:00:00Z","entries":[{"model":"openai/gpt-5","provider":"openai","provider_model_id":"gpt-5","dialects":["openai.chat","openai.responses"],"in":1250000,"out":10000000,"cache_write_5m":0,"cache_write_1h":0,"cache_read":125000,"max_image_tokens":1600,"max_page_tokens":3000,"fast_multiplier":1,"default_effort":"medium","max_output":128000,"source":"curated"}]}"#;
        let c = Catalog::parse(raw).unwrap();
        let e = c.entries.first().unwrap();
        let ok = br#"{"model":"openai/gpt-5","input":"hi","stream":true}"#;
        assert!(analyze(e, Dialect::OpenAiResponses, ok, &[]).is_ok());
        for (body, field) in [
            (r#"{"model":"openai/gpt-5","input":"hi","store":true}"#, "store"),
            (r#"{"model":"openai/gpt-5","input":"hi","previous_response_id":"resp_1"}"#, "previous_response_id"),
        ] {
            let f = analyze(e, Dialect::OpenAiResponses, body.as_bytes(), &[]).unwrap_err();
            let (status, v) = crate::native::error_body(Dialect::OpenAiResponses, &f);
            assert_eq!((status, v["error"]["type"].as_str(), v["error"]["code"].as_str()), (400, Some("invalid_request_error"), Some("firewall")), "{v}");
            assert_eq!(v["error"]["param"], field, "{v}");
        }
        // Codex's identifying headers never reach a donor: any header is refused for this dialect.
        assert!(analyze(e, Dialect::OpenAiResponses, ok, &[("session_id".into(), "s".into())]).is_err());
    }

    #[test]
    fn catalog_parse() {
        let raw = br#"{"version":2,"effective_at":"2026-01-01T00:00:00Z","entries":[{"model":"anthropic/claude-sonnet-5.5","provider":"anthropic","provider_model_id":"claude-sonnet-5-5","dialects":["anthropic.messages"],"in":3000000,"out":15000000,"cache_write_5m":3750000,"cache_write_1h":6000000,"cache_read":300000,"max_image_tokens":1600,"max_page_tokens":3000,"fast_multiplier":1,"default_effort":"medium","max_output":64000,"source":"curated"}]}"#;
        let c = Catalog::parse(raw).unwrap();
        assert_eq!(c.version, 2);
        assert_eq!(c.resolve("claude-sonnet-5-5").unwrap().model, "anthropic/claude-sonnet-5.5");
        assert!(Catalog::parse(br#"{"version":1,"version":2,"entries":[]}"#).is_err());
        assert!(Catalog::parse(br#"{"version":1,"entries":[{"model":"x","bogus":1}]}"#).is_err());
    }
}
