//! The two plug points for sibling crates.
//!
//! * [`Sealer`]: everything cryptographic on the wire (`moochy-proto`): sealing request bodies,
//!   wraps, response chunk AEAD, progress checkpoints, receipts, disputes.
//! * [`Executor`]: everything provider-facing (`moochy-worker`): route facts that the Worker
//!   recomputes, firewall + adapters, tool-call gate, tripwire.
//!
//! The node owns the orchestration (link, doors, task lifecycle) and calls only these traits.
//! Until the real crates are wired, [`StubExecutor`] serves canned responses and no `Sealer`
//! exists: relay-routed tasks fail closed.

use crate::pb::link as pb;
use bytes::Bytes;
use serde_json::{Value, json};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Anthropic,
    OpenAi,
}

impl Dialect {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic.messages",
            Self::OpenAi => "openai.chat",
        }
    }
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "anthropic.messages" => Some(Self::Anthropic),
            "openai.chat" => Some(Self::OpenAi),
            _ => None,
        }
    }
}

/// Route-header facts the Worker recomputes from the body and must match exactly (03 §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteFacts {
    pub model: String,
    pub effort: Option<String>,
    pub max_tokens: u64,
    pub est_input_tokens: u64,
    pub cache_ttl: &'static str,
    pub stream: bool,
    pub flags: Vec<&'static str>,
}

/// A failure as carried by `task.failed` / `task.nack` (03 §10.2).
#[derive(Clone, Debug)]
pub struct Failure {
    pub code: String,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    /// Human detail (already unsealed); never logged.
    pub detail: Option<String>,
}

impl Failure {
    pub fn new(code: &str, retryable: bool, detail: impl Into<Option<String>>) -> Self {
        Self { code: code.into(), retryable, retry_after_ms: None, detail: detail.into() }
    }
}

// ---------------------------------------------------------------------------------------------
// Sealer (moochy-proto)

pub struct Recipient {
    pub worker_device: String,
    pub enc_pub: [u8; 32],
}

pub struct SealInput<'a> {
    pub task_id: &'a str,
    pub repo_id: &'a str,
    pub route: &'a [u8],
    pub body: &'a [u8],
    /// Allowlisted provider headers (lowercase name, value).
    pub headers: &'a [(String, String)],
    pub gateway_device: &'a str,
    pub gateway_sign_seed: &'a [u8; 32],
    pub recipients: &'a [Recipient],
}

pub struct Sealed {
    /// One HPKE wrap (80 bytes) per recipient.
    pub wraps: Vec<pb::Wrap>,
    /// Request body ciphertext chunks (`attempt = 0`).
    pub chunks: Vec<pb::Chunk>,
    pub body_len: u64,
}

/// What the Gateway learned from a verified receipt.
pub struct ReceiptInfo {
    pub cost_uusd: u64,
    pub model_reported: String,
}

/// Per-task Gateway crypto state (holds CK and S; zeroized by the implementation on drop).
pub trait GatewayCtx: Send {
    fn wrap_more(&self, recipients: &[Recipient]) -> Result<Vec<pb::Wrap>, String>;
    /// `Accepted`: select the attempt whose stream will be decrypted.
    fn accept(&mut self, attempt: u32, worker_device: &str, r: &[u8]) -> Result<(), String>;
    /// Decrypt one response chunk of the accepted attempt (in order). `Err` = `bad_envelope`.
    fn open_chunk(&mut self, c: &pb::Chunk) -> Result<Bytes, String>;
    /// Verify a checkpoint signature with the worker's key. The node separately checks that
    /// `running_hash` equals its own SHA-256 of the plaintext up to `seq`.
    fn verify_checkpoint(&self, c: &pb::Checkpoint, worker_sign_pub: &[u8; 32]) -> bool;
    /// Check the receipt against what was sent/received. `Err((code, info))` = dispute.
    fn check_receipt(&self, end: &pb::SignedReceipt, worker_sign_pub: &[u8; 32]) -> Result<ReceiptInfo, (String, Option<ReceiptInfo>)>;
    /// Dispute signature over `lp("moochy/v1/dispute", task_id, u64(attempt), code)`.
    fn dispute_sig(&self, code: &str) -> Vec<u8>;
}

/// Per-task Worker crypto state.
pub trait WorkerCtx: Send {
    /// Response salt `R` drawn for this attempt.
    fn r(&self) -> [u8; 32];
    /// Seal one plaintext response chunk (≤ 65,497 bytes).
    fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<pb::Chunk, String>;
    /// Progress checkpoint over everything sealed so far.
    fn checkpoint(&self) -> pb::Checkpoint;
    /// Build and sign receipt + projection (and persist to the outbox before returning).
    fn finish(&mut self, outcome: &ExecOutcome) -> Result<pb::SignedReceipt, String>;
}

/// An opened assignment.
pub struct Opened {
    pub body: Bytes,
    pub headers: Vec<(String, String)>,
    pub gateway_device: String,
}

pub trait Sealer: Send + Sync {
    fn seal(&self, input: &SealInput<'_>) -> Result<(Sealed, Box<dyn GatewayCtx>), String>;
    /// Unwrap + decrypt + check `body_sha256` and the task signature (03 §7.2).
    /// `Err(code)` is a NACK code (`bad_envelope`, `unauthorized_task`, …).
    fn open(
        &self,
        assign: &pb::Assign,
        body: &[pb::Chunk],
        worker_device: &str,
        keys: &crate::keystore::DeviceKeys,
    ) -> Result<(Opened, Box<dyn WorkerCtx>), String>;
}

// ---------------------------------------------------------------------------------------------
// Executor (moochy-worker)

pub struct ExecRequest {
    pub task_id: String,
    pub dialect: Dialect,
    pub route: Value,
    pub body: Bytes,
    pub headers: Vec<(String, String)>,
    pub pledge: Option<String>,
}

pub enum ExecEvent {
    /// Firewall passed, local caps reserved, provider call starting (`task.ack`).
    Ready,
    /// Provider response headers received (`task.started`).
    Started,
    /// Original provider bytes.
    Bytes(Bytes),
    /// The bytes so far end a tool-call block: sign a progress checkpoint now.
    Checkpoint,
    Done(ExecOutcome),
    /// Failure (before `Started` this is a NACK).
    Failed(Failure),
}

#[derive(Clone, Debug, Default)]
pub struct ExecOutcome {
    pub status: String,
    pub cost_uusd: u64,
    pub model_reported: String,
    pub usage: Value,
}

pub enum GateEvent {
    /// Forward immediately.
    Pass(Bytes),
    /// A complete tool-call block, held until a verified checkpoint covers it.
    /// `replacement` is what to emit instead if structural checks / tripwire / signature fail.
    Tool { bytes: Bytes, ok: bool, replacement: Bytes },
}

/// Gateway-side tool-call inspection over the plaintext response stream (06 §8).
pub trait ToolGate: Send {
    fn push(&mut self, chunk: Bytes, out: &mut Vec<GateEvent>);
    fn finish(&mut self, out: &mut Vec<GateEvent>);
}

pub struct OfferModel {
    pub dialect: Dialect,
    pub model: String,
}

pub trait Executor: Send + Sync {
    /// Route facts from a strictly-parsed body (must equal the Worker's recomputation).
    fn route_facts(&self, dialect: Dialect, body: &serde_json::Map<String, Value>, raw: &[u8]) -> Result<RouteFacts, String>;
    /// Models this node can serve with its own provider keys.
    fn models(&self) -> Vec<OfferModel>;
    /// Served-task set (03 §7.2 check 5): `false` if `(gateway_device, task_id)` was seen before.
    fn claim_task(&self, gateway_device: &str, task_id: &str) -> bool;
    /// Firewall + provider call. Dropping the receiver aborts the provider request.
    fn execute(&self, req: ExecRequest) -> mpsc::Receiver<ExecEvent>;
    fn tool_gate(&self, dialect: Dialect, request: &serde_json::Map<String, Value>) -> Box<dyn ToolGate>;
    /// Pattern scan of untrusted text (MCP results); `Some(reason)` on a hit.
    fn tripwire(&self, text: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------------------------
// Stubs

/// Placeholder until `moochy-worker` is wired: canned responses, no provider calls.
#[derive(Default)]
pub struct StubExecutor {
    served: std::sync::Mutex<std::collections::HashSet<(String, String)>>,
}

pub const STUB_MODEL: &str = "moochy/stub";

/// Route facts per 03 §7.1. ponytail: `est_input_tokens` uses `ceil(body_bytes / 3)`; the exact
/// text/image/page split is owned by `moochy-worker` and replaces this when wired.
pub fn basic_route_facts(dialect: Dialect, b: &serde_json::Map<String, Value>, raw: &[u8]) -> Result<RouteFacts, String> {
    let model = b.get("model").and_then(Value::as_str).filter(|m| !m.is_empty() && m.len() <= 200);
    let model = model.ok_or("`model` is required")?.to_owned();
    let max_tokens = match dialect {
        Dialect::Anthropic => b.get("max_tokens"),
        Dialect::OpenAi => b.get("max_completion_tokens").or_else(|| b.get("max_tokens")),
    };
    let max_tokens = max_tokens.and_then(Value::as_u64).filter(|n| *n > 0).ok_or("`max_tokens` is required")?;
    let effort = match dialect {
        Dialect::Anthropic => b.get("output_config").and_then(|o| o.get("effort")),
        Dialect::OpenAi => b.get("reasoning_effort"),
    }
    .and_then(Value::as_str)
    .map(str::to_owned);
    let stream = match b.get("stream") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(s)) => *s,
        Some(_) => return Err("`stream` must be a boolean".into()),
    };
    let mut ttl = "none";
    let mut flags = Vec::new();
    scan(&Value::Object(b.clone()), 0, &mut ttl, &mut flags);
    let len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    Ok(RouteFacts { model, effort, max_tokens, est_input_tokens: len.div_ceil(3), cache_ttl: ttl, stream, flags })
}

fn scan(v: &Value, depth: u32, ttl: &mut &'static str, flags: &mut Vec<&'static str>) {
    if depth > crate::json::MAX_DEPTH {
        return;
    }
    let d = depth.saturating_add(1);
    match v {
        Value::Object(m) => {
            if let Some(cc) = m.get("cache_control") {
                let t = cc.get("ttl").and_then(Value::as_str);
                if t == Some("1h") {
                    *ttl = "1h";
                } else if *ttl == "none" {
                    *ttl = "5m";
                }
            }
            match m.get("type").and_then(Value::as_str) {
                Some("image" | "image_url") => add(flags, "images"),
                Some("document" | "file") => add(flags, "documents"),
                _ => {}
            }
            if m.get("speed").and_then(Value::as_str) == Some("fast") {
                add(flags, "fast");
            }
            m.values().for_each(|x| scan(x, d, ttl, flags));
        }
        Value::Array(a) => a.iter().for_each(|x| scan(x, d, ttl, flags)),
        _ => {}
    }
}

fn add(flags: &mut Vec<&'static str>, f: &'static str) {
    if !flags.contains(&f) {
        flags.push(f);
    }
}

impl Executor for StubExecutor {
    fn route_facts(&self, dialect: Dialect, body: &serde_json::Map<String, Value>, raw: &[u8]) -> Result<RouteFacts, String> {
        basic_route_facts(dialect, body, raw)
    }

    fn models(&self) -> Vec<OfferModel> {
        [Dialect::Anthropic, Dialect::OpenAi].into_iter().map(|dialect| OfferModel { dialect, model: STUB_MODEL.into() }).collect()
    }

    fn claim_task(&self, gateway_device: &str, task_id: &str) -> bool {
        // ponytail: in-memory and unbounded; moochy-worker's persisted ±10 min set replaces it.
        crate::node::lock(&self.served).insert((gateway_device.to_owned(), task_id.to_owned()))
    }

    fn execute(&self, req: ExecRequest) -> mpsc::Receiver<ExecEvent> {
        let (tx, rx) = mpsc::channel(8);
        let stream = req.route.get("stream").and_then(Value::as_bool).unwrap_or(false);
        let model = req.route.get("model").and_then(Value::as_str).unwrap_or(STUB_MODEL).to_owned();
        let text = format!("stub response from {model}");
        let body = stub_body(req.dialect, stream, &model, &text);
        tokio::spawn(async move {
            for ev in [ExecEvent::Ready, ExecEvent::Started, ExecEvent::Bytes(body)] {
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
            let out = ExecOutcome { status: "ok".into(), model_reported: model, ..ExecOutcome::default() };
            let _ = tx.send(ExecEvent::Done(out)).await;
        });
        rx
    }

    fn tool_gate(&self, _: Dialect, _: &serde_json::Map<String, Value>) -> Box<dyn ToolGate> {
        Box::new(PassGate)
    }

    fn tripwire(&self, _: &str) -> Option<String> {
        None
    }
}

fn stub_body(d: Dialect, stream: bool, model: &str, text: &str) -> Bytes {
    let s = match (d, stream) {
        (Dialect::Anthropic, false) => json!({"id":"msg_stub","type":"message","role":"assistant","model":model,
            "content":[{"type":"text","text":text}],"stop_reason":"end_turn","stop_sequence":null,
            "usage":{"input_tokens":1,"output_tokens":4}})
        .to_string(),
        (Dialect::Anthropic, true) => {
            let ev = |name: &str, v: Value| format!("event: {name}\ndata: {v}\n\n");
            [
                ev("message_start", json!({"type":"message_start","message":{"id":"msg_stub","type":"message","role":"assistant",
                    "model":model,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}})),
                ev("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
                ev("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}})),
                ev("content_block_stop", json!({"type":"content_block_stop","index":0})),
                ev("message_delta", json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":4}})),
                ev("message_stop", json!({"type":"message_stop"})),
            ]
            .concat()
        }
        (Dialect::OpenAi, false) => json!({"id":"chatcmpl-stub","object":"chat.completion","created":0,"model":model,
            "choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":1,"completion_tokens":4,"total_tokens":5}})
        .to_string(),
        (Dialect::OpenAi, true) => {
            let c = |delta: Value, fin: Value| {
                format!("data: {}\n\n", json!({"id":"chatcmpl-stub","object":"chat.completion.chunk","created":0,"model":model,
                    "choices":[{"index":0,"delta":delta,"finish_reason":fin}]}))
            };
            [c(json!({"role":"assistant","content":""}), Value::Null), c(json!({"content":text}), Value::Null), c(json!({}), json!("stop")), "data: [DONE]\n\n".into()]
                .concat()
        }
    };
    Bytes::from(s)
}

/// Pass-through gate. ponytail: holds nothing; `moochy-worker`'s structural checks + tripwire
/// replace it when wired (relay mode cannot run without them anyway: no `Sealer` yet).
pub struct PassGate;

impl ToolGate for PassGate {
    fn push(&mut self, chunk: Bytes, out: &mut Vec<GateEvent>) {
        out.push(GateEvent::Pass(chunk));
    }
    fn finish(&mut self, _: &mut Vec<GateEvent>) {}
}
