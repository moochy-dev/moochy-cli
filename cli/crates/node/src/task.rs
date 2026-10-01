//! Gateway task pipeline shared by the API door and the MCP door (07 §4.2).
//!
//! `submit` turns a validated request into a stream of [`TaskEv`]: through the relay
//! (route header → sign + seal via [`Sealer`] → `task.submit` → decrypt accepted attempt only →
//! tool-call gate held until a verified checkpoint → receipt check) or, offline, straight to the
//! local executor. Dropping the receiver cancels the task.

use crate::engine::{Dialect, ExecEvent, ExecRequest, Failure, GateEvent, GatewayCtx, Recipient, RouteFacts, SealInput, ToolGate};
use crate::link::text_msg;
use crate::node::{Node, PoolWorker, RepoPool, Side, TaskIn};
use crate::util::{b64d, b64e, log, ulid, ulid_bytes};
use bytes::Bytes;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

pub struct TaskReq {
    pub slug: String,
    pub dialect: Dialect,
    pub body: Bytes,
    pub parsed: Map<String, Value>,
    pub facts: RouteFacts,
    /// Allowlisted provider headers (`anthropic-version`, `anthropic-beta`).
    pub headers: Vec<(String, String)>,
}

pub enum TaskEv {
    /// Provider answered (no failover after this point).
    Started { task_id: String, donor: String },
    Bytes(Bytes),
    End { cost_uusd: Option<u64>, model: Option<String> },
    Failed(Failure),
}

const MAX_WRAPS: usize = 8;
const CLIENT_CLOSED: &str = "client_closed";

pub async fn submit(node: &Arc<Node>, req: TaskReq) -> Result<mpsc::Receiver<TaskEv>, Failure> {
    let pool = node.pool_for(&req.slug);
    if let Some(p) = &pool {
        if !p.models().iter().any(|(m, ds)| *m == req.facts.model && ds.iter().any(|d| d == req.dialect.wire())) {
            return Err(Failure::new("model_not_in_pool", false, format!("model `{}` is not offered by this repo's donor pool", req.facts.model)));
        }
    }
    if node.offline {
        return Ok(run_local(node, req));
    }
    let pool = pool.ok_or_else(|| Failure::new("no_pool", true, format!("no donor pool synced yet for {}", req.slug)))?;
    run_relay(node, req, pool).await
}

fn run_local(node: &Arc<Node>, req: TaskReq) -> mpsc::Receiver<TaskEv> {
    let (tx, rx) = mpsc::channel(16);
    let task_id = ulid().unwrap_or_default();
    let route = json!({"model": req.facts.model, "stream": req.facts.stream});
    let mut ex = node.executor.execute(ExecRequest { task_id: task_id.clone(), dialect: req.dialect, route, body: req.body, headers: req.headers, pledge: None });
    tokio::spawn(async move {
        loop {
            let ev = tokio::select! {
                ev = ex.recv() => ev,
                () = tx.closed() => return,
            };
            let out = match ev {
                Some(ExecEvent::Started) => TaskEv::Started { task_id: task_id.clone(), donor: "local".into() },
                Some(ExecEvent::Bytes(b)) => TaskEv::Bytes(b),
                Some(ExecEvent::Done(o)) => TaskEv::End { cost_uusd: Some(o.cost_uusd), model: Some(o.model_reported) },
                Some(ExecEvent::Failed(f)) => TaskEv::Failed(f),
                Some(ExecEvent::Checkpoint | ExecEvent::Ready) => continue,
                None => TaskEv::Failed(Failure::new("provider_error", true, "executor stopped".to_owned())),
            };
            let terminal = matches!(out, TaskEv::End { .. } | TaskEv::Failed(_));
            if tx.send(out).await.is_err() || terminal {
                return;
            }
        }
    });
    rx
}

/// Route header (03 §7.1) as the exact bytes that get signed, wrapped and sent.
fn route_header(node: &Node, req: &TaskReq, repo_id: &str) -> (Vec<u8>, [u8; 16]) {
    let p = &req.parsed;
    let enc = |v: Option<&Value>| v.map(|v| v.to_string().into_bytes()).unwrap_or_default();
    let (system, first_user) = match req.dialect {
        Dialect::Anthropic => (enc(p.get("system")), enc(first_role(p, "user"))),
        Dialect::OpenAi => (enc(first_role(p, "system").or_else(|| first_role(p, "developer"))), enc(first_role(p, "user"))),
    };
    let affinity = node.secrets.affinity(&system, &enc(p.get("tools")), &first_user);
    let f = &req.facts;
    let route = json!({
        "repo_id": repo_id, "dialect": req.dialect.wire(), "model": f.model, "effort": f.effort,
        "max_tokens": f.max_tokens, "est_input_tokens": f.est_input_tokens, "cache_ttl": f.cache_ttl,
        "stream": f.stream, "affinity": b64e(&affinity), "flags": f.flags,
    });
    (route.to_string().into_bytes(), affinity)
}

fn first_role<'a>(p: &'a Map<String, Value>, role: &str) -> Option<&'a Value> {
    p.get("messages")?.as_array()?.iter().find(|m| m.get("role").and_then(Value::as_str) == Some(role))
}

/// Affinity worker first, then the best `hint`s, ≤ 8 wraps (04 §7).
fn pick(pool: &RepoPool, dialect: Dialect, model: &str, sticky: Option<&str>) -> Vec<PoolWorker> {
    let mut c: Vec<&PoolWorker> =
        pool.workers.iter().filter(|w| w.models.iter().any(|m| m == model) && w.dialects.iter().any(|d| d == dialect.wire())).collect();
    c.sort_by_key(|w| (Some(w.worker_device.as_str()) != sticky, std::cmp::Reverse(w.hint)));
    c.into_iter().take(MAX_WRAPS).cloned().collect()
}

fn recipients(ws: &[PoolWorker]) -> Vec<Recipient> {
    ws.iter().map(|w| Recipient { worker_device: w.worker_device.clone(), enc_pub: w.enc_pub }).collect()
}

fn wraps_json(w: &[(String, Vec<u8>)]) -> Value {
    w.iter().map(|(d, x)| json!({"worker_device": d, "wrap": b64e(x)})).collect()
}

async fn run_relay(node: &Arc<Node>, req: TaskReq, pool: RepoPool) -> Result<mpsc::Receiver<TaskEv>, Failure> {
    let sealer = node.sealer.clone().ok_or_else(|| Failure::new("not_wired", false, "moochy: end-to-end encryption backend is not available in this build".to_owned()))?;
    let (Some(device), Some(keys)) = (node.device_id(), node.secrets.device.as_ref()) else {
        return Err(Failure::new("not_logged_in", false, "moochy: run `moochy login` first".to_owned()));
    };
    let (route, affinity) = route_header(node, &req, &pool.repo_id);
    let sticky = node.session_worker(&affinity);
    let chosen = pick(&pool, req.dialect, &req.facts.model, sticky.as_deref());
    if chosen.is_empty() {
        return Err(Failure::new("model_not_in_pool", false, format!("no donor offers `{}` for {}", req.facts.model, req.slug)));
    }
    let task_id = ulid().map_err(|e| Failure::new("internal", true, e.msg))?;
    let id = ulid_bytes(&task_id).ok_or_else(|| Failure::new("internal", true, "ulid".to_owned()))?;
    let input = SealInput {
        task_id: &task_id,
        repo_id: &pool.repo_id,
        route: &route,
        body: &req.body,
        headers: &req.headers,
        gateway_device: device,
        gateway_sign_seed: &keys.sign_seed,
        recipients: &recipients(&chosen),
    };
    let (sealed, ctx) = sealer.seal(&input).map_err(|e| Failure::new("internal", true, e))?;
    let key = (id, Side::Gateway);
    let rx_in = node.register(key).ok_or_else(|| Failure::new("internal", true, "task id collision".to_owned()))?;
    let submit = json!({"t":"task.submit","task":task_id,"route_b64":b64e(&route),"wraps":wraps_json(&sealed.wraps),
        "body_len":sealed.body_len,"body_chunks":sealed.frames.len()});
    let mut ok = node.send(text_msg(&submit)).await;
    for f in sealed.frames {
        ok = ok && node.send(Message::Binary(f)).await;
    }
    if !ok {
        node.unregister(&key);
        return Err(Failure::new("overloaded", true, "moochy: relay link is down".to_owned()));
    }
    let (tx, rx) = mpsc::channel(16);
    let gate = node.executor.tool_gate(req.dialect, &req.parsed);
    let ttl = if req.facts.cache_ttl == "1h" { 3_600_000 } else { 300_000 };
    let drv = Driver { node: node.clone(), task_id, pool, ctx, gate, tx, accepted: None, started: false, hasher: Sha256::new(), hashes: VecDeque::new(), verified: None, pending: VecDeque::new() };
    tokio::spawn(async move {
        let node = drv.node.clone();
        drv.run(rx_in, affinity, ttl).await;
        node.unregister(&key);
    });
    Ok(rx)
}

enum Pending {
    Bytes(Bytes),
    Tool { seq: u32, bytes: Bytes, ok: bool, replacement: Bytes },
}

struct Driver {
    node: Arc<Node>,
    task_id: String,
    pool: RepoPool,
    ctx: Box<dyn GatewayCtx>,
    gate: Box<dyn ToolGate>,
    tx: mpsc::Sender<TaskEv>,
    accepted: Option<(u8, PoolWorker)>,
    started: bool,
    hasher: Sha256,
    /// Running hash after each chunk, for checkpoint verification (bounded).
    hashes: VecDeque<(u32, [u8; 32])>,
    verified: Option<u32>,
    pending: VecDeque<Pending>,
}

enum Step {
    Continue,
    Done,
    Fail(Failure),
}

impl Driver {
    async fn run(mut self, mut rx: mpsc::Receiver<TaskIn>, affinity: [u8; 16], ttl: u64) {
        let step = loop {
            let m = tokio::select! {
                m = rx.recv() => m,
                () = self.tx.closed() => {
                    let _ = self.node.send(text_msg(&json!({"t":"task.cancel","task":self.task_id,"reason":"client_closed"}))).await;
                    return;
                }
            };
            let step = match m {
                None => Step::Fail(Failure::new("overloaded", true, "moochy: relay link lost".to_owned())),
                Some(TaskIn::Frame(b)) => self.on_frame(&b).await,
                Some(TaskIn::Text(v)) => self.on_text(&v).await,
            };
            if !matches!(step, Step::Continue) {
                break step;
            }
        };
        if let Step::Fail(f) = step {
            if f.code == CLIENT_CLOSED {
                let _ = self.node.send(text_msg(&json!({"t":"task.cancel","task":self.task_id,"reason":"client_closed"}))).await;
                return;
            }
            if f.code == "bad_envelope" {
                log("error", "bad_envelope", &json!({"task": self.task_id}));
                let _ = self.node.send(text_msg(&json!({"t":"task.cancel","task":self.task_id,"reason":"bad_envelope"}))).await;
            }
            let _ = self.tx.send(TaskEv::Failed(f)).await;
        } else if let Some((_, w)) = &self.accepted {
            self.node.session_set(affinity, w.worker_device.clone(), ttl);
        }
    }

    async fn on_text(&mut self, v: &Value) -> Step {
        let attempt = v.get("attempt").and_then(Value::as_u64).and_then(|a| u8::try_from(a).ok());
        let current = self.accepted.as_ref().map(|(a, _)| *a);
        match v.get("t").and_then(Value::as_str).unwrap_or("") {
            "task.need_wraps" => {
                let want: Vec<&str> = v.get("workers").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
                let ws: Vec<PoolWorker> = self.pool.workers.iter().filter(|w| want.contains(&w.worker_device.as_str())).cloned().collect();
                match self.ctx.wrap_more(&recipients(&ws)) {
                    Ok(w) => {
                        let _ = self.node.send(text_msg(&json!({"t":"task.wraps","task":self.task_id,"wraps":wraps_json(&w)}))).await;
                        Step::Continue
                    }
                    Err(e) => Step::Fail(Failure::new("internal", true, e)),
                }
            }
            "task.accepted" => {
                let dev = v.get("worker_device").and_then(Value::as_str).unwrap_or("");
                let (Some(a), Some(r), Some(w)) = (attempt, v.get("R").and_then(Value::as_str).and_then(b64d), self.pool.workers.iter().find(|w| w.worker_device == dev)) else {
                    return Step::Fail(Failure::new("unauthorized_task", true, "moochy: relay accepted the task for an unknown worker".to_owned()));
                };
                if self.started {
                    // A second attempt after start is only possible through a relay bug or attack (03 §6.3).
                    return Step::Fail(Failure::new("bad_envelope", true, "moochy: second attempt after start".to_owned()));
                }
                if let Err(e) = self.ctx.accept(a, dev, &r) {
                    return Step::Fail(Failure::new("bad_envelope", true, e));
                }
                self.accepted = Some((a, w.clone()));
                Step::Continue
            }
            "task.started" if attempt.is_some() && attempt == current => {
                self.started = true;
                let donor = self.accepted.as_ref().map(|(_, w)| w.donor.clone()).unwrap_or_default();
                self.emit(TaskEv::Started { task_id: self.task_id.clone(), donor }).await
            }
            "task.checkpoint" if attempt.is_some() && attempt == current => self.on_checkpoint(v).await,
            "task.end" if attempt.is_some() && attempt == current => self.on_end(v).await,
            "task.failed" => {
                let code = v.get("code").and_then(Value::as_str).unwrap_or("provider_error");
                let mut f = Failure::new(code, v.get("retryable").and_then(Value::as_bool).unwrap_or(false), None);
                f.retry_after_ms = v.get("retry_after_ms").and_then(Value::as_u64);
                Step::Fail(f)
            }
            _ => Step::Continue,
        }
    }

    async fn on_frame(&mut self, b: &[u8]) -> Step {
        let Some((attempt, _)) = &self.accepted else { return Step::Continue };
        if b.get(17) != Some(attempt) {
            return if self.started { Step::Fail(Failure::new("bad_envelope", true, "moochy: frames from a second attempt".to_owned())) } else { Step::Continue };
        }
        let chunk = match self.ctx.open_chunk(b) {
            Ok(c) => c,
            Err(_) => return Step::Fail(Failure::new("bad_envelope", true, "moochy: response failed authentication".to_owned())),
        };
        self.hasher.update(&chunk.plaintext);
        if self.hashes.len() >= 1024 {
            self.hashes.pop_front();
        }
        self.hashes.push_back((chunk.seq, self.hasher.clone().finalize().into()));
        let mut out = Vec::new();
        self.gate.push(chunk.plaintext, &mut out);
        if chunk.last {
            self.gate.finish(&mut out);
        }
        for ev in out {
            self.pending.push_back(match ev {
                GateEvent::Pass(b) => Pending::Bytes(b),
                GateEvent::Tool { bytes, ok, replacement } => Pending::Tool { seq: chunk.seq, bytes, ok, replacement },
            });
        }
        self.flush(false).await
    }

    async fn on_checkpoint(&mut self, v: &Value) -> Step {
        let Some((_, w)) = &self.accepted else { return Step::Continue };
        let seq = v.get("seq").and_then(Value::as_u64).and_then(|s| u32::try_from(s).ok());
        let (Some(seq), Some(rh), Some(sig), Some(pk)) = (
            seq,
            v.get("running_hash").and_then(Value::as_str).and_then(b64d),
            v.get("sig").and_then(Value::as_str).and_then(b64d),
            w.sign_pub,
        ) else {
            return Step::Continue;
        };
        let ours = self.hashes.iter().find(|(s, _)| *s == seq).map(|(_, h)| h);
        if ours.is_some_and(|h| h.as_slice() == rh.as_slice()) && self.ctx.verify_checkpoint(seq, &rh, &sig, &pk) {
            self.verified = Some(self.verified.map_or(seq, |v| v.max(seq)));
            return self.flush(false).await;
        }
        log("warn", "checkpoint rejected", &json!({"task": self.task_id}));
        Step::Continue
    }

    async fn on_end(&mut self, v: &Value) -> Step {
        let flushed = self.flush(true).await;
        if !matches!(flushed, Step::Continue) {
            return flushed;
        }
        let pk = self.accepted.as_ref().and_then(|(_, w)| w.sign_pub).unwrap_or([0; 32]);
        let info = match self.ctx.check_receipt(v, &pk) {
            Ok(i) => Some(i),
            Err((code, info)) => {
                let sig = self.ctx.dispute_sig(&code);
                let attempt = self.accepted.as_ref().map_or(0, |(a, _)| *a);
                let d = json!({"t":"receipt.dispute","task":self.task_id,"attempt":attempt,"code":code,"gateway_sig":b64e(&sig)});
                let _ = self.node.send(text_msg(&d)).await;
                log("warn", "receipt disputed", &json!({"task": self.task_id, "code": code}));
                info
            }
        };
        let _ = self.tx.send(TaskEv::End { cost_uusd: info.as_ref().map(|i| i.cost_uusd), model: info.map(|i| i.model_reported) }).await;
        Step::Done
    }

    /// Emit pending output in order; a tool block waits for a verified checkpoint covering it.
    /// At the end (`finale`), unverified tool blocks are replaced by their error substitute.
    async fn flush(&mut self, finale: bool) -> Step {
        while let Some(p) = self.pending.front() {
            let ready = match p {
                Pending::Bytes(_) => true,
                Pending::Tool { seq, .. } => finale || self.verified.is_some_and(|v| v >= *seq),
            };
            if !ready {
                break;
            }
            let b = match self.pending.pop_front() {
                Some(Pending::Bytes(b)) => b,
                Some(Pending::Tool { seq, bytes, ok, replacement }) => {
                    if ok && self.verified.is_some_and(|v| v >= seq) { bytes } else { replacement }
                }
                None => break,
            };
            let s = self.emit(TaskEv::Bytes(b)).await;
            if !matches!(s, Step::Continue) {
                return s;
            }
        }
        Step::Continue
    }

    async fn emit(&self, ev: TaskEv) -> Step {
        if self.tx.send(ev).await.is_err() { Step::Fail(Failure::new(CLIENT_CLOSED, false, None)) } else { Step::Continue }
    }
}
