//! Gateway task pipeline shared by the API door and the MCP door (07 §4.2).
//!
//! `submit` turns a validated request into a stream of [`TaskEv`]: through the relay (route header
//! → sign + seal via [`crate::engine::Sealer`] → one gRPC `Submit` stream → decrypt the accepted
//! attempt only → tool-call gate held until a verified checkpoint → receipt check) or, offline,
//! straight to the local executor. Dropping the receiver cancels the task (stream reset).

use crate::engine::{Dialect, ExecEvent, ExecRequest, Failure, GateEvent, GatewayCtx, Recipient, RouteFacts, SealInput, ToolGate};
use crate::node::{Busy, Node, PoolWorker, RepoPool};
use crate::pb::link::{self as pb, SubmitDown, SubmitUp, submit_down, submit_up};
use crate::pb::local::JournalEntry;
use crate::util::{b64e, clean, log, now_ms, ulid};
use bytes::Bytes;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

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

pub async fn submit(node: &Arc<Node>, req: TaskReq) -> Result<mpsc::Receiver<TaskEv>, Failure> {
    let pool = node.pool_for(&req.slug);
    if let Some(p) = &pool
        && !p.models().iter().any(|(m, ds)| *m == req.facts.model && ds.iter().any(|d| d == req.dialect.wire()))
    {
        return Err(Failure::new("model_not_in_pool", false, format!("model `{}` is not offered by this repo's donor pool", req.facts.model)));
    }
    if node.offline {
        return Ok(run_local(node, req));
    }
    let pool = pool.ok_or_else(|| Failure::new("no_pool", true, format!("moochy: no donor pool synced yet for {}", req.slug)))?;
    run_relay(node, req, pool).await
}

fn journal(node: &Node, task: &str, slug: &str, model: &str, status: &str, cost: Option<u64>, t0: u64) {
    node.journal(JournalEntry {
        t_ms: i64::try_from(t0).unwrap_or(0),
        role: "gateway".into(),
        task: task.into(),
        repo: slug.into(),
        model: model.into(),
        status: status.into(),
        cost_uusd: cost.and_then(|c| i64::try_from(c).ok()).unwrap_or(0),
        ms: u32::try_from(now_ms().saturating_sub(t0)).unwrap_or(u32::MAX),
    });
}

fn run_local(node: &Arc<Node>, req: TaskReq) -> mpsc::Receiver<TaskEv> {
    let (tx, rx) = mpsc::channel(16);
    let task_id = ulid().unwrap_or_default();
    let route = json!({"model": req.facts.model, "stream": req.facts.stream});
    let mut ex = node.executor.execute(ExecRequest { task_id: task_id.clone(), dialect: req.dialect, route, body: req.body, headers: req.headers, pledge: None });
    let node = node.clone();
    let (slug, model, t0) = (req.slug, req.facts.model, now_ms());
    tokio::spawn(async move {
        let _busy = Busy::new(&node.gateway_tasks);
        let status = loop {
            let ev = tokio::select! {
                ev = ex.recv() => ev,
                () = tx.closed() => break "cancelled".to_owned(),
            };
            let out = match ev {
                Some(ExecEvent::Started) => TaskEv::Started { task_id: task_id.clone(), donor: "local".into() },
                Some(ExecEvent::Bytes(b)) => TaskEv::Bytes(b),
                Some(ExecEvent::Done(o)) => TaskEv::End { cost_uusd: Some(o.cost_uusd), model: Some(o.model_reported) },
                Some(ExecEvent::Failed(f)) => TaskEv::Failed(f),
                Some(ExecEvent::Checkpoint | ExecEvent::Ready) => continue,
                None => TaskEv::Failed(Failure::new("provider_error", true, "executor stopped".to_owned())),
            };
            let status = match &out {
                TaskEv::End { .. } => Some("ok".to_owned()),
                TaskEv::Failed(f) => Some(format!("failed:{}", f.code)),
                _ => None,
            };
            if tx.send(out).await.is_err() {
                break "cancelled".to_owned();
            }
            if let Some(s) = status {
                break s;
            }
        };
        journal(&node, &task_id, &slug, &model, &status, None, t0);
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

fn up(m: submit_up::Msg) -> SubmitUp {
    SubmitUp { msg: Some(m) }
}

async fn run_relay(node: &Arc<Node>, req: TaskReq, pool: RepoPool) -> Result<mpsc::Receiver<TaskEv>, Failure> {
    let sealer = node.sealer.clone().ok_or_else(|| Failure::new("not_wired", false, "moochy: end-to-end encryption backend is not available in this build".to_owned()))?;
    let (Some(device), Some(keys)) = (node.device_id(), node.secrets.device.as_ref()) else {
        return Err(Failure::new("not_logged_in", false, "moochy: run `moochy login` first".to_owned()));
    };
    let link = node.link().ok_or_else(|| Failure::new("overloaded", true, "moochy: relay link is down".to_owned()))?;
    let t0 = now_ms();
    let (route, affinity) = route_header(node, &req, &pool.repo_id);
    let sticky = node.session_worker(&affinity);
    let chosen = pick(&pool, req.dialect, &req.facts.model, sticky.as_deref());
    if chosen.is_empty() {
        return Err(Failure::new("model_not_in_pool", false, format!("moochy: no donor offers `{}` for {}", req.facts.model, req.slug)));
    }
    let task_id = ulid().map_err(|e| Failure::new("internal", true, e.msg))?;
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
    // Body chunks are queued before the RPC starts, so they go out with the first flush.
    let n = sealed.chunks.len();
    let (up_tx, up_rx) = mpsc::channel::<SubmitUp>(n.saturating_add(4));
    let open = pb::SubmitOpen {
        task: task_id.clone(),
        route,
        wraps: sealed.wraps,
        body_len: sealed.body_len,
        body_chunks: u32::try_from(n).unwrap_or(u32::MAX),
    };
    let _ = up_tx.try_send(up(submit_up::Msg::Open(open)));
    for c in sealed.chunks {
        let _ = up_tx.try_send(up(submit_up::Msg::Body(c)));
    }
    let mut client = link.client.clone();
    let down = client
        .submit(crate::link::with_session(&link, ReceiverStream::new(up_rx)))
        .await
        .map_err(|s| Failure::new("overloaded", true, format!("moochy: relay refused the task ({:?})", s.code())))?
        .into_inner();
    let (tx, rx) = mpsc::channel(16);
    let gate = node.executor.tool_gate(req.dialect, &req.parsed);
    let ttl = if req.facts.cache_ttl == "1h" { 3_600_000 } else { 300_000 };
    let drv = Driver {
        node: node.clone(),
        task_id,
        pool,
        ctx,
        gate,
        tx,
        up: up_tx,
        accepted: None,
        started: false,
        hasher: Sha256::new(),
        hashes: VecDeque::new(),
        verified: None,
        pending: VecDeque::new(),
        cost: None,
    };
    let (slug, model) = (req.slug, req.facts.model);
    tokio::spawn(async move {
        let node = drv.node.clone();
        let _busy = Busy::new(&node.gateway_tasks);
        let task_id = drv.task_id.clone();
        let (status, cost) = drv.run(down, affinity, ttl).await;
        journal(&node, &task_id, &slug, &model, &status, cost, t0);
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
    /// Kept open for `Wraps` / `Cancel`; dropping it half-closes the stream.
    up: mpsc::Sender<SubmitUp>,
    accepted: Option<(u32, PoolWorker)>,
    started: bool,
    hasher: Sha256,
    /// Running hash after each chunk, for checkpoint verification (bounded).
    hashes: VecDeque<(u32, [u8; 32])>,
    verified: Option<u32>,
    pending: VecDeque<Pending>,
    cost: Option<u64>,
}

enum Step {
    Continue,
    Done,
    Fail(Failure),
    /// The client went away: cancel upstream.
    Gone,
}

impl Driver {
    /// Returns `(journal status, cost)`.
    async fn run(mut self, mut down: tonic::Streaming<SubmitDown>, affinity: [u8; 16], ttl: u64) -> (String, Option<u64>) {
        let step = loop {
            let m = tokio::select! {
                m = down.message() => m,
                () = self.tx.closed() => break Step::Gone,
            };
            let step = match m {
                Ok(Some(SubmitDown { msg: Some(m) })) => self.on_msg(m).await,
                Ok(Some(SubmitDown { msg: None })) => Step::Continue,
                Ok(None) | Err(_) => Step::Fail(Failure::new("overloaded", true, "moochy: relay link lost".to_owned())),
            };
            if !matches!(step, Step::Continue) {
                break step;
            }
        };
        match step {
            Step::Gone => {
                let _ = self.up.try_send(up(submit_up::Msg::Cancel(pb::Cancel { reason: "client_closed".into() })));
                ("cancelled".into(), None)
            }
            Step::Fail(f) => {
                if f.code == "bad_envelope" {
                    log("error", "bad_envelope", &json!({"task": self.task_id}));
                    let _ = self.up.try_send(up(submit_up::Msg::Cancel(pb::Cancel { reason: "bad_envelope".into() })));
                }
                let status = format!("failed:{}", f.code);
                let _ = self.tx.send(TaskEv::Failed(f)).await;
                (status, None)
            }
            Step::Done | Step::Continue => {
                if let Some((_, w)) = &self.accepted {
                    self.node.session_set(affinity, w.worker_device.clone(), ttl);
                }
                ("ok".into(), self.cost)
            }
        }
    }

    async fn on_msg(&mut self, m: submit_down::Msg) -> Step {
        let current = self.accepted.as_ref().map(|(a, _)| *a);
        match m {
            submit_down::Msg::NeedWraps(n) => {
                let ws: Vec<PoolWorker> = self.pool.workers.iter().filter(|w| n.workers.contains(&w.worker_device)).take(MAX_WRAPS).cloned().collect();
                match self.ctx.wrap_more(&recipients(&ws)) {
                    Ok(wraps) => {
                        let _ = self.up.send(up(submit_up::Msg::Wraps(pb::Wraps { wraps }))).await;
                        Step::Continue
                    }
                    Err(e) => Step::Fail(Failure::new("internal", true, e)),
                }
            }
            submit_down::Msg::Accepted(a) => {
                let Some(w) = self.pool.workers.iter().find(|w| w.worker_device == a.worker_device) else {
                    return Step::Fail(Failure::new("unauthorized_task", true, "moochy: relay accepted the task for an unknown worker".to_owned()));
                };
                if self.started {
                    // A second attempt after start is only possible through a relay bug or attack (03 §6.3).
                    return Step::Fail(Failure::new("bad_envelope", true, "moochy: second attempt after start".to_owned()));
                }
                if let Err(e) = self.ctx.accept(a.attempt, &a.worker_device, &a.r) {
                    return Step::Fail(Failure::new("bad_envelope", true, e));
                }
                self.accepted = Some((a.attempt, w.clone()));
                Step::Continue
            }
            submit_down::Msg::Started(s) if Some(s.attempt) == current => {
                self.started = true;
                let donor = self.accepted.as_ref().map(|(_, w)| w.donor.clone()).unwrap_or_default();
                emit(&self.tx, TaskEv::Started { task_id: self.task_id.clone(), donor }).await
            }
            submit_down::Msg::Chunk(c) => self.on_chunk(&c).await,
            submit_down::Msg::Checkpoint(c) if Some(c.attempt) == current => self.on_checkpoint(&c).await,
            submit_down::Msg::End(r) if Some(r.attempt) == current => self.on_end(&r).await,
            submit_down::Msg::Failed(f) => {
                let mut fl = Failure::new(&clean(&f.code), f.retryable, None);
                fl.retry_after_ms = (f.retry_after_ms > 0).then_some(u64::from(f.retry_after_ms));
                Step::Fail(fl)
            }
            _ => Step::Continue,
        }
    }

    async fn on_chunk(&mut self, c: &pb::Chunk) -> Step {
        let Some((attempt, _)) = &self.accepted else { return Step::Continue };
        if c.attempt != *attempt {
            return if self.started { Step::Fail(Failure::new("bad_envelope", true, "moochy: frames from a second attempt".to_owned())) } else { Step::Continue };
        }
        let Ok(plain) = self.ctx.open_chunk(c) else {
            return Step::Fail(Failure::new("bad_envelope", true, "moochy: response failed authentication; retry".to_owned()));
        };
        self.hasher.update(&plain);
        if self.hashes.len() >= 1024 {
            self.hashes.pop_front();
        }
        self.hashes.push_back((c.seq, self.hasher.clone().finalize().into()));
        let mut out = Vec::new();
        self.gate.push(plain, &mut out);
        if c.last {
            self.gate.finish(&mut out);
        }
        for ev in out {
            self.pending.push_back(match ev {
                GateEvent::Pass(b) => Pending::Bytes(b),
                GateEvent::Tool { bytes, ok, replacement } => Pending::Tool { seq: c.seq, bytes, ok, replacement },
            });
        }
        self.flush(false).await
    }

    async fn on_checkpoint(&mut self, c: &pb::Checkpoint) -> Step {
        let Some(pk) = self.accepted.as_ref().and_then(|(_, w)| w.sign_pub) else { return Step::Continue };
        let ours = self.hashes.iter().find(|(s, _)| *s == c.seq).map(|(_, h)| h);
        if ours.is_some_and(|h| h.as_slice() == c.running_hash.as_slice()) && self.ctx.verify_checkpoint(c, &pk) {
            self.verified = Some(self.verified.map_or(c.seq, |v| v.max(c.seq)));
            return self.flush(false).await;
        }
        log("warn", "checkpoint rejected", &json!({"task": self.task_id}));
        Step::Continue
    }

    async fn on_end(&mut self, r: &pb::SignedReceipt) -> Step {
        let flushed = self.flush(true).await;
        if !matches!(flushed, Step::Continue) {
            return flushed;
        }
        let pk = self.accepted.as_ref().and_then(|(_, w)| w.sign_pub).unwrap_or([0; 32]);
        let info = match self.ctx.check_receipt(r, &pk) {
            Ok(i) => Some(i),
            Err((code, info)) => {
                let gateway_sig = self.ctx.dispute_sig(&code);
                let d = pb::ReceiptDispute { task: self.task_id.clone(), attempt: r.attempt, code: code.clone(), gateway_sig };
                if let Some(l) = self.node.link() {
                    let _ = l.up.try_send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::Dispute(d)) });
                }
                log("warn", "receipt disputed", &json!({"task": self.task_id, "code": code}));
                info
            }
        };
        self.cost = info.as_ref().map(|i| i.cost_uusd);
        let _ = self.tx.send(TaskEv::End { cost_uusd: self.cost, model: info.map(|i| i.model_reported) }).await;
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
            let s = emit(&self.tx, TaskEv::Bytes(b)).await;
            if !matches!(s, Step::Continue) {
                return s;
            }
        }
        Step::Continue
    }

}

async fn emit(tx: &mpsc::Sender<TaskEv>, ev: TaskEv) -> Step {
    if tx.send(ev).await.is_err() { Step::Gone } else { Step::Continue }
}
