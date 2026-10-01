//! Gateway task pipeline shared by the API door and the MCP door (07 §4.2).
//!
//! Relay path: route header (worker `analyze`, permissive) → inner payload signed with the
//! device key → zstd + chunk AEAD under a fresh CK → HPKE wraps for ≤ 8 owner-approved workers →
//! one gRPC `Submit` stream → decrypt the accepted attempt only → tool-call gate held until a
//! verified checkpoint → receipt verified against our own commitments (silence or a signed
//! dispute). Offline: canned stub response. Dropping the receiver cancels the task.

use crate::engine::{self, DetailCtx, Dialect, Failure};
use crate::gate::Gate;
use crate::node::{Busy, Keys, Node, PoolWorker, RepoPool};
use crate::pb::link::{self as pb, SubmitDown, SubmitUp, submit_down, submit_up};
use crate::pb::local::JournalEntry;
use crate::util::{clean, log, now_ms};
use bytes::Bytes;
use moochy_proto::crypto::{self, ContentKey, ResponseOpener, SaltName};
use moochy_proto::money::CatalogEntry;
use moochy_proto::msg::{InnerPayload, ReceiptStatus};
use moochy_proto::{DeviceId, TaskId};
use moochy_worker::firewall::Facts;
use serde_json::json;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;

pub struct TaskReq {
    pub slug: String,
    pub dialect: Dialect,
    /// Exact body sent to the donor (scrubbed, otherwise as the client sent it).
    pub body: Bytes,
    /// Session-affinity key (HMAC under the device secret, 04 §5).
    pub affinity: [u8; 16],
    pub facts: Facts,
    pub entry: CatalogEntry,
    /// Allowlisted provider headers (`anthropic-version`, `anthropic-beta`).
    pub headers: Vec<(String, String)>,
    /// Unix µs when the client request was received (E22 timing).
    pub t_client_rx: u64,
}

pub enum TaskEv {
    /// Provider answered (no failover after this point).
    Started { task_id: String, donor: String },
    Bytes(Bytes),
    End { cost_uusd: Option<u64>, model: Option<String> },
    Failed(Failure),
}

const MAX_WRAPS: usize = 8;

pub fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

pub async fn submit(node: &Arc<Node>, req: TaskReq) -> Result<mpsc::Receiver<TaskEv>, Failure> {
    let offered = |p: &RepoPool| p.models().iter().any(|(m, ds)| *m == req.entry.model && ds.iter().any(|d| d == req.dialect.wire()));
    node.settle_pool(&req.slug, offered).await;
    let pool = node.pool_for(&req.slug);
    if let Some(p) = &pool
        && !p.models().iter().any(|(m, ds)| *m == req.entry.model && ds.iter().any(|d| d == req.dialect.wire()))
    {
        return Err(Failure::new("model_not_in_pool", false, format!("moochy: model `{}` is not offered by this repo's donor pool", req.entry.model)));
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

/// `up --offline`: canned stub response, no provider call.
fn run_local(node: &Arc<Node>, req: TaskReq) -> mpsc::Receiver<TaskEv> {
    let (tx, rx) = mpsc::channel(4);
    let task_id = TaskId::new(now_ms()).map(|t| t.text()).unwrap_or_default();
    let body = engine::stub_body(req.dialect, req.facts.stream, &req.entry.model, &format!("stub response from {}", req.entry.model));
    let node = node.clone();
    tokio::spawn(async move {
        let t0 = now_ms();
        for ev in [TaskEv::Started { task_id: task_id.clone(), donor: "local".into() }, TaskEv::Bytes(body), TaskEv::End { cost_uusd: Some(0), model: None }] {
            if tx.send(ev).await.is_err() {
                return;
            }
        }
        journal(&node, &task_id, &req.slug, &req.entry.model, "ok", Some(0), t0);
    });
    rx
}

/// Affinity worker first, then the best `hint`s, ≤ 8 wraps (04 §7).
fn pick(pool: &RepoPool, dialect: Dialect, model: &str, sticky: Option<&str>) -> Vec<PoolWorker> {
    let mut c: Vec<&PoolWorker> =
        pool.workers.iter().filter(|w| w.models.iter().any(|m| m == model) && w.dialects.iter().any(|d| d == dialect.wire())).collect();
    c.sort_by_key(|w| (Some(w.worker_device.as_str()) != sticky, std::cmp::Reverse(w.hint)));
    c.into_iter().take(MAX_WRAPS).cloned().collect()
}

fn wraps(ws: &[PoolWorker], task: &TaskId, route: &[u8], ck: &ContentKey) -> Vec<pb::Wrap> {
    ws.iter()
        .filter_map(|w| crypto::wrap(&w.enc_pub, task, route, ck).ok().map(|x| pb::Wrap { worker_device: w.worker_device.clone(), wrap: Bytes::copy_from_slice(&x) }))
        .collect()
}

fn up(m: submit_up::Msg) -> SubmitUp {
    SubmitUp { msg: Some(m) }
}

fn internal(e: impl std::fmt::Debug) -> Failure {
    Failure::new("internal", true, format!("moochy: internal error ({e:?})"))
}

async fn run_relay(node: &Arc<Node>, req: TaskReq, pool: RepoPool) -> Result<mpsc::Receiver<TaskEv>, Failure> {
    let keys = node.keys.as_ref().ok_or_else(|| Failure::new("not_logged_in", false, "moochy: run `moochy login` first".to_owned()))?;
    let link = node.link_now(std::time::Duration::from_secs(3)).await.ok_or_else(|| Failure::new("overloaded", true, "moochy: relay link is down".to_owned()))?;
    let t0 = now_ms();
    let aff = req.affinity;
    let header = engine::route_header(&req.entry, req.dialect, &req.facts, &pool.repo_id, aff)?;
    let route = header.to_bytes().map_err(internal)?;
    let sticky = node.session_worker(&aff);
    let chosen = pick(&pool, req.dialect, &req.entry.model, sticky.as_deref());
    if chosen.is_empty() {
        return Err(Failure::new("model_not_in_pool", false, format!("moochy: no donor offers `{}` for {}", req.entry.model, req.slug)));
    }
    let task = TaskId::new(now_ms()).map_err(internal)?;
    let ck = ContentKey::random().map_err(internal)?;
    let s = crypto::random32().map_err(internal)?;
    // HPKE wraps (X25519, ~100 µs each) run on a blocking thread while the body is signed and
    // sealed (CONTRACT §13 row 1).
    let wrap_job = {
        let (ws, route, ck) = (chosen.clone(), route.clone(), ck.clone());
        tokio::task::spawn_blocking(move || wraps(&ws, &task, &route, &ck))
    };
    let headers: BTreeMap<String, String> = req.headers.iter().cloned().collect();
    let ctx = crypto::TaskContext { task: &task, repo: &header.repo_id, route: &route };
    let inner = InnerPayload::build(&ctx, req.body.to_vec(), headers, s, keys.device_id, &keys.sign).map_err(internal)?;
    let sealed = crypto::seal_request(&ck, &task, &inner.to_bytes().map_err(internal)?).map_err(internal)?;
    drop(inner);
    let first_wraps = wrap_job.await.map_err(internal)?;
    let n = sealed.chunks.len();
    let (up_tx, up_rx) = mpsc::channel::<SubmitUp>(n.saturating_add(4));
    let open = pb::SubmitOpen {
        task: task.text(),
        route: Bytes::from(route),
        wraps: first_wraps,
        body_len: sealed.body_len,
        body_chunks: u32::try_from(n).unwrap_or(u32::MAX),
    };
    let route = open.route.clone();
    let _ = up_tx.try_send(up(submit_up::Msg::Open(open)));
    for c in sealed.chunks {
        let _ = up_tx.try_send(up(submit_up::Msg::Body(crate::pb::from_proto(c))));
    }
    // E22: stamp the moment the transport takes the first body chunk.
    let first_tx = Arc::new(AtomicU64::new(0));
    let stamp = first_tx.clone();
    let outbound = ReceiverStream::new(up_rx).map(move |m| {
        if matches!(m.msg, Some(submit_up::Msg::Body(_))) && stamp.load(Ordering::Relaxed) == 0 {
            stamp.store(now_us(), Ordering::Relaxed);
        }
        m
    });
    let mut client = link.client.clone();
    let down = client
        .submit(crate::link::with_session(&link, outbound))
        .await
        .map_err(|s| Failure::new("overloaded", true, format!("moochy: relay refused the task ({:?})", s.code())))?
        .into_inner();
    let (tx, rx) = mpsc::channel(16);
    let ttl = if req.facts.cache_ttl == moochy_worker::firewall::CacheTtl::H1 { 3_600_000 } else { 300_000 };
    let drv = Driver {
        node: node.clone(),
        task_text: task.text(),
        task,
        ck,
        s,
        body: req.body.clone(),
        repo_id: pool.repo_id.clone(),
        route,
        gate: Gate::new(req.dialect, req.facts.stream, &req.body),
        pool,
        tx,
        up: up_tx,
        acc: None,
        started: false,
        hashes: VecDeque::new(),
        verified: None,
        last_seq: None,
        cost: None,
        model: None,
        closed: false,
    };
    let (slug, model, t_rx) = (req.slug, req.entry.model, req.t_client_rx);
    tokio::spawn(async move {
        let node = drv.node.clone();
        let _busy = Busy::new(&node.gateway_tasks);
        let task_id = drv.task_text.clone();
        let (status, cost) = drv.run(down, aff, ttl).await;
        log("info", "timing", &json!({"task": task_id, "t_client_rx": t_rx, "t_first_sealed_tx": first_tx.load(Ordering::Relaxed)}));
        if status != "ok" {
            log("warn", "task failed", &json!({"task": task_id, "code": status}));
        }
        journal(&node, &task_id, &slug, &model, &status, cost, t0);
    });
    Ok(rx)
}

struct Accepted {
    attempt: u8,
    worker: PoolWorker,
    r: [u8; 32],
    opener: ResponseOpener,
}

struct Driver {
    node: Arc<Node>,
    task: TaskId,
    task_text: String,
    ck: ContentKey,
    s: [u8; 32],
    body: Bytes,
    repo_id: String,
    route: Bytes,
    gate: Gate,
    pool: RepoPool,
    tx: mpsc::Sender<TaskEv>,
    /// Kept open for `Wraps` / `Cancel`; dropping it half-closes the stream.
    up: mpsc::Sender<SubmitUp>,
    acc: Option<Accepted>,
    started: bool,
    /// Running hash after each chunk, for checkpoint verification (bounded).
    hashes: VecDeque<(u32, [u8; 32])>,
    verified: Option<u32>,
    last_seq: Option<u32>,
    cost: Option<u64>,
    model: Option<String>,
    /// The client stream was already completed (last chunk in, nothing held).
    closed: bool,
}

enum Step {
    Continue,
    Done,
    Fail(Failure),
    /// The client went away: cancel upstream.
    Gone,
}

fn retry_fail(code: &str, msg: &str) -> Step {
    Step::Fail(Failure::new(code, true, format!("moochy: {msg}")))
}

impl Driver {
    /// Returns `(journal status, cost)`.
    async fn run(mut self, mut down: tonic::Streaming<SubmitDown>, aff: [u8; 16], ttl: u64) -> (String, Option<u64>) {
        let step = loop {
            let m = tokio::select! {
                m = down.message() => m,
                () = self.tx.closed(), if !self.closed => break Step::Gone,
            };
            let step = match m {
                Ok(Some(SubmitDown { msg: Some(m) })) => self.on_msg(m).await,
                Ok(Some(SubmitDown { msg: None })) => Step::Continue,
                Ok(None) | Err(_) => retry_fail("overloaded", "relay link lost"),
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
                    log("error", "bad_envelope", &json!({"task": self.task_text, "why": f.detail}));
                    let _ = self.up.try_send(up(submit_up::Msg::Cancel(pb::Cancel { reason: "bad_envelope".into() })));
                }
                let status = format!("failed:{}", f.code);
                let _ = self.tx.send(TaskEv::Failed(f)).await;
                (status, None)
            }
            Step::Done | Step::Continue => {
                if let Some(a) = &self.acc {
                    self.node.session_set(aff, a.worker.worker_device.clone(), ttl);
                }
                ("ok".into(), self.cost)
            }
        }
    }

    async fn on_msg(&mut self, m: submit_down::Msg) -> Step {
        let current = self.acc.as_ref().map(|a| u32::from(a.attempt));
        match m {
            submit_down::Msg::NeedWraps(n) => {
                let ws: Vec<PoolWorker> = self.pool.workers.iter().filter(|w| n.workers.contains(&w.worker_device)).take(MAX_WRAPS).cloned().collect();
                let w = wraps(&ws, &self.task, &self.route, &self.ck);
                let _ = self.up.send(up(submit_up::Msg::Wraps(pb::Wraps { wraps: w }))).await;
                Step::Continue
            }
            submit_down::Msg::Accepted(a) => self.on_accepted(&a),
            submit_down::Msg::Started(s) if Some(s.attempt) == current => {
                self.started = true;
                let donor = self.acc.as_ref().map(|a| a.worker.donor.clone()).unwrap_or_default();
                emit(&self.tx, TaskEv::Started { task_id: self.task_text.clone(), donor }).await
            }
            submit_down::Msg::Chunk(c) => self.on_chunk(c).await,
            submit_down::Msg::Checkpoint(c) if Some(c.attempt) == current => self.on_checkpoint(&c).await,
            submit_down::Msg::End(r) if Some(r.attempt) == current => self.on_end(&r).await,
            submit_down::Msg::Failed(f) => {
                let code = clean(&f.code).into_owned();
                let detail = self.acc.as_ref().and_then(|a| {
                    let t16 = self.task.0.0;
                    let c = DetailCtx { ck: self.ck.expose(), r: &a.r, task: &self.task_text, task16: &t16, worker: &a.worker.worker_device, attempt: u32::from(a.attempt) };
                    engine::open_detail(&c, &code, &f.sealed_detail)
                });
                let mut fl = Failure::new(&code, f.retryable, detail);
                fl.retry_after_ms = (f.retry_after_ms > 0).then_some(u64::from(f.retry_after_ms));
                Step::Fail(fl)
            }
            _ => Step::Continue,
        }
    }

    fn on_accepted(&mut self, a: &pb::Accepted) -> Step {
        if self.started {
            // A second attempt after start is only possible through a relay bug or attack (03 §6.3).
            return retry_fail("bad_envelope", "second attempt after start");
        }
        let Some(w) = self.pool.workers.iter().find(|w| w.worker_device == a.worker_device) else {
            return retry_fail("unauthorized_task", "relay accepted the task for an unknown worker");
        };
        let (Ok(attempt), Ok(r), Ok(dev)) = (u8::try_from(a.attempt), <[u8; 32]>::try_from(a.r.as_ref()), a.worker_device.parse::<DeviceId>()) else {
            return retry_fail("bad_envelope", "malformed acceptance");
        };
        if !(1..=moochy_proto::msg::MAX_ATTEMPTS).contains(&attempt) {
            return retry_fail("bad_envelope", "attempt out of range");
        }
        if let Some(prev) = &self.acc {
            log("warn", "acceptance replaced", &json!({"task": self.task_text, "old": prev.attempt, "new": attempt, "same_r": prev.r == r}));
        }
        let Ok(opener) = ResponseOpener::new(&self.ck, &r, &self.task, &dev, attempt) else { return retry_fail("internal", "opener") };
        self.acc = Some(Accepted { attempt, worker: w.clone(), r, opener });
        Step::Continue
    }

    async fn on_chunk(&mut self, c: pb::Chunk) -> Step {
        let Some(a) = &mut self.acc else {
            log("warn", "chunk before acceptance dropped", &json!({"task": self.task_text, "attempt": c.attempt, "seq": c.seq}));
            return Step::Continue;
        };
        if c.attempt != u32::from(a.attempt) {
            return if self.started { retry_fail("bad_envelope", "frames from another attempt") } else { Step::Continue };
        }
        let seq = c.seq;
        let pt = match a.opener.open(crate::pb::to_proto(c)) {
            Ok(pt) => pt,
            Err(e) => {
                let why = format!("response failed authentication ({e:?} at seq {seq}); retry");
                return retry_fail("bad_envelope", &why);
            }
        };
        if self.hashes.len() >= 4096 {
            self.hashes.pop_front();
        }
        self.hashes.push_back((seq, a.opener.running_hash()));
        self.last_seq = Some(seq);
        if let Err(why) = self.gate.push(seq, &pt) {
            return retry_fail("provider_error", why);
        }
        let s = self.flush(false).await;
        if matches!(s, Step::Continue) { self.try_close().await } else { s }
    }

    /// Complete the client stream as soon as the response is whole and every held tool block is
    /// covered by a verified checkpoint, without waiting for the receipt (checked when it comes).
    async fn try_close(&mut self) -> Step {
        let complete = self.acc.as_ref().is_some_and(|a| a.opener.is_complete());
        let covered = self.last_seq.is_some() && self.verified >= self.last_seq;
        if self.closed || !complete || (self.gate.holds_tools() && !covered) {
            return Step::Continue;
        }
        if let Err(why) = self.gate.finish(covered) {
            return retry_fail("provider_error", why);
        }
        let s = self.flush(true).await;
        if !matches!(s, Step::Continue) {
            return s;
        }
        self.closed = true;
        emit(&self.tx, TaskEv::End { cost_uusd: None, model: None }).await
    }

    async fn on_checkpoint(&mut self, c: &pb::Checkpoint) -> Step {
        let Some(a) = &self.acc else { return Step::Continue };
        let ours = self.hashes.iter().find(|(s, _)| *s == c.seq).map(|(_, h)| *h);
        let ok = match (a.worker.sign_pub, ours, <[u8; 64]>::try_from(c.sig.as_ref())) {
            (Some(pk), Some(h), Ok(sig)) => crypto::checkpoint_msg(&self.task, a.attempt, &a.r, c.seq, &h).is_ok_and(|m| crypto::verify(&pk, &m, &sig).is_ok()),
            _ => false,
        };
        if !ok {
            log("warn", "checkpoint rejected", &json!({"task": self.task_text}));
            return Step::Continue;
        }
        self.verified = Some(self.verified.map_or(c.seq, |v| v.max(c.seq)));
        let s = self.flush(false).await;
        if matches!(s, Step::Continue) { self.try_close().await } else { s }
    }

    /// Verify the receipt against what we sent and received; `Err(code)` = dispute.
    fn check_receipt(&self, r: &pb::SignedReceipt) -> Result<(u64, String), &'static str> {
        let a = self.acc.as_ref().ok_or("no_attempt")?;
        let keys: &Keys = self.node.keys.as_ref().ok_or("no_keys")?;
        let pk = a.worker.sign_pub.ok_or("unknown_worker_key")?;
        let sig = <[u8; 64]>::try_from(r.donor_sig.as_ref()).map_err(|_| "bad_signature")?;
        let rc = crypto::open_receipt(&pk, &r.receipt, &sig).map_err(|_| "bad_signature")?;
        let s_req = crypto::salt(&self.s, SaltName::Req).map_err(|_| "internal")?;
        let s_resp = crypto::salt(&self.s, SaltName::Resp).map_err(|_| "internal")?;
        let same = rc.task_id == self.task
            && rc.attempt == a.attempt
            && rc.worker_device.text() == a.worker.worker_device
            && rc.gateway_device == keys.device_id
            && rc.repo_id.text() == self.repo_id;
        if !same {
            return Err("receipt_mismatch");
        }
        if crypto::req_commit(&s_req, &self.body).ok() != Some(rc.req_commit.0) {
            return Err("req_commit_mismatch");
        }
        if rc.status == ReceiptStatus::Ok
            && (!a.opener.is_complete() || crypto::resp_commit(&s_resp, &a.opener.running_hash()).ok() != Some(rc.resp_commit.0))
        {
            return Err("resp_commit_mismatch");
        }
        let psig = <[u8; 64]>::try_from(r.projection_sig.as_ref()).map_err(|_| "bad_signature")?;
        let p = crypto::open_projection(&pk, &r.projection, &psig).map_err(|_| "bad_signature")?;
        if p.receipt_sha256.0 != crypto::sha256(&r.receipt) || p.cost_uusd != rc.cost_uusd {
            return Err("projection_mismatch");
        }
        Ok((u64::try_from(rc.cost_uusd).unwrap_or(0), rc.model_reported))
    }

    async fn on_end(&mut self, r: &pb::SignedReceipt) -> Step {
        if !self.closed {
            let all = self.last_seq.is_some() && self.verified >= self.last_seq;
            if let Err(why) = self.gate.finish(all) {
                return retry_fail("provider_error", why);
            }
            let flushed = self.flush(true).await;
            if !matches!(flushed, Step::Continue) {
                return flushed;
            }
        }
        match self.check_receipt(r) {
            Ok((cost, model)) => {
                self.cost = Some(cost);
                self.model = Some(model);
            }
            Err(code) => {
                if let (Some(a), Some(keys)) = (&self.acc, &self.node.keys) {
                    let gateway_sig = crypto::dispute_msg(&self.task, a.attempt, code).map(|m| Bytes::copy_from_slice(&keys.sign.sign(&m))).unwrap_or_default();
                    let d = pb::ReceiptDispute { task: self.task_text.clone(), attempt: r.attempt, code: code.into(), gateway_sig };
                    if let Some(l) = self.node.link() {
                        let _ = l.up.try_send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::Dispute(d)) });
                    }
                }
                log("warn", "receipt disputed", &json!({"task": self.task_text, "code": code}));
            }
        }
        let _ = self.tx.send(TaskEv::End { cost_uusd: self.cost, model: self.model.clone() }).await;
        Step::Done
    }

    async fn flush(&mut self, finale: bool) -> Step {
        while let Some(b) = self.gate.pop(self.verified, finale) {
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

#[cfg(test)]
mod bench {
    use super::*;
    use std::time::Instant;

    /// `cargo test --release -p moochy -- --ignored --nocapture hot_path`: per-step cost of the
    /// Gateway path request → first sealed byte on a 100 KB body (CONTRACT §13 row 1).
    #[test]
    #[ignore = "benchmark"]
    fn hot_path() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(2300);
        let body = json!({"model":"anthropic/claude-sonnet-5.5","max_tokens":256,"stream":true,"messages":[{"role":"user","content":text}]}).to_string().into_bytes();
        let entry = engine::Catalog::stub().entries[0].clone();
        let entry = CatalogEntry { model: "anthropic/claude-sonnet-5.5".into(), ..entry };
        let sign = crypto::SignKey::generate().unwrap();
        let enc = crypto::EncSecret::generate().unwrap();
        let n = 200u32;
        let mut t = [0u128; 7];
        for _ in 0..n {
            let mut s = Instant::now();
            let mut lap = |i: usize, s: &mut Instant| {
                t[i] += s.elapsed().as_nanos();
                *s = Instant::now();
            };
            let b = crate::scrub::scrub(&body).unwrap_or_else(|| body.clone());
            lap(0, &mut s);
            let mut tape = Vec::new();
            let _ = moochy_worker::json::parse(&b, &mut tape).unwrap().root();
            lap(1, &mut s);
            let f = engine::analyze(&entry, Dialect::Anthropic, &b, &[]).unwrap();
            lap(2, &mut s);
            let h = engine::route_header(&entry, Dialect::Anthropic, &f, "r_01ARZ3NDEKTSV4RRFFQ69G5FAV", [0; 16]).unwrap();
            let route = h.to_bytes().unwrap();
            let task = TaskId::new(now_ms()).unwrap();
            let ck = ContentKey::random().unwrap();
            let ctx = crypto::TaskContext { task: &task, repo: &h.repo_id, route: &route };
            let inner = InnerPayload::build(&ctx, b.clone(), BTreeMap::new(), [1; 32], "d_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap(), &sign).unwrap();
            lap(3, &mut s);
            let p = inner.to_bytes().unwrap();
            lap(4, &mut s);
            let _ = crypto::seal_request(&ck, &task, &p).unwrap();
            lap(5, &mut s);
            let _ = crypto::wrap(&enc.public(), &task, &route, &ck).unwrap();
            lap(6, &mut s);
        }
        let s0 = Instant::now();
        for _ in 0..n {
            let _ = crypto::sha256(&body);
        }
        println!("sha256 100KB (sha2 via moochy-proto): {} µs", s0.elapsed().as_nanos() / u128::from(n) / 1000);
        let names = ["scrub", "tape parse", "analyze", "route+sign", "payload json", "zstd+seal", "hpke wrap"];
        for (i, nm) in names.iter().enumerate() {
            println!("{nm:>14}: {:>7} µs", t[i] / u128::from(n) / 1000);
        }
    }
}
