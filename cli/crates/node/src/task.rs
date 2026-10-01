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
use crate::util::{b64e, clean, log, now_ms};
use bytes::Bytes;
use moochy_proto::crypto::{self, ContentKey, ResponseOpener, SaltName};
use moochy_proto::money::CatalogEntry;
use moochy_proto::msg::{InnerPayload, ReceiptStatus};
use moochy_proto::{DeviceId, TaskId};
use moochy_worker::firewall::Facts;
use serde_json::{Value, json};
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
    /// §15.4: tool calls may reach this client (sandboxed run token or project opt-in).
    pub release_tools: bool,
    /// What `firewall::pool_compatible` removed (shown to the client as a `[moochy]` note).
    pub stripped: Vec<String>,
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
        return Err(Failure::new("model_not_in_pool", false, format!("moochy: no donor offers model `{}` to this project (model_not_in_pool)", req.entry.model)));
    }
    if node.offline {
        return Ok(run_local(node, req));
    }
    let pool = pool.ok_or_else(|| Failure::new("no_pool", true, format!("moochy: no donations loaded yet for {}; retry in a moment", req.slug)))?;
    run_relay(node, req, pool).await
}

/// Bound on the plaintext kept per task (evidence bundle, opt-in journal text).
const MAX_EVIDENCE: usize = 1 << 20;
const MAX_JOURNAL_TEXT: usize = 64 << 10;

/// What `moochy report` packages for a consumed task (06 §9): never the request.
pub struct Evidence {
    pub task: String,
    pub attempt: u32,
    pub worker_device: String,
    /// The worker's signing key the receipt was verified with (for `moochy verify`).
    pub worker_sign_pub: Option<[u8; 32]>,
    pub receipt: pb::SignedReceipt,
    pub checkpoints: Vec<pb::Checkpoint>,
    pub response: Vec<Bytes>,
    pub truncated: bool,
    pub s_resp: [u8; 32],
}

/// `moochy verify <receipt_ref>`: check a public receipt (projection) of a task this Gateway
/// consumed: the donor's signature over it, that it commits to the signed receipt, and, with a
/// pinned key log, that the signing key is a logged key of that donor device.
pub fn verify(node: &Node, receipt_ref: &str) -> Result<Value, String> {
    let want = crate::util::b64d(receipt_ref.strip_prefix("r_").unwrap_or(receipt_ref)).filter(|b| b.len() == 16).ok_or("not a receipt reference")?;
    let ev = crate::node::lock(&node.evidence);
    for e in ev.iter() {
        let (Some(pk), Ok(psig)) = (e.worker_sign_pub, <[u8; 64]>::try_from(e.receipt.projection_sig.as_ref())) else { continue };
        let Ok(p) = crypto::open_projection(&pk, &e.receipt.projection, &psig) else { continue };
        if p.receipt_ref.0[..] != want[..] {
            continue;
        }
        let sig = <[u8; 64]>::try_from(e.receipt.donor_sig.as_ref()).map_err(|_| "bad receipt signature")?;
        crypto::open_receipt(&pk, &e.receipt.receipt, &sig).map_err(|_| "the receipt signature does not verify")?;
        if p.receipt_sha256.0 != crypto::sha256(&e.receipt.receipt) {
            return Err("the public receipt does not commit to the signed receipt".into());
        }
        let key_log = match node.keylog.as_ref().filter(|l| l.active()) {
            Some(l) if l.device_by_key(&pk).as_deref() == Some(e.worker_device.as_str()) => "logged",
            Some(_) => return Err("the donor key is not in the public key log".into()),
            None => "not checked (no key log pinned)",
        };
        return Ok(json!({"verified": true, "receipt_ref": receipt_ref, "repo_id": p.repo_id.text(), "donor": p.donor, "model": p.model,
            "cost_uusd": p.cost_uusd, "day": p.day, "worker_device": e.worker_device, "key_log": key_log}));
    }
    Err("no receipt with this reference among this device's recent requests".into())
}

impl Evidence {
    pub fn bundle(&self, reason: &str) -> Value {
        let resp: Vec<u8> = self.response.iter().flat_map(|b| b.iter().copied()).collect();
        json!({
            "v": 1, "kind": "moochy.evidence", "reason": crate::util::clean(reason), "task": self.task, "attempt": self.attempt,
            "worker_device": self.worker_device,
            "receipt": {"receipt_b64": b64e(&self.receipt.receipt), "donor_sig": b64e(&self.receipt.donor_sig),
                "projection_b64": b64e(&self.receipt.projection), "projection_sig": b64e(&self.receipt.projection_sig)},
            "checkpoints": self.checkpoints.iter().map(|c| json!({"attempt": c.attempt, "seq": c.seq, "running_hash": b64e(&c.running_hash), "sig": b64e(&c.sig)})).collect::<Vec<_>>(),
            "response_b64": b64e(&resp), "response_truncated": self.truncated,
            // Only the response salt: it opens resp_commit and reveals nothing about the request.
            "S_resp": b64e(&self.s_resp),
        })
    }
}

fn clip(parts: &[Bytes]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        let room = MAX_JOURNAL_TEXT.saturating_sub(v.len());
        v.extend_from_slice(p.get(..room.min(p.len())).unwrap_or_default());
    }
    v
}

fn journal(node: &Node, task: &str, slug: &str, model: &str, status: &str, cost: Option<u64>, t0: u64) {
    journal_text(node, task, slug, model, status, cost, t0, None);
}

/// Journal entry; `text` = (request, response) only when `journal_full_text` is on (opt-in).
#[allow(clippy::too_many_arguments)]
fn journal_text(node: &Node, task: &str, slug: &str, model: &str, status: &str, cost: Option<u64>, t0: u64, text: Option<(&Bytes, &[Bytes])>) {
    let (request, response) = match text.filter(|_| node.cfg.journal_full_text) {
        Some((rq, rs)) => (clip(std::slice::from_ref(rq)), clip(rs)),
        None => (Vec::new(), Vec::new()),
    };
    node.journal(JournalEntry {
        request,
        response,
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

/// §15.4 provider exclusion: never seal to a donor serving through an excluded provider.
/// ponytail: pool workers do not say which provider serves each model yet, so a model that an
/// excluded provider can also serve is refused outright (fail closed); filter per worker in
/// `pick` once `PoolWorker` carries the provider.
fn excluded_check(cat: &engine::Catalog, model: &str, excluded: &[String]) -> Result<(), Failure> {
    if excluded.is_empty() {
        return Ok(());
    }
    let hit: Vec<&str> = cat.entries.iter().filter(|e| e.model == model && excluded.iter().any(|x| x == &e.provider)).map(|e| e.provider.as_str()).collect();
    if hit.is_empty() {
        return Ok(());
    }
    Err(Failure::new(
        "forbidden",
        false,
        format!("moochy: this project does not accept donations through {} for `{model}`, and donors of that model cannot be told apart by provider yet", hit.join(", ")),
    ))
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

#[allow(clippy::too_many_lines, reason = "one linear submit sequence; splitting it hides the order")]
async fn run_relay(node: &Arc<Node>, req: TaskReq, pool: RepoPool) -> Result<mpsc::Receiver<TaskEv>, Failure> {
    let keys = node.keys.as_ref().ok_or_else(|| Failure::new("not_logged_in", false, "moochy: run `moochy login` first".to_owned()))?;
    let link = node.link_now(std::time::Duration::from_secs(3)).await.ok_or_else(|| Failure::new("overloaded", true, "moochy: not connected; retry in a moment".to_owned()))?;
    let t0 = now_ms();
    let aff = req.affinity;
    let header = engine::route_header(&req.entry, req.dialect, &req.facts, &pool.repo_id, aff)?;
    let route = header.to_bytes().map_err(internal)?;
    let sticky = node.session_worker(&aff);
    excluded_check(&node.catalog(), &req.entry.model, &pool.excluded_providers)?;
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
        let _ = up_tx.try_send(up(submit_up::Msg::Body(c)));
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
        .map_err(|s| Failure::new("overloaded", true, format!("moochy: the server refused the request ({:?})", s.code())))?
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
        gate: Gate::new(req.dialect, req.facts.stream, &req.body, req.release_tools),
        canon: crate::gate::Canon::new(req.dialect, req.facts.stream),
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
        resp: Vec::new(),
        resp_len: 0,
        truncated: false,
        checkpoints: Vec::new(),
        receipt: None,
        entry: req.entry.clone(),
        est_input: req.facts.est_input_tokens,
        ttl: req.facts.cache_ttl,
    };
    let (slug, model, t_rx, req_body) = (req.slug, req.entry.model, req.t_client_rx, req.body);
    tokio::spawn(async move {
        let node = drv.node.clone();
        let _busy = Busy::new(&node.gateway_tasks);
        let task_id = drv.task_text.clone();
        let (status, cost, ev) = drv.run(down, aff, ttl).await;
        log("info", "timing", &json!({"task": task_id, "t_client_rx": t_rx, "t_first_sealed_tx": first_tx.load(Ordering::Relaxed)}));
        if status != "ok" {
            log("warn", "task failed", &json!({"task": task_id, "code": status}));
        }
        journal_text(&node, &task_id, &slug, &model, &status, cost, t0, Some((&req_body, ev.as_ref().map_or(&[][..], |e| e.response.as_slice()))));
        if let Some(e) = ev {
            node.keep_evidence(e);
        }
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
    /// Canonical re-emission of everything the client receives (§15.4).
    canon: crate::gate::Canon,
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
    /// Evidence for `moochy report`: plaintext chunks (refcounted, bounded), checkpoints, receipt.
    resp: Vec<Bytes>,
    resp_len: usize,
    truncated: bool,
    checkpoints: Vec<pb::Checkpoint>,
    receipt: Option<pb::SignedReceipt>,
    /// What the receipt's usage and model are checked against (03 §12.2).
    entry: CatalogEntry,
    est_input: u64,
    ttl: moochy_worker::firewall::CacheTtl,
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
    /// Returns `(journal status, cost, evidence)`.
    async fn run(mut self, mut down: tonic::Streaming<SubmitDown>, aff: [u8; 16], ttl: u64) -> (String, Option<u64>, Option<Evidence>) {
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
                ("cancelled".into(), None, None)
            }
            Step::Fail(f) => {
                if f.code == "bad_envelope" {
                    log("error", "bad_envelope", &json!({"task": self.task_text, "why": f.detail}));
                    let _ = self.up.try_send(up(submit_up::Msg::Cancel(pb::Cancel { reason: "bad_envelope".into() })));
                }
                let status = format!("failed:{}", f.code);
                let _ = self.tx.send(TaskEv::Failed(f)).await;
                (status, None, None)
            }
            Step::Done | Step::Continue => {
                if let Some(a) = &self.acc {
                    self.node.session_set(aff, a.worker.worker_device.clone(), ttl);
                }
                let ev = self.evidence();
                ("ok".into(), self.cost, ev)
            }
        }
    }

    fn evidence(&mut self) -> Option<Evidence> {
        let receipt = self.receipt.take()?;
        let a = self.acc.as_ref()?;
        let s_resp = *crypto::salt(&self.s, SaltName::Resp).ok()?.expose();
        Some(Evidence {
            task: self.task_text.clone(),
            attempt: u32::from(a.attempt),
            worker_device: a.worker.worker_device.clone(),
            worker_sign_pub: a.worker.sign_pub,
            receipt,
            checkpoints: std::mem::take(&mut self.checkpoints),
            response: std::mem::take(&mut self.resp),
            truncated: self.truncated,
            s_resp,
        })
    }

    async fn on_msg(&mut self, m: submit_down::Msg) -> Step {
        let current = self.acc.as_ref().map(|a| u32::from(a.attempt));
        match m {
            submit_down::Msg::NeedWraps(n) => {
                // The relay sends a fresh PoolSync right before NeedWraps: wrap from the live pool
                // (still approval-filtered), not the snapshot taken at submit (E27).
                if let Some(p) = crate::node::lock(&self.node.pools).get(&self.repo_id) {
                    self.pool = p.clone();
                }
                let ws: Vec<PoolWorker> = self.pool.workers.iter().filter(|w| n.workers.contains(&w.worker_device)).take(MAX_WRAPS).cloned().collect();
                let w = wraps(&ws, &self.task, &self.route, &self.ck);
                let _ = self.up.send(up(submit_up::Msg::Wraps(pb::Wraps { wraps: w }))).await;
                Step::Continue
            }
            submit_down::Msg::Accepted(a) => self.on_accepted(&a),
            submit_down::Msg::Started(s) if Some(s.attempt) == current && !self.started => {
                self.started = true;
                let donor = self.acc.as_ref().map(|a| a.worker.donor.clone()).unwrap_or_default();
                emit(&self.tx, TaskEv::Started { task_id: self.task_text.clone(), donor }).await
            }
            // A second Started, or one for an attempt that is not the accepted one (E49).
            submit_down::Msg::Started(s) => {
                log("warn", "stream_integrity", &json!({"task": self.task_text, "why": "unexpected Started", "attempt": s.attempt}));
                retry_fail("stream_integrity", "the relay sent an unexpected stream start; retry")
            }
            submit_down::Msg::Chunk(c) => self.on_chunk(c).await,
            submit_down::Msg::Checkpoint(c) if Some(c.attempt) == current => self.on_checkpoint(&c).await,
            submit_down::Msg::End(r) if Some(r.attempt) == current => self.on_end(&r).await,
            submit_down::Msg::Failed(f) => {
                let code = clean(&f.code).into_owned();
                // The relay names the refusing attempt (worker + R): derive K_det for it (CONTRACT §3).
                let t16 = self.task.0.0;
                let detail = <[u8; 32]>::try_from(f.r.as_ref())
                    .ok()
                    .filter(|_| f.attempt > 0 && !f.worker_device.is_empty())
                    .and_then(|r| {
                        let c = DetailCtx { ck: self.ck.expose(), r: &r, task: &self.task_text, task16: &t16, worker: &f.worker_device, attempt: f.attempt };
                        engine::open_detail(&c, &code, &f.sealed_detail)
                    })
                    .or_else(|| {
                        self.acc.as_ref().and_then(|a| {
                            let c = DetailCtx { ck: self.ck.expose(), r: &a.r, task: &self.task_text, task16: &t16, worker: &a.worker.worker_device, attempt: u32::from(a.attempt) };
                            engine::open_detail(&c, &code, &f.sealed_detail)
                        })
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
        let pt = match a.opener.open(c) {
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
        if self.resp_len.saturating_add(pt.len()) <= MAX_EVIDENCE {
            self.resp_len = self.resp_len.saturating_add(pt.len());
            self.resp.push(pt.clone());
        } else {
            self.truncated = true;
        }
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
        // Non-streamed responses wait for the receipt: it carries x-moochy-cost-uusd.
        if self.closed || !self.gate.is_stream() || !complete || (self.gate.holds_tools() && !covered) {
            return Step::Continue;
        }
        if !self.gate.ended() {
            return retry_fail("provider_error", "the donor's provider stopped mid-response");
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
        if self.checkpoints.len() < 4096 {
            self.checkpoints.push(c.clone());
        }
        let s = self.flush(false).await;
        if matches!(s, Step::Continue) { self.try_close().await } else { s }
    }

    /// Verify the receipt against what we sent and received; `Err(code)` = dispute.
    /// `Ok((cost, model, Some(code), status_ok))`: `Some(code)` = authentic receipt whose usage or
    /// model disagrees with the request; money still settles but the receipt is disputed.
    fn check_receipt(&self, r: &pb::SignedReceipt) -> Result<(u64, String, Option<&'static str>, bool), &'static str> {
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
        let soft = usage_mismatch(&rc.usage, &rc.model_reported, &self.entry, self.est_input, self.ttl == moochy_worker::firewall::CacheTtl::H1);
        Ok((u64::try_from(rc.cost_uusd).unwrap_or(0), rc.model_reported, soft, rc.status == ReceiptStatus::Ok))
    }

    async fn on_end(&mut self, r: &pb::SignedReceipt) -> Step {
        self.receipt = Some(r.clone());
        let checked = self.check_receipt(r);
        if !self.closed {
            // Integrity before the client sees the end (E49): an authentic receipt that matches
            // what we received, and the whole stream.
            if let Err(code) = checked {
                self.dispute(r.attempt, code);
                log("warn", "stream_integrity", &json!({"task": self.task_text, "why": code}));
                return retry_fail("stream_integrity", "the donor's receipt does not match the response; retry");
            }
            if !self.acc.as_ref().is_some_and(|a| a.opener.is_complete()) {
                if matches!(checked, Ok((_, _, _, true))) {
                    log("warn", "stream_integrity", &json!({"task": self.task_text, "why": "stream ended before its last chunk"}));
                    return retry_fail("stream_integrity", "the response ended before its last chunk; retry");
                }
                return retry_fail("provider_error", "the donor's provider stopped mid-response");
            }
            if !self.gate.ended() {
                return retry_fail("provider_error", "the donor's provider stopped mid-response");
            }
            let all = self.last_seq.is_some() && self.verified >= self.last_seq;
            if let Err(why) = self.gate.finish(all) {
                return retry_fail("provider_error", why);
            }
            let flushed = self.flush(true).await;
            if !matches!(flushed, Step::Continue) {
                return flushed;
            }
        }
        let code = match checked {
            Ok((cost, model, soft, _)) => {
                self.cost = Some(cost);
                self.model = Some(model);
                soft
            }
            Err(code) => Some(code),
        };
        if let Some(code) = code {
            self.dispute(r.attempt, code);
        }
        let _ = self.tx.send(TaskEv::End { cost_uusd: self.cost, model: self.model.clone() }).await;
        Step::Done
    }

    /// Signed `ReceiptDispute` (03 §12.2); money still settles.
    fn dispute(&self, attempt: u32, code: &str) {
        if let (Some(a), Some(keys)) = (&self.acc, &self.node.keys) {
            let gateway_sig = crypto::dispute_msg(&self.task, a.attempt, code).map(|m| Bytes::copy_from_slice(&keys.sign.sign(&m))).unwrap_or_default();
            let d = pb::ReceiptDispute { task: self.task_text.clone(), attempt, code: code.into(), gateway_sig };
            if let Some(l) = self.node.link() {
                let _ = l.up.try_send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::Dispute(d)) });
            }
        }
        log("warn", "receipt disputed", &json!({"task": self.task_text, "code": code}));
    }

    async fn flush(&mut self, finale: bool) -> Step {
        while let Some(b) = self.gate.pop(self.verified, finale) {
            let b = match self.canon.push(&b) {
                Ok(b) => b,
                Err(why) => return retry_fail("provider_error", why),
            };
            if b.is_empty() {
                continue;
            }
            let s = emit(&self.tx, TaskEv::Bytes(b)).await;
            if !matches!(s, Step::Continue) {
                return s;
            }
        }
        if finale {
            match self.canon.finish() {
                Ok(b) if b.is_empty() => {}
                Ok(b) => return emit(&self.tx, TaskEv::Bytes(b)).await,
                Err(why) => return retry_fail("provider_error", why),
            }
        }
        Step::Continue
    }
}

/// Usage and model checks of 03 §12.2 on an authentic receipt. The input band is generous
/// (2× the pessimistic `ceil(bytes/3)` estimate + 4096 for provider-side tool/system prompts),
/// so only real inflation is disputed.
/// ponytail: visible-output ±25% check skipped (needs a tokenizer); add with one.
fn usage_mismatch(u: &moochy_proto::msg::Usage, model: &str, entry: &CatalogEntry, est_input: u64, ttl_1h: bool) -> Option<&'static str> {
    let total_in = u.input.saturating_add(u.cache_write_5m).saturating_add(u.cache_write_1h).saturating_add(u.cache_read);
    if total_in > est_input.saturating_mul(2).saturating_add(4096) {
        return Some("usage_input_out_of_band");
    }
    if u.cache_write_1h > 0 && !ttl_1h {
        return Some("cache_write_1h_without_1h_ttl");
    }
    let m = model;
    let ids = || std::iter::once(entry.provider_model_id.as_str()).chain(std::iter::once(entry.model.as_str())).chain(entry.aliases.iter().map(String::as_str));
    // Exact id, or a dated snapshot of it (`claude-sonnet-5-5-20260514`).
    let dated = |id: &str| m.strip_prefix(id).and_then(|r| r.strip_prefix('-')).is_some_and(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit() || c == b'-'));
    if !ids().any(|id| m == id || dated(id)) {
        return Some("model_mismatch");
    }
    None
}

async fn emit(tx: &mpsc::Sender<TaskEv>, ev: TaskEv) -> Step {
    if tx.send(ev).await.is_err() { Step::Gone } else { Step::Continue }
}

#[cfg(test)]
mod exclusion {
    use super::*;

    #[test]
    fn excluded_providers_fail_closed() {
        let stub = engine::Catalog::stub();
        let mut cat = engine::Catalog { entries: stub.entries.clone(), ..engine::Catalog::default() };
        let mut or = cat.entries[0].clone();
        or.provider = "openrouter".into();
        cat.entries.push(or);
        let m = cat.entries[0].model.clone();
        assert!(excluded_check(&cat, &m, &[]).is_ok());
        assert!(excluded_check(&cat, &m, &["deepseek".into()]).is_ok());
        assert!(excluded_check(&cat, &m, &["openrouter".into()]).is_err(), "an excluded provider can serve it");
    }
}

#[cfg(test)]
mod receipt_checks {
    use super::*;
    use moochy_proto::msg::Usage;

    #[test]
    fn usage_bands_ttl_and_model() {
        let e = CatalogEntry { model: "anthropic/claude-sonnet-5.5".into(), provider_model_id: "claude-sonnet-5-5".into(), ..engine::Catalog::stub().entries[0].clone() };
        let u = |input, cw1h| Usage { input, cache_write_1h: cw1h, ..Usage::default() };
        assert_eq!(usage_mismatch(&u(100, 0), "claude-sonnet-5-5", &e, 50, false), None);
        assert_eq!(usage_mismatch(&u(100, 0), "claude-sonnet-5-5-20260514", &e, 50, false), None);
        assert_eq!(usage_mismatch(&u(100, 0), "anthropic/claude-sonnet-5.5", &e, 50, false), None);
        assert_eq!(usage_mismatch(&u(900_000, 0), "claude-sonnet-5-5", &e, 50, false), Some("usage_input_out_of_band"));
        assert_eq!(usage_mismatch(&u(10, 500), "claude-sonnet-5-5", &e, 50, false), Some("cache_write_1h_without_1h_ttl"));
        assert_eq!(usage_mismatch(&u(10, 500), "claude-sonnet-5-5", &e, 50, true), None);
        assert_eq!(usage_mismatch(&u(10, 0), "claude-opus-9", &e, 50, false), Some("model_mismatch"));
        assert_eq!(usage_mismatch(&u(10, 0), "claude-sonnet-5-5-evil", &e, 50, false), Some("model_mismatch"));
    }
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
