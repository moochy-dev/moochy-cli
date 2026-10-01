//! Worker role (07 §6.1): offers; `AssignNotice` → one gRPC `Serve` stream per attempt →
//! unwrap + decrypt + verify (moochy-proto) → served-task set + boot floor → firewall + route
//! check (moochy-worker) → local reservation → Ack → provider call on a warm adapter → sealed
//! chunks + progress checkpoints → signed receipt persisted (fsync) before `End`. Cancel or
//! stream loss aborts the provider call at once.

use crate::engine::{self, DetailCtx, Dialect, Failure};
use crate::node::{Busy, Keys, Node, lock};
use crate::pb::link::{self as pb, ServeDown, ServeUp, serve_down, serve_up};
use crate::pb::local::JournalEntry;
use crate::task::now_us;
use crate::util::{clean, log, now_ms};
use bytes::Bytes;
use moochy_proto::crypto::{self, ContentKey, RequestOpener, ResponseSealer, SaltName};
use moochy_proto::money::{self, CatalogEntry};
use moochy_proto::msg::{InnerPayload, Projection, Receipt, ReceiptStatus, RouteHeader, Usage};
use moochy_proto::{PledgeId, TaskId};
use moochy_worker::Effort;
use moochy_worker::firewall::{self, MaxPrice, Policy, Route};
use moochy_worker::provider::Adapter;
use moochy_worker::store::{Reservation, Store, StoreError};
use moochy_worker::stream::StreamParser;
use prost::Message as _;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;

/// 32 MiB body (03 §16) in ≤ 64 KiB chunks, plus slack.
const MAX_BODY_CHUNKS: u32 = 600;
const MAX_BODY_LEN: u64 = (crypto::MAX_SEALED as u64).saturating_add(1 << 20);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// The donor's device cap (07 §6.4: required at setup). Unset → the worker stays idle, except in
/// insecure dev mode (tests), where it means no device cap.
fn device_cap(node: &Node) -> Option<u64> {
    node.cfg.device_monthly_cap_uusd.or_else(|| node.insecure_dev.then_some(u64::MAX))
}

fn can_serve(node: &Node) -> bool {
    node.cfg.has_role("worker") && node.keys.is_some() && node.store.is_some() && device_cap(node).is_some() && !node.adapters.is_empty()
}

fn slots_max(node: &Node) -> u32 {
    node.cfg.slots_max.unwrap_or(crate::config::DEFAULT_SLOTS)
}

/// `(dialect, public model)` this node can serve: adapters × catalog entries of their provider.
fn served_models(node: &Node) -> Vec<(Dialect, String)> {
    let cat = node.catalog();
    let mut out = Vec::new();
    for a in &node.adapters {
        for e in cat.entries.iter().filter(|e| e.provider == a.provider().as_str()) {
            for d in &e.dialects {
                let Some(d) = Dialect::from_wire(d.as_str()) else { continue };
                if a.provider().serves(d.worker()) && !out.contains(&(d, e.model.clone())) {
                    out.push((d, e.model.clone()));
                }
            }
        }
    }
    out
}

/// Run a closure on the outbox store on a blocking thread.
async fn with_store<T: Send + 'static>(node: &Node, f: impl FnOnce(&mut Store) -> T + Send + 'static) -> Option<T> {
    let st: Arc<Mutex<Store>> = node.store.clone()?;
    tokio::task::spawn_blocking(move || f(&mut lock(&st))).await.ok()
}

pub fn offer(node: &Node) -> pb::NodeMsg {
    let paused = node.paused.load(Ordering::Relaxed);
    let models = served_models(node).into_iter().map(|(d, m)| pb::ModelOffer { dialect: d.wire().into(), model: m, rl_headroom: 100 }).collect();
    let free = if paused { 0 } else { slots_max(node).saturating_sub(node.worker_busy.load(Ordering::Relaxed)) };
    let cap = device_cap(node).unwrap_or(0);
    let left = node.store.as_ref().map_or(0, |s| lock(s).device_left(cap, now_ms()));
    let local_cap_left_uusd = i64::try_from(left).unwrap_or(i64::MAX);
    pb::NodeMsg { msg: Some(pb::node_msg::Msg::Offer(pb::WorkerOffer { slots_free: free, models, pledges: Vec::new(), window_open: !paused, local_cap_left_uusd })) }
}

/// Send a fresh offer (after a task ends, pause/resume, catalog change).
pub fn reoffer(node: &Node) {
    if can_serve(node)
        && let Some(l) = node.link()
    {
        let _ = l.up.try_send(offer(node));
    }
}

fn attempt_key(task: &str, attempt: u32) -> Vec<u8> {
    let mut k = task.as_bytes().to_vec();
    k.extend_from_slice(&u64::from(attempt).to_be_bytes());
    k
}

/// After Welcome: what we have in flight / in the outbox, outbox replay, then the offer.
pub fn on_welcome(node: &Arc<Node>) {
    if !can_serve(node) {
        log("info", "worker role idle (needs provider keys and `moochy config set device_monthly_cap_uusd`)", &json!({}));
        return;
    }
    let node = node.clone();
    tokio::spawn(async move {
        let unacked = with_store(&node, |s| s.unacked().map(|(_, p)| p.to_vec()).collect::<Vec<_>>()).await.unwrap_or_default();
        let receipts: Vec<pb::SignedReceipt> = unacked.iter().filter_map(|p| pb::SignedReceipt::decode(p.as_slice()).ok()).collect();
        let tasks = receipts.iter().map(|r| pb::KnownTask { task: r.task.clone(), attempt: r.attempt, state: "outbox".into() }).collect();
        let Some(l) = node.link() else { return };
        let _ = l.up.send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::KnownTasks(pb::KnownTasks { tasks })) }).await;
        for r in receipts {
            let _ = l.up.send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::ReplayReceipt(pb::ReplayReceipt { receipt: Some(r) })) }).await;
        }
        let _ = l.up.send(offer(&node)).await;
    });
}

/// `ReceiptAck` on the session: mark the outbox entry acknowledged.
pub fn on_receipt_ack(node: &Arc<Node>, task: &str, attempt: u32) {
    let node = node.clone();
    let key = attempt_key(task, attempt);
    tokio::spawn(async move {
        let _ = with_store(&node, move |s| s.ack(&key, now_ms())).await;
    });
}

/// `ReceiptReplaySince`: resend every receipt since then (relay disaster recovery).
pub fn on_replay_since(node: &Arc<Node>, since_ms: i64) {
    let node = node.clone();
    let since = u64::try_from(since_ms).unwrap_or(0);
    tokio::spawn(async move {
        let all = with_store(&node, move |s| s.since(since).map(|(_, p)| p.to_vec()).collect::<Vec<_>>()).await.unwrap_or_default();
        let Some(l) = node.link() else { return };
        for p in all {
            if let Ok(r) = pb::SignedReceipt::decode(p.as_slice()) {
                let _ = l.up.send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::ReplayReceipt(pb::ReplayReceipt { receipt: Some(r) })) }).await;
            }
        }
    });
}

/// Warm the provider connections now and about every minute (h2 PINGs keep them in between).
pub async fn warm_loop(node: Arc<Node>) {
    let mut stop = node.shutdown.subscribe();
    loop {
        for a in &node.adapters {
            if a.warm().await.is_err() {
                log("warn", "provider warm-up failed", &json!({"provider": a.provider().as_str()}));
            }
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
            _ = stop.changed() => return,
        }
    }
}

fn up(m: serve_up::Msg) -> ServeUp {
    ServeUp { msg: Some(m) }
}

/// Per-attempt refusal context: `R` is drawn before anything else so every NACK carries it, and
/// details are sealed to the Gateway once CK is known (CONTRACT §3).
struct Refuse<'a> {
    tx: &'a mpsc::Sender<ServeUp>,
    r: [u8; 32],
    task: &'a str,
    task16: [u8; 16],
    worker: &'a str,
    attempt: u32,
}

impl Refuse<'_> {
    async fn nack(&self, ck: Option<&ContentKey>, f: &Failure) {
        // The detail names fields / short reasons only (never prompt text): fine in the donor's own log.
        log("warn", "task refused", &json!({"task": self.task, "attempt": self.attempt, "code": f.code, "detail": f.detail.as_deref().map(|d| d.get(..200).unwrap_or(d))}));
        let sealed_detail = match (ck, &f.detail) {
            (Some(ck), Some(d)) => {
                let c = DetailCtx { ck: ck.expose(), r: &self.r, task: self.task, task16: &self.task16, worker: self.worker, attempt: self.attempt };
                Bytes::from(engine::seal_detail(&c, &f.code, d))
            }
            _ => Bytes::new(),
        };
        let retry = f.retry_after_ms.map_or(0, |m| u32::try_from(m).unwrap_or(u32::MAX));
        let n = pb::Nack { r: Bytes::copy_from_slice(&self.r), code: f.code.clone(), retryable: f.retryable, retry_after_ms: retry, sealed_detail };
        let _ = self.tx.send(up(serve_up::Msg::Nack(n))).await;
    }
}

/// Deliveries in flight per `(task, attempt)`; the flag flips when the first one is served.
type Inflight = std::collections::HashMap<(String, u32), tokio::sync::watch::Receiver<bool>>;
static INFLIGHT: std::sync::LazyLock<Mutex<Inflight>> = std::sync::LazyLock::new(|| Mutex::new(Inflight::new()));

pub fn on_assign(node: &Arc<Node>, task: String, attempt: u32) {
    let Some(link) = node.link() else { return };
    let node = node.clone();
    // A second delivery of an attempt already in flight (relay replay, 03 §7.2): refuse it once
    // the first delivery is over, so it can neither win the race nor disturb the live stream.
    let first = lock(&INFLIGHT).get(&(task.clone(), attempt)).cloned();
    let (acked_tx, acked_rx) = tokio::sync::watch::channel(false);
    if first.is_none() {
        lock(&INFLIGHT).insert((task.clone(), attempt), acked_rx);
    }
    tokio::spawn(async move {
        if let Some(mut first) = first {
            log("warn", "task refused", &json!({"task": task, "attempt": attempt, "code": "unauthorized_task", "detail": "duplicate delivery"}));
            let _ = timeout(Duration::from_secs(120), first.wait_for(|done| *done)).await;
            let (tx, rx) = mpsc::channel::<ServeUp>(4);
            let _ = tx.try_send(up(serve_up::Msg::Open(pb::ServeOpen { task: task.clone(), attempt })));
            let mut client = link.client.clone();
            if let Ok(r) = client.serve(crate::link::with_session(&link, ReceiverStream::new(rx))).await {
                let mut down = r.into_inner();
                let refuse = Refuse { tx: &tx, r: crypto::random32().unwrap_or([0; 32]), task: &task, task16: [0; 16], worker: "", attempt };
                refuse.nack(None, &Failure::new("unauthorized_task", false, Some("duplicate delivery".into()))).await;
                drop(tx);
                let _ = timeout(Duration::from_secs(5), async { while next(&mut down).await.is_some() {} }).await;
            }
            return;
        }
        let (tx, rx) = mpsc::channel::<ServeUp>(64);
        let _ = tx.try_send(up(serve_up::Msg::Open(pb::ServeOpen { task: task.clone(), attempt })));
        let mut client = link.client.clone();
        let mut down = match client.serve(crate::link::with_session(&link, ReceiverStream::new(rx))).await {
            Ok(r) => r.into_inner(),
            Err(s) => {
                log("warn", "serve stream refused", &json!({"task": task, "code": format!("{:?}", s.code())}));
                return;
            }
        };
        let t0 = now_ms();
        let out = {
            let _busy = Busy::new(&node.worker_busy);
            serve(&node, &task, attempt, &mut down, &tx).await
        };
        acked_tx.send_replace(true);
        lock(&INFLIGHT).remove(&(task.clone(), attempt));
        // Half-close and let the relay end the stream: dropping `down` first would reset it
        // before the last Nack / End is flushed.
        drop(tx);
        let _ = timeout(Duration::from_secs(10), async { while next(&mut down).await.is_some() {} }).await;
        node.journal(JournalEntry {
            t_ms: i64::try_from(t0).unwrap_or(0),
            role: "worker".into(),
            task,
            status: out.0,
            model: out.1,
            cost_uusd: out.2,
            ms: u32::try_from(now_ms().saturating_sub(t0)).unwrap_or(u32::MAX),
            ..JournalEntry::default()
        });
        reoffer(&node);
    });
}

async fn next(down: &mut tonic::Streaming<ServeDown>) -> Option<serve_down::Msg> {
    match down.message().await {
        Ok(Some(ServeDown { msg: Some(m) })) => Some(m),
        _ => None,
    }
}

/// The `Assign` and its body chunks up to `last`, bounded in count, size and time.
async fn receive(task: &str, attempt: u32, down: &mut tonic::Streaming<ServeDown>) -> Option<(pb::Assign, Vec<pb::Chunk>)> {
    let Some(serve_down::Msg::Assign(assign)) = next(down).await else { return None };
    if assign.task != task || assign.attempt != attempt || assign.body_chunks > MAX_BODY_CHUNKS || assign.body_len > MAX_BODY_LEN {
        return None;
    }
    let mut body: Vec<pb::Chunk> = Vec::new();
    let got = timeout(BODY_TIMEOUT, async {
        loop {
            match next(down).await {
                Some(serve_down::Msg::Body(c)) => {
                    let last = c.last;
                    body.push(c);
                    if last {
                        return true;
                    }
                    if body.len() > MAX_BODY_CHUNKS as usize {
                        return false;
                    }
                }
                Some(serve_down::Msg::ReceiptAck(_)) => {}
                _ => return false,
            }
        }
    })
    .await;
    (got == Ok(true)).then_some((assign, body))
}

/// Hook for the key-log mirror (moochy-keylog): the signing key of a Gateway device whose user is
/// an owner-signed member of `repo_id`. `None` until the mirror is wired.
fn gateway_key(_node: &Node, _device: &str, _repo_id: &str) -> Option<[u8; 32]> {
    None
}

/// `H(repo_id ‖ gateway_device)`: pseudonymous end-user attribution for the provider (06 §7.1).
fn user_pseudonym(repo: &str, gw: &str) -> String {
    let h = crypto::sha256(&crate::util::lp(&[b"moochy/v1/user", repo.as_bytes(), gw.as_bytes()]));
    h.iter().take(16).fold(String::from("moochy-"), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Everything known once a task passed every check, up to the Ack.
struct Admitted {
    ck: ContentKey,
    task: TaskId,
    inner: InnerPayload,
    route: RouteHeader,
    entry: CatalogEntry,
    adapter: Arc<Adapter>,
    prepared: firewall::Prepared,
    pledge: PledgeId,
    key: Vec<u8>,
}

/// Steps 1–4 of 07 §6.1. `Err((ck, failure))` = NACK (with CK when known, to seal the detail).
#[allow(clippy::too_many_lines)]
async fn admit(node: &Arc<Node>, keys: &Keys, assign: &pb::Assign, body: &[pb::Chunk]) -> Result<Admitted, (Option<ContentKey>, Failure)> {
    let refuse = |code: &str, retry: bool, d: Option<String>| (None, Failure::new(code, retry, d));
    let task: TaskId = assign.task.parse().map_err(|_| refuse("bad_envelope", false, None))?;
    let attempt = u8::try_from(assign.attempt).map_err(|_| refuse("bad_envelope", false, None))?;
    let wrap = <[u8; crypto::WRAP_LEN]>::try_from(assign.wrap.as_ref()).map_err(|_| refuse("bad_envelope", false, None))?;
    // 1. unwrap (fails if the route header was touched: HPKE AAD) → decrypt → decompress.
    let ck = crypto::unwrap(&keys.enc, &task, &assign.route, &wrap).map_err(|_| refuse("bad_envelope", false, None))?;
    let with_ck = |code: &str, retry: bool, d: Option<String>| (Some(ck.clone()), Failure::new(code, retry, d));
    let mut opener = RequestOpener::new(&ck, &task).map_err(|_| with_ck("bad_envelope", false, None))?;
    for c in body {
        opener.push(&crate::pb::to_proto(c.clone())).map_err(|_| with_ck("bad_envelope", false, None))?;
    }
    if opener.chunks() != assign.body_chunks {
        return Err(with_ck("bad_envelope", false, None));
    }
    let payload = opener.finish().map_err(|_| with_ck("bad_envelope", false, None))?;
    let inner = InnerPayload::parse(&payload).map_err(|_| with_ck("bad_envelope", false, None))?;
    drop(payload);
    let route = RouteHeader::parse(&assign.route).map_err(|_| with_ck("bad_envelope", false, None))?;
    // 2. Task authenticity (03 §7.2).
    if route.repo_id.text() != assign.repo_id {
        return Err(with_ck("unauthorized_task", false, Some("route repo differs from the assigned pledge's repo".into())));
    }
    let ctx = crypto::TaskContext { task: &task, repo: &route.repo_id, route: &assign.route };
    match gateway_key(node, &inner.gateway_device.text(), &assign.repo_id) {
        Some(pk) => inner.verify(&ctx, &pk).map_err(|_| with_ck("unauthorized_task", false, Some("task signature".into())))?,
        // D14: relay-asserted membership only in insecure dev mode; the body hash still binds.
        None if node.insecure_dev => {
            if !crypto::ct_eq(&crypto::sha256(&inner.body_b64.0), &inner.body_sha256.0) {
                return Err(with_ck("bad_envelope", false, None));
            }
        }
        None => return Err(with_ck("unauthorized_task", false, Some("gateway key not in the key log".into()))),
    }
    let now = now_ms();
    if !task.admissible(now, node.boot_ms) {
        return Err(with_ck("unauthorized_task", false, Some("task id outside the freshness window".into())));
    }
    let (gw, tid, ts) = (inner.gateway_device.text(), task.text(), task.0.timestamp_ms());
    match with_store(node, move |s| s.check_served(&gw, &tid, ts, now)).await {
        Some(Ok(())) => {}
        Some(Err(StoreError::Stale | StoreError::Replay)) => return Err(with_ck("unauthorized_task", false, Some("task already served".into()))),
        _ => return Err(with_ck("busy", true, None)),
    }
    let pledge: PledgeId = assign.pledge_id.parse().map_err(|_| with_ck("unauthorized_task", false, Some("no pledge".into())))?;
    // 3. Adapter + catalog entry, firewall, route/body consistency.
    let dialect = Dialect::from_wire(route.dialect.as_str()).ok_or_else(|| with_ck("route_mismatch", false, None))?;
    let cat = node.catalog();
    let Some((adapter, entry)) = node.adapters.iter().find_map(|a| {
        let e = cat.entry(&route.model, a.provider().as_str())?;
        (a.provider().serves(dialect.worker()) && e.dialects.contains(&route.dialect)).then(|| (a.clone(), e.clone()))
    }) else {
        return Err(with_ck("model_unavailable", true, None));
    };
    let fwc = engine::fw_catalog(&entry).ok_or_else(|| with_ck("model_unavailable", true, None))?;
    let policy = Policy { level: firewall::Level::Strict, flags: moochy_worker::Flags::NONE, max_effort: Effort::Max };
    let hdrs: Vec<(&str, &str)> = inner.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let pseudo = user_pseudonym(&assign.repo_id, &inner.gateway_device.text());
    let fw = firewall::Request {
        provider: adapter.provider(),
        dialect: dialect.worker(),
        body: &inner.body_b64.0,
        headers: &hdrs,
        policy: &policy,
        catalog: &fwc,
        provider_model_id: &entry.provider_model_id,
        user_pseudonym: &pseudo,
        max_price: Some(MaxPrice { prompt_uusd_per_mtok: entry.input, completion_uusd_per_mtok: entry.out }),
    };
    let prepared = firewall::prepare(&fw).map_err(|r| {
        let (code, retry) = r.code.nack();
        with_ck(code, retry, Some(r.to_string()))
    })?;
    let mut aliases: Vec<&str> = vec![entry.model.as_str(), entry.provider_model_id.as_str()];
    aliases.extend(entry.aliases.iter().map(String::as_str));
    let effort = Effort::parse(&route.effort).ok_or_else(|| with_ck("route_mismatch", false, Some("effort".into())))?;
    let flags = engine::route_flags(&route).ok_or_else(|| with_ck("route_mismatch", false, Some("flags".into())))?;
    let r = Route {
        dialect: dialect.worker(),
        model_aliases: &aliases,
        effort,
        max_tokens: route.max_tokens.into(),
        est_input_tokens: route.est_input_tokens,
        cache_ttl: engine::cache_ttl_w(route.cache_ttl),
        stream: route.stream,
        flags,
    };
    prepared.facts.check_route(dialect.worker(), &r).map_err(|e| {
        let (code, retry) = e.code.nack();
        with_ck(code, retry, Some(e.to_string()))
    })?;
    // 4. Local reservation (device cap; pledge numbers are relay-side until Assign carries them).
    let amount = money::reserve_for_route(&entry, &route).ok().and_then(|a| u64::try_from(a).ok()).ok_or_else(|| with_ck("local_cap", true, None))?;
    let key = attempt_key(&task.text(), u32::from(attempt));
    let (k2, p2, cap) = (key.clone(), pledge.text(), device_cap(node).unwrap_or(0));
    let reserved = with_store(node, move |s| {
        s.reserve(&Reservation {
            key: &k2,
            pledge_id: &p2,
            pledge_period: u64::from(moochy_worker::store::month_of(now)),
            pledge_budget_uusd: u64::MAX,
            per_task_cap_uusd: u64::MAX,
            amount_uusd: amount,
            device_cap_uusd: cap,
            now_ms: now,
        })
    })
    .await;
    match reserved {
        Some(Ok(())) => {}
        Some(Err(StoreError::Cap(w))) => return Err(with_ck("local_cap", true, Some(w.into()))),
        _ => return Err(with_ck("busy", true, None)),
    }
    Ok(Admitted { ck, task, inner, route, entry, adapter, prepared, pledge, key })
}

/// Returns `(journal status, model, cost)`.
async fn serve(
    node: &Arc<Node>,
    task_s: &str,
    attempt: u32,
    down: &mut tonic::Streaming<ServeDown>,
    tx: &mpsc::Sender<ServeUp>,
) -> (String, String, i64) {
    let r = crypto::random32().unwrap_or([0; 32]);
    let task16 = task_s.parse::<TaskId>().map_or([0; 16], |t| t.0.0);
    let device = node.device_id().unwrap_or_default().to_owned();
    let refuse = Refuse { tx, r, task: task_s, task16, worker: &device, attempt };
    let refused = |code: &str| (format!("refused:{code}"), String::new(), 0);
    let paused = node.paused.load(Ordering::Relaxed);
    let Some(keys) = node.keys.as_ref().filter(|_| can_serve(node) && !paused && node.worker_busy.load(Ordering::Relaxed) <= slots_max(node)) else {
        let code = if paused { "local_cap" } else { "busy" };
        refuse.nack(None, &Failure::new(code, true, None)).await;
        return refused(code);
    };
    let Some((assign, body)) = receive(task_s, attempt, down).await else {
        refuse.nack(None, &Failure::new("bad_envelope", false, None)).await;
        return refused("bad_envelope");
    };
    let t_assign_rx = now_us();
    let t_start = now_ms();
    let a = match admit(node, keys, &assign, &body).await {
        Ok(a) => a,
        Err((ck, f)) => {
            refuse.nack(ck.as_ref(), &f).await;
            log("info", "timing", &json!({"task": task_s, "attempt": attempt, "t_assign_rx": t_assign_rx}));
            return refused(&f.code);
        }
    };
    drop(body);
    let _ = tx.send(up(serve_up::Msg::Ack(pb::Ack { r: Bytes::copy_from_slice(&r) }))).await;
    log("info", "timing", &json!({"task": task_s, "attempt": attempt, "t_assign_rx": t_assign_rx, "t_ack_tx": now_us()}));
    run_provider(node, keys, a, attempt, r, t_start, down, &refuse).await
}

/// Steps 6–9: provider call, sealed streaming, receipt.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_provider(node: &Arc<Node>, keys: &Keys, a: Admitted, attempt: u32, r: [u8; 32], t_start: u64, down: &mut tonic::Streaming<ServeDown>, refuse: &Refuse<'_>) -> (String, String, i64) {
    let tx = refuse.tx;
    let dialect = Dialect::from_wire(a.route.dialect.as_str()).unwrap_or(Dialect::Anthropic);
    let attempt8 = u8::try_from(attempt).unwrap_or(0);
    let Ok(mut sealer) = ResponseSealer::new(&a.ck, &r, &a.task, &keys.device_id, attempt8) else { return ("failed:internal".into(), String::new(), 0) };
    let call = tokio::select! {
        r = a.adapter.send(dialect.worker(), a.prepared.body.clone(), &a.prepared.headers) => Some(r),
        () = wait_cancel(down) => None,
    };
    let mut resp = match call {
        Some(Ok(resp)) => resp,
        Some(Err(f)) => {
            let (code, retry) = f.nack();
            let mut fl = Failure::new(code, retry, Some(String::from_utf8_lossy(&f.body).into_owned()));
            fl.retry_after_ms = f.retry_after_ms;
            refuse.nack(Some(&a.ck), &fl).await;
            // After the Ack the relay awaits a receipt: zero usage, provably nothing generated.
            let end = Ending { status: ReceiptStatus::NotStarted, usage: Usage::default(), cost: 0, model: String::new(), req_id: String::new(), times: (t_start, 0) };
            finish(node, keys, &a, attempt8, &sealer, end, down, refuse).await;
            return (format!("refused:{code}"), String::new(), 0);
        }
        None => {
            let end = Ending { status: ReceiptStatus::NotStarted, usage: Usage::default(), cost: 0, model: String::new(), req_id: String::new(), times: (t_start, 0) };
            finish(node, keys, &a, attempt8, &sealer, end, down, refuse).await;
            return ("cancelled".into(), String::new(), 0);
        }
    };
    let t_started = now_ms();
    let _ = tx.send(up(serve_up::Msg::Started(pb::Started { attempt }))).await;
    let mut parser = StreamParser::new(dialect.worker(), a.route.stream);
    let checkpoint = |s: &ResponseSealer| -> Option<pb::Checkpoint> {
        let seq = s.last_seq()?;
        let h = s.running_hash();
        let m = crypto::checkpoint_msg(&a.task, attempt8, &r, seq, &h).ok()?;
        Some(pb::Checkpoint { attempt, seq, running_hash: Bytes::copy_from_slice(&h), sig: Bytes::copy_from_slice(&keys.sign.sign(&m)) })
    };
    let mut status = ReceiptStatus::Ok;
    let mut link_ok = true;
    loop {
        let next = tokio::select! {
            n = resp.next() => n,
            () = wait_cancel(down) => { status = ReceiptStatus::Cancelled; break; }
        };
        match next {
            Ok(Some(b)) => {
                let tool_ends = parser.feed(&b, &mut |_, _| {}).map_or(0, |c| c.tool_ends);
                // Seal and send at once (CONTRACT §13); the stream ends with an empty `last` chunk.
                for part in b.chunks(crypto::MAX_CHUNK) {
                    let Ok(c) = sealer.seal(part, false) else { break };
                    if tx.send(up(serve_up::Msg::Chunk(crate::pb::from_proto(c)))).await.is_err() {
                        link_ok = false;
                    }
                }
                if tool_ends > 0
                    && let Some(c) = checkpoint(&sealer)
                {
                    let _ = tx.send(up(serve_up::Msg::Checkpoint(c))).await;
                }
                if !link_ok {
                    status = ReceiptStatus::Cancelled;
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                status = ReceiptStatus::ProviderError;
                break;
            }
        }
    }
    let request_id = resp.request_id.clone();
    drop(resp); // aborts the provider request if still running
    if link_ok
        && let Ok(c) = sealer.seal(&[], true)
        && tx.send(up(serve_up::Msg::Chunk(crate::pb::from_proto(c)))).await.is_ok()
        && let Some(cp) = checkpoint(&sealer)
    {
        let _ = tx.send(up(serve_up::Msg::Checkpoint(cp))).await;
    }
    let out = parser.finish();
    if status == ReceiptStatus::Ok && (!out.complete || out.provider_error || out.malformed) {
        status = if out.provider_error { ReceiptStatus::ProviderError } else { ReceiptStatus::Partial };
    }
    let openrouter = a.entry.provider == "openrouter";
    let reserved = money::reserve_for_route(&a.entry, &a.route).unwrap_or(0);
    // OpenRouter's reported cost is authoritative; when it never came, settle pessimistically at
    // the reservation and mark the usage estimated (05 §5.2).
    let or_cost = out.usage.provider_cost_uusd.and_then(|c| i64::try_from(c).ok());
    let usage = Usage {
        input: out.usage.input,
        output: out.usage.output,
        cache_write_5m: out.usage.cache_write_5m,
        cache_write_1h: out.usage.cache_write_1h,
        cache_read: out.usage.cache_read,
        estimated: out.usage.estimated || (openrouter && or_cost.is_none()),
        provider_cost_uusd: if openrouter { Some(or_cost.unwrap_or(reserved)) } else { None },
    };
    let fast = a.route.flags.iter().any(|f| f == "fast");
    // Fallback when a cost cannot be computed (e.g. OpenRouter without a reported cost): the reservation.
    let cost = money::cost_uusd(&a.entry, &usage, fast).unwrap_or(reserved);
    let model = clean(out.model.as_deref().unwrap_or("")).into_owned();
    let req_id = request_id.or(out.id).unwrap_or_default();
    let end = Ending { status, usage, cost, model: model.clone(), req_id, times: (t_start, t_started) };
    finish(node, keys, &a, attempt8, &sealer, end, down, refuse).await;
    let st = match status {
        ReceiptStatus::Ok => "ok",
        ReceiptStatus::Cancelled => "cancelled",
        ReceiptStatus::ProviderError => "provider_error",
        ReceiptStatus::Partial => "partial",
        ReceiptStatus::NotStarted => "not_started",
    };
    (st.into(), model, cost)
}

struct Ending {
    status: ReceiptStatus,
    usage: Usage,
    cost: i64,
    model: String,
    req_id: String,
    times: (u64, u64),
}

/// Sign the receipt, persist it (fsync) before `End`, then wait for the ack; if none comes on
/// the Serve stream, hand it to the session (`ReplayReceipt`) so it is never lost.
#[allow(clippy::too_many_arguments)]
async fn finish(node: &Arc<Node>, keys: &Keys, a: &Admitted, attempt: u8, sealer: &ResponseSealer, e: Ending, down: &mut tonic::Streaming<ServeDown>, refuse: &Refuse<'_>) {
    let ucost = u64::try_from(e.cost).unwrap_or(0);
    let Some(signed) = build_receipt(keys, a, attempt, sealer, &e.req_id, e.usage, e.cost, e.status, &e.model, e.times, node.catalog().version) else {
        log("error", "receipt signing failed", &json!({"task": refuse.task}));
        return;
    };
    let (key, payload) = (a.key.clone(), signed.encode_to_vec());
    if with_store(node, move |s| s.put_receipt(&key, &payload, ucost, now_ms())).await.is_none_or(|r| r.is_err()) {
        log("error", "outbox write failed", &json!({"task": refuse.task}));
    }
    let sent = refuse.tx.send(up(serve_up::Msg::End(signed.clone()))).await.is_ok();
    let acked = sent
        && matches!(
            timeout(Duration::from_secs(5), async {
                while let Some(m) = next(down).await {
                    if matches!(m, serve_down::Msg::ReceiptAck(_)) {
                        return true;
                    }
                }
                false
            })
            .await,
            Ok(true)
        );
    if acked {
        let key = a.key.clone();
        let _ = with_store(node, move |s| s.ack(&key, now_ms())).await;
    } else if let Some(l) = node.link() {
        let _ = l.up.send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::ReplayReceipt(pb::ReplayReceipt { receipt: Some(signed) })) }).await;
    }
}

/// Resolves when the relay cancels the attempt (or the stream dies). Other messages are ignored.
async fn wait_cancel(down: &mut tonic::Streaming<ServeDown>) {
    loop {
        match next(down).await {
            Some(serve_down::Msg::Cancel(_)) | None => return,
            Some(_) => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_receipt(
    keys: &Keys,
    a: &Admitted,
    attempt: u8,
    sealer: &ResponseSealer,
    provider_req_id: &str,
    usage: Usage,
    cost: i64,
    status: ReceiptStatus,
    model: &str,
    (t_start, t_started): (u64, u64),
    catalog_version: u64,
) -> Option<pb::SignedReceipt> {
    let s = &a.inner.s.0;
    let rc = Receipt {
        v: 1,
        task_id: a.task,
        attempt,
        repo_id: a.route.repo_id,
        pledge_id: a.pledge,
        worker_device: keys.device_id,
        gateway_device: a.inner.gateway_device,
        dialect: a.route.dialect,
        provider: a.entry.provider.clone(),
        model_reported: model.into(),
        usage,
        catalog_version,
        cost_uusd: cost,
        req_commit: moochy_proto::B(crypto::req_commit(&crypto::salt(s, SaltName::Req).ok()?, &a.inner.body_b64.0).ok()?),
        resp_commit: moochy_proto::B(crypto::resp_commit(&crypto::salt(s, SaltName::Resp).ok()?, &sealer.running_hash()).ok()?),
        provider_req_hash: moochy_proto::B(crypto::provider_req_hash(&crypto::salt(s, SaltName::Pid).ok()?, provider_req_id).ok()?),
        status,
        t_start,
        t_started: if status == ReceiptStatus::NotStarted { 0 } else { t_started },
        t_end: now_ms(),
    };
    let (rbytes, rsig) = crypto::sign_receipt(&keys.sign, &rc).ok()?;
    let p = Projection {
        v: 1,
        receipt_ref: moochy_proto::B(crate::util::rand_bytes::<16>().ok()?),
        repo_id: a.route.repo_id,
        donor: None,
        model: a.route.model.clone(),
        cost_uusd: cost,
        day: utc_day(now_ms()),
        receipt_sha256: moochy_proto::B(crypto::sha256(&rbytes)),
    };
    let (pbytes, psig) = crypto::sign_projection(&keys.sign, &p).ok()?;
    Some(pb::SignedReceipt {
        task: a.task.text(),
        attempt: attempt.into(),
        receipt: Bytes::from(rbytes),
        donor_sig: Bytes::copy_from_slice(&rsig),
        projection: Bytes::from(pbytes),
        projection_sig: Bytes::copy_from_slice(&psig),
    })
}

/// `YYYY-MM-DD` (UTC) of a Unix time in ms (Howard Hinnant's civil_from_days).
pub fn utc_day(ms: u64) -> String {
    let z = i64::try_from(ms / 86_400_000).unwrap_or(0).saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = doe.saturating_sub(doe / 1460).saturating_add(doe / 36_524).saturating_sub(doe / 146_096) / 365;
    let doy = doe.saturating_sub(yoe.saturating_mul(365).saturating_add(yoe / 4).saturating_sub(yoe / 100));
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let d = doy.saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5).saturating_add(1);
    let m = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
    let y = yoe.saturating_add(era.saturating_mul(400)).saturating_add(i64::from(m <= 2));
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_days() {
        assert_eq!(super::utc_day(0), "1970-01-01");
        assert_eq!(super::utc_day(951_782_400_000), "2000-02-29");
        assert_eq!(super::utc_day(1_790_812_800_000), "2026-10-01");
    }
}
