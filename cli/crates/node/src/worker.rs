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
use moochy_proto::crypto::{self, ContentKey, RequestDecryptor, ResponseSealer, SaltName};
use moochy_proto::money::{self, CatalogEntry};
use moochy_proto::msg::{InnerPayload, Projection, Receipt, ReceiptStatus, RouteHeader, Usage};
use moochy_proto::{PledgeId, TaskId};
use moochy_worker::Effort;
use moochy_worker::firewall::{self, MaxPrice, Policy, Route};
use moochy_worker::validate::ValidateRequest;
use moochy_worker::provider::Adapter;
use moochy_worker::store::{Reservation, Store, StoreError};
use moochy_worker::stream::{Event, StreamParser};
use prost::Message as _;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;

/// Bound on the opt-in journal text per side.
const MAX_JOURNAL_TEXT: usize = 64 << 10;

/// `(journal status, model, cost, opt-in (request, response) text)`.
/// `(journal status, model, cost, opt-in texts, journaled)`; `journaled`: `finish` already wrote
/// the journal entry (before `End`, so it exists once the relay counts the task settled, E62).
type Served = (String, String, i64, Option<Texts>, bool);
/// Opt-in journal texts (request, response).
type Texts = (Vec<u8>, Vec<u8>);

fn clip(b: &[u8]) -> Vec<u8> {
    b.get(..b.len().min(MAX_JOURNAL_TEXT)).unwrap_or_default().to_vec()
}

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
    node.cfg.has_role("worker")
        && node.keys.is_some()
        && node.store.is_some()
        && node.locked
        && node.validator.as_ref().is_some_and(|v| v.alive())
        && device_cap(node).is_some()
        && !node.adapters.is_empty()
        // 07 §8.1 step 4 (mo-node `moochy safety`): the safety step was accepted.
        && (node.insecure_dev || node.cfg.donor_safety_ack_ms.is_some())
}

fn slots_max(node: &Node) -> u32 {
    node.cfg.slots_max.unwrap_or(crate::config::DEFAULT_SLOTS)
}

/// `(dialect, public model, provider)` this node can serve: adapters × catalog entries of their
/// provider (the relay steers on the provider too, e.g. a project's excluded providers).
fn served_models(node: &Node) -> Vec<(Dialect, String, &'static str)> {
    let cat = node.catalog();
    let only = node.cfg.models_override();
    let mut out = Vec::new();
    for a in &node.adapters {
        for e in cat.entries.iter().filter(|e| e.provider == a.provider().as_str() && only.as_ref().is_none_or(|o| o.contains(&e.model.as_str())) && node.provider_model_id(e).is_some()) {
            for d in &e.dialects {
                let Some(d) = Dialect::from_wire(d.as_str()) else { continue };
                let item = (d, e.model.clone(), a.provider().as_str());
                if a.provider().serves(d.worker()) && !out.contains(&item) {
                    out.push(item);
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

/// How long a provider's rate-limit reading steers the offer; then it decays back to 100 %.
const RL_TTL_MS: u64 = 60_000;

/// Record the provider's rate-limit headroom for `model` (sent with the next offer).
fn note_headroom(node: &Node, model: &str, rl: &moochy_worker::provider::RateLimit) {
    if let Some(p) = rl.headroom_pct() {
        lock(&node.rl_headroom).insert(model.to_owned(), (p, now_ms().saturating_add(RL_TTL_MS)));
    }
}

pub fn offer(node: &Node) -> pb::NodeMsg {
    let paused = node.paused.load(Ordering::Relaxed);
    let now = now_ms();
    let rl = lock(&node.rl_headroom);
    let headroom = |m: &str| rl.get(m).filter(|(_, exp)| *exp > now).map_or(100, |(p, _)| u32::from(*p));
    let models = served_models(node).into_iter().map(|(d, m, p)| pb::ModelOffer { dialect: d.wire().into(), rl_headroom: headroom(&m), model: m, provider: p.into() }).collect();
    drop(rl);
    let free = if paused || !can_serve(node) { 0 } else { slots_max(node).saturating_sub(node.worker_busy.load(Ordering::Relaxed)) };
    let cap = device_cap(node).unwrap_or(0);
    let left = node.store.as_ref().map_or(0, |s| lock(s).device_left(cap, now_ms()));
    let local_cap_left_uusd = i64::try_from(left).unwrap_or(i64::MAX);
    pb::NodeMsg { msg: Some(pb::node_msg::Msg::Offer(pb::WorkerOffer { slots_free: free, models, pledges: Vec::new(), window_open: !paused, local_cap_left_uusd })) }
}

/// Send a fresh offer (after a task ends, pause/resume, catalog change).
pub fn reoffer(node: &Node) {
    // Also when we can no longer serve (validator gone): the offer then says 0 slots.
    if node.cfg.has_role("worker")
        && node.keys.is_some()
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
        log("info", "not donating: add a provider key (`moochy keys add`) and finish the safety step (`moochy safety --monthly-limit 25 --accept-safety`)", &json!({}));
        return;
    }
    let node = node.clone();
    tokio::spawn(async move {
        if let Some(keys) = &node.keys {
            recover_inflight(&node, keys).await;
        }
        // Own donations up front, so the first tasks do not wait for ListDonations (T-03-088).
        let _ = refresh_own_pledges(&node, "").await;
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
pub fn on_receipt_ack(node: &Arc<Node>, ack: pb::ReceiptAck) {
    let node = node.clone();
    let key = attempt_key(&ack.task, ack.attempt);
    tokio::spawn(async move {
        let k2 = key.clone();
        let receipt = with_store(&node, move |s| s.since(0).find(|(k, _)| *k == k2.as_slice()).map(|(_, p)| p.to_vec())).await.flatten();
        if let Some(r) = receipt.and_then(|p| pb::SignedReceipt::decode(p.as_slice()).ok()) {
            crate::keylog::check_receipt_ack(&node, &r.receipt, &ack);
        }
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
        // Our own refusal reasons name fields only; provider error bodies may echo request
        // content, so they are sealed to the Gateway but never logged here.
        let ours = matches!(f.code.as_str(), "firewall" | "route_mismatch" | "unauthorized_task" | "bad_envelope" | "local_cap" | "busy");
        let detail = f.detail.as_deref().filter(|_| ours).map(|d| d.get(..200).unwrap_or(d));
        log("warn", "task refused", &json!({"task": self.task, "attempt": self.attempt, "code": f.code, "detail": detail}));
        let sealed_detail = match (ck, &f.detail) {
            (Some(ck), Some(d)) => {
                let c = DetailCtx { ck: ck.expose(), r: &self.r, task: self.task, task16: &self.task16, worker: self.worker, attempt: self.attempt };
                Bytes::from(engine::seal_detail(&c, &f.code, d))
            }
            _ => Bytes::new(),
        };
        let retry = f.retry_after_ms.unwrap_or(0);
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
        // Attempts that reached a receipt were journaled in `finish`; the others (refused before
        // any receipt, so no tokens) here, before the stream drain below (up to 10 s).
        let ms = u32::try_from(now_ms().saturating_sub(t0)).unwrap_or(u32::MAX);
        if !out.4 {
            node.journal(JournalEntry {
                t_ms: i64::try_from(t0).unwrap_or(0),
                role: "worker".into(),
                task,
                status: out.0,
                model: out.1,
                cost_uusd: out.2,
                request: out.3.as_ref().map(|t| t.0.clone()).unwrap_or_default(),
                response: out.3.map(|t| t.1).unwrap_or_default(),
                ms,
                ..JournalEntry::default()
            });
        }
        // Half-close and let the relay end the stream: dropping `down` first would reset it
        // before the last Nack / End is flushed.
        drop(tx);
        let _ = timeout(Duration::from_secs(10), async { while next(&mut down).await.is_some() {} }).await;
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

/// The logged signing key of the requesting Gateway `device` (03 §7.2 1–2). A repo/org pledge: its
/// user is the repo's owner or an owner-signed member. A person pledge (CONTRACT §24.4): it is a
/// device of the owner of exactly the sponsored profile `Some(person_id)` (`Donation.person_id`;
/// empty from an older relay: any profile of that owner, see `keylog::person_requester`), which
/// covers `repo_id` and approved this donor; otherwise `Err` (`not_approved`, never the member
/// rule, so another member of the repo never spends the sponsorship). `Ok(None)`: no verified
/// key log (the caller refuses outside D14).
fn requester_key(node: &Node, person: Option<&str>, device: &str, repo_id: &str) -> Result<Option<[u8; 32]>, String> {
    let Some(l) = node.keylog.as_ref().filter(|l| l.verified()) else { return Ok(None) };
    let Some(person_id) = person else {
        return Ok(l.gateway_key(device, repo_id));
    };
    match l.person_gateway_key(node.device_id().unwrap_or_default(), device, repo_id, person_id) {
        Ok(pk) => Ok(Some(pk)),
        Err(c) => Err(format!("{}: this person sponsorship does not cover this request (key log)", c.as_str())),
    }
}

/// A donation turns active when its owner approves it: re-list soon, but never more than 4×/s.
const OWN_PLEDGES_REFRESH_MS: u64 = 250;

/// T-03-088: the relay's pledge/repo assignment is never trusted alone. The pledge must be one of
/// this donor's own active donations (listed on our own authenticated session), and with a
/// verified key log this device must hold an owner-signed DONOR_APPROVED for the repo, unless the
/// pledge targets a person: that route is checked with the signed request's gateway device
/// (CONTRACT §24.4, [`requester_key`]). Returns the sponsored profile when the pledge targets a
/// person (`Some("")` when the relay did not name its `m_` id).
async fn own_donation(node: &Arc<Node>, pledge: &str, repo_id: &str) -> Result<Option<String>, &'static str> {
    let known = |n: &Node| lock(&n.own_pledges).get(pledge).map(|(s, person, _)| (s == "active", *person));
    if known(node).is_none_or(|k| !k.0) {
        refresh_own_pledges(node, pledge).await?;
    }
    let person = match known(node) {
        Some((true, person)) => person,
        Some((false, _)) => return Err("this donation is not active"),
        None => return Err("not one of this donor's donations"),
    };
    if !person
        && let Some(l) = &node.keylog
        && l.verified()
        && !l.donor_approved(node.device_id().unwrap_or_default(), repo_id)
    {
        return Err("this project has not approved this donor (key log)");
    }
    Ok(person.then(|| lock(&node.own_people).get(pledge).cloned().unwrap_or_default()))
}

/// Refresh this donor's own donations (`ListDonations` on our own session), at most every 250 ms.
/// Concurrent tasks wait for the refresh in flight and re-check, so a burst never refuses a
/// donation that is being fetched. A wanted donation that the last listing (< 250 ms ago) did not
/// show active may have been approved since (E41): wait out the rest of the window (refresh lock
/// released while waiting) and list once more before the caller refuses. `Err` only for
/// "relay-asserted, dev": a relay without the donation RPCs under `MOOCHY_INSECURE_DEV` (the
/// caller then accepts).
async fn refresh_own_pledges(node: &Arc<Node>, want: &str) -> Result<(), &'static str> {
    let active = |n: &Node| !want.is_empty() && lock(&n.own_pledges).get(want).is_some_and(|(s, ..)| s == "active");
    let mut last = node.pledge_refresh.lock().await;
    if active(node) {
        return Ok(());
    }
    let age = now_ms().saturating_sub(*last);
    if *last != 0 && age < OWN_PLEDGES_REFRESH_MS {
        if want.is_empty() {
            return Ok(());
        }
        let seen = *last;
        drop(last);
        tokio::time::sleep(Duration::from_millis(OWN_PLEDGES_REFRESH_MS.saturating_sub(age))).await;
        last = node.pledge_refresh.lock().await;
        // Another task listed after our window opened: that answer is fresh enough.
        if active(node) || *last != seen {
            return Ok(());
        }
    }
    let Some(l) = node.link() else { return Ok(()) };
    let mut c = l.client.clone();
    match timeout(Duration::from_secs(5), c.list_donations(crate::link::with_session(&l, pb::ListDonationsRequest::default()))).await {
        Ok(Ok(r)) => {
            *last = now_ms();
            let ds = r.into_inner().donations;
            *lock(&node.own_people) = ds.iter().take(10_000).filter(|d| !d.person.is_empty() && !d.person_id.is_empty()).map(|d| (d.pledge_id.clone(), d.person_id.clone())).collect();
            *lock(&node.own_pledges) = ds.into_iter().take(10_000).map(|d| (d.pledge_id.clone(), (d.status.clone(), !d.person.is_empty(), crate::donations::target(&d)))).collect();
        }
        Ok(Err(s)) if s.code() == tonic::Code::Unimplemented && node.insecure_dev => {
            lock(&node.own_pledges).insert(want.to_owned(), ("active".into(), false, String::new()));
        }
        _ => *last = 0, // failed: retry at the next task
    }
    Ok(())
}

/// The pledge policy carried in `Assign` (models, dialects, max_effort, flags), enforced locally
/// whatever the relay decided; the firewall level is the donor's own setting (06 §7.3).
/// The keys of `Assign.pledge_policy` this client knows (protocol §9.1). Any other key is refused:
/// a new limit must never be served as if it were absent.
const POLICY_KEYS: [&str; 6] = ["models", "max_effort", "dialects", "flags", "daily_limit_uusd", "weekly_limit_uusd"];

/// A donation's `(daily, weekly)` limits in µ$, `u64::MAX` = none.
type Windows = (u64, u64);

fn policy_windows(v: &serde_json::Map<String, serde_json::Value>) -> Result<Windows, String> {
    if let Some(k) = v.keys().find(|k| !POLICY_KEYS.contains(&k.as_str())) {
        return Err(format!("this donation has a setting this version of Moochy does not know (`{}`): update moochy", clean(k)));
    }
    let limit = |k: &str| match v.get(k) {
        None | Some(serde_json::Value::Null) => Ok(u64::MAX),
        Some(x) => x.as_u64().map(|n| if n == 0 { u64::MAX } else { n }).ok_or_else(|| format!("donation settings: `{k}` is not a whole number of µ$")),
    };
    Ok((limit("daily_limit_uusd")?, limit("weekly_limit_uusd")?))
}

fn pledge_policy(node: &Node, raw: &[u8], route: &RouteHeader) -> Result<(Policy, Windows), String> {
    let level = if node.cfg.firewall_level.as_deref() == Some("paranoid") { firewall::Level::Paranoid } else { firewall::Level::Strict };
    if raw.is_empty() {
        // Older relay without the field: no opt-in flags, effort unbounded by the pledge.
        return Ok((Policy { level, flags: moochy_worker::Flags::NONE, max_effort: Effort::Max }, (u64::MAX, u64::MAX)));
    }
    let v = crate::json::parse_object(raw).map_err(|e| format!("donation settings: {e}"))?;
    let windows = policy_windows(&v)?;
    let strs = |k: &str| -> Vec<&str> { v.get(k).and_then(serde_json::Value::as_array).into_iter().flatten().filter_map(serde_json::Value::as_str).collect() };
    let models = strs("models");
    let model_ok = models.is_empty() || models.iter().any(|m| *m == route.model || m.strip_suffix('*').is_some_and(|p| route.model.starts_with(p)));
    if !model_ok {
        return Err(format!("model `{}` is not allowed by this donation", route.model));
    }
    let dialects = strs("dialects");
    if !dialects.is_empty() && !dialects.contains(&route.dialect.as_str()) {
        return Err("this API format is not allowed by this donation".into());
    }
    let max_effort = match v.get("max_effort").and_then(serde_json::Value::as_str).filter(|e| !e.is_empty()) {
        Some(e) => Effort::parse(e).ok_or("unknown maximum reasoning effort in the donation settings")?,
        None => Effort::Max,
    };
    let flags = moochy_worker::Flags::parse(strs("flags")).map_err(|e| format!("donation settings: {e}"))?;
    Ok((Policy { level, flags, max_effort }, windows))
}

/// `H(repo_id ‖ gateway_device)`: pseudonymous end-user attribution for the provider (06 §7.1).
fn user_pseudonym(repo: &str, gw: &str) -> String {
    let h = crypto::sha256(&crate::util::lp(&[b"moochy/v1/user", repo.as_bytes(), gw.as_bytes()]));
    h.iter().take(16).fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Everything known once a task passed every check, up to the Ack.
struct Admitted {
    ck: ContentKey,
    task: TaskId,
    /// Shared with the off-path crash-record builder (no copy of the body).
    inner: Arc<InnerPayload>,
    route: RouteHeader,
    entry: CatalogEntry,
    adapter: Arc<Adapter>,
    prepared: firewall::Prepared,
    pledge: PledgeId,
    key: Vec<u8>,
    catalog_version: u64,
}

/// Steps 1–4 of 07 §6.1. `Err((ck, failure))` = NACK (with CK when known, to seal the detail).
#[allow(clippy::too_many_lines)]
async fn admit(node: &Arc<Node>, keys: &Keys, assign: &pb::Assign, body: &[pb::Chunk]) -> Result<Admitted, (Option<ContentKey>, Failure)> {
    let refuse = |code: &str, retry: bool, d: Option<String>| (None, Failure::new(code, retry, d));
    let task: TaskId = assign.task.parse().map_err(|_| refuse("bad_envelope", false, None))?;
    let attempt = u8::try_from(assign.attempt).map_err(|_| refuse("bad_envelope", false, None))?;
    let wrap = <[u8; crypto::WRAP_LEN]>::try_from(assign.wrap.as_ref()).map_err(|_| refuse("bad_envelope", false, None))?;
    // 1. unwrap (fails if the route header was touched: HPKE AAD) → decrypt only. The stranger's
    // bytes (zstd, JSON) are parsed in the jailed single-use validator, never here (§15.2).
    let ck = crypto::unwrap(&keys.enc, &task, &assign.route, &wrap).map_err(|_| refuse("bad_envelope", false, None))?;
    let with_ck = |code: &str, retry: bool, d: Option<String>| (Some(ck.clone()), Failure::new(code, retry, d));
    let mut dec = RequestDecryptor::new(&ck, &task).map_err(|_| with_ck("bad_envelope", false, None))?;
    for c in body {
        dec.push(c).map_err(|_| with_ck("bad_envelope", false, None))?;
    }
    if dec.chunks() != assign.body_chunks {
        return Err(with_ck("bad_envelope", false, None));
    }
    let payload = dec.finish().map_err(|_| with_ck("bad_envelope", false, None))?;
    // The route header is fixed-size-ish signed JSON: the parent's strict parser (CONTRACT §1).
    let route = RouteHeader::parse(&assign.route).map_err(|_| with_ck("bad_envelope", false, None))?;
    if route.repo_id.text() != assign.repo_id {
        return Err(with_ck("unauthorized_task", false, Some("the request is for another project than this donation".into())));
    }
    let now = now_ms();
    if !task.admissible(now, node.boot_ms) {
        return Err(with_ck("unauthorized_task", false, Some("task id outside the freshness window".into())));
    }
    let pledge: PledgeId = assign.pledge_id.parse().map_err(|_| with_ck("unauthorized_task", false, Some("no donation".into())))?;
    let person = own_donation(node, &assign.pledge_id, &assign.repo_id).await.map_err(|d| with_ck("unauthorized_task", false, Some(d.into())))?;
    // 2. Adapter + catalog entry, pledge policy, route expectations for the validator.
    let dialect = Dialect::from_wire(route.dialect.as_str()).ok_or_else(|| with_ck("route_mismatch", false, None))?;
    let cat = node.catalog_v(assign.catalog_version).ok_or_else(|| with_ck("model_unavailable", true, Some("unknown price list version".into())))?;
    // F11: the donor's limits are counted with this price list: only the one the key log shows.
    // D14: relay-asserted only without a verified key log and in insecure dev mode.
    let logged = || match node.keylog.as_ref().filter(|l| l.verified()) {
        Some(l) => cat.logged(l.catalog_sha256(cat.version)),
        None => node.insecure_dev,
    };
    // A new price list can reach this node just before the checkpoint that logs it: give the
    // mirror a moment instead of refusing every task right after a publish.
    // ponytail: 3 s poll, a key-log update notification if this ever shows in latency.
    let mut ok = logged();
    for _ in 0..30 {
        if ok {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        ok = logged();
    }
    if !ok {
        return Err(with_ck("model_unavailable", true, Some("price list not in the key log".into())));
    }
    let Some((adapter, entry)) = node.adapters.iter().find_map(|a| {
        let e = cat.entry(&route.model, a.provider().as_str())?;
        (a.provider().serves(dialect.worker()) && e.dialects.contains(&route.dialect)).then(|| (a.clone(), e.clone()))
    }) else {
        return Err(with_ck("model_unavailable", true, None));
    };
    let fwc = engine::fw_catalog(&entry).ok_or_else(|| with_ck("model_unavailable", true, None))?;
    let (policy, (daily, weekly)) = pledge_policy(node, &assign.pledge_policy, &route).map_err(|d| with_ck("firewall", false, Some(d)))?;
    let pmid = node.provider_model_id(&entry).ok_or_else(|| with_ck("model_unavailable", true, None))?;
    let mut aliases: Vec<&str> = vec![entry.model.as_str(), pmid.as_str()];
    aliases.extend(entry.aliases.iter().map(String::as_str));
    let effort = Effort::parse(&route.effort).ok_or_else(|| with_ck("route_mismatch", false, Some("effort".into())))?;
    let flags = engine::route_flags(&route).ok_or_else(|| with_ck("route_mismatch", false, Some("flags".into())))?;
    // Per-member provider pseudonym H(repo ‖ gateway device), never the raw id. The device comes
    // from `Assign.gateway_device` (relay-asserted, ids only): it is checked below against the
    // device the child decoded from the signed payload, and that device against the key log,
    // before anything reaches the provider. An older relay without it: per (repo, donation).
    let claimed_gw = Some(assign.gateway_device.as_str()).filter(|d| !d.is_empty());
    if claimed_gw.is_some_and(|d| d.parse::<moochy_proto::DeviceId>().is_err()) {
        return Err(with_ck("bad_envelope", false, None));
    }
    let pseudo = user_pseudonym(&assign.repo_id, claimed_gw.unwrap_or(&assign.pledge_id));
    let req = ValidateRequest {
        provider: adapter.provider(),
        dialect: dialect.worker(),
        policy,
        catalog: fwc,
        provider_model_id: &pmid,
        user_pseudonym: &pseudo,
        max_price: Some(MaxPrice { prompt_uusd_per_mtok: entry.input, completion_uusd_per_mtok: entry.out }),
        route: Route {
            dialect: dialect.worker(),
            model_aliases: &aliases,
            effort,
            max_tokens: route.max_tokens.into(),
            est_input_tokens: route.est_input_tokens,
            cache_ttl: engine::cache_ttl_w(route.cache_ttl),
            stream: route.stream,
            flags,
        },
        payload: &payload,
    };
    // 3. Decompress + inner payload + firewall + route/body consistency, in the jailed child.
    let validator = node.validator.as_ref().ok_or_else(|| with_ck("busy", true, None))?;
    let v = validator.validate(&req).await.map_err(|e| {
        let (code, retry) = e.nack();
        if code == "busy" {
            log("warn", "request validator failed", &json!({"task": task.text(), "error": e.to_string()}));
        }
        with_ck(code, retry, Some(e.to_string()))
    })?;
    drop(payload);
    // The child's verdict is the firewall, but authenticity is checked here, by the parent:
    // body hash + task signature over the exact bytes the child returned (03 §7.2).
    let inner = InnerPayload {
        v: 1,
        body_b64: moochy_proto::Blob(v.body.to_vec()),
        body_sha256: moochy_proto::B(v.body_sha256),
        headers: v.headers.iter().cloned().collect(),
        s: moochy_proto::B(v.s),
        gateway_device: v.gateway_device.parse().map_err(|_| with_ck("bad_envelope", false, None))?,
        task_sig: moochy_proto::B(v.task_sig),
    };
    let prepared = v.prepared;
    if claimed_gw.is_some_and(|d| d != inner.gateway_device.text()) {
        return Err(with_ck("bad_envelope", false, Some("the relay named another requesting device than the signed request".into())));
    }
    let ctx = crypto::TaskContext { task: &task, repo: &route.repo_id, route: &assign.route };
    match requester_key(node, person.as_deref(), &inner.gateway_device.text(), &assign.repo_id).map_err(|d| with_ck("unauthorized_task", false, Some(d)))? {
        Some(pk) => inner.verify(&ctx, &pk).map_err(|_| with_ck("unauthorized_task", false, Some("task signature".into())))?,
        // D14: relay-asserted membership only without a verified key log and in insecure dev
        // mode; the body hash still binds.
        None if node.insecure_dev && !node.keylog.as_ref().is_some_and(|l| l.verified()) => {
            if !crypto::ct_eq(&crypto::sha256(&inner.body_b64.0), &inner.body_sha256.0) {
                return Err(with_ck("bad_envelope", false, None));
            }
        }
        None => return Err(with_ck("unauthorized_task", false, Some("gateway key not in the key log".into()))),
    }
    let (gw, tid, ts) = (inner.gateway_device.text(), task.text(), task.0.timestamp_ms());
    match with_store(node, move |s| s.check_served(&gw, &tid, ts, now)).await {
        Some(Ok(())) => {}
        Some(Err(StoreError::Stale | StoreError::Replay)) => return Err(with_ck("unauthorized_task", false, Some("task already served".into()))),
        _ => return Err(with_ck("busy", true, None)),
    }
    // 4. Local reservation: device cap, plus the pledge's per-task cap and headroom from Assign.
    let amount = money::reserve_for_route(&entry, &route).ok().and_then(|a| u64::try_from(a).ok()).ok_or_else(|| with_ck("local_cap", true, None))?;
    let positive = |v: i64| u64::try_from(v).ok().filter(|v| *v > 0);
    let task_cap = positive(assign.per_task_cap_uusd).unwrap_or(u64::MAX);
    if positive(assign.pledge_headroom_uusd).is_some_and(|h| amount > h) && assign.pledge_headroom_uusd != 0 {
        return Err(with_ck("local_cap", true, Some("this donation's limit is reached".into())));
    }
    let key = attempt_key(&task.text(), u32::from(attempt));
    let (k2, p2, cap) = (key.clone(), pledge.text(), device_cap(node).unwrap_or(0));
    let reserved = with_store(node, move |s| {
        s.reserve(&Reservation {
            key: &k2,
            pledge_id: &p2,
            pledge_period: u64::from(moochy_worker::store::month_of(now)),
            pledge_budget_uusd: u64::MAX,
            pledge_daily_uusd: daily,
            pledge_weekly_uusd: weekly,
            per_task_cap_uusd: task_cap,
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
    Ok(Admitted { ck, task, inner: Arc::new(inner), route, entry, adapter, prepared, pledge, key, catalog_version: cat.version })
}

/// Returns `(journal status, model, cost)`.
async fn serve(
    node: &Arc<Node>,
    task_s: &str,
    attempt: u32,
    down: &mut tonic::Streaming<ServeDown>,
    tx: &mpsc::Sender<ServeUp>,
) -> Served {
    let r = crypto::random32().unwrap_or([0; 32]);
    let task16 = task_s.parse::<TaskId>().map_or([0; 16], |t| t.0.0);
    let device = node.device_id().unwrap_or_default().to_owned();
    let refuse = Refuse { tx, r, task: task_s, task16, worker: &device, attempt };
    let refused = |code: &str| (format!("refused:{code}"), String::new(), 0, None, false);
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
    let reserved = money::reserve_for_route(&a.entry, &a.route).unwrap_or(0);
    // The crash record hashes the whole body (req_commit): built on a blocking thread, so the
    // provider call (and `Started`) never waits for it.
    let (prov, path, model) = (a.prov(keys), inflight_path(node, task_s, attempt), a.route.model.clone());
    let attempt8 = u8::try_from(attempt).unwrap_or(0);
    let record = Some(tokio::task::spawn_blocking(move || {
        if let Some(rc) = provisional_of(&prov, attempt8, t_start) {
            write_inflight_now(&path, &rc, &model, reserved);
        }
    }));
    log("info", "timing", &json!({"task": task_s, "attempt": attempt, "t_assign_rx": t_assign_rx, "t_ack_tx": now_us()}));
    let out = run_provider(node, keys, a, attempt, r, t_start, down, &refuse).await;
    // The attempt is settled (receipt in the outbox): the record has served its purpose.
    if let Some(h) = record {
        let _ = h.await;
        drop_inflight(node, task_s, attempt);
    }
    out
}

/// Steps 6–9: provider call, sealed streaming, receipt.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_provider(node: &Arc<Node>, keys: &Keys, a: Admitted, attempt: u32, r: [u8; 32], t_start: u64, down: &mut tonic::Streaming<ServeDown>, refuse: &Refuse<'_>) -> Served {
    let tx = refuse.tx;
    let dialect = Dialect::from_wire(a.route.dialect.as_str()).unwrap_or(Dialect::Anthropic);
    let attempt8 = u8::try_from(attempt).unwrap_or(0);
    let Ok(mut sealer) = ResponseSealer::new(&a.ck, &r, &a.task, &keys.device_id, attempt8) else { return ("failed:internal".into(), String::new(), 0, None, false) };
    let call = tokio::select! {
        r = a.adapter.send(dialect.worker(), a.prepared.body.clone(), &a.prepared.headers) => Some(r),
        () = wait_cancel(down) => None,
    };
    let mut resp = match call {
        Some(Ok(resp)) => {
            note_headroom(node, &a.route.model, &resp.rate_limit);
            resp
        }
        Some(Err(f)) => {
            if let Some(rl) = &f.rate_limit {
                note_headroom(node, &a.route.model, rl);
            }
            let (code, retry) = f.nack();
            // A291: the provider's error text (which may echo the key) stays here.
            let mut fl = Failure::new(code, retry, Some(f.public_message()));
            fl.retry_after_ms = f.retry_after_ms.map(|m| u32::try_from(m).unwrap_or(u32::MAX));
            refuse.nack(Some(&a.ck), &fl).await;
            // After the Ack the relay awaits a receipt: zero usage, provably nothing generated.
            let end = Ending { status: ReceiptStatus::NotStarted, usage: Usage::default(), cost: 0, local: 0, model: String::new(), req_id: String::new(), times: (t_start, 0) };
            let st = format!("refused:{code}");
            finish(node, keys, &a, attempt8, &sealer, end, down, refuse, (&st, None)).await;
            return (st, String::new(), 0, None, true);
        }
        None => {
            let end = Ending { status: ReceiptStatus::NotStarted, usage: Usage::default(), cost: 0, local: 0, model: String::new(), req_id: String::new(), times: (t_start, 0) };
            finish(node, keys, &a, attempt8, &sealer, end, down, refuse, ("cancelled", None)).await;
            return ("cancelled".into(), String::new(), 0, None, true);
        }
    };
    let t_started = now_ms();
    let _ = tx.send(up(serve_up::Msg::Started(pb::Started { attempt }))).await;
    let mut parser = StreamParser::new(dialect.worker(), a.route.stream);
    let mut seen: Vec<u8> = Vec::new();
    let checkpoint = |s: &ResponseSealer| -> Option<pb::Checkpoint> {
        let seq = s.last_seq()?;
        let h = s.running_hash();
        let m = crypto::checkpoint_msg(&a.task, attempt8, &r, seq, &h).ok()?;
        Some(pb::Checkpoint { attempt, seq, running_hash: Bytes::copy_from_slice(&h), sig: Bytes::copy_from_slice(&keys.sign.sign(&m)) })
    };
    let mut status = ReceiptStatus::Ok;
    let mut link_ok = true;
    let red = a.adapter.redactor();
    // CONTRACT §23, A291: only whole SSE events leave this machine and a provider error event
    // never does (the stream is cut there; the Gateway reports it in our own words); a
    // non-streamed body leaves once complete and known not to be an error. Everything that
    // leaves is redacted of the key. `held`: received, not forwarded yet, starting at offset `fwd`.
    let mut held = bytes::BytesMut::new();
    let mut fwd: u64 = 0;
    let len64 = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    loop {
        let next = tokio::select! {
            n = resp.next() => n,
            () = wait_cancel(down) => { status = ReceiptStatus::Cancelled; break; }
        };
        match next {
            Ok(Some(b)) => {
                let (mut cut, mut ready) = (None::<u64>, fwd);
                let fed = parser.feed(&b, &mut |span, ev| {
                    if cut.is_none() && matches!(ev, Event::Error) {
                        cut = Some(span.start);
                    }
                    ready = span.end;
                });
                let Ok(fed) = fed else {
                    status = ReceiptStatus::ProviderError;
                    break;
                };
                let end = fwd.saturating_add(len64(held.len())).saturating_add(len64(b.len()));
                let upto = if a.route.stream { cut.unwrap_or(ready) } else { fwd };
                // Fast path (one event or more per chunk, nothing held): the chunk as is.
                let piece = if held.is_empty() && upto == end {
                    b
                } else {
                    held.extend_from_slice(&b);
                    let n = usize::try_from(upto.saturating_sub(fwd)).unwrap_or(usize::MAX).min(held.len());
                    held.split_to(n).freeze()
                };
                fwd = upto;
                let piece = redacted(red, piece);
                if node.cfg.journal_full_text && seen.len() < MAX_JOURNAL_TEXT {
                    seen.extend_from_slice(piece.get(..piece.len().min(MAX_JOURNAL_TEXT.saturating_sub(seen.len()))).unwrap_or_default());
                }
                link_ok = send_sealed(tx, &mut sealer, &piece).await;
                if fed.tool_ends > 0
                    && let Some(c) = checkpoint(&sealer)
                {
                    let _ = tx.send(up(serve_up::Msg::Checkpoint(c))).await;
                }
                if !link_ok {
                    status = ReceiptStatus::Cancelled;
                    break;
                }
                if cut.is_some() {
                    status = ReceiptStatus::ProviderError;
                    break;
                }
            }
            Ok(None) => {
                if !a.route.stream {
                    let body = if parser.finish().provider_error { own_error_body(dialect.worker()) } else { redacted(red, held.split().freeze()) };
                    if node.cfg.journal_full_text {
                        seen.extend_from_slice(body.get(..body.len().min(MAX_JOURNAL_TEXT)).unwrap_or_default());
                    }
                    link_ok = send_sealed(tx, &mut sealer, &body).await;
                }
                break;
            }
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
        && tx.send(up(serve_up::Msg::Chunk(c))).await.is_ok()
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
        // xAI's reported charge (`cost_in_usd_ticks`) is authoritative too, but optional; the
        // relay refuses a provider cost above the reservation, so it is capped there.
        provider_cost_uusd: match a.entry.provider.as_str() {
            "openrouter" => Some(or_cost.unwrap_or(reserved)),
            "xai" => or_cost.map(|c| c.min(reserved)),
            _ => None,
        },
    };
    let fast = a.route.flags.iter().any(|f| f == "fast");
    // Fallback when a cost cannot be computed (e.g. OpenRouter without a reported cost): the reservation.
    let cost = money::cost_uusd(&a.entry, &usage, fast).unwrap_or(reserved);
    let xai_charged = (a.entry.provider == "xai").then(|| out.usage.provider_cost_uusd.and_then(|c| i64::try_from(c).ok())).flatten();
    let local = local_cost(cost, reserved, usage.estimated, xai_charged);
    let model = red.redact_str(&clean(out.model.as_deref().unwrap_or(""))).into_owned();
    let req_id = request_id.or(out.id).unwrap_or_default();
    let end = Ending { status, usage, cost, local, model: model.clone(), req_id, times: (t_start, t_started) };
    let st = match status {
        ReceiptStatus::Ok => "ok",
        ReceiptStatus::Cancelled => "cancelled",
        ReceiptStatus::ProviderError => "provider_error",
        ReceiptStatus::Partial => "partial",
        ReceiptStatus::NotStarted => "not_started",
    };
    // Opt-in full text for the donor's own journal (bounded; never sent anywhere).
    let text = node.cfg.journal_full_text.then(|| (clip(&a.inner.body_b64.0), clip(&seen)));
    finish(node, keys, &a, attempt8, &sealer, end, down, refuse, (st, text.clone())).await;
    (st.into(), model, cost, text, true)
}

/// What the donor's own caps settle at: an upper bound of what the provider billed. The receipt
/// cost; never less than the reservation when the usage is estimated (a cut or cancelled stream
/// lost the final usage: the provider still billed the whole prompt; the relay settles these at
/// the reservation too, 05 §5.2, F01); xAI: what it actually charged when that is above the
/// receipt (reasoning beyond the reservation).
fn local_cost(cost: i64, reserved: i64, estimated: bool, xai_charged: Option<i64>) -> i64 {
    let c = xai_charged.map_or(cost, |x| x.max(cost));
    if estimated { c.max(reserved) } else { c }
}

/// `b` with the adapter's key redacted (A291); the same buffer when clean.
fn redacted(red: &moochy_worker::redact::Redactor, b: Bytes) -> Bytes {
    let owned = match red.redact(&b) {
        std::borrow::Cow::Owned(v) => Some(v),
        std::borrow::Cow::Borrowed(_) => None,
    };
    owned.map_or(b, Bytes::from)
}

/// A291: a non-streamed provider error body is replaced by ours (same shape, our words).
fn own_error_body(d: moochy_worker::Dialect) -> Bytes {
    Bytes::from_static(match d {
        moochy_worker::Dialect::AnthropicMessages => br#"{"type":"error","error":{"type":"api_error","message":"the donor's provider reported an error"}}"#,
        _ => br#"{"error":{"message":"the donor's provider reported an error","type":"server_error"}}"#,
    })
}

/// Seal and send `piece` at once (CONTRACT §13), in frames of at most `MAX_CHUNK`. `false`:
/// the link is gone.
async fn send_sealed(tx: &mpsc::Sender<ServeUp>, sealer: &mut ResponseSealer, piece: &[u8]) -> bool {
    for part in piece.chunks(crypto::MAX_CHUNK) {
        let Ok(c) = sealer.seal(part, false) else { return true };
        if tx.send(up(serve_up::Msg::Chunk(c))).await.is_err() {
            return false;
        }
    }
    true
}

struct Ending {
    status: ReceiptStatus,
    usage: Usage,
    cost: i64,
    /// What the donor's local cap settles at (≥ `cost`).
    local: i64,
    model: String,
    req_id: String,
    times: (u64, u64),
}

/// Sign the receipt, persist it (fsync) before `End`, journal the attempt, send `End`, then wait
/// for the ack; if none comes on the Serve stream, hand it to the session (`ReplayReceipt`) so
/// it is never lost. The journal entry is written before `End`: the relay settles the task on
/// `End`, and the ack wait plus its outbox fsync can take seconds on a slow disk (E62).
#[allow(clippy::too_many_arguments)]
async fn finish(
    node: &Arc<Node>,
    keys: &Keys,
    a: &Admitted,
    attempt: u8,
    sealer: &ResponseSealer,
    e: Ending,
    down: &mut tonic::Streaming<ServeDown>,
    refuse: &Refuse<'_>,
    journal: (&str, Option<Texts>),
) {
    let ucost = u64::try_from(e.local).unwrap_or(0);
    // CONTRACT §20: the receipt's split, as the Gateway journals it (in = input + cache reads and
    // writes, out = output).
    let u = &e.usage;
    let tokens = (u.input.saturating_add(u.cache_read).saturating_add(u.cache_write_5m).saturating_add(u.cache_write_1h), u.output);
    let Some(signed) = build_receipt(keys, a, attempt, sealer, &e.req_id, e.usage, e.cost, e.status, &e.model, e.times) else {
        log("error", "receipt signing failed", &json!({"task": refuse.task}));
        return;
    };
    let (key, payload) = (a.key.clone(), signed.encode_to_vec());
    if with_store(node, move |s| s.put_receipt(&key, &payload, ucost, now_ms())).await.is_none_or(|r| r.is_err()) {
        log("error", "outbox write failed", &json!({"task": refuse.task}));
    } else {
        // The receipt is in the outbox: the in-flight record has served its purpose.
        let path = inflight_path(node, refuse.task, refuse.attempt);
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(path)).await;
    }
    let (t0, now) = (e.times.0, now_ms());
    let (request, response) = journal.1.unwrap_or_default();
    // m8: the project as this donor's donation names it (an org or person donation: the org or
    // person; `Assign` carries only the served repo's id), and the donation.
    let pledge = a.pledge.text();
    let repo = lock(&node.own_pledges).get(&pledge).map(|(.., t)| t.clone()).unwrap_or_default();
    node.journal(JournalEntry {
        t_ms: i64::try_from(t0).unwrap_or(0),
        role: "worker".into(),
        task: refuse.task.to_owned(),
        repo,
        pledge_id: pledge,
        status: journal.0.to_owned(),
        model: e.model.clone(),
        cost_uusd: e.cost,
        request,
        response,
        ms: u32::try_from(now.saturating_sub(t0)).unwrap_or(u32::MAX),
        tokens_in: tokens.0,
        tokens_out: tokens.1,
        ..JournalEntry::default()
    });
    let sent = refuse.tx.send(up(serve_up::Msg::End(signed.clone()))).await.is_ok();
    let ack = if sent {
        timeout(Duration::from_secs(5), async {
            while let Some(m) = next(down).await {
                if let serve_down::Msg::ReceiptAck(a) = m {
                    return Some(a);
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    } else {
        None
    };
    if let Some(ack) = ack {
        crate::keylog::check_receipt_ack(node, &signed.receipt, &ack);
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
) -> Option<pb::SignedReceipt> {
    let s = &a.inner.s.0;
    let mut rc = provisional(keys, a, attempt, t_start)?;
    rc.model_reported = model.into();
    rc.usage = usage;
    rc.cost_uusd = cost;
    rc.resp_commit = moochy_proto::B(crypto::resp_commit(&crypto::salt(s, SaltName::Resp).ok()?, &sealer.running_hash()).ok()?);
    rc.provider_req_hash = moochy_proto::B(crypto::provider_req_hash(&crypto::salt(s, SaltName::Pid).ok()?, provider_req_id).ok()?);
    rc.status = status;
    rc.t_started = if status == ReceiptStatus::NotStarted { 0 } else { t_started };
    sign_receipt(keys, &rc, &a.route.model)
}

/// The receipt as known at the Ack: what a crash mid-stream settles at (05 §5.2): usage
/// unknown (estimated), cost = the reservation, status `partial`.
/// What the provisional (crash) receipt needs, owned, so it can be built off the async path.
struct Prov {
    worker: moochy_proto::DeviceId,
    task: TaskId,
    pledge: PledgeId,
    catalog_version: u64,
    inner: Arc<InnerPayload>,
    route: RouteHeader,
    entry: CatalogEntry,
}

impl Admitted {
    fn prov(&self, keys: &Keys) -> Prov {
        Prov { worker: keys.device_id, task: self.task, pledge: self.pledge, catalog_version: self.catalog_version, inner: self.inner.clone(), route: self.route.clone(), entry: self.entry.clone() }
    }
}

fn provisional(keys: &Keys, a: &Admitted, attempt: u8, t_start: u64) -> Option<Receipt> {
    provisional_of(&a.prov(keys), attempt, t_start)
}

fn provisional_of(a: &Prov, attempt: u8, t_start: u64) -> Option<Receipt> {
    let s = &a.inner.s.0;
    let reserved = money::reserve_for_route(&a.entry, &a.route).ok()?;
    let usage = Usage { estimated: true, provider_cost_uusd: (a.entry.provider == "openrouter").then_some(reserved), ..Usage::default() };
    // The relay recomputes cost from usage and settles estimated receipts at the reservation.
    let cost = money::cost_uusd(&a.entry, &usage, a.route.flags.iter().any(|f| f == "fast")).ok()?;
    Some(Receipt {
        v: 1,
        task_id: a.task,
        attempt,
        repo_id: a.route.repo_id,
        pledge_id: a.pledge,
        worker_device: a.worker,
        gateway_device: a.inner.gateway_device,
        dialect: a.route.dialect,
        provider: a.entry.provider.clone(),
        model_reported: String::new(),
        usage,
        catalog_version: a.catalog_version,
        cost_uusd: cost,
        req_commit: moochy_proto::B(crypto::req_commit(&crypto::salt(s, SaltName::Req).ok()?, &a.inner.body_b64.0).ok()?),
        resp_commit: moochy_proto::B(crypto::resp_commit(&crypto::salt(s, SaltName::Resp).ok()?, &crypto::sha256(b"")).ok()?),
        provider_req_hash: moochy_proto::B(crypto::provider_req_hash(&crypto::salt(s, SaltName::Pid).ok()?, "").ok()?),
        status: ReceiptStatus::Partial,
        t_start,
        t_started: t_start,
        t_end: 0,
    })
}

/// Sign a receipt and its public projection (`model` = the public model id).
fn sign_receipt(keys: &Keys, rc: &Receipt, model: &str) -> Option<pb::SignedReceipt> {
    let mut rc = rc.clone();
    rc.t_end = now_ms();
    let (rbytes, rsig) = crypto::sign_receipt(&keys.sign, &rc).ok()?;
    let p = Projection {
        v: 1,
        receipt_ref: moochy_proto::B(crate::util::rand_bytes::<16>().ok()?),
        repo_id: rc.repo_id,
        donor: None,
        model: model.into(),
        cost_uusd: rc.cost_uusd,
        day: utc_day(now_ms()),
        receipt_sha256: moochy_proto::B(crypto::sha256(&rbytes)),
    };
    let (pbytes, psig) = crypto::sign_projection(&keys.sign, &p).ok()?;
    Some(pb::SignedReceipt {
        task: rc.task_id.text(),
        attempt: rc.attempt.into(),
        receipt: Bytes::from(rbytes),
        donor_sig: Bytes::copy_from_slice(&rsig),
        projection: Bytes::from(pbytes),
        projection_sig: Bytes::copy_from_slice(&psig),
    })
}

// ---- durable in-flight record (E37) ----
//
// Written right after the Ack (off the Ack path, no fsync: it must survive a crash of this
// process, not a power loss, where the relay settles at the reservation after 24 h anyway) and
// removed once the real receipt is in the outbox. A record left over at start means the process
// died mid-attempt: its provisional receipt goes to the outbox and is replayed on Welcome, so the
// relay replaces its pessimistic settlement.

fn inflight_dir(node: &Node) -> std::path::PathBuf {
    node.home.state_dir().join("inflight")
}

fn inflight_path(node: &Node, task: &str, attempt: u32) -> std::path::PathBuf {
    inflight_dir(node).join(format!("{task}-{attempt}"))
}

/// Record: `<public model> <reserved µ$>\n<receipt JSON>`; the donor's own cap settles at the
/// reservation.
/// Write one in-flight record (blocking; a torn write fails to parse at recovery and is dropped).
fn write_inflight_now(path: &std::path::Path, rc: &Receipt, model: &str, reserved: i64) {
    let Ok(json) = serde_json::to_vec(rc) else { return };
    let mut data = format!("{model} {reserved}\n").into_bytes();
    data.extend_from_slice(&json);
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if std::fs::write(path, &data).is_err() {
        log("warn", "in-flight record write failed", &json!({}));
    }
}

fn drop_inflight(node: &Node, task: &str, attempt: u32) {
    let path = inflight_path(node, task, attempt);
    tokio::task::spawn_blocking(move || std::fs::remove_file(path));
}

/// At start: turn every leftover in-flight record into an outbox receipt (bounded).
async fn recover_inflight(node: &Arc<Node>, keys: &Keys) {
    let dir = inflight_dir(node);
    let files = tokio::task::spawn_blocking(move || {
        let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
        rd.filter_map(Result::ok).take(1024).filter_map(|e| Some((e.path(), std::fs::read(e.path()).ok().filter(|b| b.len() <= 64 << 10)?))).collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    for (path, data) in files {
        let parsed = data.iter().position(|b| *b == b'\n').and_then(|i| {
            let (head, json) = (std::str::from_utf8(data.get(..i)?).ok()?, data.get(i.checked_add(1)?..)?);
            let (model, reserved) = head.split_once(' ')?;
            Some((model.to_owned(), reserved.parse::<u64>().ok()?, serde_json::from_slice::<Receipt>(json).ok()?))
        });
        let signed = parsed
            .as_ref()
            .filter(|(m, _, rc)| crate::node::plain_id(m) && rc.worker_device == keys.device_id)
            .and_then(|(m, reserved, rc)| Some((sign_receipt(keys, rc, m)?, *reserved, rc)));
        if let Some((signed, cost, rc)) = signed {
            let (key, payload) = (attempt_key(&rc.task_id.text(), rc.attempt.into()), signed.encode_to_vec());
            // Never a second receipt for an attempt the outbox already holds one for (the real
            // receipt is fsynced before `End`): the relay treats different bytes for a settled
            // attempt as a conflict.
            let put = with_store(node, move |s| {
                if s.since(0).any(|(k, _)| k == key.as_slice()) {
                    return Ok(false);
                }
                s.put_receipt(&key, &payload, cost, now_ms()).map(|()| true)
            })
            .await;
            match put {
                Some(Ok(true)) => log("warn", "recovered an attempt interrupted by a crash: estimated receipt queued", &json!({"task": rc.task_id.text(), "attempt": rc.attempt})),
                Some(Ok(false)) => {}
                _ => continue, // keep the record: retried at the next start
            }
        }
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(path)).await;
    }
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
    fn local_caps_settle_estimated_usage_at_the_reservation() {
        use super::local_cost;
        // F01: a stream cut before the final usage chunk prices ~0 input; the caps book the reservation.
        assert_eq!(local_cost(12, 9_000, true, None), 9_000);
        assert_eq!(local_cost(12, 9_000, true, Some(40)), 9_000, "xAI too");
        assert_eq!(local_cost(12_000, 9_000, true, None), 12_000, "never below the receipt cost");
        assert_eq!(local_cost(12, 9_000, false, None), 12, "final usage: the receipt cost");
        assert_eq!(local_cost(12, 9_000, false, Some(15_000)), 15_000, "xAI's charge above the receipt");
    }

    #[test]
    fn utc_days() {
        assert_eq!(super::utc_day(0), "1970-01-01");
        assert_eq!(super::utc_day(951_782_400_000), "2000-02-29");
        assert_eq!(super::utc_day(1_790_812_800_000), "2026-10-01");
    }

    #[test]
    fn policy_windows_known_keys_and_unknown_refused() {
        let w = |s: &str| super::policy_windows(&crate::json::parse_object(s.as_bytes()).unwrap_or_default());
        assert_eq!(w(r#"{"models":[],"max_effort":"","dialects":[],"flags":[]}"#), Ok((u64::MAX, u64::MAX)), "the 0.1.2 relay's policy");
        assert_eq!(w(r#"{"models":[],"daily_limit_uusd":2000000,"weekly_limit_uusd":8000000}"#), Ok((2_000_000, 8_000_000)));
        assert_eq!(w(r#"{"daily_limit_uusd":0,"weekly_limit_uusd":null}"#), Ok((u64::MAX, u64::MAX)), "0 / null = none");
        assert!(w(r#"{"daily_limit_uusd":-1}"#).is_err());
        assert!(w(r#"{"weekly_limit_uusd":"8"}"#).is_err());
        // A limit this client does not know: refuse the donation, never serve it without the limit.
        assert!(w(r#"{"models":[],"hourly_limit_uusd":100}"#).is_err_and(|e| e.contains("hourly_limit_uusd")));
    }
}
