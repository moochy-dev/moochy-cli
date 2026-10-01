//! Worker role orchestration (07 §6.1): offers; `AssignNotice` → one gRPC `Serve` stream per
//! attempt → open (Sealer) → execute (Executor) → Ack/Nack, Started, sealed chunks,
//! checkpoints, signed receipt. Cancel or stream loss aborts the provider call.

use crate::engine::{Dialect, ExecEvent, ExecOutcome, ExecRequest, Failure, WorkerCtx};
use crate::node::{Busy, Node};
use crate::pb::link::{self as pb, ServeDown, ServeUp, serve_down, serve_up};
use crate::pb::local::JournalEntry;
use crate::util::{clean, log, now_ms, rand_bytes};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;

/// 32 MiB body (03 §16) in ≤ 64 KiB chunks, plus slack.
const MAX_BODY_CHUNKS: u32 = 600;
const MAX_BODY_LEN: u64 = 32 << 20;
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Max plaintext per chunk: 65,536 − 23 − 16 (03 §4.2).
const MAX_PLAIN: usize = 65_497;

fn can_serve(node: &Node) -> bool {
    node.cfg.has_role("worker") && node.sealer.is_some() && node.cfg.device_monthly_cap_uusd.is_some() && !node.executor.models().is_empty()
}

fn slots_max(node: &Node) -> u32 {
    node.cfg.slots_max.unwrap_or(crate::config::DEFAULT_SLOTS)
}

pub fn offer(node: &Node) -> pb::NodeMsg {
    let paused = node.paused.load(Ordering::Relaxed);
    let models = node.executor.models().iter().map(|m| pb::ModelOffer { dialect: m.dialect.wire().into(), model: m.model.clone(), rl_headroom: 100 }).collect();
    let free = if paused { 0 } else { slots_max(node).saturating_sub(node.worker_busy.load(Ordering::Relaxed)) };
    let cap = node.cfg.device_monthly_cap_uusd.and_then(|c| i64::try_from(c).ok()).unwrap_or(0);
    pb::NodeMsg { msg: Some(pb::node_msg::Msg::Offer(pb::WorkerOffer { slots_free: free, models, pledges: Vec::new(), window_open: !paused, local_cap_left_uusd: cap })) }
}

/// Send a fresh offer (after a task ends, pause/resume).
pub fn reoffer(node: &Node) {
    if can_serve(node)
        && let Some(l) = node.link()
    {
        let _ = l.up.try_send(offer(node));
    }
}

pub fn on_welcome(node: &Arc<Node>) {
    if !can_serve(node) {
        log("info", "worker role idle (needs provider keys, device_monthly_cap_uusd, and the crypto backend)", &json!({}));
        return;
    }
    if let Some(l) = node.link() {
        let _ = l.up.try_send(pb::NodeMsg { msg: Some(pb::node_msg::Msg::KnownTasks(pb::KnownTasks { tasks: Vec::new() })) });
        let _ = l.up.try_send(offer(node));
    }
}

fn up(m: serve_up::Msg) -> ServeUp {
    ServeUp { msg: Some(m) }
}

fn nack(f: &Failure) -> ServeUp {
    let r: [u8; 32] = rand_bytes().unwrap_or([0; 32]);
    let retry = f.retry_after_ms.map_or(0, |m| u32::try_from(m).unwrap_or(u32::MAX));
    up(serve_up::Msg::Nack(pb::Nack { r: r.to_vec(), code: f.code.clone(), retryable: f.retryable, retry_after_ms: retry, sealed_detail: Vec::new() }))
}

pub fn on_assign(node: &Arc<Node>, task: String, attempt: u32) {
    let Some(link) = node.link() else { return };
    let node = node.clone();
    tokio::spawn(async move {
        let (tx, rx) = mpsc::channel::<ServeUp>(64);
        let _ = tx.try_send(up(serve_up::Msg::Open(pb::ServeOpen { task: task.clone(), attempt })));
        let mut client = link.client.clone();
        let down = match client.serve(crate::link::with_session(&link, ReceiverStream::new(rx))).await {
            Ok(r) => r.into_inner(),
            Err(s) => {
                log("warn", "serve stream refused", &json!({"task": task, "code": format!("{:?}", s.code())}));
                return;
            }
        };
        let paused = node.paused.load(Ordering::Relaxed);
        if !can_serve(&node) || paused || node.worker_busy.load(Ordering::Relaxed) >= slots_max(&node) {
            let code = if paused { "local_cap" } else { "busy" };
            let _ = tx.send(nack(&Failure::new(code, true, None))).await;
            return;
        }
        let t0 = now_ms();
        let status = {
            let _busy = Busy::new(&node.worker_busy);
            serve(&node, &task, attempt, down, &tx).await
        };
        node.journal(JournalEntry {
            t_ms: i64::try_from(t0).unwrap_or(0),
            role: "worker".into(),
            task,
            status: status.status,
            model: status.model_reported,
            cost_uusd: i64::try_from(status.cost_uusd).unwrap_or(0),
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

fn outcome(status: &str) -> ExecOutcome {
    ExecOutcome { status: status.into(), ..ExecOutcome::default() }
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

async fn serve(node: &Arc<Node>, task: &str, attempt: u32, mut down: tonic::Streaming<ServeDown>, tx: &mpsc::Sender<ServeUp>) -> ExecOutcome {
    let Some((assign, body)) = receive(task, attempt, &mut down).await else {
        let _ = tx.send(nack(&Failure::new("bad_envelope", false, None))).await;
        return outcome("not_started");
    };
    let (Some(sealer), Some(keys), Some(device)) = (node.sealer.as_ref(), node.secrets.device.as_ref(), node.device_id()) else {
        return outcome("not_started");
    };
    // 2. Unwrap, decrypt, verify body hash + task signature.
    let (opened, mut ctx) = match sealer.open(&assign, &body, device, keys) {
        Ok(x) => x,
        Err(code) => {
            log("warn", "task refused", &json!({"task": task, "code": code}));
            let _ = tx.send(nack(&Failure::new(&code, false, None))).await;
            return outcome("not_started");
        }
    };
    drop(body);
    if !node.executor.claim_task(&opened.gateway_device, task) {
        let _ = tx.send(nack(&Failure::new("unauthorized_task", false, None))).await;
        return outcome("not_started");
    }
    let route = crate::json::parse(&assign.route).unwrap_or(Value::Null);
    let Some(dialect) = route.get("dialect").and_then(Value::as_str).and_then(Dialect::from_wire) else {
        let _ = tx.send(nack(&Failure::new("route_mismatch", false, None))).await;
        return outcome("not_started");
    };
    let req = ExecRequest {
        task_id: task.to_owned(),
        dialect,
        route,
        body: opened.body,
        headers: opened.headers,
        pledge: Some(assign.pledge_id.clone()).filter(|p| !p.is_empty()),
    };
    // 3. Firewall + reservation + provider call; stream sealed chunks as they come.
    let mut ex = node.executor.execute(req);
    let mut started = false;
    let cancelled = |started: bool| outcome(if started { "cancelled" } else { "not_started" });
    let result = loop {
        let ev = tokio::select! {
            ev = ex.recv() => ev,
            m = next(&mut down) => match m {
                Some(serve_down::Msg::Cancel(_)) | None => break cancelled(started),
                Some(_) => continue,
            },
        };
        match ev {
            Some(ExecEvent::Ready) => {
                if tx.send(up(serve_up::Msg::Ack(pb::Ack { r: ctx.r().to_vec() }))).await.is_err() {
                    break cancelled(started);
                }
            }
            Some(ExecEvent::Started) => {
                started = true;
                let _ = tx.send(up(serve_up::Msg::Started(pb::Started { attempt }))).await;
            }
            Some(ExecEvent::Bytes(b)) => {
                // Sealed and sent at once (CONTRACT §13); the stream ends with an empty `last` chunk.
                if !send_chunk(tx, ctx.as_mut(), &b, false).await {
                    break cancelled(started);
                }
            }
            Some(ExecEvent::Checkpoint) => {
                let _ = tx.send(up(serve_up::Msg::Checkpoint(ctx.checkpoint()))).await;
            }
            Some(ExecEvent::Done(o)) => break o,
            Some(ExecEvent::Failed(f)) if !started => {
                let _ = tx.send(nack(&f)).await;
                return outcome("not_started");
            }
            Some(ExecEvent::Failed(f)) => break outcome(if f.code == "provider_error" { "provider_error" } else { "partial" }),
            None => break outcome("provider_error"),
        }
    };
    drop(ex);
    // 4. Last chunk + final checkpoint, then the signed receipt (outbox persistence is the Sealer's).
    if started && send_chunk(tx, ctx.as_mut(), &[], true).await {
        let _ = tx.send(up(serve_up::Msg::Checkpoint(ctx.checkpoint()))).await;
    }
    match ctx.finish(&result) {
        Ok(r) => {
            let _ = tx.send(up(serve_up::Msg::End(r))).await;
        }
        Err(e) => log("error", "receipt signing failed", &json!({"task": task, "error": clean(&e)})),
    }
    // Wait briefly for ReceiptAck so the stream ends cleanly.
    let _ = timeout(Duration::from_secs(5), async {
        while let Some(m) = next(&mut down).await {
            if matches!(m, serve_down::Msg::ReceiptAck(_)) {
                break;
            }
        }
    })
    .await;
    result
}

async fn send_chunk(tx: &mpsc::Sender<ServeUp>, ctx: &mut dyn WorkerCtx, b: &[u8], last: bool) -> bool {
    let n = b.len().div_ceil(MAX_PLAIN).max(1);
    for (i, part) in b.chunks(MAX_PLAIN).chain(b.is_empty().then_some(&[][..])).enumerate() {
        let is_last = last && i.saturating_add(1) == n;
        let Ok(c) = ctx.seal_chunk(part, is_last) else { return false };
        if tx.send(up(serve_up::Msg::Chunk(c))).await.is_err() {
            return false;
        }
    }
    true
}
