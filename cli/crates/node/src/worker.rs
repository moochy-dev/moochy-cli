//! Worker role orchestration (07 §6.1): offers, `task.assign` → open (Sealer) → execute
//! (Executor) → ack/nack, started, sealed chunks, checkpoints, `task.end`; cancel aborts.

use crate::engine::{Dialect, ExecEvent, ExecOutcome, ExecRequest, Failure, WorkerCtx};
use crate::link::{MAX_FRAME, text_msg};
use crate::node::{Node, Side, TaskIn};
use crate::util::{b64e, log, rand_bytes, ulid_from_bytes};
use bytes::Bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

/// 32 MiB body (03 §16) in ≤ 64 KiB frames, plus slack.
const MAX_BODY_FRAMES: usize = 600;
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

static BUSY: AtomicU32 = AtomicU32::new(0);

fn can_serve(node: &Node) -> bool {
    node.cfg.has_role("worker") && node.sealer.is_some() && node.cfg.device_monthly_cap_uusd.is_some() && !node.executor.models().is_empty()
}

fn slots_max(node: &Node) -> u32 {
    node.cfg.slots_max.unwrap_or(crate::config::DEFAULT_SLOTS)
}

pub fn offer(node: &Node) -> Value {
    let models: Vec<Value> =
        node.executor.models().iter().map(|m| json!({"dialect": m.dialect.wire(), "model": m.model, "rl_headroom": 100})).collect();
    let free = slots_max(node).saturating_sub(BUSY.load(Ordering::Relaxed));
    json!({"t":"worker.offer","slots_free":free,"models":models,"pledges":[],"window_open":true,
        "local_cap_left":node.cfg.device_monthly_cap_uusd.unwrap_or(0)})
}

pub fn on_welcome(node: &Arc<Node>) {
    if !can_serve(node) {
        log("info", "worker role idle (needs provider keys, device_monthly_cap_uusd, and the crypto backend)", &json!({}));
        return;
    }
    let node = node.clone();
    tokio::spawn(async move {
        let _ = node.send(text_msg(&json!({"t":"worker.known_tasks","tasks":[]}))).await;
        let _ = node.send(text_msg(&offer(&node))).await;
    });
}

pub fn on_assign(node: &Arc<Node>, id: [u8; 16], assign: Value) {
    let key = (id, Side::Worker);
    let task = ulid_from_bytes(&id);
    let attempt = assign.get("attempt").and_then(Value::as_u64).unwrap_or(0);
    let Some(rx) = node.register(key) else {
        // Same task delivered twice while in flight (relay replay).
        nack(node, &task, attempt, &Failure::new("unauthorized_task", false, None));
        return;
    };
    let node = node.clone();
    tokio::spawn(async move {
        if !can_serve(&node) || BUSY.load(Ordering::Relaxed) >= slots_max(&node) {
            nack(&node, &task, attempt, &Failure::new("busy", true, None));
        } else {
            BUSY.fetch_add(1, Ordering::Relaxed);
            serve(&node, &task, attempt, &assign, rx).await;
            BUSY.fetch_sub(1, Ordering::Relaxed);
            let _ = node.send(text_msg(&offer(&node))).await;
        }
        node.unregister(&key);
    });
}

fn nack(node: &Node, task: &str, attempt: u64, f: &Failure) {
    let r: [u8; 32] = rand_bytes().unwrap_or([0; 32]);
    let m = json!({"t":"task.nack","task":task,"attempt":attempt,"R":b64e(&r),"code":f.code,"retryable":f.retryable,"retry_after_ms":f.retry_after_ms});
    node.try_send(text_msg(&m));
}

async fn serve(node: &Arc<Node>, task: &str, attempt: u64, assign: &Value, mut rx: mpsc::Receiver<TaskIn>) {
    // 1. Collect body frames until the last-flagged one.
    let mut frames: Vec<Bytes> = Vec::new();
    let got = timeout(BODY_TIMEOUT, async {
        while let Some(m) = rx.recv().await {
            match m {
                TaskIn::Frame(f) if f.len() <= MAX_FRAME => {
                    let last = f.get(22).is_some_and(|b| b & 1 == 1);
                    frames.push(f);
                    if last {
                        return true;
                    }
                    if frames.len() > MAX_BODY_FRAMES {
                        return false;
                    }
                }
                TaskIn::Text(v) if v.get("t").and_then(Value::as_str) == Some("task.cancel") => return false,
                _ => {}
            }
        }
        false
    })
    .await;
    if got != Ok(true) {
        nack(node, task, attempt, &Failure::new("bad_envelope", false, None));
        return;
    }
    let (Some(sealer), Some(keys), Some(device)) = (node.sealer.as_ref(), node.secrets.device.as_ref(), node.device_id()) else { return };
    // 2. Unwrap, decrypt, verify body hash + task signature.
    let (opened, mut ctx) = match sealer.open(assign, &frames, device, keys) {
        Ok(x) => x,
        Err(code) => {
            log("warn", "task refused", &json!({"task": task, "code": code}));
            nack(node, task, attempt, &Failure::new(&code, false, None));
            return;
        }
    };
    drop(frames);
    if !node.executor.claim_task(&opened.gateway_device, task) {
        nack(node, task, attempt, &Failure::new("unauthorized_task", false, None));
        return;
    }
    let dialect = opened.route.get("dialect").and_then(Value::as_str).and_then(Dialect::from_wire);
    let Some(dialect) = dialect else {
        nack(node, task, attempt, &Failure::new("route_mismatch", false, None));
        return;
    };
    let req = ExecRequest {
        task_id: task.to_owned(),
        dialect,
        route: opened.route,
        body: opened.body,
        headers: opened.headers,
        pledge: assign.get("pledge").and_then(Value::as_str).map(str::to_owned),
    };
    // 3. Firewall + reservation + provider call.
    let mut ex = node.executor.execute(req);
    let mut held: Option<Bytes> = None;
    let mut started = false;
    let outcome = loop {
        let ev = tokio::select! {
            ev = ex.recv() => ev,
            m = rx.recv() => match m {
                Some(TaskIn::Text(v)) if v.get("t").and_then(Value::as_str) == Some("task.cancel") => break cancelled(started),
                Some(_) => continue,
                None => break cancelled(started),
            },
        };
        match ev {
            Some(ExecEvent::Ready) => {
                let m = json!({"t":"task.ack","task":task,"attempt":attempt,"R":b64e(&ctx.r())});
                if !node.send(text_msg(&m)).await {
                    break cancelled(started);
                }
            }
            Some(ExecEvent::Started) => {
                started = true;
                let _ = node.send(text_msg(&json!({"t":"task.started","task":task,"attempt":attempt}))).await;
            }
            Some(ExecEvent::Bytes(b)) => {
                if let Some(prev) = held.replace(b) {
                    if !send_chunk(node, ctx.as_mut(), &prev, false).await {
                        break cancelled(started);
                    }
                }
            }
            Some(ExecEvent::Checkpoint) => {
                if let Some(prev) = held.take() {
                    if !send_chunk(node, ctx.as_mut(), &prev, false).await {
                        break cancelled(started);
                    }
                }
                send_checkpoint(node, ctx.as_ref(), task, attempt).await;
            }
            Some(ExecEvent::Done(o)) => break o,
            Some(ExecEvent::Failed(f)) if !started => {
                nack(node, task, attempt, &f);
                return;
            }
            Some(ExecEvent::Failed(f)) => break ExecOutcome { status: if f.code == "provider_error" { "provider_error".into() } else { "partial".into() }, ..ExecOutcome::default() },
            None => break ExecOutcome { status: "provider_error".into(), ..ExecOutcome::default() },
        }
    };
    drop(ex);
    // 4. Last chunk + final checkpoint, then the signed receipt (outbox is the Sealer/worker's).
    if started {
        let last = held.take().unwrap_or_default();
        if send_chunk(node, ctx.as_mut(), &last, true).await {
            send_checkpoint(node, ctx.as_ref(), task, attempt).await;
        }
    }
    match ctx.finish(&outcome) {
        Ok(mut end) => {
            if let Some(o) = end.as_object_mut() {
                o.insert("t".into(), "task.end".into());
                o.insert("task".into(), task.into());
                o.insert("attempt".into(), attempt.into());
            }
            let _ = node.send(text_msg(&end)).await;
        }
        Err(e) => log("error", "receipt signing failed", &json!({"task": task, "error": e})),
    }
}

fn cancelled(started: bool) -> ExecOutcome {
    ExecOutcome { status: if started { "cancelled" } else { "not_started" }.into(), ..ExecOutcome::default() }
}

/// Max plaintext per frame: 65,536 − 23 − 16 (03 §4.2).
const MAX_PLAIN: usize = 65_497;

async fn send_chunk(node: &Node, ctx: &mut dyn WorkerCtx, b: &[u8], last: bool) -> bool {
    let n = b.len().div_ceil(MAX_PLAIN).max(1);
    for (i, part) in b.chunks(MAX_PLAIN).chain(b.is_empty().then_some(&[][..])).enumerate() {
        let is_last = last && i.saturating_add(1) == n;
        let Ok(frame) = ctx.seal_chunk(part, is_last) else { return false };
        if !node.send(Message::Binary(frame)).await {
            return false;
        }
    }
    true
}

async fn send_checkpoint(node: &Node, ctx: &dyn WorkerCtx, task: &str, attempt: u64) {
    let (seq, rh, sig) = ctx.checkpoint();
    let m = json!({"t":"task.checkpoint","task":task,"attempt":attempt,"seq":seq,"running_hash":b64e(&rh),"sig":b64e(&sig)});
    let _ = node.send(text_msg(&m)).await;
}
