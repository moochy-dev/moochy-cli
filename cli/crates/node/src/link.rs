//! Relay link: TLS 1.3 + WebSocket (`moochy.v1`), channel-bound auth, reconnect with full
//! jitter, keepalive, and the frame mux that routes task traffic to bounded per-task queues.

use crate::node::{LinkState, Node, Side, TaskIn, lock};
use crate::tls::{self, Origin};
use crate::util::{Result, auth, b64d, b64e, log, lp, net, now_ms, rand_u64, ulid_bytes};
use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval, sleep, timeout};
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

pub const SUBPROTOCOL: &str = "moochy.v1";
pub const FRAME_HEADER: usize = 23;
pub const MAX_FRAME: usize = 64 * 1024;
const PING_EVERY: Duration = Duration::from_secs(15);
const DEAD_AFTER: Duration = Duration::from_secs(31);
const BACKOFF_BASE_MS: u64 = 250;
const BACKOFF_CAP_MS: u64 = 30_000;
const OUT_QUEUE: usize = 256;

enum End {
    /// Clean close or drain: reconnect after the given delay.
    Reconnect(u64),
    Net(String),
    Refused(String),
}

/// Full-jitter exponential backoff (03 §14): uniform in `[0, min(cap, base·2^n)]`.
pub fn backoff_ms(attempt: u32) -> u64 {
    let ceil = BACKOFF_BASE_MS.checked_shl(attempt.min(20)).unwrap_or(BACKOFF_CAP_MS).min(BACKOFF_CAP_MS);
    rand_u64() % ceil.saturating_add(1)
}

/// Run forever: connect, authenticate, serve, reconnect.
pub async fn run(node: Arc<Node>) {
    let Some(relay) = node.cfg.relay.clone() else { return };
    let mut attempt: u32 = 0;
    let mut shutdown = node.shutdown.subscribe();
    loop {
        let end = tokio::select! {
            e = session(&node, &relay) => e,
            _ = shutdown.changed() => return,
        };
        *lock(&node.link_out) = None;
        // Dropping every registered sender fails in-flight tasks (no stream resume in v1).
        lock(&node.tasks).clear();
        let delay = match end {
            End::Reconnect(ms) => {
                attempt = 0;
                node.link_state.send_replace(LinkState::Down);
                ms
            }
            End::Net(e) => {
                log("warn", "relay link down", &json!({"error": e}));
                node.link_state.send_replace(LinkState::Down);
                backoff_ms(attempt)
            }
            End::Refused(e) => {
                log("error", "relay refused authentication", &json!({"error": e}));
                node.link_state.send_replace(LinkState::Refused(e));
                BACKOFF_CAP_MS
            }
        };
        attempt = attempt.saturating_add(1);
        tokio::select! {
            () = sleep(Duration::from_millis(delay)) => {}
            _ = shutdown.changed() => return,
        }
    }
}

fn text(v: &Value) -> Message {
    Message::Text(Utf8Bytes::from(v.to_string()))
}

async fn session(node: &Arc<Node>, relay: &str) -> End {
    match session_inner(node, relay).await {
        Ok(e) | Err(e) => e,
    }
}

async fn session_inner(node: &Arc<Node>, relay: &str) -> std::result::Result<End, End> {
    let origin = Origin::parse(relay).map_err(|e| End::Refused(e.msg))?;
    let (Some(device_id), Some(keys)) = (node.device_id(), node.secrets.device.as_ref()) else {
        return Err(End::Refused("not logged in".into()));
    };
    let cfg = tls::client_config(node.cfg.ca_file.as_deref()).map_err(|e| End::Refused(e.msg))?;
    let stream = tls::connect(&cfg, &origin).await.map_err(|e| End::Net(e.msg))?;
    let exporter = tls::exporter(&stream).map_err(|e| End::Net(e.msg))?;

    let mut req = format!("{}/v1/node", origin.wss()).into_client_request().map_err(|e| End::Refused(e.to_string()))?;
    req.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static(SUBPROTOCOL));
    req.headers_mut().insert("x-moochy-client", HeaderValue::from_static(env!("CARGO_PKG_VERSION")));
    let wscfg = WebSocketConfig::default().max_message_size(Some(1 << 20)).max_frame_size(Some(1 << 20));
    let (ws, resp) = timeout(tls::IO_TIMEOUT, tokio_tungstenite::client_async_with_config(req, stream, Some(wscfg)))
        .await
        .map_err(|_| End::Net("websocket handshake timeout".into()))?
        .map_err(|e| End::Net(format!("websocket: {e}")))?;
    if resp.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()) != Some(SUBPROTOCOL) {
        return Err(End::Refused("relay did not select subprotocol moochy.v1".into()));
    }
    let (mut sink, mut stream) = ws.split();

    // hello → auth → welcome
    let hello = next_json(&mut stream).await?;
    if hello.get("t").and_then(Value::as_str) != Some("hello") {
        return Err(End::Refused(format!("expected hello, got {}", hello.get("t").unwrap_or(&Value::Null))));
    }
    let nonce = hello.get("nonce").and_then(Value::as_str).and_then(b64d).filter(|n| n.len() == 32);
    let nonce = nonce.ok_or_else(|| End::Refused("hello without a 32-byte nonce".into()))?;
    if let Some(st) = hello.get("server_time").and_then(Value::as_u64) {
        if st.abs_diff(now_ms()) > 300_000 {
            log("warn", "clock skew larger than 5 minutes vs relay", &json!({}));
        }
    }
    let origin_s = origin.wss();
    let sig = keys.sign(&lp(&[b"moochy/v1/auth", &nonce, origin_s.as_bytes(), &exporter, device_id.as_bytes()]));
    let roles = &node.cfg.roles;
    sink.send(text(&json!({"t":"auth","device_id":device_id,"roles":roles,"sig":b64e(&sig)})))
        .await
        .map_err(|e| End::Net(e.to_string()))?;
    let welcome = next_json(&mut stream).await?;
    match welcome.get("t").and_then(Value::as_str) {
        Some("welcome") => {}
        Some("error") => {
            let code = welcome.get("code").and_then(Value::as_str).unwrap_or("auth_failed");
            return Err(End::Refused(code.to_owned()));
        }
        other => return Err(End::Refused(format!("expected welcome, got {other:?}"))),
    }

    let (tx, mut rx) = mpsc::channel::<Message>(OUT_QUEUE);
    *lock(&node.link_out) = Some(tx);
    node.link_state.send_replace(LinkState::Up);
    log("info", "relay link up", &json!({"session": welcome.get("session_id")}));
    if node.cfg.has_role("worker") {
        crate::worker::on_welcome(node);
    }

    let mut ping = interval(PING_EVERY);
    ping.tick().await;
    let mut last_pong = Instant::now();
    loop {
        tokio::select! {
            m = stream.next() => match m {
                Some(Ok(Message::Text(t))) => {
                    if let Some(delay) = on_text(node, t.as_bytes()) {
                        let _ = sink.close().await;
                        return Ok(End::Reconnect(delay));
                    }
                }
                Some(Ok(Message::Binary(b))) => on_binary(node, b),
                Some(Ok(Message::Pong(_))) => last_pong = Instant::now(),
                Some(Ok(Message::Close(_))) | None => return Ok(End::Reconnect(0)),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(End::Net(e.to_string())),
            },
            m = rx.recv() => {
                let Some(m) = m else { return Err(End::Net("outbound queue closed".into())) };
                sink.send(m).await.map_err(|e| End::Net(e.to_string()))?;
            }
            _ = ping.tick() => {
                if last_pong.elapsed() > DEAD_AFTER {
                    return Err(End::Net("relay missed 2 pongs".into()));
                }
                sink.send(Message::Ping(Bytes::new())).await.map_err(|e| End::Net(e.to_string()))?;
            }
        }
    }
}

async fn next_json<S>(stream: &mut S) -> std::result::Result<Value, End>
where
    S: futures_util::Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match timeout(tls::IO_TIMEOUT, stream.next()).await {
            Err(_) => return Err(End::Net("relay handshake timeout".into())),
            Ok(Some(Ok(Message::Text(t)))) => return crate::json::parse(t.as_bytes()).map_err(|e| End::Refused(format!("bad JSON from relay: {e}"))),
            Ok(Some(Ok(Message::Close(c)))) => {
                return Err(End::Refused(c.map_or_else(|| "closed during handshake".into(), |c| c.reason.to_string())));
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(e))) => return Err(End::Net(e.to_string())),
            Ok(None) => return Err(End::Net("closed during handshake".into())),
        }
    }
}

/// Which side of a task a message type belongs to.
fn side_of(t: &str) -> Option<Side> {
    match t {
        "task.accepted" | "task.started" | "task.checkpoint" | "task.end" | "task.failed" | "task.need_wraps" => Some(Side::Gateway),
        "task.assign" | "task.cancel" | "receipt.ack" => Some(Side::Worker),
        _ => None,
    }
}

/// Handle one text frame; `Some(delay)` asks the caller to reconnect (drain).
fn on_text(node: &Arc<Node>, raw: &[u8]) -> Option<u64> {
    let Ok(v) = crate::json::parse(raw) else {
        log("warn", "relay sent invalid JSON", &json!({}));
        return None;
    };
    let t = v.get("t").and_then(Value::as_str).unwrap_or("");
    if let Some(side) = side_of(t) {
        let Some(id) = v.get("task").and_then(Value::as_str).and_then(ulid_bytes) else { return None };
        if t == "task.assign" {
            crate::worker::on_assign(node, id, v);
            return None;
        }
        deliver(node, (id, side), TaskIn::Text(v));
        return None;
    }
    match t {
        "pool.sync" => node.apply_pool_sync(&v),
        "relay.draining" => {
            let ms = v.get("reconnect_after_ms").and_then(Value::as_u64).unwrap_or(0).min(BACKOFF_CAP_MS);
            return Some(ms);
        }
        "error" => log("warn", "relay error", &json!({"code": v.get("code"), "task": v.get("task")})),
        "receipt.replay_since" | "log.checkpoint" | "catalog.update" | "welcome" => {}
        _ => {
            node.try_send(text(&json!({"t":"error","code":"unknown_type","message":t})));
        }
    }
    None
}

fn on_binary(node: &Arc<Node>, b: Bytes) {
    if b.len() < FRAME_HEADER || b.len() > MAX_FRAME {
        return;
    }
    let (Some(kind), Some(id)) = (b.first(), b.get(1..17).and_then(|s| <[u8; 16]>::try_from(s).ok())) else { return };
    let side = match kind {
        0x01 => Side::Worker,
        0x02 => Side::Gateway,
        _ => return,
    };
    deliver(node, (id, side), TaskIn::Frame(b));
}

/// Route to a task's bounded queue. A task that cannot keep up is dropped (its driver sees the
/// channel close and fails the task) rather than buffering without bound.
fn deliver(node: &Node, key: crate::node::TaskKey, m: TaskIn) {
    let mut tasks = lock(&node.tasks);
    let Some(tx) = tasks.get(&key) else { return };
    if tx.try_send(m).is_err() {
        tasks.remove(&key);
    }
}

pub fn text_msg(v: &Value) -> Message {
    text(v)
}

/// Wait for the first link outcome (up / refused), at most `wait`.
pub async fn wait_first(node: &Node, wait: Duration) -> Result<()> {
    let mut rx = node.link_state.subscribe();
    let r = timeout(wait, rx.wait_for(|s| *s != LinkState::Down)).await;
    match r {
        Ok(Ok(s)) => match &*s {
            LinkState::Refused(e) => Err(auth(format!("relay refused this device: {e}"))),
            _ => Ok(()),
        },
        _ => Err(net("relay not reachable yet")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn backoff_bounds() {
        for a in 0..40 {
            let v = super::backoff_ms(a);
            assert!(v <= super::BACKOFF_CAP_MS);
            if a == 0 {
                assert!(v <= super::BACKOFF_BASE_MS);
            }
        }
    }
}
