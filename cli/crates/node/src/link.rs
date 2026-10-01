//! Relay link over gRPC (`moochy.v1.NodeLink`, CONTRACT §12).
//!
//! One TLS connection = one tonic `Channel` = one authenticated session. Our own `tokio-rustls`
//! connector captures the RFC 9266 exporter for the Auth signature and is single-use: if the
//! connection dies, the channel cannot silently redial an unauthenticated connection; the session
//! loop rebuilds and re-authenticates with full-jitter backoff instead.

use crate::node::{LinkHandle, LinkState, Node, lock};
use crate::pb::link::{
    Auth, NodeMsg, Ping, RelayMsg, Role, node_link_client::NodeLinkClient, node_msg, relay_msg,
};
use crate::tls::{self, Origin};
use crate::util::{Result, auth, clean, log, lp, net, now_ms, rand_u64};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval, sleep, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};

/// gRPC message cap (a chunk is ≤ 64 KiB; CONTRACT §12).
pub const MAX_MSG: usize = 128 * 1024;
const PING_EVERY: Duration = Duration::from_secs(15);
const DEAD_AFTER: Duration = Duration::from_secs(31);
const BACKOFF_BASE_MS: u64 = 250;
const BACKOFF_CAP_MS: u64 = 30_000;

enum End {
    /// Clean close or drain: reconnect after the given delay.
    Reconnect(u64),
    Net(String),
    Refused(String),
}

/// Full-jitter exponential backoff (03 §14): uniform in `[0, min(cap, base·2^n)]`.
pub fn backoff_ms(attempt: u32) -> u64 {
    let ceil = BACKOFF_BASE_MS.checked_shl(attempt.min(20)).unwrap_or(BACKOFF_CAP_MS).min(BACKOFF_CAP_MS);
    rand_u64().checked_rem(ceil.saturating_add(1)).unwrap_or(0)
}

/// Dial one TLS 1.3 + h2 connection and wrap it in a single-use tonic channel.
/// Returns the channel and the connection's RFC 9266 exporter.
pub async fn dial(ca_file: Option<&std::path::Path>, origin: &Origin) -> Result<(Channel, [u8; 32])> {
    let cfg = tls::client_config(ca_file)?;
    let stream = tls::connect(&cfg, origin).await?;
    if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(net("relay did not negotiate HTTP/2 (ALPN h2)"));
    }
    let exporter = tls::exporter(&stream)?;
    let slot = Arc::new(Mutex::new(Some(stream)));
    let connector = tower::service_fn(move |_| {
        let s = lock(&slot).take();
        async move { s.map(TokioIo::new).ok_or_else(|| std::io::Error::other("relay connection closed; session must re-authenticate")) }
    });
    let ep = Endpoint::from_shared(origin.url())
        .map_err(|e| net(format!("relay url: {e}")))?
        .initial_stream_window_size(Some(1 << 20))
        .initial_connection_window_size(Some(4 << 20))
        .http2_keep_alive_interval(PING_EVERY)
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .http2_max_header_list_size(16 * 1024)
        .connect_timeout(tls::IO_TIMEOUT);
    let ch = ep.connect_with_connector(connector).await.map_err(|e| net(format!("relay h2: {e}")))?;
    Ok((ch, exporter))
}

pub fn client(ch: Channel) -> NodeLinkClient<Channel> {
    NodeLinkClient::new(ch).max_decoding_message_size(MAX_MSG).max_encoding_message_size(MAX_MSG)
}

pub fn roles(cfg_roles: &[String]) -> Vec<i32> {
    cfg_roles
        .iter()
        .filter_map(|r| match r.as_str() {
            "gateway" => Some(Role::Gateway as i32),
            "worker" => Some(Role::Worker as i32),
            _ => None,
        })
        .collect()
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
        // Dropping the handle drops the channel: every Submit/Serve stream on it fails.
        *lock(&node.link) = None;
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
            () = node.link_kick.notified() => {}
            _ = shutdown.changed() => return,
        }
    }
}

async fn session(node: &Arc<Node>, relay: &str) -> End {
    match session_inner(node, relay).await {
        Ok(e) | Err(e) => e,
    }
}

fn status_end(s: &tonic::Status) -> End {
    let msg = format!("{:?}: {}", s.code(), clean(s.message()));
    match s.code() {
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => End::Refused(msg),
        _ => End::Net(msg),
    }
}

async fn next(down: &mut tonic::Streaming<RelayMsg>) -> std::result::Result<relay_msg::Msg, End> {
    match timeout(tls::IO_TIMEOUT, down.message()).await {
        Err(_) => Err(End::Net("relay handshake timeout".into())),
        Ok(Err(s)) => Err(status_end(&s)),
        Ok(Ok(None)) => Err(End::Net("relay closed the session during handshake".into())),
        Ok(Ok(Some(RelayMsg { msg: None }))) => Err(End::Refused("empty relay message".into())),
        Ok(Ok(Some(RelayMsg { msg: Some(m) }))) => Ok(m),
    }
}

async fn session_inner(node: &Arc<Node>, relay: &str) -> std::result::Result<End, End> {
    let origin = Origin::parse(relay).map_err(|e| End::Refused(e.msg))?;
    let (Some(device_id), Some(keys)) = (node.device_id(), node.secrets.device.as_ref()) else {
        return Err(End::Refused("not logged in".into()));
    };
    let (ch, exporter) = dial(node.cfg.ca_file.as_deref(), &origin).await.map_err(|e| End::Net(e.msg))?;
    let mut client = client(ch);
    let (up, up_rx) = mpsc::channel::<NodeMsg>(64);
    let resp = timeout(tls::IO_TIMEOUT, client.session(ReceiverStream::new(up_rx)))
        .await
        .map_err(|_| End::Net("relay session timeout".into()))?
        .map_err(|s| status_end(&s))?;
    let mut down = resp.into_inner();

    // Hello → Auth → Welcome
    let relay_msg::Msg::Hello(hello) = next(&mut down).await? else {
        return Err(End::Refused("expected Hello".into()));
    };
    if hello.nonce.len() != 32 {
        return Err(End::Refused("Hello without a 32-byte nonce".into()));
    }
    let skew = hello.server_time_ms.saturating_sub(i64::try_from(now_ms()).unwrap_or(i64::MAX));
    node.clock_skew_ms.store(skew, std::sync::atomic::Ordering::Relaxed);
    if u64::try_from(hello.server_time_ms).unwrap_or(0).abs_diff(now_ms()) > 300_000 {
        log("warn", "clock skew larger than 5 minutes vs relay: task ids from other nodes may be refused", &json!({"skew_ms": i128::from(hello.server_time_ms).saturating_sub(i128::from(now_ms()))}));
    }
    let origin_s = origin.url();
    let sig = keys.sign(&lp(&[b"moochy/v1/auth", &hello.nonce, origin_s.as_bytes(), &exporter, device_id.as_bytes()]));
    let auth_msg = Auth { device_id: device_id.to_owned(), roles: roles(&node.cfg.roles), sig: bytes::Bytes::copy_from_slice(&sig), client_version: env!("CARGO_PKG_VERSION").into() };
    up.send(NodeMsg { msg: Some(node_msg::Msg::Auth(auth_msg)) }).await.map_err(|_| End::Net("session closed".into()))?;
    let welcome = match next(&mut down).await? {
        relay_msg::Msg::Welcome(w) => w,
        relay_msg::Msg::Error(e) => return Err(End::Refused(clean(&e.code).into_owned())),
        _ => return Err(End::Refused("expected Welcome".into())),
    };
    if welcome.max_concurrent_tasks > 0 {
        node.max_tasks.store(welcome.max_concurrent_tasks.min(4096), std::sync::atomic::Ordering::Relaxed);
        node.task_freed.notify_waiters();
    }
    let session = welcome.session_id.parse().map_err(|_| End::Refused("bad session id".into()))?;
    *lock(&node.link) = Some(LinkHandle { client, session, up: up.clone() });
    node.link_state.send_replace(LinkState::Up);
    log("info", "relay link up", &json!({"session": welcome.session_id}));
    if node.cfg.has_role("worker") {
        crate::worker::on_welcome(node);
    }
    if let (Some(l), false) = (node.keylog.clone(), hello.log_checkpoint.is_empty()) {
        let c = node.link().map(|h| h.client);
        if let Some(c) = c {
            tokio::spawn(async move { l.sync(c, hello.log_checkpoint.to_vec()).await });
        }
    }

    let mut ping = interval(PING_EVERY);
    ping.tick().await;
    let mut last_pong = Instant::now();
    loop {
        tokio::select! {
            m = down.message() => match m {
                Ok(Some(RelayMsg { msg: Some(m) })) => match m {
                    relay_msg::Msg::PoolSync(p) => node.apply_pool_sync(&p),
                    relay_msg::Msg::Assign(a) => crate::worker::on_assign(node, a.task, a.attempt),
                    relay_msg::Msg::LogCheckpoint(c) => {
                        if let (Some(l), Some(h)) = (node.keylog.clone(), node.link()) {
                            tokio::spawn(async move { l.sync(h.client, c.note.to_vec()).await });
                        }
                    }
                    relay_msg::Msg::Draining(d) => return Ok(End::Reconnect(u64::from(d.reconnect_after_ms).min(BACKOFF_CAP_MS))),
                    relay_msg::Msg::Pong(_) => last_pong = Instant::now(),
                    relay_msg::Msg::Error(e) => log("warn", "relay error", &json!({"code": e.code, "message": e.message, "task": e.task})),
                    relay_msg::Msg::Catalog(c) => match crate::engine::Catalog::parse(&c.catalog_json) {
                        Ok(cat) => {
                            node.set_catalog(cat);
                            crate::worker::reoffer(node);
                        }
                        Err(e) => log("warn", "catalog refused", &json!({"error": e})),
                    },
                    relay_msg::Msg::ReceiptAck(a) => crate::worker::on_receipt_ack(node, &a.task, a.attempt),
                    relay_msg::Msg::ReplaySince(r) => crate::worker::on_replay_since(node, r.since_ms),
                    relay_msg::Msg::ApprovalRequests(r) => crate::approve::on_requests(node, r),
                    relay_msg::Msg::LogEntryAck(a) => crate::approve::on_ack(node, a),
                    // Key-log checkpoints: monitor hook (moochy-keylog), not wired yet.
                    _ => {}
                },
                Ok(Some(RelayMsg { msg: None })) => {}
                Ok(None) => return Ok(End::Reconnect(0)),
                Err(s) => return Err(status_end(&s)),
            },
            _ = ping.tick() => {
                if last_pong.elapsed() > DEAD_AFTER {
                    return Err(End::Net("relay missed 2 pongs".into()));
                }
                let t_ms = i64::try_from(now_ms()).unwrap_or(0);
                if up.try_send(NodeMsg { msg: Some(node_msg::Msg::Ping(Ping { t_ms })) }).is_err() {
                    return Err(End::Net("session send queue full".into()));
                }
            }
        }
    }
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

/// Attach `x-moochy-session` to a per-task stream request.
pub fn with_session<T>(h: &LinkHandle, msg: T) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    r.metadata_mut().insert("x-moochy-session", h.session.clone());
    r
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
