//! Loopback HTTP server: the API door (`/v1/messages`, `/v1/chat/completions`, `/v1/models`,
//! `/v1/messages/count_tokens`) and the MCP Streamable HTTP door (`/mcp`).
//!
//! Hardening (06 §13, E14): loopback bind only, Host allowlist (DNS rebinding), cross-origin
//! `Origin` refused, never any CORS header, repo-scoped tokens compared in constant time, bounded
//! bodies, header timeouts, connection cap.

use crate::engine::{Dialect, Failure};
use crate::node::Node;
use crate::task::{TaskEv, TaskReq, submit};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Limited};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};

pub const MAX_API_BODY: usize = 32 << 20;
pub const MAX_MCP_BODY: usize = 4 << 20;
const MAX_RESPONSE: usize = 16 << 20;
const MAX_CONNS: usize = 512;
const BODY_TIMEOUT: Duration = Duration::from_secs(60);
/// Default `max_tokens` injected for OpenAI-dialect requests that omit it (tools often do).
const DEFAULT_MAX_TOKENS: u64 = 4096;

/// Response body: a full buffer or a channel of chunks flushed one by one.
pub enum Body {
    Full(Option<Bytes>),
    Chan(mpsc::Receiver<Bytes>),
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Body::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Body::Chan(rx) => rx.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b)))),
        }
    }
    fn is_end_stream(&self) -> bool {
        matches!(self, Body::Full(None))
    }
}

pub type Resp = Response<Body>;

pub fn json_resp(status: u16, v: &Value) -> Resp {
    let mut r = Response::new(Body::Full(Some(Bytes::from(v.to_string()))));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

pub fn native_error(d: Dialect, f: &Failure) -> Resp {
    let (status, body) = crate::native::error_body(d, f);
    let mut r = json_resp(status, &body);
    if let Some(ms) = f.retry_after_ms {
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(ms.div_ceil(1000).max(1)));
    }
    r
}

/// Accept loop. The listener is bound to loopback by the caller.
pub async fn serve(node: Arc<Node>, listener: TcpListener) {
    let port = listener.local_addr().map_or(0, |a| a.port());
    let allowed: Arc<[String; 3]> = Arc::new([format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")]);
    let conns = Arc::new(Semaphore::new(MAX_CONNS));
    let mut shutdown = node.shutdown.subscribe();
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
            _ = shutdown.changed() => return,
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = conns.clone().try_acquire_owned() else { continue };
        let _ = stream.set_nodelay(true);
        let node = node.clone();
        let allowed = allowed.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let node = node.clone();
                let allowed = allowed.clone();
                async move { Ok::<_, Infallible>(handle(node, &allowed, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .max_buf_size(64 * 1024)
                .serve_connection(TokioIo::new(stream), svc)
                .await;
            drop(permit);
        });
    }
}

fn token(h: &HeaderMap) -> Option<&str> {
    if let Some(v) = h.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.trim());
    }
    let a = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = a.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
}

async fn handle(node: Arc<Node>, allowed: &[String; 3], req: Request<Incoming>) -> Resp {
    let path = req.uri().path().to_owned();
    let dialect = if path.ends_with("/chat/completions") || (path.ends_with("/models") && req.headers().get("anthropic-version").is_none()) {
        Dialect::OpenAi
    } else {
        Dialect::Anthropic
    };
    // 1. DNS rebinding: Host must be our exact loopback authority.
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok());
    if !host.is_some_and(|h| allowed.iter().any(|a| a == h)) {
        return native_error(dialect, &Failure::new("forbidden", false, "moochy: Host header not allowed".to_owned()));
    }
    // 2. Browsers: refuse any cross-origin request (no CORS, ever).
    if let Some(o) = req.headers().get(header::ORIGIN) {
        let ok = o.to_str().ok().and_then(|o| o.strip_prefix("http://")).is_some_and(|o| allowed.iter().any(|a| a == o));
        if !ok {
            return native_error(dialect, &Failure::new("forbidden", false, "moochy: cross-origin requests are not allowed".to_owned()));
        }
    }
    // 3. Repo-scoped local token.
    let Some(slug) = token(req.headers()).and_then(|t| node.check_token(t)) else {
        if path == "/mcp" {
            let mut r = json_resp(401, &json!({"error": "unauthorized"}));
            r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return r;
        }
        return native_error(dialect, &Failure::new("unauthorized", false, "moochy: invalid local token (see `moochy env`)".to_owned()));
    };
    match (req.method(), path.as_str()) {
        (_, "/mcp") => crate::mcp::http(node, slug, req).await,
        (&Method::GET, "/v1/models") => models(&node, &slug),
        (&Method::POST, "/v1/messages") => api(node, slug, Dialect::Anthropic, req, false).await,
        (&Method::POST, "/v1/messages/count_tokens") => api(node, slug, Dialect::Anthropic, req, true).await,
        (&Method::POST, "/v1/chat/completions") => api(node, slug, Dialect::OpenAi, req, false).await,
        _ => native_error(dialect, &Failure::new("not_found", false, format!("moochy: no route for {path}"))),
    }
}

/// One shape that satisfies both the Anthropic and the OpenAI model-list parsers.
fn models(node: &Node, slug: &str) -> Resp {
    let ms = node.pool_for(slug).map(|p| p.models()).unwrap_or_default();
    let data: Vec<Value> = ms
        .iter()
        .map(|(id, _)| json!({"id": id, "object": "model", "type": "model", "created": 0, "created_at": "1970-01-01T00:00:00Z", "owned_by": "moochy", "display_name": id}))
        .collect();
    let first = ms.first().map(|(m, _)| m.as_str());
    let last = ms.last().map(|(m, _)| m.as_str());
    json_resp(200, &json!({"object": "list", "data": data, "has_more": false, "first_id": first, "last_id": last}))
}

pub async fn read_body(b: Incoming, limit: usize) -> Result<Bytes, Failure> {
    match tokio::time::timeout(BODY_TIMEOUT, Limited::new(b, limit).collect()).await {
        Ok(Ok(c)) => Ok(c.to_bytes()),
        Ok(Err(_)) => Err(Failure::new("too_large", false, format!("moochy: request body larger than {limit} bytes"))),
        Err(_) => Err(Failure::new("invalid_request", false, "moochy: request body timeout".to_owned())),
    }
}

/// Validate + scrub a provider-dialect body into a task request.
pub fn prepare(node: &Node, slug: String, dialect: Dialect, raw: Bytes, headers: Vec<(String, String)>, t_client_rx: u64) -> Result<TaskReq, Failure> {
    let bad = |m: String| Failure::new("invalid_request", false, m);
    let mut body = crate::scrub::scrub(&raw).map_or(raw, Bytes::from);
    let mut parsed = crate::json::parse_object(&body).map_err(|e| bad(format!("moochy: invalid JSON body: {e}")))?;
    if dialect == Dialect::OpenAi && !parsed.contains_key("max_tokens") && !parsed.contains_key("max_completion_tokens") {
        parsed.insert("max_tokens".into(), DEFAULT_MAX_TOKENS.into());
        body = Bytes::from(Value::Object(parsed.clone()).to_string());
    }
    let entry = catalog_entry(node, &parsed)?;
    let facts = crate::engine::analyze(&entry, dialect, &body, &headers)?;
    Ok(TaskReq { slug, dialect, body, parsed, facts, entry, headers, t_client_rx })
}

fn catalog_entry(node: &Node, parsed: &serde_json::Map<String, Value>) -> Result<moochy_proto::money::CatalogEntry, Failure> {
    let model = parsed.get("model").and_then(Value::as_str).ok_or_else(|| Failure::new("invalid_request", false, "moochy: `model` is required".to_owned()))?;
    let cat = node.catalog();
    cat.resolve(model).cloned().ok_or_else(|| {
        let why = if cat.version == 0 { "moochy: no price catalog from the relay yet".to_owned() } else { format!("moochy: model `{}` is not in the catalog", crate::util::clean(model)) };
        Failure::new("model_not_in_pool", false, why)
    })
}

async fn api(node: Arc<Node>, slug: String, dialect: Dialect, req: Request<Incoming>, count_only: bool) -> Resp {
    let t_rx = crate::task::now_us();
    let headers: Vec<(String, String)> = ["anthropic-version", "anthropic-beta"]
        .iter()
        .filter(|_| dialect == Dialect::Anthropic)
        .filter_map(|k| Some(((*k).to_owned(), req.headers().get(*k)?.to_str().ok()?.to_owned())))
        .collect();
    let raw = match read_body(req.into_body(), MAX_API_BODY).await {
        Ok(b) => b,
        Err(f) => return native_error(dialect, &f),
    };
    if count_only {
        // count_tokens bodies carry no max_tokens: estimate with a placeholder (ADR-23, local).
        let mut v = match crate::json::parse_object(&raw) {
            Ok(v) => v,
            Err(e) => return native_error(dialect, &Failure::new("invalid_request", false, format!("moochy: invalid JSON body: {e}"))),
        };
        v.entry("max_tokens").or_insert(1.into());
        let body = Value::Object(v.clone()).to_string();
        return match catalog_entry(&node, &v).and_then(|e| crate::engine::analyze(&e, dialect, body.as_bytes(), &headers)) {
            Ok(f) => json_resp(200, &json!({"input_tokens": f.est_input_tokens})),
            Err(f) => native_error(dialect, &f),
        };
    }
    let treq = match prepare(&node, slug, dialect, raw, headers, t_rx) {
        Ok(t) => t,
        Err(f) => return native_error(dialect, &f),
    };
    let stream = treq.facts.stream;
    let mut rx = match submit(&node, treq).await {
        Ok(rx) => rx,
        Err(f) => return native_error(dialect, &f),
    };
    // Wait for the provider to answer: before that, failures are plain HTTP errors.
    let (task_id, donor) = match rx.recv().await {
        Some(TaskEv::Started { task_id, donor }) => (task_id, donor),
        Some(TaskEv::Failed(f)) => return native_error(dialect, &f),
        _ => return native_error(dialect, &Failure::new("overloaded", true, "moochy: task ended before start".to_owned())),
    };
    let mut resp = if stream {
        let (tx, brx) = mpsc::channel::<Bytes>(32);
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                match ev {
                    TaskEv::Bytes(b) => {
                        if tx.send(b).await.is_err() {
                            return; // client gone: dropping rx cancels the task
                        }
                    }
                    TaskEv::Failed(f) => {
                        let _ = tx.send(crate::native::sse_error(dialect, &f)).await;
                        return;
                    }
                    TaskEv::End { .. } => return,
                    TaskEv::Started { .. } => {}
                }
            }
        });
        let mut r = Response::new(Body::Chan(brx));
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
        r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        r
    } else {
        let mut buf = Vec::new();
        let cost;
        loop {
            match rx.recv().await {
                Some(TaskEv::Bytes(b)) => {
                    if buf.len().saturating_add(b.len()) > MAX_RESPONSE {
                        return native_error(dialect, &Failure::new("provider_error", true, "moochy: response too large".to_owned()));
                    }
                    buf.extend_from_slice(&b);
                }
                Some(TaskEv::End { cost_uusd, .. }) => {
                    cost = cost_uusd;
                    break;
                }
                Some(TaskEv::Failed(f)) => return native_error(dialect, &f),
                Some(TaskEv::Started { .. }) => {}
                None => return native_error(dialect, &Failure::new("overloaded", true, "moochy: task lost".to_owned())),
            }
        }
        let mut r = Response::new(Body::Full(Some(Bytes::from(buf))));
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(c) = cost {
            r.headers_mut().insert("x-moochy-cost-uusd", HeaderValue::from(c));
        }
        r
    };
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&task_id) {
        h.insert("x-moochy-task", v);
    }
    if let Ok(v) = HeaderValue::from_str(&donor) {
        h.insert("x-moochy-donor", v);
    }
    resp
}
