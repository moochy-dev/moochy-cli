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
pub const MAX_MCP_BODY: usize = 8 << 20;
const MAX_RESPONSE: usize = 16 << 20;
const MAX_CONNS: usize = 512;
const BODY_TIMEOUT: Duration = Duration::from_secs(60);
static MAX_NOTICE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Default `max_tokens` injected for requests that omit it (tools often do), capped by the
/// catalog's `max_output`.
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
    if let Err(e) = crate::run::init_key(&node.home.state_dir()) {
        crate::util::log("error", "no run key: `moochy run` cannot get a sandboxed session", &json!({"error": e.msg}));
    }
    let port = listener.local_addr().map_or(0, |a| a.port());
    let allowed: Arc<[String; 3]> = Arc::new([format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")]);
    let conns = Arc::new(Semaphore::new(MAX_CONNS));
    // Same door on a 0600 Unix socket: `moochy run` bridges it into the sandbox's empty netns,
    // where the agent reaches it as 127.0.0.1:<port> (same Host allowlist).
    let unix = gateway_socket(&node);
    let mut shutdown = node.shutdown.subscribe();
    loop {
        tokio::select! {
            r = listener.accept() => {
                let Ok((stream, peer)) = r else { continue };
                if !peer.ip().is_loopback() {
                    continue;
                }
                let _ = stream.set_nodelay(true);
                conn(&node, &allowed, &conns, stream, None);
            }
            r = async { unix.as_ref()?.accept().await.ok() }, if unix.is_some() => {
                if let Some((stream, _)) = r {
                    let peer = stream.peer_cred().ok().map(|c| crate::run::Peer { uid: c.uid(), pid: c.pid() });
                    conn(&node, &allowed, &conns, stream, peer);
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

/// `<state>/gateway.sock`, mode 0600 (the state dir is 0700 as well).
pub fn gateway_socket_path(node: &Node) -> std::path::PathBuf {
    node.home.state_dir().join("gateway.sock")
}

fn gateway_socket(node: &Node) -> Option<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    let p = gateway_socket_path(node);
    let _ = std::fs::remove_file(&p);
    let l = tokio::net::UnixListener::bind(&p).ok()?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).ok()?;
    Some(l)
}

/// `peer`: the Unix-socket peer's credentials (A201); `None` over TCP.
fn conn<S>(node: &Arc<Node>, allowed: &Arc<[String; 3]>, conns: &Arc<Semaphore>, stream: S, peer: Option<crate::run::Peer>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(permit) = conns.clone().try_acquire_owned() else { return };
    let node = node.clone();
    let allowed = allowed.clone();
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |req| {
            let node = node.clone();
            let allowed = allowed.clone();
            async move { Ok::<_, Infallible>(handle(node, &allowed, req, peer).await) }
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

fn token(h: &HeaderMap) -> Option<&str> {
    if let Some(v) = h.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.trim());
    }
    let a = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = a.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
}

async fn handle(node: Arc<Node>, allowed: &[String; 3], req: Request<Incoming>, peer: Option<crate::run::Peer>) -> Resp {
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
    // 3. Bounded bodies (A35): refuse a declared length over the cap at the headers, before any
    //    read; chunked bodies are capped by `read_body` at the same limit.
    let cap = if path == "/mcp" { MAX_MCP_BODY } else { MAX_API_BODY };
    let declared = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > cap as u64) {
        let mut r = native_error(dialect, &Failure::new("too_large", false, format!("moochy: request body larger than {cap} bytes")));
        r.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
        return r;
    }
    // Local-only endpoints for the CLI, authenticated by the 0600 run key (no repo needed).
    if let Some(r) = path.strip_prefix("/moochy/verify/") {
        let key = req.headers().get(crate::run::RUN_KEY_HEADER).and_then(|v| v.to_str().ok());
        if !crate::run::key_ok(key) {
            return json_resp(403, &json!({"error": "run_key_required"}));
        }
        return match crate::task::verify(&node, r).await {
            Ok(v) => json_resp(200, &v),
            Err(e) => json_resp(422, &json!({"verified": false, "error": e})),
        };
    }
    // 4. A live sandboxed run token (§15.4), else a repo-scoped local token.
    let caller = token(req.headers()).and_then(|t| crate::run::check(t).map(|s| (s, true)).or_else(|| node.check_token(t).map(|s| (s, false))));
    let Some((slug, sandboxed)) = caller else {
        if path == "/mcp" {
            let mut r = json_resp(401, &json!({"error": "unauthorized"}));
            r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return r;
        }
        return native_error(dialect, &Failure::new("unauthorized", false, "moochy: invalid local token (see `moochy env`)".to_owned()));
    };
    // Tool calls are released only to sandboxed sessions or projects that opted in (§15.4).
    // The project's own setting (PoolSync), or the local override in development only.
    let repo_allows = crate::node::lock(&node.pools).values().any(|p| p.allow_unsandboxed_tools && p.slug.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(&slug)));
    let release = sandboxed || repo_allows || (node.insecure_dev && node.cfg.unsandboxed_tools_allowed(&slug));
    match (req.method(), path.as_str()) {
        (&Method::POST, "/moochy/run") if !sandboxed => {
            let key = req.headers().get(crate::run::RUN_KEY_HEADER).and_then(|v| v.to_str().ok());
            crate::run::open(slug, key, peer, &node.home.state_dir())
        }
        (_, "/mcp") => crate::mcp::http(node, slug, req).await,
        (&Method::GET, "/v1/models") => {
            node.settle_pool(&slug, |p| !p.models().is_empty()).await;
            models(&node, &slug)
        }
        (&Method::POST, "/v1/messages") => api(node, slug, Dialect::Anthropic, req, false, release).await,
        (&Method::POST, "/v1/messages/count_tokens") => api(node, slug, Dialect::Anthropic, req, true, release).await,
        (&Method::POST, "/v1/chat/completions") => api(node, slug, Dialect::OpenAi, req, false, release).await,
        _ => native_error(dialect, &Failure::new("not_found", false, format!("moochy: no route for {path}"))),
    }
}

/// One shape that satisfies both the Anthropic and the OpenAI model-list parsers.
fn models(node: &Node, slug: &str) -> Resp {
    // Pool slugs, then the native aliases the catalog maps to them (05 §2.1).
    let mut ids: Vec<String> = node.pool_for(slug).map(|p| p.models()).unwrap_or_default().into_iter().map(|(m, _)| m).collect();
    let cat = node.catalog();
    let aliases: Vec<String> = ids
        .iter()
        .flat_map(|m| cat.entries.iter().filter(move |e| &e.model == m))
        .flat_map(|e| std::iter::once(e.provider_model_id.clone()).chain(e.aliases.iter().cloned()))
        .collect();
    for a in aliases {
        if !ids.contains(&a) {
            ids.push(a);
        }
    }
    let data: Vec<Value> = ids
        .iter()
        .map(|id| json!({"id": id, "object": "model", "type": "model", "created": 0, "created_at": "1970-01-01T00:00:00Z", "owned_by": "moochy", "display_name": id}))
        .collect();
    let first = ids.first().map(String::as_str);
    let last = ids.last().map(String::as_str);
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
pub fn prepare(node: &Node, slug: String, dialect: Dialect, raw: Bytes, headers: &[(String, String)], t_client_rx: u64) -> Result<TaskReq, Failure> {
    use moochy_worker::json::{self as wj, Kind, Val};
    let bad = |m: String| Failure::new("invalid_request", false, m);
    let body = crate::scrub::scrub(&raw).map_or(raw, Bytes::from);
    // Drop what a pooled donor refuses but the client can do without (Claude Code `safeguards`,
    // unknown betas, extra headers) before anything else; the client is told (x-moochy-note).
    let hdr: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    // The body is re-serialized only when it can hold a stripped member (CONTRACT §13: no extra
    // pass over a large body otherwise); headers are always filtered.
    let strip_body = body.windows(12).any(|w| w == b"\"safeguards\"");
    let pool = moochy_worker::firewall::pool_compatible(dialect.worker(), if strip_body { &body } else { b"{}" }, &hdr)
        .map_err(|r| Failure::new("firewall", false, format!("moochy: {r} (refused before leaving this machine)")))?;
    drop(hdr);
    if !pool.stripped.is_empty() {
        crate::util::log("info", "removed what donors refuse", &json!({"stripped": pool.stripped}));
    }
    let (mut body, headers, stripped) = (if strip_body { Bytes::from(pool.body) } else { body }, pool.headers, pool.stripped);
    // Strict tape parse (no tree allocation): this is the per-request hot path (CONTRACT §13).
    let mut tape = Vec::new();
    let (inject_max, auto_cache) = {
        let doc = wj::parse(&body, &mut tape).map_err(|e| bad(format!("moochy: invalid JSON body: {e}")))?;
        let root = doc.root();
        if root.kind() != Kind::Obj {
            return Err(bad("moochy: the body must be a JSON object".into()));
        }
        let model = root.get("model").and_then(Val::as_str).ok_or_else(|| bad("moochy: `model` is required".into()))?;
        let max_out = catalog_entry(node, &model)?.max_output;
        let missing = root.get("max_tokens").is_none() && root.get("max_completion_tokens").is_none();
        // 07 §4.2 step 4: multi-turn Anthropic conversation with no cache_control anywhere →
        // top-level automatic caching (5 m): cache reads cost donors a fraction of input.
        let turns = root.get("messages").map_or(0, |m| m.items().count());
        // Both the repo setting and the local config must allow it.
        let cache = dialect == Dialect::Anthropic && turns >= 2 && node.cfg.auto_cache() && !body.windows(15).any(|w| w == b"\"cache_control\"") && node.repo_auto_cache(&slug);
        (missing.then(|| u64::from(max_out).min(DEFAULT_MAX_TOKENS)), cache)
    };
    if inject_max.is_some() || auto_cache {
        let mut m = crate::json::parse_object(&body).map_err(|e| bad(format!("moochy: invalid JSON body: {e}")))?;
        if let Some(n) = inject_max {
            if !MAX_NOTICE.swap(true, std::sync::atomic::Ordering::Relaxed) {
                crate::util::log("warn", "request without max_tokens: injected the catalog default (told once)", &json!({"max_tokens": n}));
            }
            m.insert("max_tokens".into(), n.into());
        }
        if auto_cache {
            m.insert("cache_control".into(), json!({"type": "ephemeral"}));
        }
        body = Bytes::from(Value::Object(m).to_string());
    }
    let doc = wj::parse(&body, &mut tape).map_err(|e| bad(format!("moochy: invalid JSON body: {e}")))?;
    let root = doc.root();
    let model = root.get("model").and_then(Val::as_str).ok_or_else(|| bad("moochy: `model` is required".into()))?;
    let entry = catalog_entry(node, &model)?;
    // Affinity key over system, tools and the first user message (04 §5), each re-serialized
    // canonically (`Val::raw` is empty for objects and arrays, which made every key equal).
    let first = |role: &str| root.get("messages").and_then(|m| m.items().find(|x| x.get("role").is_some_and(|r| r.is_str(role))));
    let system = match dialect {
        Dialect::Anthropic => root.get("system"),
        Dialect::OpenAi => first("system").or_else(|| first("developer")),
    };
    let affinity = affinity_key(&node.secrets, system, root.get("tools"), first("user"));
    drop(model);
    let facts = crate::engine::analyze(&entry, dialect, &body, &headers)?;
    Ok(TaskReq { slug, dialect, body, affinity, facts, entry, headers, t_client_rx, release_tools: false, stripped })
}

fn affinity_key(secrets: &crate::keystore::Secrets, system: Option<moochy_worker::json::Val<'_>>, tools: Option<moochy_worker::json::Val<'_>>, user: Option<moochy_worker::json::Val<'_>>) -> [u8; 16] {
    let mut buf = Vec::new();
    let mut ends = [0usize; 3];
    for (end, v) in ends.iter_mut().zip([system, tools, user]) {
        if let Some(v) = v {
            moochy_worker::json::write(v, &mut buf);
        }
        *end = buf.len();
    }
    let [a, b, c] = ends;
    secrets.affinity(buf.get(..a).unwrap_or_default(), buf.get(a..b).unwrap_or_default(), buf.get(b..c).unwrap_or_default())
}

fn catalog_entry(node: &Node, model: &str) -> Result<moochy_proto::money::CatalogEntry, Failure> {
    let cat = node.catalog();
    cat.resolve(model).cloned().ok_or_else(|| {
        let why = if cat.version == 0 { "moochy: prices not loaded yet; retry in a moment".to_owned() } else { format!("moochy: model `{}` is not in the catalog", crate::util::clean(model)) };
        Failure::new("model_not_in_pool", false, why)
    })
}

#[allow(clippy::too_many_lines, reason = "one request: read, prepare, submit, stream or buffer, headers")]
async fn api(node: Arc<Node>, slug: String, dialect: Dialect, req: Request<Incoming>, count_only: bool, release: bool) -> Resp {
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
        let model = v.get("model").and_then(Value::as_str).unwrap_or_default();
        return match catalog_entry(&node, model).and_then(|e| crate::engine::analyze(&e, dialect, body.as_bytes(), &headers)) {
            Ok(f) => json_resp(200, &json!({"input_tokens": f.est_input_tokens})),
            Err(f) => native_error(dialect, &f),
        };
    }
    let treq = match prepare(&node, slug, dialect, raw, &headers, t_rx) {
        Ok(t) => TaskReq { release_tools: release, ..t },
        Err(f) => return native_error(dialect, &f),
    };
    let stream = treq.facts.stream;
    let note = (!treq.stripped.is_empty()).then(|| format!("[moochy] removed before sending to donors: {}", treq.stripped.join(", ")));
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
    if let Some(v) = note.and_then(|n| HeaderValue::from_str(&crate::util::clean(&n)).ok()) {
        h.insert("x-moochy-note", v);
    }
    resp
}

#[cfg(test)]
mod affinity_tests {
    use super::*;

    fn key(body: &str) -> [u8; 16] {
        let mut tape = Vec::new();
        let doc = moochy_worker::json::parse(body.as_bytes(), &mut tape).unwrap();
        let root = doc.root();
        let user = root.get("messages").and_then(|m| m.items().next());
        affinity_key(&crate::keystore::Secrets::default(), root.get("system"), root.get("tools"), user)
    }

    #[test]
    fn affinity_depends_on_object_and_array_content() {
        let a = key(r#"{"messages":[{"role":"user","content":"probe 1"}]}"#);
        let b = key(r#"{"messages":[{"role":"user","content":"probe 2"}]}"#);
        assert_ne!(a, b, "first user message must change the key");
        assert_eq!(a, key(r#"{"messages":[{"role":"user", "content":"probe 1"}]}"#), "formatting must not");
        let t1 = key(r#"{"tools":[{"name":"x"}],"messages":[{"role":"user","content":"p"}]}"#);
        let t2 = key(r#"{"tools":[{"name":"y"}],"messages":[{"role":"user","content":"p"}]}"#);
        assert_ne!(t1, t2, "tools must change the key");
    }
}
