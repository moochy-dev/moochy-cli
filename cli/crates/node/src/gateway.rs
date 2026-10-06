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
    /// A streamed task, read straight from the task's channel (no forwarding task per request,
    /// no second channel hop per chunk). Dropping it (client gone) cancels the task.
    Task { rx: mpsc::Receiver<TaskEv>, dialect: Dialect, done: bool },
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Body::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Body::Chan(rx) => rx.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b)))),
            Body::Task { rx, dialect, done } => loop {
                if *done {
                    return Poll::Ready(None);
                }
                return match std::task::ready!(rx.poll_recv(cx)) {
                    Some(TaskEv::Bytes(b)) => Poll::Ready(Some(Ok(Frame::data(b)))),
                    Some(TaskEv::Failed(f)) => {
                        *done = true;
                        Poll::Ready(Some(Ok(Frame::data(crate::native::sse_error(*dialect, &f)))))
                    }
                    Some(TaskEv::Started { .. }) => continue,
                    Some(TaskEv::End { .. }) | None => {
                        *done = true;
                        Poll::Ready(None)
                    }
                };
            },
        }
    }
    fn is_end_stream(&self) -> bool {
        matches!(self, Body::Full(None) | Body::Task { done: true, .. })
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
pub async fn serve(node: Arc<Node>, listener: TcpListener, unix: Option<std::os::unix::net::UnixListener>) {
    if let Err(e) = crate::run::init_key(&node.home.state_dir()) {
        crate::util::log("error", "no run key: `moochy run` cannot get a sandboxed session", &json!({"error": e.msg}));
    }
    let port = listener.local_addr().map_or(0, |a| a.port());
    let allowed: Arc<[String; 3]> = Arc::new([format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")]);
    let conns = Arc::new(Semaphore::new(MAX_CONNS));
    // Same door on a 0600 Unix socket: `moochy run` bridges it into the sandbox's empty netns,
    // where the agent reaches it as 127.0.0.1:<port> (same Host allowlist).
    let unix = unix.and_then(|l| tokio::net::UnixListener::from_std(l).ok());
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

/// Bind `<state>/gateway.sock` (0600) before the lockdown (macOS Seatbelt refuses a
/// Unix-socket bind afterwards). `None` when it cannot be made: `moochy run` then fails closed.
pub fn bind_gateway_socket(state_dir: &std::path::Path) -> Option<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    let p = state_dir.join("gateway.sock");
    let _ = std::fs::remove_file(&p);
    let l = std::os::unix::net::UnixListener::bind(&p).ok()?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).ok()?;
    l.set_nonblocking(true).ok()?;
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
    let dialect = if path.ends_with("/responses") {
        Dialect::OpenAiResponses
    } else if path.ends_with("/chat/completions") || (path.ends_with("/models") && req.headers().get("anthropic-version").is_none()) {
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
        let v = match crate::task::verify(&node, r) {
            Ok(v) => Ok(v),
            Err(_) => crate::keylog::verify_ref(&node, r.strip_prefix("r_").unwrap_or(r)).await,
        };
        return match v {
            Ok(v) => json_resp(200, &v),
            Err(e) => json_resp(422, &json!({"verified": false, "error": e})),
        };
    }
    // 4. A live sandboxed run token (§15.4), else a repo-scoped local token.
    // A215: a run token is honoured only on the 0600 Unix socket (the sandbox bridge), from a
    // peer running as this user; over TCP it is just an unknown token.
    let on_socket = crate::run::same_user(peer, &node.home.state_dir());
    let caller = token(req.headers())
        .and_then(|t| crate::run::check(t).filter(|_| on_socket).map(|r| (r.slug, true, r.platform)).or_else(|| node.check_token(t).map(|s| (s, false, false))));
    let Some((slug, sandboxed, platform)) = caller else {
        if path == "/mcp" {
            let mut r = json_resp(401, &json!({"error": "unauthorized"}));
            r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return r;
        }
        return native_error(dialect, &Failure::new("unauthorized", false, "moochy: invalid local token (see `moochy env`)".to_owned()));
    };
    // Tool calls are released only to sandboxed sessions or projects that opted in (§15.4).
    // The project's settings come from the relay (PoolSync), so only the pools of a repo this
    // account owns or is a member of in the verified key log count (F06), never one the relay
    // merely names with the same slug. A platform-sandboxed run (§17.2, `--box-is-sandbox`)
    // only if the project allows platform sandboxes.
    let bound = |repo: &str| match node.keylog.as_ref().filter(|l| l.verified()) {
        Some(l) => node.cfg.pseudonym.as_deref().is_some_and(|me| l.owner_or_member(repo, me)),
        None => node.insecure_dev,
    };
    let settings = crate::node::lock(&node.pools)
        .values()
        .filter(|p| p.slug.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(&slug)) && bound(&p.repo_id))
        .fold((false, false), |(a, b), p| (a || p.allow_unsandboxed_tools, b || p.allow_platform_sandboxes));
    let release = release_tools((sandboxed, platform), settings, (node.cfg.unsandboxed_tools_allowed(&slug), node.insecure_dev));
    match (req.method(), path.as_str()) {
        (&Method::POST, "/moochy/run") if !sandboxed => {
            let key = req.headers().get(crate::run::RUN_KEY_HEADER).and_then(|v| v.to_str().ok());
            let platform = req.headers().get(crate::run::PLATFORM_HEADER).is_some_and(|v| v.as_bytes() == b"1");
            crate::run::open(slug, platform, key, peer, &node.home.state_dir())
        }
        (_, "/mcp") => crate::mcp::http(node, slug, req).await,
        (&Method::GET, "/v1/models") => {
            node.settle_pool(&slug, |p| !p.models().is_empty()).await;
            models(&node, &slug)
        }
        (&Method::POST, "/v1/messages") => api(node, slug, Dialect::Anthropic, req, false, (release, platform)).await,
        (&Method::POST, "/v1/messages/count_tokens") => api(node, slug, Dialect::Anthropic, req, true, (release, platform)).await,
        (&Method::POST, "/v1/chat/completions") => api(node, slug, Dialect::OpenAi, req, false, (release, platform)).await,
        // §18.6 Codex: OpenAI Responses, sealed only to offers that list it.
        (&Method::POST, "/v1/responses") => api(node, slug, Dialect::OpenAiResponses, req, false, (release, platform)).await,
        _ => native_error(dialect, &Failure::new("not_found", false, format!("moochy: no route for {path}"))),
    }
}

/// Project pins narrowed by the session's `x-moochy-donors` list (a session can only narrow).
fn narrow_pins(project: Vec<String>, session: Option<&str>) -> Vec<String> {
    let Some(s) = session else { return project };
    let names: Vec<String> = s.split(',').map(str::trim).filter(|n| !n.is_empty() && n.len() <= 64).take(64).map(str::to_owned).collect();
    if project.is_empty() {
        return names;
    }
    let kept: Vec<String> = project.into_iter().filter(|p| names.iter().any(|n| n.eq_ignore_ascii_case(p))).collect();
    // Disjoint lists: nobody qualifies (fail closed, never "any donor").
    if kept.is_empty() { vec!["(no session donor is pinned for this project)".into()] } else { kept }
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
    let strip_body = memchr::memmem::find(&body, b"\"safeguards\"").is_some();
    let pool = moochy_worker::firewall::pool_compatible(dialect.worker(), if strip_body { &body } else { b"{}" }, &hdr)
        .map_err(|r| Failure::new("firewall", false, format!("moochy: {r} (refused before leaving this machine)")))?;
    drop(hdr);
    if !pool.stripped.is_empty() {
        crate::util::log("info", "removed what donors refuse", &json!({"stripped": pool.stripped}));
    }
    let (mut body, headers, stripped) = (if strip_body { Bytes::from(pool.body) } else { body }, pool.headers, pool.stripped);
    // One strict tape parse (no tree allocation): the per-request hot path (CONTRACT §13).
    let mut tape = Vec::new();
    let (entry, affinity, inject_max, auto_cache) = {
        let doc = wj::parse(&body, &mut tape).map_err(|e| bad(format!("moochy: invalid JSON body: {e}")))?;
        let root = doc.root();
        if root.kind() != Kind::Obj {
            return Err(bad("moochy: the body must be a JSON object".into()));
        }
        let model = root.get("model").and_then(Val::as_str).ok_or_else(|| bad("moochy: `model` is required".into()))?;
        let entry = catalog_entry(node, &model)?;
        // Responses: no injection (`max_tokens` is not a member there; the route takes the
        // catalog's max_output and the worker writes `max_output_tokens`).
        let missing = dialect != Dialect::OpenAiResponses && root.get("max_tokens").is_none() && root.get("max_completion_tokens").is_none();
        // 07 §4.2 step 4: multi-turn Anthropic conversation with no cache_control anywhere →
        // top-level automatic caching (5 m): cache reads cost donors a fraction of input.
        let turns = root.get("messages").map_or(0, |m| m.items().count());
        // Both the repo setting and the local config must allow it.
        let cache = dialect == Dialect::Anthropic && turns >= 2 && node.cfg.auto_cache() && memchr::memmem::find(&body, b"\"cache_control\"").is_none() && node.repo_auto_cache(&slug);
        // Affinity key over system, tools and the first user message (04 §5), each re-serialized
        // canonically (`Val::raw` is empty for objects and arrays, which made every key equal).
        // The members injected below are top-level and change none of them.
        let turns_key = if dialect == Dialect::OpenAiResponses { "input" } else { "messages" };
        let first = |role: &str| root.get(turns_key).and_then(|m| m.items().find(|x| x.get("role").is_some_and(|r| r.is_str(role))));
        let (system, user) = match dialect {
            Dialect::Anthropic => (root.get("system"), first("user")),
            Dialect::OpenAi => (first("system").or_else(|| first("developer")), first("user")),
            // Responses: `instructions`; `input` is a string or a list of items.
            Dialect::OpenAiResponses => (root.get("instructions"), root.get("input").filter(|i| i.kind() == Kind::Str).or_else(|| first("user"))),
        };
        let affinity = affinity_key(&node.secrets, system, root.get("tools"), user, body.len());
        let inject = missing.then(|| u64::from(entry.max_output).min(DEFAULT_MAX_TOKENS));
        (entry, affinity, inject, cache)
    };
    drop(tape);
    if inject_max.is_some() || auto_cache {
        if let Some(n) = inject_max
            && !MAX_NOTICE.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            crate::util::log("warn", "request without max_tokens: injected the catalog default (told once)", &json!({"max_tokens": n}));
        }
        let mut members = inject_max.map(|n| format!("\"max_tokens\":{n},")).unwrap_or_default();
        if auto_cache {
            members.push_str("\"cache_control\":{\"type\":\"ephemeral\"},");
        }
        body = insert_members(&body, &members);
    }
    let facts = crate::engine::analyze(&entry, dialect, &body, &headers)?;
    let pinned = node.cfg.pinned_donors.get(&slug.to_ascii_lowercase()).cloned().unwrap_or_default();
    Ok(TaskReq { slug, dialect, body, affinity, facts, entry, headers, t_client_rx, release_tools: false, platform_sandboxed: false, stripped, pinned })
}

/// Members (`"k":v,` each, comma-terminated) spliced in right after the opening `{` of a body
/// already parsed as a JSON object without them: no tree parse and re-serialization of the
/// whole body (it can be megabytes) to add two top-level members.
fn insert_members(body: &[u8], members: &str) -> Bytes {
    let open = body.iter().position(|c| *c == b'{').unwrap_or(0);
    let rest = body.get(open.saturating_add(1)..).unwrap_or_default();
    let empty = rest.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'}');
    let members = if empty { members.trim_end_matches(',') } else { members };
    let mut out = Vec::with_capacity(body.len().saturating_add(members.len()));
    out.extend_from_slice(body.get(..=open).unwrap_or_default());
    out.extend_from_slice(members.as_bytes());
    out.extend_from_slice(rest);
    Bytes::from(out)
}

/// `cap`: an upper bound of the canonical bytes (the body length), so the one buffer never
/// regrows (each regrowth copied everything written so far).
fn affinity_key(
    secrets: &crate::keystore::Secrets,
    system: Option<moochy_worker::json::Val<'_>>,
    tools: Option<moochy_worker::json::Val<'_>>,
    user: Option<moochy_worker::json::Val<'_>>,
    cap: usize,
) -> [u8; 16] {
    let mut buf = Vec::with_capacity(cap.saturating_add(64));
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
/// `release`: (tool calls may reach this client, the session is platform-sandboxed).
async fn api(node: Arc<Node>, slug: String, dialect: Dialect, req: Request<Incoming>, count_only: bool, release: (bool, bool)) -> Resp {
    let t_rx = crate::task::now_us();
    // Session-level pinned donors (06 §8): `x-moochy-donors: alice,bob`.
    let session_pins = req.headers().get("x-moochy-donors").and_then(|v| v.to_str().ok()).map(str::to_owned);
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
        Ok(t) => TaskReq { release_tools: release.0, platform_sandboxed: release.1, pinned: narrow_pins(t.pinned.clone(), session_pins.as_deref()), ..t },
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
        let mut r = Response::new(Body::Task { rx, dialect, done: false });
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

/// Whether donor tool calls reach this session (§15.4, F06): the session (`moochy run`, platform
/// sandbox), the project's settings, and this machine (`allow_unsandboxed_tools` names the
/// project, insecure dev mode).
/// Outside `moochy run`, the relay's word is never enough: local consent is required too
/// (development alone may skip the project's setting).
fn release_tools((sandboxed, platform): (bool, bool), (repo_allows, platform_ok): (bool, bool), (consent, insecure_dev): (bool, bool)) -> bool {
    (sandboxed && (!platform || platform_ok)) || (consent && (repo_allows || insecure_dev))
}

#[cfg(test)]
mod release_tests {
    #[test]
    fn the_relay_alone_never_releases_tool_calls_outside_moochy_run() {
        use super::release_tools as r;
        let off = (false, false);
        assert!(!r(off, (true, true), off), "F06: a relay-set project flag without local consent");
        assert!(r(off, (true, false), (true, false)), "project setting + local consent");
        assert!(!r(off, off, (true, false)), "local consent alone (production)");
        assert!(r((true, false), off, off), "moochy run");
        assert!(!r((true, true), off, off), "platform sandbox the project does not allow");
        assert!(r((true, true), (false, true), off));
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    #[test]
    fn session_pins_only_narrow() {
        assert_eq!(narrow_pins(vec![], None), Vec::<String>::new());
        assert_eq!(narrow_pins(vec![], Some("alice, bob")), vec!["alice", "bob"]);
        assert_eq!(narrow_pins(vec!["alice".into(), "carol".into()], Some("Alice,bob")), vec!["alice"]);
        let none = narrow_pins(vec!["alice".into()], Some("bob"));
        assert_eq!(none.len(), 1);
        assert!(none[0].contains(' '), "disjoint lists select nobody, never any donor");
    }
}

#[cfg(test)]
mod affinity_tests {
    use super::*;

    fn key(body: &str) -> [u8; 16] {
        let mut tape = Vec::new();
        let doc = moochy_worker::json::parse(body.as_bytes(), &mut tape).unwrap();
        let root = doc.root();
        let user = root.get("messages").and_then(|m| m.items().next());
        affinity_key(&crate::keystore::Secrets::default(), root.get("system"), root.get("tools"), user, 0)
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

    /// `cargo test --release -p moochy -- --ignored --nocapture prepare_cost`: the auto-cache
    /// injection (splice vs the former serde round-trip) and the affinity key on a large body.
    #[test]
    #[ignore = "bench"]
    fn prepare_cost() {
        let tools: Vec<serde_json::Value> = (0..400).map(|i| json!({"name": format!("tool{i}"), "description": "x".repeat(200), "input_schema": {"type": "object"}})).collect();
        let msgs: Vec<serde_json::Value> = (0..40).map(|i| json!({"role": if i % 2 == 0 { "user" } else { "assistant" }, "content": "y".repeat(2000)})).collect();
        let body = json!({"model": "m", "system": "s".repeat(20_000), "tools": tools, "messages": msgs}).to_string();
        let n = 50u32;
        let t = std::time::Instant::now();
        for _ in 0..n {
            let mut m = crate::json::parse_object(body.as_bytes()).unwrap();
            m.insert("cache_control".into(), json!({"type": "ephemeral"}));
            std::hint::black_box(Value::Object(m).to_string());
        }
        let serde = t.elapsed() / n;
        let t = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(insert_members(body.as_bytes(), r#""cache_control":{"type":"ephemeral"},"#));
        }
        let splice = t.elapsed() / n;
        let mut tape = Vec::new();
        let doc = moochy_worker::json::parse(body.as_bytes(), &mut tape).unwrap();
        let root = doc.root();
        let user = root.get("messages").and_then(|m| m.items().next());
        let s = crate::keystore::Secrets::default();
        let time = |cap: usize| {
            let t = std::time::Instant::now();
            for _ in 0..n {
                std::hint::black_box(affinity_key(&s, root.get("system"), root.get("tools"), user, cap));
            }
            t.elapsed() / n
        };
        let (grow, sized) = (time(0), time(body.len()));
        println!("body {} KB: inject serde {serde:?} → splice {splice:?}; affinity growing {grow:?} → presized {sized:?}", body.len() / 1024);
    }

    #[test]
    fn injected_members_keep_the_body_valid_json() {
        let m = r#""max_tokens":4096,"cache_control":{"type":"ephemeral"},"#;
        for (body, want) in [
            (r#"{"model":"m","messages":[]}"#, r#"{"max_tokens":4096,"cache_control":{"type":"ephemeral"},"model":"m","messages":[]}"#),
            (" \n { } ", " "),
            ("{}", r#"{"max_tokens":4096,"cache_control":{"type":"ephemeral"}}"#),
        ] {
            let out = insert_members(body.as_bytes(), m);
            let v: serde_json::Value = serde_json::from_slice(&out).unwrap_or_else(|e| panic!("{body:?}: {e}: {:?}", String::from_utf8_lossy(&out)));
            assert_eq!(v["max_tokens"], 4096);
            assert_eq!(v["cache_control"]["type"], "ephemeral");
            if want.len() > 2 {
                assert_eq!(String::from_utf8_lossy(&out), want);
            }
            let mut tape = Vec::new();
            assert!(moochy_worker::json::parse(&out, &mut tape).is_ok(), "strict parser accepts it");
        }
    }
}
