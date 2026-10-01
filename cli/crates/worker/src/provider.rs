//! Provider adapters (plan 07 §6.2–6.3): fixed hosts, HTTP/2 over rustls (ring), one warm
//! multiplexed connection per adapter, strict timeouts, response size caps, and
//! cancellation by drop (an h2 stream reset / closed h1 socket stops the provider).
//!
//! A base-URL override is accepted only for loopback IP literals and only when the caller
//! passes `insecure_dev` (CONTRACT §6). Plain `http://` is served over HTTP/1.1 (the e2e
//! fakes); `https://` always uses HTTP/2.

use std::future::{Future, poll_fn};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::header::{HeaderMap, HeaderValue};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::{Dialect, Provider};

/// Timeouts and caps. Defaults are the production values.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// TCP connect and TLS handshake, each.
    pub connect: Duration,
    /// Request sent → response headers (includes dialing).
    pub headers: Duration,
    /// Max silence between two body chunks (providers ping every few seconds).
    pub idle: Duration,
    /// Whole response.
    pub total: Duration,
    /// Response body bytes.
    pub max_response: u64,
    /// Error body bytes kept for the Gateway.
    pub max_error_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            headers: Duration::from_secs(30),
            idle: Duration::from_secs(120),
            total: Duration::from_secs(3600),
            max_response: 128 << 20,
            max_error_body: 64 << 10,
        }
    }
}

/// HTTP/2 flow-control windows (CONTRACT §13: stream ≥ 1 MiB, connection ≥ 4 MiB).
const H2_STREAM_WINDOW: u32 = 2 << 20;
const H2_CONN_WINDOW: u32 = 8 << 20;
const USER_AGENT: &str = concat!("moochy-worker/", env!("CARGO_PKG_VERSION"));

pub struct AdapterConfig {
    pub provider: Provider,
    pub api_key: Zeroizing<String>,
    /// Loopback-only override (`http://127.0.0.1:PORT[/prefix]`), honoured only with `insecure_dev`.
    pub base_url: Option<String>,
    pub insecure_dev: bool,
    /// Extra trust root for an `https://` loopback override (tests), only with `insecure_dev`.
    pub dev_root: Option<CertificateDer<'static>>,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Why a provider call failed (before or during the stream).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailKind {
    RateLimited,
    Overloaded,
    ProviderError,
    Auth,
    ModelUnavailable,
    InvalidRequest,
    Network,
    Timeout,
    TooLarge,
    Unsupported,
}

/// Provider rate-limit headers, for `worker.offer.models[].rl_headroom` (Anthropic
/// `anthropic-ratelimit-{requests,tokens}-{limit,remaining}`, OpenAI-style
/// `x-ratelimit-{limit,remaining}-{requests,tokens}`). Absent headers stay `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateLimit {
    pub requests_limit: Option<u64>,
    pub requests_remaining: Option<u64>,
    pub tokens_limit: Option<u64>,
    pub tokens_remaining: Option<u64>,
    /// Milliseconds until the request budget resets (Anthropic RFC 3339 `…-requests-reset`,
    /// OpenAI-style duration `x-ratelimit-reset-requests` such as `6m0s`).
    pub requests_reset_ms: Option<u64>,
    pub tokens_reset_ms: Option<u64>,
}

impl RateLimit {
    pub fn from_headers(h: &HeaderMap) -> Self {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self::from_headers_at(h, now)
    }

    /// Header names per adapter: Anthropic `anthropic-ratelimit-{requests,tokens}-{limit,
    /// remaining,reset}`; OpenAI and OpenRouter `x-ratelimit-{limit,remaining,reset}-{requests,
    /// tokens}`; DeepSeek and xAI document none (all `None`).
    pub fn from_headers_at(h: &HeaderMap, now_ms: u64) -> Self {
        let reset = |anth: &str, oai: &str| {
            let t = h.get(anth).and_then(|v| v.to_str().ok()).and_then(rfc3339_ms).map(|t| t.saturating_sub(now_ms));
            t.or_else(|| h.get(oai).and_then(|v| v.to_str().ok()).and_then(duration_ms))
        };
        Self {
            requests_limit: header_u64(h, &["anthropic-ratelimit-requests-limit", "x-ratelimit-limit-requests"]),
            requests_remaining: header_u64(h, &["anthropic-ratelimit-requests-remaining", "x-ratelimit-remaining-requests"]),
            tokens_limit: header_u64(h, &["anthropic-ratelimit-tokens-limit", "x-ratelimit-limit-tokens"]),
            tokens_remaining: header_u64(h, &["anthropic-ratelimit-tokens-remaining", "x-ratelimit-remaining-tokens"]),
            requests_reset_ms: reset("anthropic-ratelimit-requests-reset", "x-ratelimit-reset-requests"),
            tokens_reset_ms: reset("anthropic-ratelimit-tokens-reset", "x-ratelimit-reset-tokens"),
        }
    }

    /// Headroom in percent (0–100): the tighter of the request and token budgets, `None`
    /// when the provider sent no complete limit/remaining pair.
    pub fn headroom_pct(&self) -> Option<u8> {
        let pct = |rem: Option<u64>, lim: Option<u64>| {
            let (rem, lim) = (rem?, lim?);
            let p = rem.min(lim).saturating_mul(100).checked_div(lim).unwrap_or(0);
            u8::try_from(p).ok()
        };
        match (pct(self.requests_remaining, self.requests_limit), pct(self.tokens_remaining, self.tokens_limit)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Failure {
    pub kind: FailKind,
    pub status: Option<u16>,
    pub retry_after_ms: Option<u64>,
    /// Rate-limit headers of an HTTP error response (a 429 usually reports zero headroom);
    /// `None` for failures without a response. Boxed: keeps `Result<_, Failure>` small.
    pub rate_limit: Option<Box<RateLimit>>,
    /// The provider's error body (bounded), to seal to the Gateway as the native error.
    pub body: Bytes,
    pub detail: &'static str,
}

impl Failure {
    fn new(kind: FailKind, detail: &'static str) -> Self {
        Self { kind, status: None, retry_after_ms: None, rate_limit: None, body: Bytes::new(), detail }
    }

    /// NACK code (03 §10.2) and whether another worker may retry.
    pub fn nack(&self) -> (&'static str, bool) {
        match self.kind {
            FailKind::RateLimited => ("rate_limited", true),
            FailKind::Overloaded => ("overloaded", true),
            FailKind::ProviderError | FailKind::Network | FailKind::Timeout | FailKind::Auth => ("provider_error", true),
            FailKind::ModelUnavailable | FailKind::Unsupported => ("model_unavailable", true),
            FailKind::InvalidRequest | FailKind::TooLarge => ("provider_error", false),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(s) => write!(f, "{:?} (HTTP {s}): {}", self.kind, self.detail),
            None => write!(f, "{:?}: {}", self.kind, self.detail),
        }
    }
}

impl std::error::Error for Failure {}

/// One adapter definition (07 §6.2): the official origin and the **full request path for
/// each dialect it serves**. Paths are fixed per adapter: a configured base URL (loopback
/// dev override only) replaces the *origin* and never the path, so the e2e fakes serve
/// exactly the real paths and nothing is guessed from a URL prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterDef {
    pub host: &'static str,
    /// Anthropic Messages endpoint path, if served.
    pub messages: Option<&'static str>,
    /// OpenAI chat-completions endpoint path, if served.
    pub chat: Option<&'static str>,
}

impl AdapterDef {
    pub const fn of(p: Provider) -> Self {
        match p {
            Provider::Anthropic => Self { host: "api.anthropic.com", messages: Some("/v1/messages"), chat: None },
            Provider::OpenAi => Self { host: "api.openai.com", messages: None, chat: Some("/v1/chat/completions") },
            // OpenAI-compatible root `https://openrouter.ai/api/v1`; Anthropic-compatible root
            // `https://openrouter.ai/api` (+ `/v1/messages`).
            Provider::OpenRouter => {
                Self { host: "openrouter.ai", messages: Some("/api/v1/messages"), chat: Some("/api/v1/chat/completions") }
            }
            // OpenAI-compatible root `https://api.deepseek.com`; Anthropic-compatible root
            // `https://api.deepseek.com/anthropic` (+ `/v1/messages`).
            Provider::DeepSeek => {
                Self { host: "api.deepseek.com", messages: Some("/anthropic/v1/messages"), chat: Some("/chat/completions") }
            }
            // OpenAI-compatible root `https://api.x.ai/v1` (global endpoint; the US regional
            // host costs +10% and is not allowlisted). No Anthropic-compatible endpoint.
            Provider::XAi => Self { host: "api.x.ai", messages: None, chat: Some("/v1/chat/completions") },
        }
    }

    pub const fn path(&self, d: Dialect) -> Option<&'static str> {
        match d {
            Dialect::AnthropicMessages => self.messages,
            Dialect::OpenAiChat => self.chat,
        }
    }
}

struct Target {
    tls: bool,
    /// Host to dial (DNS name or IP literal).
    host: String,
    port: u16,
    /// `host[:port]` for the URI authority.
    authority: String,
}

fn real_target(p: Provider) -> Target {
    let host = AdapterDef::of(p).host;
    Target { tls: true, host: host.to_owned(), port: 443, authority: host.to_owned() }
}

/// Parse a dev base URL: an **origin** only (`http(s)://loopback-ip[:port]`, optional
/// trailing `/`). A path is refused rather than interpreted: the adapter owns the paths.
fn dev_target(url: &str) -> Result<Target, ConfigError> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        return Err(ConfigError("base URL must be http:// or https://"));
    };
    if rest.contains(['?', '#', '@', '\\']) || rest.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(ConfigError("base URL must be scheme://loopback-ip[:port]"));
    }
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains('/') {
        return Err(ConfigError("base URL must be an origin (scheme://loopback-ip[:port]); request paths are fixed per adapter"));
    }
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, p) = r.split_once(']').ok_or(ConfigError("bad IPv6 literal"))?;
        (h, p.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let ip: IpAddr = host.parse().map_err(|_| ConfigError("base URL host must be a loopback IP literal"))?;
    if !ip.is_loopback() {
        return Err(ConfigError("base URL host must be loopback"));
    }
    let port = match port {
        Some(p) => p.parse().map_err(|_| ConfigError("bad port"))?,
        None if tls => 443,
        None => 80,
    };
    Ok(Target { tls, host: ip.to_string(), port, authority: authority.to_owned() })
}

fn tls_config(dev_root: Option<&CertificateDer<'static>>) -> Result<Arc<rustls::ClientConfig>, ConfigError> {
    static DEFAULT: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    let build = |extra: Option<&CertificateDer<'static>>| -> Option<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        if let Some(c) = extra {
            roots.add(c.clone()).ok()?;
        }
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Some(Arc::new(cfg))
    };
    match dev_root {
        Some(c) => build(Some(c)),
        None => DEFAULT.get_or_init(|| build(None)).clone(),
    }
    .ok_or(ConfigError("TLS configuration failed"))
}

type H2 = http2::SendRequest<Full<Bytes>>;

/// One provider key. Cheap to share (`Arc<Adapter>`); all requests multiplex on one warm
/// HTTP/2 connection, re-dialed transparently when it dies.
pub struct Adapter {
    provider: Provider,
    target: Target,
    auth_name: &'static str,
    auth: HeaderValue,
    tls: Option<TlsConnector>,
    h2: Mutex<Option<H2>>,
    /// Idle HTTP/1.1 keep-alive connections (`http://` loopback dev targets only).
    h1_idle: Arc<StdMutex<Vec<H1Conn>>>,
    limits: Limits,
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter").field("provider", &self.provider).field("authority", &self.target.authority).finish_non_exhaustive()
    }
}

impl Adapter {
    pub fn new(cfg: &AdapterConfig) -> Result<Self, ConfigError> {
        let target = match &cfg.base_url {
            None => real_target(cfg.provider),
            Some(_) if !cfg.insecure_dev => return Err(ConfigError("base URL override needs MOOCHY_INSECURE_DEV=1")),
            Some(u) => dev_target(u)?,
        };
        if cfg.dev_root.is_some() && !(cfg.insecure_dev && cfg.base_url.is_some()) {
            return Err(ConfigError("a dev trust root is only accepted with a loopback dev base URL"));
        }
        let key = cfg.api_key.trim();
        if key.is_empty() || key.len() > 512 || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ConfigError("API key must be 1..512 visible ASCII characters"));
        }
        let (auth_name, value) = match cfg.provider {
            Provider::Anthropic => ("x-api-key", Zeroizing::new(key.to_owned())),
            _ => ("authorization", Zeroizing::new(format!("Bearer {key}"))),
        };
        // ponytail: the HeaderValue copy cannot be zeroized (http crate); it lives as long as the adapter.
        let mut auth = HeaderValue::from_str(&value).map_err(|_| ConfigError("API key is not a valid header value"))?;
        auth.set_sensitive(true);
        let tls = if target.tls { Some(TlsConnector::from(tls_config(cfg.dev_root.as_ref())?)) } else { None };
        Ok(Self { provider: cfg.provider, target, auth_name, auth, tls, h2: Mutex::new(None), h1_idle: Arc::default(), limits: cfg.limits })
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Open (or keep) the warm HTTP/2 connection. Call at startup, on key add, and every
    /// minute or so; keep-alive PINGs hold it open in between. No-op for `http://` dev targets.
    pub async fn warm(&self) -> Result<(), Failure> {
        let warm = async {
            if self.tls.is_some() {
                self.h2_sender().await.map(drop)
            } else if self.h1_idle_count() == 0 {
                let c = self.dial_h1().await?;
                self.h1_return(c);
                Ok(())
            } else {
                Ok(())
            }
        };
        tokio::time::timeout(self.limits.headers, warm).await.map_err(|_| Failure::new(FailKind::Timeout, "connect timed out"))?
    }

    fn h1_idle_count(&self) -> usize {
        self.h1_idle.lock().map_or(0, |g| g.iter().filter(|c| !c.sender.is_closed()).count())
    }

    fn h1_return(&self, c: H1Conn) {
        return_h1(&self.h1_idle, c);
    }

    async fn dial_h1(&self) -> Result<H1Conn, Failure> {
        let tcp = self.tcp().await?;
        let (sender, conn) =
            http1::handshake(TokioIo::new(tcp)).await.map_err(|_| Failure::new(FailKind::Network, "HTTP/1 handshake failed"))?;
        let task = AbortOnDrop(tokio::spawn(async move {
            let _ = conn.await;
        }));
        Ok(H1Conn { sender, _task: task })
    }

    /// An idle keep-alive connection that is still usable, else a fresh one.
    async fn h1_conn(&self) -> Result<(H1Conn, bool), Failure> {
        loop {
            let idle = self.h1_idle.lock().ok().and_then(|mut g| g.pop());
            let Some(mut c) = idle else { break };
            if c.sender.is_closed() {
                continue;
            }
            if c.sender.ready().await.is_ok() {
                return Ok((c, true));
            }
        }
        Ok((self.dial_h1().await?, false))
    }

    async fn h2_sender(&self) -> Result<H2, Failure> {
        let mut g = self.h2.lock().await;
        if let Some(s) = g.as_ref().filter(|s| !s.is_closed()) {
            return Ok(s.clone());
        }
        *g = None;
        let s = self.dial_h2().await?;
        *g = Some(s.clone());
        Ok(s)
    }

    async fn tcp(&self) -> Result<TcpStream, Failure> {
        let t = &self.target;
        let tcp = tokio::time::timeout(self.limits.connect, TcpStream::connect((t.host.as_str(), t.port)))
            .await
            .map_err(|_| Failure::new(FailKind::Timeout, "TCP connect timed out"))?
            .map_err(|_| Failure::new(FailKind::Network, "TCP connect failed"))?;
        tcp.set_nodelay(true).map_err(|_| Failure::new(FailKind::Network, "TCP_NODELAY failed"))?;
        Ok(tcp)
    }

    async fn dial_h2(&self) -> Result<H2, Failure> {
        let Some(tls) = &self.tls else {
            return Err(Failure::new(FailKind::Unsupported, "no TLS for this target"));
        };
        let tcp = self.tcp().await?;
        let name = ServerName::try_from(self.target.host.clone()).map_err(|_| Failure::new(FailKind::Network, "bad TLS server name"))?;
        let stream = tokio::time::timeout(self.limits.connect, tls.connect(name, tcp))
            .await
            .map_err(|_| Failure::new(FailKind::Timeout, "TLS handshake timed out"))?
            .map_err(|_| Failure::new(FailKind::Network, "TLS handshake failed"))?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(Failure::new(FailKind::Network, "provider did not negotiate HTTP/2"));
        }
        let (sender, conn) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .initial_stream_window_size(H2_STREAM_WINDOW)
            .initial_connection_window_size(H2_CONN_WINDOW)
            .keep_alive_interval(Duration::from_secs(20))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .max_header_list_size(64 << 10)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| Failure::new(FailKind::Network, "HTTP/2 handshake failed"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }

    /// Send a prepared body ([`crate::firewall::prepare`]). Returns once response headers
    /// arrive (= `task.started`) with a 2xx; any other status is a [`Failure`] carrying the
    /// provider's bounded error body. Drop the [`Response`] to abort the provider request.
    pub async fn send(&self, dialect: Dialect, body: Bytes, headers: &[(&'static str, String)]) -> Result<Response, Failure> {
        let Some(path) = AdapterDef::of(self.provider).path(dialect) else {
            return Err(Failure::new(FailKind::Unsupported, "dialect not served by this provider"));
        };
        let t = &self.target;
        // h2 needs the absolute URI (:scheme/:authority); HTTP/1.1 wants origin-form + Host.
        let uri = if t.tls {
            format!("https://{}{path}", t.authority)
        } else {
            path.to_owned()
        };
        let mut b = hyper::Request::post(uri)
            .header("content-type", "application/json")
            .header("user-agent", USER_AGENT)
            .header(self.auth_name, self.auth.clone());
        if !t.tls {
            b = b.header("host", t.authority.as_str());
        }
        for (k, v) in headers {
            b = b.header(*k, HeaderValue::from_str(v).map_err(|_| Failure::new(FailKind::InvalidRequest, "bad header value"))?);
        }
        let req = b.body(Full::new(body)).map_err(|_| Failure::new(FailKind::InvalidRequest, "bad request"))?;

        let fut = async {
            if self.tls.is_some() {
                let mut s = self.h2_sender().await?;
                s.ready().await.map_err(|_| Failure::new(FailKind::Network, "HTTP/2 connection lost"))?;
                let resp = s.send_request(req).await.map_err(|_| Failure::new(FailKind::Network, "request failed before headers"))?;
                Ok::<_, Failure>((resp, None))
            } else {
                // Keep-alive pool, like production's warm h2 connection. A request is retried
                // on a fresh connection only when hyper proves it was never sent (a reused
                // connection closed by the server in between): no double execution.
                let (mut c, reused) = self.h1_conn().await?;
                let resp = match c.sender.try_send_request(req).await {
                    Ok(r) => r,
                    Err(mut e) => match e.take_message() {
                        Some(req) if reused => {
                            c = self.dial_h1().await?;
                            c.sender.send_request(req).await.map_err(|_| Failure::new(FailKind::Network, "request failed before headers"))?
                        }
                        _ => return Err(Failure::new(FailKind::Network, "request failed before headers")),
                    },
                };
                Ok((resp, Some(H1Lease { conn: Some(c), pool: self.h1_idle.clone(), reusable: false })))
            }
        };
        let (resp, conn) =
            tokio::time::timeout(self.limits.headers, fut).await.map_err(|_| Failure::new(FailKind::Timeout, "no response headers in time"))??;
        let (parts, body) = resp.into_parts();
        let status = parts.status.as_u16();
        if !parts.status.is_success() {
            return Err(self.error(status, &parts.headers, body).await);
        }
        let now = Instant::now();
        Ok(Response {
            status,
            request_id: header_str(&parts.headers, &["request-id", "x-request-id"]),
            rate_limit: RateLimit::from_headers(&parts.headers),
            body,
            idle: Box::pin(tokio::time::sleep(self.limits.idle)),
            deadline: now.checked_add(self.limits.total).unwrap_or(now),
            limits: self.limits,
            read: 0,
            lease: conn,
        })
    }

    async fn error(&self, status: u16, headers: &HeaderMap, mut body: Incoming) -> Failure {
        let kind = match status {
            429 => FailKind::RateLimited,
            503 | 529 => FailKind::Overloaded,
            401 | 403 => FailKind::Auth,
            404 => FailKind::ModelUnavailable,
            400..=499 if status != 408 => FailKind::InvalidRequest,
            _ => FailKind::ProviderError,
        };
        let mut buf = Vec::new();
        let cap = self.limits.max_error_body;
        let read = async {
            while let Some(Ok(f)) = body.frame().await {
                if let Ok(d) = f.into_data() {
                    let room = cap.saturating_sub(buf.len());
                    buf.extend_from_slice(d.get(..room.min(d.len())).unwrap_or_default());
                    if buf.len() >= cap {
                        break;
                    }
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(5), read).await;
        let retry_after_ms = header_u64(headers, &["retry-after-ms"])
            .or_else(|| header_u64(headers, &["retry-after"]).filter(|s| *s <= 86_400).and_then(|s| s.checked_mul(1000)));
        Failure {
            kind,
            status: Some(status),
            retry_after_ms,
            rate_limit: Some(Box::new(RateLimit::from_headers(headers))),
            body: Bytes::from(buf),
            detail: "provider returned an error status",
        }
    }
}

/// RFC 3339 UTC-or-offset timestamp → Unix ms (`2026-10-01T21:50:00Z`, `…00.123+02:00`).
fn rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let num = |a: usize, n: usize| -> Option<i64> {
        let r = s.get(a..a.checked_add(n)?)?;
        if r.bytes().all(|c| c.is_ascii_digit()) { r.parse().ok() } else { None }
    };
    if b.len() < 20 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') || !matches!(b.get(10), Some(b'T' | b't' | b' ')) || b.get(13) != Some(&b':') || b.get(16) != Some(&b':') {
        return None;
    }
    let (y, mo, d, hh, mm, ss) = (num(0, 4)?, num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let mut i = 19usize;
    let mut ms = 0i64;
    if b.get(i) == Some(&b'.') {
        i = i.checked_add(1)?;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i = i.checked_add(1)?;
        }
        let frac = s.get(start..i)?;
        let digits = frac.get(..frac.len().min(3))?;
        ms = format!("{digits:0<3}").parse().ok()?;
    }
    let offset = match b.get(i) {
        Some(b'Z' | b'z') if b.len() == i.checked_add(1)? => 0,
        Some(sign @ (b'+' | b'-')) if b.len() == i.checked_add(6)? && b.get(i.checked_add(3)?) == Some(&b':') => {
            let m = num(i.checked_add(1)?, 2)?.checked_mul(60)?.checked_add(num(i.checked_add(4)?, 2)?)?;
            if *sign == b'+' { m } else { m.checked_neg()? }
        }
        _ => return None,
    };
    // Howard Hinnant's days_from_civil.
    let y2 = if mo <= 2 { y.checked_sub(1)? } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2.checked_sub(era.checked_mul(400)?)?;
    let mp = if mo > 2 { mo.checked_sub(3)? } else { mo.checked_add(9)? };
    let doy = mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?.checked_add(d)?.checked_sub(1)?;
    let doe = yoe.checked_mul(365)?.checked_add(yoe.checked_div(4)?)?.checked_sub(yoe.checked_div(100)?)?.checked_add(doy)?;
    let days = era.checked_mul(146_097)?.checked_add(doe)?.checked_sub(719_468)?;
    let secs = days.checked_mul(86_400)?.checked_add(hh.checked_mul(3600)?)?.checked_add(mm.checked_mul(60)?)?.checked_add(ss)?.checked_sub(offset.checked_mul(60)?)?;
    u64::try_from(secs.checked_mul(1000)?.checked_add(ms)?).ok()
}

/// OpenAI-style duration (`1s`, `6m0s`, `1h2m3.5s`, `20ms`) → ms.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // finite, ≥ 0, < 1e15: exact in u64
fn duration_ms(s: &str) -> Option<u64> {
    let mut total = 0f64;
    let mut rest = s.trim();
    if rest.is_empty() || rest.len() > 32 {
        return None;
    }
    while !rest.is_empty() {
        let n = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).filter(|n| *n > 0)?;
        let (num, tail) = rest.split_at(n);
        let v: f64 = num.parse().ok()?;
        let (mult, len) = if tail.starts_with("ms") {
            (1.0, 2)
        } else if tail.starts_with('h') {
            (3_600_000.0, 1)
        } else if tail.starts_with('m') {
            (60_000.0, 1)
        } else if tail.starts_with('s') {
            (1000.0, 1)
        } else {
            return None;
        };
        total += v * mult;
        rest = tail.get(len..)?;
    }
    (total.is_finite() && total < 1e15).then(|| total.ceil() as u64)
}

fn header_str(h: &HeaderMap, names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| h.get(*n)).and_then(|v| v.to_str().ok()).filter(|s| s.len() <= 256).map(str::to_owned)
}

fn header_u64(h: &HeaderMap, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|n| h.get(*n)).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok())
}

struct AbortOnDrop(JoinHandle<()>);

/// Most idle keep-alive connections kept per adapter (dev `http://` targets).
const H1_MAX_IDLE: usize = 16;

struct H1Conn {
    sender: http1::SendRequest<Full<Bytes>>,
    /// Dropping the connection aborts its task, which closes the socket (cancellation).
    _task: AbortOnDrop,
}

fn return_h1(pool: &StdMutex<Vec<H1Conn>>, c: H1Conn) {
    if c.sender.is_closed() {
        return;
    }
    if let Ok(mut g) = pool.lock() {
        g.retain(|c| !c.sender.is_closed());
        if g.len() < H1_MAX_IDLE {
            g.push(c);
        }
    }
}

struct H1Lease {
    conn: Option<H1Conn>,
    pool: Arc<StdMutex<Vec<H1Conn>>>,
    /// Set when the body was read to the end: only then may the connection serve again.
    reusable: bool,
}

impl Drop for H1Lease {
    fn drop(&mut self) {
        if let Some(c) = self.conn.take()
            && self.reusable
        {
            return_h1(&self.pool, c);
        }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A streaming 2xx response. Dropping it aborts the provider request immediately.
pub struct Response {
    pub status: u16,
    /// Provider request id header, if any (else use [`crate::stream::Outcome::id`]).
    pub request_id: Option<String>,
    /// Rate-limit headers of this response (`rate_limit.headroom_pct()` → `rl_headroom`).
    pub rate_limit: RateLimit,
    body: Incoming,
    idle: Pin<Box<Sleep>>,
    deadline: Instant,
    limits: Limits,
    read: u64,
    /// HTTP/1.1 connection, returned to the keep-alive pool only after the body ended.
    lease: Option<H1Lease>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response").field("status", &self.status).field("read", &self.read).finish_non_exhaustive()
    }
}

impl Response {
    /// Next body chunk exactly as received (forward it at once: no batching), `None` at the
    /// end. Enforces the idle timeout, the total deadline and the size cap.
    pub async fn next(&mut self) -> Result<Option<Bytes>, Failure> {
        loop {
            let now = Instant::now();
            let idle_at = now.checked_add(self.limits.idle).unwrap_or(now).min(self.deadline);
            self.idle.as_mut().reset(idle_at);
            let (body, idle) = (&mut self.body, &mut self.idle);
            let frame = poll_fn(|cx| {
                if let Poll::Ready(f) = Pin::new(&mut *body).poll_frame(cx) {
                    return Poll::Ready(Ok(f));
                }
                if idle.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(()));
                }
                Poll::Pending
            })
            .await
            .map_err(|()| Failure::new(FailKind::Timeout, "provider stream stalled"))?;
            match frame {
                None => {
                    if let Some(l) = &mut self.lease {
                        l.reusable = true;
                    }
                    return Ok(None);
                }
                Some(Err(_)) => return Err(Failure::new(FailKind::Network, "provider stream broke")),
                Some(Ok(f)) => {
                    let Ok(data) = f.into_data() else { continue };
                    if data.is_empty() {
                        continue;
                    }
                    self.read = self.read.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
                    if self.read > self.limits.max_response {
                        return Err(Failure::new(FailKind::TooLarge, "provider response too large"));
                    }
                    return Ok(Some(data));
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dev_urls() {
        let t = dev_target("http://127.0.0.1:8080").unwrap();
        assert_eq!((t.tls, t.host.as_str(), t.port, t.authority.as_str()), (false, "127.0.0.1", 8080, "127.0.0.1:8080"));
        let t = dev_target("https://[::1]:9/").unwrap();
        assert_eq!((t.tls, t.host.as_str(), t.port, t.authority.as_str()), (true, "::1", 9, "[::1]:9"));
        for bad in [
            "http://localhost:1",
            "http://10.0.0.1:1",
            "http://evil.com",
            "ftp://127.0.0.1",
            "http://127.0.0.1@evil.com",
            "http://127.0.0.1:1?x",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:8080/api",
            "http://127.0.0.1:8080/anthropic/",
            "http://127.0.0.1:8080//",
        ] {
            assert!(dev_target(bad).is_err(), "{bad}");
        }
    }

    fn cfg(base: Option<&str>, dev: bool) -> AdapterConfig {
        AdapterConfig {
            provider: Provider::Anthropic,
            api_key: Zeroizing::new("sk-test".into()),
            base_url: base.map(str::to_owned),
            insecure_dev: dev,
            dev_root: None,
            limits: Limits::default(),
        }
    }

    #[test]
    fn override_needs_dev_flag() {
        assert!(Adapter::new(&cfg(Some("http://127.0.0.1:1"), false)).is_err());
        assert!(Adapter::new(&cfg(Some("http://127.0.0.1:1"), true)).is_ok());
        assert!(Adapter::new(&cfg(Some("http://192.168.1.1:1"), true)).is_err());
        assert!(Adapter::new(&cfg(None, false)).is_ok());
    }

    #[test]
    fn rate_limit_headers() {
        let mut h = HeaderMap::new();
        assert_eq!(RateLimit::from_headers(&h).headroom_pct(), None);
        h.insert("anthropic-ratelimit-requests-limit", HeaderValue::from_static("4000"));
        h.insert("anthropic-ratelimit-requests-remaining", HeaderValue::from_static("1000"));
        let r = RateLimit::from_headers(&h);
        assert_eq!((r.requests_limit, r.requests_remaining, r.headroom_pct()), (Some(4000), Some(1000), Some(25)));
        h.insert("anthropic-ratelimit-tokens-limit", HeaderValue::from_static("2000000"));
        h.insert("anthropic-ratelimit-tokens-remaining", HeaderValue::from_static("200000"));
        assert_eq!(RateLimit::from_headers(&h).headroom_pct(), Some(10), "tighter budget wins");
        let mut o = HeaderMap::new();
        o.insert("x-ratelimit-limit-requests", HeaderValue::from_static("0"));
        o.insert("x-ratelimit-remaining-requests", HeaderValue::from_static("5"));
        assert_eq!(RateLimit::from_headers(&o).headroom_pct(), Some(0), "zero limit = no headroom");
        o.insert("x-ratelimit-limit-requests", HeaderValue::from_static("10"));
        o.insert("x-ratelimit-remaining-requests", HeaderValue::from_static("99"));
        assert_eq!(RateLimit::from_headers(&o).headroom_pct(), Some(100), "clamped");
        o.insert("x-ratelimit-remaining-requests", HeaderValue::from_static("lots"));
        assert_eq!(RateLimit::from_headers(&o).headroom_pct(), None, "unparsable = unknown");
    }

    #[test]
    fn rate_limit_resets() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_ms("2026-10-01T00:00:00Z"), Some(1_790_812_800_000));
        assert_eq!(rfc3339_ms("2026-10-01T02:00:00.5+02:00"), Some(1_790_812_800_500));
        assert_eq!(rfc3339_ms("2000-02-29T12:34:56.789Z"), Some(951_827_696_789));
        for bad in ["2026-13-01T00:00:00Z", "2026-10-01 00:00:00", "garbage", "2026-10-01T00:00:00+0200", "2026-10-01T25:00:00Z"] {
            assert_eq!(rfc3339_ms(bad), None, "{bad}");
        }
        assert_eq!(duration_ms("1s"), Some(1000));
        assert_eq!(duration_ms("6m0s"), Some(360_000));
        assert_eq!(duration_ms("1h2m3.5s"), Some(3_723_500));
        assert_eq!(duration_ms("20ms"), Some(20));
        for bad in ["", "s", "1x", "5"] {
            assert_eq!(duration_ms(bad), None, "{bad}");
        }
        let mut h = HeaderMap::new();
        h.insert("anthropic-ratelimit-requests-reset", HeaderValue::from_static("2026-10-01T00:00:30Z"));
        h.insert("x-ratelimit-reset-tokens", HeaderValue::from_static("1.5s"));
        let r = RateLimit::from_headers_at(&h, 1_790_812_800_000);
        assert_eq!((r.requests_reset_ms, r.tokens_reset_ms), (Some(30_000), Some(1500)));
        assert_eq!(RateLimit::from_headers_at(&h, 1_790_812_900_000).requests_reset_ms, Some(0), "past reset = now");
    }

    #[test]
    fn paths() {
        let full = |p: Provider, d: Dialect| AdapterDef::of(p).path(d).map(|path| format!("https://{}{path}", AdapterDef::of(p).host));
        let a = Dialect::AnthropicMessages;
        let o = Dialect::OpenAiChat;
        let want = [
            (Provider::Anthropic, a, Some("https://api.anthropic.com/v1/messages")),
            (Provider::Anthropic, o, None),
            (Provider::OpenAi, a, None),
            (Provider::OpenAi, o, Some("https://api.openai.com/v1/chat/completions")),
            (Provider::OpenRouter, a, Some("https://openrouter.ai/api/v1/messages")),
            (Provider::OpenRouter, o, Some("https://openrouter.ai/api/v1/chat/completions")),
            (Provider::DeepSeek, a, Some("https://api.deepseek.com/anthropic/v1/messages")),
            (Provider::DeepSeek, o, Some("https://api.deepseek.com/chat/completions")),
            (Provider::XAi, a, None),
            (Provider::XAi, o, Some("https://api.x.ai/v1/chat/completions")),
        ];
        for (p, d, url) in want {
            assert_eq!(full(p, d).as_deref(), url, "{p:?} {d:?}");
            assert_eq!(p.serves(d), url.is_some(), "Provider::serves agrees with the adapter table");
        }
    }
}
