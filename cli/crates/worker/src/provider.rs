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
use std::sync::{Arc, OnceLock};
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

#[derive(Clone, Debug)]
pub struct Failure {
    pub kind: FailKind,
    pub status: Option<u16>,
    pub retry_after_ms: Option<u64>,
    /// The provider's error body (bounded), to seal to the Gateway as the native error.
    pub body: Bytes,
    pub detail: &'static str,
}

impl Failure {
    fn new(kind: FailKind, detail: &'static str) -> Self {
        Self { kind, status: None, retry_after_ms: None, body: Bytes::new(), detail }
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

struct Target {
    tls: bool,
    /// Host to dial (DNS name or IP literal).
    host: String,
    port: u16,
    /// `host[:port]` for the URI authority.
    authority: String,
    /// Path prefix before the per-dialect path (e.g. `/api` for OpenRouter).
    root: String,
}

fn real_target(p: Provider) -> Target {
    let (host, root) = match p {
        Provider::Anthropic => ("api.anthropic.com", ""),
        Provider::OpenAi => ("api.openai.com", ""),
        Provider::OpenRouter => ("openrouter.ai", "/api"),
        Provider::DeepSeek => ("api.deepseek.com", ""),
    };
    Target { tls: true, host: host.to_owned(), port: 443, authority: host.to_owned(), root: root.to_owned() }
}

/// Path below the root. DeepSeek's Anthropic-compatible API lives under `/anthropic`.
fn path(p: Provider, d: Dialect) -> &'static str {
    match (p, d) {
        (Provider::DeepSeek, Dialect::AnthropicMessages) => "/anthropic/v1/messages",
        (_, Dialect::AnthropicMessages) => "/v1/messages",
        (_, Dialect::OpenAiChat) => "/v1/chat/completions",
    }
}

fn dev_target(url: &str) -> Result<Target, ConfigError> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        return Err(ConfigError("base URL must be http:// or https://"));
    };
    if rest.contains(['?', '#', '@', '\\']) || rest.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(ConfigError("base URL must be scheme://loopback-ip[:port][/path]"));
    }
    let (authority, root) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
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
    Ok(Target { tls, host: ip.to_string(), port, authority: authority.to_owned(), root: root.trim_end_matches('/').to_owned() })
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
        Ok(Self { provider: cfg.provider, target, auth_name, auth, tls, h2: Mutex::new(None), limits: cfg.limits })
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Open (or keep) the warm HTTP/2 connection. Call at startup, on key add, and every
    /// minute or so; keep-alive PINGs hold it open in between. No-op for `http://` dev targets.
    pub async fn warm(&self) -> Result<(), Failure> {
        if self.tls.is_some() {
            tokio::time::timeout(self.limits.headers, self.h2_sender()).await.map_err(|_| Failure::new(FailKind::Timeout, "connect timed out"))??;
        }
        Ok(())
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
        if !self.provider.serves(dialect) {
            return Err(Failure::new(FailKind::Unsupported, "dialect not served by this provider"));
        }
        let t = &self.target;
        let scheme = if t.tls { "https" } else { "http" };
        let uri = format!("{scheme}://{}{}{}", t.authority, t.root, path(self.provider, dialect));
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
                let tcp = self.tcp().await?;
                let (mut s, conn) =
                    http1::handshake(TokioIo::new(tcp)).await.map_err(|_| Failure::new(FailKind::Network, "HTTP/1 handshake failed"))?;
                let conn = tokio::spawn(async move {
                    let _ = conn.await;
                });
                let guard = AbortOnDrop(conn);
                let resp = s.send_request(req).await.map_err(|_| Failure::new(FailKind::Network, "request failed before headers"))?;
                Ok((resp, Some(guard)))
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
            requests_remaining: header_u64(&parts.headers, &["anthropic-ratelimit-requests-remaining", "x-ratelimit-remaining-requests"]),
            body,
            idle: Box::pin(tokio::time::sleep(self.limits.idle)),
            deadline: now.checked_add(self.limits.total).unwrap_or(now),
            limits: self.limits,
            read: 0,
            _conn: conn,
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
        Failure { kind, status: Some(status), retry_after_ms, body: Bytes::from(buf), detail: "provider returned an error status" }
    }
}

fn header_str(h: &HeaderMap, names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| h.get(*n)).and_then(|v| v.to_str().ok()).filter(|s| s.len() <= 256).map(str::to_owned)
}

fn header_u64(h: &HeaderMap, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|n| h.get(*n)).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse().ok())
}

struct AbortOnDrop(JoinHandle<()>);

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
    /// Rate-limit headroom (requests remaining), for `worker.offer`.
    pub requests_remaining: Option<u64>,
    body: Incoming,
    idle: Pin<Box<Sleep>>,
    deadline: Instant,
    limits: Limits,
    read: u64,
    _conn: Option<AbortOnDrop>,
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
                None => return Ok(None),
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
        assert_eq!((t.tls, t.host.as_str(), t.port, t.root.as_str()), (false, "127.0.0.1", 8080, ""));
        let t = dev_target("http://[::1]:9/prefix/").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.root.as_str(), t.authority.as_str()), ("::1", 9, "/prefix", "[::1]:9"));
        for bad in [
            "http://localhost:1",
            "http://10.0.0.1:1",
            "http://evil.com",
            "ftp://127.0.0.1",
            "http://127.0.0.1@evil.com",
            "http://127.0.0.1:1?x",
            "http://127.0.0.1:99999",
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
    fn paths() {
        assert_eq!(path(Provider::DeepSeek, Dialect::AnthropicMessages), "/anthropic/v1/messages");
        assert_eq!(path(Provider::OpenRouter, Dialect::OpenAiChat), "/v1/chat/completions");
        assert_eq!(real_target(Provider::OpenRouter).root, "/api");
    }
}
