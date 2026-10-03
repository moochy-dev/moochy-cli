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
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
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
    /// An idle pooled HTTP/1.1 connection older than this is not reused: proxies in front of
    /// GPU hosts (RunPod, Cloudflare: ~100 s) drop idle keep-alive connections silently.
    pub pool_idle: Duration,
}

impl Limits {
    /// For [`Provider::Local`]: a local server may load the model on the first request and
    /// process a long prompt before the first byte (headers 300 s, idle 300 s).
    pub fn local() -> Self {
        Self { headers: Duration::from_secs(300), idle: Duration::from_secs(300), ..Self::default() }
    }
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
            pool_idle: Duration::from_secs(60),
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
    /// The provider's error body (bounded). Stays on the donor's machine (A291: a provider may
    /// echo the API key in it); the requester gets [`Failure::public_message`].
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

impl Failure {
    /// What the requester is told (CONTRACT §23, A291): our own words from the kind and the
    /// HTTP status, never the provider's error text. A context-window overflow keeps the wording
    /// agents react to ("prompt is too long").
    pub fn public_message(&self) -> String {
        let what = match self.kind {
            FailKind::RateLimited => "the donor's provider is rate limiting this key",
            FailKind::Overloaded => "the donor's provider is overloaded",
            FailKind::Auth => "the donor's provider refused the donor's API key",
            FailKind::ModelUnavailable => "the donor's provider does not serve this model",
            FailKind::InvalidRequest if context_overflow(&self.body) => "prompt is too long: the request exceeds the model's context window",
            FailKind::InvalidRequest => "the donor's provider refused the request as invalid",
            FailKind::TooLarge => "the request is too large for the donor's provider",
            FailKind::ProviderError | FailKind::Network | FailKind::Timeout | FailKind::Unsupported => self.detail,
        };
        match self.status {
            Some(st) => format!("{what} (HTTP {st})"),
            None => what.to_owned(),
        }
    }
}

/// Does a provider error body say the prompt overflows the context window? Matched on fixed
/// phrases only; nothing of the body is copied.
fn context_overflow(body: &[u8]) -> bool {
    const PHRASES: [&[u8]; 5] = [b"prompt is too long", b"context_length_exceeded", b"maximum context length", b"context window", b"too many tokens"];
    let lower: Vec<u8> = body.iter().take(64 << 10).map(u8::to_ascii_lowercase).collect();
    PHRASES.iter().any(|p| lower.windows(p.len()).any(|w| w == *p))
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
    /// OpenAI Responses endpoint path, if the provider speaks it natively (§18.6).
    pub responses: Option<&'static str>,
}

impl AdapterDef {
    pub const fn of(p: Provider) -> Self {
        match p {
            Provider::Anthropic => Self { host: "api.anthropic.com", messages: Some("/v1/messages"), chat: None, responses: None },
            Provider::OpenAi => Self { host: "api.openai.com", messages: None, chat: Some("/v1/chat/completions"), responses: Some("/v1/responses") },
            // OpenAI-compatible root `https://openrouter.ai/api/v1`; Anthropic-compatible root
            // `https://openrouter.ai/api` (+ `/v1/messages`).
            Provider::OpenRouter => {
                Self { host: "openrouter.ai", messages: Some("/api/v1/messages"), chat: Some("/api/v1/chat/completions"), responses: Some("/api/v1/responses") }
            }
            // OpenAI-compatible root `https://api.deepseek.com`; Anthropic-compatible root
            // `https://api.deepseek.com/anthropic` (+ `/v1/messages`).
            Provider::DeepSeek => {
                Self { host: "api.deepseek.com", messages: Some("/anthropic/v1/messages"), chat: Some("/chat/completions"), responses: None }
            }
            // OpenAI-compatible root `https://api.x.ai/v1` (global endpoint; the US regional
            // host costs +10% and is not allowlisted). No Anthropic-compatible endpoint.
            Provider::XAi => Self { host: "api.x.ai", messages: None, chat: Some("/v1/chat/completions"), responses: Some("/v1/responses") },
            // The donor's own server (Ollama :11434, LM Studio :1234, vLLM :8000, llama.cpp
            // :8080): no official host; the base URL comes from `check_local_base_url`.
            Provider::Local => Self { host: "", messages: None, chat: Some("/v1/chat/completions"), responses: None },
        }
    }

    pub const fn path(&self, d: Dialect) -> Option<&'static str> {
        match d {
            Dialect::AnthropicMessages => self.messages,
            Dialect::OpenAiChat => self.chat,
            Dialect::OpenAiResponses => self.responses,
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
    /// Remote local server (§17.3): resolve here, refuse unless every address is public, and
    /// dial that exact address (no second lookup an attacker could rebind).
    public_only: bool,
}

fn real_target(p: Provider) -> Target {
    let host = AdapterDef::of(p).host;
    Target { tls: true, host: host.to_owned(), port: 443, authority: host.to_owned(), public_only: false }
}

/// `scheme://host[:port][/]`: an origin only (a path is refused rather than interpreted:
/// the adapter owns the paths).
struct Origin<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    authority: &'a str,
}

fn parse_origin(url: &str) -> Result<Origin<'_>, ConfigError> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        return Err(ConfigError("base URL must be http:// or https://"));
    };
    if rest.contains(['?', '#', '@', '\\']) || rest.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(ConfigError("base URL must be scheme://host[:port]"));
    }
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains('/') {
        return Err(ConfigError("base URL must be an origin (scheme://host[:port]); request paths are fixed per adapter"));
    }
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let (h, p) = r.split_once(']').ok_or(ConfigError("bad IPv6 literal"))?;
        if !(p.is_empty() || p.starts_with(':')) {
            return Err(ConfigError("bad IPv6 literal"));
        }
        (h, p.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(ConfigError("base URL has no host"));
    }
    let port = match port {
        Some(p) => p.parse().ok().filter(|p| *p != 0).ok_or(ConfigError("bad port"))?,
        None if tls => 443,
        None => 80,
    };
    Ok(Origin { tls, host, port, authority })
}

/// Parse a dev base URL for a hosted provider: loopback IP literals only (CONTRACT §6).
fn dev_target(url: &str) -> Result<Target, ConfigError> {
    let o = parse_origin(url)?;
    let ip: IpAddr = o.host.parse().map_err(|_| ConfigError("base URL host must be a loopback IP literal"))?;
    if !ip.is_loopback() {
        return Err(ConfigError("base URL host must be loopback"));
    }
    Ok(Target { tls: o.tls, host: ip.to_string(), port: o.port, authority: o.authority.to_owned(), public_only: false })
}

/// Where a local inference server may live. Vetted: loopback, private LAN (RFC 1918, IPv6
/// ULA) and CGNAT/Tailscale (100.64.0.0/10) IP literals, over http or https. A donor's own GPU
/// box elsewhere (RunPod, Vast, Lambda: CONTRACT §17.3) only over https and only when its exact
/// `host:port` is on the donor's vetted list ([`LocalOptions::vetted_hosts`]). Never:
/// link-local (cloud metadata 169.254.169.254, fe80::/10), unspecified, multicast, broadcast,
/// plain HTTP off the LAN. `allow_unvetted_host` (`--allow-unvetted-host`, dev) skips the list,
/// not the https rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalHost {
    Loopback,
    Lan,
    /// A remote TLS server on the donor's vetted list.
    Remote,
    Unvetted,
}

/// How a remote (or LAN https) local server's certificate is checked.
#[derive(Clone, Debug, Default)]
pub enum RemoteTrust {
    /// Mozilla roots (webpki-roots) and the host name.
    #[default]
    Roots,
    /// Only this CA (DER), and the host name: a self-signed CA on the GPU box.
    Ca(CertificateDer<'static>),
    /// Exactly this end-entity certificate: SHA-256 of its DER (no CA, no name check).
    Fingerprint([u8; 32]),
}

/// Options of a [`Provider::Local`] adapter (`moochy keys add local --url …`).
#[derive(Default)]
pub struct LocalOptions {
    /// Dev only: hosts off the vetted list (still https-only off the LAN).
    pub allow_unvetted_host: bool,
    /// Remote servers the donor vetted, each exactly as [`remote_host_key`] returns it.
    pub vetted_hosts: Vec<String>,
    /// Auth header from the keystore: `(name, value)`, the value a secret (never logged). Takes
    /// the place of the API key (`Authorization: Bearer …`).
    pub auth_header: Option<(String, Zeroizing<String>)>,
    pub trust: RemoteTrust,
}

impl std::fmt::Debug for LocalOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalOptions")
            .field("allow_unvetted_host", &self.allow_unvetted_host)
            .field("vetted_hosts", &self.vetted_hosts)
            .field("auth_header", &self.auth_header.as_ref().map(|(n, _)| n))
            .field("trust", &self.trust)
            .finish()
    }
}

fn vet_ip(ip: IpAddr) -> Result<LocalHost, ConfigError> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(ConfigError("local host must not be unspecified or multicast"));
    }
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_link_local() || v4.is_broadcast() {
                return Err(ConfigError("local host must not be link-local (cloud metadata) or broadcast"));
            }
            if v4.is_loopback() {
                Ok(LocalHost::Loopback)
            } else if v4.is_private() || (a == 100 && (64..=127).contains(&b)) {
                Ok(LocalHost::Lan)
            } else {
                Ok(LocalHost::Unvetted)
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments().first().copied().unwrap_or(0);
            if first & 0xffc0 == 0xfe80 {
                return Err(ConfigError("local host must not be link-local"));
            }
            if v6.is_loopback() {
                Ok(LocalHost::Loopback)
            } else if first & 0xfe00 == 0xfc00 {
                Ok(LocalHost::Lan)
            } else {
                Ok(LocalHost::Unvetted)
            }
        }
    }
}

/// A DNS host name, lowercased: ASCII labels `[a-z0-9-]`, no empty label (no trailing dot), no
/// numeric last label (`2130706433`, `127.1`, `0x7f.1` are IPv4 in other parsers), ≤ 253 bytes.
fn dns_name(host: &str) -> Result<String, ConfigError> {
    let h = host.to_ascii_lowercase();
    let label_ok = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let last = h.rsplit('.').next().unwrap_or("");
    if h.len() > 253 || !h.split('.').all(label_ok) || last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return Err(ConfigError("local host must be an IP literal or a DNS name"));
    }
    Ok(h)
}

/// `host:port` (IPv6 in brackets, port always explicit) of a remote server URL: the exact entry
/// to store in [`LocalOptions::vetted_hosts`] once the donor confirmed it. https only; loopback
/// and LAN addresses need no vetting and are refused here.
pub fn remote_host_key(url: &str) -> Result<String, ConfigError> {
    let o = parse_origin(url)?;
    if !o.tls {
        return Err(ConfigError("a remote model server needs https:// (plain HTTP is refused off the LAN)"));
    }
    let host = match o.host.parse::<IpAddr>() {
        Ok(ip) if vet_ip(ip)? == LocalHost::Unvetted => ip.to_string(),
        Ok(_) => return Err(ConfigError("loopback and LAN servers need no vetting")),
        Err(_) => dns_name(o.host)?,
    };
    Ok(host_key(&host, o.port))
}

fn host_key(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// Vet a local inference server's base URL (`moochy keys add local --base-url …`) with no
/// vetted remote hosts: returns its class, or why it is refused.
pub fn check_local_base_url(url: &str, allow_unvetted_host: bool) -> Result<LocalHost, ConfigError> {
    check_local_url(url, &LocalOptions { allow_unvetted_host, ..LocalOptions::default() })
}

/// Vet a local server URL against the donor's options (§17.3): its class, or why it is refused.
/// Origin only; the path is always `/v1/chat/completions`.
pub fn check_local_url(url: &str, opts: &LocalOptions) -> Result<LocalHost, ConfigError> {
    local_target(url, opts).map(|(_, c)| c)
}

fn local_target(url: &str, opts: &LocalOptions) -> Result<(Target, LocalHost), ConfigError> {
    let o = parse_origin(url)?;
    let (host, class) = match o.host.parse::<IpAddr>() {
        Ok(ip) => (ip.to_string(), vet_ip(ip)?),
        Err(_) => (dns_name(o.host)?, LocalHost::Unvetted),
    };
    let class = if class == LocalHost::Unvetted {
        if !o.tls {
            return Err(ConfigError("a remote model server needs https:// (plain HTTP is refused off the LAN)"));
        }
        let key = host_key(&host, o.port);
        if opts.vetted_hosts.contains(&key) {
            LocalHost::Remote
        } else if opts.allow_unvetted_host {
            LocalHost::Unvetted
        } else {
            return Err(ConfigError("remote model server is not on your vetted host list (moochy keys add local --url https://…)"));
        }
    } else {
        class
    };
    let public_only = matches!(class, LocalHost::Remote | LocalHost::Unvetted);
    let authority = o.authority.to_ascii_lowercase();
    Ok((Target { tls: o.tls, host, port: o.port, authority, public_only }, class))
}

/// Resolve a remote host and refuse unless every address is public (DNS rebinding to loopback,
/// LAN, link-local or metadata addresses); the caller dials the returned address itself.
async fn resolve_public(host: &str, port: u16) -> Result<std::net::SocketAddr, Failure> {
    #[cfg(test)]
    if let Some((ips, public)) = test_dns::lookup(host) {
        let first = ips.first().copied().ok_or(Failure::new(FailKind::Network, "DNS lookup returned nothing"))?;
        if public {
            return Ok(std::net::SocketAddr::new(first, port));
        }
        return check_public(&ips.into_iter().map(|ip| std::net::SocketAddr::new(ip, port)).collect::<Vec<_>>());
    }
    let addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host((host, port)).await.map_err(|_| Failure::new(FailKind::Network, "DNS lookup failed"))?.take(16).collect();
    check_public(&addrs)
}

fn check_public(addrs: &[std::net::SocketAddr]) -> Result<std::net::SocketAddr, Failure> {
    let first = addrs.first().copied().ok_or(Failure::new(FailKind::Network, "DNS lookup returned nothing"))?;
    if addrs.iter().any(|a| vet_ip(a.ip()) != Ok(LocalHost::Unvetted)) {
        return Err(Failure::new(FailKind::Network, "remote model server resolves to a loopback, private or link-local address (refused: DNS rebinding)"));
    }
    Ok(first)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod test_dns {
    use std::net::IpAddr;
    use std::sync::Mutex;

    /// Test-only resolver entries: name → addresses, and whether to treat them as public (to
    /// reach a loopback fake under a vetted remote name).
    static ENTRIES: Mutex<Vec<(String, Vec<IpAddr>, bool)>> = Mutex::new(Vec::new());

    pub fn set(name: &str, ips: Vec<IpAddr>, public: bool) {
        ENTRIES.lock().unwrap().push((name.to_owned(), ips, public));
    }

    pub fn lookup(name: &str) -> Option<(Vec<IpAddr>, bool)> {
        ENTRIES.lock().unwrap().iter().find(|e| e.0 == name).map(|e| (e.1.clone(), e.2))
    }
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

/// TLS to a local server (§17.3): HTTP/1.1 only, certificate per [`RemoteTrust`].
fn local_tls_config(trust: &RemoteTrust) -> Result<Arc<rustls::ClientConfig>, ConfigError> {
    let fail = |_| ConfigError("TLS configuration failed");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(fail)?;
    let mut cfg = match trust {
        RemoteTrust::Roots => builder.with_root_certificates(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }).with_no_client_auth(),
        RemoteTrust::Ca(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.clone()).map_err(|_| ConfigError("pinned CA is not a valid certificate"))?;
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        RemoteTrust::Fingerprint(fp) => builder.dangerous().with_custom_certificate_verifier(Arc::new(PinnedCert { sha256: *fp, provider })).with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// [`RemoteTrust::Fingerprint`]: the server must present exactly this certificate (SHA-256 of
/// its DER) and prove it holds the key (handshake signatures are verified as usual).
#[derive(Debug)]
struct PinnedCert {
    sha256: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got = ring::digest::digest(&ring::digest::SHA256, end_entity);
        if got.as_ref() == self.sha256.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The header that carries a local server's credential (`authorization`, `x-api-key`, …):
/// lowercase token, never one that frames or routes the request.
fn auth_header_name(name: &str) -> Result<HeaderName, ConfigError> {
    const FRAMING: &[&str] = &[
        "host", "content-length", "content-type", "content-encoding", "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade", "expect",
        "user-agent", "accept-encoding", "cookie", "forwarded", "via",
    ];
    let ok = !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !name.starts_with("proxy-") && !name.starts_with("x-forwarded-") && !FRAMING.contains(&name);
    if !ok {
        return Err(ConfigError("auth header name must be a lowercase token such as authorization or x-api-key"));
    }
    HeaderName::from_bytes(name.as_bytes()).map_err(|_| ConfigError("bad auth header name"))
}

type H2 = http2::SendRequest<Full<Bytes>>;

/// One provider key. Cheap to share (`Arc<Adapter>`); all requests multiplex on one warm
/// HTTP/2 connection, re-dialed transparently when it dies.
pub struct Adapter {
    provider: Provider,
    target: Target,
    auth_name: HeaderName,
    auth: Option<HeaderValue>,
    tls: Option<TlsConnector>,
    /// Hosted providers: one warm HTTP/2 connection. Local servers (also over TLS): HTTP/1.1.
    use_h2: bool,
    h2: Mutex<Option<H2>>,
    /// Idle HTTP/1.1 keep-alive connections (`http://` loopback dev targets only).
    h1_idle: Arc<StdMutex<Vec<H1Conn>>>,
    limits: Limits,
    /// This adapter's key (or auth header value) in every form a provider could echo (A291).
    redactor: crate::redact::Redactor,
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adapter").field("provider", &self.provider).field("authority", &self.target.authority).finish_non_exhaustive()
    }
}

impl Adapter {
    pub fn new(cfg: &AdapterConfig) -> Result<Self, ConfigError> {
        Self::build(cfg, &LocalOptions::default())
    }

    /// [`Adapter::new`] for [`Provider::Local`] with the dev-only `--allow-unvetted-host`
    /// switch (public IPs and host names; the node prints a warning at every start).
    pub fn new_local(cfg: &AdapterConfig, allow_unvetted_host: bool) -> Result<Self, ConfigError> {
        Self::build(cfg, &LocalOptions { allow_unvetted_host, ..LocalOptions::default() })
    }

    /// [`Provider::Local`] with the donor's options (§17.3): vetted remote hosts, an auth header
    /// from the keystore, how to check the server's certificate.
    pub fn new_local_with(cfg: &AdapterConfig, opts: &LocalOptions) -> Result<Self, ConfigError> {
        Self::build(cfg, opts)
    }

    fn build(cfg: &AdapterConfig, opts: &LocalOptions) -> Result<Self, ConfigError> {
        let local = cfg.provider == Provider::Local;
        if !local && (opts.auth_header.is_some() || !matches!(opts.trust, RemoteTrust::Roots) || !opts.vetted_hosts.is_empty()) {
            return Err(ConfigError("local server options are for the local provider only"));
        }
        let target = match &cfg.base_url {
            None if local => return Err(ConfigError("a local provider needs its server's base URL")),
            Some(u) if local => local_target(u, opts)?.0,
            None => real_target(cfg.provider),
            Some(_) if !cfg.insecure_dev => return Err(ConfigError("base URL override needs MOOCHY_INSECURE_DEV=1")),
            Some(u) => dev_target(u)?,
        };
        if cfg.dev_root.is_some() && !(cfg.insecure_dev && cfg.base_url.is_some()) {
            return Err(ConfigError("a dev trust root is only accepted with a loopback dev base URL"));
        }
        let key = cfg.api_key.trim();
        let header_secret = opts.auth_header.as_ref().map_or(&b""[..], |(_, v)| v.as_bytes());
        let redactor = crate::redact::Redactor::new(&[key.as_bytes(), header_secret]);
        let mut auth_name = HeaderName::from_static(if cfg.provider == Provider::Anthropic { "x-api-key" } else { "authorization" });
        // Local servers usually take no key (Ollama/LM Studio ignore it): empty = no auth header.
        let auth = if let Some((name, value)) = &opts.auth_header {
            if !key.is_empty() {
                return Err(ConfigError("give either an API key or an auth header, not both"));
            }
            auth_name = auth_header_name(name)?;
            if value.is_empty() || value.len() > 4096 || !value.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
                return Err(ConfigError("auth header value must be 1..4096 visible ASCII characters"));
            }
            let mut v = HeaderValue::from_str(value).map_err(|_| ConfigError("auth header value is not a valid header value"))?;
            v.set_sensitive(true);
            Some(v)
        } else if local && key.is_empty() {
            None
        } else {
            if key.is_empty() || key.len() > 512 || !key.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(ConfigError("API key must be 1..512 visible ASCII characters"));
            }
            let value = match cfg.provider {
                Provider::Anthropic => Zeroizing::new(key.to_owned()),
                _ => Zeroizing::new(format!("Bearer {key}")),
            };
            // ponytail: the HeaderValue copy cannot be zeroized (http crate); it lives as long as the adapter.
            let mut v = HeaderValue::from_str(&value).map_err(|_| ConfigError("API key is not a valid header value"))?;
            v.set_sensitive(true);
            Some(v)
        };
        if local && cfg.dev_root.is_some() {
            return Err(ConfigError("a local server's certificate is checked per LocalOptions::trust"));
        }
        let tls = match (target.tls, local) {
            (false, _) => None,
            (true, false) => Some(TlsConnector::from(tls_config(cfg.dev_root.as_ref())?)),
            (true, true) => Some(TlsConnector::from(local_tls_config(&opts.trust)?)),
        };
        let use_h2 = target.tls && !local;
        Ok(Self { provider: cfg.provider, target, auth_name, auth, tls, use_h2, h2: Mutex::new(None), h1_idle: Arc::default(), limits: cfg.limits, redactor })
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Hides this adapter's key in anything that leaves the donor's machine (A291).
    pub fn redactor(&self) -> &crate::redact::Redactor {
        &self.redactor
    }

    /// Open (or keep) the warm HTTP/2 connection. Call at startup, on key add, and every
    /// minute or so; keep-alive PINGs hold it open in between. No-op for `http://` dev targets.
    pub async fn warm(&self) -> Result<(), Failure> {
        let warm = async {
            if self.use_h2 {
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
        self.h1_idle.lock().map_or(0, |g| g.iter().filter(|c| !c.is_dead()).count())
    }

    fn h1_return(&self, c: H1Conn) {
        return_h1(&self.h1_idle, c);
    }

    async fn dial_h1(&self) -> Result<H1Conn, Failure> {
        let tcp = self.tcp().await?;
        let io: Box<dyn Io> = match &self.tls {
            Some(tls) => Box::new(self.tls_handshake(tls, tcp).await?),
            None => Box::new(tcp),
        };
        let (sender, conn) =
            http1::handshake(TokioIo::new(io)).await.map_err(|_| Failure::new(FailKind::Network, "HTTP/1 handshake failed"))?;
        Ok(H1Conn { sender, conn: Some(conn), idle_since: None })
    }

    /// An idle keep-alive connection that is still usable, else a fresh one.
    async fn h1_conn(&self) -> Result<(H1Conn, bool), Failure> {
        loop {
            let idle = self.h1_idle.lock().ok().and_then(|mut g| g.pop());
            let Some(mut c) = idle else { break };
            if c.idle_since.is_some_and(|t| t.elapsed() > self.limits.pool_idle) {
                continue; // likely cut by a proxy in between: dropping it closes our end
            }
            // An idle connection is not driven: one poll lets it notice a server close.
            c.drive(&mut Context::from_waker(Waker::noop()));
            if c.is_dead() {
                continue;
            }
            let H1Conn { sender, conn, .. } = &mut c;
            if drive(conn, sender.ready()).await.is_ok() {
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
        let connect = async {
            if t.public_only {
                TcpStream::connect(resolve_public(&t.host, t.port).await?).await
            } else {
                TcpStream::connect((t.host.as_str(), t.port)).await
            }
            .map_err(|_| Failure::new(FailKind::Network, "TCP connect failed"))
        };
        let tcp = tokio::time::timeout(self.limits.connect, connect)
            .await
            .map_err(|_| Failure::new(FailKind::Timeout, "TCP connect timed out"))??;
        tcp.set_nodelay(true).map_err(|_| Failure::new(FailKind::Network, "TCP_NODELAY failed"))?;
        Ok(tcp)
    }

    async fn dial_h2(&self) -> Result<H2, Failure> {
        let Some(tls) = &self.tls else {
            return Err(Failure::new(FailKind::Unsupported, "no TLS for this target"));
        };
        let tcp = self.tcp().await?;
        let stream = self.tls_handshake(tls, tcp).await?;
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

    async fn tls_handshake(&self, tls: &TlsConnector, tcp: TcpStream) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Failure> {
        let name = ServerName::try_from(self.target.host.clone()).map_err(|_| Failure::new(FailKind::Network, "bad TLS server name"))?;
        tokio::time::timeout(self.limits.connect, tls.connect(name, tcp))
            .await
            .map_err(|_| Failure::new(FailKind::Timeout, "TLS handshake timed out"))?
            .map_err(|_| Failure::new(FailKind::Network, "TLS handshake failed (certificate not trusted?)"))
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
        let uri = if self.use_h2 {
            format!("https://{}{path}", t.authority)
        } else {
            path.to_owned()
        };
        let mut b = hyper::Request::post(uri)
            .header("content-type", "application/json")
            .header("user-agent", USER_AGENT);
        if let Some(a) = &self.auth {
            b = b.header(&self.auth_name, a.clone());
        }
        if !self.use_h2 {
            b = b.header("host", t.authority.as_str());
        }
        for (k, v) in headers {
            b = b.header(*k, HeaderValue::from_str(v).map_err(|_| Failure::new(FailKind::InvalidRequest, "bad header value"))?);
        }
        let req = b.body(Full::new(body)).map_err(|_| Failure::new(FailKind::InvalidRequest, "bad request"))?;

        let fut = async {
            if self.use_h2 {
                let mut s = self.h2_sender().await?;
                s.ready().await.map_err(|_| Failure::new(FailKind::Network, "HTTP/2 connection lost"))?;
                let resp = s.send_request(req).await.map_err(|_| Failure::new(FailKind::Network, "request failed before headers"))?;
                Ok::<_, Failure>((resp, None))
            } else {
                // Keep-alive pool, like production's warm h2 connection. A request is retried
                // on a fresh connection only when hyper proves it was never sent (a reused
                // connection closed by the server in between): no double execution.
                let (mut c, reused) = self.h1_conn().await?;
                let sent = c.sender.try_send_request(req);
                let resp = match drive(&mut c.conn, sent).await {
                    Ok(r) => r,
                    Err(mut e) => match e.take_message() {
                        Some(req) if reused => {
                            c = self.dial_h1().await?;
                            let sent = c.sender.send_request(req);
                            drive(&mut c.conn, sent).await.map_err(|_| Failure::new(FailKind::Network, "request failed before headers"))?
                        }
                        _ => return Err(Failure::new(FailKind::Network, "request failed before headers")),
                    },
                };
                Ok((resp, Some(H1Lease { conn: Some(c), pool: self.h1_idle.clone(), reusable: false })))
            }
        };
        let (resp, mut conn) =
            tokio::time::timeout(self.limits.headers, fut).await.map_err(|_| Failure::new(FailKind::Timeout, "no response headers in time"))??;
        let (parts, body) = resp.into_parts();
        let status = parts.status.as_u16();
        if !parts.status.is_success() {
            return Err(self.error(status, &parts.headers, body, conn.as_mut().and_then(|l| l.conn.as_mut())).await);
        }
        let now = Instant::now();
        Ok(Response {
            status,
            request_id: header_str(&parts.headers, &["request-id", "x-request-id"]),
            rate_limit: RateLimit::from_headers(&parts.headers),
            body,
            idle: Box::pin(tokio::time::sleep_until(now.checked_add(self.limits.idle).unwrap_or(now).min(now.checked_add(self.limits.total).unwrap_or(now)))),
            deadline: now.checked_add(self.limits.total).unwrap_or(now),
            last: now,
            limits: self.limits,
            read: 0,
            lease: conn,
            ended: None,
            handed: false,
        })
    }

    async fn error(&self, status: u16, headers: &HeaderMap, mut body: Incoming, mut conn: Option<&mut H1Conn>) -> Failure {
        let kind = match status {
            429 => FailKind::RateLimited,
            // 520/521/523: a Cloudflare-fronted GPU proxy (RunPod) cannot reach the origin.
            503 | 529 | 520 | 521 | 523 => FailKind::Overloaded,
            401 | 403 => FailKind::Auth,
            404 => FailKind::ModelUnavailable,
            // 522/524: the proxy timed out waiting for the origin.
            522 | 524 => FailKind::Timeout,
            400..=499 if status != 408 => FailKind::InvalidRequest,
            _ => FailKind::ProviderError,
        };
        let mut buf = Vec::new();
        let cap = self.limits.max_error_body;
        let read = async {
            while let Some(Ok(f)) = poll_fn(|cx| poll_body(&mut body, conn.as_deref_mut(), cx)).await {
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
            detail: if matches!(status, 522 | 524) {
                "the server's proxy timed out before the first byte (RunPod-style proxies cut at ~100 s): use streaming requests"
            } else {
                "provider returned an error status"
            },
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

/// Most idle keep-alive connections kept per adapter (`http://` targets).
const H1_MAX_IDLE: usize = 16;

/// A plain or TLS byte stream (local servers speak HTTP/1.1 over either).
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Io for T {}

type H1Driver = http1::Connection<TokioIo<Box<dyn Io>>, Full<Bytes>>;

/// An HTTP/1.1 connection driven from the task that uses it (no connection task): a body
/// chunk reaches the reader without a cross-thread wake, and every chunk already in the
/// read buffer is taken in the same poll. Dropping it closes the socket (cancellation).
struct H1Conn {
    sender: http1::SendRequest<Full<Bytes>>,
    /// `None` once the connection has finished.
    conn: Option<H1Driver>,
    /// When it was returned to the pool.
    idle_since: Option<Instant>,
}

impl H1Conn {
    fn drive(&mut self, cx: &mut Context<'_>) {
        drive_conn(&mut self.conn, cx);
    }

    fn is_dead(&self) -> bool {
        self.conn.is_none() || self.sender.is_closed()
    }
}

fn drive_conn(conn: &mut Option<H1Driver>, cx: &mut Context<'_>) {
    if let Some(c) = conn
        && Pin::new(c).poll(cx).is_ready()
    {
        *conn = None;
    }
}

/// Await `f` while driving the connection it depends on.
async fn drive<F: Future>(conn: &mut Option<H1Driver>, f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    poll_fn(|cx| {
        if let Poll::Ready(v) = f.as_mut().poll(cx) {
            return Poll::Ready(v);
        }
        drive_conn(conn, cx);
        f.as_mut().poll(cx)
    })
    .await
}

/// Next body frame, driving the HTTP/1.1 connection (if any) in this task.
fn poll_body(body: &mut Incoming, conn: Option<&mut H1Conn>, cx: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
    if let Poll::Ready(f) = Pin::new(&mut *body).poll_frame(cx) {
        return Poll::Ready(f);
    }
    let Some(c) = conn else { return Poll::Pending };
    c.drive(cx);
    Pin::new(body).poll_frame(cx)
}

fn return_h1(pool: &StdMutex<Vec<H1Conn>>, mut c: H1Conn) {
    if c.is_dead() {
        return;
    }
    c.idle_since = Some(Instant::now());
    if let Ok(mut g) = pool.lock() {
        g.retain(|c| !c.is_dead());
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

/// Largest run of already-received body frames merged into one chunk.
const COALESCE_MAX: usize = 16 << 10;
/// Most frames merged into one chunk. Unbounded, the merge loop chases a burst (each extra
/// frame may cost a socket read) and holds the first frame back; one frame per chunk costs a
/// link message per event downstream. Measured on E22-style bursts (interleaved A/B, dev box):
/// 4 gives the lowest per-chunk p50 end to end (cap 1 / 2 / unbounded were all slower).
const MERGE_MAX_FRAMES: u32 = 4;

/// How a body ended, kept while a merged chunk in front of it is handed out first.
#[derive(Debug, Clone, Copy)]
enum Ended {
    Clean,
    Broken,
    TooLarge,
}

/// A streaming 2xx response. Dropping it aborts the provider request immediately.
pub struct Response {
    pub status: u16,
    /// Provider request id header, if any (else use [`crate::stream::Outcome::id`]).
    pub request_id: Option<String>,
    /// Rate-limit headers of this response (`rate_limit.headroom_pct()` → `rl_headroom`).
    pub rate_limit: RateLimit,
    body: Incoming,
    /// Fires at the earliest possible stall; re-armed from `last` only when it fires, so the
    /// per-chunk path never touches the timer wheel.
    idle: Pin<Box<Sleep>>,
    deadline: Instant,
    /// When body bytes last arrived.
    last: Instant,
    limits: Limits,
    read: u64,
    /// HTTP/1.1 connection, returned to the keep-alive pool only after the body ended.
    lease: Option<H1Lease>,
    /// End of body seen behind the chunk handed out last.
    ended: Option<Ended>,
    /// A chunk was handed out by the previous call.
    handed: bool,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response").field("status", &self.status).field("read", &self.read).finish_non_exhaustive()
    }
}

impl Response {
    /// Next body bytes, `None` at the end. Never waits to batch: it returns as soon as one
    /// frame is there, merged with the frames already received (at most 4 frames, 16 KiB), so
    /// a burst costs one chunk downstream instead of one per frame. Enforces the idle
    /// timeout, the total deadline and the size cap.
    pub async fn next(&mut self) -> Result<Option<Bytes>, Failure> {
        if std::mem::take(&mut self.handed) {
            // The caller just passed the previous chunk to another task (the link writer),
            // which tokio parks in this worker's LIFO slot: let it run before reading more,
            // or a burst is read and sealed in full before its first byte is written.
            tokio::task::yield_now().await;
        }
        if self.ended.is_none() {
            let Self { body, idle, deadline, last, limits, read, lease, ended, .. } = self;
            let mut conn = lease.as_mut().and_then(|l| l.conn.as_mut());
            let mut first: Option<Bytes> = None;
            let mut merged: Option<BytesMut> = None;
            let mut frames = 0u32;
            let polled = poll_fn(|cx| {
                loop {
                    let have = first.is_some();
                    match poll_body(body, conn.as_deref_mut(), cx) {
                        Poll::Ready(Some(Ok(f))) => {
                            let Ok(data) = f.into_data() else { continue };
                            if data.is_empty() {
                                continue;
                            }
                            *read = read.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
                            if *read > limits.max_response {
                                *ended = Some(Ended::TooLarge);
                                return Poll::Ready(Ok(()));
                            }
                            let total = match (&first, &mut merged) {
                                (None, _) => {
                                    let n = data.len();
                                    first = Some(data);
                                    n
                                }
                                (Some(a), None) => {
                                    let mut m = BytesMut::with_capacity(a.len().saturating_add(data.len()));
                                    m.extend_from_slice(a);
                                    m.extend_from_slice(&data);
                                    let n = m.len();
                                    merged = Some(m);
                                    n
                                }
                                (Some(_), Some(m)) => {
                                    m.extend_from_slice(&data);
                                    m.len()
                                }
                            };
                            frames = frames.saturating_add(1);
                            if total >= COALESCE_MAX || frames >= MERGE_MAX_FRAMES {
                                return Poll::Ready(Ok(()));
                            }
                        }
                        Poll::Ready(Some(Err(_))) => {
                            *ended = Some(Ended::Broken);
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(None) => {
                            *ended = Some(Ended::Clean);
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Pending if have => return Poll::Ready(Ok(())),
                        Poll::Pending => {
                            if idle.as_mut().poll(cx).is_pending() {
                                return Poll::Pending;
                            }
                            let due = last.checked_add(limits.idle).unwrap_or(*last).min(*deadline);
                            if Instant::now() >= due {
                                return Poll::Ready(Err(()));
                            }
                            idle.as_mut().reset(due);
                        }
                    }
                }
            })
            .await;
            if polled.is_err() {
                return Err(Failure::new(FailKind::Timeout, "provider stream stalled"));
            }
            if let Some(data) = merged.map(BytesMut::freeze).or(first) {
                self.last = Instant::now();
                self.handed = true;
                return Ok(Some(data));
            }
        }
        match self.ended {
            Some(Ended::Broken) => Err(Failure::new(FailKind::Network, "provider stream broke")),
            Some(Ended::TooLarge) => Err(Failure::new(FailKind::TooLarge, "provider response too large")),
            _ => {
                if let Some(l) = &mut self.lease {
                    l.reusable = true;
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::too_many_lines)]
mod tests {
    use super::*;

    // ---- §17.3 remote local servers over TLS ------------------------------------------------

    const SSE_OK: &str = "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n";

    struct TlsFake {
        port: u16,
        ca: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        heads: tokio::sync::mpsc::UnboundedReceiver<String>,
    }

    /// HTTP/1.1-over-TLS fake with a certificate for `names` from its own CA; answers every
    /// request with `resp` (a whole raw response) and reports each request head.
    async fn tls_fake(names: &[&str], resp: &'static str) -> TlsFake {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap().signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, heads) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else { return };
                    let mut buf = Vec::new();
                    let mut b = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&b[..n]),
                        }
                    }
                    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    let len: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    while buf.len() < end + 4 + len {
                        match tls.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&b[..n]),
                        }
                    }
                    let _ = tx.send(head);
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        TlsFake { port, ca: ca.der().clone(), leaf: leaf.der().clone(), heads }
    }

    fn ok_response() -> &'static str {
        static R: OnceLock<String> = OnceLock::new();
        R.get_or_init(|| format!("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{SSE_OK}", SSE_OK.len()))
    }

    fn local_cfg(url: String) -> AdapterConfig {
        AdapterConfig { provider: Provider::Local, api_key: Zeroizing::new(String::new()), base_url: Some(url), insecure_dev: false, dev_root: None, limits: Limits::local() }
    }

    const BODY: &[u8] = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;

    async fn call(a: &Adapter) -> Result<Vec<u8>, Failure> {
        let mut r = a.send(Dialect::OpenAiChat, Bytes::from_static(BODY), &[]).await?;
        let mut out = Vec::new();
        while let Some(c) = r.next().await? {
            out.extend_from_slice(&c);
        }
        Ok(out)
    }

    fn remote_opts(port: u16, name: &str, trust: RemoteTrust) -> LocalOptions {
        LocalOptions {
            vetted_hosts: vec![format!("{name}:{port}")],
            auth_header: Some(("x-api-key".into(), Zeroizing::new("s3cr3t-runpod-key".into()))),
            trust,
            ..LocalOptions::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_tls_vetted_host_pinned_ca_and_auth_header() {
        let name = "gpu1.moochy.test";
        test_dns::set(name, vec![IpAddr::from([127, 0, 0, 1])], true);
        let mut f = tls_fake(&[name], ok_response()).await;
        let opts = remote_opts(f.port, name, RemoteTrust::Ca(f.ca.clone()));
        let url = format!("https://GPU1.moochy.test:{}", f.port);
        assert_eq!(check_local_url(&url, &opts), Ok(LocalHost::Remote));
        let a = Adapter::new_local_with(&local_cfg(url), &opts).unwrap();
        assert_eq!(call(&a).await.unwrap(), SSE_OK.as_bytes());
        let head = f.heads.recv().await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("post /v1/chat/completions http/1.1\r\n"), "{head}");
        assert!(head.contains(&format!("host: gpu1.moochy.test:{}\r\n", f.port)), "{head}");
        assert!(head.contains("x-api-key: s3cr3t-runpod-key\r\n") && !head.contains("authorization"), "{head}");
        // The secret never shows up in what gets logged.
        assert!(!format!("{a:?} {opts:?}").contains("s3cr3t"));
        // Fingerprint pin: exactly this certificate, no CA needed.
        let fp: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &f.leaf).as_ref().try_into().unwrap();
        let a = Adapter::new_local_with(&local_cfg(format!("https://{name}:{}", f.port)), &remote_opts(f.port, name, RemoteTrust::Fingerprint(fp))).unwrap();
        assert_eq!(call(&a).await.unwrap(), SSE_OK.as_bytes());
        // Untrusted: wrong fingerprint, Mozilla roots for a self-signed CA, another CA.
        let other = tls_fake(&[name], ok_response()).await;
        for trust in [RemoteTrust::Fingerprint([7; 32]), RemoteTrust::Roots, RemoteTrust::Ca(other.ca.clone())] {
            let a = Adapter::new_local_with(&local_cfg(format!("https://{name}:{}", f.port)), &remote_opts(f.port, name, trust.clone())).unwrap();
            let e = call(&a).await.unwrap_err();
            assert_eq!(e.kind, FailKind::Network, "{trust:?}: {e:?}");
        }
    }

    /// SSRF: a redirect is an error status, never followed; nothing else is requested.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_redirect_is_not_followed() {
        let name = "gpu2.moochy.test";
        test_dns::set(name, vec![IpAddr::from([127, 0, 0, 1])], true);
        let mut f = tls_fake(&[name], "HTTP/1.1 307 Temporary Redirect\r\nlocation: http://169.254.169.254/latest/meta-data/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        let a = Adapter::new_local_with(&local_cfg(format!("https://{name}:{}", f.port)), &remote_opts(f.port, name, RemoteTrust::Ca(f.ca.clone()))).unwrap();
        let e = call(&a).await.unwrap_err();
        assert_eq!(e.status, Some(307));
        assert!(f.heads.recv().await.is_some());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(f.heads.try_recv().is_err(), "exactly one request");
    }

    /// SSRF: a vetted name that resolves to loopback, LAN, link-local or metadata addresses (or a
    /// mix) is refused at connect time, every time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_dns_rebinding_is_refused() {
        let f = tls_fake(&["rebind.moochy.test", "localhost"], ok_response()).await;
        let cases: [(&str, Vec<IpAddr>); 5] = [
            ("rebind1.moochy.test", vec![IpAddr::from([127, 0, 0, 1])]),
            ("rebind2.moochy.test", vec![IpAddr::from([8, 8, 8, 8]), IpAddr::from([10, 0, 0, 1])]),
            ("rebind3.moochy.test", vec![IpAddr::from([169, 254, 169, 254])]),
            ("rebind4.moochy.test", vec!["::ffff:127.0.0.1".parse().unwrap()]),
            ("rebind5.moochy.test", vec!["fd00::1".parse().unwrap()]),
        ];
        for (name, ips) in cases {
            test_dns::set(name, ips, false);
            let a = Adapter::new_local_with(&local_cfg(format!("https://{name}:{}", f.port)), &remote_opts(f.port, name, RemoteTrust::Ca(f.ca.clone()))).unwrap();
            let e = call(&a).await.unwrap_err();
            assert!(e.detail.contains("DNS rebinding"), "{name}: {e:?}");
        }
        // The real resolver: `localhost` resolves to loopback.
        let a = Adapter::new_local_with(&local_cfg(format!("https://localhost:{}", f.port)), &remote_opts(f.port, "localhost", RemoteTrust::Ca(f.ca.clone()))).unwrap();
        assert!(call(&a).await.unwrap_err().detail.contains("DNS rebinding"));
    }

    #[test]
    fn remote_host_url_matrix() {
        let vetted = |hosts: &[&str]| LocalOptions { vetted_hosts: hosts.iter().map(|h| (*h).to_owned()).collect(), ..LocalOptions::default() };
        let dev = LocalOptions { allow_unvetted_host: true, ..LocalOptions::default() };
        let o = vetted(&["gpu.example.com:8443", "gpu.example.com:443", "[2001:4860::8888]:8443", "203.0.113.7:443", "localhost:8443", "2130706433:443", "gpu.example.com.:443"]);
        for (url, want) in [
            ("https://gpu.example.com:8443", LocalHost::Remote),
            ("https://GPU.Example.COM:8443/", LocalHost::Remote),
            ("https://gpu.example.com", LocalHost::Remote),
            ("https://[2001:4860::8888]:8443", LocalHost::Remote),
            ("https://203.0.113.7", LocalHost::Remote),
            // Syntactically fine; the connect-time check refuses its loopback addresses.
            ("https://localhost:8443", LocalHost::Remote),
            // Loopback and LAN: unchanged, http or https, no vetting.
            ("http://127.0.0.1:11434", LocalHost::Loopback),
            ("http://192.168.1.5:11434", LocalHost::Lan),
            ("https://10.0.0.2:8443", LocalHost::Lan),
        ] {
            assert_eq!(check_local_url(url, &o), Ok(want), "{url}");
        }
        for url in [
            // Plain HTTP off the LAN, even vetted or in dev mode.
            "http://gpu.example.com:8443",
            "http://203.0.113.7",
            // Not exactly vetted: other port, other host, suffix games.
            "https://gpu.example.com:9443",
            "https://gpu.example.com.evil.com:8443",
            "https://evilgpu.example.com:8443",
            // IPv6 zone ids, link-local, metadata (also v4-mapped).
            "https://[fe80::1%25eth0]:8443",
            "https://[fe80::1%eth0]:8443",
            "https://[::1%lo]:8443",
            "https://[fe80::1]:8443",
            "https://169.254.169.254",
            "https://[::ffff:169.254.169.254]",
            "https://0.0.0.0:8443",
            // Numeric host forms other parsers read as IPv4.
            "https://2130706433",
            "https://0x7f000001",
            "https://127.1",
            "https://0177.0.0.1",
            // Userinfo, fragments, backslashes, trailing dot, IDN, paths.
            "https://gpu.example.com@169.254.169.254",
            "https://169.254.169.254#@gpu.example.com",
            "https://gpu.example.com\\@169.254.169.254",
            "https://gpu.example.com.:443",
            "https://gpü.example.com",
            "https://gpu.example.com:8443/v1",
        ] {
            assert!(check_local_url(url, &o).is_err(), "accepted {url}");
        }
        assert!(check_local_url("http://gpu.example.com", &dev).is_err(), "dev mode keeps https-only off the LAN");
        assert_eq!(check_local_url("https://gpu.example.com", &dev), Ok(LocalHost::Unvetted));
        assert_eq!(remote_host_key("https://GPU.example.com").as_deref(), Ok("gpu.example.com:443"));
        assert_eq!(remote_host_key("https://[2001:4860::8888]:8443/").as_deref(), Ok("[2001:4860::8888]:8443"));
        for bad in ["http://gpu.example.com", "https://192.168.1.5", "https://127.0.0.1:8443", "https://169.254.169.254", "https://2130706433"] {
            assert!(remote_host_key(bad).is_err(), "{bad}");
        }
    }

    /// Keep-alive HTTP/1.1 fake on loopback: answers every request on the same connection and
    /// counts connections.
    async fn keepalive_fake() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = conns.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 4096];
                    loop {
                        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                            let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                            if buf.len() < end + 4 + len {
                                break;
                            }
                            buf.drain(..end + 4 + len);
                            let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n{SSE_OK}", SSE_OK.len());
                            if s.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&b[..n]),
                        }
                    }
                });
            }
        });
        (port, conns)
    }

    /// RunPod-style proxies drop idle keep-alive connections: an idle pooled connection older
    /// than `pool_idle` is never reused; a fresh one is dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pooled_connections_expire_after_pool_idle() {
        let (port, conns) = keepalive_fake().await;
        let mut cfg = local_cfg(format!("http://127.0.0.1:{port}"));
        cfg.limits.pool_idle = Duration::from_millis(150);
        let a = Adapter::new(&cfg).unwrap();
        assert_eq!(call(&a).await.unwrap(), SSE_OK.as_bytes());
        assert_eq!(call(&a).await.unwrap(), SSE_OK.as_bytes());
        assert_eq!(conns.load(std::sync::atomic::Ordering::SeqCst), 1, "reused while fresh");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(call(&a).await.unwrap(), SSE_OK.as_bytes());
        assert_eq!(conns.load(std::sync::atomic::Ordering::SeqCst), 2, "an idle-expired connection is not reused");
    }

    /// A proxy's "origin timed out" (Cloudflare 524) is a retryable timeout with a clear hint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_timeout_status_is_a_retryable_timeout() {
        let name = "gpu3.moochy.test";
        test_dns::set(name, vec![IpAddr::from([127, 0, 0, 1])], true);
        let f = tls_fake(&[name], "HTTP/1.1 524 A Timeout Occurred\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        let a = Adapter::new_local_with(&local_cfg(format!("https://{name}:{}", f.port)), &remote_opts(f.port, name, RemoteTrust::Ca(f.ca.clone()))).unwrap();
        let e = call(&a).await.unwrap_err();
        assert_eq!((e.kind, e.status), (FailKind::Timeout, Some(524)));
        assert!(e.detail.contains("streaming"), "{}", e.detail);
    }

    #[test]
    fn remote_auth_header_rules() {
        let url = "https://gpu.example.com".to_owned();
        let with = |name: &str, key: &str| {
            let mut cfg = local_cfg(url.clone());
            cfg.api_key = Zeroizing::new(key.to_owned());
            let o = LocalOptions { vetted_hosts: vec!["gpu.example.com:443".into()], auth_header: Some((name.to_owned(), Zeroizing::new("v".into()))), ..LocalOptions::default() };
            Adapter::new_local_with(&cfg, &o).map(drop)
        };
        assert!(with("authorization", "").is_ok());
        assert!(with("x-api-key", "").is_ok());
        for bad in ["Authorization", "host", "content-length", "transfer-encoding", "proxy-authorization", "x-forwarded-for", "cookie", "", "a b"] {
            assert!(with(bad, "").is_err(), "{bad}");
        }
        assert!(with("authorization", "sk-also").is_err(), "key and header both");
        // Local options on a hosted provider are refused.
        let hosted = AdapterConfig { provider: Provider::OpenAi, api_key: Zeroizing::new("sk".into()), base_url: None, insecure_dev: false, dev_root: None, limits: Limits::default() };
        let o = LocalOptions { auth_header: Some(("x-api-key".into(), Zeroizing::new("v".into()))), ..LocalOptions::default() };
        assert!(Adapter::new_local_with(&hosted, &o).is_err());
        // Plain HTTP to a remote host never builds.
        assert!(Adapter::new_local_with(&local_cfg("http://gpu.example.com".into()), &LocalOptions { allow_unvetted_host: true, ..LocalOptions::default() }).is_err());
    }

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
        let r = Dialect::OpenAiResponses;
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
            // §18.6: Responses only where the provider speaks it natively.
            (Provider::OpenAi, r, Some("https://api.openai.com/v1/responses")),
            (Provider::XAi, r, Some("https://api.x.ai/v1/responses")),
            (Provider::OpenRouter, r, Some("https://openrouter.ai/api/v1/responses")),
            (Provider::Anthropic, r, None),
            (Provider::DeepSeek, r, None),
            (Provider::Local, r, None),
        ];
        for (p, d, url) in want {
            assert_eq!(full(p, d).as_deref(), url, "{p:?} {d:?}");
            assert_eq!(p.serves(d), url.is_some(), "Provider::serves agrees with the adapter table");
        }
    }

    #[test]
    fn public_message_never_carries_provider_text() {
        let key = "sk-ant-api03-CANARY291-0123456789abcdef";
        let f = |kind, status, body: String| Failure { kind, status: Some(status), retry_after_ms: None, rate_limit: None, body: Bytes::from(body), detail: "provider returned an error status" };
        for (kind, status) in [(FailKind::InvalidRequest, 400), (FailKind::Auth, 401), (FailKind::Overloaded, 529), (FailKind::ProviderError, 500), (FailKind::RateLimited, 429)] {
            let m = f(kind, status, format!(r#"{{"error":{{"message":"header x-api-key {key}: malformed"}}}}"#)).public_message();
            assert!(!m.contains("CANARY") && !m.contains("x-api-key") && m.ends_with(&format!("(HTTP {status})")), "{m}");
        }
        let m = f(FailKind::InvalidRequest, 400, r#"{"error":{"message":"Prompt is too long: 250000 tokens > 200000 maximum"}}"#.into()).public_message();
        assert_eq!(m, "prompt is too long: the request exceeds the model's context window (HTTP 400)");
    }
}
