//! Single-use request validator (CONTRACT §15.2): the only place a stranger's request bytes
//! are parsed. Runs in a pre-spawned child (`moochy __validate`) with no files, no network and
//! no keys; the parent keeps the AEAD keys, provider keys, outbox and caps.
//!
//! Child: [`child_main`] reads one request from stdin (task context + the **opened but still
//! zstd-compressed** inner payload), runs pure-Rust zstd (`ruzstd`) → strict JSON inner
//! payload (CONTRACT §4 rules) → base64url body → firewall + safe mutations → route check,
//! writes one response (validated inner fields + canonical body, or a refusal) and exits.
//! Every allocation is bounded by the input caps below.
//!
//! Parent: [`Validator`] keeps warm children (spawned by the node's sandboxing spawner),
//! uses each for exactly one request, spawns the replacement off the critical path, enforces
//! a deadline, and maps any child crash, timeout or garbage to a retryable error.
//!
//! The parent still verifies `body_sha256` and `task_sig` (it has the original body and the
//! key log) and computes `req_commit` from the original body.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;

use crate::codec::{Rd, W};
use crate::firewall::{self, CacheTtl, Catalog, Facts, Level, MaxPrice, Policy, Prepared, Reject, RejectCode, Route};
use crate::json::{self, Kind, Val};
use crate::{Dialect, Effort, Flags, Provider};

/// Largest decompressed inner payload (03 §16 / CONTRACT §15.2: 32 MiB).
pub const MAX_INNER: usize = 32 << 20;
/// zstd window the decoder accepts (the same bound as the encoder side's `WindowLogMax(25)`).
pub const MAX_WINDOW: u64 = 1 << 25;
/// Largest request the child reads (compressed payload ≤ inner cap + context).
pub const MAX_REQUEST: usize = MAX_INNER + (1 << 20);
/// Largest response the parent reads (original body + canonical body + fields).
pub const MAX_RESPONSE: usize = 2 * MAX_INNER + (1 << 20);
const VERSION: u8 = 1;
const MAX_STR: usize = 4096;

// ---------------------------------------------------------------------------------------
// Request / response types

/// What the parent sends: task context (already parsed by the parent) + the compressed
/// inner payload exactly as opened from the AEAD chunks.
#[derive(Clone, Copy, Debug)]
pub struct ValidateRequest<'a> {
    pub provider: Provider,
    pub dialect: Dialect,
    pub policy: Policy,
    pub catalog: Catalog,
    pub provider_model_id: &'a str,
    pub user_pseudonym: &'a str,
    pub max_price: Option<MaxPrice>,
    /// The route header fields (parsed by the parent with the strict proto parser).
    pub route: Route<'a>,
    /// zstd-compressed inner payload (plaintext after AEAD opening, before decompression).
    pub payload: &'a [u8],
}

/// A validated request: inner-payload fields for the parent's signature check and
/// `req_commit`, plus the canonical body to send to the provider.
#[derive(Debug)]
pub struct Validated {
    pub s: [u8; 32],
    pub gateway_device: String,
    pub task_sig: [u8; 64],
    pub body_sha256: [u8; 32],
    /// Inner-payload provider headers, sorted by name (feed `headers_sha256`).
    pub headers: Vec<(String, String)>,
    /// The original body (verify `body_sha256`, compute `req_commit`).
    pub body: Bytes,
    pub prepared: Prepared,
}

#[derive(Debug)]
pub enum ValidateError {
    /// Firewall / route / unsupported refusal (NACK per [`RejectCode::nack`]).
    Refused(Reject),
    /// Decompression, inner-payload schema or encoding failure (NACK `bad_envelope`).
    BadEnvelope(String),
    /// The child crashed, timed out, could not be spawned or returned garbage.
    Child(&'static str),
    /// A220: the child's provider request is not what the parent derives from the inner request
    /// it returned (a compromised child). NACK `bad_envelope`, not retried: only a request
    /// that broke the validator gets here.
    Tampered(&'static str),
}

impl ValidateError {
    /// NACK code (03 §10.2) and retryability. A child failure is retryable elsewhere and
    /// carries no penalty (`busy`): it is not the provider's or the donor's fault.
    pub fn nack(&self) -> (&'static str, bool) {
        match self {
            Self::Refused(r) => r.code.nack(),
            Self::BadEnvelope(_) | Self::Tampered(_) => ("bad_envelope", false),
            Self::Child(_) => ("busy", true),
        }
    }
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => r.fmt(f),
            Self::BadEnvelope(m) => write!(f, "bad envelope: {m}"),
            Self::Child(m) => write!(f, "validator child: {m}"),
            Self::Tampered(m) => write!(f, "validator child output rejected: {m}"),
        }
    }
}

impl std::error::Error for ValidateError {}

// ---------------------------------------------------------------------------------------
// Small enum <-> byte maps (fail closed on unknown values)

const PROVIDERS: [Provider; 6] = [Provider::Anthropic, Provider::OpenRouter, Provider::DeepSeek, Provider::OpenAi, Provider::XAi, Provider::Local];
const DIALECTS: [Dialect; 2] = [Dialect::AnthropicMessages, Dialect::OpenAiChat];
const EFFORTS: [Effort; 7] = [Effort::None, Effort::Minimal, Effort::Low, Effort::Medium, Effort::High, Effort::XHigh, Effort::Max];
const TTLS: [CacheTtl; 3] = [CacheTtl::None, CacheTtl::M5, CacheTtl::H1];
const LEVELS: [Level; 2] = [Level::Strict, Level::Paranoid];
const CODES: [RejectCode; 3] = [RejectCode::Firewall, RejectCode::RouteMismatch, RejectCode::Unsupported];
const FWD_HEADERS: [&str; 2] = ["anthropic-version", "anthropic-beta"];

fn idx<T: PartialEq>(all: &[T], v: &T) -> u8 {
    all.iter().position(|x| x == v).and_then(|i| u8::try_from(i).ok()).unwrap_or(u8::MAX)
}

fn pick<T: Copy>(all: &[T], b: u8) -> Option<T> {
    all.get(usize::from(b)).copied()
}

fn utf8(b: &[u8]) -> Option<&str> {
    std::str::from_utf8(b).ok()
}

// ---------------------------------------------------------------------------------------
// Wire encoding

/// The parent's wire encoding of a request (exposed for tests and fuzzing).
pub fn encode_request(r: &ValidateRequest<'_>, out: &mut Vec<u8>) {
    let mut w = W(out);
    w.u8(VERSION);
    w.u8(idx(&PROVIDERS, &r.provider));
    w.u8(idx(&DIALECTS, &r.dialect));
    w.u8(idx(&LEVELS, &r.policy.level));
    w.u8(r.policy.flags.0);
    w.u8(idx(&EFFORTS, &r.policy.max_effort));
    w.u8(idx(&EFFORTS, &r.catalog.default_effort));
    w.u64(r.catalog.max_output);
    w.u64(r.catalog.max_image_tokens);
    w.u64(r.catalog.max_page_tokens);
    match r.max_price {
        Some(p) => {
            w.u8(1);
            w.u64(p.prompt_uusd_per_mtok);
            w.u64(p.completion_uusd_per_mtok);
        }
        None => w.u8(0),
    }
    w.bytes(r.provider_model_id.as_bytes());
    w.bytes(r.user_pseudonym.as_bytes());
    let rt = &r.route;
    w.u8(idx(&DIALECTS, &rt.dialect));
    w.u8(idx(&EFFORTS, &rt.effort));
    w.u64(rt.max_tokens);
    w.u64(rt.est_input_tokens);
    w.u8(idx(&TTLS, &rt.cache_ttl));
    w.u8(u8::from(rt.stream));
    w.u8(rt.flags.0);
    w.u32(u32::try_from(rt.model_aliases.len()).unwrap_or(u32::MAX));
    for a in rt.model_aliases {
        w.bytes(a.as_bytes());
    }
    w.bytes(r.payload);
}

/// Owned decode of the request inside the child.
struct ChildRequest<'a> {
    provider: Provider,
    dialect: Dialect,
    policy: Policy,
    catalog: Catalog,
    max_price: Option<MaxPrice>,
    model_id: &'a str,
    pseudonym: &'a str,
    route_dialect: Dialect,
    effort: Effort,
    max_tokens: u64,
    est_input: u64,
    ttl: CacheTtl,
    stream: bool,
    flags: Flags,
    aliases: Vec<&'a str>,
    payload: &'a [u8],
}

fn decode_request(b: &[u8]) -> Option<ChildRequest<'_>> {
    let mut r = Rd(b);
    if r.u8()? != VERSION {
        return None;
    }
    let provider = pick(&PROVIDERS, r.u8()?)?;
    let dialect = pick(&DIALECTS, r.u8()?)?;
    let level = pick(&LEVELS, r.u8()?)?;
    let pflags = Flags(r.u8()?);
    let max_effort = pick(&EFFORTS, r.u8()?)?;
    let default_effort = pick(&EFFORTS, r.u8()?)?;
    let (max_output, max_image_tokens, max_page_tokens) = (r.u64()?, r.u64()?, r.u64()?);
    let max_price = match r.u8()? {
        0 => None,
        1 => Some(MaxPrice { prompt_uusd_per_mtok: r.u64()?, completion_uusd_per_mtok: r.u64()? }),
        _ => return None,
    };
    let model_id = utf8(r.bytes()?)?;
    let pseudonym = utf8(r.bytes()?)?;
    let route_dialect = pick(&DIALECTS, r.u8()?)?;
    let effort = pick(&EFFORTS, r.u8()?)?;
    let (max_tokens, est_input) = (r.u64()?, r.u64()?);
    let ttl = pick(&TTLS, r.u8()?)?;
    let stream = match r.u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let flags = Flags(r.u8()?);
    let n = usize::try_from(r.u32()?).ok().filter(|n| *n <= 64)?;
    let mut aliases = Vec::with_capacity(n);
    for _ in 0..n {
        aliases.push(utf8(r.bytes()?)?);
    }
    let payload = r.bytes()?;
    if !r.is_empty() || model_id.len() > MAX_STR || pseudonym.len() > MAX_STR {
        return None;
    }
    Some(ChildRequest {
        provider,
        dialect,
        policy: Policy { level, flags: pflags, max_effort },
        catalog: Catalog { default_effort, max_output, max_image_tokens, max_page_tokens },
        max_price,
        model_id,
        pseudonym,
        route_dialect,
        effort,
        max_tokens,
        est_input,
        ttl,
        stream,
        flags,
        aliases,
        payload,
    })
}

const OK: u8 = 0;
const REFUSED: u8 = 1;
const BAD_ENVELOPE: u8 = 2;

fn encode_ok(v: &Validated, out: &mut Vec<u8>) {
    let mut w = W(out);
    w.u8(VERSION);
    w.u8(OK);
    w.bytes(&v.s);
    w.bytes(v.gateway_device.as_bytes());
    w.bytes(&v.task_sig);
    w.bytes(&v.body_sha256);
    w.u32(u32::try_from(v.headers.len()).unwrap_or(u32::MAX));
    for (k, val) in &v.headers {
        w.bytes(k.as_bytes());
        w.bytes(val.as_bytes());
    }
    w.bytes(&v.body);
    let f = &v.prepared.facts;
    w.bytes(f.model.as_bytes());
    w.u64(f.max_tokens);
    w.u8(idx(&EFFORTS, &f.effort));
    w.u64(f.est_input_tokens);
    w.u8(idx(&TTLS, &f.cache_ttl));
    w.u8(u8::from(f.stream));
    w.u8(f.flags.0);
    w.u64(f.text_bytes);
    w.u64(f.images);
    w.u64(f.pages);
    w.u32(u32::try_from(v.prepared.headers.len()).unwrap_or(u32::MAX));
    for (k, val) in &v.prepared.headers {
        w.bytes(k.as_bytes());
        w.bytes(val.as_bytes());
    }
    w.bytes(&v.prepared.body);
}

fn encode_err(e: &ValidateError, out: &mut Vec<u8>) {
    let mut w = W(out);
    w.u8(VERSION);
    match e {
        ValidateError::Refused(r) => {
            w.u8(REFUSED);
            w.u8(idx(&CODES, &r.code));
            w.bytes(r.path.as_bytes());
            w.bytes(r.reason.as_bytes());
        }
        ValidateError::BadEnvelope(m) => {
            w.u8(BAD_ENVELOPE);
            w.bytes(m.as_bytes());
        }
        ValidateError::Child(m) | ValidateError::Tampered(m) => {
            w.u8(BAD_ENVELOPE);
            w.bytes(m.as_bytes());
        }
    }
}

/// Parent-side strict decode of the child's response (the bytes after the `u32_be` length
/// prefix). Byte fields become zero-copy slices of `buf`. Public for custom transports (a
/// zygote-forked child on a socket); [`validate_on`] does the whole exchange.
pub fn decode_response(buf: &Bytes) -> Result<Validated, ValidateError> {
    let garbage = || ValidateError::Child("malformed response");
    let mut r = Rd(buf);
    let slice = |s: &[u8]| buf.slice_ref(s);
    let s32 = |s: Option<&[u8]>| s.and_then(|s| <[u8; 32]>::try_from(s).ok());
    let text = |s: Option<&[u8]>| s.and_then(utf8).filter(|s| s.len() <= MAX_STR).map(str::to_owned);
    if r.u8() != Some(VERSION) {
        return Err(garbage());
    }
    match r.u8().ok_or_else(garbage)? {
        OK => {}
        REFUSED => {
            let code = r.u8().and_then(|c| pick(&CODES, c)).ok_or_else(garbage)?;
            let path = text(r.bytes()).ok_or_else(garbage)?;
            let reason = text(r.bytes()).ok_or_else(garbage)?;
            return if r.is_empty() { Err(ValidateError::Refused(Reject { code, path, reason: reason.into() })) } else { Err(garbage()) };
        }
        BAD_ENVELOPE => {
            let m = text(r.bytes()).ok_or_else(garbage)?;
            return if r.is_empty() { Err(ValidateError::BadEnvelope(m)) } else { Err(garbage()) };
        }
        _ => return Err(garbage()),
    }
    let s = s32(r.bytes()).ok_or_else(garbage)?;
    let gateway_device = text(r.bytes()).filter(|d| device_id_ok(d)).ok_or_else(garbage)?;
    let task_sig = r.bytes().and_then(|s| <[u8; 64]>::try_from(s).ok()).ok_or_else(garbage)?;
    let body_sha256 = s32(r.bytes()).ok_or_else(garbage)?;
    let n = usize::try_from(r.u32().ok_or_else(garbage)?).map_err(|_| garbage())?;
    if n > 16 {
        return Err(garbage());
    }
    let mut headers = Vec::with_capacity(n);
    for _ in 0..n {
        let k = text(r.bytes()).filter(|k| header_name_ok(k)).ok_or_else(garbage)?;
        let v = text(r.bytes()).filter(|v| header_value_ok(v)).ok_or_else(garbage)?;
        headers.push((k, v));
    }
    let body = slice(r.bytes().ok_or_else(garbage)?);
    let model = text(r.bytes()).ok_or_else(garbage)?;
    let max_tokens = r.u64().ok_or_else(garbage)?;
    let effort = r.u8().and_then(|e| pick(&EFFORTS, e)).ok_or_else(garbage)?;
    let est_input_tokens = r.u64().ok_or_else(garbage)?;
    let cache_ttl = r.u8().and_then(|t| pick(&TTLS, t)).ok_or_else(garbage)?;
    let stream = match r.u8() {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(garbage()),
    };
    let flags = Flags(r.u8().ok_or_else(garbage)?);
    let text_bytes = r.u64().ok_or_else(garbage)?;
    let images = r.u64().ok_or_else(garbage)?;
    let pages = r.u64().ok_or_else(garbage)?;
    let nf = usize::try_from(r.u32().ok_or_else(garbage)?).map_err(|_| garbage())?;
    if nf > FWD_HEADERS.len() {
        return Err(garbage());
    }
    let mut fwd = Vec::with_capacity(nf);
    for _ in 0..nf {
        let k = r.bytes().and_then(utf8).and_then(|k| FWD_HEADERS.iter().find(|h| **h == k)).ok_or_else(garbage)?;
        let v = text(r.bytes()).filter(|v| header_value_ok(v)).ok_or_else(garbage)?;
        fwd.push((*k, v));
    }
    let prepared_body = slice(r.bytes().ok_or_else(garbage)?);
    if !r.is_empty() {
        return Err(garbage());
    }
    let facts = Facts { model, max_tokens, effort, est_input_tokens, cache_ttl, stream, flags, text_bytes, images, pages };
    Ok(Validated { s, gateway_device, task_sig, body_sha256, headers, body, prepared: Prepared { facts, body: prepared_body, headers: fwd } })
}

// ---------------------------------------------------------------------------------------
// Validation proper (runs in the child)

fn header_name_ok(k: &str) -> bool {
    !k.is_empty() && k.len() <= 64 && k.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&c))
}

fn header_value_ok(v: &str) -> bool {
    v.len() <= MAX_STR && v.bytes().all(|c| c == b'\t' || (b' '..=b'~').contains(&c))
}

/// `d_` + canonical ULID (26 Crockford base32 characters, uppercase, first ≤ '7').
fn device_id_ok(d: &str) -> bool {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    d.strip_prefix("d_").is_some_and(|u| {
        u.len() == 26 && u.bytes().all(|c| CROCKFORD.contains(&c)) && u.as_bytes().first().is_some_and(|c| *c <= b'7')
    })
}

/// zstd → bytes with every bound enforced: one frame, window ≤ 32 MiB, output ≤ 32 MiB,
/// no trailing bytes.
fn decompress(payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut src = payload;
    let dec = ruzstd::decoding::StreamingDecoder::new_with_max_window_size(&mut src, MAX_WINDOW).map_err(|e| format!("zstd header: {e}"))?;
    let mut out = Vec::new();
    let cap = u64::try_from(MAX_INNER).unwrap_or(u64::MAX).saturating_add(1);
    dec.take(cap).read_to_end(&mut out).map_err(|e| format!("zstd: {e}"))?;
    if out.len() > MAX_INNER {
        return Err("inner payload larger than 32 MiB".into());
    }
    if !src.is_empty() {
        return Err("trailing bytes after the zstd frame".into());
    }
    Ok(out)
}

struct Inner {
    s: [u8; 32],
    gateway_device: String,
    task_sig: [u8; 64],
    body_sha256: [u8; 32],
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// CONTRACT §4 inner payload, strict: exactly these members, `v == 1`, canonical
/// base64url-no-pad bytes of the right sizes, lowercase token header names.
fn parse_inner(bytes: &[u8]) -> Result<Inner, String> {
    const KEYS: [&str; 7] = ["v", "body_b64", "body_sha256", "headers", "S", "gateway_device", "task_sig"];
    let mut tape = Vec::new();
    let root = json::parse(bytes, &mut tape).map_err(|e| format!("inner payload: {e}"))?.root();
    if root.kind() != Kind::Obj {
        return Err("inner payload must be an object".into());
    }
    if let Some((k, _)) = root.entries().find(|(k, _)| !KEYS.iter().any(|n| k.is_str(n))) {
        return Err(format!("inner payload: unknown member `{}`", k.raw().chars().take(64).collect::<String>()));
    }
    let get = |k: &str| root.get(k).ok_or_else(|| format!("inner payload: `{k}` is required"));
    let b64 = |k: &str| -> Result<Vec<u8>, String> {
        let v = get(k)?.as_str().ok_or_else(|| format!("inner payload: `{k}` must be a string"))?;
        URL_SAFE_NO_PAD.decode(v.as_bytes()).map_err(|_| format!("inner payload: `{k}` is not canonical base64url"))
    };
    if get("v")?.as_i64() != Some(1) {
        return Err("inner payload: `v` must be 1".into());
    }
    let s = <[u8; 32]>::try_from(b64("S")?).map_err(|_| "inner payload: `S` must be 32 bytes".to_owned())?;
    let task_sig = <[u8; 64]>::try_from(b64("task_sig")?).map_err(|_| "inner payload: `task_sig` must be 64 bytes".to_owned())?;
    let body_sha256 = <[u8; 32]>::try_from(b64("body_sha256")?).map_err(|_| "inner payload: `body_sha256` must be 32 bytes".to_owned())?;
    let gateway_device = get("gateway_device")?.as_str().filter(|d| device_id_ok(d)).ok_or("inner payload: bad `gateway_device`")?.into_owned();
    let hv: Val<'_> = get("headers")?;
    if hv.kind() != Kind::Obj {
        return Err("inner payload: `headers` must be an object".into());
    }
    let mut headers = Vec::new();
    for (k, v) in hv.entries() {
        let (Some(k), Some(v)) = (k.as_str(), v.as_str()) else {
            return Err("inner payload: header values must be strings".into());
        };
        if !header_name_ok(&k) || !header_value_ok(&v) || headers.len() >= 16 {
            return Err("inner payload: bad header".into());
        }
        headers.push((k.into_owned(), v.into_owned()));
    }
    headers.sort();
    let body = b64("body_b64")?;
    Ok(Inner { s, gateway_device, task_sig, body_sha256, headers, body })
}

fn run(req: &ChildRequest<'_>) -> Result<Validated, ValidateError> {
    let inner_bytes = decompress(req.payload).map_err(ValidateError::BadEnvelope)?;
    let inner = parse_inner(&inner_bytes).map_err(ValidateError::BadEnvelope)?;
    drop(inner_bytes);
    let hdrs: Vec<(&str, &str)> = inner.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let prepared = firewall::prepare(&firewall::Request {
        provider: req.provider,
        dialect: req.dialect,
        body: &inner.body,
        headers: &hdrs,
        policy: &req.policy,
        catalog: &req.catalog,
        provider_model_id: req.model_id,
        user_pseudonym: req.pseudonym,
        max_price: req.max_price,
    })
    .map_err(ValidateError::Refused)?;
    let route = Route {
        dialect: req.route_dialect,
        model_aliases: &req.aliases,
        effort: req.effort,
        max_tokens: req.max_tokens,
        est_input_tokens: req.est_input,
        cache_ttl: req.ttl,
        stream: req.stream,
        flags: req.flags,
    };
    prepared.facts.check_route(req.dialect, &route).map_err(ValidateError::Refused)?;
    Ok(Validated {
        s: inner.s,
        gateway_device: inner.gateway_device,
        task_sig: inner.task_sig,
        body_sha256: inner.body_sha256,
        headers: inner.headers,
        body: Bytes::from(inner.body),
        prepared,
    })
}

/// Child entry point (`moochy __validate`): one request in, one response out. Returns the
/// process exit code: 0 after writing a response (accept or refusal), 2 on an unreadable
/// request (the parent then sees no valid response and retries elsewhere).
pub fn child_main(input: impl Read, mut output: impl Write) -> i32 {
    let _ = warm_up();
    let mut buf = Vec::new();
    let cap = u64::try_from(MAX_REQUEST).unwrap_or(u64::MAX).saturating_add(1);
    if input.take(cap).read_to_end(&mut buf).is_err() || buf.len() > MAX_REQUEST {
        return 2;
    }
    let Some(req) = decode_request(&buf) else { return 2 };
    // `u32_be len || response`: the parent reads exactly this and never waits for our exit.
    let mut out = vec![0; 4];
    match run(&req) {
        Ok(v) => encode_ok(&v, &mut out),
        Err(e) => encode_err(&e, &mut out),
    }
    let len = u32::try_from(out.len().saturating_sub(4)).unwrap_or(u32::MAX).to_be_bytes();
    if let Some(h) = out.get_mut(..4) {
        h.copy_from_slice(&len);
    }
    if output.write_all(&out).and_then(|()| output.flush()).is_err() {
        return 2;
    }
    0
}

/// Run the whole pipeline once on a small built-in request while the child is still idle
/// (before reading stdin): code pages and allocator arenas are warm when the real request
/// arrives, so the parent does not pay for first-touch faults.
fn warm_up() -> bool {
    const BODY: &[u8] = br#"{"model":"m","max_tokens":16,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"warm up"}]}]}"#;
    let zero32 = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let inner = format!(
        r#"{{"v":1,"body_b64":"{}","body_sha256":"{zero32}","headers":{{}},"S":"{zero32}","gateway_device":"d_00000000000000000000000000","task_sig":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(BODY),
        URL_SAFE_NO_PAD.encode([0u8; 64])
    );
    let frame = ruzstd::encoding::compress_to_vec(inner.as_bytes(), ruzstd::encoding::CompressionLevel::Fastest);
    let req = ChildRequest {
        provider: Provider::Anthropic,
        dialect: Dialect::AnthropicMessages,
        policy: Policy::PERMISSIVE,
        catalog: Catalog { default_effort: Effort::High, max_output: 1024, max_image_tokens: 0, max_page_tokens: 0 },
        max_price: None,
        model_id: "m",
        pseudonym: "p",
        route_dialect: Dialect::AnthropicMessages,
        effort: Effort::High,
        max_tokens: 16,
        est_input: u64::try_from(BODY.len()).unwrap_or(0).div_ceil(3),
        ttl: CacheTtl::None,
        stream: true,
        flags: Flags::NONE,
        aliases: vec!["m"],
        payload: &frame,
    };
    let mut sink = Vec::with_capacity(1024);
    match run(&req) {
        Ok(v) => {
            encode_ok(&v, &mut sink);
            true
        }
        Err(e) => {
            encode_err(&e, &mut sink);
            false
        }
    }
}

/// A220 (defense in depth), in the parent: re-derive the provider request from the inner
/// request the child returned (`v.body` / `v.headers`, the bytes the node then checks against
/// the gateway's task signature) and accept the child's [`Prepared`] only if it is exactly
/// that, with the route matching. A compromised child can then neither add server tools or
/// betas, change the model, raise `max_tokens`, nor swap the prompt. The hostile part, zstd
/// decompression, stays in the child; this is one strict parse of a bounded, decompressed
/// body (≈ 22 µs per 100 KB). [`Validator::validate`] and [`validate_on`] call it already.
pub fn recheck(req: &ValidateRequest<'_>, v: &Validated) -> Result<(), ValidateError> {
    let hdrs: Vec<(&str, &str)> = v.headers.iter().map(|(k, x)| (k.as_str(), x.as_str())).collect();
    let mine = firewall::prepare(&firewall::Request {
        provider: req.provider,
        dialect: req.dialect,
        body: &v.body,
        headers: &hdrs,
        policy: &req.policy,
        catalog: &req.catalog,
        provider_model_id: req.provider_model_id,
        user_pseudonym: req.user_pseudonym,
        max_price: req.max_price,
    })
    .map_err(|_| ValidateError::Tampered("the returned request does not pass the firewall"))?;
    mine.facts.check_route(req.dialect, &req.route).map_err(|_| ValidateError::Tampered("the returned request does not match the route"))?;
    if mine.body != v.prepared.body {
        return Err(ValidateError::Tampered("provider body differs from the returned request"));
    }
    if mine.headers != v.prepared.headers {
        return Err(ValidateError::Tampered("provider headers differ from the returned request"));
    }
    if mine.facts != v.prepared.facts {
        return Err(ValidateError::Tampered("route facts differ from the returned request"));
    }
    Ok(())
}

/// Same validation without a child: tests, benchmarks, and the parent's latency baseline.
/// Production must use [`Validator`] (CONTRACT §15.2).
pub fn validate_in_process(req: &ValidateRequest<'_>) -> Result<Validated, ValidateError> {
    let mut wire = Vec::new();
    encode_request(req, &mut wire);
    let creq = decode_request(&wire).ok_or(ValidateError::Child("request encoding"))?;
    run(&creq)
}

// ---------------------------------------------------------------------------------------
// Parent side

/// Spawns one sandboxed validator child with piped stdin/stdout (the node wraps
/// `moochy __validate` with the moochy-sandbox lockdown and sets `kill_on_drop(true)`).
pub type Spawner = Arc<dyn Fn() -> std::io::Result<Child> + Send + Sync>;

#[derive(Clone, Copy, Debug)]
pub struct ValidatorLimits {
    /// Whole request: write, child work, read, exit.
    pub deadline: Duration,
    /// Children kept spawned and waiting.
    pub warm: usize,
}

impl Default for ValidatorLimits {
    fn default() -> Self {
        Self { deadline: Duration::from_secs(5), warm: 2 }
    }
}

/// Pre-spawned, single-use validator children. Cheap to share (`Arc<Validator>`).
pub struct Validator {
    spawn: Spawner,
    idle: Arc<Mutex<Vec<Child>>>,
    limits: ValidatorLimits,
}

impl std::fmt::Debug for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Validator").field("limits", &self.limits).finish_non_exhaustive()
    }
}

impl Validator {
    pub fn new(spawn: Spawner, limits: ValidatorLimits) -> Self {
        Self { spawn, idle: Arc::default(), limits }
    }

    /// Fill the warm pool now (call at startup, inside the runtime). Returns how many
    /// children are waiting.
    pub fn prewarm(&self) -> std::io::Result<usize> {
        let mut g = self.idle.lock().map_err(|_| std::io::Error::other("validator pool poisoned"))?;
        while g.len() < self.limits.warm {
            g.push((self.spawn)()?);
        }
        Ok(g.len())
    }

    /// Top the pool up in the background (spawning is a blocking fork/exec).
    fn replenish(&self) {
        let (spawn, idle, warm) = (self.spawn.clone(), self.idle.clone(), self.limits.warm);
        tokio::task::spawn_blocking(move || {
            let need = idle.lock().map_or(0, |g| warm.saturating_sub(g.len()));
            for _ in 0..need {
                match spawn() {
                    Ok(c) => {
                        if let Ok(mut g) = idle.lock() {
                            g.push(c);
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    fn take_child(&self) -> Result<Child, ValidateError> {
        loop {
            let c = self.idle.lock().ok().and_then(|mut g| g.pop());
            match c {
                // A child that already exited (killed, OOM) is discarded.
                Some(mut c) => {
                    if matches!(c.try_wait(), Ok(None)) {
                        return Ok(c);
                    }
                }
                None => return (self.spawn)().map_err(|_| ValidateError::Child("spawn failed")),
            }
        }
    }

    /// Validate one request in a fresh child. Any child failure is
    /// [`ValidateError::Child`] (retryable elsewhere).
    pub async fn validate(&self, req: &ValidateRequest<'_>) -> Result<Validated, ValidateError> {
        let mut child = self.take_child()?;
        self.replenish();
        let mut wire = Vec::with_capacity(req.payload.len().saturating_add(256));
        encode_request(req, &mut wire);
        let work = async {
            let stdin = child.stdin.take().ok_or(ValidateError::Child("no stdin"))?;
            let stdout = child.stdout.take().ok_or(ValidateError::Child("no stdout"))?;
            exchange(stdout, stdin, &wire, req).await
        };
        let out = tokio::time::timeout(self.limits.deadline, work).await;
        match out {
            Ok(r) => r,
            Err(_) => {
                let _ = child.start_kill();
                Err(ValidateError::Child("deadline exceeded"))
            }
        }
    }
}

/// Write one request (then half-close), read exactly one length-prefixed response; never wait
/// for the child's exit (it is killed and reaped when dropped).
async fn exchange<R, W>(mut reader: R, mut writer: W, wire: &[u8], req: &ValidateRequest<'_>) -> Result<Validated, ValidateError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let write = async move {
        writer.write_all(wire).await?;
        writer.shutdown().await
    };
    let read = async {
        let len = reader.read_u32().await?;
        let len = usize::try_from(len).ok().filter(|l| *l <= MAX_RESPONSE).ok_or_else(|| std::io::Error::other("oversize"))?;
        let mut resp = vec![0; len];
        reader.read_exact(&mut resp).await?;
        Ok::<_, std::io::Error>(resp)
    };
    let (w, r) = tokio::join!(write, read);
    w.map_err(|_| ValidateError::Child("write failed"))?;
    let resp = r.map_err(|_| ValidateError::Child("no complete response"))?;
    let v = decode_response(&Bytes::from(resp))?;
    recheck(req, &v)?;
    Ok(v)
}

/// Validate one request over any byte stream to a single-use child running [`child_main`]
/// on the other end (e.g. a socketpair to a zygote-forked, jailed child): write, half-close,
/// read one framed response, all within `deadline`. Child failures map to
/// [`ValidateError::Child`] (retryable, `busy`). The caller owns the child's lifetime.
pub async fn validate_on<S>(stream: S, req: &ValidateRequest<'_>, deadline: Duration) -> Result<Validated, ValidateError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut wire = Vec::with_capacity(req.payload.len().saturating_add(256));
    encode_request(req, &mut wire);
    let (r, w) = tokio::io::split(stream);
    tokio::time::timeout(deadline, exchange(r, w, &wire, req)).await.map_err(|_| ValidateError::Child("deadline exceeded"))?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_possible_truncation, clippy::items_after_statements)]
mod tests {
    use super::*;

    /// A request whose inner body is `body` and a matching route (as an honest Gateway sends).
    fn a220_case(body: &'static str, aliases: &'static [&'static str]) -> (Vec<u8>, Route<'static>) {
        let z = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let inner = format!(
            r#"{{"v":1,"body_b64":"{}","body_sha256":"{z}","headers":{{"anthropic-version":"2023-06-01"}},"S":"{z}","gateway_device":"d_01ARZ3NDEKTSV4RRFFQ69G5FAV","task_sig":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(body),
            URL_SAFE_NO_PAD.encode([0u8; 64])
        );
        let f = firewall::analyze(Dialect::AnthropicMessages, body.as_bytes(), &[], &Policy::PERMISSIVE, &A220_CAT).unwrap();
        let route = Route {
            dialect: Dialect::AnthropicMessages,
            model_aliases: aliases,
            effort: f.effort,
            max_tokens: f.max_tokens,
            est_input_tokens: f.est_input_tokens,
            cache_ttl: f.cache_ttl,
            stream: f.stream,
            flags: f.flags,
        };
        (ruzstd::encoding::compress_to_vec(inner.as_bytes(), ruzstd::encoding::CompressionLevel::Fastest), route)
    }

    const A220_CAT: Catalog = Catalog { default_effort: Effort::High, max_output: 64_000, max_image_tokens: 1600, max_page_tokens: 3000 };

    /// A compromised child answering `forged` (framed) to whatever request it reads.
    async fn evil_child(req: &ValidateRequest<'_>, forged: &Validated) -> Result<Validated, ValidateError> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut out = vec![0; 4];
        encode_ok(forged, &mut out);
        let len = u32::try_from(out.len() - 4).unwrap().to_be_bytes();
        out[..4].copy_from_slice(&len);
        let (parent, mut child) = tokio::io::duplex(1 << 20);
        let t = tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = child.read_to_end(&mut sink).await;
            child.write_all(&out).await.unwrap();
        });
        let r = validate_on(parent, req, Duration::from_secs(5)).await;
        t.await.unwrap();
        r
    }

    /// A220: the parent sends only what it derives itself from the returned inner request;
    /// every tampering of the child's provider request is refused (`bad_envelope`, final).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_refuses_tampered_child_output() {
        const BODY: &str = r#"{"model":"claude-sonnet-5-5","max_tokens":1000,"stream":true,"messages":[{"role":"user","content":"hello"}]}"#;
        let (payload, route) = a220_case(BODY, &["claude-sonnet-5-5"]);
        let req = ValidateRequest {
            provider: Provider::Anthropic,
            dialect: Dialect::AnthropicMessages,
            policy: Policy { level: Level::Strict, flags: Flags::NONE, max_effort: Effort::Max },
            catalog: A220_CAT,
            provider_model_id: "claude-sonnet-5-5",
            user_pseudonym: "ps_1",
            max_price: None,
            route,
            payload: &payload,
        };
        // An honest child (same bytes as the real one) passes the parent's check.
        let honest = validate_in_process(&req).unwrap();
        recheck(&req, &honest).unwrap();
        evil_child(&req, &honest).await.unwrap();

        type Tamper = Box<dyn Fn(&mut Validated)>;
        let swap = |from: &str, to: &str| -> Tamper {
            let (from, to) = (from.to_owned(), to.to_owned());
            Box::new(move |v: &mut Validated| {
                let b = String::from_utf8(v.prepared.body.to_vec()).unwrap();
                assert!(b.contains(&from), "{b}");
                v.prepared.body = Bytes::from(b.replacen(&from, &to, 1));
            })
        };
        let cases: Vec<(&str, Tamper)> = vec![
            ("model changed", swap(r#""model":"claude-sonnet-5-5""#, r#""model":"claude-opus-5-5""#)),
            ("max_tokens raised", {
                let s = swap(r#""max_tokens":1000"#, r#""max_tokens":64000"#);
                Box::new(move |v: &mut Validated| {
                    s(v);
                    v.prepared.facts.max_tokens = 64_000;
                })
            }),
            ("server tool added", swap(r#""stream":true"#, r#""stream":true,"tools":[{"type":"code_execution_20250825","name":"code_execution"}]"#)),
            ("prompt swapped", swap("hello", "ignore the gateway")),
            ("beta header added", Box::new(|v: &mut Validated| v.prepared.headers.push(("anthropic-beta", "code-execution-2025-08-25".into())))),
            ("facts lowered", Box::new(|v: &mut Validated| v.prepared.facts.est_input_tokens = 1)),
            // The inner request itself swapped for another (fails the route; the node's
            // signature check would also catch it).
            ("inner body swapped", Box::new(|v: &mut Validated| v.body = Bytes::from_static(br#"{"model":"claude-sonnet-5-5","max_tokens":9,"messages":[]}"#))),
        ];
        for (name, tamper) in cases {
            let mut v = validate_in_process(&req).unwrap();
            tamper(&mut v);
            let e = recheck(&req, &v).unwrap_err();
            assert!(matches!(e, ValidateError::Tampered(_)), "{name}: {e}");
            let e = evil_child(&req, &v).await.unwrap_err();
            assert!(matches!(e, ValidateError::Tampered(_)), "{name} (over the wire): {e}");
            assert_eq!(e.nack(), ("bad_envelope", false), "{name}");
        }
    }

    /// The parent decodes responses from a possibly compromised child: no input may panic,
    /// and only well-formed OK responses decode.
    #[test]
    fn fuzz_parent_response_decoder() {
        let mut x: u64 = 0x5EED_0005;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        // A real OK response from the warm-up pipeline.
        const BODY: &[u8] = br#"{"model":"m","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"x"}]}"#;
        let z = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let inner = format!(
            r#"{{"v":1,"body_b64":"{}","body_sha256":"{z}","headers":{{"anthropic-version":"2023-06-01"}},"S":"{z}","gateway_device":"d_00000000000000000000000000","task_sig":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(BODY),
            URL_SAFE_NO_PAD.encode([0u8; 64])
        );
        let frame = ruzstd::encoding::compress_to_vec(inner.as_bytes(), ruzstd::encoding::CompressionLevel::Fastest);
        let req = ChildRequest {
            provider: Provider::Anthropic,
            dialect: Dialect::AnthropicMessages,
            policy: Policy::PERMISSIVE,
            catalog: Catalog { default_effort: Effort::High, max_output: 1024, max_image_tokens: 0, max_page_tokens: 0 },
            max_price: None,
            model_id: "m",
            pseudonym: "p",
            route_dialect: Dialect::AnthropicMessages,
            effort: Effort::High,
            max_tokens: 16,
            est_input: u64::try_from(BODY.len()).unwrap().div_ceil(3),
            ttl: CacheTtl::None,
            stream: true,
            flags: Flags::NONE,
            aliases: vec!["m"],
            payload: &frame,
        };
        let mut good = Vec::new();
        encode_ok(&run(&req).unwrap(), &mut good);
        assert!(decode_response(&Bytes::from(good.clone())).is_ok());
        let n = std::env::var("MOOCHY_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000usize);
        for _ in 0..n * 4 {
            let mut b = good.clone();
            for _ in 0..=(rnd() % 4) {
                let i = usize::try_from(rnd() % (b.len() as u64 + 1)).unwrap();
                match rnd() % 4 {
                    0 if i < b.len() => b[i] ^= 1 << (rnd() % 8),
                    1 if i < b.len() => {
                        b.truncate(i);
                    }
                    2 => b.insert(i, u8::try_from(rnd() & 0xff).unwrap()),
                    _ => b.splice(i..i, [0xff, 0xff, 0xff, 0xff]).for_each(drop),
                }
            }
            let _ = decode_response(&Bytes::from(b));
        }
    }

    #[test]
    fn warm_up_runs_the_full_pipeline() {
        assert!(warm_up());
    }

    #[test]
    fn device_ids() {
        assert!(device_id_ok("d_01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!device_id_ok("d_81ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!device_id_ok("d_01arz3ndektsv4rrffq69g5fav"));
        assert!(!device_id_ok("u_01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assert!(!device_id_ok("d_01ARZ3NDEKTSV4RRFFQ69G5FAI"));
    }
}
