//! The Worker's request firewall (plan 06 §7): allowlist tables interpreted by a small
//! recursive validator over the strict JSON tape, route facts (03 §7.1), and the safe
//! mutations re-serialized from the validated tree.
//!
//! Anything not in a table is rejected with the field path, e.g.
//! "field `mcp_servers` is not allowed: the provider would connect to arbitrary servers".

use std::borrow::Cow;
use std::fmt;

use base64::Engine as _;
use bytes::Bytes;

use crate::json::{self, Kind, Patch, Val};
use crate::tables;
use crate::{Dialect, Effort, Flags, Provider};

/// Largest request body accepted (03 §16: 32 MiB decompressed).
pub const MAX_BODY: usize = 32 << 20;
/// `max_tokens` ceiling at the `paranoid` level.
pub const PARANOID_MAX_TOKENS: u64 = 16_384;
const MAX_MODEL_LEN: usize = 256;

/// Donor strictness level (06 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Level {
    #[default]
    Strict,
    /// Also denies images and documents and lowers the `max_tokens` ceiling.
    Paranoid,
}

/// The pledge policy and device settings that gate a request.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub level: Level,
    /// Pledge opt-ins (`images`, `documents`, `fast`, `long_context`, `service_tier`, `inference_geo`).
    pub flags: Flags,
    pub max_effort: Effort,
}

impl Policy {
    /// Everything a pledge could opt into: used by the Gateway to compute route facts.
    pub const PERMISSIVE: Self = Self {
        level: Level::Strict,
        flags: Flags(0)
            .with(Flags::IMAGES)
            .with(Flags::DOCUMENTS)
            .with(Flags::FAST)
            .with(Flags::LONG_CONTEXT)
            .with(Flags::SERVICE_TIER)
            .with(Flags::INFERENCE_GEO),
        max_effort: Effort::Max,
    };
}

/// The signed-catalog numbers for the requested model (05 §2.2).
#[derive(Clone, Copy, Debug)]
pub struct Catalog {
    pub default_effort: Effort,
    pub max_output: u64,
    pub max_image_tokens: u64,
    /// Input-token allowance per PDF page (CONTRACT R3).
    pub max_page_tokens: u64,
}

/// Most PDF pages per request (CONTRACT R3).
pub const MAX_PDF_PAGES: u64 = 100;

/// OpenRouter max-price preference, from the catalog price (µ$ per million tokens).
#[derive(Clone, Copy, Debug)]
pub struct MaxPrice {
    pub prompt_uusd_per_mtok: u64,
    pub completion_uusd_per_mtok: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum CacheTtl {
    #[default]
    None,
    M5,
    H1,
}

impl CacheTtl {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::M5 => "5m",
            Self::H1 => "1h",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::None, Self::M5, Self::H1].into_iter().find(|t| t.as_str() == s)
    }
}

/// What the body says, for the route-header check (03 §7.1). The Gateway computes the
/// route header with [`analyze`]; the Worker recomputes it in [`prepare`]: one function,
/// so the deterministic estimate always matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// `model` as written in the body (public slug or a native alias).
    pub model: String,
    pub max_tokens: u64,
    /// Effective effort: the body's, else the catalog default.
    pub effort: Effort,
    /// `ceil(text_bytes / 3) + images × max_image_tokens + pages × max_page_tokens`.
    pub est_input_tokens: u64,
    pub cache_ttl: CacheTtl,
    pub stream: bool,
    /// Opt-in features the request uses.
    pub flags: Flags,
    /// Body bytes minus inline base64 image data.
    pub text_bytes: u64,
    pub images: u64,
    /// PDF pages across all documents (≤ [`MAX_PDF_PAGES`]).
    pub pages: u64,
}

/// The route header fields the Worker checks against the body.
#[derive(Clone, Copy, Debug)]
pub struct Route<'a> {
    pub dialect: Dialect,
    /// Public model id plus its catalog aliases; the body's `model` must be one of them.
    pub model_aliases: &'a [&'a str],
    pub effort: Effort,
    pub max_tokens: u64,
    pub est_input_tokens: u64,
    pub cache_ttl: CacheTtl,
    pub stream: bool,
    pub flags: Flags,
}

impl Facts {
    /// 03 §7.1: every field must match exactly, else `route_mismatch` (non-retryable).
    pub fn check_route(&self, dialect: Dialect, route: &Route<'_>) -> Result<(), Reject> {
        let bad = |field: &str| Err(Reject::new(RejectCode::RouteMismatch, format!("route.{field}"), "does not match the body"));
        if route.dialect != dialect {
            return bad("dialect");
        }
        if !route.model_aliases.contains(&self.model.as_str()) {
            return bad("model");
        }
        if route.effort != self.effort {
            return bad("effort");
        }
        if route.max_tokens != self.max_tokens {
            return bad("max_tokens");
        }
        if route.est_input_tokens != self.est_input_tokens {
            return bad("est_input_tokens");
        }
        if route.cache_ttl != self.cache_ttl {
            return bad("cache_ttl");
        }
        if route.stream != self.stream {
            return bad("stream");
        }
        if route.flags != self.flags {
            return bad("flags");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectCode {
    /// Disallowed field, feature or value (NACK `firewall`, non-retryable).
    Firewall,
    /// Route header ≠ body (NACK `route_mismatch`, non-retryable).
    RouteMismatch,
    /// This adapter cannot serve the request (NACK `model_unavailable`, retryable elsewhere).
    Unsupported,
}

impl RejectCode {
    /// NACK code (03 §10.2) and whether another worker may retry.
    pub fn nack(self) -> (&'static str, bool) {
        match self {
            Self::Firewall => ("firewall", false),
            Self::RouteMismatch => ("route_mismatch", false),
            Self::Unsupported => ("model_unavailable", true),
        }
    }
}

/// A refusal with its precise reason. `to_string()` is the sealed detail for the Gateway
/// (field names and short enum values only, never prompt text).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    pub code: RejectCode,
    pub path: String,
    pub reason: Cow<'static, str>,
}

impl Reject {
    fn new(code: RejectCode, path: impl Into<String>, reason: impl Into<Cow<'static, str>>) -> Self {
        Self { code, path: path.into(), reason: reason.into() }
    }
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() { write!(f, "request {}", self.reason) } else { write!(f, "field `{}` {}", self.path, self.reason) }
    }
}

impl std::error::Error for Reject {}

/// Everything the Worker needs to call the provider.
#[derive(Debug)]
pub struct Request<'a> {
    pub provider: Provider,
    pub dialect: Dialect,
    /// The exact body the Gateway sent (after `body_sha256` was checked).
    pub body: &'a [u8],
    /// Provider headers from the inner payload (`anthropic-version`, `anthropic-beta`).
    pub headers: &'a [(&'a str, &'a str)],
    pub policy: &'a Policy,
    pub catalog: &'a Catalog,
    /// The catalog's provider model id for the route's public model.
    pub provider_model_id: &'a str,
    /// `H(repo_id ‖ member_id)`, set as `metadata.user_id` (or the OpenAI-style equivalent).
    pub user_pseudonym: &'a str,
    /// Required for OpenRouter.
    pub max_price: Option<MaxPrice>,
}

/// A validated, mutated request ready for [`crate::provider::Adapter::send`].
#[derive(Debug)]
pub struct Prepared {
    pub facts: Facts,
    /// Re-serialized from the validated tree, with the safe mutations applied.
    pub body: Bytes,
    /// Allowlisted provider headers to forward.
    pub headers: Vec<(&'static str, String)>,
}

/// Validate a body and compute its route facts without mutating it (Gateway side, or a
/// Worker that only wants the facts). Uses `policy` for gating.
pub fn analyze(dialect: Dialect, body: &[u8], headers: &[(&str, &str)], policy: &Policy, catalog: &Catalog) -> Result<Facts, Reject> {
    let mut tape = Vec::new();
    let (facts, _, _) = check(dialect, body, headers, *policy, catalog, &mut tape)?;
    Ok(facts)
}

/// What [`pool_compatible`] produced: the body and headers to seal, and what was removed.
#[derive(Debug)]
pub struct PoolRequest {
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    /// Removed members, beta values and headers (for a visible `[moochy]` note and logs).
    pub stripped: Vec<String>,
}

/// Gateway side, before sealing: drop what a pooled donor would refuse although the client can
/// do without it, so real clients (Claude Code's `safeguards` classifier, unknown betas,
/// `anthropic-dangerous-direct-browser-access`) work through the pool. Strips only:
/// top-level members in the strip list, beta values outside the allowlist, and headers other
/// than `anthropic-version` / `anthropic-beta`. Everything else is left for [`analyze`] to
/// accept or refuse. The body is re-serialized canonically from the strict parse.
pub fn pool_compatible(dialect: Dialect, body: &[u8], headers: &[(&str, &str)]) -> Result<PoolRequest, Reject> {
    let mut tape = Vec::new();
    let root = json::parse(body, &mut tape).map_err(|e| Reject::new(RejectCode::Firewall, "", format!("is not strict JSON ({e})")))?.root();
    let mut stripped = Vec::new();
    let mut out = Vec::with_capacity(body.len());
    if root.kind() == Kind::Obj && dialect == Dialect::AnthropicMessages {
        out.push(b'{');
        let mut first = true;
        for (k, v) in root.entries() {
            if let Some(name) = tables::POOL_STRIP.iter().find(|n| k.is_str(n)) {
                stripped.push((*name).to_owned());
                continue;
            }
            if !std::mem::replace(&mut first, false) {
                out.push(b',');
            }
            json::write(k, &mut out);
            out.push(b':');
            json::write(v, &mut out);
        }
        out.push(b'}');
    } else {
        json::write(root, &mut out);
    }
    let mut kept = Vec::new();
    for (name, value) in headers {
        let lname = name.to_ascii_lowercase();
        match lname.as_str() {
            "anthropic-version" if dialect == Dialect::AnthropicMessages => kept.push((lname, (*value).to_owned())),
            "anthropic-beta" if dialect == Dialect::AnthropicMessages => {
                let mut ok = Vec::new();
                for b in value.split(',').map(str::trim).filter(|b| !b.is_empty()) {
                    if tables::ANTHROPIC_BETAS.iter().any(|(a, _)| *a == b) {
                        ok.push(b);
                    } else {
                        stripped.push(format!("anthropic-beta: {}", b.chars().take(64).collect::<String>()));
                    }
                }
                if !ok.is_empty() {
                    kept.push((lname, ok.join(",")));
                }
            }
            _ => stripped.push(format!("header {}", lname.chars().take(64).collect::<String>())),
        }
    }
    Ok(PoolRequest { body: out, headers: kept, stripped })
}

/// Firewall + route facts + safe mutations (06 §7.1–7.2), in one pass over one parse.
pub fn prepare(req: &Request<'_>) -> Result<Prepared, Reject> {
    if !req.provider.serves(req.dialect) {
        return Err(Reject::new(RejectCode::Unsupported, "", "uses a dialect this provider does not serve"));
    }
    if req.provider_model_id.is_empty() || req.provider_model_id.len() > MAX_MODEL_LEN {
        return Err(Reject::new(RejectCode::Unsupported, "", "has no catalog mapping for this provider"));
    }
    if req.provider == Provider::Local && is_cloud_routed(req.provider_model_id) {
        return Err(Reject::new(RejectCode::Unsupported, "", "maps to a cloud-routed model (e.g. Ollama `*-cloud`): a local donor serves local models only"));
    }
    let mut tape = Vec::new();
    let (facts, headers, root) = check(req.dialect, req.body, req.headers, *req.policy, req.catalog, &mut tape)?;
    // Fields the shared dialect table allows but this provider's API does not have.
    if let Some((field, why)) = tables::provider_denies(req.provider, req.dialect).iter().find(|(f, _)| root.get(f).is_some()) {
        return Err(Reject::new(RejectCode::Firewall, *field, format!("is not allowed: {why}")));
    }

    let enc = |s: &str| {
        let mut v = Vec::with_capacity(s.len().saturating_add(2));
        json::push_str(&mut v, s);
        v
    };
    let model = enc(req.provider_model_id);
    let user = enc(req.user_pseudonym);
    let max_out = facts.max_tokens.to_string();
    let (prompt, completion);
    let mut patches: Vec<Patch<'_>> = vec![Patch { path: &["model"], json: &model }];
    match req.dialect {
        Dialect::AnthropicMessages => patches.push(Patch { path: &["metadata", "user_id"], json: &user }),
        Dialect::OpenAiChat => {
            if facts.stream {
                patches.push(Patch { path: &["stream_options", "include_usage"], json: b"true" });
            }
            match req.provider {
                Provider::OpenAi => {
                    patches.push(Patch { path: &["safety_identifier"], json: &user });
                    patches.push(Patch { path: &["store"], json: b"false" });
                }
                Provider::OpenRouter => {
                    patches.push(Patch { path: &["user"], json: &user });
                    patches.push(Patch { path: &["usage", "include"], json: b"true" });
                }
                // xAI documents `safety_identifier` for end-user attribution.
                Provider::XAi => patches.push(Patch { path: &["safety_identifier"], json: &user }),
                // Local servers: no end-user id (nothing to attribute abuse to on the donor's own box).
                Provider::DeepSeek | Provider::Anthropic | Provider::Local => {}
            }
        }
        // §18.6: stateless (OpenAI and xAI store responses by default) and output-bounded.
        Dialect::OpenAiResponses => {
            patches.push(Patch { path: &["store"], json: b"false" });
            patches.push(Patch { path: &["max_output_tokens"], json: max_out.as_bytes() });
            match req.provider {
                Provider::OpenAi | Provider::XAi => patches.push(Patch { path: &["safety_identifier"], json: &user }),
                Provider::OpenRouter => patches.push(Patch { path: &["user"], json: &user }),
                Provider::DeepSeek | Provider::Anthropic | Provider::Local => {}
            }
        }
    }
    if req.provider == Provider::OpenRouter {
        let Some(mp) = req.max_price else {
            return Err(Reject::new(RejectCode::Unsupported, "", "has no catalog max price for OpenRouter"));
        };
        prompt = dollars(mp.prompt_uusd_per_mtok);
        completion = dollars(mp.completion_uusd_per_mtok);
        patches.push(Patch { path: &["provider", "max_price", "prompt"], json: prompt.as_bytes() });
        patches.push(Patch { path: &["provider", "max_price", "completion"], json: completion.as_bytes() });
        patches.push(Patch { path: &["provider", "allow_fallbacks"], json: b"false" });
    }
    let mut out = Vec::with_capacity(req.body.len().saturating_add(256));
    json::write_patched(root, &patches, &mut out);
    Ok(Prepared { facts, body: Bytes::from(out), headers })
}

/// A model id a "local" server would forward to a remote service: Ollama routes tags such as
/// `gpt-oss:120b-cloud` / `model:cloud` to ollama.com (content leaves the machine, billed to the
/// donor's account). Refused for [`Provider::Local`].
pub fn is_cloud_routed(model_id: &str) -> bool {
    let m = model_id.to_ascii_lowercase();
    m.rsplit_once(':').is_some_and(|(_, tag)| tag == "cloud" || tag.ends_with("-cloud")) || m.ends_with("-cloud")
}

/// µ$ per million tokens → a JSON decimal in dollars per million tokens.
fn dollars(uusd: u64) -> String {
    let whole = uusd.checked_div(1_000_000).unwrap_or(0);
    let frac = uusd.checked_rem(1_000_000).unwrap_or(0);
    if frac == 0 {
        return whole.to_string();
    }
    let f = format!("{frac:06}");
    format!("{whole}.{}", f.trim_end_matches('0'))
}

type Checked<'a> = (Facts, Vec<(&'static str, String)>, Val<'a>);

fn ceiling_for(policy: Policy, catalog: &Catalog) -> u64 {
    match policy.level {
        Level::Strict => catalog.max_output,
        Level::Paranoid => catalog.max_output.min(PARANOID_MAX_TOKENS),
    }
}

fn check<'a>(
    dialect: Dialect,
    body: &'a [u8],
    headers: &[(&str, &str)],
    policy: Policy,
    catalog: &Catalog,
    tape: &'a mut Vec<json::Node>,
) -> Result<Checked<'a>, Reject> {
    let fw = |path: &str, reason: Cow<'static, str>| Reject::new(RejectCode::Firewall, path, reason);
    if body.len() > MAX_BODY {
        return Err(fw("", "is larger than 32 MiB".into()));
    }
    let doc = json::parse(body, tape).map_err(|e| fw("", format!("is not strict JSON ({e})").into()))?;
    let root = doc.root();
    let mut w = Walk { policy, path: Vec::new(), acc: Acc::default() };
    let top = match dialect {
        Dialect::AnthropicMessages => &tables::ANTHROPIC,
        Dialect::OpenAiChat => &tables::OPENAI,
        Dialect::OpenAiResponses => &tables::RESPONSES,
    };
    w.check(top, root, None)?;
    let out_headers = w.headers(dialect, headers)?;

    let model = root.get("model").and_then(Val::as_str).unwrap_or_default().into_owned();
    if model.is_empty() || model.len() > MAX_MODEL_LEN {
        return Err(fw("model", "must be a non-empty model id".into()));
    }
    let (max_tokens, effort) = match dialect {
        Dialect::AnthropicMessages => (
            root.get("max_tokens").and_then(Val::as_u64),
            root.get("output_config").and_then(|o| o.get("effort")),
        ),
        Dialect::OpenAiChat => {
            let (a, b) = (root.get("max_tokens"), root.get("max_completion_tokens"));
            if a.is_some() && b.is_some() {
                return Err(fw("max_completion_tokens", "must not be sent together with `max_tokens`".into()));
            }
            (a.or(b).and_then(Val::as_u64), root.get("reasoning_effort"))
        }
        // Codex sends no `max_output_tokens`: the catalog ceiling bounds it (and `prepare`
        // writes it into the provider request, so cost stays bounded by the route).
        Dialect::OpenAiResponses => (
            Some(root.get("max_output_tokens").and_then(Val::as_u64).unwrap_or_else(|| ceiling_for(policy, catalog))),
            root.get("reasoning").and_then(|r| r.get("effort")).filter(|e| !e.is_null()),
        ),
    };
    let Some(max_tokens) = max_tokens else {
        return Err(fw("max_tokens", "is required".into()));
    };
    let ceiling = ceiling_for(policy, catalog);
    if max_tokens == 0 || max_tokens > ceiling {
        return Err(fw("max_tokens", format!("must be between 1 and {ceiling}").into()));
    }
    let effort = match effort {
        None => catalog.default_effort,
        Some(e) => e.as_str().as_deref().and_then(Effort::parse).ok_or_else(|| fw("effort", "is not a known effort".into()))?,
    };
    // Per-turn efforts can only raise the effective effort (cost bound, 05 §5.1).
    let effort = effort.max(w.acc.turn_effort.unwrap_or(Effort::None));
    if effort > policy.max_effort {
        return Err(fw("effort", format!("`{}` exceeds the pledge maximum `{}`", effort.as_str(), policy.max_effort.as_str()).into()));
    }
    let stream = root.get("stream").and_then(Val::as_bool).unwrap_or(false);

    let len = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let text_bytes = len.saturating_sub(w.acc.excluded);
    let images = w.acc.images.checked_mul(catalog.max_image_tokens).ok_or_else(|| fw("", "has too many images".into()))?;
    let pages = w.acc.pages.checked_mul(catalog.max_page_tokens).ok_or_else(|| fw("", "has too many pages".into()))?;
    let est_input_tokens =
        text_bytes.div_ceil(3).checked_add(images).and_then(|x| x.checked_add(pages)).ok_or_else(|| fw("", "is too large".into()))?;
    let facts = Facts {
        model,
        max_tokens,
        effort,
        est_input_tokens,
        cache_ttl: w.acc.ttl,
        stream,
        flags: w.acc.flags,
        text_bytes,
        images: w.acc.images,
        pages: w.acc.pages,
    };
    Ok((facts, out_headers, root))
}

// ---------------------------------------------------------------------------------------
// The table language and its interpreter.

/// One allowlist rule. Tables in `tables.rs` are built from these.
pub(crate) enum R {
    /// Any JSON value (already strict-parsed): tool schemas, tool inputs.
    Any,
    Null,
    Str,
    Bool,
    Num,
    /// Integer ≥ 0.
    UInt,
    /// One of these strings.
    Enum(&'static [&'static str]),
    Arr(&'static R),
    /// Closed object: unknown members are rejected.
    Obj(&'static [F]),
    /// The first rule whose JSON kind matches the value.
    OneOf(&'static [R]),
    /// Object discriminated by member `key`; `cases` are `(pattern, rule)` where pattern is
    /// an exact tag, `prefix_*` (prefix + date digits), or `""` (tag absent). The tag member
    /// itself is implicitly allowed in the case's object rule.
    Tagged { key: &'static str, cases: &'static [(&'static str, R)] },
    /// Explicitly denied, with the reason shown to the Gateway.
    Deny(&'static str),
    /// Validate the inner rule, then run a gate or fact-collecting hook.
    Hook(Hook, &'static R),
}

/// Object member: name, rule, required.
pub(crate) struct F(pub &'static str, pub R, pub bool);

#[derive(Clone, Copy)]
pub(crate) enum Hook {
    Image,
    Document,
    /// Base64 PDF data: strict decode, page count, ≤ 100 pages, excluded from `text_bytes`.
    Pdf,
    CacheControl,
    /// Inline base64 payload: excluded from `text_bytes`.
    B64,
    /// OpenAI `image_url.url`: only `data:image/...` URLs.
    DataUrl,
    Speed,
    ServiceTier,
    InferenceGeo,
    /// OpenAI `n`: must be 1.
    One,
    /// Per-turn `output_config.effort` (Anthropic `per-turn-control`): tracked, max wins.
    TurnEffort,
    /// Must be `false` (Responses `store`, `background`: stateless only).
    False,
}

#[derive(Default)]
struct Acc {
    turn_effort: Option<Effort>,
    images: u64,
    pages: u64,
    excluded: u64,
    flags: Flags,
    ttl: CacheTtl,
}

enum Seg<'a> {
    Key(&'a str),
    Idx(usize),
}

struct Walk<'a> {
    policy: Policy,
    path: Vec<Seg<'a>>,
    acc: Acc,
}

fn kind_of(r: &R) -> Option<Kind> {
    Some(match r {
        R::Any | R::Deny(_) | R::OneOf(_) => return None,
        R::Null => Kind::Null,
        R::Str | R::Enum(_) => Kind::Str,
        R::Bool => Kind::Bool,
        R::Num | R::UInt => Kind::Num,
        R::Arr(_) => Kind::Arr,
        R::Obj(_) | R::Tagged { .. } => Kind::Obj,
        R::Hook(_, inner) => return kind_of(inner),
    })
}

fn tag_matches(pattern: &str, tag: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => tag.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())),
        None => pattern == tag,
    }
}

/// Short, safe rendering of an offending enum-ish value.
fn shown(v: Val<'_>) -> String {
    let s = v.as_str().unwrap_or(Cow::Borrowed(v.raw()));
    let s: String = s.chars().take(48).filter(|c| !c.is_control() && *c != '`').collect();
    s
}

impl<'a> Walk<'a> {
    fn path_str(&self) -> String {
        let mut s = String::new();
        for seg in &self.path {
            match seg {
                Seg::Key(k) => {
                    if !s.is_empty() {
                        s.push('.');
                    }
                    s.extend(k.chars().take(64));
                }
                Seg::Idx(i) => {
                    s.push('[');
                    s.push_str(&i.to_string());
                    s.push(']');
                }
            }
        }
        s
    }

    fn fail<T>(&self, reason: impl Into<Cow<'static, str>>) -> Result<T, Reject> {
        Err(Reject::new(RejectCode::Firewall, self.path_str(), reason))
    }

    fn check(&mut self, rule: &R, v: Val<'a>, skip: Option<&str>) -> Result<(), Reject> {
        let want = |k: Kind, what: &'static str| if v.kind() == k { Ok(()) } else { self.fail(what) };
        match rule {
            R::Any => Ok(()),
            R::Null => want(Kind::Null, "must be null"),
            R::Str => want(Kind::Str, "must be a string"),
            R::Bool => want(Kind::Bool, "must be a boolean"),
            R::Num => want(Kind::Num, "must be a number"),
            R::UInt => {
                if v.as_u64().is_some() {
                    Ok(())
                } else {
                    self.fail("must be a non-negative integer")
                }
            }
            R::Enum(opts) => {
                want(Kind::Str, "must be a string")?;
                if opts.iter().any(|o| v.is_str(o)) { Ok(()) } else { self.fail(format!("value `{}` is not allowed", shown(v))) }
            }
            R::Arr(item) => {
                want(Kind::Arr, "must be an array")?;
                for (n, it) in v.items().enumerate() {
                    self.path.push(Seg::Idx(n));
                    self.check(item, it, None)?;
                    self.path.pop();
                }
                Ok(())
            }
            R::Obj(fields) => self.obj(fields, v, skip),
            R::OneOf(rules) => match rules.iter().find(|r| kind_of(r).is_none_or(|k| k == v.kind())) {
                Some(r) => self.check(r, v, None),
                None => self.fail("has the wrong type"),
            },
            R::Tagged { key, cases } => {
                want(Kind::Obj, "must be an object")?;
                let tag = v.get(key);
                let case = match tag {
                    None => cases.iter().find(|(p, _)| p.is_empty()),
                    Some(t) => {
                        let ts = t.as_str();
                        let Some(ts) = ts else {
                            self.path.push(Seg::Key(key));
                            return self.fail("must be a string");
                        };
                        cases.iter().find(|(p, _)| !p.is_empty() && tag_matches(p, &ts))
                    }
                };
                let Some((_, r)) = case else {
                    self.path.push(Seg::Key(key));
                    return match tag {
                        None => self.fail("is required"),
                        Some(t) => self.fail(format!("value `{}` is not allowed", shown(t))),
                    };
                };
                if let R::Deny(why) = r {
                    self.path.push(Seg::Key(key));
                    let t = tag.map(shown).unwrap_or_default();
                    return self.fail(format!("value `{t}` is not allowed: {why}"));
                }
                self.check(r, v, Some(key))
            }
            R::Deny(why) => self.fail(format!("is not allowed: {why}")),
            R::Hook(h, inner) => {
                self.check(inner, v, skip)?;
                self.hook(*h, v)
            }
        }
    }

    fn obj(&mut self, fields: &[F], v: Val<'a>, skip: Option<&str>) -> Result<(), Reject> {
        if v.kind() != Kind::Obj {
            return self.fail("must be an object");
        }
        for (k, val) in v.entries() {
            if skip.is_some_and(|s| k.is_str(s)) {
                continue;
            }
            self.path.push(Seg::Key(k.raw()));
            let Some(f) = fields.iter().find(|f| k.is_str(f.0)) else {
                return self.fail("is not allowed");
            };
            self.check(&f.1, val, None)?;
            self.path.pop();
        }
        for f in fields.iter().filter(|f| f.2) {
            if v.get(f.0).is_none() {
                self.path.push(Seg::Key(f.0));
                return self.fail("is required");
            }
        }
        Ok(())
    }

    fn need(&self, flag: Flags, what: &'static str) -> Result<(), Reject> {
        if self.policy.flags.has(flag) { Ok(()) } else { self.fail(what) }
    }

    fn hook(&mut self, h: Hook, v: Val<'a>) -> Result<(), Reject> {
        let raw_len = || u64::try_from(v.raw().len()).unwrap_or(u64::MAX);
        match h {
            Hook::Image | Hook::Document => {
                let (flag, name) = if matches!(h, Hook::Image) { (Flags::IMAGES, "image") } else { (Flags::DOCUMENTS, "document") };
                if self.policy.level == Level::Paranoid {
                    return self.fail(format!("is not allowed: {name} input is disabled at the paranoid level"));
                }
                self.need(flag, if matches!(h, Hook::Image) { "is not allowed: images need the `images` opt-in" } else { "is not allowed: documents need the `documents` opt-in" })?;
                self.acc.flags = self.acc.flags.with(flag);
                if matches!(h, Hook::Image) {
                    self.acc.images = self.acc.images.saturating_add(1);
                }
            }
            Hook::Pdf => {
                self.need(Flags::DOCUMENTS, "is not allowed: documents need the `documents` opt-in")?;
                let s = v.as_str().unwrap_or_default();
                let Ok(pdf) = base64::engine::general_purpose::STANDARD.decode(s.as_bytes()) else {
                    return self.fail("is not valid base64");
                };
                let Some(pages) = pdf_pages(&pdf) else {
                    return self.fail("is not allowed: the PDF page count cannot be determined (not a PDF, or pages only in compressed object streams)");
                };
                self.acc.pages = self.acc.pages.saturating_add(pages);
                if self.acc.pages > MAX_PDF_PAGES {
                    return self.fail(format!("is not allowed: documents exceed {MAX_PDF_PAGES} pages"));
                }
                self.acc.excluded = self.acc.excluded.saturating_add(raw_len());
            }
            Hook::CacheControl => {
                let ttl = if v.get("ttl").is_some_and(|t| t.is_str("1h")) { CacheTtl::H1 } else { CacheTtl::M5 };
                self.acc.ttl = self.acc.ttl.max(ttl);
            }
            Hook::B64 => self.acc.excluded = self.acc.excluded.saturating_add(raw_len()),
            Hook::DataUrl => {
                if !v.as_str().is_some_and(|s| s.starts_with("data:image/")) {
                    return self.fail("is not allowed: only inline `data:image/` URLs (the provider would fetch URLs)");
                }
                self.acc.excluded = self.acc.excluded.saturating_add(raw_len());
            }
            Hook::Speed => {
                if v.is_str("fast") {
                    self.need(Flags::FAST, "is not allowed: `fast` needs the `fast` opt-in (price multiplier)")?;
                    self.acc.flags = self.acc.flags.with(Flags::FAST);
                }
            }
            Hook::ServiceTier => {
                self.need(Flags::SERVICE_TIER, "is not allowed: the service tier is the donor's call")?;
                self.acc.flags = self.acc.flags.with(Flags::SERVICE_TIER);
            }
            Hook::InferenceGeo => {
                self.need(Flags::INFERENCE_GEO, "is not allowed: data residency is the donor's call")?;
                // F20: a regional value is billed at a premium (US-only: 1.1x) that the catalog
                // does not price; the receipt and every limit would under-count it.
                if !v.is_str("global") {
                    return self.fail("is not allowed: only `global` (regional inference costs a premium Moochy does not price)");
                }
                self.acc.flags = self.acc.flags.with(Flags::INFERENCE_GEO);
            }
            Hook::TurnEffort => {
                let e = v.as_str().as_deref().and_then(Effort::parse);
                self.acc.turn_effort = self.acc.turn_effort.max(e);
            }
            Hook::False => {
                if v.as_bool() != Some(false) {
                    return self.fail(format!("must be false: {}", tables::STATELESS_WHY));
                }
            }
            Hook::One => {
                if v.as_u64() != Some(1) {
                    return self.fail("must be 1 (n > 1 multiplies output beyond max_tokens)");
                }
            }
        }
        Ok(())
    }

    /// Header-value allowlist (06 §7.1): only for the Anthropic dialect.
    fn headers(&mut self, dialect: Dialect, given: &[(&str, &str)]) -> Result<Vec<(&'static str, String)>, Reject> {
        let fw = |name: &str, reason: Cow<'static, str>| Err(Reject::new(RejectCode::Firewall, format!("header {name}"), reason));
        let mut version: Option<&'static str> = None;
        let mut betas: Option<Vec<&'static str>> = None;
        for (name, value) in given {
            let name = name.to_ascii_lowercase();
            if dialect != Dialect::AnthropicMessages {
                return fw(&name, "is not allowed for this dialect".into());
            }
            match name.as_str() {
                "anthropic-version" => {
                    if version.is_some() {
                        return fw(&name, "is duplicated".into());
                    }
                    let Some(v) = tables::ANTHROPIC_VERSIONS.iter().find(|v| *v == value) else {
                        return fw(&name, "value is not allowed".into());
                    };
                    version = Some(v);
                }
                "anthropic-beta" => {
                    if betas.is_some() {
                        return fw(&name, "is duplicated".into());
                    }
                    let mut list = Vec::new();
                    for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        let Some((b, flag)) = tables::ANTHROPIC_BETAS.iter().find(|(b, _)| *b == item) else {
                            let shown: String = item.chars().take(64).filter(|c| !c.is_control() && *c != '`').collect();
                            return fw(&name, format!("value `{shown}` is not allowed").into());
                        };
                        if *flag != Flags::NONE {
                            if !self.policy.flags.has(*flag) {
                                return fw(&name, format!("value `{b}` needs the `{flag}` opt-in").into());
                            }
                            self.acc.flags = self.acc.flags.with(*flag);
                        }
                        if !list.contains(b) {
                            list.push(*b);
                        }
                    }
                    betas = Some(list);
                }
                _ => return fw(&name, "is not allowed".into()),
            }
        }
        let mut out = Vec::new();
        if dialect == Dialect::AnthropicMessages {
            out.push(("anthropic-version", version.unwrap_or(tables::ANTHROPIC_VERSION_DEFAULT).to_owned()));
            if let Some(b) = betas.filter(|b| !b.is_empty()) {
                out.push(("anthropic-beta", b.join(",")));
            }
        }
        Ok(out)
    }
}

/// Pages of a PDF, deterministically (the Gateway and the Worker must agree):
/// `max(number of "/Type /Page" objects, largest "/Count")`. `None` when the bytes are not a
/// PDF or no page object is visible (page tree only inside compressed object streams): such
/// documents are refused rather than under-estimated. Over-counting only raises the
/// reservation.
pub fn pdf_pages(b: &[u8]) -> Option<u64> {
    const DELIM: &[u8] = b" \t\r\n\x0c\x00()<>[]{}/%";
    let head = b.get(..b.len().min(1024))?;
    head.windows(5).position(|w| w == b"%PDF-")?;
    let ws = |c: u8| b" \t\r\n\x0c\x00".contains(&c);
    let skip_ws = |mut i: usize| {
        while b.get(i).is_some_and(|c| ws(*c)) {
            i = i.saturating_add(1);
        }
        i
    };
    let (mut objects, mut count) = (0u64, 0u64);
    let mut i = 0usize;
    while let Some(off) = b.get(i..).and_then(|r| r.windows(5).position(|w| w == b"/Type" || w == b"/Coun")) {
        let at = i.saturating_add(off);
        i = at.saturating_add(5);
        if b.get(at..at.saturating_add(5)) == Some(b"/Type") {
            let j = skip_ws(i);
            if b.get(j..j.saturating_add(5)) == Some(b"/Page") && b.get(j.saturating_add(5)).is_none_or(|c| DELIM.contains(c)) {
                objects = objects.saturating_add(1);
            }
        } else if b.get(at..at.saturating_add(6)) == Some(b"/Count") {
            let mut j = skip_ws(at.saturating_add(6));
            let mut n = 0u64;
            let start = j;
            while let Some(d) = b.get(j).filter(|c| c.is_ascii_digit()) {
                n = n.saturating_mul(10).saturating_add(u64::from(d.wrapping_sub(b'0')));
                j = j.saturating_add(1);
            }
            if j > start {
                count = count.max(n);
            }
        }
    }
    let pages = objects.max(count);
    (pages > 0).then_some(pages)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pdf_page_counting() {
        let pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n4 0 obj <</Type/Page/Parent 2 0 R>> endobj\n%%EOF";
        assert_eq!(pdf_pages(pdf), Some(2));
        // /Count larger than the visible page objects (some in object streams): take the max.
        assert_eq!(pdf_pages(b"%PDF-1.7\n<< /Type /Pages /Count 37 >> << /Type /Page >>"), Some(37));
        assert_eq!(pdf_pages(b"%PDF-1.7\n<< /Type /ObjStm /N 40 >> stream compressed endstream"), None);
        assert_eq!(pdf_pages(b"not a pdf /Type /Page"), None);
        assert_eq!(pdf_pages(b"%PDF-1.4 /Type /Pages"), None, "/Pages is not a page");
        assert_eq!(pdf_pages(b"%PDF-1.4 /Count 99999999999999999999999 /Type /Page"), Some(u64::MAX));
    }

    #[test]
    fn dollars_format() {
        assert_eq!(dollars(2_000_000), "2");
        assert_eq!(dollars(150_000), "0.15");
        assert_eq!(dollars(1), "0.000001");
        assert_eq!(dollars(15_250_000), "15.25");
        assert_eq!(dollars(0), "0");
    }

    #[test]
    fn tags() {
        assert!(tag_matches("bash_*", "bash_20250124"));
        assert!(!tag_matches("bash_*", "bash_"));
        assert!(!tag_matches("bash_*", "bash_2025x"));
        assert!(tag_matches("text", "text"));
        assert!(!tag_matches("text", "texts"));
    }
}
