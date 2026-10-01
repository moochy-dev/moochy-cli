//! Money math (plan 05 §2–5) and the deterministic route facts of a provider body (plan 03 §7.1).
//!
//! All amounts are integer µ$ (`i64`). Prices are µ$ per **million** tokens. Every operation is
//! checked; anything that overflows is [`Error::Overflow`], never a wrapped value.

use crate::msg::{CacheTtl, Dialect, RouteHeader, Usage};
use crate::{Error, json};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PER_MILLION: u128 = 1_000_000;

/// One catalog row (plan 05 §2.2). Prices in µ$ per million tokens.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    /// Public slug, e.g. `anthropic/claude-sonnet-5.5`.
    pub model: String,
    /// `anthropic`, `openrouter`, `deepseek`, `openai`.
    pub provider: String,
    pub provider_model_id: String,
    /// Native ids the Gateway also accepts for this slug.
    #[serde(default)]
    pub aliases: Vec<String>,
    pub dialects: Vec<Dialect>,
    #[serde(rename = "in")]
    pub input: u64,
    pub out: u64,
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
    pub cache_read: u64,
    pub max_image_tokens: u64,
    pub max_page_tokens: u64,
    /// Integer price multiplier of the premium speed mode (applies only with the `fast` flag).
    #[serde(default = "one")]
    pub fast_multiplier: u32,
    pub default_effort: String,
    pub max_output: u32,
    #[serde(default)]
    pub source: String,
}

fn one() -> u32 {
    1
}

fn ceil_div(n: u128, d: u128) -> Result<i64, Error> {
    let q = n.checked_div(d).ok_or(Error::Overflow)?;
    let q = if n.checked_rem(d).ok_or(Error::Overflow)? == 0 { q } else { q.checked_add(1).ok_or(Error::Overflow)? };
    i64::try_from(q).map_err(|_| Error::Overflow)
}

fn mul(a: u64, b: u64) -> Result<u128, Error> {
    u128::from(a).checked_mul(u128::from(b)).ok_or(Error::Overflow)
}

/// Receipt cost (plan 05 §3): `ceil(Σ usage × price × fast / 1e6)`.
/// OpenRouter: the provider-reported cost (already µ$, rounded up) is authoritative and required;
/// every other provider MUST NOT carry one (a forged `provider_cost_uusd` is refused).
pub fn cost_uusd(c: &CatalogEntry, u: &Usage, fast: bool) -> Result<i64, Error> {
    let openrouter = c.provider == "openrouter";
    match (openrouter, u.provider_cost_uusd) {
        (true, Some(pc)) if pc >= 0 => return Ok(pc),
        (false, None) => {}
        _ => return Err(Error::Malformed),
    }
    let sum = [
        mul(u.input, c.input)?,
        mul(u.output, c.out)?,
        mul(u.cache_write_5m, c.cache_write_5m)?,
        mul(u.cache_write_1h, c.cache_write_1h)?,
        mul(u.cache_read, c.cache_read)?,
    ]
    .into_iter()
    .try_fold(0u128, u128::checked_add)
    .ok_or(Error::Overflow)?;
    let m = if fast { c.fast_multiplier } else { 1 };
    ceil_div(sum.checked_mul(u128::from(m)).ok_or(Error::Overflow)?, PER_MILLION)
}

/// Reservation (plan 05 §5.1):
/// `ceil((est_input × in × m_cache + max_tokens × out) × fast / 1e6)`,
/// `m_cache` = 5/4 for `5m`, 2 for `1h`, 1 otherwise — computed exactly over a common denominator.
pub fn reserve_uusd(c: &CatalogEntry, est_input: u64, max_tokens: u32, ttl: CacheTtl, fast: bool) -> Result<i64, Error> {
    let (num, den): (u64, u64) = match ttl {
        CacheTtl::None => (1, 1),
        CacheTtl::M5 => (5, 4),
        CacheTtl::H1 => (2, 1),
    };
    let input = mul(est_input, c.input)?.checked_mul(u128::from(num)).ok_or(Error::Overflow)?;
    let output = mul(max_tokens.into(), c.out)?.checked_mul(u128::from(den)).ok_or(Error::Overflow)?;
    let m = if fast { c.fast_multiplier } else { 1 };
    let n = input.checked_add(output).and_then(|s| s.checked_mul(u128::from(m))).ok_or(Error::Overflow)?;
    ceil_div(n, PER_MILLION.checked_mul(u128::from(den)).ok_or(Error::Overflow)?)
}

/// Reservation for a route header against a catalog entry.
pub fn reserve_for_route(c: &CatalogEntry, r: &RouteHeader) -> Result<i64, Error> {
    reserve_uusd(c, r.est_input_tokens, r.max_tokens, r.cache_ttl, r.flags.iter().any(|f| f == "fast"))
}

/// Exact decimal USD (JSON number text, e.g. OpenRouter's `usage.cost`: `0.0001234`, `1.5e-05`)
/// → µ$ rounded **up**. No floating point anywhere, so Go and Rust agree to the µ$.
/// Rejects negatives, `NaN`, hex, and anything that is not a JSON number.
pub fn usd_decimal_to_uusd_ceil(s: &str) -> Result<i64, Error> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return Err(Error::Malformed);
    }
    let (mantissa, exp_part) = match b.iter().position(|&c| c == b'e' || c == b'E') {
        Some(i) => (b.get(..i).unwrap_or_default(), Some(b.get(i.saturating_add(1)..).unwrap_or_default())),
        None => (b, None),
    };
    let (int, frac) = match mantissa.iter().position(|&c| c == b'.') {
        Some(i) => (mantissa.get(..i).unwrap_or_default(), Some(mantissa.get(i.saturating_add(1)..).unwrap_or_default())),
        None => (mantissa, None),
    };
    let digits = |d: &[u8]| !d.is_empty() && d.iter().all(u8::is_ascii_digit);
    // JSON grammar: int = 0 | [1-9][0-9]*; frac, if present, non-empty.
    if !digits(int) || (int.len() > 1 && int.first() == Some(&b'0')) || frac.is_some_and(|f| !digits(f)) {
        return Err(Error::Malformed);
    }
    let frac = frac.unwrap_or_default();
    let exp: i64 = match exp_part {
        None => 0,
        Some(e) => {
            let (neg, d) = match e.first() {
                Some(b'-') => (true, e.get(1..).unwrap_or_default()),
                Some(b'+') => (false, e.get(1..).unwrap_or_default()),
                _ => (false, e),
            };
            if !digits(d) || d.len() > 4 {
                return Err(Error::Malformed);
            }
            let v = d.iter().try_fold(0i64, |a, &c| a.checked_mul(10)?.checked_add(i64::from(digit(c)))).ok_or(Error::Overflow)?;
            if neg { v.checked_neg().ok_or(Error::Overflow)? } else { v }
        }
    };
    // value = M × 10^(exp − |frac|); µ$ = M × 10^(exp − |frac| + 6), rounded up.
    let all = int.iter().chain(frac.iter()).skip_while(|&&c| c == b'0');
    let mut m: u128 = 0;
    for &c in all {
        m = m.checked_mul(10).and_then(|m| m.checked_add(u128::from(digit(c)))).ok_or(Error::Overflow)?;
    }
    let flen = i64::try_from(frac.len()).map_err(|_| Error::Overflow)?;
    let k = exp.checked_sub(flen).and_then(|k| k.checked_add(6)).ok_or(Error::Overflow)?;
    if m == 0 {
        return Ok(0);
    }
    if k >= 0 {
        let p = 10u128.checked_pow(u32::try_from(k).map_err(|_| Error::Overflow)?).ok_or(Error::Overflow)?;
        i64::try_from(m.checked_mul(p).ok_or(Error::Overflow)?).map_err(|_| Error::Overflow)
    } else {
        // m < 10^39, so dividing by ≥ 10^39 leaves 0 remainder-positive → 1 µ$.
        match 10u128.checked_pow(u32::try_from(k.unsigned_abs()).map_err(|_| Error::Overflow)?) {
            Some(p) => ceil_div(m, p),
            None => Ok(1),
        }
    }
}

// ---------- deterministic route facts (plan 03 §7.1) ----------

/// Everything the route header asserts about a provider body that can be recomputed from it.
/// Gateway and Worker both call [`body_facts`] on the exact body bytes the client sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyFacts {
    /// `model` as written in the body (slug or native alias).
    pub model: String,
    /// Explicit effort (`output_config.effort` / `reasoning_effort`), if any.
    pub effort: Option<String>,
    pub max_tokens: u32,
    pub stream: bool,
    /// Longest `cache_control` TTL anywhere in the body.
    pub cache_ttl: CacheTtl,
    /// Anthropic `speed: "fast"`.
    pub fast: bool,
    /// Body length minus the bytes of inline image data.
    pub text_bytes: u64,
    pub images: u64,
    /// Pages across PDF documents.
    pub pages: u64,
}

impl BodyFacts {
    /// `ceil(text_bytes / 3) + images × max_image_tokens + pages × max_page_tokens`.
    pub fn est_input_tokens(&self, c: &CatalogEntry) -> Result<u64, Error> {
        let t = self.text_bytes.div_ceil(3);
        let i = self.images.checked_mul(c.max_image_tokens).ok_or(Error::Overflow)?;
        let p = self.pages.checked_mul(c.max_page_tokens).ok_or(Error::Overflow)?;
        t.checked_add(i).and_then(|x| x.checked_add(p)).ok_or(Error::Overflow)
    }

    /// Flags the body requires (each needs donor opt-in), sorted.
    #[must_use]
    pub fn flags(&self) -> Vec<String> {
        let mut f = Vec::new();
        if self.pages > 0 {
            f.push("documents".to_owned());
        }
        if self.fast {
            f.push("fast".to_owned());
        }
        if self.images > 0 {
            f.push("images".to_owned());
        }
        f
    }

    /// Build the route-header fields that derive from the body and catalog.
    pub fn route(&self, c: &CatalogEntry, dialect: Dialect, repo_id: crate::RepoId, affinity: [u8; 16]) -> Result<RouteHeader, Error> {
        Ok(RouteHeader {
            repo_id,
            dialect,
            model: c.model.clone(),
            effort: self.effort.clone().unwrap_or_else(|| c.default_effort.clone()),
            max_tokens: self.max_tokens,
            est_input_tokens: self.est_input_tokens(c)?,
            cache_ttl: self.cache_ttl,
            stream: self.stream,
            affinity: crate::B(affinity),
            flags: self.flags(),
        })
    }
}

/// Worker-side route check (plan 03 §7.1). `Err(field)` names the first mismatch; send
/// `nack{route_mismatch}` and seal the field name to the Gateway. `c` is the catalog entry the
/// Worker resolved for `route.model`; extra route flags beyond what the body needs are allowed
/// (they only restrict), missing ones are not.
pub fn check_route(route: &RouteHeader, f: &BodyFacts, c: &CatalogEntry) -> Result<(), &'static str> {
    let model_ok = route.model == c.model && (f.model == c.model || f.model == c.provider_model_id || c.aliases.contains(&f.model));
    let effort = f.effort.as_deref().unwrap_or(&c.default_effort);
    let checks: [(bool, &'static str); 8] = [
        (model_ok, "model"),
        (c.dialects.contains(&route.dialect), "dialect"),
        (route.effort == effort, "effort"),
        (route.max_tokens == f.max_tokens && f.max_tokens <= c.max_output, "max_tokens"),
        (f.est_input_tokens(c).ok() == Some(route.est_input_tokens), "est_input_tokens"),
        (route.cache_ttl == f.cache_ttl, "cache_ttl"),
        (route.stream == f.stream, "stream"),
        (f.flags().iter().all(|x| route.flags.contains(x)), "flags"),
    ];
    match checks.into_iter().find(|(ok, _)| !ok) {
        Some((_, field)) => Err(field),
        None => Ok(()),
    }
}

/// Extract [`BodyFacts`] from a provider request body. Strict JSON (CONTRACT §1).
/// `max_tokens` is required (Anthropic: `max_tokens`; OpenAI: `max_completion_tokens` or
/// `max_tokens`, and if both are present they must be equal).
pub fn body_facts(dialect: Dialect, body: &[u8]) -> Result<BodyFacts, Error> {
    let v = json::parse_value(body)?;
    let o = v.as_object().ok_or(Error::Malformed)?;
    let str_field = |k: &str| match o.get(k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Error::Malformed),
    };
    let u32_field = |k: &str| match o.get(k) {
        None => Ok(None),
        Some(x) => x.as_u64().and_then(|n| u32::try_from(n).ok()).map(Some).ok_or(Error::Malformed),
    };
    let model = str_field("model")?.ok_or(Error::Malformed)?;
    let stream = match o.get("stream") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(Error::Malformed),
    };
    let (max_tokens, effort, fast) = match dialect {
        Dialect::AnthropicMessages => {
            let effort = match o.get("output_config").and_then(|c| c.get("effort")) {
                None => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => return Err(Error::Malformed),
            };
            let fast = str_field("speed")?.as_deref() == Some("fast");
            (u32_field("max_tokens")?, effort, fast)
        }
        Dialect::OpenAiChat => {
            let mt = match (u32_field("max_completion_tokens")?, u32_field("max_tokens")?) {
                (Some(a), Some(b)) if a != b => return Err(Error::Malformed),
                (a, b) => a.or(b),
            };
            (mt, str_field("reasoning_effort")?, false)
        }
    };
    let mut w = Walk { cache_ttl: CacheTtl::None, images: 0, pages: 0, image_bytes: 0 };
    w.walk(&v)?;
    let text_bytes = u64::try_from(body.len())
        .ok()
        .and_then(|n| n.checked_sub(w.image_bytes))
        .ok_or(Error::Overflow)?;
    Ok(BodyFacts {
        model,
        effort,
        max_tokens: max_tokens.ok_or(Error::Malformed)?,
        stream,
        cache_ttl: w.cache_ttl,
        fast,
        text_bytes,
        images: w.images,
        pages: w.pages,
    })
}

struct Walk {
    cache_ttl: CacheTtl,
    images: u64,
    pages: u64,
    image_bytes: u64,
}

const PDF_DATA_URL: &str = "data:application/pdf;base64,";

impl Walk {
    // Depth is bounded by json::MAX_DEPTH (checked before parsing).
    fn walk(&mut self, v: &Value) -> Result<(), Error> {
        match v {
            Value::Array(a) => a.iter().try_for_each(|x| self.walk(x)),
            Value::Object(o) => {
                if let Some(cc) = o.get("cache_control") {
                    // Present without ttl = the provider default, 5 minutes.
                    let ttl = match (cc.is_object(), cc.get("ttl")) {
                        (false, _) => CacheTtl::None,
                        (true, None) => CacheTtl::M5,
                        (true, Some(t)) => match t.as_str() {
                            Some("5m") => CacheTtl::M5,
                            Some("1h") => CacheTtl::H1,
                            _ => return Err(Error::Malformed),
                        },
                    };
                    self.cache_ttl = self.cache_ttl.max(ttl);
                }
                match o.get("type").and_then(Value::as_str) {
                    // Anthropic image block: any source (base64 data is excluded from text bytes).
                    Some("image") if o.contains_key("source") => {
                        self.images = self.images.checked_add(1).ok_or(Error::Overflow)?;
                        if let Some(d) = o.get("source").and_then(|s| s.get("data")).and_then(Value::as_str) {
                            self.exclude(d)?;
                        }
                    }
                    // OpenAI image part; inline `data:` URLs are excluded from text bytes.
                    Some("image_url") => {
                        self.images = self.images.checked_add(1).ok_or(Error::Overflow)?;
                        if let Some(u) = o.get("image_url").and_then(|i| i.get("url")).and_then(Value::as_str)
                            && u.starts_with("data:")
                        {
                            self.exclude(u)?;
                        }
                    }
                    // Anthropic base64 PDF document.
                    Some("document") => {
                        let src = o.get("source");
                        if src.and_then(|s| s.get("type")).and_then(Value::as_str) == Some("base64")
                            && src.and_then(|s| s.get("media_type")).and_then(Value::as_str) == Some("application/pdf")
                        {
                            let data = src.and_then(|s| s.get("data")).and_then(Value::as_str).ok_or(Error::Malformed)?;
                            self.pdf(data)?;
                        }
                    }
                    // OpenAI-style inline file part.
                    Some("file") => {
                        if let Some(d) = o.get("file").and_then(|f| f.get("file_data")).and_then(Value::as_str)
                            && let Some(b) = d.strip_prefix(PDF_DATA_URL)
                        {
                            self.pdf(b)?;
                        }
                    }
                    _ => {}
                }
                o.values().try_for_each(|x| self.walk(x))
            }
            _ => Ok(()),
        }
    }

    fn exclude(&mut self, s: &str) -> Result<(), Error> {
        let n = u64::try_from(s.len()).map_err(|_| Error::Overflow)?;
        self.image_bytes = self.image_bytes.checked_add(n).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// PDF bytes stay counted as text (pessimistic floor for pages hidden in object streams);
    /// pages = number of `/Type /Page` objects, at least 1.
    fn pdf(&mut self, b64data: &str) -> Result<(), Error> {
        let raw = base64::engine::general_purpose::STANDARD.decode(b64data).map_err(|_| Error::Malformed)?;
        let n = count_pdf_pages(&raw).max(1);
        self.pages = self.pages.checked_add(n).ok_or(Error::Overflow)?;
        Ok(())
    }
}

/// Value of an ASCII digit (callers check `is_ascii_digit` first).
fn digit(c: u8) -> u8 {
    c & 0x0F
}

fn pdf_ws(c: u8) -> bool {
    matches!(c, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn pdf_regular(c: u8) -> bool {
    !pdf_ws(c) && !b"()<>[]{}/%".contains(&c)
}

/// Count `/Type <ws>* /Page` where `/Page` is a complete name (so `/Pages` does not count).
/// ponytail: page dictionaries inside compressed object streams are not seen; the PDF's bytes
/// are still charged as text, and documents need donor opt-in. Parse object streams if abused.
#[must_use]
pub fn count_pdf_pages(pdf: &[u8]) -> u64 {
    let mut n = 0u64;
    let mut rest = pdf;
    while let Some(i) = find(rest, b"/Type") {
        rest = rest.get(i.saturating_add(5)..).unwrap_or_default();
        let after = rest.iter().position(|&c| !pdf_ws(c)).map_or(&[][..], |j| rest.get(j..).unwrap_or_default());
        if let Some(tail) = after.strip_prefix(b"/Page")
            && !tail.first().is_some_and(|&c| pdf_regular(c))
        {
            n = n.saturating_add(1);
        }
    }
    n
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
