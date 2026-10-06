//! Signed / sealed JSON artifacts (CONTRACT §1, §4; plan 03 §7.1, §12.1; plan 05 §2.2).
//!
//! Control messages are protobuf ([`crate::pb`], CONTRACT §12). What stays JSON is everything
//! that is signed or bound as exact bytes: route header, inner payload, receipt, projection,
//! catalog. All of them are parsed with [`crate::json::parse`] (duplicate keys etc. rejected) and
//! use `deny_unknown_fields`: a field a verifier does not understand could carry meaning it
//! cannot check, so it fails closed. Never re-serialize a received artifact; keep its bytes.

use crate::enc::{B, Blob, Sig};
use crate::money::CatalogEntry;
use crate::{DeviceId, Error, PledgeId, RepoId, TaskId, json};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// NACK / failure codes (plan 03 §10.2) plus the client-facing policy codes (§10.3).
pub mod code {
    pub const BUSY: &str = "busy";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const OVERLOADED: &str = "overloaded";
    pub const PROVIDER_ERROR: &str = "provider_error";
    pub const LOCAL_CAP: &str = "local_cap";
    pub const MODEL_UNAVAILABLE: &str = "model_unavailable";
    pub const FIREWALL: &str = "firewall";
    pub const ROUTE_MISMATCH: &str = "route_mismatch";
    pub const UNAUTHORIZED_TASK: &str = "unauthorized_task";
    pub const BAD_ENVELOPE: &str = "bad_envelope";
    pub const OVER_TASK_CAP: &str = "over_task_cap";
    pub const QUOTA_EXCEEDED: &str = "quota_exceeded";
    pub const MODEL_NOT_IN_POOL: &str = "model_not_in_pool";
    pub const UNKNOWN_TYPE: &str = "unknown_type";

    /// Retry elsewhere? (plan 03 §10.2). Unknown codes are treated as non-retryable.
    #[must_use]
    pub fn retryable(code: &str) -> bool {
        matches!(code, BUSY | RATE_LIMITED | OVERLOADED | PROVIDER_ERROR | LOCAL_CAP | MODEL_UNAVAILABLE)
    }
}

pub const MAX_ATTEMPTS: u8 = 3;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    #[serde(rename = "anthropic.messages")]
    AnthropicMessages,
    #[serde(rename = "openai.chat")]
    OpenAiChat,
    /// OpenAI Responses API (`POST /v1/responses`, CONTRACT §18.6; Codex).
    #[serde(rename = "openai.responses")]
    OpenAiResponses,
}

impl Dialect {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnthropicMessages => "anthropic.messages",
            Self::OpenAiChat => "openai.chat",
            Self::OpenAiResponses => "openai.responses",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CacheTtl {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "5m")]
    M5,
    #[serde(rename = "1h")]
    H1,
}

// ---------- route header (plan 03 §7.1) ----------

/// The plaintext the Relay schedules on. Transmitted as `route_b64` = exact UTF-8 JSON bytes;
/// those bytes (never a re-serialization) are the HPKE AAD and go into the task signature.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteHeader {
    pub repo_id: RepoId,
    pub dialect: Dialect,
    /// Public model slug (`vendor/model`).
    pub model: String,
    /// Effective effort (request value, else catalog `default_effort`).
    pub effort: String,
    pub max_tokens: u32,
    pub est_input_tokens: u64,
    pub cache_ttl: CacheTtl,
    pub stream: bool,
    /// Opaque 16-byte HMAC; not checked by the Worker.
    pub affinity: B<16>,
    /// Opt-in features used by the body: `fast`, `images`, `documents`, …
    pub flags: Vec<String>,
}

impl RouteHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        json::parse(bytes)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Malformed)
    }
}

// ---------- inner payload (CONTRACT §4) ----------

/// Sealed request plaintext (before zstd).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InnerPayload {
    /// Must be 1.
    pub v: u8,
    /// Provider request body exactly as the client sent it.
    pub body_b64: Blob,
    pub body_sha256: B<32>,
    /// Allowlisted provider headers, lowercase names (e.g. `anthropic-version`, `anthropic-beta`).
    pub headers: BTreeMap<String, String>,
    /// Commitment salt seed `S`.
    #[serde(rename = "S")]
    pub s: B<32>,
    pub gateway_device: DeviceId,
    pub task_sig: Sig,
}

impl InnerPayload {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let p: Self = json::parse(bytes)?;
        // Header names: lowercase RFC 9110 token characters only (no case-variant duplicates).
        let name_ok = |k: &String| !k.is_empty() && k.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&c));
        let value_ok = |v: &String| v.bytes().all(|c| c == b'\t' || (b' '..=b'~').contains(&c));
        if p.v != 1 || !p.headers.iter().all(|(k, v)| name_ok(k) && value_ok(v)) {
            return Err(Error::Malformed);
        }
        Ok(p)
    }
    /// The same bytes as `serde_json::to_vec(self)`, built without the body's temporary base64
    /// `String` and without serde_json's escape pass over it (base64url never needs escaping):
    /// the body is most of the payload and this runs on every request (CONTRACT §13).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Tail<'a> {
            body_sha256: &'a B<32>,
            headers: &'a BTreeMap<String, String>,
            #[serde(rename = "S")]
            s: &'a B<32>,
            gateway_device: &'a DeviceId,
            task_sig: &'a Sig,
        }
        let tail = serde_json::to_vec(&Tail { body_sha256: &self.body_sha256, headers: &self.headers, s: &self.s, gateway_device: &self.gateway_device, task_sig: &self.task_sig })
            .map_err(|_| Error::Malformed)?;
        let tail = tail.get(1..).ok_or(Error::Malformed)?; // without its `{`
        let cap = self.body_b64.0.len().div_ceil(3).saturating_mul(4).saturating_add(tail.len()).saturating_add(32);
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(b"{\"v\":");
        serde_json::to_writer(&mut out, &self.v).map_err(|_| Error::Malformed)?;
        out.extend_from_slice(b",\"body_b64\":\"");
        crate::enc::b64_extend(&self.body_b64.0, &mut out)?;
        out.extend_from_slice(b"\",");
        out.extend_from_slice(tail);
        Ok(out)
    }
}

// ---------- receipt & projection (plan 03 §12.1) ----------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Ok,
    Cancelled,
    ProviderError,
    Partial,
    NotStarted,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
    pub cache_read: u64,
    pub estimated: bool,
    /// Provider-charged cost already converted to µ$ (rounded up) with
    /// [`crate::money::usd_decimal_to_uusd_ceil`]; OpenRouter only. No floats in signed bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_cost_uusd: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub v: u8,
    pub task_id: TaskId,
    pub attempt: u8,
    pub repo_id: RepoId,
    pub pledge_id: PledgeId,
    pub worker_device: DeviceId,
    pub gateway_device: DeviceId,
    pub dialect: Dialect,
    pub provider: String,
    pub model_reported: String,
    pub usage: Usage,
    pub catalog_version: u64,
    pub cost_uusd: i64,
    pub req_commit: B<32>,
    pub resp_commit: B<32>,
    pub provider_req_hash: B<32>,
    pub status: ReceiptStatus,
    /// Worker timestamps, ms since the Unix epoch.
    pub t_start: u64,
    pub t_started: u64,
    pub t_end: u64,
}

/// Public, donor-signed view of a receipt.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    pub v: u8,
    /// Random, unlinkable reference.
    pub receipt_ref: B<16>,
    pub repo_id: RepoId,
    /// Donor pseudonym per pledge visibility; `null` when anonymous.
    pub donor: Option<String>,
    pub model: String,
    pub cost_uusd: i64,
    /// UTC day `YYYY-MM-DD`.
    pub day: String,
    pub receipt_sha256: B<32>,
}

/// Signed price catalog (plan 05 §2.2), carried as exact bytes in `CatalogUpdate.catalog_json`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Monotonic; Nodes reject decreases.
    pub version: u64,
    /// Prices apply to tasks started at or after this time (ms since the Unix epoch).
    pub effective_at_ms: i64,
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        json::parse(bytes)
    }

    /// Entry for a public slug served by `provider`.
    #[must_use]
    pub fn entry(&self, model: &str, provider: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.model == model && e.provider == provider)
    }
}
