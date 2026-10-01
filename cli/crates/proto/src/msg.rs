//! Wire structs (CONTRACT §4–5, plan 03 §5, §7.1, §12.1).
//!
//! Unknown-field policy:
//! - **Control messages** ([`Msg`]): unknown fields are **ignored** (CONTRACT §1, forward
//!   compatibility within v1). Unknown `t` → [`Error::UnknownType`].
//! - **Signed or sealed artifacts** ([`RouteHeader`], [`InnerPayload`], [`Receipt`],
//!   [`Projection`]): `deny_unknown_fields`. Their bytes are signed/bound and checked by peers; a
//!   field a verifier does not understand could carry meaning it cannot check, so it fails closed.
//!
//! Every parse goes through [`crate::json::parse`] (duplicate keys etc. rejected first).

use crate::enc::{B, Blob, Sig};
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
#[serde(rename_all = "lowercase")]
pub enum Role {
    Gateway,
    Worker,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    #[serde(rename = "anthropic.messages")]
    AnthropicMessages,
    #[serde(rename = "openai.chat")]
    OpenAiChat,
}

impl Dialect {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnthropicMessages => "anthropic.messages",
            Self::OpenAiChat => "openai.chat",
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
        if p.v != 1 {
            return Err(Error::Malformed);
        }
        Ok(p)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Malformed)
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

// ---------- control messages (plan 03 §5) ----------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub nonce: B<32>,
    pub server_time: u64,
    pub min_client_version: String,
    pub relay_release: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    pub device_id: DeviceId,
    pub roles: Vec<Role>,
    pub sig: Sig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub session_id: String,
    pub roles: Vec<Role>,
    /// Named integer limits (plan 03 §16), e.g. `max_body_bytes`, `max_wraps`.
    #[serde(default)]
    pub limits: BTreeMap<String, u64>,
    pub catalog_version: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PoolWorker {
    pub worker_device: DeviceId,
    pub enc_pub: B<32>,
    pub key_log_index: u64,
    pub approval_log_index: u64,
    pub donor_pseudonym: String,
    pub dialects: Vec<Dialect>,
    pub models: Vec<String>,
    pub hint: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PoolSync {
    pub repo: RepoId,
    pub workers: Vec<PoolWorker>,
    /// `true` = full snapshot; `false` = delta (upsert `workers`, drop `removed`).
    pub full: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<DeviceId>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Wrap {
    pub worker_device: DeviceId,
    pub wrap: B<80>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskSubmit {
    pub task: TaskId,
    pub route_b64: Blob,
    pub wraps: Vec<Wrap>,
    /// Total sealed bytes (sum of the `0x01` frame payloads, tags included).
    pub body_len: u64,
    /// Number of `0x01` frames that follow.
    pub body_chunks: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskWraps {
    pub task: TaskId,
    pub wraps: Vec<Wrap>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskNeedWraps {
    pub task: TaskId,
    pub workers: Vec<DeviceId>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskAccepted {
    pub task: TaskId,
    pub attempt: u8,
    pub worker_device: DeviceId,
    #[serde(rename = "R")]
    pub r: B<32>,
}

/// `task.started` and `receipt.ack` share this shape.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskRef {
    pub task: TaskId,
    pub attempt: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskCheckpoint {
    pub task: TaskId,
    pub attempt: u8,
    pub seq: u32,
    pub running_hash: B<32>,
    pub sig: Sig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskEnd {
    pub task: TaskId,
    pub attempt: u8,
    pub receipt_b64: Blob,
    pub donor_sig: Sig,
    pub projection_b64: Blob,
    pub projection_sig: Sig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskFailed {
    pub task: TaskId,
    pub code: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_detail: Option<Blob>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskCancel {
    pub task: TaskId,
    /// Present R → W (attempt to abort); absent G → R (whole task).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReceiptDispute {
    pub task: TaskId,
    pub attempt: u8,
    pub code: String,
    pub gateway_sig: Sig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KnownTask {
    pub task: TaskId,
    pub attempt: u8,
    pub state: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WorkerKnownTasks {
    pub tasks: Vec<KnownTask>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OfferModel {
    pub dialect: Dialect,
    pub model: String,
    /// Rate-limit headroom 0–100.
    pub rl_headroom: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WorkerOffer {
    pub slots_free: u16,
    pub models: Vec<OfferModel>,
    pub pledges: Vec<PledgeId>,
    pub window_open: bool,
    pub local_cap_left: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskAssign {
    pub task: TaskId,
    pub attempt: u8,
    pub route_b64: Blob,
    pub wrap: B<80>,
    pub pledge: PledgeId,
    pub deadline_ack_ms: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskAck {
    pub task: TaskId,
    pub attempt: u8,
    #[serde(rename = "R")]
    pub r: B<32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskNack {
    pub task: TaskId,
    pub attempt: u8,
    #[serde(rename = "R")]
    pub r: B<32>,
    pub code: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_detail: Option<Blob>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReceiptReplaySince {
    /// ms since the Unix epoch.
    pub since: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RelayDraining {
    pub reconnect_after_ms: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LogCheckpoint {
    /// Signed checkpoint note text.
    pub checkpoint: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CatalogUpdate {
    pub version: u64,
    pub catalog_b64: Blob,
    pub sig: Sig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorMsg {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskId>,
}

macro_rules! messages {
    ($($t:literal => $v:ident($ty:ty),)*) => {
        /// Every control message. Serializes with its `t` tag; parse with [`Msg::parse`].
        #[derive(Serialize, Clone, Debug, PartialEq, Eq)]
        #[serde(tag = "t")]
        pub enum Msg {
            $(#[serde(rename = $t)] $v($ty),)*
        }

        impl Msg {
            /// Strict parse. Unknown fields are ignored; unknown `t` → [`Error::UnknownType`].
            pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
                #[derive(Deserialize)]
                struct Head { t: String }
                json::check(bytes)?;
                let head: Head = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
                match head.t.as_str() {
                    $($t => serde_json::from_slice(bytes).map(Msg::$v).map_err(|_| Error::Malformed),)*
                    _ => Err(Error::UnknownType),
                }
            }

            #[must_use]
            pub fn t(&self) -> &'static str {
                match self { $(Msg::$v(_) => $t,)* }
            }

            pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
                serde_json::to_vec(self).map_err(|_| Error::Malformed)
            }
        }
    };
}

messages! {
    "hello" => Hello(Hello),
    "auth" => Auth(Auth),
    "welcome" => Welcome(Welcome),
    "pool.sync" => PoolSync(PoolSync),
    "task.submit" => TaskSubmit(TaskSubmit),
    "task.wraps" => TaskWraps(TaskWraps),
    "task.need_wraps" => TaskNeedWraps(TaskNeedWraps),
    "task.accepted" => TaskAccepted(TaskAccepted),
    "task.started" => TaskStarted(TaskRef),
    "task.checkpoint" => TaskCheckpoint(TaskCheckpoint),
    "task.end" => TaskEnd(TaskEnd),
    "task.failed" => TaskFailed(TaskFailed),
    "task.cancel" => TaskCancel(TaskCancel),
    "receipt.dispute" => ReceiptDispute(ReceiptDispute),
    "worker.known_tasks" => WorkerKnownTasks(WorkerKnownTasks),
    "worker.offer" => WorkerOffer(WorkerOffer),
    "task.assign" => TaskAssign(TaskAssign),
    "task.ack" => TaskAck(TaskAck),
    "task.nack" => TaskNack(TaskNack),
    "receipt.ack" => ReceiptAck(TaskRef),
    "receipt.replay_since" => ReceiptReplaySince(ReceiptReplaySince),
    "relay.draining" => RelayDraining(RelayDraining),
    "log.checkpoint" => LogCheckpoint(LogCheckpoint),
    "catalog.update" => CatalogUpdate(CatalogUpdate),
    "error" => Error(ErrorMsg),
}
