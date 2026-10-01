//! `moochy-proto`: the protocol core every other Moochy component trusts.
//!
//! - [`enc`]: `lp`, labels, base64url, ULID ids (CONTRACT §1–2)
//! - [`json`]: parser-differential-safe JSON (CONTRACT §1)
//! - [`frame`]: 23-byte binary frame header (plan 03 §4.2)
//! - [`msg`]: control messages, route header, inner payload, receipt, projection (CONTRACT §4–5)
//! - [`crypto`]: keys, envelopes, HPKE wraps, signatures (CONTRACT §3)
//! - [`money`]: catalog entry, cost, reservation, deterministic input estimate (plan 05)
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod crypto;
pub mod enc;
pub mod frame;
pub mod json;
pub mod money;
pub mod msg;

pub use enc::{B, Blob, DeviceId, PledgeId, RepoId, Sig, TaskId, Ulid, UserId, b64, lp, unb64};

/// One error type, deliberately coarse: callers map it to a wire code, never to a message
/// that could leak secrets. `Decrypt`/`BadSignature`/`Hash`/`Sequence` → nack `bad_envelope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Bad encoding: base64, id, frame header, wrong JSON shape or field.
    Malformed,
    /// JSON parser-differential rule violated (duplicate key, depth, number range, UTF-8, trailing data).
    Json,
    /// Unknown control message type (`t`); answer `error{code:"unknown_type"}`.
    UnknownType,
    /// A hard size bound was exceeded (frame, chunk, body, decompression bomb).
    TooLarge,
    /// AEAD or HPKE authentication failed.
    Decrypt,
    /// Ed25519 (ZIP-215) verification failed or malformed key/signature.
    BadSignature,
    /// A committed hash did not match (e.g. `body_sha256`).
    Hash,
    /// Frame out of order, for the wrong task/attempt/kind, or after the last chunk.
    Sequence,
    /// Checked integer arithmetic overflowed or a money input is out of range.
    Overflow,
    /// The OS random generator failed.
    Rng,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for Error {}
