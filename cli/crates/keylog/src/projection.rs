//! Donor-signed projections fetched by reference (`moochy verify <receipt_ref>`, E63;
//! spec/KEYLOG.md §1). The relay returns the exact signed bytes, the signature, the
//! worker device and the index of its `KEY_ADDED`; this checks them against the
//! Node's own verified mirror, so nothing the relay says is trusted.

use crate::{
    entry::{LABEL_PROJECTION, lp},
    state::{Code, State},
};
use ed25519_zebra::{Signature, VerificationKey};

/// Bound on the relay's JSON reply (a projection is a few hundred bytes).
pub const MAX_REPLY: usize = 16 * 1024;

/// A receipt reference: 1–64 chars of `[A-Za-z0-9_-]` (base64url).
#[must_use]
pub fn valid_ref(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 64
        && r.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// What a verified projection proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Pseudonym of the donor whose logged device key signed it.
    pub donor_pseudonym: String,
    /// The signing device has since been revoked (the signature stays valid for
    /// what it signed before; show it).
    pub revoked: bool,
}

/// Checks that `worker_device` is the device logged at `key_log_index` and that its
/// key signed `lp("moochy/v1/projection", projection)`. The caller still parses
/// `projection` with its strict JSON parser and checks it names the requested ref.
pub fn verify(
    state: &State,
    projection: &[u8],
    sig: &[u8],
    worker_device: &str,
    key_log_index: u64,
) -> Result<Verified, Code> {
    let d = state.device(worker_device).ok_or(Code::UnknownDevice)?;
    if d.idx != key_log_index {
        return Err(Code::IndexMismatch);
    }
    let (Ok(k), Ok(s)) = (
        VerificationKey::try_from(d.sign_pub),
        <[u8; 64]>::try_from(sig),
    ) else {
        return Err(Code::BadSig);
    };
    k.verify(&Signature::from(s), &lp(&[LABEL_PROJECTION, projection]))
        .map_err(|_| Code::BadSig)?;
    Ok(Verified {
        donor_pseudonym: d.pseudonym.clone(),
        revoked: d.revoked,
    })
}
