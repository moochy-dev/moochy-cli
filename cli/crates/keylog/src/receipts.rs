//! Receipt transparency log (spec/KEYLOG.md §6): the relay appends SHA-256 of every
//! settled receipt; a donor (or maintainer) holding the receipt bytes proves it was
//! logged with an inclusion proof against a signed receipt-log checkpoint.

use crate::{
    entry::{LABEL_RECEIPT_LOG, lp},
    merkle::{Hash, leaf_hash, verify_inclusion},
    note::Checkpoint,
};
use sha2::{Digest, Sha256};

/// The leaf record of a receipt: `lp("moochy/v1/receipt-log", sha256(receipt))`.
#[must_use]
pub fn record(receipt: &[u8]) -> Vec<u8> {
    let h: Hash = Sha256::digest(receipt).into();
    lp(&[LABEL_RECEIPT_LOG, &h])
}

/// Leaf hash of a receipt in the receipt log.
#[must_use]
pub fn leaf(receipt: &[u8]) -> Hash {
    leaf_hash(&record(receipt))
}

/// Is `receipt` the leaf at `index` of the tree described by the verified receipt-log
/// checkpoint `cp` (opened with the receipt log's key and origin)?
#[must_use]
pub fn verify(receipt: &[u8], index: u64, cp: &Checkpoint, proof: &[Hash]) -> bool {
    verify_inclusion(index, cp.size, &leaf(receipt), proof, &cp.root)
}
