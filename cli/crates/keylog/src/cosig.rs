//! Witness cosignatures (C2SP tlog-cosignature, `cosignature/v1`, Ed25519, key-ID
//! algorithm byte 0x04). A checkpoint carrying valid cosignatures from k pinned,
//! independent witnesses cannot be one side of a split view unless k witnesses
//! signed both sides.

use crate::{
    Error, b64,
    note::{be32, split, valid_name},
};
use ed25519_zebra::{Signature, VerificationKey};
use sha2::{Digest, Sha256};

const ALG_COSIG: u8 = 4;

/// A pinned witness key: `<name>+<id hex8>+base64(0x04 || pub32)`.
#[derive(Clone, Debug)]
pub struct CosignerKey {
    name: String,
    id: u32,
    key: VerificationKey,
}

impl CosignerKey {
    pub fn parse(vkey: &str) -> Result<Self, Error> {
        let mut it = vkey.splitn(3, '+');
        let (Some(name), Some(hex), Some(k)) = (it.next(), it.next(), it.next()) else {
            return Err(Error::Format("cosigner key"));
        };
        let raw = b64::decode(k.as_bytes()).ok_or(Error::Format("cosigner key"))?;
        let id = (hex.len() == 8 && hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
            .then(|| u32::from_str_radix(hex, 16).ok())
            .flatten()
            .ok_or(Error::Format("cosigner key id"))?;
        let d = Sha256::new()
            .chain_update(name.as_bytes())
            .chain_update(b"\n")
            .chain_update(&raw)
            .finalize();
        if !valid_name(name) || raw.first() != Some(&ALG_COSIG) || raw.len() != 33 || be32(&d) != Some(id) {
            return Err(Error::Format("cosigner key"));
        }
        let key = VerificationKey::try_from(raw.get(1..).unwrap_or_default()).map_err(|_| Error::Format("cosigner key point"))?;
        Ok(Self { name: name.to_owned(), id, key })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A verified cosignature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosignature {
    pub witness: String,
    /// POSIX seconds at which the witness cosigned.
    pub timestamp: u64,
}

/// Returns the valid cosignatures in `note` from the pinned `witnesses` (at most one
/// per witness; lines from unknown keys are ignored; a line that claims a pinned key
/// but does not verify is an error). The caller also verifies the log's own
/// signature with [`crate::note::open_checkpoint`].
pub fn cosignatures(note: &[u8], witnesses: &[CosignerKey]) -> Result<Vec<Cosignature>, Error> {
    let (text, sigs) = split(note)?;
    let mut out: Vec<Cosignature> = Vec::new();
    for (name, raw) in sigs {
        let Some(w) = witnesses.iter().find(|w| w.name == name && be32(&raw) == Some(w.id)) else {
            continue;
        };
        let (Some(ts), Some(sig)) = (raw.get(4..12), raw.get(12..)) else {
            return Err(Error::BadSig);
        };
        let ts = u64::from_be_bytes(ts.try_into().map_err(|_| Error::BadSig)?);
        let sig: [u8; 64] = sig.try_into().map_err(|_| Error::BadSig)?;
        if ts >= 1 << 63 {
            return Err(Error::BadSig);
        }
        let msg = format!("cosignature/v1\ntime {ts}\n{text}");
        w.key.verify(&Signature::from(sig), msg.as_bytes()).map_err(|_| Error::BadSig)?;
        if !out.iter().any(|c| c.witness == w.name) {
            out.push(Cosignature { witness: w.name.clone(), timestamp: ts });
        }
    }
    Ok(out)
}
