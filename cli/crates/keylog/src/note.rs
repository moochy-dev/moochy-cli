//! Signed-note checkpoints (C2SP signed-note + tlog-checkpoint), as produced by Go's
//! `x/mod/sumdb/note`. Ed25519 only, verified with ZIP-215 (`ed25519-zebra`).

use crate::{Error, b64, merkle::Hash};
use ed25519_zebra::{Signature, VerificationKey};
use sha2::{Digest, Sha256};

/// Bound on a checkpoint note (text + signature lines).
pub const MAX_NOTE: usize = 8192;
const ALG_ED25519: u8 = 1;
const SIG_PREFIX: &str = "\u{2014} ";

/// A pinned log verifier key: `<name>+<hash hex8>+<base64(0x01 || pub32)>`.
#[derive(Clone, Debug)]
pub struct NoteKey {
    name: String,
    hash: u32,
    key: VerificationKey,
}

fn key_hash(name: &str, alg_and_key: &[u8]) -> u32 {
    let d = Sha256::new()
        .chain_update(name.as_bytes())
        .chain_update(b"\n")
        .chain_update(alg_and_key)
        .finalize();
    be32(&d).unwrap_or_default()
}

pub(crate) fn be32(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(..4)?.try_into().ok()?))
}

pub(crate) fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.chars()
            .all(|c| !c.is_whitespace() && c != '+' && !c.is_control())
}

impl NoteKey {
    pub fn parse(vkey: &str) -> Result<Self, Error> {
        let mut it = vkey.splitn(3, '+');
        let (Some(name), Some(hex), Some(k)) = (it.next(), it.next(), it.next()) else {
            return Err(Error::Format("vkey"));
        };
        let raw = b64::decode(k.as_bytes()).ok_or(Error::Format("vkey base64"))?;
        let (&[alg], pubkey) = (
            raw.get(..1).unwrap_or_default(),
            raw.get(1..).unwrap_or_default(),
        ) else {
            return Err(Error::Format("vkey"));
        };
        let hash = (hex.len() == 8
            && hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
        .ok_or(Error::Format("vkey hash"))?;
        if !valid_name(name)
            || alg != ALG_ED25519
            || pubkey.len() != 32
            || key_hash(name, &raw) != hash
        {
            return Err(Error::Format("vkey"));
        }
        let key = VerificationKey::try_from(pubkey).map_err(|_| Error::Format("vkey point"))?;
        Ok(Self {
            name: name.to_owned(),
            hash,
            key,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A verified checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub size: u64,
    pub root: Hash,
}

/// A parsed signed note: the text (ending in '\n') and its signature lines as
/// (key name, decoded base64 payload). Valid UTF-8, no control characters except
/// '\n', ≤ [`MAX_NOTE`] bytes, ≤ 100 signature lines.
pub(crate) fn split(note: &[u8]) -> Result<(&str, Vec<(&str, Vec<u8>)>), Error> {
    if note.len() > MAX_NOTE {
        return Err(Error::TooLarge);
    }
    let s = std::str::from_utf8(note).map_err(|_| Error::Format("note utf-8"))?;
    if s.chars().any(|c| c.is_control() && c != '\n') {
        return Err(Error::Format("note control char"));
    }
    let split = s.rfind("\n\n").ok_or(Error::Format("note signatures"))?;
    let (text, sigs) = (
        s.get(..=split).unwrap_or_default(),
        s.get(split.saturating_add(2)..).unwrap_or_default(),
    );
    if !sigs.ends_with('\n') {
        return Err(Error::Format("note signatures"));
    }
    let mut out = Vec::new();
    for (i, line) in sigs.lines().enumerate() {
        if i >= 100 {
            return Err(Error::TooLarge);
        }
        let rest = line
            .strip_prefix(SIG_PREFIX)
            .ok_or(Error::Format("note signature line"))?;
        let (name, b) = rest
            .split_once(' ')
            .ok_or(Error::Format("note signature line"))?;
        let raw = b64::decode(b.as_bytes()).ok_or(Error::Format("note signature base64"))?;
        if !valid_name(name) || raw.len() < 5 {
            return Err(Error::Format("note signature line"));
        }
        out.push((name, raw));
    }
    Ok((text, out))
}

/// Verifies a signed checkpoint note: valid UTF-8 without control characters
/// (except '\n'), text exactly `origin\nsize\nbase64(root)\n`, and at least one valid
/// signature by `key` (other signers, e.g. witnesses, are ignored; a bad signature
/// claiming `key` fails).
pub fn open_checkpoint(note: &[u8], origin: &str, key: &NoteKey) -> Result<Checkpoint, Error> {
    let (text, sigs) = split(note)?;
    let mut ok = false;
    for (name, raw) in sigs {
        let (h, sig) = raw.split_at(4);
        if name != key.name || be32(h) != Some(key.hash) {
            continue;
        }
        let sig: [u8; 64] = sig.try_into().map_err(|_| Error::BadSig)?;
        key.key
            .verify(&Signature::from(sig), text.as_bytes())
            .map_err(|_| Error::BadSig)?;
        ok = true;
    }
    if !ok {
        return Err(Error::BadSig);
    }
    parse_text(text, origin)
}

fn parse_text(text: &str, origin: &str) -> Result<Checkpoint, Error> {
    let mut lines = text.split('\n');
    let (Some(o), Some(n), Some(r), Some(""), None) = (
        lines.next(),
        lines.next(),
        lines.next(),
        lines.next(),
        lines.next(),
    ) else {
        return Err(Error::Format("checkpoint text"));
    };
    if o != origin {
        return Err(Error::Format("checkpoint origin"));
    }
    if n.is_empty()
        || n.len() > 20
        || (n.starts_with('0') && n.len() > 1)
        || !n.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(Error::Format("checkpoint size"));
    }
    let size = n.parse().map_err(|_| Error::Format("checkpoint size"))?;
    let root = b64::decode(r.as_bytes())
        .and_then(|v| Hash::try_from(v).ok())
        .ok_or(Error::Format("checkpoint root"))?;
    Ok(Checkpoint { size, root })
}
