//! Exact key-log record formats (spec/KEYLOG.md §2–3). Same grammar as Go's
//! `relay/internal/tlog/entry.go`. Parsing is zero-copy: fields borrow the record.

use crate::Error;

pub const LABEL_RECORD: &[u8] = b"moochy/v1/keylog";
pub const LABEL_SIG: &[u8] = b"moochy/v1/keylog-sig";
pub const LABEL_POP: &[u8] = b"moochy/v1/key-pop";
/// Bound on every record (and every entry of an entry bundle).
/// 256 × (2 + 480) = 123,392 bytes: a full entry bundle fits one 128 KiB gRPC message.
pub const MAX_RECORD: usize = 480;
/// Label of receipt-log leaves: `lp("moochy/v1/receipt-log", sha256(receipt))`.
pub const LABEL_RECEIPT_LOG: &[u8] = b"moochy/v1/receipt-log";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    KeyAdded = 1,
    KeyRevoked = 2,
    RepoClaimed = 3,
    DonorApproved = 4,
    DonorRevoked = 5,
    MemberAdded = 6,
    MemberRemoved = 7,
    Catalog = 8,
    Moderation = 9,
    /// Binds a user's owner key: the only key that signs kinds 3–7 (CONTRACT §15.4).
    OwnerKeyAdded = 10,
    /// Retires a user's owner key (relay-asserted; removes trust only).
    OwnerKeyRevoked = 11,
}

impl Kind {
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::KeyAdded,
            2 => Self::KeyRevoked,
            3 => Self::RepoClaimed,
            4 => Self::DonorApproved,
            5 => Self::DonorRevoked,
            6 => Self::MemberAdded,
            7 => Self::MemberRemoved,
            8 => Self::Catalog,
            9 => Self::Moderation,
            10 => Self::OwnerKeyAdded,
            11 => Self::OwnerKeyRevoked,
            _ => return None,
        })
    }

    /// Parses a kind name as used in `SignedLogEntry.kind` / `ApprovalRequest.kind`.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        (1..=11).filter_map(Self::from_u32).find(|k| k.name() == s)
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::KeyAdded => "KEY_ADDED",
            Self::KeyRevoked => "KEY_REVOKED",
            Self::RepoClaimed => "REPO_CLAIMED",
            Self::DonorApproved => "DONOR_APPROVED",
            Self::DonorRevoked => "DONOR_REVOKED",
            Self::MemberAdded => "MEMBER_ADDED",
            Self::MemberRemoved => "MEMBER_REMOVED",
            Self::Catalog => "CATALOG",
            Self::Moderation => "MODERATION",
            Self::OwnerKeyAdded => "OWNER_KEY_ADDED",
            Self::OwnerKeyRevoked => "OWNER_KEY_REVOKED",
        }
    }

    /// Kinds 3–7 carry an owner-device signature.
    #[must_use]
    pub fn owner_signed(self) -> bool {
        matches!(
            self,
            Self::RepoClaimed
                | Self::DonorApproved
                | Self::DonorRevoked
                | Self::MemberAdded
                | Self::MemberRemoved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Roles {
    Gateway,
    Worker,
    Both,
}

impl Roles {
    #[must_use]
    pub fn has_gateway(self) -> bool {
        self != Self::Worker
    }
    #[must_use]
    pub fn has_worker(self) -> bool {
        self != Self::Gateway
    }
}

/// A parsed body. Strings are validated ASCII ids/tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    Key {
        device_id: &'a str,
        pseudonym: &'a str,
        sign_pub: &'a [u8; 32],
        enc_pub: &'a [u8; 32],
        suite: &'a str,
        roles: Roles,
        repo_scope: Option<&'a str>,
    },
    Revoke {
        device_id: &'a str,
        pseudonym: &'a str,
        reason: &'a str,
    },
    Claim {
        repo_id: &'a str,
        provider: &'a str,
        provider_repo_id: &'a str,
        owner: &'a str,
        signer: &'a str,
        issued_at_ms: u64,
    },
    /// DONOR_APPROVED / DONOR_REVOKED / MEMBER_ADDED / MEMBER_REMOVED.
    Grant {
        repo_id: &'a str,
        subject: &'a str,
        signer: &'a str,
        issued_at_ms: u64,
    },
    Catalog {
        version: u64,
        sha256: &'a [u8; 32],
        sig: &'a [u8],
    },
    Moderation {
        subject: &'a str,
        action: &'a str,
        reason: &'a str,
    },
    /// OWNER_KEY_ADDED: `prev` is the owner key being rotated out (then `sig` is
    /// new-key signature ‖ prev-key signature, 128 bytes).
    OwnerKey {
        pseudonym: &'a str,
        owner_pub: &'a [u8; 32],
        prev: Option<&'a [u8; 32]>,
        issued_at_ms: u64,
    },
    OwnerRevoke {
        pseudonym: &'a str,
        owner_pub: &'a [u8; 32],
        reason: &'a str,
    },
}

/// A parsed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub kind: Kind,
    pub logged_at_ms: u64,
    pub body: Body<'a>,
    /// The exact body bytes (what owner signatures cover).
    pub raw_body: &'a [u8],
    /// 64 bytes for KEY_ADDED (proof of possession) and kinds 3–7; empty otherwise.
    pub sig: &'a [u8],
}

/// `lp(a, b, …)` (CONTRACT §1).
#[must_use]
pub fn lp(fields: &[&[u8]]) -> Vec<u8> {
    let n = fields
        .iter()
        .fold(0usize, |n, f| n.saturating_add(f.len()).saturating_add(4));
    let mut out = Vec::with_capacity(n);
    for f in fields {
        out.extend_from_slice(&u32::try_from(f.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

fn unlp<const N: usize>(mut b: &[u8]) -> Result<[&[u8]; N], Error> {
    let mut out: [&[u8]; N] = [&[]; N];
    for slot in &mut out {
        let (len, rest) = b
            .split_first_chunk::<4>()
            .ok_or(Error::Format("lp truncated"))?;
        let len =
            usize::try_from(u32::from_be_bytes(*len)).map_err(|_| Error::Format("lp length"))?;
        if len > rest.len() {
            return Err(Error::Format("lp length"));
        }
        let (field, rest) = rest.split_at(len);
        *slot = field;
        b = rest;
    }
    if b.is_empty() {
        Ok(out)
    } else {
        Err(Error::Format("lp trailing bytes"))
    }
}

fn u64_of(b: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        b.try_into().map_err(|_| Error::Format("u64 width"))?,
    ))
}

/// The message an owner device signs for kinds 3–7: `lp("moochy/v1/keylog-sig", u32(kind), body)`.
#[must_use]
pub fn sig_message(kind: Kind, body: &[u8]) -> Vec<u8> {
    lp(&[LABEL_SIG, &(kind as u32).to_be_bytes(), body])
}

/// The proof-of-possession message a new device signs at DeviceStart:
/// `lp("moochy/v1/key-pop", sign_pub, enc_pub, suite)`.
#[must_use]
pub fn pop_message(sign_pub: &[u8; 32], enc_pub: &[u8; 32], suite: &str) -> Vec<u8> {
    lp(&[LABEL_POP, sign_pub, enc_pub, suite.as_bytes()])
}

/// REPO_CLAIMED body (the owner's Node builds it, signs `sig_message`, and submits it).
#[must_use]
pub fn claim_body(
    repo_id: &str,
    provider: &str,
    provider_repo_id: &str,
    owner: &str,
    signer: &str,
    issued_at_ms: u64,
) -> Vec<u8> {
    lp(&[
        repo_id.as_bytes(),
        provider.as_bytes(),
        provider_repo_id.as_bytes(),
        owner.as_bytes(),
        signer.as_bytes(),
        &issued_at_ms.to_be_bytes(),
    ])
}

/// DONOR_APPROVED / DONOR_REVOKED / MEMBER_ADDED / MEMBER_REMOVED body.
#[must_use]
pub fn grant_body(repo_id: &str, subject: &str, signer: &str, issued_at_ms: u64) -> Vec<u8> {
    lp(&[
        repo_id.as_bytes(),
        subject.as_bytes(),
        signer.as_bytes(),
        &issued_at_ms.to_be_bytes(),
    ])
}

/// The record (tree leaf data): `lp("moochy/v1/keylog", u32(kind), u64(logged_at_ms), body, sig)`.
#[must_use]
pub fn record(kind: Kind, logged_at_ms: u64, body: &[u8], sig: &[u8]) -> Vec<u8> {
    lp(&[
        LABEL_RECORD,
        &(kind as u32).to_be_bytes(),
        &logged_at_ms.to_be_bytes(),
        body,
        sig,
    ])
}

fn s(b: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(b).map_err(|_| Error::Format("utf-8"))
}

/// Parses and validates one record (format only; authority needs the log prefix, see
/// [`crate::State`]).
pub fn parse_record(rec: &[u8]) -> Result<Entry<'_>, Error> {
    if rec.len() > MAX_RECORD {
        return Err(Error::TooLarge);
    }
    let [label, kind, at, body, sig] = unlp::<5>(rec)?;
    let kind: [u8; 4] = kind.try_into().map_err(|_| Error::Format("kind width"))?;
    if label != LABEL_RECORD {
        return Err(Error::Format("record label"));
    }
    let kind = Kind::from_u32(u32::from_be_bytes(kind)).ok_or(Error::Format("unknown kind"))?;
    let logged_at_ms = u64_of(at)?;
    let want_sig = kind == Kind::KeyAdded || kind.owner_signed();
    let sig_ok = match kind {
        Kind::OwnerKeyAdded => sig.len() == 64 || sig.len() == 128,
        _ => sig.len() == if want_sig { 64 } else { 0 },
    };
    if !sig_ok {
        return Err(Error::Format("sig length"));
    }
    let body_p = parse_body(kind, body)?;
    if let Body::OwnerKey { prev, .. } = body_p
        && prev.is_some() != (sig.len() == 128)
    {
        return Err(Error::Format("OWNER_KEY_ADDED sig count"));
    }
    Ok(Entry {
        kind,
        logged_at_ms,
        body: body_p,
        raw_body: body,
        sig,
    })
}

#[allow(clippy::too_many_lines)] // one flat arm per entry kind
/// Parses and validates a bare body of `kind` (e.g. `ApprovalRequest.body_to_sign`
/// before showing it to the owner).
pub fn parse_body(kind: Kind, b: &[u8]) -> Result<Body<'_>, Error> {
    let bad = Error::Format(kind.name());
    Ok(match kind {
        Kind::KeyAdded => {
            let [d, p, sp, ep, su, ro, sc] = unlp::<7>(b)?;
            let (d, p, su, ro, sc) = (s(d)?, s(p)?, s(su)?, s(ro)?, s(sc)?);
            let roles = match ro {
                "gateway" => Roles::Gateway,
                "worker" => Roles::Worker,
                "gateway,worker" => Roles::Both,
                _ => return Err(bad),
            };
            let (Ok(sign_pub), Ok(enc_pub)) =
                (<&[u8; 32]>::try_from(sp), <&[u8; 32]>::try_from(ep))
            else {
                return Err(bad);
            };
            if !is_id(d, "d_")
                || !is_pseudonym(p)
                || !is_token(su, 64)
                || !(sc.is_empty() || is_id(sc, "r_"))
            {
                return Err(bad);
            }
            Body::Key {
                device_id: d,
                pseudonym: p,
                sign_pub,
                enc_pub,
                suite: su,
                roles,
                repo_scope: (!sc.is_empty()).then_some(sc),
            }
        }
        Kind::KeyRevoked => {
            let [d, p, r] = unlp::<3>(b)?;
            let (d, p, r) = (s(d)?, s(p)?, s(r)?);
            if !is_id(d, "d_") || !is_pseudonym(p) || !is_token(r, 32) {
                return Err(bad);
            }
            Body::Revoke {
                device_id: d,
                pseudonym: p,
                reason: r,
            }
        }
        Kind::RepoClaimed => {
            let [r, pv, pid, o, sg, t] = unlp::<6>(b)?;
            let (r, pv, pid, o, sg, t) = (s(r)?, s(pv)?, s(pid)?, s(o)?, s(sg)?, u64_of(t)?);
            if !is_id(r, "r_")
                || !(pv == "github" || pv == "gitlab")
                || !is_decimal(pid)
                || !is_pseudonym(o)
                || !is_owner_key_id(sg)
                || t == 0
            {
                return Err(bad);
            }
            Body::Claim {
                repo_id: r,
                provider: pv,
                provider_repo_id: pid,
                owner: o,
                signer: sg,
                issued_at_ms: t,
            }
        }
        Kind::DonorApproved | Kind::DonorRevoked | Kind::MemberAdded | Kind::MemberRemoved => {
            let [r, sub, sg, t] = unlp::<4>(b)?;
            let (r, sub, sg, t) = (s(r)?, s(sub)?, s(sg)?, u64_of(t)?);
            if !is_id(r, "r_") || !is_pseudonym(sub) || !is_owner_key_id(sg) || t == 0 {
                return Err(bad);
            }
            Body::Grant {
                repo_id: r,
                subject: sub,
                signer: sg,
                issued_at_ms: t,
            }
        }
        Kind::Catalog => {
            let [v, h, sig] = unlp::<3>(b)?;
            let version = u64_of(v)?;
            let Ok(sha256) = <&[u8; 32]>::try_from(h) else {
                return Err(bad);
            };
            if version == 0 || sig.is_empty() || sig.len() > 128 {
                return Err(bad);
            }
            Body::Catalog {
                version,
                sha256,
                sig,
            }
        }
        Kind::Moderation => {
            let [sub, a, r] = unlp::<3>(b)?;
            let (sub, a, r) = (s(sub)?, s(a)?, s(r)?);
            if !is_pseudonym(sub) || !is_token(a, 32) || !is_token(r, 32) {
                return Err(bad);
            }
            Body::Moderation {
                subject: sub,
                action: a,
                reason: r,
            }
        }
        Kind::OwnerKeyAdded => {
            let [p, k, prev, t] = unlp::<4>(b)?;
            let (p, t) = (s(p)?, u64_of(t)?);
            let Ok(owner_pub) = <&[u8; 32]>::try_from(k) else {
                return Err(bad);
            };
            let prev = match prev.len() {
                0 => None,
                _ => Some(<&[u8; 32]>::try_from(prev).map_err(|_| bad.clone())?),
            };
            if !is_pseudonym(p) || t == 0 || prev == Some(owner_pub) {
                return Err(bad);
            }
            Body::OwnerKey {
                pseudonym: p,
                owner_pub,
                prev,
                issued_at_ms: t,
            }
        }
        Kind::OwnerKeyRevoked => {
            let [p, k, r] = unlp::<3>(b)?;
            let (p, r) = (s(p)?, s(r)?);
            let Ok(owner_pub) = <&[u8; 32]>::try_from(k) else {
                return Err(bad);
            };
            if !is_pseudonym(p) || !is_token(r, 32) {
                return Err(bad);
            }
            Body::OwnerRevoke {
                pseudonym: p,
                owner_pub,
                reason: r,
            }
        }
    })
}

/// Owner key id used as `signer` in kinds 3–7: `ok_` + hex(SHA-256(pub)[..16]).
#[must_use]
pub fn owner_key_id(owner_pub: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(owner_pub);
    let mut out = String::with_capacity(35);
    out.push_str("ok_");
    for b in d.iter().take(16) {
        out.push(char::from(
            HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
        ));
        out.push(char::from(
            HEX.get(usize::from(b & 15)).copied().unwrap_or(b'0'),
        ));
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn is_owner_key_id(s: &str) -> bool {
    s.strip_prefix("ok_")
        .is_some_and(|u| u.len() == 32 && u.bytes().all(|c| HEX.contains(&c)))
}

/// OWNER_KEY_ADDED body (the user's foreground CLI builds and signs it; on rotation
/// with both keys: `sig = new.sign(m) ‖ prev.sign(m)`, `m = sig_message(OwnerKeyAdded, body)`).
#[must_use]
pub fn owner_key_body(
    pseudonym: &str,
    owner_pub: &[u8; 32],
    prev: Option<&[u8; 32]>,
    issued_at_ms: u64,
) -> Vec<u8> {
    lp(&[
        pseudonym.as_bytes(),
        owner_pub,
        prev.map_or(&[][..], |p| &p[..]),
        &issued_at_ms.to_be_bytes(),
    ])
}

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `prefix` + canonical 26-char ULID (first char ≤ '7').
#[must_use]
pub fn is_id(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix).is_some_and(|u| {
        u.len() == 26
            && u.as_bytes().first().is_some_and(|&c| c <= b'7')
            && u.bytes().all(|c| CROCKFORD.contains(&c))
    })
}

/// `ps_` + 16 lowercase Crockford base32 chars (CONTRACT §1).
#[must_use]
pub fn is_pseudonym(s: &str) -> bool {
    s.strip_prefix("ps_").is_some_and(|u| {
        u.len() == 16
            && u.bytes()
                .all(|c| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&c))
    })
}

fn is_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().all(|c| {
            c.is_ascii_digit() || c.is_ascii_lowercase() || matches!(c, b'.' | b'_' | b'-')
        })
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 20
        && !(s.starts_with('0') && s.len() > 1)
        && s.bytes().all(|c| c.is_ascii_digit())
}
