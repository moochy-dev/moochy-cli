//! Binary frame header (plan 03 §4.2): `kind(1) task_id(16) attempt(1) seq(4 BE) flags(1)` then
//! the AEAD ciphertext+tag. Total frame ≤ 64 KiB. Decoding never panics and allocates nothing.

use crate::{Error, TaskId, Ulid};

pub const HEADER_LEN: usize = 23;
pub const MAX_FRAME: usize = 65_536;
pub const TAG_LEN: usize = 16;
/// Largest plaintext chunk: 65,536 − 23 − 16.
pub const MAX_CHUNK: usize = MAX_FRAME - HEADER_LEN - TAG_LEN;

pub const FLAG_LAST: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Request-body chunk (Gateway → Relay → Worker).
    Request = 0x01,
    /// Response chunk (Worker → Relay → Gateway).
    Response = 0x02,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub task: TaskId,
    /// Request frames carry 0 (the body is attempt-independent); response frames carry 1–3.
    pub attempt: u8,
    pub seq: u32,
    pub last: bool,
}

impl Header {
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        let [k, t @ .., a, s0, s1, s2, s3, f] = &mut h;
        *k = self.kind as u8;
        t.copy_from_slice(&self.task.0.0);
        *a = self.attempt;
        [*s0, *s1, *s2, *s3] = self.seq.to_be_bytes();
        *f = u8::from(self.last);
        h
    }

    /// Parse the header of a whole frame. Rejects: short or oversize frames, kind `0x03`
    /// (reserved) or unknown, unknown flag bits, and frames with no room for an AEAD tag.
    pub fn decode(frame: &[u8]) -> Result<(Self, &[u8]), Error> {
        if frame.len() > MAX_FRAME {
            return Err(Error::TooLarge);
        }
        let (h, payload) = frame.split_first_chunk::<HEADER_LEN>().ok_or(Error::Malformed)?;
        let [k, t @ .., a, s0, s1, s2, s3, f] = *h;
        let kind = match k {
            0x01 => Kind::Request,
            0x02 => Kind::Response,
            _ => return Err(Error::Malformed),
        };
        if f & !FLAG_LAST != 0 || payload.len() < TAG_LEN {
            return Err(Error::Malformed);
        }
        let hdr = Self {
            kind,
            task: TaskId(Ulid(t)),
            attempt: a,
            seq: u32::from_be_bytes([s0, s1, s2, s3]),
            last: f & FLAG_LAST != 0,
        };
        Ok((hdr, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_bounds() {
        let h = Header {
            kind: Kind::Response,
            task: TaskId(Ulid([7; 16])),
            attempt: 3,
            seq: 0xDEAD_BEEF,
            last: true,
        };
        let mut f = h.encode().to_vec();
        f.extend_from_slice(&[0; TAG_LEN]);
        assert_eq!(Header::decode(&f).unwrap().0, h);
        f.resize(MAX_FRAME, 0);
        assert!(Header::decode(&f).is_ok());
        f.push(0);
        assert_eq!(Header::decode(&f), Err(Error::TooLarge));
        // Hostile inputs: every short length, bad kinds, bad flags.
        for n in 0..HEADER_LEN + TAG_LEN {
            assert!(Header::decode(&f[..n]).is_err());
        }
        f.truncate(HEADER_LEN + TAG_LEN);
        for k in [0u8, 3, 4, 0xFF] {
            f[0] = k;
            assert!(Header::decode(&f).is_err());
        }
        f[0] = 1;
        f[22] = 2;
        assert!(Header::decode(&f).is_err());
    }
}
