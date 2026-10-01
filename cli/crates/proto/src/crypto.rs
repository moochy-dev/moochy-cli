//! Keys, envelopes and signatures (CONTRACT §1, §3, §4; plan 03 §6, §7.2, §12).
//!
//! Encoding choices where the contract says only "task_id" (no `_16B`): the canonical 26-char
//! text form. Integers in `lp` are `u64_be` unless the contract writes `u32(..)`. All of this is
//! pinned by `spec/vectors/`.

use crate::enc::{label, lp, u64be};
use crate::frame::{HEADER_LEN, Header, Kind, MAX_CHUNK, MAX_FRAME, TAG_LEN};
use crate::msg::{InnerPayload, Projection, Receipt};
use crate::{B, Blob, DeviceId, Error, RepoId, TaskId, json};
use bytes::{Bytes, BytesMut};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use hkdf::Hkdf;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use rand_core::{CryptoRng, RngCore, TryRngCore};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SUITE_ID: &[u8] = b"moochy.v1.hpke.x25519-sha256-chacha20poly1305";
/// Hard cap on the decompressed inner payload (plan 03 §2: 32 MiB).
pub const MAX_PAYLOAD: usize = 32 << 20;
/// Hard cap on sealed request bytes (zstd worst-case expansion of MAX_PAYLOAD, plus tags).
pub const MAX_SEALED: usize = MAX_PAYLOAD + (MAX_PAYLOAD >> 7) + (1 << 20);
pub const WRAP_LEN: usize = 80;
pub const ZSTD_LEVEL: i32 = 3;

type HKem = hpke::kem::X25519HkdfSha256;
type HKdf = hpke::kdf::HkdfSha256;
type HAead = hpke::aead::ChaCha20Poly1305;

// ---------- randomness & secrets ----------

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    rand_core::OsRng.try_fill_bytes(buf).map_err(|_| Error::Rng)
}

pub fn random32() -> Result<[u8; 32], Error> {
    let mut b = [0u8; 32];
    fill_random(&mut b)?;
    Ok(b)
}

/// 32 secret bytes, wiped on drop. Used for CK, K_req, RK and the commitment salts.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);

/// Content key CK: fresh per sealed body, never used directly as an AEAD key.
pub type ContentKey = Secret32;

impl Secret32 {
    pub fn random() -> Result<Self, Error> {
        random32().map(Self)
    }
    #[must_use]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret32(..)")
    }
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Secret32, Error> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut okm).map_err(|_| Error::Malformed)?;
    Ok(Secret32(okm))
}

#[must_use]
pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// `K_req = HKDF(salt="", ikm=CK, info=lp("moochy/v1/req", task_id))`.
pub fn k_req(ck: &ContentKey, task: &TaskId) -> Result<Secret32, Error> {
    hkdf32(&[], &ck.0, &lp(&[label::REQ, task.text().as_bytes()])?)
}

/// `RK = HKDF(salt=R, ikm=CK, info=lp("moochy/v1/resp", task_id, worker_device, u64(attempt)))`.
pub fn rk(ck: &ContentKey, r: &[u8; 32], task: &TaskId, worker: &DeviceId, attempt: u8) -> Result<Secret32, Error> {
    let info = lp(&[label::RESP, task.text().as_bytes(), worker.text().as_bytes(), &u64be(attempt.into())])?;
    hkdf32(r, &ck.0, &info)
}

/// Commitment salt names (CONTRACT §3).
#[derive(Clone, Copy, Debug)]
pub enum SaltName {
    Req,
    Resp,
    Pid,
}

/// `S_x = HKDF(salt="", ikm=S, info=lp("moochy/v1/salt", name))`.
pub fn salt(s: &[u8; 32], name: SaltName) -> Result<Secret32, Error> {
    let n: &[u8] = match name {
        SaltName::Req => b"req",
        SaltName::Resp => b"resp",
        SaltName::Pid => b"pid",
    };
    hkdf32(&[], s, &lp(&[label::SALT, n])?)
}

// ---------- commitments ----------

/// `SHA-256(lp("moochy/v1/req-commit", S_req, body))`, body as sent by the Gateway (pre-mutation).
pub fn req_commit(s_req: &Secret32, body: &[u8]) -> Result<[u8; 32], Error> {
    Ok(sha256(&lp(&[label::REQ_COMMIT, &s_req.0, body])?))
}

/// `SHA-256(lp("moochy/v1/resp-commit", S_resp, SHA-256(plaintext response)))`.
/// The inner hash makes it streamable (lp needs the length up front) and lifts the 4 GiB lp limit.
pub fn resp_commit(s_resp: &Secret32, resp_sha256: &[u8; 32]) -> Result<[u8; 32], Error> {
    Ok(sha256(&lp(&[label::RESP_COMMIT, &s_resp.0, resp_sha256])?))
}

/// `SHA-256(lp("moochy/v1/provider-req", S_pid, provider_request_id))`.
pub fn provider_req_hash(s_pid: &Secret32, request_id: &str) -> Result<[u8; 32], Error> {
    Ok(sha256(&lp(&[label::PROVIDER_REQ, &s_pid.0, request_id.as_bytes()])?))
}

/// `headers_sha256 = SHA-256(lp(name_1, value_1, …))` over the inner-payload headers in
/// ascending byte order of names (BTreeMap order). No headers → SHA-256 of the empty string.
pub fn headers_sha256(h: &BTreeMap<String, String>) -> Result<[u8; 32], Error> {
    let fields: Vec<&[u8]> = h.iter().flat_map(|(k, v)| [k.as_bytes(), v.as_bytes()]).collect();
    Ok(sha256(&lp(&fields)?))
}

// ---------- chunk AEAD streams ----------

fn nonce(seq: u32) -> Nonce {
    let mut n = [0u8; 12];
    let [.., a, b, c, d] = &mut n;
    [*a, *b, *c, *d] = seq.to_be_bytes();
    n.into()
}

/// Both AADs end with `lp(.., u32(seq), last_byte)` = `00000004 seq(4) 00000001 last(1)`.
/// Patch those 5 bytes in a precomputed AAD so no per-chunk allocation happens.
fn patch_aad<const N: usize>(aad: &mut [u8; N], seq: u32, last: bool) {
    if let Some([s0, s1, s2, s3, _, _, _, _, l]) = aad.last_chunk_mut::<9>() {
        [*s0, *s1, *s2, *s3] = seq.to_be_bytes();
        *l = u8::from(last);
    }
}

fn req_aad(task: &TaskId) -> Result<[u8; 55], Error> {
    let v = lp(&[label::REQ, &[Kind::Request as u8], &task.0.0, &[0; 4], &[0]])?;
    v.try_into().map_err(|_| Error::Malformed)
}

fn resp_aad(task: &TaskId, attempt: u8, r: &[u8; 32]) -> Result<[u8; 99], Error> {
    let v = lp(&[label::RESP, &task.0.0, &u64be(attempt.into()), r, &[0; 4], &[0]])?;
    v.try_into().map_err(|_| Error::Malformed)
}

/// Sealed request: ready-to-send `0x01` frames plus the `task.submit` size fields.
pub struct SealedRequest {
    pub frames: Vec<Bytes>,
    /// Sum of frame payload lengths (ciphertext + tags) → `task.submit.body_len`.
    pub body_len: u64,
}

/// Gateway: zstd(level 3) the inner payload, chunk it (≤ 65,497 B), seal every chunk under
/// `K_req`. One contiguous allocation for all frames; each frame is a zero-copy `Bytes` slice.
pub fn seal_request(ck: &ContentKey, task: &TaskId, payload: &[u8]) -> Result<SealedRequest, Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::TooLarge);
    }
    let z = zstd::bulk::compress(payload, ZSTD_LEVEL).map_err(|_| Error::Malformed)?;
    let n = z.len().div_ceil(MAX_CHUNK).max(1);
    let total = n.checked_mul(HEADER_LEN + TAG_LEN).and_then(|o| o.checked_add(z.len())).ok_or(Error::TooLarge)?;
    let aead = ChaCha20Poly1305::new(k_req(ck, task)?.expose().into());
    let mut aad = req_aad(task)?;
    let mut buf = BytesMut::with_capacity(total);
    let mut frames = Vec::with_capacity(n);
    for (i, chunk) in z.chunks(MAX_CHUNK).enumerate() {
        let seq = u32::try_from(i).map_err(|_| Error::TooLarge)?;
        let last = i.checked_add(1) == Some(n);
        let h = Header { kind: Kind::Request, task: *task, attempt: 0, seq, last };
        buf.extend_from_slice(&h.encode());
        buf.extend_from_slice(chunk);
        patch_aad(&mut aad, seq, last);
        let ct = buf.get_mut(HEADER_LEN..).ok_or(Error::Malformed)?;
        let tag = aead.encrypt_in_place_detached(&nonce(seq), &aad, ct).map_err(|_| Error::Decrypt)?;
        buf.extend_from_slice(&tag);
        frames.push(buf.split().freeze());
    }
    let body_len = u64::try_from(total.saturating_sub(n.saturating_mul(HEADER_LEN))).map_err(|_| Error::TooLarge)?;
    Ok(SealedRequest { frames, body_len })
}

/// Worker: decrypts `0x01` frames in order and decompresses as they arrive. The zstd window is
/// capped and the output is a hard 32 MiB: a decompression bomb fails on the chunk that crosses
/// the limit, without ever holding more than `MAX_PAYLOAD + 1` bytes.
pub struct RequestOpener {
    aead: ChaCha20Poly1305,
    aad: [u8; 55],
    task: TaskId,
    next: u32,
    sealed: usize,
    last_seen: bool,
    zstd_done: bool,
    failed: bool,
    dctx: zstd::zstd_safe::DCtx<'static>,
    out: Vec<u8>,
}

impl RequestOpener {
    pub fn new(ck: &ContentKey, task: &TaskId) -> Result<Self, Error> {
        let mut dctx = zstd::zstd_safe::DCtx::create();
        // 2^25 = 32 MiB: no legitimate payload needs a larger window.
        dctx.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(25)).map_err(|_| Error::Malformed)?;
        Ok(Self {
            aead: ChaCha20Poly1305::new(k_req(ck, task)?.expose().into()),
            aad: req_aad(task)?,
            task: *task,
            next: 0,
            sealed: 0,
            last_seen: false,
            zstd_done: false,
            failed: false,
            dctx,
            out: Vec::new(),
        })
    }

    /// Feed one whole binary frame (header included). Decrypts in place. Any error poisons the
    /// opener: every later call fails too.
    pub fn push(&mut self, frame: &mut [u8]) -> Result<(), Error> {
        let r = self.push_inner(frame);
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn push_inner(&mut self, frame: &mut [u8]) -> Result<(), Error> {
        if self.failed || self.last_seen {
            return Err(Error::Sequence);
        }
        let (h, _) = Header::decode(frame)?;
        // The attempt byte is not authenticated for request frames and is ignored.
        if h.kind != Kind::Request || h.task != self.task || h.seq != self.next {
            return Err(Error::Sequence);
        }
        let (_, payload) = frame.split_at_mut_checked(HEADER_LEN).ok_or(Error::Malformed)?;
        self.sealed = self.sealed.saturating_add(payload.len());
        if self.sealed > MAX_SEALED {
            return Err(Error::TooLarge);
        }
        let ct_len = payload.len().checked_sub(TAG_LEN).ok_or(Error::Malformed)?;
        let (ct, tag) = payload.split_at_mut_checked(ct_len).ok_or(Error::Malformed)?;
        patch_aad(&mut self.aad, h.seq, h.last);
        self.aead
            .decrypt_in_place_detached(&nonce(h.seq), &self.aad, ct, Tag::from_slice(tag))
            .map_err(|_| Error::Decrypt)?;
        self.next = self.next.checked_add(1).ok_or(Error::TooLarge)?;
        self.last_seen = h.last;
        self.inflate(ct)
    }

    fn inflate(&mut self, src: &[u8]) -> Result<(), Error> {
        use zstd::zstd_safe::{InBuffer, OutBuffer};
        let mut input = InBuffer::around(src);
        loop {
            if self.zstd_done {
                // Bytes after the end of the single zstd frame: refuse (parser-differential rule).
                return if input.pos() == src.len() { Ok(()) } else { Err(Error::Malformed) };
            }
            if self.out.len() == self.out.capacity() {
                if self.out.len() > MAX_PAYLOAD {
                    return Err(Error::TooLarge);
                }
                let want = self.out.capacity().saturating_mul(2).clamp(1 << 16, MAX_PAYLOAD + 1);
                self.out.reserve_exact(want.saturating_sub(self.out.len()));
            }
            let mut ob = OutBuffer::around(&mut self.out);
            let hint = self.dctx.decompress_stream(&mut ob, &mut input).map_err(|_| Error::Malformed)?;
            let out_full = ob.pos() == ob.capacity();
            if self.out.len() > MAX_PAYLOAD {
                return Err(Error::TooLarge);
            }
            if hint == 0 {
                self.zstd_done = true;
            } else if input.pos() == src.len() && !out_full {
                return Ok(());
            }
        }
    }

    /// The decompressed inner payload. Requires the last frame and a complete zstd frame.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if self.failed || !self.last_seen || !self.zstd_done {
            return Err(Error::Sequence);
        }
        Ok(std::mem::take(&mut self.out))
    }
}

/// Worker: seals response chunks under the attempt's RK and keeps the running SHA-256 of the
/// plaintext (for checkpoints and `resp_commit`).
pub struct ResponseSealer {
    aead: ChaCha20Poly1305,
    aad: [u8; 99],
    task: TaskId,
    attempt: u8,
    next: u32,
    done: bool,
    hash: Sha256,
}

impl ResponseSealer {
    pub fn new(ck: &ContentKey, r: &[u8; 32], task: &TaskId, worker: &DeviceId, attempt: u8) -> Result<Self, Error> {
        Ok(Self {
            aead: ChaCha20Poly1305::new(rk(ck, r, task, worker, attempt)?.expose().into()),
            aad: resp_aad(task, attempt, r)?,
            task: *task,
            attempt,
            next: 0,
            done: false,
            hash: Sha256::new(),
        })
    }

    /// Append one `0x02` frame (header + ciphertext + tag) to `out`.
    pub fn seal_into(&mut self, pt: &[u8], last: bool, out: &mut BytesMut) -> Result<(), Error> {
        if self.done {
            return Err(Error::Sequence);
        }
        if pt.len() > MAX_CHUNK {
            return Err(Error::TooLarge);
        }
        let seq = self.next;
        let h = Header { kind: Kind::Response, task: self.task, attempt: self.attempt, seq, last };
        out.reserve(pt.len().saturating_add(HEADER_LEN + TAG_LEN));
        out.extend_from_slice(&h.encode());
        let start = out.len();
        out.extend_from_slice(pt);
        patch_aad(&mut self.aad, seq, last);
        let ct = out.get_mut(start..).ok_or(Error::Malformed)?;
        let tag = self.aead.encrypt_in_place_detached(&nonce(seq), &self.aad, ct).map_err(|_| Error::Decrypt)?;
        out.extend_from_slice(&tag);
        self.hash.update(pt);
        self.next = seq.checked_add(1).ok_or(Error::TooLarge)?;
        self.done = last;
        Ok(())
    }

    /// One frame as its own buffer.
    pub fn seal(&mut self, pt: &[u8], last: bool) -> Result<Bytes, Error> {
        let mut out = BytesMut::with_capacity(pt.len().saturating_add(HEADER_LEN + TAG_LEN));
        self.seal_into(pt, last, &mut out)?;
        Ok(out.freeze())
    }

    /// Seq of the most recently sealed frame (for a checkpoint covering it).
    #[must_use]
    pub fn last_seq(&self) -> Option<u32> {
        self.next.checked_sub(1)
    }

    /// SHA-256 of all plaintext sealed so far.
    #[must_use]
    pub fn running_hash(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }
}

/// Gateway: opens `0x02` frames of exactly one (task, attempt), strictly in order, in place.
pub struct ResponseOpener {
    aead: ChaCha20Poly1305,
    aad: [u8; 99],
    task: TaskId,
    attempt: u8,
    next: u32,
    done: bool,
    failed: bool,
    hash: Sha256,
}

impl ResponseOpener {
    pub fn new(ck: &ContentKey, r: &[u8; 32], task: &TaskId, worker: &DeviceId, attempt: u8) -> Result<Self, Error> {
        Ok(Self {
            aead: ChaCha20Poly1305::new(rk(ck, r, task, worker, attempt)?.expose().into()),
            aad: resp_aad(task, attempt, r)?,
            task: *task,
            attempt,
            next: 0,
            done: false,
            failed: false,
            hash: Sha256::new(),
        })
    }

    /// Decrypt one frame in place; returns the plaintext as a zero-copy slice of `frame`.
    /// Any error poisons the opener (the Gateway fails the task on the first bad frame).
    pub fn open(&mut self, mut frame: BytesMut) -> Result<(Bytes, bool), Error> {
        let last = self.open_in_place(&mut frame)?.1;
        let mut pt = frame.split_off(HEADER_LEN);
        pt.truncate(pt.len().saturating_sub(TAG_LEN));
        Ok((pt.freeze(), last))
    }

    /// Like [`Self::open`] on a borrowed buffer: returns (plaintext, last).
    pub fn open_in_place<'a>(&mut self, frame: &'a mut [u8]) -> Result<(&'a [u8], bool), Error> {
        let r = self.open_inner(frame);
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn open_inner<'a>(&mut self, frame: &'a mut [u8]) -> Result<(&'a [u8], bool), Error> {
        if self.failed || self.done {
            return Err(Error::Sequence);
        }
        let (h, _) = Header::decode(frame)?;
        if h.kind != Kind::Response || h.task != self.task || h.attempt != self.attempt || h.seq != self.next {
            return Err(Error::Sequence);
        }
        let ct_len = frame.len().checked_sub(HEADER_LEN + TAG_LEN).ok_or(Error::Malformed)?;
        let (_, payload) = frame.split_at_mut_checked(HEADER_LEN).ok_or(Error::Malformed)?;
        let (ct, tag) = payload.split_at_mut_checked(ct_len).ok_or(Error::Malformed)?;
        patch_aad(&mut self.aad, h.seq, h.last);
        self.aead
            .decrypt_in_place_detached(&nonce(h.seq), &self.aad, ct, Tag::from_slice(tag))
            .map_err(|_| Error::Decrypt)?;
        self.hash.update(&*ct);
        self.next = h.seq.checked_add(1).ok_or(Error::TooLarge)?;
        self.done = h.last;
        Ok((ct, h.last))
    }

    /// True once the frame flagged `last` was opened (otherwise the stream was truncated).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.done && !self.failed
    }

    #[must_use]
    pub fn running_hash(&self) -> [u8; 32] {
        self.hash.clone().finalize().into()
    }
}

// Keep MAX_FRAME referenced for readers: a frame never exceeds it (checked in Header::decode).
const _: () = assert!(HEADER_LEN + MAX_CHUNK + TAG_LEN == MAX_FRAME);

// ---------- HPKE wraps ----------

/// Worker X25519 decryption key (`enc_pub` is published in the key log).
pub struct EncSecret(<HKem as hpke::Kem>::PrivateKey);

impl EncSecret {
    pub fn generate() -> Result<Self, Error> {
        Self::from_bytes(&Zeroizing::new(random32()?))
    }
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self, Error> {
        <HKem as hpke::Kem>::PrivateKey::from_bytes(b).map(Self).map_err(|_| Error::Malformed)
    }
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes().into())
    }
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        HKem::sk_to_pk(&self.0).to_bytes().into()
    }
}

fn wrap_info(task: &TaskId) -> Result<Vec<u8>, Error> {
    lp(&[label::WRAP, SUITE_ID, task.text().as_bytes()])
}

/// `HPKE.SealBase(enc_pub, info=lp("moochy/v1/wrap", suite_id, task_id), aad=route_bytes, pt=CK)`
/// → `enc(32) || ct(32) || tag(16)`.
pub fn wrap(enc_pub: &[u8; 32], task: &TaskId, route: &[u8], ck: &ContentKey) -> Result<[u8; WRAP_LEN], Error> {
    wrap_with_rng(enc_pub, task, route, ck, &mut rand_core::UnwrapErr(rand_core::OsRng))
}

/// [`wrap`] with a caller RNG (deterministic test vectors only: the ephemeral key is
/// `DeriveKeyPair(32 bytes read from rng)`).
pub fn wrap_with_rng<R: CryptoRng + RngCore>(
    enc_pub: &[u8; 32],
    task: &TaskId,
    route: &[u8],
    ck: &ContentKey,
    rng: &mut R,
) -> Result<[u8; WRAP_LEN], Error> {
    let pk = <HKem as hpke::Kem>::PublicKey::from_bytes(enc_pub).map_err(|_| Error::Malformed)?;
    let mut pt = Zeroizing::new(ck.0);
    let (enc, tag) = hpke::single_shot_seal_in_place_detached::<HAead, HKdf, HKem, R>(
        &OpModeS::Base,
        &pk,
        &wrap_info(task)?,
        &mut pt[..],
        route,
        rng,
    )
    .map_err(|_| Error::Decrypt)?;
    let mut out = [0u8; WRAP_LEN];
    let (e, rest) = out.split_at_mut(32);
    let (c, t) = rest.split_at_mut(32);
    e.copy_from_slice(&enc.to_bytes());
    c.copy_from_slice(&pt[..]);
    t.copy_from_slice(&tag.to_bytes());
    Ok(out)
}

/// Worker: open the wrap. Fails if the route header bytes differ by a single bit.
pub fn unwrap(sk: &EncSecret, task: &TaskId, route: &[u8], wrap: &[u8; WRAP_LEN]) -> Result<ContentKey, Error> {
    let (e, rest) = wrap.split_at(32);
    let (c, t) = rest.split_at(32);
    let enc = <HKem as hpke::Kem>::EncappedKey::from_bytes(e).map_err(|_| Error::Decrypt)?;
    let tag = hpke::aead::AeadTag::<HAead>::from_bytes(t).map_err(|_| Error::Decrypt)?;
    let mut ck = Secret32([0; 32]);
    ck.0.copy_from_slice(c);
    hpke::single_shot_open_in_place_detached::<HAead, HKdf, HKem>(
        &OpModeR::Base,
        &sk.0,
        &enc,
        &wrap_info(task)?,
        &mut ck.0,
        route,
        &tag,
    )
    .map_err(|_| Error::Decrypt)?;
    Ok(ck)
}

// ---------- Ed25519 (sign RFC 8032, verify ZIP-215) ----------

/// Device signing key; the seed is wiped on drop.
pub struct SignKey(ed25519_zebra::SigningKey);

impl SignKey {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_seed(&Zeroizing::new(random32()?)))
    }
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_zebra::SigningKey::from(*seed))
    }
    #[must_use]
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.into())
    }
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        ed25519_zebra::VerificationKeyBytes::from(&self.0).into()
    }
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl Drop for SignKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// ZIP-215 verification: accepts non-canonical point encodings of A and R, requires canonical
/// S, uses the cofactored equation. Identical verdicts to Go `ed25519consensus`.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
    let vk = ed25519_zebra::VerificationKey::try_from(*public).map_err(|_| Error::BadSignature)?;
    vk.verify(&ed25519_zebra::Signature::from_bytes(sig), msg).map_err(|_| Error::BadSignature)
}

// ---------- signed byte strings ----------

/// `lp("moochy/v1/auth", nonce, dialed_origin, tls_exporter, device_id)`.
pub fn auth_msg(nonce: &[u8; 32], dialed_origin: &str, tls_exporter: &[u8; 32], device: &DeviceId) -> Result<Vec<u8>, Error> {
    lp(&[label::AUTH, nonce, dialed_origin.as_bytes(), tls_exporter, device.text().as_bytes()])
}

/// `lp("moochy/v1/task", task_id, repo_id, route_header_bytes, body_sha256, headers_sha256)`.
pub fn task_msg(task: &TaskId, repo: &RepoId, route: &[u8], body_sha256: &[u8; 32], headers_sha256: &[u8; 32]) -> Result<Vec<u8>, Error> {
    lp(&[label::TASK, task.text().as_bytes(), repo.text().as_bytes(), route, body_sha256, headers_sha256])
}

/// `lp("moochy/v1/resp-progress", task_id, u64(attempt), R, u64(seq), running_sha256)`.
pub fn checkpoint_msg(task: &TaskId, attempt: u8, r: &[u8; 32], seq: u32, running: &[u8; 32]) -> Result<Vec<u8>, Error> {
    lp(&[label::RESP_PROGRESS, task.text().as_bytes(), &u64be(attempt.into()), r, &u64be(seq.into()), running])
}

/// `lp("moochy/v1/dispute", task_id, u64(attempt), code)`.
pub fn dispute_msg(task: &TaskId, attempt: u8, code: &str) -> Result<Vec<u8>, Error> {
    lp(&[label::DISPUTE, task.text().as_bytes(), &u64be(attempt.into()), code.as_bytes()])
}

/// `lp("moochy/v1/receipt", receipt_bytes)`.
pub fn receipt_msg(receipt_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    lp(&[label::RECEIPT, receipt_bytes])
}

/// `lp("moochy/v1/projection", projection_bytes)`.
pub fn projection_msg(projection_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    lp(&[label::PROJECTION, projection_bytes])
}

/// Serialize and sign a receipt. The returned bytes are the artifact; never re-serialize.
pub fn sign_receipt(key: &SignKey, r: &Receipt) -> Result<(Vec<u8>, [u8; 64]), Error> {
    let bytes = serde_json::to_vec(r).map_err(|_| Error::Malformed)?;
    let sig = key.sign(&receipt_msg(&bytes)?);
    Ok((bytes, sig))
}

/// Verify the signature over the exact bytes first, then strictly parse them.
pub fn open_receipt(donor: &[u8; 32], bytes: &[u8], sig: &[u8; 64]) -> Result<Receipt, Error> {
    verify(donor, &receipt_msg(bytes)?, sig)?;
    let r: Receipt = json::parse(bytes)?;
    if r.v != 1 {
        return Err(Error::Malformed);
    }
    Ok(r)
}

pub fn sign_projection(key: &SignKey, p: &Projection) -> Result<(Vec<u8>, [u8; 64]), Error> {
    let bytes = serde_json::to_vec(p).map_err(|_| Error::Malformed)?;
    let sig = key.sign(&projection_msg(&bytes)?);
    Ok((bytes, sig))
}

pub fn open_projection(donor: &[u8; 32], bytes: &[u8], sig: &[u8; 64]) -> Result<Projection, Error> {
    verify(donor, &projection_msg(bytes)?, sig)?;
    let p: Projection = json::parse(bytes)?;
    if p.v != 1 {
        return Err(Error::Malformed);
    }
    Ok(p)
}

/// Everything the Gateway needs to know to build an inner payload.
pub struct TaskContext<'a> {
    pub task: &'a TaskId,
    pub repo: &'a RepoId,
    /// Exact route header bytes (as sent in `route_b64`).
    pub route: &'a [u8],
}

impl InnerPayload {
    /// Gateway: build and sign (`task_sig`, plan 03 §7.2).
    pub fn build(
        ctx: &TaskContext<'_>,
        body: Vec<u8>,
        headers: BTreeMap<String, String>,
        s: [u8; 32],
        gateway_device: DeviceId,
        key: &SignKey,
    ) -> Result<Self, Error> {
        let body_sha256 = sha256(&body);
        let msg = task_msg(ctx.task, ctx.repo, ctx.route, &body_sha256, &headers_sha256(&headers)?)?;
        Ok(Self {
            v: 1,
            body_b64: Blob(body),
            body_sha256: B(body_sha256),
            headers,
            s: B(s),
            gateway_device,
            task_sig: B(key.sign(&msg)),
        })
    }

    /// Worker: body hash (constant time) and task signature for `gateway_pub`. The caller still
    /// checks that `gateway_device` is logged, a member of `repo`, and the other §7.2 rules.
    pub fn verify(&self, ctx: &TaskContext<'_>, gateway_pub: &[u8; 32]) -> Result<(), Error> {
        if !bool::from(sha256(&self.body_b64.0).ct_eq(&self.body_sha256.0)) {
            return Err(Error::Hash);
        }
        let msg = task_msg(ctx.task, ctx.repo, ctx.route, &self.body_sha256.0, &headers_sha256(&self.headers)?)?;
        verify(gateway_pub, &msg, &self.task_sig.0)
    }
}

/// Constant-time equality for tokens/MACs/hashes.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
