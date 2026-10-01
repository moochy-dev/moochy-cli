//! Keys, envelopes and signatures (CONTRACT §1, §3, §4; plan 03 §6, §7.2, §12).
//!
//! Encoding choices where the contract says only "task_id" (no `_16B`): the canonical 26-char
//! text form. Integers in `lp` are `u64_be` unless the contract writes `u32(..)`. All of this is
//! pinned by `spec/vectors/`.

use crate::enc::{label, lp, u64be};
use crate::msg::{InnerPayload, Projection, Receipt};
use crate::{B, Blob, DeviceId, Error, RepoId, TaskId, json, pb};
use bytes::{Bytes, BytesMut};
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
//
// Chunks travel as `pb::Chunk{attempt, seq, last, ct}` (CONTRACT §12); `ct` = ciphertext || tag.
// The AEAD AAD (CONTRACT §3) binds the task id (16 B), attempt, seq and last, so the gRPC fields
// are only hints that must agree with what the opener expects.

pub const TAG_LEN: usize = 16;
/// Largest plaintext chunk (65,536 − 23 − 16, kept from plan 03 §4.2 so a Chunk stays < 64 KiB).
pub const MAX_CHUNK: usize = 65_497;
/// Request-body chunk kind byte inside the request AAD.
const KIND_REQUEST: u8 = 0x01;

/// Chunk AEAD = ChaCha20-Poly1305 (RFC 8439) through ring's assembly implementation: same bytes
/// as any RFC 8439 implementation, ~5–10× faster than the portable one on arm64 (CONTRACT §13).
/// ring is already in the tree via rustls' ring provider.
struct ChunkAead(ring::aead::LessSafeKey);

impl ChunkAead {
    fn new(k: &Secret32) -> Result<Self, Error> {
        ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, k.expose())
            .map(|k| Self(ring::aead::LessSafeKey::new(k)))
            .map_err(|_| Error::Malformed)
    }

    /// Nonce (12 bytes) = `0x00 * 8 || u32_be(seq)`; unique because each key seals one stream.
    fn nonce(seq: u32) -> ring::aead::Nonce {
        let mut n = [0u8; 12];
        let [.., a, b, c, d] = &mut n;
        [*a, *b, *c, *d] = seq.to_be_bytes();
        ring::aead::Nonce::assume_unique_for_key(n)
    }

    fn seal(&self, seq: u32, aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        let tag = self.0.seal_in_place_separate_tag(Self::nonce(seq), ring::aead::Aad::from(aad), buf).map_err(|_| Error::Decrypt)?;
        tag.as_ref().try_into().map_err(|_| Error::Decrypt)
    }

    /// `buf` = ciphertext || tag; decrypts in place and returns the plaintext length.
    fn open(&self, seq: u32, aad: &[u8], buf: &mut [u8]) -> Result<usize, Error> {
        self.0.open_in_place(Self::nonce(seq), ring::aead::Aad::from(aad), buf).map(|p| p.len()).map_err(|_| Error::Decrypt)
    }
}

/// Running SHA-256 of a plaintext stream (ring: ARMv8 SHA extensions when present).
#[derive(Clone)]
struct Running(ring::digest::Context);

impl Running {
    fn new() -> Self {
        Self(ring::digest::Context::new(&ring::digest::SHA256))
    }
    fn update(&mut self, b: &[u8]) {
        self.0.update(b);
    }
    fn value(&self) -> [u8; 32] {
        self.0.clone().finish().as_ref().try_into().unwrap_or([0; 32])
    }
}

/// Both AADs end with `lp(.., u32(seq), last_byte)` = `00000004 seq(4) 00000001 last(1)`.
/// Patch those 5 bytes in a precomputed AAD so no per-chunk allocation happens.
fn patch_aad<const N: usize>(aad: &mut [u8; N], seq: u32, last: bool) {
    if let Some([s0, s1, s2, s3, _, _, _, _, l]) = aad.last_chunk_mut::<9>() {
        [*s0, *s1, *s2, *s3] = seq.to_be_bytes();
        *l = u8::from(last);
    }
}

/// `lp("moochy/v1/req", kind_byte, task_id_16B, u32(seq), last_byte)` with seq/last = 0.
fn req_aad(task: &TaskId) -> Result<[u8; 55], Error> {
    let v = lp(&[label::REQ, &[KIND_REQUEST], &task.0.0, &[0; 4], &[0]])?;
    v.try_into().map_err(|_| Error::Malformed)
}

/// `lp("moochy/v1/resp", task_id_16B, u64(attempt), R, u32(seq), last_byte)` with seq/last = 0.
fn resp_aad(task: &TaskId, attempt: u8, r: &[u8; 32]) -> Result<[u8; 99], Error> {
    let v = lp(&[label::RESP, &task.0.0, &u64be(attempt.into()), r, &[0; 4], &[0]])?;
    v.try_into().map_err(|_| Error::Malformed)
}

/// Split `buf` = ciphertext || tag and decrypt in place; returns the plaintext length.
fn open_in_place<const N: usize>(aead: &ChunkAead, aad: &mut [u8; N], seq: u32, last: bool, buf: &mut [u8]) -> Result<usize, Error> {
    if buf.len() < TAG_LEN || buf.len() > MAX_CHUNK + TAG_LEN {
        return Err(Error::TooLarge);
    }
    patch_aad(aad, seq, last);
    aead.open(seq, aad, buf)
}

/// zstd level by size (CONTRACT §13): 3 for ordinary bodies, 1 for very large ones.
#[must_use]
pub fn zstd_level(len: usize) -> i32 {
    if len <= 4 << 20 { 3 } else { 1 }
}

/// Sealed request: ready-to-send body chunks (attempt 0) plus the `SubmitOpen` size fields.
pub struct SealedRequest {
    pub chunks: Vec<pb::Chunk>,
    /// Sum of `ct` lengths (tags included) → `SubmitOpen.body_len`; `body_chunks` = `chunks.len()`.
    pub body_len: u64,
}

/// Gateway: zstd the inner payload, cut it into ≤ 65,497-byte chunks, seal each under `K_req`.
/// One contiguous allocation holds every chunk; each `ct` is a zero-copy `Bytes` slice of it.
pub fn seal_request(ck: &ContentKey, task: &TaskId, payload: &[u8]) -> Result<SealedRequest, Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::TooLarge);
    }
    let z = zstd::bulk::compress(payload, zstd_level(payload.len())).map_err(|_| Error::Malformed)?;
    seal_compressed(ck, task, &z)
}

/// Seal already-compressed bytes as-is. Only for test vectors (bombs, trailing data); a
/// Gateway always uses [`seal_request`].
#[doc(hidden)]
pub fn seal_compressed(ck: &ContentKey, task: &TaskId, z: &[u8]) -> Result<SealedRequest, Error> {
    let n = z.len().div_ceil(MAX_CHUNK).max(1);
    let total = n.checked_mul(TAG_LEN).and_then(|t| t.checked_add(z.len())).ok_or(Error::TooLarge)?;
    let aead = ChunkAead::new(&k_req(ck, task)?)?;
    let mut aad = req_aad(task)?;
    let mut buf = BytesMut::with_capacity(total);
    let mut chunks = Vec::with_capacity(n);
    // Empty input still yields one (empty, last) chunk.
    for (i, part) in z.chunks(MAX_CHUNK).chain(z.is_empty().then_some(&[][..])).enumerate() {
        let seq = u32::try_from(i).map_err(|_| Error::TooLarge)?;
        let last = i.checked_add(1) == Some(n);
        buf.extend_from_slice(part);
        patch_aad(&mut aad, seq, last);
        let tag = aead.seal(seq, &aad, &mut buf)?;
        buf.extend_from_slice(&tag);
        chunks.push(pb::Chunk { attempt: 0, seq, last, ct: buf.split().freeze() });
    }
    Ok(SealedRequest { chunks, body_len: u64::try_from(total).map_err(|_| Error::TooLarge)? })
}

/// Worker: decrypts request chunks in order and decompresses as they arrive. The zstd window is
/// capped and the output is a hard 32 MiB: a decompression bomb fails on the chunk that crosses
/// the limit, without ever holding more than `MAX_PAYLOAD + 1` bytes. One reusable scratch
/// buffer: no allocation per chunk.
pub struct RequestOpener {
    aead: ChunkAead,
    aad: [u8; 55],
    next: u32,
    sealed: usize,
    last_seen: bool,
    zstd_done: bool,
    failed: bool,
    dctx: zstd::zstd_safe::DCtx<'static>,
    scratch: Vec<u8>,
    out: Vec<u8>,
}

impl RequestOpener {
    pub fn new(ck: &ContentKey, task: &TaskId) -> Result<Self, Error> {
        let mut dctx = zstd::zstd_safe::DCtx::create();
        // 2^25 = 32 MiB: no legitimate payload needs a larger window.
        dctx.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(25)).map_err(|_| Error::Malformed)?;
        Ok(Self {
            aead: ChunkAead::new(&k_req(ck, task)?)?,
            aad: req_aad(task)?,
            next: 0,
            sealed: 0,
            last_seen: false,
            zstd_done: false,
            failed: false,
            dctx,
            scratch: Vec::with_capacity(MAX_CHUNK + TAG_LEN),
            out: Vec::new(),
        })
    }

    /// Feed the next body chunk. Any error poisons the opener: every later call fails too.
    pub fn push(&mut self, c: &pb::Chunk) -> Result<(), Error> {
        let r = self.push_inner(c);
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    /// Chunks accepted so far (compare with `Assign.body_chunks`).
    #[must_use]
    pub fn chunks(&self) -> u32 {
        self.next
    }

    fn push_inner(&mut self, c: &pb::Chunk) -> Result<(), Error> {
        if self.failed || self.last_seen {
            return Err(Error::Sequence);
        }
        if c.attempt != 0 || c.seq != self.next {
            return Err(Error::Sequence);
        }
        self.sealed = self.sealed.saturating_add(c.ct.len());
        if self.sealed > MAX_SEALED {
            return Err(Error::TooLarge);
        }
        let mut buf = std::mem::take(&mut self.scratch);
        buf.clear();
        buf.extend_from_slice(&c.ct);
        let r = open_in_place(&self.aead, &mut self.aad, c.seq, c.last, &mut buf).and_then(|n| {
            self.next = c.seq.checked_add(1).ok_or(Error::TooLarge)?;
            self.last_seen = c.last;
            self.inflate(buf.get(..n).unwrap_or_default())
        });
        buf.zeroize();
        self.scratch = buf;
        r
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
            let pos = self.out.len();
            let mut ob = OutBuffer::around_pos(&mut self.out, pos);
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

    /// The decompressed inner payload. Requires the last chunk and a complete zstd frame.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if self.failed || !self.last_seen || !self.zstd_done {
            return Err(Error::Sequence);
        }
        Ok(std::mem::take(&mut self.out))
    }
}

/// Worker: seals response chunks under the attempt's RK and keeps the running SHA-256 of the
/// plaintext (for checkpoints and `resp_commit`). Output comes from one reused arena: once the
/// previous chunks have been sent and dropped, sealing allocates nothing.
pub struct ResponseSealer {
    aead: ChunkAead,
    aad: [u8; 99],
    attempt: u8,
    next: u32,
    done: bool,
    hash: Running,
    arena: BytesMut,
}

impl ResponseSealer {
    pub fn new(ck: &ContentKey, r: &[u8; 32], task: &TaskId, worker: &DeviceId, attempt: u8) -> Result<Self, Error> {
        Ok(Self {
            aead: ChunkAead::new(&rk(ck, r, task, worker, attempt)?)?,
            aad: resp_aad(task, attempt, r)?,
            attempt,
            next: 0,
            done: false,
            hash: Running::new(),
            arena: BytesMut::new(),
        })
    }

    /// Append `ct || tag` for the next chunk to `out`; returns its seq.
    pub fn seal_into(&mut self, pt: &[u8], last: bool, out: &mut BytesMut) -> Result<u32, Error> {
        if self.done {
            return Err(Error::Sequence);
        }
        if pt.len() > MAX_CHUNK {
            return Err(Error::TooLarge);
        }
        let seq = self.next;
        out.reserve(pt.len().saturating_add(TAG_LEN));
        let start = out.len();
        out.extend_from_slice(pt);
        patch_aad(&mut self.aad, seq, last);
        let ct = out.get_mut(start..).ok_or(Error::Malformed)?;
        let tag = self.aead.seal(seq, &self.aad, ct)?;
        out.extend_from_slice(&tag);
        self.hash.update(pt);
        self.next = seq.checked_add(1).ok_or(Error::TooLarge)?;
        self.done = last;
        Ok(seq)
    }

    /// The next chunk as a ready-to-send message.
    pub fn seal(&mut self, pt: &[u8], last: bool) -> Result<pb::Chunk, Error> {
        let mut arena = std::mem::take(&mut self.arena);
        let r = self.seal_into(pt, last, &mut arena);
        let ct = arena.split().freeze();
        self.arena = arena;
        Ok(pb::Chunk { attempt: self.attempt.into(), seq: r?, last, ct })
    }

    /// Seq of the most recently sealed chunk (for a checkpoint covering it).
    #[must_use]
    pub fn last_seq(&self) -> Option<u32> {
        self.next.checked_sub(1)
    }

    /// SHA-256 of all plaintext sealed so far.
    #[must_use]
    pub fn running_hash(&self) -> [u8; 32] {
        self.hash.value()
    }
}

/// Gateway: opens the response chunks of exactly one (task, attempt), strictly in order.
pub struct ResponseOpener {
    aead: ChunkAead,
    aad: [u8; 99],
    attempt: u8,
    next: u32,
    done: bool,
    failed: bool,
    hash: Running,
}

impl ResponseOpener {
    pub fn new(ck: &ContentKey, r: &[u8; 32], task: &TaskId, worker: &DeviceId, attempt: u8) -> Result<Self, Error> {
        Ok(Self {
            aead: ChunkAead::new(&rk(ck, r, task, worker, attempt)?)?,
            aad: resp_aad(task, attempt, r)?,
            attempt,
            next: 0,
            done: false,
            failed: false,
            hash: Running::new(),
        })
    }

    /// Decrypt one chunk. In place and zero-copy when the received buffer is uniquely owned,
    /// otherwise into one fresh output buffer. Returns the plaintext.
    /// Any error poisons the opener (the Gateway fails the task on the first bad chunk).
    pub fn open(&mut self, c: pb::Chunk) -> Result<Bytes, Error> {
        let mut buf = c.ct.try_into_mut().unwrap_or_else(|b| BytesMut::from(&b[..]));
        let n = self.guard(c.attempt, c.seq, c.last, &mut buf)?;
        buf.truncate(n);
        Ok(buf.freeze())
    }

    /// Decrypt one chunk, appending the plaintext to a caller-owned (reused) buffer.
    pub fn open_into(&mut self, c: &pb::Chunk, out: &mut BytesMut) -> Result<(), Error> {
        let start = out.len();
        out.extend_from_slice(&c.ct);
        let r = match out.get_mut(start..) {
            Some(tail) => self.guard(c.attempt, c.seq, c.last, tail),
            None => Err(Error::Malformed),
        };
        match r {
            Ok(n) => out.truncate(start.saturating_add(n)),
            Err(_) => out.truncate(start),
        }
        r.map(|_| ())
    }

    fn guard(&mut self, attempt: u32, seq: u32, last: bool, buf: &mut [u8]) -> Result<usize, Error> {
        let r = self.open_inner(attempt, seq, last, buf);
        if r.is_err() {
            self.failed = true;
        }
        r
    }

    fn open_inner(&mut self, attempt: u32, seq: u32, last: bool, buf: &mut [u8]) -> Result<usize, Error> {
        if self.failed || self.done || attempt != u32::from(self.attempt) || seq != self.next {
            return Err(Error::Sequence);
        }
        let n = open_in_place(&self.aead, &mut self.aad, seq, last, buf)?;
        self.hash.update(buf.get(..n).unwrap_or_default());
        self.next = seq.checked_add(1).ok_or(Error::TooLarge)?;
        self.done = last;
        Ok(n)
    }

    /// True once the chunk flagged `last` was opened (otherwise the stream was truncated).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.done && !self.failed
    }

    #[must_use]
    pub fn running_hash(&self) -> [u8; 32] {
        self.hash.value()
    }
}

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
