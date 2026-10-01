//! Streaming, capped zstd decompression of another party's bytes, in pure Rust (`ruzstd`).
//! CONTRACT §15.2: no C code on hostile input.
//!
//! Input arrives chunk by chunk. We parse and police the frame header ourselves (RFC 8878
//! §3.1.1.1), then hand `ruzstd` exactly one complete block at a time, so the decoder never
//! sees partial input and never decodes more than one block (≤ 128 KiB of output) between two
//! size checks. Output is counted exactly (`drained + window` once anything was drained, see
//! [`Inflater::produced`]), so a bomb fails on the block that crosses the cap, having allocated
//! at most the cap.
//!
//! Accepted frames: exactly one standard zstd frame, no dictionary, no content checksum (the
//! AEAD already authenticates every byte; one accepted form = no parser differential), window
//! and declared content size ≤ the cap, declared content size (if any) equal to the output,
//! nothing after the frame.

use crate::Error;
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use std::io::Write;

const MAGIC: u32 = 0xFD2F_B528;
/// Largest frame header: magic 4 + descriptor 1 + window 1 + dictionary id 4 + content size 8.
const MAX_HEADER: usize = 18;
/// zstd `Block_Maximum_Size` (RFC 8878 §3.1.1.2.3).
const MAX_BLOCK: usize = 128 * 1024;
const BLOCK_HEADER: usize = 3;

struct Frame {
    window: usize,
    content_size: Option<usize>,
}

pub struct Inflater {
    dec: FrameDecoder,
    frame: Option<Frame>,
    /// Undecoded input: at most one partial block + header + the newest chunk.
    pending: Vec<u8>,
    out: Vec<u8>,
    cap: usize,
    done: bool,
}

impl Inflater {
    /// Decoder whose total output may never exceed `cap` bytes.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        let mut dec = FrameDecoder::new();
        dec.set_max_window_size(u64::try_from(cap).unwrap_or(u64::MAX));
        Self { dec, frame: None, pending: Vec::new(), out: Vec::new(), cap, done: false }
    }

    /// Feed the next piece of compressed input. Errors are final.
    pub fn push(&mut self, src: &[u8]) -> Result<(), Error> {
        if self.done {
            // Anything after the single frame is refused.
            return if src.is_empty() { Ok(()) } else { Err(Error::Malformed) };
        }
        // Invariant: `step` consumes everything decodable, so what is left is at most a frame
        // header or one partial block. Memory is bounded by that plus the newest piece.
        if self.pending.len() > MAX_HEADER.saturating_add(BLOCK_HEADER).saturating_add(MAX_BLOCK) {
            return Err(Error::Malformed);
        }
        self.pending.extend_from_slice(src);
        self.step()
    }

    /// The decompressed bytes. Fails unless exactly one complete frame was seen.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.done { Ok(self.out) } else { Err(Error::Malformed) }
    }

    /// Exact output so far: once the decoder has drained anything it keeps exactly `window`
    /// bytes of history; before that everything is still inside it (≤ window ≤ cap).
    fn produced(&self, window: usize) -> usize {
        if self.done || self.out.is_empty() { self.out.len() } else { self.out.len().saturating_add(window) }
    }

    fn step(&mut self) -> Result<(), Error> {
        loop {
            let window = match &self.frame {
                Some(f) => f.window,
                None => match parse_header(&self.pending, self.cap)? {
                    None => return Ok(()),
                    Some((f, len)) => {
                        let mut hdr = self.pending.get(..len).ok_or(Error::Malformed)?;
                        self.dec.init(&mut hdr).map_err(|_| Error::Malformed)?;
                        if self.dec.bytes_read_from_source() != u64::try_from(len).map_err(|_| Error::Malformed)? {
                            return Err(Error::Malformed);
                        }
                        self.pending.drain(..len);
                        let w = f.window;
                        self.frame = Some(f);
                        w
                    }
                },
            };
            // One complete block or wait for more input.
            let Some(&[b0, b1, b2]) = self.pending.first_chunk::<BLOCK_HEADER>() else { return Ok(()) };
            let bh = u32::from_le_bytes([b0, b1, b2, 0]);
            let size = usize::try_from(bh >> 3).map_err(|_| Error::Malformed)?;
            if size > MAX_BLOCK {
                return Err(Error::Malformed);
            }
            let body = match (bh >> 1) & 3 {
                0 | 2 => size, // raw, compressed
                1 => 1,        // RLE: one byte regenerated `size` times
                _ => return Err(Error::Malformed),
            };
            let need = BLOCK_HEADER.saturating_add(body);
            if self.pending.len() < need {
                return Ok(());
            }
            let before = self.dec.bytes_read_from_source();
            let mut block = self.pending.get(..need).ok_or(Error::Malformed)?;
            self.dec.decode_blocks(&mut block, BlockDecodingStrategy::UptoBlocks(1)).map_err(|_| Error::Malformed)?;
            let used = self.dec.bytes_read_from_source().checked_sub(before).ok_or(Error::Malformed)?;
            if used != u64::try_from(need).map_err(|_| Error::Malformed)? || !block.is_empty() {
                return Err(Error::Malformed);
            }
            self.pending.drain(..need);
            let finished = self.dec.is_finished();
            // While decoding, `window` bytes stay inside the decoder: leave room for them.
            let room = if finished { self.cap } else { self.cap.saturating_sub(window) };
            self.dec
                .collect_to_writer(Capped { out: &mut self.out, cap: room })
                .map_err(|_| Error::TooLarge)?;
            if finished {
                self.done = true;
            }
            let produced = self.produced(window);
            if produced > self.cap {
                return Err(Error::TooLarge);
            }
            if let Some(cs) = self.frame.as_ref().and_then(|f| f.content_size) {
                // More than declared, or less than declared at the end: refuse.
                if produced > cs || (self.done && produced != cs) {
                    return Err(Error::Malformed);
                }
            }
            if self.done {
                return if self.pending.is_empty() { Ok(()) } else { Err(Error::Malformed) };
            }
        }
    }
}

/// Parse a frame header from the front of `p`: `Ok(None)` = need more bytes.
fn parse_header(p: &[u8], cap: usize) -> Result<Option<(Frame, usize)>, Error> {
    let Some(&[m0, m1, m2, m3, d]) = p.first_chunk::<5>() else { return Ok(None) };
    if u32::from_le_bytes([m0, m1, m2, m3]) != MAGIC {
        return Err(Error::Malformed); // includes skippable frames
    }
    // reserved bit, content checksum, dictionary id: all refused.
    if d & 0x08 != 0 || d & 0x04 != 0 || d & 0x03 != 0 {
        return Err(Error::Malformed);
    }
    let single = d & 0x20 != 0;
    let fcs_len: usize = match d >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let win_len = usize::from(!single);
    let len = 5usize.saturating_add(win_len).saturating_add(fcs_len);
    let Some(rest) = p.get(5..len) else { return Ok(None) };
    let (win, fcs_bytes) = rest.split_at(win_len);
    let content_size = if fcs_len == 0 {
        None
    } else {
        let mut v = [0u8; 8];
        v.get_mut(..fcs_len).ok_or(Error::Malformed)?.copy_from_slice(fcs_bytes);
        let n = u64::from_le_bytes(v);
        let n = if fcs_len == 2 { n.checked_add(256).ok_or(Error::Malformed)? } else { n };
        Some(usize::try_from(n).map_err(|_| Error::TooLarge)?)
    };
    let window = match win.first() {
        None => content_size.ok_or(Error::Malformed)?, // single segment: window = content size
        Some(&w) => {
            let log = 10u32.saturating_add(u32::from(w >> 3));
            let base = 1u64.checked_shl(log).ok_or(Error::TooLarge)?;
            let add = (base >> 3).saturating_mul(u64::from(w & 7));
            usize::try_from(base.saturating_add(add)).map_err(|_| Error::TooLarge)?
        }
    };
    if window > cap || content_size.is_some_and(|c| c > cap) {
        return Err(Error::TooLarge);
    }
    Ok(Some((Frame { window, content_size }, len)))
}

/// `Write` into a Vec that refuses to grow past `cap` bytes (and grows by doubling up to it).
struct Capped<'a> {
    out: &'a mut Vec<u8>,
    cap: usize,
}

impl Write for Capped<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let need = self.out.len().checked_add(buf.len()).filter(|&n| n <= self.cap).ok_or(std::io::ErrorKind::OutOfMemory)?;
        if need > self.out.capacity() {
            let target = self.out.capacity().saturating_mul(2).max(need).max(1 << 16).min(self.cap);
            self.out.reserve_exact(target.saturating_sub(self.out.len()));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(z: &[u8], cap: usize, piece: usize) -> Result<Vec<u8>, Error> {
        let mut i = Inflater::new(cap);
        for c in z.chunks(piece.max(1)) {
            i.push(c)?;
        }
        i.finish()
    }

    #[test]
    fn roundtrip_any_split() {
        let data: Vec<u8> = (0..300_000u32).map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 13) & 0x3f).unwrap()).collect();
        for lvl in [1, 3, 19] {
            let z = zstd::bulk::compress(&data, lvl).unwrap();
            for piece in [1, 2, 3, 7, 17, 4096, 65_497, z.len()] {
                assert_eq!(run(&z, 1 << 20, piece).unwrap(), data, "level {lvl} piece {piece}");
            }
        }
        assert_eq!(run(&zstd::bulk::compress(b"", 3).unwrap(), 10, 1).unwrap(), b"");
    }

    #[test]
    fn caps_and_refusals() {
        let z = zstd::bulk::compress(&vec![0u8; 1 << 20], 3).unwrap();
        assert_eq!(run(&z, 1 << 20, 65_497).unwrap().len(), 1 << 20);
        assert_eq!(run(&z, (1 << 20) - 1, 65_497), Err(Error::TooLarge));
        // Streaming frame (no declared size, window 2^log) through the C streaming encoder.
        let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        enc.include_contentsize(false).unwrap();
        enc.write_all(&vec![7u8; 5 << 20]).unwrap();
        let z = enc.finish().unwrap();
        assert_eq!(run(&z, 5 << 20, 65_497).unwrap().len(), 5 << 20);
        assert_eq!(run(&z, (5 << 20) - 1, 65_497), Err(Error::TooLarge));
        // Checksum flag, trailing data, two frames, bad magic, skippable frame, truncated.
        let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        enc.include_checksum(true).unwrap();
        enc.write_all(b"hello").unwrap();
        assert_eq!(run(&enc.finish().unwrap(), 100, 64), Err(Error::Malformed));
        let one = zstd::bulk::compress(b"{}", 3).unwrap();
        assert_eq!(run(&[one.clone(), vec![0]].concat(), 100, 64), Err(Error::Malformed));
        assert_eq!(run(&[one.clone(), one.clone()].concat(), 100, 64), Err(Error::Malformed));
        assert_eq!(run(b"\x00\x00\x00\x00rest", 100, 64), Err(Error::Malformed));
        assert_eq!(run(b"\x50\x2a\x4d\x18\x00\x00\x00\x00", 100, 64), Err(Error::Malformed));
        assert_eq!(run(&one[..one.len() - 1], 100, 64), Err(Error::Malformed));
        // Declared content size larger than the cap: refused from the header alone.
        let z = zstd::bulk::compress(&vec![1u8; 2000], 3).unwrap();
        assert_eq!(run(&z, 1999, 64), Err(Error::TooLarge));
        // Declared content size lying (patched FCS): refused.
        let mut lie = zstd::bulk::compress(&[9u8; 300], 3).unwrap();
        assert_eq!(lie[4] >> 6, 1, "2-byte FCS (value − 256)");
        lie[6] = lie[6].wrapping_add(1);
        assert_eq!(run(&lie, 1000, 64), Err(Error::Malformed));
    }
}
