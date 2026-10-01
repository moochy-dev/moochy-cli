//! C2SP tlog-tiles paths and bounded entry-bundle parsing.

use crate::{Error, entry::MAX_RECORD};
use std::fmt::Write;

/// 256 hashes or entries per tile (C2SP fixed height 8).
pub const TILE_WIDTH: u64 = 256;
/// Largest checkpoint response accepted.
pub const MAX_CHECKPOINT_BYTES: usize = crate::note::MAX_NOTE;
/// Largest hash tile: 256 × 32.
pub const MAX_HASH_TILE_BYTES: usize = 8192;
/// Largest entry bundle: 256 × (2 + MAX_RECORD).
pub const MAX_BUNDLE_BYTES: usize = 256 * (2 + MAX_RECORD);

/// Path of a tile relative to the log prefix: `tile/<L>/<N>[.p/<W>]`, or
/// `tile/entries/<N>[.p/<W>]` when `level` is `None`. `width` 256 = full tile.
#[must_use]
pub fn tile_path(level: Option<u8>, n: u64, width: u64) -> String {
    let mut groups = Vec::with_capacity(7);
    let mut n = n;
    loop {
        groups.push(n % 1000);
        n /= 1000;
        if n == 0 {
            break;
        }
    }
    let mut p = match level {
        Some(l) => format!("tile/{l}"),
        None => "tile/entries".to_owned(),
    };
    let last = groups.len().saturating_sub(1);
    for (i, g) in groups.iter().rev().enumerate() {
        let _ = if i == last { write!(p, "/{g:03}") } else { write!(p, "/x{g:03}") };
    }
    if width > 0 && width < TILE_WIDTH {
        let _ = write!(p, ".p/{width}");
    }
    p
}

/// One entry bundle to fetch: tile index, width, and how many leading records to skip
/// because the mirror already has them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleFetch {
    pub n: u64,
    pub width: u64,
    pub skip: u64,
}

impl BundleFetch {
    #[must_use]
    pub fn path(&self) -> String {
        tile_path(None, self.n, self.width)
    }
}

/// The entry bundles needed to grow a mirror from `from` to `to` entries.
#[must_use]
pub fn bundles(from: u64, to: u64) -> Vec<BundleFetch> {
    let mut out = Vec::new();
    let mut i = from;
    while i < to {
        let n = i / TILE_WIDTH;
        let start = n.saturating_mul(TILE_WIDTH);
        let width = to.saturating_sub(start).min(TILE_WIDTH);
        out.push(BundleFetch { n, width, skip: i.saturating_sub(start) });
        i = start.saturating_add(width);
    }
    out
}

/// Splits an entry bundle (`(u16_be(len) || record)*`) into exactly `width` records.
pub fn parse_bundle(data: &[u8], width: u64) -> Result<Vec<&[u8]>, Error> {
    if data.len() > MAX_BUNDLE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::with_capacity(usize::try_from(width.min(TILE_WIDTH)).unwrap_or(0));
    let mut b = data;
    while !b.is_empty() {
        let (len, rest) = b.split_first_chunk::<2>().ok_or(Error::Format("bundle truncated"))?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len > MAX_RECORD || len > rest.len() {
            return Err(Error::Format("bundle entry length"));
        }
        let (rec, rest) = rest.split_at(len);
        out.push(rec);
        b = rest;
    }
    if u64::try_from(out.len()).ok() != Some(width) {
        return Err(Error::Format("bundle width"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(tile_path(Some(0), 0, 256), "tile/0/000");
        assert_eq!(tile_path(Some(0), 1_234_067, 256), "tile/0/x001/x234/067");
        assert_eq!(tile_path(Some(1), 5, 3), "tile/1/005.p/3");
        assert_eq!(tile_path(None, 1000, 255), "tile/entries/x001/000.p/255");
    }

    #[test]
    fn bundle_plan() {
        assert_eq!(bundles(0, 0), vec![]);
        assert_eq!(bundles(0, 5), vec![BundleFetch { n: 0, width: 5, skip: 0 }]);
        assert_eq!(
            bundles(250, 600),
            vec![
                BundleFetch { n: 0, width: 256, skip: 250 },
                BundleFetch { n: 1, width: 256, skip: 0 },
                BundleFetch { n: 2, width: 88, skip: 0 }
            ]
        );
    }

    #[test]
    fn bundle_parse_bounds() {
        assert_eq!(parse_bundle(&[0, 1, 7, 0, 0], 2).unwrap(), vec![&[7u8][..], &[][..]]);
        assert!(parse_bundle(&[0, 1, 7], 2).is_err());
        assert!(parse_bundle(&[0, 2, 7], 1).is_err());
        assert!(parse_bundle(&[4, 1], 1).is_err());
    }
}
