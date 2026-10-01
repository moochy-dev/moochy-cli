//! RFC 6962 / RFC 9162 Merkle tree hashing and proof verification (the same tree
//! as Go's `x/mod/sumdb/tlog`). Allocation-free except [`CompactRange`]'s ≤ 64 hashes.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// Root of the empty tree: SHA-256("").
#[must_use]
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// Leaf hash: SHA-256(0x00 || record).
#[must_use]
pub fn leaf_hash(record: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(record);
    h.finalize().into()
}

/// Interior node hash: SHA-256(0x01 || left || right).
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Verifies an inclusion proof (RFC 9162 §2.1.3.2) of `leaf` at `index` in a tree of
/// `size` leaves with root `root`.
#[must_use]
pub fn verify_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if index >= size || proof.len() > 64 {
        return false;
    }
    let (mut f, mut s) = (index, size.saturating_sub(1));
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

/// Verifies a consistency proof (RFC 9162 §2.1.4.2) that the tree of `size1` leaves with
/// root `root1` is a prefix of the tree of `size2` leaves with root `root2`.
#[must_use]
pub fn verify_consistency(size1: u64, size2: u64, root1: &Hash, root2: &Hash, proof: &[Hash]) -> bool {
    if size1 > size2 || proof.len() > 128 {
        return false;
    }
    if size1 == size2 {
        return proof.is_empty() && root1 == root2;
    }
    if size1 == 0 {
        return proof.is_empty();
    }
    // When size1 is a power of two, root1 is the first node of the proof path.
    let mut path = proof.iter();
    let first = if size1.is_power_of_two() {
        *root1
    } else {
        match path.next() {
            Some(h) => *h,
            None => return false,
        }
    };
    let (mut f, mut s) = (size1.saturating_sub(1), size2.saturating_sub(1));
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (first, first);
    for c in path {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && fr == *root1 && sr == *root2
}

/// The right edge of a tree: one hash per set bit of `size` (perfect subtrees, largest
/// first). Appending is amortised O(1); the root is O(log n).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactRange {
    size: u64,
    nodes: Vec<Hash>,
}

impl CompactRange {
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Appends one leaf hash.
    pub fn push(&mut self, leaf: Hash) {
        let mut h = leaf;
        let mut s = self.size;
        // Merge with every complete subtree this leaf completes.
        while s & 1 == 1 {
            let Some(left) = self.nodes.pop() else { break };
            h = node_hash(&left, &h);
            s >>= 1;
        }
        self.nodes.push(h);
        self.size = self.size.saturating_add(1);
    }

    /// Root of the tree (RFC 6962 MTH).
    #[must_use]
    pub fn root(&self) -> Hash {
        let mut it = self.nodes.iter().rev();
        let Some(last) = it.next() else { return empty_root() };
        it.fold(*last, |acc, left| node_hash(left, &acc))
    }
}

/// Root over a slice of leaf hashes.
#[must_use]
pub fn root_of(leaves: &[Hash]) -> Hash {
    let mut r = CompactRange::default();
    for l in leaves {
        r.push(*l);
    }
    r.root()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference MTH (RFC 6962 §2.1), recursive.
    fn mth(l: &[Hash]) -> Hash {
        match l.len() {
            0 => empty_root(),
            1 => l[0],
            n => {
                let mut k = 1;
                while k * 2 < n {
                    k *= 2;
                }
                node_hash(&mth(&l[..k]), &mth(&l[k..]))
            }
        }
    }

    #[test]
    fn compact_range_matches_reference() {
        let leaves: Vec<Hash> = (0..70u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        for n in 0..=leaves.len() {
            assert_eq!(root_of(&leaves[..n]), mth(&leaves[..n]), "n={n}");
        }
    }
}
