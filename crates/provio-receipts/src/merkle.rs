//! RFC 6962 Merkle tree hashing (as restated in RFC 9162 §2.1), the same
//! tree Rekor and Certificate Transparency use.
//!
//! - leaf hash: `SHA-256(0x00 || leaf_data)`
//! - node hash: `SHA-256(0x01 || left || right)`
//! - `MTH({}) = SHA-256("")`; for `n > 1`, split at `k`, the largest power
//!   of two strictly less than `n`: `MTH(D[n]) = node(MTH(D[0:k]), MTH(D[k:n]))`.
//!
//! In a provio receipt the leaf data of record `i` is the 32 raw bytes of its
//! `record_hash` (hex-decoded), in ledger order.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle tree hash over already-computed leaf hashes.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path `PATH(m, D[n])` for leaf `index` (RFC 9162 §2.1.3.1), leaf to
/// root. `None` if `index` is out of range.
pub fn inclusion_path(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    build_path(leaves, index, &mut path);
    Some(path)
}

fn build_path(leaves: &[Hash], m: usize, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        build_path(&leaves[..k], m, out);
        out.push(root(&leaves[k..]));
    } else {
        build_path(&leaves[k..], m - k, out);
        out.push(root(&leaves[..k]));
    }
}

/// Verify an inclusion proof (RFC 9162 §2.1.3.2): does `leaf` (a leaf
/// *hash*) sit at `index` in the tree of `size` leaves whose root is `root`?
pub fn verify_inclusion(leaf: &Hash, index: u64, size: u64, path: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let mut fnode = index;
    let mut snode = size - 1;
    let mut r = *leaf;
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &r == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
            .collect()
    }

    /// RFC 6962 empty-tree root and the single-leaf rule.
    #[test]
    fn empty_and_single() {
        assert_eq!(
            hex::encode(root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let l = leaf_hash(b"");
        // Known vector: leaf hash of the empty string.
        assert_eq!(
            hex::encode(l),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        assert_eq!(root(&[l]), l);
    }

    /// Certificate Transparency test vectors (trillian/merkle testonly):
    /// the tree over the eight leaves "", 0x00, 0x10, 0x2021, 0x3031,
    /// 0x40414243, 0x5051525354555657, 0x606162636465666768696a6b6c6d6e6f.
    #[test]
    fn ct_reference_roots() {
        let data: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            (0x60..=0x6f).collect(),
        ];
        let l: Vec<Hash> = data.iter().map(|d| leaf_hash(d)).collect();
        let expect = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (n, want) in expect.iter().enumerate() {
            assert_eq!(hex::encode(root(&l[..=n])), *want, "tree size {}", n + 1);
        }
    }

    #[test]
    fn every_proof_verifies_and_tampering_fails() {
        for n in 1..=33usize {
            let l = leaves(n);
            let r = root(&l);
            for i in 0..n {
                let path = inclusion_path(&l, i).unwrap();
                assert!(verify_inclusion(&l[i], i as u64, n as u64, &path, &r));
                // Wrong index, wrong size, wrong leaf, tampered path.
                if n > 1 {
                    let other = (i + 1) % n;
                    assert!(!verify_inclusion(&l[i], other as u64, n as u64, &path, &r));
                    assert!(!verify_inclusion(&l[other], i as u64, n as u64, &path, &r));
                    let mut bad = path.clone();
                    bad[0][0] ^= 1;
                    assert!(!verify_inclusion(&l[i], i as u64, n as u64, &bad, &r));
                }
                // (A path can be structurally valid for a neighbouring tree
                // size; the size is bound by the signed checkpoint, not the path.)
                assert!(!verify_inclusion(&l[i], n as u64, n as u64, &path, &r));
            }
            assert!(inclusion_path(&l, n).is_none());
        }
    }
}
