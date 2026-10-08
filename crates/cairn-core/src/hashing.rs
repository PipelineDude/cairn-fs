//! Hash primitives for file verification, snapshot trees, inventories and
//! replica transfers.  These helpers deliberately use domain-separated,
//! length-delimited encodings: concatenating human-controlled names or bytes
//! directly into a BLAKE3 input would make a tree format ambiguous.

use std::collections::{BTreeMap, BTreeSet};

const FILE_CONTEXT: &str = "cairn file digest v1";
const ENTRY_CONTEXT: &str = "cairn snapshot entry v1";
const NODE_CONTEXT: &str = "cairn snapshot node v1";
const EMPTY_CONTEXT: &str = "cairn snapshot empty v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDigest {
    pub logical_size: u64,
    pub hash: [u8; 32],
}

/// Streaming digest of a logical file. `update_zeros` hashes sparse holes
/// without allocating their complete contents.
pub struct FileHasher {
    hasher: blake3::Hasher,
    logical_size: u64,
}

impl FileHasher {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new_derive_key(FILE_CONTEXT),
            logical_size: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.logical_size = self
            .logical_size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("logical file size overflow"))?;
        self.hasher.update(bytes);
        Ok(())
    }

    pub fn update_zeros(&mut self, len: u64) -> anyhow::Result<()> {
        const ZEROS: [u8; 8192] = [0; 8192];
        self.logical_size = self
            .logical_size
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("logical file size overflow"))?;
        let mut remaining = len;
        while remaining != 0 {
            let take = remaining.min(ZEROS.len() as u64) as usize;
            self.hasher.update(&ZEROS[..take]);
            remaining -= take as u64;
        }
        Ok(())
    }

    pub fn finish(mut self) -> FileDigest {
        self.hasher.update(&self.logical_size.to_le_bytes());
        FileDigest {
            logical_size: self.logical_size,
            hash: *self.hasher.finalize().as_bytes(),
        }
    }
}

impl Default for FileHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEntry {
    pub name: Vec<u8>,
    /// One byte on purpose: file=1, directory=2, symlink=3; callers must not
    /// overload it with platform `mode_t` bits.
    pub kind: u8,
    pub mode: u32,
    pub logical_size: u64,
    pub content_hash: [u8; 32],
}

fn prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub fn snapshot_entry_hash(entry: &SnapshotEntry) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(ENTRY_CONTEXT);
    h.update(&[entry.kind]);
    h.update(&entry.mode.to_le_bytes());
    h.update(&entry.logical_size.to_le_bytes());
    prefixed(&mut h, &entry.name);
    h.update(&entry.content_hash);
    *h.finalize().as_bytes()
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(NODE_CONTEXT);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

pub fn snapshot_root(entries: &[SnapshotEntry]) -> anyhow::Result<[u8; 32]> {
    let mut ordered = BTreeMap::new();
    for entry in entries {
        if ordered
            .insert(entry.name.clone(), snapshot_entry_hash(entry))
            .is_some()
        {
            anyhow::bail!("duplicate snapshot entry name");
        }
    }
    let leaves: Vec<[u8; 32]> = ordered.into_values().collect();
    if leaves.is_empty() {
        return Ok(blake3::derive_key(EMPTY_CONTEXT, b""));
    }
    Ok(merkle_root_consistent(&leaves))
}

/// H15: a Merkle inclusion proof for one leaf of a `snapshot_root` tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: usize,
    pub level_count: usize,
    pub siblings: Vec<[u8; 32]>,
}

pub fn merkle_root_consistent(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(match pair {
                [l, r] => merkle_node(l, r),
                [only] => merkle_node(only, only),
                _ => unreachable!(),
            });
        }
        level = next;
    }
    level[0]
}

/// H15: build the proof for `leaf_index` in the same pairing scheme as
/// `snapshot_root` (odd round duplicates the last leaf/node).  The proof
/// binds name+kind+metadata+content via the leaf hash `snapshot_entry_hash`.
pub fn merkle_proof_for(sorted_leaves: &[[u8; 32]], leaf_index: usize) -> Option<InclusionProof> {
    if sorted_leaves.is_empty() || leaf_index >= sorted_leaves.len() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = sorted_leaves.to_vec();
    let mut index = leaf_index;
    let mut siblings = Vec::new();
    let mut level_count = 1usize;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for (i, pair) in level.chunks(2).enumerate() {
            next.push(match pair {
                [l, r] => {
                    if i == index / 2 {
                        siblings.push(if index % 2 == 0 { *r } else { *l });
                    }
                    merkle_node(l, r)
                }
                [only] => {
                    if i == index / 2 {
                        siblings.push(*only); // self-sibling for odd node
                    }
                    merkle_node(only, only)
                }
                _ => unreachable!(),
            });
        }
        index /= 2;
        level = next;
        level_count += 1;
    }
    Some(InclusionProof {
        index: leaf_index,
        level_count,
        siblings,
    })
}

/// H15: verify that `leaf_hash` is included at `proof.index` under `value`.
/// Purely recomputes the path; it does NOT prove freshness of `value`.
pub fn verify_merkle_inclusion(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    proof: &InclusionProof,
) -> bool {
    if proof.siblings.len() + 1 != proof.level_count {
        return false;
    }
    let mut cur = *leaf_hash;
    let mut index = proof.index;
    for sibling in &proof.siblings {
        cur = if index % 2 == 0 {
            merkle_node(&cur, sibling)
        } else {
            merkle_node(sibling, &cur)
        };
        index /= 2;
    }
    &cur == root
}

/// H10: kind of change between two snapshot states for one path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    Added,
    Removed,
    ContentChanged,
    MetadataChanged,
}

/// H10: one changed path in a snapshot diff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeChange {
    pub path: Vec<u8>,
    pub kind: ChangeKind,
}

/// H10: diff two snapshot entry sets (full paths, sorted by name) and classify
/// every change as content-only, metadata-only, added or removed.
///
/// Equal names with equal content (files) or equal subtree digest (directories,
/// kind=2) are skipped by `entry_equal`, so unrelated metadata noise does not
/// mark a subtree changed.  Renames surface as added+removed; hardlinks share
/// content with different metadata and are reported as metadata-only.
pub fn diff_snapshots(
    old: &[(Vec<u8>, SnapshotEntry)],
    new: &[(Vec<u8>, SnapshotEntry)],
) -> Vec<TreeChange> {
    let mut sorted_old: BTreeMap<Vec<u8>, SnapshotEntry> = BTreeMap::new();
    for (name, entry) in old {
        sorted_old.insert(name.clone(), entry.clone());
    }
    let mut sorted_new: BTreeMap<Vec<u8>, SnapshotEntry> = BTreeMap::new();
    for (name, entry) in new {
        sorted_new.insert(name.clone(), entry.clone());
    }

    let mut out = Vec::new();
    for (name, old_entry) in &sorted_old {
        match sorted_new.get(name) {
            None => out.push(TreeChange {
                path: name.clone(),
                kind: ChangeKind::Removed,
            }),
            Some(new_entry) => {
                if old_entry == new_entry {
                    continue;
                }
                let content_equal = old_entry.kind == new_entry.kind
                    && old_entry.content_hash == new_entry.content_hash;
                let kind = if content_equal {
                    ChangeKind::MetadataChanged
                } else {
                    ChangeKind::ContentChanged
                };
                out.push(TreeChange {
                    path: name.clone(),
                    kind,
                });
            }
        }
    }
    for name in sorted_new.keys() {
        if !sorted_old.contains_key(name) {
            out.push(TreeChange {
                path: name.clone(),
                kind: ChangeKind::Added,
            });
        }
    }
    out
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryReport {
    pub missing: Vec<String>,
    pub corrupt: Vec<String>,
    pub unreferenced: Vec<String>,
}

/// Compare a complete manifest reference set with a complete durable object
/// listing.  It intentionally never calls an object an orphan when `complete`
/// is false (e.g. a paginated or concurrent listing).
pub fn inventory_report(
    referenced: impl IntoIterator<Item = String>,
    available: impl IntoIterator<Item = (String, Vec<u8>)>,
    complete: bool,
) -> InventoryReport {
    let expected: BTreeSet<_> = referenced.into_iter().collect();
    let mut present = BTreeSet::new();
    let mut corrupt = Vec::new();
    for (id, bytes) in available {
        if blake3::hash(&bytes).to_hex().as_str() != id {
            corrupt.push(id.clone());
        }
        present.insert(id);
    }
    let missing = expected.difference(&present).cloned().collect();
    let unreferenced = if complete {
        present.difference(&expected).cloned().collect()
    } else {
        Vec::new()
    };
    InventoryReport {
        missing,
        corrupt,
        unreferenced,
    }
}

/// A copy can be skipped only after the destination object is read and proves
/// its expected ciphertext ID.  Metadata such as ETag is deliberately absent.
pub fn replica_matches(object_id: &str, bytes: &[u8]) -> bool {
    blake3::hash(bytes).to_hex().as_str() == object_id
}

/// Reconstruct the LOGICAL file digest from ordered chunk spans (offset, bytes).
///
/// Behaviour (H09):
/// - spans are processed sorted by offset; a later span must start exactly at
///   the previous end (duplicate/overlapping/out-of-placement spans are an
///   error — they would silently mask reorder/duplicate corruption);
/// - gaps between spans are hashed as logical zeroes without allocating them
///   (`FileHasher::update_zeros`), so sparse files keep bounded memory;
/// - the result includes the total logical size (same encoding as
///   `FileHasher::finish`), so a truncated file never verifies equal.
pub fn file_digest_from_spans(chunks: &[(u64, &[u8])]) -> anyhow::Result<FileDigest> {
    let mut ordered: Vec<(u64, &[u8])> = chunks.to_vec();
    ordered.sort_by_key(|(off, _)| *off);
    let mut hasher = FileHasher::new();
    let mut cursor: u64 = 0;
    for (off, data) in ordered {
        if off < cursor {
            anyhow::bail!(
                "chunk span at offset {off} overlaps or duplicates already-covered data (cursor {cursor})"
            );
        }
        hasher.update_zeros(off - cursor)?;
        hasher.update(data)?;
        cursor = off
            .checked_add(data.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("chunk span end overflow"))?;
    }
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_digest_is_streaming_and_sparse_holes_are_logical_zeroes() {
        let mut sparse = FileHasher::new();
        sparse.update(b"abc").unwrap();
        sparse.update_zeros(10_000).unwrap();
        sparse.update(b"z").unwrap();
        let sparse = sparse.finish();
        let mut contiguous = FileHasher::new();
        contiguous.update(b"abc").unwrap();
        contiguous.update(&vec![0; 10_000]).unwrap();
        contiguous.update(b"z").unwrap();
        assert_eq!(sparse, contiguous.finish());
    }

    #[test]
    fn merkle_root_binds_name_kind_metadata_and_content() {
        let entry = SnapshotEntry {
            name: b"a".to_vec(),
            kind: 1,
            mode: 0o644,
            logical_size: 3,
            content_hash: [1; 32],
        };
        let root = snapshot_root(std::slice::from_ref(&entry)).unwrap();
        let mut renamed = entry.clone();
        renamed.name = b"b".to_vec();
        assert_ne!(root, snapshot_root(&[renamed]).unwrap());
        let mut mode = entry;
        mode.mode = 0o600;
        assert_ne!(root, snapshot_root(&[mode]).unwrap());
    }

    #[test]
    fn file_digest_from_spans_matches_contiguous_and_rejects_bad_placement() {
        // Out-of-order input must sort to the SAME digest as sorted input.
        let a = b"prefix".as_slice();
        let b = b"middle".as_slice();
        let c = b"suffix".as_slice();
        let sorted = file_digest_from_spans(&[(0, a), (6, b), (12, c)]).unwrap();
        let shuffled = file_digest_from_spans(&[(12, c), (0, a), (6, b)]).unwrap();
        assert_eq!(sorted, shuffled);
        assert_eq!(sorted.logical_size, 18);

        // A sparse gap must be hashed as logical zeros.
        let with_gap = file_digest_from_spans(&[(0, a), (2_000, b)]).unwrap();
        let mut contiguous = FileHasher::new();
        contiguous.update(a).unwrap();
        contiguous.update_zeros(2_000 - a.len() as u64).unwrap();
        contiguous.update(b).unwrap();
        assert_eq!(with_gap, contiguous.finish());

        // Duplicate/overlap placement is an error: it would muffle a reorder.
        assert!(file_digest_from_spans(&[(0, a), (1, b)]).is_err());
        assert!(file_digest_from_spans(&[(0, a), (0, b)]).is_err());
    }

    #[test]
    fn snapshot_diff_classifies_changes_and_skips_equal_entries() {
        fn e(
            name: &[u8],
            kind: u8,
            mode: u32,
            size: u64,
            hash: [u8; 32],
        ) -> (Vec<u8>, SnapshotEntry) {
            (
                name.to_vec(),
                SnapshotEntry {
                    name: name.to_vec(),
                    kind,
                    mode,
                    logical_size: size,
                    content_hash: hash,
                },
            )
        }
        let old = vec![
            e(b"dir/f1", 1, 0o644, 3, [1; 32]),
            e(b"dir/f2", 1, 0o644, 3, [2; 32]),
            e(b"sym", 3, 0o777, 0, [3; 32]),
        ];
        let mut new = old.clone();
        // chmod on f1: metadata-only.
        new[0].1.mode = 0o600;
        let changes = diff_snapshots(&old, &new);
        assert_eq!(
            changes,
            vec![TreeChange {
                path: b"dir/f1".to_vec(),
                kind: ChangeKind::MetadataChanged
            }]
        );

        // Content change on f2 → ContentChanged.
        let mut content = old.clone();
        content[1].1.content_hash = [9; 32];
        let changes = diff_snapshots(&old, &content);
        assert_eq!(
            changes,
            vec![TreeChange {
                path: b"dir/f2".to_vec(),
                kind: ChangeKind::ContentChanged
            }]
        );

        // Rename sym → sm: surfaces as Added + Removed.
        let renamed = vec![
            old[0].clone(),
            old[1].clone(),
            e(b"sm", 3, 0o777, 0, [3; 32]),
        ];
        let changes = diff_snapshots(&old, &renamed);
        assert!(changes.contains(&TreeChange {
            path: b"sym".to_vec(),
            kind: ChangeKind::Removed
        }));
        assert!(changes.contains(&TreeChange {
            path: b"sm".to_vec(),
            kind: ChangeKind::Added
        }));
        // The remaining entries (f1, f2 with unchanged metadata) are skipped.
        assert_eq!(
            changes.len(),
            2,
            "unchanged entries must not be reported: {changes:?}"
        );
    }

    #[test]
    fn inventory_never_labels_orphans_from_partial_listing() {
        let good = b"good".to_vec();
        let id = blake3::hash(&good).to_hex().to_string();
        let report = inventory_report(
            vec![id.clone(), "missing".into()],
            vec![(id, good), ("bad".into(), b"wrong".to_vec())],
            false,
        );
        assert_eq!(report.missing, vec!["missing"]);
        assert_eq!(report.corrupt, vec!["bad"]);
        assert!(report.unreferenced.is_empty());
    }
}

#[test]
fn merkle_inclusion_proofs_verify_only_for_the_actual_members() {
    let entries = vec![
        SnapshotEntry {
            name: b"a".to_vec(),
            kind: 1,
            mode: 0o644,
            logical_size: 2,
            content_hash: [1; 32],
        },
        SnapshotEntry {
            name: b"b".to_vec(),
            kind: 1,
            mode: 0o644,
            logical_size: 3,
            content_hash: [2; 32],
        },
        SnapshotEntry {
            name: b"c".to_vec(),
            kind: 3,
            mode: 0o777,
            logical_size: 0,
            content_hash: [3; 32],
        },
    ];
    let root = snapshot_root(&entries).unwrap();
    let leaves: Vec<[u8; 32]> = entries.iter().map(snapshot_entry_hash).collect();

    for i in 0..entries.len() {
        let proof = merkle_proof_for(&leaves, i).unwrap();
        assert!(
            verify_merkle_inclusion(&root, &leaves[i], &proof),
            "idx {i}"
        );
        // Changing the leaf (content) must fail against the same root.
        let forged = [0xFFu8; 32];
        assert!(
            !verify_merkle_inclusion(&root, &forged, &proof),
            "forged leaf {i}"
        );
        // Wrong position must fail.
        let mut shifted = proof.clone();
        shifted.index = (i + 1) % entries.len();
        assert!(
            !verify_merkle_inclusion(&root, &leaves[i], &shifted),
            "shifted idx {i}"
        );
    }
    // Authenticity ≠ freshness: the same proof is valid for ANY root that
    // was computed from this leaf set — the doc's H15 warning.
    let other_root = merkle_proof_for(&leaves, 1)
        .map(|p| {
            let mut cur = leaves[1];
            let mut idx = 1;
            for sib in &p.siblings {
                cur = if idx % 2 == 0 {
                    merkle_node(&cur, sib)
                } else {
                    merkle_node(sib, &cur)
                };
                idx /= 2;
            }
            cur
        })
        .unwrap();
    assert_eq!(other_root, snapshot_root(&entries).unwrap());
}
