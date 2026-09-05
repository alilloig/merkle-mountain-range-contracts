/// Pure inclusion-proof verification against a caller-supplied anchor `(root, size)`.
///
/// Nothing in this module reads objects. The anchor is trusted as given: a caller that takes
/// `root` from an untrusted source proves nothing. `mmr::mmr` wraps these functions with anchors
/// read from the MMR object or its checkpoint table; use those wrappers in dispute paths.
///
/// Soundness invariants:
/// 1. every position that reaches `hash_with_integer` is derived here from `(position, size)`;
///    the proof carries no positions except the leaf position(s);
/// 2. leaf positions are validated: `1 <= position <= size` and height 1;
/// 3. the root is a comparison target only; it is never hashed again.
///
/// Malformed proofs abort with the error constants of this module. A well-formed proof that
/// does not match the anchor returns `false`.
module mmr::mmr_proof;

use mmr::mmr_utils;

/// Byte length of every accepted proof hash (blake2b-256).
const HASH_LENGTH: u64 = 32;

/// `size` is not a reachable MMR size (checked by the public pure functions only).
#[error]
const EInvalidSize: vector<u8> = b"Size is not a reachable MMR size";
/// Position 0 or beyond the MMR size.
#[error]
const EPositionOutOfRange: vector<u8> = b"Position must be between 1 and the MMR size";
/// Position is an internal node; only leaves can be proven.
#[error]
const ENotALeaf: vector<u8> = b"Proofs can only be verified for leaf nodes";
/// The local tree path has the wrong number of hashes for `(position, size)`.
#[error]
const EPathLength: vector<u8> = b"Local tree path has the wrong number of hashes";
/// The left or right peak list has the wrong number of hashes for `(position, size)`.
#[error]
const EPeaksCount: vector<u8> = b"Wrong number of left or right peak hashes";
/// A proof hash is not 32 bytes.
#[error]
const EHashLength: vector<u8> = b"Every proof hash must be 32 bytes";
/// A batch proof with no positions.
#[error]
const EEmptyBatch: vector<u8> = b"Batch must contain at least one leaf";
/// `positions` and `leaves` differ in length.
#[error]
const ELengthMismatch: vector<u8> = b"positions and leaves must have the same length";
/// `positions` is not strictly increasing (also rejects position 0 and duplicates).
#[error]
const EPositionsNotSorted: vector<u8> = b"positions must be strictly increasing";
/// The batch proof ran out of sibling or untouched-peak hashes.
#[error]
const EMissingProofHashes: vector<u8> = b"Proof ran out of hashes";
/// The batch proof has hashes the verifier did not consume, or the queue was not drained at a peak.
#[error]
const ELeftoverProofHashes: vector<u8> = b"Proof has unused hashes";
/// A computed parent lies above its peak. Unreachable for the position math as specified;
/// defence in depth.
#[error]
const EMalformedProof: vector<u8> = b"Proof structure is inconsistent";

// ------------------------------------------------------------------------------ single leaf

/// Return true when `leaf` is the data at `position` in the MMR whose root at `size` nodes is
/// `root`. Aborts on a malformed proof, including an unreachable `size` (`EInvalidSize`).
/// `path`: sibling hashes from the leaf up to its local peak, bottom-up.
/// `left_peaks` / `right_peaks`: hashes of the peaks left / right of the local peak.
public fun verify_with_root(
    root: vector<u8>,
    size: u64,
    position: u64,
    leaf: vector<u8>,
    path: vector<vector<u8>>,
    left_peaks: vector<vector<u8>>,
    right_peaks: vector<vector<u8>>,
): bool {
    compute_root(size, position, leaf, path, left_peaks, right_peaks) == root
}

/// Recompute the MMR root implied by an inclusion proof of `leaf` at `position` in an MMR of
/// `size` nodes. Asserts `is_valid_size(size)`. Aborts on a malformed proof. Compare the result
/// with a trusted root.
public fun compute_root(
    size: u64,
    position: u64,
    leaf: vector<u8>,
    path: vector<vector<u8>>,
    left_peaks: vector<vector<u8>>,
    right_peaks: vector<vector<u8>>,
): vector<u8> {
    assert!(mmr_utils::is_valid_size(size), EInvalidSize);
    root_from_single_proof(size, position, leaf, path, left_peaks, right_peaks)
}

/// Same as `compute_root` without the `is_valid_size` check. Package-internal: `mmr::mmr` calls
/// it with sizes read from storage, which are valid by construction.
public(package) fun compute_root_trusted_size(
    size: u64,
    position: u64,
    leaf: vector<u8>,
    path: vector<vector<u8>>,
    left_peaks: vector<vector<u8>>,
    right_peaks: vector<vector<u8>>,
): vector<u8> {
    root_from_single_proof(size, position, leaf, path, left_peaks, right_peaks)
}

/// Single verify core. Check order is normative: the first failing check names the abort.
fun root_from_single_proof(
    size: u64,
    position: u64,
    leaf: vector<u8>,
    path: vector<vector<u8>>,
    left_peaks: vector<vector<u8>>,
    right_peaks: vector<vector<u8>>,
): vector<u8> {
    // Position checks come before any position math.
    assert!(position >= 1 && position <= size, EPositionOutOfRange);
    assert!(mmr_utils::get_height(position) == 1, ENotALeaf);
    // Shape checks: the proof length is fixed by (position, size).
    let merge_path = mmr_utils::calc_proof_tree_path_positions(position, size);
    assert!(path.length() == merge_path.length(), EPathLength);
    let local_peak = if (merge_path.length() != 0) {
        mmr_utils::get_parent_position(merge_path[merge_path.length() - 1])
    } else {
        position
    };
    let peaks_positions = mmr_utils::get_peaks_positions(size);
    let expected_left = mmr_utils::get_left_peaks_positions(local_peak, peaks_positions).length();
    let expected_right = mmr_utils::get_right_peaks_positions(local_peak, peaks_positions).length();
    assert!(left_peaks.length() == expected_left, EPeaksCount);
    assert!(right_peaks.length() == expected_right, EPeaksCount);
    assert_hash_lengths(&path);
    assert_hash_lengths(&left_peaks);
    assert_hash_lengths(&right_peaks);
    // Path merge (unchanged v1 math): climb from the leaf to the local peak.
    let mut node_hash = mmr_utils::hash_with_integer(position, vector[leaf]);
    let mut i = 0;
    while (i < merge_path.length()) {
        let child_hashes = if (!mmr_utils::is_right_sibling(merge_path[i])) {
            vector[path[i], node_hash]
        } else {
            vector[node_hash, path[i]]
        };
        node_hash = mmr_utils::hash_with_integer(
            mmr_utils::get_parent_position(merge_path[i]),
            child_hashes,
        );
        i = i + 1;
    };
    // Bag the peaks with the size (unchanged v1 math).
    let mut peaks_hashes = left_peaks;
    peaks_hashes.push_back(node_hash);
    peaks_hashes.append(right_peaks);
    mmr_utils::hash_with_integer(size, peaks_hashes)
}

// ------------------------------------------------------------------------------ multiple leaves

/// Return true when `leaves[i]` is the data at `positions[i]` for every `i`, in the MMR whose
/// root at `size` nodes is `root`. Aborts on a malformed proof.
/// `positions`: strictly increasing 1-based leaf positions (the caller sorts; Move does not).
/// `leaves`: raw data, `leaves[i]` belongs to `positions[i]`.
/// `siblings`: sibling hashes the verifier cannot derive from the batch, in consumption order:
/// mountain by mountain left to right; inside a mountain by (height, position), i.e. all
/// height-1 siblings left to right, then height-2, and so on.
/// `untouched_peaks`: hashes of the peaks whose mountain holds no batch leaf, left to right.
/// A batch of one leaf equals the single proof: `siblings == path`,
/// `untouched_peaks == left_peaks ++ right_peaks`. A batch of all leaves has both empty.
public fun verify_multiple_with_root(
    root: vector<u8>,
    size: u64,
    positions: vector<u64>,
    leaves: vector<vector<u8>>,
    siblings: vector<vector<u8>>,
    untouched_peaks: vector<vector<u8>>,
): bool {
    compute_batch_root(size, positions, leaves, siblings, untouched_peaks) == root
}

/// Recompute the MMR root implied by a batch inclusion proof. Asserts `is_valid_size(size)`.
/// Aborts on a malformed proof.
public fun compute_batch_root(
    size: u64,
    positions: vector<u64>,
    leaves: vector<vector<u8>>,
    siblings: vector<vector<u8>>,
    untouched_peaks: vector<vector<u8>>,
): vector<u8> {
    assert!(mmr_utils::is_valid_size(size), EInvalidSize);
    root_from_batch_proof(size, positions, leaves, siblings, untouched_peaks)
}

/// Same as `compute_batch_root` without the `is_valid_size` check. Package-internal.
public(package) fun compute_batch_root_trusted_size(
    size: u64,
    positions: vector<u64>,
    leaves: vector<vector<u8>>,
    siblings: vector<vector<u8>>,
    untouched_peaks: vector<vector<u8>>,
): vector<u8> {
    root_from_batch_proof(size, positions, leaves, siblings, untouched_peaks)
}

/// Batch verify core: one FIFO climb per mountain, left to right. Siblings are read from the
/// proof only when the verifier cannot derive them from the batch itself.
fun root_from_batch_proof(
    size: u64,
    positions: vector<u64>,
    leaves: vector<vector<u8>>,
    siblings: vector<vector<u8>>,
    untouched_peaks: vector<vector<u8>>,
): vector<u8> {
    let k = positions.length();
    assert!(k >= 1, EEmptyBatch);
    assert!(leaves.length() == k, ELengthMismatch);
    let mut prev = 0;
    positions.do_ref!(|position| {
        let p = *position;
        assert!(p > prev, EPositionsNotSorted); // rejects position 0, duplicates and unsorted input
        assert!(p <= size, EPositionOutOfRange);
        assert!(mmr_utils::get_height(p) == 1, ENotALeaf);
        prev = p;
    });
    assert_hash_lengths(&siblings);
    assert_hash_lengths(&untouched_peaks);
    let peaks_positions = mmr_utils::get_peaks_positions(size);
    let s = siblings.length();
    let u = untouched_peaks.length();
    let mut computed_peaks = vector[];
    let mut li = 0; // cursor over positions / leaves
    let mut si = 0; // cursor over siblings
    let mut pi = 0; // cursor over untouched_peaks
    peaks_positions.do_ref!(|peak_ref| {
        let peak = *peak_ref;
        // FIFO queue of (position, hash): `head` is the front, push_back is the back.
        let mut q_pos = vector[];
        let mut q_hash = vector[];
        while (li < k && positions[li] <= peak) {
            q_pos.push_back(positions[li]);
            q_hash.push_back(mmr_utils::hash_with_integer(positions[li], vector[leaves[li]]));
            li = li + 1;
        };
        if (q_pos.is_empty()) {
            // Mountain untouched by the batch: its peak comes from the proof.
            assert!(pi < u, EMissingProofHashes);
            computed_peaks.push_back(untouched_peaks[pi]);
            pi = pi + 1;
        } else {
            let mut head = 0;
            loop {
                let pos = q_pos[head];
                let h = q_hash[head];
                head = head + 1;
                if (pos == peak) {
                    // Drain check: with distinct sorted leaves exactly one entry reaches the peak.
                    assert!(head == q_pos.length(), ELeftoverProofHashes);
                    computed_peaks.push_back(h);
                    break
                };
                // Position math once per node (the definitions of `mmr_utils`, inlined): a node
                // is a right sibling when the node one sibling offset to its right has a
                // different height. `pos >= 1` here (positions were validated above), so the
                // `EStartsAtOne` guard of `is_right_sibling` is not needed and `get_height(pos)`
                // runs once instead of twice.
                let height = mmr_utils::get_height(pos);
                let off = mmr_utils::sibling_offset(height);
                let right = mmr_utils::get_height(pos + off) != height;
                let sibling = if (right) { pos - off } else { pos + off };
                let parent = if (right) { pos + 1 } else { sibling + 1 };
                assert!(parent <= peak, EMalformedProof);
                let sibling_hash = if (head < q_pos.length() && q_pos[head] == sibling) {
                    // The sibling is in the batch: derived, nothing consumed from the proof.
                    let derived = q_hash[head];
                    head = head + 1;
                    derived
                } else {
                    assert!(si < s, EMissingProofHashes);
                    let read = siblings[si];
                    si = si + 1;
                    read
                };
                let children = if (right) {
                    vector[sibling_hash, h]
                } else {
                    vector[h, sibling_hash]
                };
                q_pos.push_back(parent);
                q_hash.push_back(mmr_utils::hash_with_integer(parent, children));
            };
        };
    });
    assert!(si == s, ELeftoverProofHashes);
    assert!(pi == u, ELeftoverProofHashes);
    // Bag every peak with the size (unchanged v1 math).
    mmr_utils::hash_with_integer(size, computed_peaks)
}

// ------------------------------------------------------------------------------ helpers

/// Abort with `EHashLength` unless every hash has exactly `HASH_LENGTH` bytes.
fun assert_hash_lengths(hashes: &vector<vector<u8>>) {
    hashes.do_ref!(|h| assert!(h.length() == HASH_LENGTH, EHashLength));
}
