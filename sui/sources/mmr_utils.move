/// Pure Merkle Mountain Range position math and hashing.
///
/// Positions are 1-based node positions in post-order numbering. Heights are 1-based (leaves
/// have height 1). Every function here is pure: no objects, no context. The hashing convention
/// is shared with the Aptos port and MUST NOT change:
///   leaf = blake2b256(decimal_ascii(position) || data)
///   node = blake2b256(decimal_ascii(position) || left || right)
///   root = blake2b256(decimal_ascii(size) || peaks left-to-right)
///   empty root = blake2b256("0")
module mmr::mmr_utils;

use sui::hash;
use mmr::mmr_bits;

/// Attempting to access node 0.
#[error]
const EStartsAtOne: vector<u8> = b"First position of a MMR node is 1";
/// The position is an internal node, not a leaf.
#[error]
const ENotALeaf: vector<u8> = b"Position is not a leaf node";
/// Position 0 or beyond the MMR size (or beyond the node set in `get_hashes_from_positions`).
#[error]
const EPositionOutOfRange: vector<u8> = b"Position must be between 1 and the MMR size";

/// The node positions an inclusion proof for one leaf needs, split by role.
public struct ProofPositions has copy, drop {
    /// Sibling positions on the path from the leaf to its local peak, bottom-up.
    local_tree_path_positions: vector<u64>,
    /// Positions of the peaks left of the leaf's local peak, left to right.
    left_peaks_positions: vector<u64>,
    /// Positions of the peaks right of the leaf's local peak, left to right.
    right_peaks_positions: vector<u64>,
}

/// Sibling positions on the path from the leaf to its local peak, bottom-up.
public fun local_tree_path_positions(proof_positions: &ProofPositions): vector<u64> {
    proof_positions.local_tree_path_positions
}

/// Positions of the peaks left of the leaf's local peak.
public fun left_peaks_positions(proof_positions: &ProofPositions): vector<u64> {
    proof_positions.left_peaks_positions
}

/// Positions of the peaks right of the leaf's local peak.
public fun right_peaks_positions(proof_positions: &ProofPositions): vector<u64> {
    proof_positions.right_peaks_positions
}

/// Calculate all positions needed for an inclusion proof of the leaf at `position` in an MMR of
/// `size` nodes: the local path, and the peaks to the left and to the right of its local peak.
/// Aborts with `EPositionOutOfRange` unless `1 <= position <= size` and with `ENotALeaf` when
/// `position` is an internal node.
public fun calc_proof_positions(position: u64, size: u64): ProofPositions {
    assert!(position >= 1 && position <= size, EPositionOutOfRange);
    assert!(get_height(position) == 1, ENotALeaf);
    // Get the local tree path positions
    let tree_path_positions = calc_proof_tree_path_positions(position, size);
    // The local peak is the parent of the last path position, or the leaf itself when the leaf
    // is a peak (empty path)
    let path_peak_position: u64;
    if (tree_path_positions.length() != 0) {
        path_peak_position = get_parent_position(tree_path_positions[tree_path_positions.length() - 1]);
    } else {
        path_peak_position = position;
    };
    // Get all peaks in the MMR
    let peaks_positions = get_peaks_positions(size);
    let mut left_peaks_positions = vector::empty<u64>();
    let mut right_peaks_positions = vector::empty<u64>();
    // If MMR is not a perfect binary tree or an empty tree
    if (peaks_positions.length() > 1) {
        // Collect peaks to the left of the element's peak
        left_peaks_positions = get_left_peaks_positions(path_peak_position, peaks_positions);
        // Collect peaks to the right of the element's peak
        right_peaks_positions = get_right_peaks_positions(path_peak_position, peaks_positions);
    };
    ProofPositions {
        local_tree_path_positions: tree_path_positions,
        left_peaks_positions: left_peaks_positions,
        right_peaks_positions: right_peaks_positions,
    }
}

/// Calculate the sibling positions on the path from `proof_position` up to its local peak in an
/// MMR of `size` nodes. The last node of an MMR is always a peak, so its path is empty.
/// Aborts with `EPositionOutOfRange` unless `1 <= proof_position <= size` (the loop would pop an
/// empty vector otherwise).
public fun calc_proof_tree_path_positions(proof_position: u64, size: u64): vector<u64> {
    assert!(proof_position >= 1 && proof_position <= size, EPositionOutOfRange);
    let mut path_positions = vector::empty<u64>();
    let mut current_node_position: u64;
    let mut sibling_position: u64;
    // The last node of an MMR is always a peak, so its path is empty
    if (proof_position != size) {
        // navigate the binary tree from the leaf to the peak, storing each node that would be
        // necessary to calculate the peak hash
        current_node_position = proof_position;
        while (current_node_position <= size) {
            // store the sibling position we need for computing the next level node
            sibling_position = get_sibling_position(current_node_position);
            path_positions.push_back(sibling_position);
            // calculate the parent node position for the next iteration
            current_node_position = get_parent_position(current_node_position);
        };
        // Algorithm always stores one more node than necessary so we need to trim it
        path_positions.pop_back();
    };
    path_positions
}

/// Calculate all peak positions of an MMR of `size` nodes, left to right.
/// `size` must be a reachable MMR size (see `is_valid_size`); for other sizes the returned list
/// is the greedy partial decomposition and MUST NOT be used.
public fun get_peaks_positions(size: u64): vector<u64> {
    let mut peaks_positions: vector<u64> = vector::empty<u64>();
    // Empty MMR has no peaks
    if (size == 0) { return peaks_positions };
    // Check if the MMR is a perfect binary tree so the size is the position of the only peak
    if (mmr_bits::are_all_ones(size)) {
        peaks_positions.push_back(size);
    } else {
        // If the MMR is multi tree, calculate the height of the largest perfect binary tree
        // that can fit a MMR of this size
        let largest_tree_height = mmr_bits::get_length(size) - 1;
        // Use the height to calculate the largest, and therefore leftmost, tree size (2^height - 1)
        let mut tree_size = mmr_bits::create_all_ones(largest_tree_height);
        // Iterate over all perfect trees inside the MMR, storing how many nodes are outside the
        // tree we store the peak position on each iteration
        let mut nodes_left = size;
        let mut peak_position = 0;
        while (tree_size != 0) {
            // If the amount of nodes left to check is smaller than the tree size, that means
            // that that peak is not in the MMR and we just need to get the next smaller tree
            if (nodes_left >= tree_size) {
                nodes_left = nodes_left - tree_size;
                peak_position = peak_position + tree_size;
                // Peaks positions are stored from left to right
                peaks_positions.push_back(peak_position);
            };
            // Calculate the next smaller perfect binary tree size
            tree_size = tree_size >> 1;
        };
    };
    peaks_positions
}

/// Return true when `size` is a reachable MMR size, i.e. the greedy decomposition into perfect
/// binary trees of strictly decreasing height leaves no node over. 0 is valid (empty MMR).
/// Never aborts: the largest tree considered has height 63 (2^63 - 1 nodes), so the bit length
/// of `size` is clamped to 63 before `create_all_ones` is called.
public fun is_valid_size(size: u64): bool {
    let mut nodes_left = size;
    let mut height = mmr_bits::get_length(size);
    if (height == 64) { height = 63 };
    while (height > 0) {
        let tree_size = mmr_bits::create_all_ones(height);
        if (nodes_left >= tree_size) {
            nodes_left = nodes_left - tree_size;
        };
        height = height - 1;
    };
    nodes_left == 0
}

/// Number of leaves in an MMR of `size` nodes: the sum of 2^(height-1) over its peaks.
/// `size` must be valid.
public fun size_to_leaf_count(size: u64): u64 {
    let peaks_positions = get_peaks_positions(size);
    let mut count = 0;
    peaks_positions.do_ref!(|peak| {
        count = count + (1 << (get_height(*peak) - 1));
    });
    count
}

/// Position of the leaf with 0-based leaf index `index`: `2 * index - popcount(index) + 1`.
/// Precondition: `index < 2^63` (the multiplication overflows u64 otherwise; raw arithmetic
/// abort). No verifier calls this function.
public fun leaf_index_to_position(index: u64): u64 {
    2 * index - mmr_bits::count_ones(index) + 1
}

/// 0-based leaf index of the leaf at `position`. Aborts with `EStartsAtOne` for position 0 and
/// `ENotALeaf` when `position` is an internal node. Every leaf is appended onto a valid MMR of
/// size `position - 1`, so the index is `size_to_leaf_count(position - 1)`.
/// Precondition: `position < u64::MAX` (see `get_height`).
public fun position_to_leaf_index(position: u64): u64 {
    assert!(position > 0, EStartsAtOne);
    assert!(get_height(position) == 1, ENotALeaf);
    size_to_leaf_count(position - 1)
}

/// Collect the peak positions smaller than `peak_position`, left to right.
public fun get_left_peaks_positions(peak_position: u64, peaks_positions: vector<u64>): vector<u64> {
    let mut left_peaks_positions = vector::empty<u64>();
    let mut i = 0;
    while (i < peaks_positions.length()) {
        if (peaks_positions[i] < peak_position){
            left_peaks_positions.push_back(peaks_positions[i]);
        };
        i = i + 1;
    };
    left_peaks_positions
}

/// Collect the peak positions greater than `peak_position`, left to right.
public fun get_right_peaks_positions(peak_position: u64, peaks_positions: vector<u64>): vector<u64> {
    let mut right_peaks_positions = vector::empty<u64>();
    let mut i = 0;
    while (i < peaks_positions.length()) {
        if (peaks_positions[i] > peak_position){
            right_peaks_positions.push_back(peaks_positions[i]);
        };
        i = i + 1;
    };
    right_peaks_positions
}

/// Position of the parent of the node at `position`. A right sibling's parent is the next
/// position; a left sibling's parent is the position after its right sibling.
public fun get_parent_position(position: u64): u64 {
    let parent_position: u64;
    if (is_right_sibling(position)) {
        parent_position = position + 1;
    } else {
        parent_position = get_sibling_position(position) + 1;
    };
    parent_position
}

/// Position of the sibling of the node at `position`. Siblings at height h are 2^h - 1 apart.
public fun get_sibling_position(position: u64): u64 {
    let sibling_position: u64;
    if (is_right_sibling(position)) {
        sibling_position = position - sibling_offset(get_height(position));
    } else {
        sibling_position = position + sibling_offset(get_height(position));
    };
    sibling_position
}

/// Return true when the node at `position` is a right sibling: a left sibling has a node of the
/// same height one sibling offset to its right. Aborts with `EStartsAtOne` for position 0.
public fun is_right_sibling(position: u64): bool {
    // Ensure position is a valid MMR node
    assert!(position > 0, EStartsAtOne);
    // If the node is at the same height as the node on position + offset, it is a left node
    let height = get_height(position);
    let sibling_offset = sibling_offset(height);
    height != get_height(position + sibling_offset)
}

/// Distance between two siblings at `height`: 2^height - 1.
public fun sibling_offset(height: u8): u64 {
    mmr_bits::create_all_ones(height)
}

/// Height (1-based) of the node at `position`. The leftmost node of each height has an all-ones
/// binary representation; jump left until one is reached and read its bit length (7 = 0b111 -> 3).
/// Precondition: `position < u64::MAX` (`mmr_bits::are_all_ones` computes `num + 1`; raw
/// arithmetic abort at u64::MAX). Unreachable through the verifiers: `EPositionOutOfRange`
/// bounds every position by a real size first.
public fun get_height(position: u64): u8 {
    // We are looking for the leftmost node at the node level, we start our search from the position itself
    let mut left_most_node = position;
    // Leftmost nodes bit representation have all their bits set to one, if the current isn't
    // jump to the next* node on the left
    while (!mmr_bits::are_all_ones(left_most_node)) {
        left_most_node = jump_left(left_most_node)
    };
    // The height of a level can be obtained by getting the length of the binary representation
    // of the leftmost node of that level, e.g. 7(111), length 3, height 3
    mmr_bits::get_length(left_most_node)
}

/// Move to a node of the same height further left by dropping the most significant bit and
/// adding one: `position - (2^(len-1) - 1)`. Examples: 6 -> 3; 11 -> 4.
public fun jump_left (position: u64): u64 {
    // Find the most significant bit position
    let most_significant_bit: u64 = 1 << (mmr_bits::get_length(position) - 1);
    // Subtract all bits to the right of the MSB
    position - (most_significant_bit - 1)
}

/// Read the hashes stored at `positions` (1-based) out of a full node set (`nodes_hashes[p - 1]`).
/// Aborts with `EStartsAtOne` for position 0 and with `EPositionOutOfRange` for a position beyond
/// `nodes_hashes.length()`.
public fun get_hashes_from_positions(nodes_hashes: &vector<vector<u8>>, positions: &vector<u64>): vector<vector<u8>> {
    let mut hashes = vector::empty<vector<u8>>();
    let mut i = 0;
    while (i < positions.length()) {
        assert!(positions[i] >= 1, EStartsAtOne);
        assert!(positions[i] <= nodes_hashes.length(), EPositionOutOfRange);
        hashes.push_back(nodes_hashes[positions[i] - 1]);
        i = i + 1;
    };
    hashes
}

/// Hash `number` (decimal ASCII) followed by `hashes` concatenated, with blake2b-256.
/// Used for leaves (position, [data]), internal nodes (position, [left, right]) and the root
/// (size, peaks). The integer is not length-framed; see the README "Hashing" caveats.
public fun hash_with_integer(number: u64, hashes: vector<vector<u8>>): vector<u8> {
    // Concatenate all hashes together
    let mut chain: vector<u8> = vector::empty<u8>();
    chain.append(number.to_string().into_bytes());
    let mut i = 0;
    while (i < hashes.length()) {
        chain.append(hashes[i]);
        i = i + 1;
    };
    hash::blake2b256(&chain)
}
