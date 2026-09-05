#[test_only]
module mmr::mmr_utils_tests;

use std::unit_test::assert_eq;
use mmr::mmr_bits;
use mmr::mmr_utils;

/// Empty root `blake2b256("0")` (Python reference, spec H.2).
const ROOT_0: vector<u8> = x"0fd923ca5e7218c4ba3c3801c26a617ecdbfdaebb9c76ce2eca166e7855efbb8";

// ------------------------------------------------------------------------------ helpers

/// Independent greedy decomposition of `size` into perfect trees (2^k - 1 nodes) of strictly
/// decreasing height, returning the peak positions left to right.
fun greedy_peaks(size: u64): vector<u64> {
    let mut peaks = vector[];
    let mut remaining = size;
    let mut position = 0;
    while (remaining > 0) {
        let mut k: u8 = 1;
        while ((1u64 << (k + 1)) - 1 <= remaining) { k = k + 1; };
        let block = (1u64 << k) - 1;
        position = position + block;
        remaining = remaining - block;
        peaks.push_back(position);
    };
    peaks
}

/// For every leaf count in `[from, to]`: `get_peaks_positions(size)` equals the greedy
/// decomposition, has `popcount(leaves)` entries, and its last peak is `size`.
fun check_peaks_match_greedy(from: u64, to: u64) {
    let mut leaves = from;
    while (leaves <= to) {
        let size = 2 * leaves - mmr_bits::count_ones(leaves);
        let peaks = mmr_utils::get_peaks_positions(size);
        assert_eq!(peaks, greedy_peaks(size));
        assert_eq!(peaks.length(), mmr_bits::count_ones(leaves));
        assert_eq!(peaks[peaks.length() - 1], size);
        assert!(mmr_utils::is_valid_size(size));
        leaves = leaves + 1;
    };
}

// ------------------------------------------------------------------------------ peaks

#[test]
fun peaks_positions_known_values() {
    assert_eq!(mmr_utils::get_peaks_positions(0), vector[]);
    assert_eq!(mmr_utils::get_peaks_positions(1), vector[1]);
    assert_eq!(mmr_utils::get_peaks_positions(3), vector[3]);
    assert_eq!(mmr_utils::get_peaks_positions(4), vector[3, 4]);
    assert_eq!(mmr_utils::get_peaks_positions(7), vector[7]);
    assert_eq!(mmr_utils::get_peaks_positions(10), vector[7, 10]);
    assert_eq!(mmr_utils::get_peaks_positions(11), vector[7, 10, 11]);
    assert_eq!(mmr_utils::get_peaks_positions(18), vector[15, 18]);
    assert_eq!(mmr_utils::get_peaks_positions(23), vector[15, 22, 23]);
    assert_eq!(mmr_utils::get_peaks_positions(184), vector[127, 158, 173, 180, 183, 184]);
    assert_eq!(mmr_utils::get_peaks_positions(255), vector[255]);
    assert_eq!(mmr_utils::get_peaks_positions(397), vector[255, 382, 397]);
}

#[test] fun peaks_positions_match_greedy_a() { check_peaks_match_greedy(1, 2000); }
#[test] fun peaks_positions_match_greedy_b() { check_peaks_match_greedy(2001, 4000); }
#[test] fun peaks_positions_match_greedy_c() { check_peaks_match_greedy(4001, 6000); }
#[test] fun peaks_positions_match_greedy_d() { check_peaks_match_greedy(6001, 8000); }
#[test] fun peaks_positions_match_greedy_e() { check_peaks_match_greedy(8001, 10000); }

// ------------------------------------------------------------------------------ sizes

#[test]
fun valid_sizes_up_to_31() {
    let valid = vector[0, 1, 3, 4, 7, 8, 10, 11, 15, 16, 18, 19, 22, 23, 25, 26, 31];
    32u64.do!(|size| {
        assert_eq!(mmr_utils::is_valid_size(size), valid.contains(&size));
    });
}

#[test]
fun valid_size_64_bit_edge() {
    // perfect tree of height 63
    assert!(mmr_utils::is_valid_size((1u64 << 63) - 1));
    // that tree plus one leaf
    assert!(mmr_utils::is_valid_size(1u64 << 63));
    // that tree plus two leaves (a second tree of height 2)
    assert!(mmr_utils::is_valid_size((1u64 << 63) + 2));
    // one node over the height-63 tree plus one leaf
    assert!(!mmr_utils::is_valid_size((1u64 << 63) + 1));
    assert!(!mmr_utils::is_valid_size(std::u64::max_value!()));
    assert!(!mmr_utils::is_valid_size(std::u64::max_value!() - 1));
}

#[test]
fun size_to_leaf_count_known_values() {
    assert_eq!(mmr_utils::size_to_leaf_count(0), 0);
    assert_eq!(mmr_utils::size_to_leaf_count(1), 1);
    assert_eq!(mmr_utils::size_to_leaf_count(3), 2);
    assert_eq!(mmr_utils::size_to_leaf_count(4), 3);
    assert_eq!(mmr_utils::size_to_leaf_count(23), 13);
    assert_eq!(mmr_utils::size_to_leaf_count(184), 95);
    assert_eq!(mmr_utils::size_to_leaf_count(397), 200);
}

// ------------------------------------------------------------------------------ leaf index

#[test]
fun leaf_index_and_position_round_trip() {
    let expected = vector[1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20, 23];
    13u64.do!(|i| assert_eq!(mmr_utils::leaf_index_to_position(i), expected[i]));
    200u64.do!(|i| {
        let position = mmr_utils::leaf_index_to_position(i);
        assert_eq!(mmr_utils::get_height(position), 1);
        assert_eq!(mmr_utils::position_to_leaf_index(position), i);
    });
}

#[test, expected_failure(abort_code = mmr_utils::ENotALeaf)]
fun position_to_leaf_index_rejects_internal_node() {
    mmr_utils::position_to_leaf_index(3);
}

#[test, expected_failure(abort_code = mmr_utils::EStartsAtOne)]
fun position_to_leaf_index_rejects_zero() {
    mmr_utils::position_to_leaf_index(0);
}

// ------------------------------------------------------------------------------ node math

#[test]
fun height_sibling_parent_known_values() {
    assert_eq!(mmr_utils::get_height(1), 1);
    assert_eq!(mmr_utils::get_height(3), 2);
    assert_eq!(mmr_utils::get_height(7), 3);
    assert_eq!(mmr_utils::get_height(15), 4);
    assert_eq!(mmr_utils::get_height(16), 1);
    assert_eq!(mmr_utils::get_sibling_position(1), 2);
    assert_eq!(mmr_utils::get_sibling_position(2), 1);
    assert_eq!(mmr_utils::get_sibling_position(3), 6);
    assert_eq!(mmr_utils::get_sibling_position(16), 17);
    assert_eq!(mmr_utils::get_parent_position(1), 3);
    assert_eq!(mmr_utils::get_parent_position(2), 3);
    assert_eq!(mmr_utils::get_parent_position(6), 7);
    assert!(mmr_utils::is_right_sibling(2));
    assert!(mmr_utils::is_right_sibling(6));
    assert!(mmr_utils::is_right_sibling(14));
    assert!(!mmr_utils::is_right_sibling(1));
    assert!(!mmr_utils::is_right_sibling(3));
    assert!(!mmr_utils::is_right_sibling(16));
    assert_eq!(mmr_utils::jump_left(6), 3);
    assert_eq!(mmr_utils::jump_left(11), 4);
    assert_eq!(mmr_utils::sibling_offset(3), 7);
}

/// Structural pins for positions 1..600: the sibling of the sibling is the node itself, siblings
/// share a parent and are `sibling_offset(height)` apart, exactly one of the pair is the right
/// sibling (the larger one), and the parent has height + 1 and sits right after the right sibling.
#[test]
fun sibling_and_parent_relations_1_to_600() {
    600u64.do!(|i| {
        let p = i + 1;
        let h = mmr_utils::get_height(p);
        let s = mmr_utils::get_sibling_position(p);
        assert_eq!(mmr_utils::get_height(s), h);
        assert_eq!(mmr_utils::get_sibling_position(s), p);
        assert_eq!(mmr_utils::get_parent_position(s), mmr_utils::get_parent_position(p));
        let right = mmr_utils::is_right_sibling(p);
        assert!(right != mmr_utils::is_right_sibling(s));
        if (right) {
            assert_eq!(p - s, mmr_utils::sibling_offset(h));
            assert_eq!(mmr_utils::get_parent_position(p), p + 1);
        } else {
            assert_eq!(s - p, mmr_utils::sibling_offset(h));
            assert_eq!(mmr_utils::get_parent_position(p), s + 1);
        };
        assert_eq!(mmr_utils::get_height(mmr_utils::get_parent_position(p)), h + 1);
    });
}

#[test, expected_failure(abort_code = mmr_utils::EStartsAtOne)]
fun is_right_sibling_rejects_zero() {
    mmr_utils::is_right_sibling(0);
}

// ------------------------------------------------------------------------------ u64 edges
// Raw arithmetic aborts of the pure helpers (spec D.2 / E.3 preconditions). Unreachable through
// every verifier: `EInvalidSize` / `EPositionOutOfRange` fire first.

#[test, expected_failure(arithmetic_error, location = mmr::mmr_bits)]
fun get_height_u64_max_overflows() {
    // are_all_ones(u64::MAX) computes num + 1
    mmr_utils::get_height(std::u64::max_value!());
}

#[test, expected_failure(arithmetic_error, location = mmr::mmr_utils)]
fun leaf_index_to_position_overflows_at_2_63() {
    mmr_utils::leaf_index_to_position(1u64 << 63);
}

#[test, expected_failure(arithmetic_error, location = mmr::mmr_bits)]
fun position_to_leaf_index_u64_max_is_raw_abort() {
    // aborts in get_height before ENotALeaf can fire
    mmr_utils::position_to_leaf_index(std::u64::max_value!());
}

// ------------------------------------------------------------------------------ proof positions

#[test]
fun proof_positions_readme_example() {
    assert_eq!(mmr_utils::calc_proof_tree_path_positions(16, 23), vector[17, 21]);
    let pp = mmr_utils::calc_proof_positions(16, 23);
    assert_eq!(pp.local_tree_path_positions(), vector[17, 21]);
    assert_eq!(pp.left_peaks_positions(), vector[15]);
    assert_eq!(pp.right_peaks_positions(), vector[23]);
    // the last node of an MMR is always a peak: empty path
    assert_eq!(mmr_utils::calc_proof_tree_path_positions(23, 23), vector[]);
    let last = mmr_utils::calc_proof_positions(23, 23);
    assert_eq!(last.local_tree_path_positions(), vector[]);
    assert_eq!(last.left_peaks_positions(), vector[15, 22]);
    assert_eq!(last.right_peaks_positions(), vector[]);
}

/// The path of every leaf of every leaf count 1..32 climbs to its local peak: path entry i is the
/// sibling of the current node and has height i + 1, the parent chain ends at a peak of `size`,
/// and `left ++ [local peak] ++ right` is exactly the peak list.
#[test]
fun proof_positions_climb_to_a_peak_for_every_leaf_up_to_32_leaves() {
    32u64.do!(|l| {
        let leaves = l + 1;
        let size = 2 * leaves - mmr_bits::count_ones(leaves);
        let peaks = mmr_utils::get_peaks_positions(size);
        leaves.do!(|index| {
            let position = mmr_utils::leaf_index_to_position(index);
            let pp = mmr_utils::calc_proof_positions(position, size);
            let path = pp.local_tree_path_positions();
            let mut cur = position;
            path.length().do!(|i| {
                assert_eq!(path[i], mmr_utils::get_sibling_position(cur));
                assert_eq!(mmr_utils::get_height(path[i]), (i as u8) + 1);
                cur = mmr_utils::get_parent_position(cur);
            });
            assert!(peaks.contains(&cur));
            assert!(cur <= size);
            let mut all = pp.left_peaks_positions();
            all.push_back(cur);
            all.append(pp.right_peaks_positions());
            assert_eq!(all, peaks);
        });
    });
}

// ------------------------------------------------------------------------------ hashing

#[test]
fun hash_with_integer_empty_root() {
    assert_eq!(mmr_utils::hash_with_integer(0, vector[]), sui::hash::blake2b256(&b"0"));
    assert_eq!(mmr_utils::hash_with_integer(0, vector[]), ROOT_0);
}

/// The framing is decimal ASCII with no separator: `H(12, [x]) == H(1, ["2" || x])` and
/// `H(n, [a, b]) == blake2b256(enc(n) || a || b)`.
#[test]
fun hash_with_integer_framing_is_decimal_ascii_concatenation() {
    let x = b"payload";
    let mut prefixed = b"2";
    prefixed.append(x);
    assert_eq!(mmr_utils::hash_with_integer(12, vector[x]), mmr_utils::hash_with_integer(1, vector[prefixed]));
    let mut raw = b"23";
    raw.append(b"ab");
    raw.append(b"cd");
    assert_eq!(mmr_utils::hash_with_integer(23, vector[b"ab", b"cd"]), sui::hash::blake2b256(&raw));
    assert!(mmr_utils::hash_with_integer(1, vector[b"a"]) != mmr_utils::hash_with_integer(2, vector[b"a"]));
}

#[test]
fun get_hashes_from_positions_reads_by_reference() {
    let n1 = b"node-1";
    let n2 = b"node-2";
    let n3 = b"node-3";
    let n4 = b"node-4";
    let nodes = vector[n1, n2, n3, n4];
    let positions = vector[3, 1];
    assert_eq!(mmr_utils::get_hashes_from_positions(&nodes, &positions), vector[n3, n1]);
    // the inputs are untouched
    assert_eq!(nodes.length(), 4);
    assert_eq!(positions, vector[3, 1]);
}
