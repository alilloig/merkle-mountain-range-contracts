/// Adversarial regression suite: every test tries to make a verifier return `true` for a leaf that is not
/// at that position behind the anchored root, or to reach a raw VM abort. Expected outcomes are
/// `false` or a named error from `mmr::mmr_proof` / `mmr::mmr` (see the README "Results and errors").
#[test_only]
module mmr::mmr_adversarial_tests;

use std::unit_test::assert_eq;
use mmr::mmr::{Self, MMR, AdminCap, AppendCap};
use mmr::mmr_test_fixtures::{setup, teardown};
use mmr::mmr_proof;
use mmr::mmr_prover::{Self, NodeSet};
use mmr::mmr_utils;

const ROOT_13: vector<u8> = x"737ff3b5d4244e05bc4248b78002040f3d9e37a55fcdea39a57d955cdb5e79d5";
const U64_MAX: u64 = 18446744073709551615;
/// 2^63: a valid size (perfect tree of height 63 plus one leaf).
const TWO_63: u64 = 9223372036854775808;
/// 2^64 - 65: the largest valid size (one mountain of every height 1..63).
const MAX_VALID_SIZE: u64 = 18446744073709551551;

// ------------------------------------------------------------------------------ helpers

fun n(ns: &NodeSet, p: u64): vector<u8> { ns.node(p) }

fun concat(a: vector<u8>, b: vector<u8>): vector<u8> {
    let mut v = a;
    v.append(b);
    v
}

/// Leaves "from".."to" (inclusive).
fun leaves_range(from: u64, to: u64): vector<vector<u8>> {
    vector::tabulate!(to - from + 1, |i| mmr_prover::leaf_data(from + i))
}

// ============================================================================== single, pure
// README MMR: 13 leaves "1".."13", size 23, peaks 15, 22, 23.
// Leaf positions: 1,2,4,5,8,9,11,12,16,17,19,20,23 hold leaves "1".."13" in order.

/// A01: a real internal-node hash (n3) used as leaf data at leaf position 1 with the honest path
/// of position 1 -> false.
#[test]
fun a01_internal_node_hash_as_leaf_data() {
    let ns = mmr_prover::build(13);
    let (path, left, right) = ns.single_proof(1);
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, n(&ns, 3), path, left, right));
    // the same with the peak hash n15 and with n2 (the sibling) as data
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, n(&ns, 15), path, left, right));
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, n(&ns, 2), path, left, right));
    // and the leaf's own hash n1 (H(1,"1")) as data: double hashing must not verify
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, n(&ns, 1), path, left, right));
}

/// A02: `left || right` of node 3 supplied as leaf data AT position 3 -> ENotALeaf.
#[test, expected_failure(abort_code = mmr_proof::ENotALeaf)]
fun a02_left_right_concat_at_internal_position() {
    let ns = mmr_prover::build(13);
    let data = concat(n(&ns, 1), n(&ns, 2));
    // honest siblings of node 3: n6, n14; right peaks n22, n23
    mmr_proof::verify_with_root(ROOT_13, 23, 3, data, vector[n(&ns, 6), n(&ns, 14)], vector[], vector[n(&ns, 22), n(&ns, 23)]);
}

/// A02b: `left || right` of node 22 (a peak) at position 22 -> ENotALeaf.
#[test, expected_failure(abort_code = mmr_proof::ENotALeaf)]
fun a02b_left_right_concat_at_peak_position() {
    let ns = mmr_prover::build(13);
    let data = concat(n(&ns, 18), n(&ns, 21));
    mmr_proof::verify_with_root(ROOT_13, 23, 22, data, vector[], vector[n(&ns, 15)], vector[n(&ns, 23)]);
}

/// A03: prefix impersonation. H(1, "2"||"8") == H(12, "8") == n12 because the integer prefix is
/// not length-framed. The verifier still climbs from position 1, so both the honest path of 1
/// and the honest path of 12 give false.
#[test]
fun a03_prefix_impersonation_1_vs_12() {
    let ns = mmr_prover::build(13);
    // premise: the leaf hash collides
    let fake = b"28"; // "2" || "8"; leaf number 8 sits at position 12
    assert_eq!(mmr_utils::hash_with_integer(1, vector[fake]), n(&ns, 12));
    // with the honest path of position 1
    let (path1, left1, right1) = ns.single_proof(1);
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, fake, path1, left1, right1));
    // with the honest path of position 12 (same length 3, same peak 15)
    let (path12, left12, right12) = ns.single_proof(12);
    assert_eq!(path12.length(), 3);
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, fake, path12, left12, right12));
    // the reverse direction: claim position 12 with data "8" is the honest leaf; claim position
    // 12 with "" and path of 1 is false
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 12, b"", path1, left1, right1));
}

/// A03b: prefix impersonation across mountains. H(1, "6"||"9") == H(16, "9") == n16 (both left
/// children). Any 3-entry path at position 1 gives false because parent prefixes are derived
/// from position 1 (3, 7, 15), not from 16 (18, 22).
#[test]
fun a03b_prefix_impersonation_1_vs_16() {
    let ns = mmr_prover::build(13);
    let fake = b"69";
    assert_eq!(mmr_utils::hash_with_integer(1, vector[fake]), n(&ns, 16));
    // path of 16 is [n17, n21]; pad to length 3 with n14 (the real third sibling of 1)
    let path = vector[n(&ns, 17), n(&ns, 21), n(&ns, 14)];
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, fake, path, vector[], vector[n(&ns, 22), n(&ns, 23)]));
    // and pretend the local peak is 22 by moving the peaks around (counts stay 0 / 2)
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 1, fake, path, vector[], vector[n(&ns, 15), n(&ns, 23)]));
    // batch variant, position 1 alone
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1], vector[fake], path, vector[n(&ns, 22), n(&ns, 23)]));
}

/// A04: the root as a leaf. H(23, n15||n22||n23) == ROOT_13 because size and the leaf-peak
/// position share the prefix "23". The verifier bags the computed node again, so it is false.
#[test]
fun a04_root_as_leaf_at_leaf_peak() {
    let ns = mmr_prover::build(13);
    let data = concat(concat(n(&ns, 15), n(&ns, 22)), n(&ns, 23));
    assert_eq!(mmr_utils::hash_with_integer(23, vector[data]), ROOT_13);
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 23, data, vector[], vector[n(&ns, 15), n(&ns, 22)], vector[]));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[23], vector[data], vector[], vector[n(&ns, 15), n(&ns, 22)]));
    // root as an untouched peak, as a left peak, as a sibling
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 23, b"13", vector[], vector[ROOT_13, n(&ns, 22)], vector[]));
    let (s, _u) = ns.batch_proof(vector[16]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], s, vector[ROOT_13, n(&ns, 23)]));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[ROOT_13, n(&ns, 21)], vector[n(&ns, 15), n(&ns, 23)]));
}

/// A05: a proof for position p replayed at another leaf position of the same path shape
/// (same length, same local peak, same left/right role) -> false.
#[test]
fun a05_proof_replayed_at_same_shape_position() {
    let ns = mmr_prover::build(13);
    // 1 and 4 are both left children under peak 15 with path length 3
    let (path, left, right) = ns.single_proof(1);
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 4, b"1", path, left, right));
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 4, b"3", path, left, right));
    // 16 and 19 are both left children under peak 22 with path length 2
    let (path, left, right) = ns.single_proof(16);
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 19, b"9", path, left, right));
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 19, b"11", path, left, right));
    // 16's proof at its right sibling 17 (same length, same peak, other role)
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 17, b"9", path, left, right));
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 17, b"10", path, left, right));
    // the honest proof of 17 verifies (sanity)
    let (path17, left17, right17) = ns.single_proof(17);
    assert!(mmr_proof::verify_with_root(ROOT_13, 23, 17, b"10", path17, left17, right17));
    // batch: proof of {16} replayed at {19} and at {17}
    let (s, u) = ns.batch_proof(vector[16]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[19], vector[b"9"], s, u));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[19], vector[b"11"], s, u));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[17], vector[b"10"], s, u));
}

/// A06: leaf-peak case (empty path): peaks of the right count but wrong order / wrong data.
#[test]
fun a06_leaf_peak_wrong_peaks() {
    let ns = mmr_prover::build(13);
    // honest
    assert!(mmr_proof::verify_with_root(ROOT_13, 23, 23, b"13", vector[], vector[n(&ns, 15), n(&ns, 22)], vector[]));
    // swapped left peaks
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 23, b"13", vector[], vector[n(&ns, 22), n(&ns, 15)], vector[]));
    // wrong data with honest peaks
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 23, b"12", vector[], vector[n(&ns, 15), n(&ns, 22)], vector[]));
    // empty data
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 23, b"", vector[], vector[n(&ns, 15), n(&ns, 22)], vector[]));
    // n23 itself as data (double hash)
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 23, n(&ns, 23), vector[], vector[n(&ns, 15), n(&ns, 22)], vector[]));
    // a leaf hash of another leaf position as left peak
    assert!(!mmr_proof::verify_with_root(ROOT_13, 23, 23, b"13", vector[], vector[n(&ns, 15), n(&ns, 20)], vector[]));
}

/// A07: two path entries merged into one 64-byte entry -> EPathLength (count check first).
#[test, expected_failure(abort_code = mmr_proof::EPathLength)]
fun a07_merged_path_entries() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_with_root(ROOT_13, 23, 16, b"9", vector[concat(n(&ns, 17), n(&ns, 21))], vector[n(&ns, 15)], vector[n(&ns, 23)]);
}

/// A07b: correct path count, one 64-byte path entry -> EHashLength.
#[test, expected_failure(abort_code = mmr_proof::EHashLength)]
fun a07b_oversized_path_entry() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_with_root(ROOT_13, 23, 16, b"9", vector[n(&ns, 17), concat(n(&ns, 21), n(&ns, 21))], vector[n(&ns, 15)], vector[n(&ns, 23)]);
}

/// A07c: an empty (0-byte) path entry -> EHashLength.
#[test, expected_failure(abort_code = mmr_proof::EHashLength)]
fun a07c_empty_path_entry() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_with_root(ROOT_13, 23, 16, b"9", vector[n(&ns, 17), vector[]], vector[n(&ns, 15)], vector[n(&ns, 23)]);
}

/// A07d: a 31-byte left peak -> EHashLength.
#[test, expected_failure(abort_code = mmr_proof::EHashLength)]
fun a07d_short_left_peak() {
    let ns = mmr_prover::build(13);
    let mut short = n(&ns, 15);
    short.pop_back();
    mmr_proof::verify_with_root(ROOT_13, 23, 16, b"9", vector[n(&ns, 17), n(&ns, 21)], vector[short], vector[n(&ns, 23)]);
}

/// A08: position u64::MAX at size 23 -> EPositionOutOfRange (never reaches `get_height`, whose
/// `num + 1` would overflow).
#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun a08_position_u64_max() {
    mmr_proof::verify_with_root(ROOT_13, 23, U64_MAX, b"x", vector[], vector[], vector[]);
}

/// A08b: position u64::MAX at the valid size 2^63 -> EPositionOutOfRange.
#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun a08b_position_u64_max_at_size_2_63() {
    mmr_proof::verify_with_root(ROOT_13, TWO_63, U64_MAX, b"x", vector[], vector[], vector[]);
}

/// A09: size 2^63 (valid) with position 2^63 (the last leaf, a peak) and empty vectors ->
/// EPeaksCount (one left peak expected, none supplied).
#[test, expected_failure(abort_code = mmr_proof::EPeaksCount)]
fun a09_size_2_63_position_2_63_empty() {
    assert!(mmr_utils::is_valid_size(TWO_63));
    mmr_proof::verify_with_root(ROOT_13, TWO_63, TWO_63, b"x", vector[], vector[], vector[]);
}

/// A09b: same size and position with a well-formed proof -> false, no abort.
#[test]
fun a09b_size_2_63_position_2_63_well_formed_is_false() {
    let ns = mmr_prover::build(13);
    assert!(!mmr_proof::verify_with_root(ROOT_13, TWO_63, TWO_63, b"x", vector[], vector[n(&ns, 15)], vector[]));
    // the computed root has 32 bytes
    let r = mmr_proof::compute_root(TWO_63, TWO_63, b"x", vector[], vector[n(&ns, 15)], vector[]);
    assert_eq!(r.length(), 32);
    // batch: [2^63] with one untouched peak -> false
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, TWO_63, vector[TWO_63], vector[b"x"], vector[], vector[n(&ns, 15)]));
}

/// A09c: batch at size 2^63 with position 2^63 and empty vectors -> EMissingProofHashes (the
/// first mountain is untouched and has no hash).
#[test, expected_failure(abort_code = mmr_proof::EMissingProofHashes)]
fun a09c_batch_size_2_63_empty() {
    mmr_proof::verify_multiple_with_root(ROOT_13, TWO_63, vector[TWO_63], vector[b"x"], vector[], vector[]);
}

/// A09d: position 2^63 - 1 (the height-63 peak) at size 2^63 -> ENotALeaf.
#[test, expected_failure(abort_code = mmr_proof::ENotALeaf)]
fun a09d_size_2_63_internal_peak_position() {
    mmr_proof::verify_with_root(ROOT_13, TWO_63, TWO_63 - 1, b"x", vector[], vector[], vector[]);
}

/// A10: size u64::MAX -> EInvalidSize (both pure variants).
#[test, expected_failure(abort_code = mmr_proof::EInvalidSize)]
fun a10_size_u64_max_single() {
    mmr_proof::verify_with_root(ROOT_13, U64_MAX, U64_MAX, b"x", vector[], vector[], vector[]);
}

#[test, expected_failure(abort_code = mmr_proof::EInvalidSize)]
fun a10b_size_u64_max_batch() {
    mmr_proof::verify_multiple_with_root(ROOT_13, U64_MAX, vector[U64_MAX], vector[b"x"], vector[], vector[]);
}

/// A10c: size 2^63 + 1 is not reachable -> EInvalidSize.
#[test, expected_failure(abort_code = mmr_proof::EInvalidSize)]
fun a10c_size_2_63_plus_1() {
    mmr_proof::verify_with_root(ROOT_13, TWO_63 + 1, 1, b"x", vector[], vector[], vector[]);
}

/// A11: the largest valid size 2^64 - 65 with its last leaf (a peak) and empty vectors ->
/// EPeaksCount; with 62 left peaks -> false and no abort.
#[test, expected_failure(abort_code = mmr_proof::EPeaksCount)]
fun a11_max_valid_size_empty() {
    assert!(mmr_utils::is_valid_size(MAX_VALID_SIZE));
    assert!(!mmr_utils::is_valid_size(MAX_VALID_SIZE + 1));
    mmr_proof::verify_with_root(ROOT_13, MAX_VALID_SIZE, MAX_VALID_SIZE, b"x", vector[], vector[], vector[]);
}

#[test]
fun a11b_max_valid_size_well_formed_is_false() {
    let ns = mmr_prover::build(13);
    let left = vector::tabulate!(62, |_| n(&ns, 15));
    assert!(!mmr_proof::verify_with_root(ROOT_13, MAX_VALID_SIZE, MAX_VALID_SIZE, b"x", vector[], left, vector[]));
    // batch: 62 untouched peaks then the leaf peak
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, MAX_VALID_SIZE, vector[MAX_VALID_SIZE], vector[b"x"], vector[], left));
}

/// A11c: position 1 at the largest valid size: the path climbs 62 levels. Empty path ->
/// EPathLength (a named error, and within the meter).
#[test, expected_failure(abort_code = mmr_proof::EPathLength)]
fun a11c_max_valid_size_position_1_empty_path() {
    mmr_proof::verify_with_root(ROOT_13, MAX_VALID_SIZE, 1, b"x", vector[], vector[], vector[]);
}

/// A11d: a deep leaf in the last internal mountain of the largest valid size: position
/// 2^64 - 68 (left leaf of the height-2 mountain). Empty path -> EPathLength.
#[test, expected_failure(abort_code = mmr_proof::EPathLength)]
fun a11d_max_valid_size_last_mountain_leaf() {
    let p = MAX_VALID_SIZE - 3;
    assert_eq!(mmr_utils::get_height(p), 1);
    mmr_proof::verify_with_root(ROOT_13, MAX_VALID_SIZE, p, b"x", vector[], vector[], vector[]);
}

/// A11e: the same leaf with a 1-entry path and 61 left peaks, 1 right peak -> false, no abort.
/// This exercises `is_right_sibling` / `get_parent_position` near u64::MAX.
#[test]
fun a11e_max_valid_size_last_mountain_leaf_well_formed() {
    let ns = mmr_prover::build(13);
    let p = MAX_VALID_SIZE - 3;
    let left = vector::tabulate!(61, |_| n(&ns, 15));
    assert!(!mmr_proof::verify_with_root(ROOT_13, MAX_VALID_SIZE, p, b"x", vector[n(&ns, 2)], left, vector[n(&ns, 23)]));
    // batch: {p, p+1} (both leaves of the height-2 mountain) and the last leaf
    let mut u = left;
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, MAX_VALID_SIZE, vector[p, p + 1, MAX_VALID_SIZE], vector[b"a", b"b", b"c"], vector[], u));
    u.push_back(n(&ns, 23));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, MAX_VALID_SIZE, vector[p, p + 1], vector[b"a", b"b"], vector[], u));
}

/// A12: an MMR of one leaf (size 1): honest true, wrong data false, any extra hash aborts.
#[test]
fun a12_one_leaf_mmr() {
    let ns = mmr_prover::build(1);
    let root = ns.root();
    assert!(mmr_proof::verify_with_root(root, 1, 1, b"1", vector[], vector[], vector[]));
    assert!(!mmr_proof::verify_with_root(root, 1, 1, b"2", vector[], vector[], vector[]));
    assert!(!mmr_proof::verify_with_root(root, 1, 1, b"", vector[], vector[], vector[]));
    // the leaf hash n1 as data and the root as data
    assert!(!mmr_proof::verify_with_root(root, 1, 1, n(&ns, 1), vector[], vector[], vector[]));
    assert!(!mmr_proof::verify_with_root(root, 1, 1, root, vector[], vector[], vector[]));
    assert!(mmr_proof::verify_multiple_with_root(root, 1, vector[1], vector[b"1"], vector[], vector[]));
    assert!(!mmr_proof::verify_multiple_with_root(root, 1, vector[1], vector[b"2"], vector[], vector[]));
}

#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun a12b_one_leaf_mmr_position_2() {
    let ns = mmr_prover::build(1);
    mmr_proof::verify_with_root(ns.root(), 1, 2, b"2", vector[], vector[], vector[]);
}

#[test, expected_failure(abort_code = mmr_proof::EPathLength)]
fun a12c_one_leaf_mmr_extra_path() {
    let ns = mmr_prover::build(1);
    mmr_proof::verify_with_root(ns.root(), 1, 1, b"1", vector[n(&ns, 1)], vector[], vector[]);
}

#[test, expected_failure(abort_code = mmr_proof::ELeftoverProofHashes)]
fun a12d_one_leaf_mmr_batch_extra_untouched() {
    let ns = mmr_prover::build(1);
    mmr_proof::verify_multiple_with_root(ns.root(), 1, vector[1], vector[b"1"], vector[], vector[n(&ns, 1)]);
}

// ============================================================================== batch, pure

/// B01: siblings in position order instead of consumption order -> false (well-formed).
#[test]
fun b01_siblings_in_position_order() {
    let ns = mmr_prover::build(13);
    let (siblings, untouched) = ns.batch_proof(vector[4, 9, 16]);
    assert_eq!(siblings, vector[n(&ns, 5), n(&ns, 8), n(&ns, 3), n(&ns, 13), n(&ns, 17), n(&ns, 21)]);
    let sorted = vector[n(&ns, 3), n(&ns, 5), n(&ns, 8), n(&ns, 13), n(&ns, 17), n(&ns, 21)];
    let leaves = vector[b"3", b"6", b"9"];
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[4, 9, 16], leaves, sorted, untouched));
    // every other permutation of the two mountain-15 groups
    let swapped = vector[n(&ns, 8), n(&ns, 5), n(&ns, 3), n(&ns, 13), n(&ns, 17), n(&ns, 21)];
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[4, 9, 16], leaves, swapped, untouched));
    let swapped2 = vector[n(&ns, 5), n(&ns, 8), n(&ns, 13), n(&ns, 3), n(&ns, 17), n(&ns, 21)];
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[4, 9, 16], leaves, swapped2, untouched));
    let swapped3 = vector[n(&ns, 5), n(&ns, 8), n(&ns, 3), n(&ns, 13), n(&ns, 21), n(&ns, 17)];
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[4, 9, 16], leaves, swapped3, untouched));
}

/// B02: an untouched-peak hash supplied for a mountain that has batch leaves, with that
/// mountain's siblings dropped -> EMissingProofHashes (the traversal always climbs a touched
/// mountain and asks for its siblings first).
#[test, expected_failure(abort_code = mmr_proof::EMissingProofHashes)]
fun b02_untouched_peak_for_touched_mountain() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[], vector[n(&ns, 15), n(&ns, 22), n(&ns, 23)]);
}

/// B02b: siblings kept AND the touched peak added to untouched -> ELeftoverProofHashes.
#[test, expected_failure(abort_code = mmr_proof::ELeftoverProofHashes)]
fun b02b_untouched_peak_for_touched_mountain_siblings_kept() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[n(&ns, 17), n(&ns, 21)], vector[n(&ns, 15), n(&ns, 22), n(&ns, 23)]);
}

/// B02c: peak of the touched mountain supplied as untouched IN PLACE of a real untouched peak
/// (same count, wrong content) -> false.
#[test]
fun b02c_touched_peak_replaces_untouched_peak() {
    let ns = mmr_prover::build(13);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[n(&ns, 17), n(&ns, 21)], vector[n(&ns, 22), n(&ns, 23)]));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[n(&ns, 17), n(&ns, 21)], vector[n(&ns, 15), n(&ns, 22)]));
}

/// B03: a derived sibling (n2, in the batch) also supplied in `siblings` -> ELeftoverProofHashes
/// (the extra hash shifts the reads; one is left over).
#[test, expected_failure(abort_code = mmr_proof::ELeftoverProofHashes)]
fun b03_derived_sibling_also_supplied() {
    let ns = mmr_prover::build(13);
    let (siblings, untouched) = ns.batch_proof(vector[1, 2]);
    assert_eq!(siblings, vector[n(&ns, 6), n(&ns, 14)]);
    let mut with_derived = vector[n(&ns, 2)];
    with_derived.append(siblings);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 2], vector[b"1", b"2"], with_derived, untouched);
}

/// B03b: derived sibling supplied in place of a needed one (same count) -> false.
#[test]
fun b03b_derived_sibling_replaces_needed_sibling() {
    let ns = mmr_prover::build(13);
    let (_siblings, untouched) = ns.batch_proof(vector[1, 2]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 2], vector[b"1", b"2"], vector[n(&ns, 2), n(&ns, 14)], untouched));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 2], vector[b"1", b"2"], vector[n(&ns, 6), n(&ns, 2)], untouched));
}

/// B04: zero in the middle -> EPositionsNotSorted.
#[test, expected_failure(abort_code = mmr_proof::EPositionsNotSorted)]
fun b04_zero_in_the_middle() {
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 0], vector[b"1", b"x"], vector[], vector[]);
}

/// B04b: duplicate leaf peak -> EPositionsNotSorted.
#[test, expected_failure(abort_code = mmr_proof::EPositionsNotSorted)]
fun b04b_duplicate_leaf_peak() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[23, 23], vector[b"13", b"13"], vector[], vector[n(&ns, 15), n(&ns, 22)]);
}

/// B04c: descending positions with otherwise honest hashes -> EPositionsNotSorted.
#[test, expected_failure(abort_code = mmr_proof::EPositionsNotSorted)]
fun b04c_descending_positions() {
    let ns = mmr_prover::build(13);
    let (s, u) = ns.batch_proof(vector[16, 23]);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[23, 16], vector[b"13", b"9"], s, u);
}

/// B05: a later position beyond size (u64::MAX) -> EPositionOutOfRange, never arithmetic.
#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun b05_position_u64_max_in_batch() {
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, U64_MAX], vector[b"1", b"x"], vector[], vector[]);
}

/// B05b: position == size + 1 -> EPositionOutOfRange.
#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun b05b_position_size_plus_one() {
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16, 24], vector[b"9", b"x"], vector[], vector[]);
}

/// B06: leaf-peak batches on small MMRs (size 1 and size 4, position 4).
#[test]
fun b06_leaf_peak_batches_small() {
    let ns4 = mmr_prover::build(3); // leaves 1,2,3 -> size 4, peaks 3, 4
    assert_eq!(ns4.size(), 4);
    let root = ns4.root();
    // honest {4}
    assert!(mmr_proof::verify_multiple_with_root(root, 4, vector[4], vector[b"3"], vector[], vector[n(&ns4, 3)]));
    // wrong data
    assert!(!mmr_proof::verify_multiple_with_root(root, 4, vector[4], vector[b"2"], vector[], vector[n(&ns4, 3)]));
    // wrong untouched peak (a leaf hash)
    assert!(!mmr_proof::verify_multiple_with_root(root, 4, vector[4], vector[b"3"], vector[], vector[n(&ns4, 1)]));
    // all leaves, no hashes
    assert!(mmr_proof::verify_multiple_with_root(root, 4, vector[1, 2, 4], vector[b"1", b"2", b"3"], vector[], vector[]));
    assert!(!mmr_proof::verify_multiple_with_root(root, 4, vector[1, 2, 4], vector[b"1", b"3", b"2"], vector[], vector[]));
    // {2, 4}: sibling n1 read, then peak 4
    assert!(mmr_proof::verify_multiple_with_root(root, 4, vector[2, 4], vector[b"2", b"3"], vector[n(&ns4, 1)], vector[]));
    assert!(!mmr_proof::verify_multiple_with_root(root, 4, vector[2, 4], vector[b"2", b"3"], vector[n(&ns4, 2)], vector[]));
}

#[test, expected_failure(abort_code = mmr_proof::EMissingProofHashes)]
fun b06b_leaf_peak_size_4_no_untouched() {
    let ns4 = mmr_prover::build(3);
    mmr_proof::verify_multiple_with_root(ns4.root(), 4, vector[4], vector[b"3"], vector[], vector[]);
}

#[test, expected_failure(abort_code = mmr_proof::ELeftoverProofHashes)]
fun b06c_leaf_peak_size_4_sibling_for_peak() {
    let ns4 = mmr_prover::build(3);
    mmr_proof::verify_multiple_with_root(ns4.root(), 4, vector[4], vector[b"3"], vector[n(&ns4, 1)], vector[n(&ns4, 3)]);
}

/// B06d: the untouched peak of size 4 moved into `siblings` -> EMissingProofHashes (the
/// untouched cursor runs dry first).
#[test, expected_failure(abort_code = mmr_proof::EMissingProofHashes)]
fun b06d_leaf_peak_size_4_untouched_as_sibling() {
    let ns4 = mmr_prover::build(3);
    mmr_proof::verify_multiple_with_root(ns4.root(), 4, vector[4], vector[b"3"], vector[n(&ns4, 3)], vector[]);
}

/// B07: leaves swapped between two batch positions -> false.
#[test]
fun b07_batch_leaves_swapped() {
    let ns = mmr_prover::build(13);
    let (s, u) = ns.batch_proof(vector[1, 2]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 2], vector[b"2", b"1"], s, u));
    let (s, u) = ns.batch_proof(vector[16, 23]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16, 23], vector[b"13", b"9"], s, u));
    // and honest for sanity
    assert!(mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16, 23], vector[b"9", b"13"], s, u));
}

/// B08: node hashes as batch leaf data -> false.
#[test]
fun b08_batch_node_hash_as_leaf_data() {
    let ns = mmr_prover::build(13);
    let (s, u) = ns.batch_proof(vector[1]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1], vector[n(&ns, 1)], s, u));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1], vector[n(&ns, 3)], s, u));
    let (s, u) = ns.batch_proof(vector[1, 2]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 2], vector[n(&ns, 1), n(&ns, 2)], s, u));
    // left||right of node 3 split across the two leaves that make node 3
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 2], vector[concat(n(&ns, 1), n(&ns, 2)), b"2"], s, u));
}

/// B09: untouched peaks wrong or reordered, siblings reordered -> false.
#[test]
fun b09_batch_wrong_untouched_and_reordered_siblings() {
    let ns = mmr_prover::build(13);
    let (s, u) = ns.batch_proof(vector[16, 23]);
    assert_eq!(s, vector[n(&ns, 17), n(&ns, 21)]);
    assert_eq!(u, vector[n(&ns, 15)]);
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16, 23], vector[b"9", b"13"], s, vector[n(&ns, 23)]));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16, 23], vector[b"9", b"13"], s, vector[n(&ns, 22)]));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16, 23], vector[b"9", b"13"], vector[n(&ns, 21), n(&ns, 17)], u));
    // {1, 23}: untouched [n22]
    let (s, u) = ns.batch_proof(vector[1, 23]);
    assert_eq!(u, vector[n(&ns, 22)]);
    assert!(mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 23], vector[b"1", b"13"], s, u));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 23], vector[b"1", b"13"], s, vector[n(&ns, 15)]));
}

/// B10: internal positions in a batch -> ENotALeaf (3 with left||right data).
#[test, expected_failure(abort_code = mmr_proof::ENotALeaf)]
fun b10_batch_internal_position_with_concat_data() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[3], vector[concat(n(&ns, 1), n(&ns, 2))], vector[n(&ns, 6), n(&ns, 14)], vector[n(&ns, 22), n(&ns, 23)]);
}

#[test, expected_failure(abort_code = mmr_proof::ENotALeaf)]
fun b10b_batch_peak_position_with_concat_data() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[15], vector[concat(n(&ns, 7), n(&ns, 14))], vector[], vector[n(&ns, 22), n(&ns, 23)]);
}

#[test, expected_failure(abort_code = mmr_proof::ENotALeaf)]
fun b10c_batch_leaf_then_internal() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1, 2, 3], vector[b"1", b"2", concat(n(&ns, 1), n(&ns, 2))], vector[n(&ns, 6), n(&ns, 14)], vector[n(&ns, 22), n(&ns, 23)]);
}

/// B10d: `size` itself as a batch position when the last mountain is internal (size 7) ->
/// ENotALeaf.
#[test, expected_failure(abort_code = mmr_proof::ENotALeaf)]
fun b10d_batch_size_position_internal() {
    let ns = mmr_prover::build(4);
    assert_eq!(ns.size(), 7);
    mmr_proof::verify_multiple_with_root(ns.root(), 7, vector[7], vector[b"x"], vector[], vector[]);
}

/// B11: traversal shapes that stress the FIFO: two right children only, a right child then a
/// left pair, three leaves under one peak with one derived, etc. Honest -> true; a swap -> false.
#[test]
fun b11_fifo_shapes_size_7() {
    let ns = mmr_prover::build(4); // size 7, leaves at 1, 2, 4, 5
    let root = ns.root();
    // {2, 5}: reads n1 then n4 (height-1 siblings, left to right), derives 6 from 3? no: 3 and 6
    // are both parents; 3's sibling is 6 which is in the queue -> derived
    let (s, u) = ns.batch_proof(vector[2, 5]);
    assert_eq!(s, vector[n(&ns, 1), n(&ns, 4)]);
    assert_eq!(u, vector[]);
    assert!(mmr_proof::verify_multiple_with_root(root, 7, vector[2, 5], vector[b"2", b"4"], s, u));
    assert!(!mmr_proof::verify_multiple_with_root(root, 7, vector[2, 5], vector[b"2", b"4"], vector[n(&ns, 4), n(&ns, 1)], u));
    // {1, 4, 5}: reads n2; derives 5 for 4; derives 6 for 3
    let (s, u) = ns.batch_proof(vector[1, 4, 5]);
    assert_eq!(s, vector[n(&ns, 2)]);
    assert!(mmr_proof::verify_multiple_with_root(root, 7, vector[1, 4, 5], vector[b"1", b"3", b"4"], s, u));
    assert!(!mmr_proof::verify_multiple_with_root(root, 7, vector[1, 4, 5], vector[b"1", b"4", b"3"], s, u));
    // {2, 4}: reads n1, n5
    let (s, u) = ns.batch_proof(vector[2, 4]);
    assert_eq!(s, vector[n(&ns, 1), n(&ns, 5)]);
    assert!(mmr_proof::verify_multiple_with_root(root, 7, vector[2, 4], vector[b"2", b"3"], s, u));
    // a "sibling" that is the hash of the parent 6 instead of leaf 5 -> false
    assert!(!mmr_proof::verify_multiple_with_root(root, 7, vector[2, 4], vector[b"2", b"3"], vector[n(&ns, 1), n(&ns, 6)], u));
}

/// B12: 33-byte sibling -> EHashLength before traversal.
#[test, expected_failure(abort_code = mmr_proof::EHashLength)]
fun b12_oversized_sibling() {
    let ns = mmr_prover::build(13);
    let mut long = n(&ns, 17);
    long.push_back(0);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[long, n(&ns, 21)], vector[n(&ns, 15), n(&ns, 23)]);
}

/// B12b: a 64-byte merged sibling pair -> EHashLength (not EMissingProofHashes).
#[test, expected_failure(abort_code = mmr_proof::EHashLength)]
fun b12b_merged_siblings() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[concat(n(&ns, 17), n(&ns, 21))], vector[n(&ns, 15), n(&ns, 23)]);
}

/// B12c: empty untouched peak entry -> EHashLength.
#[test, expected_failure(abort_code = mmr_proof::EHashLength)]
fun b12c_empty_untouched_entry() {
    let ns = mmr_prover::build(13);
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[16], vector[b"9"], vector[n(&ns, 17), n(&ns, 21)], vector[n(&ns, 15), vector[]]);
}

/// B12d: an unused 31-byte sibling in an all-leaves batch -> EHashLength (checked before the
/// leftover check).
#[test, expected_failure(abort_code = mmr_proof::EHashLength)]
fun b12d_short_unused_sibling() {
    let ns = mmr_prover::build(13);
    let mut short = n(&ns, 2);
    short.pop_back();
    let all = vector[1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20, 23];
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, all, mmr_prover::leaves(13), vector[short], vector[]);
}

/// B13: all 13 leaves plus one extra sibling -> ELeftoverProofHashes; all 13 with one wrong leaf
/// -> false.
#[test, expected_failure(abort_code = mmr_proof::ELeftoverProofHashes)]
fun b13_all_leaves_extra_sibling() {
    let ns = mmr_prover::build(13);
    let all = vector[1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20, 23];
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, all, mmr_prover::leaves(13), vector[n(&ns, 2)], vector[]);
}

#[test]
fun b13b_all_leaves_one_wrong() {
    let all = vector[1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20, 23];
    let mut leaves = mmr_prover::leaves(13);
    *(&mut leaves[12]) = b"14";
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, all, leaves, vector[], vector[]));
    // all leaves except the last, with n23 as untouched -> true (honest); with n22 -> false
    let ns = mmr_prover::build(13);
    let twelve = vector[1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20];
    assert!(mmr_proof::verify_multiple_with_root(ROOT_13, 23, twelve, mmr_prover::leaves(12), vector[], vector[n(&ns, 23)]));
    assert!(!mmr_proof::verify_multiple_with_root(ROOT_13, 23, twelve, mmr_prover::leaves(12), vector[], vector[n(&ns, 22)]));
}

/// B14: leaves longer than positions -> ELengthMismatch.
#[test, expected_failure(abort_code = mmr_proof::ELengthMismatch)]
fun b14_more_leaves_than_positions() {
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, vector[1], vector[b"1", b"2"], vector[], vector[]);
}

/// B15: batch of every leaf of one mountain plus the other peaks; the mountain's peak also
/// offered as an untouched peak -> ELeftoverProofHashes.
#[test, expected_failure(abort_code = mmr_proof::ELeftoverProofHashes)]
fun b15_whole_mountain_plus_its_peak() {
    let ns = mmr_prover::build(13);
    let positions = vector[16, 17, 19, 20];
    let leaves = vector[b"9", b"10", b"11", b"12"];
    mmr_proof::verify_multiple_with_root(ROOT_13, 23, positions, leaves, vector[], vector[n(&ns, 15), n(&ns, 22), n(&ns, 23)]);
}

// ============================================================================== object wrappers

/// O01: honest `verify` true; the same proof at another position or with another MMR's data
/// false; wrapper aborts are the `mmr_proof` errors.
#[test]
fun o01_object_verify_replays() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    assert_eq!(mmr.size(), 23);
    assert_eq!(mmr.root(), ROOT_13);
    let ns = mmr_prover::build(13);
    let (path, left, right) = ns.single_proof(16);
    assert!(mmr.verify(16, b"9", path, left, right));
    assert!(!mmr.verify(19, b"9", path, left, right));
    assert!(!mmr.verify(17, b"10", path, left, right));
    assert!(!mmr.verify(16, b"10", path, left, right));
    // prefix impersonation through the object
    assert!(!mmr.verify(1, b"69", vector[n(&ns, 17), n(&ns, 21), n(&ns, 14)], vector[], vector[n(&ns, 22), n(&ns, 23)]));
    // root as leaf through the object
    let data = concat(concat(n(&ns, 15), n(&ns, 22)), n(&ns, 23));
    assert!(!mmr.verify(23, data, vector[], vector[n(&ns, 15), n(&ns, 22)], vector[]));
    // batch replays
    let (s, u) = ns.batch_proof(vector[4, 9, 16]);
    assert!(mmr.verify_multiple(vector[4, 9, 16], vector[b"3", b"6", b"9"], s, u));
    assert!(!mmr.verify_multiple(vector[5, 9, 16], vector[b"3", b"6", b"9"], s, u));
    assert!(!mmr.verify_multiple(vector[4, 9, 16], vector[b"3", b"6", b"9"], vector[n(&ns, 3), n(&ns, 5), n(&ns, 8), n(&ns, 13), n(&ns, 17), n(&ns, 21)], u));
    teardown(mmr, admin, cap);
}

/// O02: three batches -> checkpoints 4, 15, 23. A proof from size 23 used at an earlier
/// checkpoint aborts on shape or returns false; it never verifies a leaf that was not there.
#[test]
fun o02_checkpoint_shapes() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.append_leaves(&cap, leaves_range(4, 8), ctx);
    mmr.append_leaves(&cap, leaves_range(9, 13), ctx);
    assert!(mmr.has_checkpoint(4));
    assert!(mmr.has_checkpoint(15));
    assert!(mmr.has_checkpoint(23));
    let ns = mmr_prover::build(13);
    // position 1 proof at size 15: path [n2, n6, n14], no peaks. Legitimately true (leaf 1 is in
    // the size-15 MMR and this IS the size-15 proof).
    assert!(mmr.verify_at_checkpoint(15, 1, b"1", vector[n(&ns, 2), n(&ns, 6), n(&ns, 14)], vector[], vector[]));
    assert!(!mmr.verify_at_checkpoint(15, 1, b"2", vector[n(&ns, 2), n(&ns, 6), n(&ns, 14)], vector[], vector[]));
    // batch {1} at checkpoint 4: honest size-4 proof true; wrong untouched false
    assert!(mmr.verify_multiple_at_checkpoint(4, vector[1], vector[b"1"], vector[n(&ns, 2)], vector[n(&ns, 4)]));
    assert!(!mmr.verify_multiple_at_checkpoint(4, vector[1], vector[b"1"], vector[n(&ns, 2)], vector[n(&ns, 5)]));
    // a size-23 proof for leaf 9 (position 16) can never verify at checkpoint 4 or 15 (aborts,
    // tested below); a size-23 proof for position 1 at checkpoint 23 is true
    let (path, left, right) = ns.single_proof(1);
    assert!(mmr.verify_at_checkpoint(23, 1, b"1", path, left, right));
    assert!(mmr.verify(1, b"1", path, left, right));
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun o02b_later_position_at_earlier_checkpoint() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.append_leaves(&cap, leaves_range(4, 8), ctx);
    mmr.append_leaves(&cap, leaves_range(9, 13), ctx);
    let ns = mmr_prover::build(13);
    let (path, left, right) = ns.single_proof(16);
    mmr.verify_at_checkpoint(15, 16, b"9", path, left, right);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr_proof::EPathLength)]
fun o02c_size_23_proof_at_checkpoint_4() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.append_leaves(&cap, leaves_range(4, 8), ctx);
    mmr.append_leaves(&cap, leaves_range(9, 13), ctx);
    let ns = mmr_prover::build(13);
    let (path, left, right) = ns.single_proof(1);
    mmr.verify_at_checkpoint(4, 1, b"1", path, left, right);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr_proof::EPeaksCount)]
fun o02d_size_23_proof_at_checkpoint_15() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.append_leaves(&cap, leaves_range(4, 8), ctx);
    mmr.append_leaves(&cap, leaves_range(9, 13), ctx);
    let ns = mmr_prover::build(13);
    let (path, left, right) = ns.single_proof(1);
    mmr.verify_at_checkpoint(15, 1, b"1", path, left, right);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr_proof::ELeftoverProofHashes)]
fun o02e_size_23_batch_at_checkpoint_4() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.append_leaves(&cap, leaves_range(4, 8), ctx);
    mmr.append_leaves(&cap, leaves_range(9, 13), ctx);
    let ns = mmr_prover::build(13);
    let (s, u) = ns.batch_proof(vector[1]);
    mmr.verify_multiple_at_checkpoint(4, vector[1], vector[b"1"], s, u);
    teardown(mmr, admin, cap);
}

/// O03: a valid MMR size with no checkpoint row -> ENoCheckpoint, before any proof math (the
/// proof is deliberately malformed and would abort with EPathLength otherwise).
#[test, expected_failure(abort_code = mmr::ENoCheckpoint)]
fun o03_checkpoint_missing_size() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.append_leaves(&cap, leaves_range(4, 8), ctx);
    mmr.verify_at_checkpoint(7, 1, b"1", vector[], vector[], vector[]);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENoCheckpoint)]
fun o03b_checkpoint_size_zero() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.verify_multiple_at_checkpoint(0, vector[1], vector[b"1"], vector[], vector[]);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENoCheckpoint)]
fun o03c_checkpoint_beyond_size() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    mmr.verify_at_checkpoint(23, 16, b"9", vector[], vector[], vector[]);
    teardown(mmr, admin, cap);
}

/// O04: cross-anchor. Two MMRs share leaves 1..3 and differ in leaf 4 (both size 7, one
/// checkpoint at 4 and one at 7). A proof of leaf 4 from A is false against B; a proof of leaf 1
/// at the shared checkpoint 4 is true against both (the leaf IS in both).
#[test]
fun o04_cross_anchor() {
    let ctx = &mut tx_context::dummy();
    let (mut a, admin_a, cap_a) = setup(ctx);
    let (mut b, admin_b, cap_b) = setup(ctx);
    a.append_leaves(&cap_a, leaves_range(1, 3), ctx);
    b.append_leaves(&cap_b, leaves_range(1, 3), ctx);
    a.append_leaves(&cap_a, vector[b"4"], ctx);
    b.append_leaves(&cap_b, vector[b"4!"], ctx);
    assert_eq!(a.size(), 7);
    assert_eq!(b.size(), 7);
    assert!(a.root() != b.root());
    assert_eq!(a.root_at(4), b.root_at(4));
    let ns_a = mmr_prover::build(4);
    let mut ns_b = mmr_prover::new();
    ns_b.append_all(vector[b"1", b"2", b"3", b"4!"]);
    assert_eq!(ns_a.root(), a.root());
    assert_eq!(ns_b.root(), b.root());
    // leaf 4 (position 5) proof from A
    let (path, left, right) = ns_a.single_proof(5);
    assert!(a.verify(5, b"4", path, left, right));
    assert!(!b.verify(5, b"4", path, left, right));
    // A's proof for position 5 is byte-identical to B's (siblings n4, n3 do not depend on leaf 4),
    // so B's honest leaf "4!" verifies with it: that is B's own proof, not a forgery.
    assert!(b.verify(5, b"4!", path, left, right));
    // B's own proof with A's data
    let (path_b, left_b, right_b) = ns_b.single_proof(5);
    assert!(b.verify(5, b"4!", path_b, left_b, right_b));
    assert!(!b.verify(5, b"4", path_b, left_b, right_b));
    assert!(!a.verify(5, b"4!", path_b, left_b, right_b));
    // batch versions
    let (s, u) = ns_a.batch_proof(vector[5]);
    assert!(a.verify_multiple(vector[5], vector[b"4"], s, u));
    assert!(!b.verify_multiple(vector[5], vector[b"4"], s, u));
    let (s, u) = ns_a.batch_proof(vector[1, 5]);
    assert!(!b.verify_multiple(vector[1, 5], vector[b"1", b"4"], s, u));
    // leaf 1 at the shared checkpoint 4 (honest size-4 proof) verifies against both
    let ns3 = mmr_prover::build(3);
    let (p4, l4, r4) = ns3.single_proof(1);
    assert!(a.verify_at_checkpoint(4, 1, b"1", p4, l4, r4));
    assert!(b.verify_at_checkpoint(4, 1, b"1", p4, l4, r4));
    // but leaf 4 cannot be proven at checkpoint 4 of either (position 5 > 4: abort, see o04b)
    // and A's size-7 proof of leaf 1 is false against B's current root
    let (p7, l7, r7) = ns_a.single_proof(1);
    assert!(a.verify(1, b"1", p7, l7, r7));
    assert!(!b.verify(1, b"1", p7, l7, r7));
    teardown(a, admin_a, cap_a);
    teardown(b, admin_b, cap_b);
}

#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun o04b_cross_anchor_leaf_4_at_checkpoint_4() {
    let ctx = &mut tx_context::dummy();
    let (mut a, admin_a, cap_a) = setup(ctx);
    a.append_leaves(&cap_a, leaves_range(1, 3), ctx);
    a.append_leaves(&cap_a, vector[b"4"], ctx);
    let ns_a = mmr_prover::build(4);
    let (path, left, right) = ns_a.single_proof(5);
    a.verify_at_checkpoint(4, 5, b"4", path, left, right);
    teardown(a, admin_a, cap_a);
}

/// O05: empty MMR object: every position is out of range (single and batch).
#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun o05_empty_object_single() {
    let ctx = &mut tx_context::dummy();
    let (mmr, admin, cap) = setup(ctx);
    mmr.verify(1, b"1", vector[], vector[], vector[]);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun o05b_empty_object_batch() {
    let ctx = &mut tx_context::dummy();
    let (mmr, admin, cap) = setup(ctx);
    mmr.verify_multiple(vector[1], vector[b"1"], vector[], vector[]);
    teardown(mmr, admin, cap);
}

/// O06: one-leaf object: honest true, wrong data false, the empty-root H("0") never matches.
#[test]
fun o06_one_leaf_object() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, vector[b"1"], ctx);
    assert!(mmr.verify(1, b"1", vector[], vector[], vector[]));
    assert!(!mmr.verify(1, b"2", vector[], vector[], vector[]));
    assert!(!mmr.verify(1, mmr.root(), vector[], vector[], vector[]));
    assert!(mmr.verify_multiple(vector[1], vector[b"1"], vector[], vector[]));
    assert!(!mmr.verify_multiple(vector[1], vector[b"2"], vector[], vector[]));
    assert!(mmr.verify_at_checkpoint(1, 1, b"1", vector[], vector[], vector[]));
    // sealing does not change verification
    mmr.seal(&admin);
    assert!(mmr.verify(1, b"1", vector[], vector[], vector[]));
    assert!(!mmr.verify(1, b"2", vector[], vector[], vector[]));
    teardown(mmr, admin, cap);
}

/// O07: after more appends, an old single proof is false against the current root but true at
/// its checkpoint; a batch proof at the current size with a stale untouched peak is false.
#[test]
fun o07_stale_proofs() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    let ns3 = mmr_prover::build(3);
    let (p4, l4, r4) = ns3.single_proof(1);
    assert!(mmr.verify(1, b"1", p4, l4, r4));
    mmr.append_leaves(&cap, leaves_range(4, 4), ctx); // size 7, single peak
    // the size-4 proof has one path entry and one right peak; size 7 expects two path entries
    // -> EPathLength (see o07b). A proof of the right shape for size 7 but with the size-4 peak
    // n4 as path[1] is false.
    let ns4 = mmr_prover::build(4);
    assert!(!mmr.verify(1, b"1", vector[n(&ns3, 2), n(&ns3, 4)], vector[], vector[]));
    assert!(mmr.verify(1, b"1", vector[n(&ns4, 2), n(&ns4, 6)], vector[], vector[]));
    assert!(mmr.verify_at_checkpoint(4, 1, b"1", p4, l4, r4));
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr_proof::EPathLength)]
fun o07b_stale_single_proof_shape() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, leaves_range(1, 3), ctx);
    let ns3 = mmr_prover::build(3);
    let (p4, l4, r4) = ns3.single_proof(1);
    mmr.append_leaves(&cap, leaves_range(4, 4), ctx);
    mmr.verify(1, b"1", p4, l4, r4);
    teardown(mmr, admin, cap);
}

// ============================================================================== traversal probe

/// T01: the batch loop always reaches the peak with exactly one node for every subset of the
/// leaves of a 3-mountain MMR (size 11: peaks 7, 10, 11) and every leaf-data corruption still
/// yields false, never an abort. Covers each mountain being touched or untouched and every
/// derive/read pattern on the first mountain.
fun every_subset_size_11(from_mask: u64, to_mask: u64) {
    let ns = mmr_prover::build(7); // leaves at 1, 2, 4, 5, 8, 9, 11; size 11
    assert_eq!(ns.size(), 11);
    let root = ns.root();
    let leaf_positions = vector[1, 2, 4, 5, 8, 9, 11];
    let mut mask = from_mask;
    while (mask <= to_mask) {
        let mut positions = vector[];
        let mut leaves = vector[];
        7u64.do!(|i| if ((mask >> (i as u8)) & 1 == 1) {
            positions.push_back(leaf_positions[i]);
            leaves.push_back(mmr_prover::leaf_data(i + 1));
        });
        let (s, u) = ns.batch_proof(positions);
        assert!(mmr_proof::verify_multiple_with_root(root, 11, positions, leaves, s, u));
        // corrupt each leaf in turn
        let k = positions.length();
        k.do!(|j| {
            let mut bad = leaves;
            *(&mut bad[j]) = b"zz";
            assert!(!mmr_proof::verify_multiple_with_root(root, 11, positions, bad, s, u));
        });
        // rotate the siblings (if 2 or more) -> false
        if (s.length() >= 2) {
            let mut rot = s;
            let first = rot.remove(0);
            rot.push_back(first);
            assert!(!mmr_proof::verify_multiple_with_root(root, 11, positions, leaves, rot, u));
        };
        // rotate the untouched peaks (if 2 or more) -> false
        if (u.length() >= 2) {
            let mut rot = u;
            let first = rot.remove(0);
            rot.push_back(first);
            assert!(!mmr_proof::verify_multiple_with_root(root, 11, positions, leaves, s, rot));
        };
        mask = mask + 1;
    };
}

#[test] fun t01a_every_subset_size_11() { every_subset_size_11(1, 42); }
#[test] fun t01b_every_subset_size_11() { every_subset_size_11(43, 85); }
#[test] fun t01c_every_subset_size_11() { every_subset_size_11(86, 127); }

/// T02: `compute_batch_root` on a well-formed but wrong proof always returns 32 bytes (no abort)
/// when siblings/untouched are arbitrary 32-byte values.
#[test]
fun t02_arbitrary_32_byte_hashes_never_abort() {
    let ns = mmr_prover::build(13);
    let junk = vector::tabulate!(32, |i| (i as u8));
    let (s, u) = ns.batch_proof(vector[4, 9, 16]);
    let s_junk = vector::tabulate!(s.length(), |_| junk);
    let u_junk = vector::tabulate!(u.length(), |_| junk);
    let r = mmr_proof::compute_batch_root(23, vector[4, 9, 16], vector[b"3", b"6", b"9"], s_junk, u_junk);
    assert_eq!(r.length(), 32);
    assert!(r != ROOT_13);
    let (path, left, right) = ns.single_proof(16);
    let r2 = mmr_proof::compute_root(23, 16, junk, vector::tabulate!(path.length(), |_| junk), vector::tabulate!(left.length(), |_| junk), vector::tabulate!(right.length(), |_| junk));
    assert_eq!(r2.length(), 32);
    assert!(r2 != ROOT_13);
}
