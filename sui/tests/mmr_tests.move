#[test_only]
module mmr::mmr_tests;

use std::unit_test::{assert_eq, destroy};
use sui::event;
use sui::test_scenario;
use mmr::mmr::{Self, MMR, AdminCap, AppendCap};
use mmr::mmr_test_fixtures::{setup, teardown};
use mmr::mmr_proof;
use mmr::mmr_prover;
use mmr::mmr_utils;

const ROOT_0: vector<u8> = x"0fd923ca5e7218c4ba3c3801c26a617ecdbfdaebb9c76ce2eca166e7855efbb8";
const ROOT_13: vector<u8> = x"737ff3b5d4244e05bc4248b78002040f3d9e37a55fcdea39a57d955cdb5e79d5";
const ROOT_95: vector<u8> = x"58cd048bbf551d2b2ca2f72360c1f9a51b1b4eff9d694c236976096e1199ff91";
const ROOT_1000: vector<u8> = x"3bc88226da8e8fc7ec4d7571cc23d9de18e6eaa9667f9be06c2069bbce994de0";
// README MMR node hashes of the byte-pinned proof for position 16 (leaf "9"), from
// `scripts/golden.py --move`.
const N15: vector<u8> = x"8d2ffeca2d06c15af359441bc8292071f17c9aa820c62c33c4eca3955e060675";
const N17: vector<u8> = x"0144ea629dc1bd8fe6fc9eb51a8524b8e7529cbec44741bd020763e1a1377c63";
const N21: vector<u8> = x"a989072f2a74d648c1a53a036adc2af63e71d4d0ec3f604d4080a67146243f84";
const N23: vector<u8> = x"fa4d80fd8386d9b5abaca7d1d5660a0255921013df1928b59501b8bd6d342772";

// ------------------------------------------------------------------------------ helpers

/// Leaves "14".."95".
fun leaves_14_to_95(): vector<vector<u8>> {
    vector::tabulate!(82, |i| mmr_prover::leaf_data(i + 14))
}

/// The README proof for position 16 (leaf "9") at size 23, from the pinned node hashes and
/// independent of the prover: (path, left_peaks, right_peaks).
fun readme_proof(): (vector<vector<u8>>, vector<vector<u8>>, vector<vector<u8>>) {
    (vector[N17, N21], vector[N15], vector[N23])
}

// ------------------------------------------------------------------------------ creation

#[test]
fun new_is_empty_and_versioned() {
    let ctx = &mut tx_context::dummy();
    let (mmr, admin) = mmr::new(b"app-7/log-42".to_string(), ctx);
    assert_eq!(mmr.size(), 0);
    assert_eq!(mmr.leaf_count(), 0);
    assert_eq!(mmr.peaks(), vector[]);
    assert_eq!(mmr.root(), sui::hash::blake2b256(&b"0"));
    assert_eq!(mmr.root(), ROOT_0);
    assert_eq!(mmr.version(), 1);
    assert!(!mmr.is_sealed());
    assert_eq!(mmr.label(), b"app-7/log-42".to_string());
    assert_eq!(mmr.anchor_count(), 0);
    assert!(!mmr.has_anchor(0));
    assert_eq!(admin.mmr_id(), object::id(&mmr));
    assert_eq!(mmr.append_cap_ids(), vector[]);
    let events = event::events_by_type<mmr::MMRCreatedEvent>();
    assert_eq!(events.length(), 1);
    let (id, label, admin_id) = mmr::created_event_fields_for_testing(&events[0]);
    assert_eq!(id, object::id(&mmr));
    assert_eq!(label, b"app-7/log-42".to_string());
    assert_eq!(admin_id, object::id(&admin));
    destroy(mmr);
    destroy(admin);
}

#[test]
fun package_constants_are_exposed() {
    let ctx = &mut tx_context::dummy();
    let (mmr, admin) = mmr::new(b"log".to_string(), ctx);
    assert_eq!(mmr::package_version(), 1);
    assert_eq!(mmr.version(), mmr::package_version());
    assert_eq!(mmr::max_append_caps(), 64);
    destroy(mmr);
    destroy(admin);
}

#[test]
fun label_of_exactly_128_bytes_is_accepted() {
    let ctx = &mut tx_context::dummy();
    let label = vector::tabulate!(128, |_| 97u8).to_string();
    let (mmr, admin) = mmr::new(label, ctx);
    assert_eq!(mmr.label().length(), 128);
    destroy(mmr);
    destroy(admin);
}

#[test, expected_failure(abort_code = mmr::ELabelTooLong)]
fun new_rejects_long_label() {
    let ctx = &mut tx_context::dummy();
    let label = vector::tabulate!(129, |_| 97u8).to_string();
    let (_mmr, _admin) = mmr::new(label, ctx);
    abort
}

#[test, expected_failure(abort_code = mmr::ELabelTooLong)]
fun create_rejects_long_label() {
    // 43 three-byte UTF-8 characters = 129 bytes: the limit counts bytes, not characters
    let mut bytes = vector[];
    43u64.do!(|_| bytes.append(x"e282ac"));
    let mut scenario = test_scenario::begin(@0xCAFE);
    mmr::create(bytes.to_string(), scenario.ctx());
    abort
}

#[test]
fun create_entry_shares_and_sends_admin_cap() {
    let owner = @0xCAFE;
    let mut scenario = test_scenario::begin(owner);
    mmr::create(b"log".to_string(), scenario.ctx());
    scenario.next_tx(owner);
    let mut mmr = scenario.take_shared<MMR>();
    let admin = scenario.take_from_sender<AdminCap>();
    // `create` mints no writer cap
    assert!(!test_scenario::has_most_recent_for_sender<AppendCap>(&scenario));
    assert_eq!(admin.mmr_id(), object::id(&mmr));
    assert_eq!(mmr.label(), b"log".to_string());
    let cap = mmr.mint_append_cap(&admin, scenario.ctx());
    let first = mmr.append_leaves(&cap, vector[b"a", b"b", b"c"], scenario.ctx());
    assert_eq!(first, 0);
    assert_eq!(mmr.size(), 4);
    test_scenario::return_shared(mmr);
    scenario.return_to_sender(admin);
    // minted inside this transaction: transfer it, never `return_to_sender`
    transfer::public_transfer(cap, owner);
    scenario.end();
}

#[test]
fun new_and_share_in_one_transaction() {
    let owner = @0xCAFE;
    let mut scenario = test_scenario::begin(owner);
    let (mmr, admin) = mmr::new(b"log".to_string(), scenario.ctx());
    mmr::share(mmr);
    transfer::public_transfer(admin, owner);
    scenario.next_tx(owner);
    let mmr = scenario.take_shared<MMR>();
    assert_eq!(mmr.size(), 0);
    let admin = scenario.take_from_sender<AdminCap>();
    assert_eq!(admin.mmr_id(), object::id(&mmr));
    test_scenario::return_shared(mmr);
    scenario.return_to_sender(admin);
    scenario.end();
}

/// Two append batches in two transactions on the shared object: the anchor of the first batch
/// survives the second one, and the same cap writes both.
#[test]
fun append_across_transactions_keeps_anchors() {
    let owner = @0xCAFE;
    let mut scenario = test_scenario::begin(owner);
    mmr::create(b"log".to_string(), scenario.ctx());
    // tx 2: mint a writer cap and append the first batch
    scenario.next_tx(owner);
    let mut mmr = scenario.take_shared<MMR>();
    let admin = scenario.take_from_sender<AdminCap>();
    let cap = mmr.mint_append_cap(&admin, scenario.ctx());
    mmr.append_leaves(&cap, mmr_prover::leaves(13), scenario.ctx());
    assert_eq!(mmr.root(), ROOT_13);
    test_scenario::return_shared(mmr);
    scenario.return_to_sender(admin);
    // tx 3: the same cap appends leaves 14..95; the first anchor is untouched
    scenario.next_tx(owner);
    let mut mmr = scenario.take_shared<MMR>();
    let first = mmr.append_leaves(&cap, leaves_14_to_95(), scenario.ctx());
    assert_eq!(first, 13);
    assert_eq!(mmr.root(), ROOT_95);
    assert_eq!(mmr.root_at(23), ROOT_13);
    assert_eq!(mmr.anchor(184).batch_index(), 1);
    assert_eq!(mmr.anchor(184).cap_id(), object::id(&cap));
    assert_eq!(mmr.anchor_count(), 2);
    test_scenario::return_shared(mmr);
    // minted inside tx 2 and never transferred: consume it here
    destroy(cap);
    scenario.end();
}

// ------------------------------------------------------------------------------ append

#[test]
fun append_matches_node_vector_reference_incrementally() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    let mut ns = mmr_prover::new();
    // one leaf per batch: every intermediate state must match the node-vector append
    200u64.do!(|i| {
        let leaf = mmr_prover::leaf_data(i + 1);
        ns.append(leaf);
        let first = mmr.append_leaves(&cap, vector[leaf], ctx);
        assert_eq!(first, i);
        assert_eq!(mmr.size(), ns.size());
        assert_eq!(mmr.leaf_count(), i + 1);
        assert_eq!(mmr.peaks(), ns.peaks());
        assert_eq!(mmr.root(), ns.root());
        assert!(mmr.has_anchor(mmr.size()));
    });
    assert_eq!(mmr.root(), mmr_prover::build(200).root());
    assert_eq!(mmr.anchor_count(), 200);
    teardown(mmr, admin, cap);
}

#[test]
fun peaks_stack_pops_last_peak_lockstep() {
    // The peaks-stack append (`mmr::append_leaf`, verbatim) run next to the node-vector reference: at
    // every merge the popped value is the left sibling of the node being placed.
    let mut ns = mmr_prover::new();
    let mut stack: vector<vector<u8>> = vector[];
    let mut size = 0;
    200u64.do!(|i| {
        let leaf = mmr_prover::leaf_data(i + 1);
        ns.append(leaf);
        let mut position = size + 1;
        let mut node_hash = mmr_utils::hash_with_integer(position, vector[leaf]);
        while (mmr_utils::is_right_sibling(position)) {
            let left = stack.pop_back();
            assert_eq!(left, ns.node(mmr_utils::get_sibling_position(position)));
            position = position + 1;
            node_hash = mmr_utils::hash_with_integer(position, vector[left, node_hash]);
            assert_eq!(node_hash, ns.node(position));
        };
        stack.push_back(node_hash);
        size = position;
        assert_eq!(size, ns.size());
        assert_eq!(stack, ns.peaks());
        assert_eq!(mmr_utils::hash_with_integer(size, stack), ns.root());
    });
}

#[test]
fun append_batches_match_reference_and_golden() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    let first = mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    assert_eq!(first, 0);
    assert_eq!(mmr.size(), 23);
    assert_eq!(mmr.leaf_count(), 13);
    assert_eq!(mmr.root(), ROOT_13);
    // second batch: leaves 14..95
    let first = mmr.append_leaves(&cap, leaves_14_to_95(), ctx);
    assert_eq!(first, 13);
    assert_eq!(mmr.size(), 184);
    assert_eq!(mmr.leaf_count(), 95);
    assert_eq!(mmr.root(), ROOT_95);
    assert_eq!(mmr.peaks(), mmr_prover::build(95).peaks());
    assert_eq!(event::events_by_type<mmr::LeavesAppendedEvent>().length(), 2);
    teardown(mmr, admin, cap);
}

#[test]
fun append_event_contents() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let events = event::events_by_type<mmr::LeavesAppendedEvent>();
    assert_eq!(events.length(), 1);
    let (mmr_id, cap_id, batch_index, first_leaf_index, batch_leaf_count, leaf_count, old_size, new_size, leaf_hashes, peaks, root, epoch) =
        mmr::leaves_appended_event_fields_for_testing(&events[0]);
    assert_eq!(mmr_id, object::id(&mmr));
    assert_eq!(cap_id, object::id(&cap));
    assert_eq!(batch_index, 0);
    assert_eq!(first_leaf_index, 0);
    assert_eq!(batch_leaf_count, 13);
    assert_eq!(leaf_count, 13);
    assert_eq!(old_size, 0);
    assert_eq!(new_size, 23);
    let ns = mmr_prover::build(13);
    assert_eq!(leaf_hashes.length(), 13);
    13u64.do!(|i| assert_eq!(leaf_hashes[i], ns.node(mmr_prover::leaf_position(i + 1))));
    assert_eq!(peaks, ns.peaks());
    assert_eq!(root, ROOT_13);
    assert_eq!(epoch, ctx.epoch());
    // the event and the anchor row name the same writer
    assert_eq!(mmr.anchor(23).cap_id(), object::id(&cap));
    // a second batch in a later epoch: indices and sizes advance, the epoch follows the context
    ctx.increment_epoch_number();
    mmr.append_leaves(&cap, vector[b"x", b"y"], ctx);
    let events = event::events_by_type<mmr::LeavesAppendedEvent>();
    assert_eq!(events.length(), 2);
    let (_, cap_id2, batch_index, first_leaf_index, batch_leaf_count, leaf_count, old_size, new_size, leaf_hashes, peaks, root, epoch2) =
        mmr::leaves_appended_event_fields_for_testing(&events[1]);
    assert_eq!(cap_id2, object::id(&cap));
    assert_eq!(batch_index, 1);
    assert_eq!(first_leaf_index, 13);
    assert_eq!(batch_leaf_count, 2);
    assert_eq!(leaf_count, 15);
    assert_eq!(old_size, 23);
    assert_eq!(new_size, 26);
    // leaf 14 sits at position 24 (merging with leaf 13 at 23 into parent 25) and leaf 15 at 26
    assert_eq!(leaf_hashes, vector[
        mmr_utils::hash_with_integer(24, vector[b"x"]),
        mmr_utils::hash_with_integer(26, vector[b"y"]),
    ]);
    assert_eq!(peaks, mmr.peaks());
    assert_eq!(root, mmr.root());
    assert_eq!(epoch2, ctx.epoch());
    assert!(epoch2 != epoch);
    assert_eq!(mmr.anchor(26).batch_index(), 1);
    assert_eq!(mmr.anchor(26).epoch(), epoch2);
    assert!(mmr.anchor(23).epoch() != epoch2);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::EEmptyBatch)]
fun append_rejects_empty_batch() {
    // The abort rolls the whole transaction back, so no event and no anchor can result;
    // a unit test can only observe the abort itself.
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, vector[], ctx);
    abort
}

#[test, expected_failure(abort_code = mmr::EBatchTooLarge)]
fun append_rejects_oversized_batch() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(1001), ctx);
    abort
}

/// Exactly `MAX_BATCH_LEAVES` leaves in one call: 1000 leaves give size 1994 and the golden root.
#[test]
fun append_accepts_max_batch() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    let first = mmr.append_leaves(&cap, mmr_prover::leaves(1000), ctx);
    assert_eq!(first, 0);
    assert_eq!(mmr.size(), 1994);
    assert_eq!(mmr.leaf_count(), 1000);
    assert_eq!(mmr.root(), ROOT_1000);
    assert_eq!(mmr.anchor_count(), 1);
    assert!(mmr.has_anchor(1994));
    teardown(mmr, admin, cap);
}

// ------------------------------------------------------------------------------ verify

#[test]
fun verify_current_and_at_anchor() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let ns13 = mmr_prover::build(13);
    assert_eq!(ns13.root(), mmr.root());
    // the byte-pinned README proof, independent of the prover
    let (path, left, right) = readme_proof();
    assert!(mmr.verify(16, b"9", path, left, right));
    assert!(!mmr.verify(16, b"8", path, left, right));
    assert!(mmr.verify_at_anchor(23, 16, b"9", path, left, right));
    // a second writer appends leaves 14..95: the old proof stays valid at anchor 23
    let cap2 = mmr.mint_append_cap(&admin, ctx);
    mmr.append_leaves(&cap2, leaves_14_to_95(), ctx);
    assert!(mmr.verify_at_anchor(23, 16, b"9", path, left, right));
    assert!(!mmr.verify_at_anchor(23, 16, b"8", path, left, right));
    let cp = mmr.anchor(23);
    assert_eq!(cp.root(), ROOT_13);
    assert_eq!(cp.leaf_count(), 13);
    assert_eq!(cp.peaks(), ns13.peaks());
    assert_eq!(cp.batch_index(), 0);
    assert_eq!(cp.size(), 23);
    assert_eq!(cp.epoch(), ctx.epoch());
    assert_eq!(cp.cap_id(), object::id(&cap));
    let cp2 = mmr.anchor(184);
    assert_eq!(cp2.root(), ROOT_95);
    assert_eq!(cp2.batch_index(), 1);
    assert_eq!(cp2.cap_id(), object::id(&cap2));
    assert!(cp.cap_id() != cp2.cap_id());
    assert_eq!(mmr.anchor_count(), 2);
    assert_eq!(mmr.root_at(23), ROOT_13);
    assert_eq!(mmr.root_at(184), ROOT_95);
    // a fresh proof verifies against the current root and the latest anchor
    let ns95 = mmr_prover::build(95);
    assert_eq!(ns95.root(), mmr.root());
    let (p2, l2, r2) = ns95.single_proof(16);
    assert!(mmr.verify(16, b"9", p2, l2, r2));
    assert!(mmr.verify_at_anchor(184, 16, b"9", p2, l2, r2));
    teardown(mmr, admin, cap);
    destroy(cap2);
}

#[test, expected_failure(abort_code = mmr_proof::EPathLength)]
fun stale_proof_against_current_root_aborts_on_shape() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (path, left, right) = mmr_prover::build(13).single_proof(16);
    mmr.append_leaves(&cap, leaves_14_to_95(), ctx);
    // the path length for position 16 at size 184 differs from the one at size 23
    mmr.verify(16, b"9", path, left, right);
    abort
}

/// A stale proof whose shape happens to match the new size returns false (never true).
#[test]
fun stale_proof_of_matching_shape_is_false() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (path, left, right) = readme_proof();
    // size 23 -> 25: peaks [15, 22, 25]; position 16 keeps path length 2, one left, one right
    mmr.append_leaves(&cap, vector[b"14"], ctx);
    assert_eq!(mmr.size(), 25);
    assert!(!mmr.verify(16, b"9", path, left, right));
    assert!(mmr.verify_at_anchor(23, 16, b"9", path, left, right));
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENoAnchor)]
fun verify_at_anchor_rejects_unknown_size() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.verify_at_anchor(22, 16, b"9", vector[], vector[], vector[]);
    abort
}

#[test, expected_failure(abort_code = mmr::ENoAnchor)]
fun anchor_getter_rejects_unknown_size() {
    let ctx = &mut tx_context::dummy();
    let (mmr, _admin, _cap) = setup(ctx);
    mmr.anchor(1);
    abort
}

#[test, expected_failure(abort_code = mmr::ENoAnchor)]
fun root_at_rejects_unknown_size() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.root_at(22);
    abort
}

/// No row exists at size 0, even though the empty root is well defined.
#[test, expected_failure(abort_code = mmr::ENoAnchor)]
fun root_at_rejects_size_zero() {
    let ctx = &mut tx_context::dummy();
    let (mmr, _admin, _cap) = setup(ctx);
    mmr.root_at(0);
    abort
}

#[test]
fun verify_multiple_current_and_at_anchor() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let ns = mmr_prover::build(13);
    assert_eq!(ns.root(), mmr.root());
    let (siblings, untouched) = ns.batch_proof(vector[4, 9, 16]);
    let leaves = vector[b"3", b"6", b"9"];
    assert!(mmr.verify_multiple(vector[4, 9, 16], leaves, siblings, untouched));
    assert!(mmr.verify_multiple_at_anchor(23, vector[4, 9, 16], leaves, siblings, untouched));
    mmr.append_leaves(&cap, vector[b"14"], ctx);
    assert!(mmr.verify_multiple_at_anchor(23, vector[4, 9, 16], leaves, siblings, untouched));
    assert!(!mmr.verify_multiple_at_anchor(23, vector[4, 9, 16], vector[b"3", b"6", b"x"], siblings, untouched));
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENoAnchor)]
fun verify_multiple_at_anchor_rejects_unknown_size() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.verify_multiple_at_anchor(4, vector[1], vector[b"1"], vector[], vector[]);
    abort
}

// The object wrappers propagate the `mmr_proof` errors of a malformed proof.

/// `verify_multiple` on the object aborts with `mmr_proof::EEmptyBatch`, not `mmr::EEmptyBatch`.
#[test, expected_failure(abort_code = mmr_proof::EEmptyBatch)]
fun verify_multiple_rejects_empty_batch_with_proof_error() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.verify_multiple(vector[], vector[], vector[], vector[]);
    abort
}

#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun verify_rejects_position_beyond_object_size() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.verify(24, b"14", vector[], vector[], vector[]);
    abort
}

#[test, expected_failure(abort_code = mmr_proof::EPositionOutOfRange)]
fun verify_on_empty_mmr_rejects_every_position() {
    let ctx = &mut tx_context::dummy();
    let (mmr, _admin, _cap) = setup(ctx);
    mmr.verify(1, b"1", vector[], vector[], vector[]);
    abort
}

#[test]
fun assert_included_true_is_noop() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (path, left, right) = readme_proof();
    mmr::assert_included(mmr.verify(16, b"9", path, left, right));
    mmr::assert_included(true);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENotIncluded)]
fun assert_included_false_aborts() {
    mmr::assert_included(false);
}

// ------------------------------------------------------------------------------ abort-shaped verifiers
// The `assert_verify*` wrappers return nothing: an honest proof is a no-op, a wrong one aborts
// with `ENotIncluded` inside the module.

#[test]
fun assert_verify_passes_on_honest_proof() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (path, left, right) = readme_proof();
    mmr.assert_verify(16, b"9", path, left, right);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENotIncluded)]
fun assert_verify_aborts_on_wrong_leaf() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (path, left, right) = readme_proof();
    mmr.assert_verify(16, b"8", path, left, right);
    abort
}

#[test]
fun assert_verify_at_anchor_passes_on_honest_proof() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.append_leaves(&cap, vector[b"14"], ctx);
    let (path, left, right) = readme_proof();
    mmr.assert_verify_at_anchor(23, 16, b"9", path, left, right);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENotIncluded)]
fun assert_verify_at_anchor_aborts_on_wrong_leaf() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (path, left, right) = readme_proof();
    mmr.assert_verify_at_anchor(23, 16, b"8", path, left, right);
    abort
}

#[test]
fun assert_verify_multiple_passes_on_honest_proof() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (siblings, untouched) = mmr_prover::build(13).batch_proof(vector[4, 9, 16]);
    mmr.assert_verify_multiple(vector[4, 9, 16], vector[b"3", b"6", b"9"], siblings, untouched);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENotIncluded)]
fun assert_verify_multiple_aborts_on_wrong_leaf() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (siblings, untouched) = mmr_prover::build(13).batch_proof(vector[4, 9, 16]);
    mmr.assert_verify_multiple(vector[4, 9, 16], vector[b"3", b"6", b"x"], siblings, untouched);
    abort
}

#[test]
fun assert_verify_multiple_at_anchor_passes_on_honest_proof() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.append_leaves(&cap, vector[b"14"], ctx);
    let (siblings, untouched) = mmr_prover::build(13).batch_proof(vector[4, 9, 16]);
    mmr.assert_verify_multiple_at_anchor(23, vector[4, 9, 16], vector[b"3", b"6", b"9"], siblings, untouched);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENotIncluded)]
fun assert_verify_multiple_at_anchor_aborts_on_wrong_leaf() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    let (siblings, untouched) = mmr_prover::build(13).batch_proof(vector[4, 9, 16]);
    mmr.assert_verify_multiple_at_anchor(23, vector[4, 9, 16], vector[b"3", b"6", b"x"], siblings, untouched);
    abort
}

// ------------------------------------------------------------------------------ versioning

#[test, expected_failure(abort_code = mmr::EWrongVersion)]
fun wrong_version_blocks_append() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.set_version_for_testing(0);
    mmr.append_leaves(&cap, vector[b"x"], ctx);
    abort
}

/// A version ABOVE the package version blocks writes too (the guard is equality).
#[test, expected_failure(abort_code = mmr::EWrongVersion)]
fun future_version_blocks_append() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, _admin, cap) = setup(ctx);
    mmr.set_version_for_testing(2);
    mmr.append_leaves(&cap, vector[b"x"], ctx);
    abort
}

#[test, expected_failure(abort_code = mmr::EWrongVersion)]
fun wrong_version_blocks_mint() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, _cap) = setup(ctx);
    mmr.set_version_for_testing(0);
    let _cap2 = mmr.mint_append_cap(&admin, ctx);
    abort
}

#[test]
fun wrong_version_does_not_block_reads() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.set_version_for_testing(0);
    assert_eq!(mmr.version(), 0);
    let ns = mmr_prover::build(13);
    let (path, left, right) = ns.single_proof(16);
    assert!(mmr.verify(16, b"9", path, left, right));
    assert!(mmr.verify_at_anchor(23, 16, b"9", path, left, right));
    let (siblings, untouched) = ns.batch_proof(vector[4, 9, 16]);
    assert!(mmr.verify_multiple(vector[4, 9, 16], vector[b"3", b"6", b"9"], siblings, untouched));
    assert!(mmr.verify_multiple_at_anchor(23, vector[4, 9, 16], vector[b"3", b"6", b"9"], siblings, untouched));
    let cp = mmr.anchor(23);
    assert_eq!(cp.size(), 23);
    assert_eq!(cp.root(), ROOT_13);
    assert_eq!(cp.leaf_count(), 13);
    assert_eq!(mmr.root_at(23), ROOT_13);
    assert_eq!(mmr.root(), ROOT_13);
    assert_eq!(mmr.size(), 23);
    assert_eq!(mmr.leaf_count(), 13);
    assert_eq!(mmr.peaks(), ns.peaks());
    mmr::assert_included(mmr.verify(16, b"9", path, left, right));
    teardown(mmr, admin, cap);
}

#[test]
fun migrate_restores_version() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.set_version_for_testing(0);
    mmr::migrate(&mut mmr, &admin);
    assert_eq!(mmr.version(), 1);
    mmr.append_leaves(&cap, vector[b"x"], ctx);
    assert_eq!(mmr.size(), 1);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::ENotUpgrade)]
fun migrate_rejects_current_version() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, _cap) = setup(ctx);
    mmr::migrate(&mut mmr, &admin);
    abort
}

#[test, expected_failure(abort_code = mmr::ENotUpgrade)]
fun migrate_rejects_version_above_package() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, _cap) = setup(ctx);
    mmr.set_version_for_testing(2);
    mmr::migrate(&mut mmr, &admin);
    abort
}

#[test, expected_failure(abort_code = mmr::EWrongMMR)]
fun migrate_rejects_admin_of_another_mmr() {
    let ctx = &mut tx_context::dummy();
    let (mut a, _admin_a, _cap_a) = setup(ctx);
    let (_b, admin_b, _cap_b) = setup(ctx);
    a.set_version_for_testing(0);
    mmr::migrate(&mut a, &admin_b);
    abort
}
