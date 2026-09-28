/// Gas probes: run with `sui move test --build-env testnet -s csv` and read the gas column
/// (reported as 49999995000000 + units used). Each probe isolates one operation on top of a
/// fixed setup so costs can be subtracted.
#[test_only]
module mmr::gas_probe_tests;

use std::unit_test::{assert_eq, destroy};
use mmr::mmr;
use mmr::mmr_proof;
use mmr::mmr_prover;

fun build_mmr(n: u64, ctx: &mut TxContext): (mmr::MMR, mmr::AdminCap, mmr::AppendCap) {
    let (mut m, admin) = mmr::new(b"log".to_string(), ctx);
    let cap = m.mint_append_cap(&admin, ctx);
    if (n > 0) { m.append_leaves(&cap, mmr_prover::leaves(n), ctx); };
    (m, admin, cap)
}

fun batch_inputs(k: u64, step: u64): (vector<u64>, vector<vector<u8>>) {
    let leaf_numbers = vector::tabulate!(k, |i| i * step + 1);
    (
        leaf_numbers.map_ref!(|n| mmr_prover::leaf_position(*n)),
        leaf_numbers.map_ref!(|n| mmr_prover::leaf_data(*n)),
    )
}

// ---- object appends

#[test]
fun probe_setup_only() {
    let ctx = &mut tx_context::dummy();
    let (m, admin, cap) = build_mmr(0, ctx);
    assert_eq!(m.size(), 0);
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_append_1_on_empty() {
    let ctx = &mut tx_context::dummy();
    let (m, admin, cap) = build_mmr(1, ctx);
    assert_eq!(m.size(), 1);
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_append_100_batch() {
    let ctx = &mut tx_context::dummy();
    let (m, admin, cap) = build_mmr(100, ctx);
    assert_eq!(m.size(), 197);
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_append_500_batch() {
    let ctx = &mut tx_context::dummy();
    let (m, admin, cap) = build_mmr(500, ctx);
    assert_eq!(m.size(), 994);
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_append_1_on_500() {
    let ctx = &mut tx_context::dummy();
    let (mut m, admin, cap) = build_mmr(500, ctx);
    m.append_leaves(&cap, vector[b"501"], ctx);
    assert_eq!(m.size(), 995);
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_append_10_on_500() {
    let ctx = &mut tx_context::dummy();
    let (mut m, admin, cap) = build_mmr(500, ctx);
    m.append_leaves(&cap, vector::tabulate!(10, |i| mmr_prover::leaf_data(501 + i)), ctx);
    assert_eq!(m.size(), 1012);
    destroy(m); destroy(admin); destroy(cap);
}

// ---- capability management and seal (subtract probe_setup_only)

#[test]
fun probe_cap_mint() {
    let ctx = &mut tx_context::dummy();
    let (mut m, admin, cap) = build_mmr(0, ctx);
    let cap2 = m.mint_append_cap(&admin, ctx);
    assert_eq!(m.append_cap_ids().length(), 2);
    destroy(m); destroy(admin); destroy(cap); destroy(cap2);
}

#[test]
fun probe_cap_revoke() {
    let ctx = &mut tx_context::dummy();
    let (mut m, admin, cap) = build_mmr(0, ctx);
    m.revoke_append_cap(&admin, object::id(&cap));
    assert_eq!(m.append_cap_ids().length(), 0);
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_cap_destroy() {
    let ctx = &mut tx_context::dummy();
    let (mut m, admin, cap) = build_mmr(0, ctx);
    m.destroy_append_cap(cap);
    assert_eq!(m.append_cap_ids().length(), 0);
    destroy(m); destroy(admin);
}

#[test]
fun probe_seal() {
    let ctx = &mut tx_context::dummy();
    let (mut m, admin, cap) = build_mmr(0, ctx);
    m.seal(&admin);
    assert!(m.is_sealed());
    destroy(m); destroy(admin); destroy(cap);
}

// ---- prover builds (baselines)

#[test]
fun probe_prover_build_200() { assert!(mmr_prover::build(200).size() == 397); }

#[test]
fun probe_prover_build_1000() { assert!(mmr_prover::build(1000).size() == 1994); }

// ---- single verify at 200 and 1000 leaves (subtract the build + gen baselines)

#[test]
fun probe_gen_single_at_200() {
    let ns = mmr_prover::build(200);
    let (path, _l, _r) = ns.single_proof(1);
    assert!(path.length() == 7);
}

#[test]
fun probe_verify_single_at_200() {
    let ns = mmr_prover::build(200);
    let (path, left, right) = ns.single_proof(1);
    assert!(mmr_proof::verify_with_root(ns.root(), ns.size(), 1, b"1", path, left, right));
}

#[test]
fun probe_gen_single_at_1000() {
    let ns = mmr_prover::build(1000);
    let (path, _l, _r) = ns.single_proof(1);
    assert!(path.length() == 9);
}

#[test]
fun probe_verify_single_at_1000() {
    let ns = mmr_prover::build(1000);
    let (path, left, right) = ns.single_proof(1);
    assert!(mmr_proof::verify_with_root(ns.root(), ns.size(), 1, b"1", path, left, right));
}

// ---- batch verify (subtract build + gen baselines)

#[test]
fun probe_gen_batch_10_at_1000() {
    let ns = mmr_prover::build(1000);
    let (positions, _leaves) = batch_inputs(10, 97);
    let (siblings, untouched) = ns.batch_proof(positions);
    assert!(siblings.length() + untouched.length() > 0);
}

#[test]
fun probe_verify_batch_10_at_1000() {
    let ns = mmr_prover::build(1000);
    let (positions, leaves) = batch_inputs(10, 97);
    let (siblings, untouched) = ns.batch_proof(positions);
    assert!(mmr_proof::verify_multiple_with_root(ns.root(), ns.size(), positions, leaves, siblings, untouched));
}

#[test]
fun probe_gen_batch_100_at_200() {
    let ns = mmr_prover::build(200);
    let (positions, _leaves) = batch_inputs(100, 2);
    let (siblings, untouched) = ns.batch_proof(positions);
    assert!(siblings.length() + untouched.length() > 0);
}

#[test]
fun probe_verify_batch_100_at_200() {
    let ns = mmr_prover::build(200);
    let (positions, leaves) = batch_inputs(100, 2);
    let (siblings, untouched) = ns.batch_proof(positions);
    assert!(mmr_proof::verify_multiple_with_root(ns.root(), ns.size(), positions, leaves, siblings, untouched));
}

#[test]
fun probe_gen_10_singles_at_200() {
    let ns = mmr_prover::build(200);
    let (positions, _leaves) = batch_inputs(10, 20);
    positions.do_ref!(|p| { let (path, _l, _r) = ns.single_proof(*p); assert!(!path.is_empty()); });
}

#[test]
fun probe_verify_10_singles_at_200() {
    let ns = mmr_prover::build(200);
    let (positions, leaves) = batch_inputs(10, 20);
    positions.length().do!(|i| {
        let (path, left, right) = ns.single_proof(positions[i]);
        assert!(mmr_proof::verify_with_root(ns.root(), ns.size(), positions[i], leaves[i], path, left, right));
    });
}

#[test]
fun probe_gen_batch_10_at_200() {
    let ns = mmr_prover::build(200);
    let (positions, _leaves) = batch_inputs(10, 20);
    let (siblings, untouched) = ns.batch_proof(positions);
    assert!(siblings.length() + untouched.length() > 0);
}

#[test]
fun probe_verify_batch_10_at_200() {
    let ns = mmr_prover::build(200);
    let (positions, leaves) = batch_inputs(10, 20);
    let (siblings, untouched) = ns.batch_proof(positions);
    assert!(mmr_proof::verify_multiple_with_root(ns.root(), ns.size(), positions, leaves, siblings, untouched));
}

// ---- object-bound verify (current vs anchor)

#[test]
fun probe_object_200_and_gen_only() {
    let ctx = &mut tx_context::dummy();
    let (m, admin, cap) = build_mmr(200, ctx);
    let ns = mmr_prover::build(200);
    let (path, _l, _r) = ns.single_proof(1);
    assert!(path.length() == 7);
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_object_verify_current_at_200() {
    let ctx = &mut tx_context::dummy();
    let (m, admin, cap) = build_mmr(200, ctx);
    let ns = mmr_prover::build(200);
    let (path, left, right) = ns.single_proof(1);
    assert!(m.verify(1, b"1", path, left, right));
    destroy(m); destroy(admin); destroy(cap);
}

#[test]
fun probe_object_verify_anchor_at_200() {
    let ctx = &mut tx_context::dummy();
    let (m, admin, cap) = build_mmr(200, ctx);
    let ns = mmr_prover::build(200);
    let (path, left, right) = ns.single_proof(1);
    assert!(m.verify_at_anchor(397, 1, b"1", path, left, right));
    destroy(m); destroy(admin); destroy(cap);
}
