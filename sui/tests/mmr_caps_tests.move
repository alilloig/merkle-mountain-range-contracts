#[test_only]
module mmr::mmr_caps_tests;

use std::unit_test::{assert_eq, destroy};
use sui::event;
use sui::test_scenario;
use mmr::mmr::{Self, MMR, AdminCap, AppendCap};
use mmr::mmr_test_fixtures::{setup, teardown};
use mmr::mmr_prover;

// ------------------------------------------------------------------------------ helpers

/// The only `AppendCapRevokedEvent` emitted so far, as (mmr_id, cap_id, destroyed).
fun only_revoked_event(): (ID, ID, bool) {
    let events = event::events_by_type<mmr::AppendCapRevokedEvent>();
    assert_eq!(events.length(), 1);
    mmr::cap_revoked_event_fields_for_testing(&events[0])
}

// ------------------------------------------------------------------------------ mint

#[test]
fun mint_activates_and_emits() {
    let ctx = &mut tx_context::dummy();
    let (mmr, admin, cap) = setup(ctx);
    let cap_id = object::id(&cap);
    assert!(mmr.is_append_cap_active(cap_id));
    assert_eq!(mmr.append_cap_ids(), vector[cap_id]);
    assert_eq!(cap.mmr_id(), object::id(&mmr));
    let events = event::events_by_type<mmr::AppendCapMintedEvent>();
    assert_eq!(events.length(), 1);
    let (event_mmr_id, event_cap_id) = mmr::cap_minted_event_fields_for_testing(&events[0]);
    assert_eq!(event_mmr_id, object::id(&mmr));
    assert_eq!(event_cap_id, cap_id);
    teardown(mmr, admin, cap);
}

#[test, expected_failure(abort_code = mmr::EWrongMMR)]
fun append_rejects_cap_of_another_mmr() {
    let ctx = &mut tx_context::dummy();
    let (mut a, _admin_a, _cap_a) = setup(ctx);
    let (_b, _admin_b, cap_b) = setup(ctx);
    a.append_leaves(&cap_b, vector[b"x"], ctx);
    abort
}

#[test, expected_failure(abort_code = mmr::EWrongMMR)]
fun mint_rejects_admin_of_another_mmr() {
    let ctx = &mut tx_context::dummy();
    let (mut a, _admin_a, _cap_a) = setup(ctx);
    let (_b, admin_b, _cap_b) = setup(ctx);
    let _cap = a.mint_append_cap(&admin_b, ctx);
    abort
}

#[test, expected_failure(abort_code = mmr::EWrongMMR)]
fun revoke_rejects_admin_of_another_mmr() {
    let ctx = &mut tx_context::dummy();
    let (mut a, _admin_a, cap_a) = setup(ctx);
    let (_b, admin_b, _cap_b) = setup(ctx);
    a.revoke_append_cap(&admin_b, object::id(&cap_a));
    abort
}

#[test, expected_failure(abort_code = mmr::EWrongMMR)]
fun seal_rejects_admin_of_another_mmr() {
    let ctx = &mut tx_context::dummy();
    let (mut a, _admin_a, _cap_a) = setup(ctx);
    let (_b, admin_b, _cap_b) = setup(ctx);
    a.seal(&admin_b);
    abort
}

#[test, expected_failure(abort_code = mmr::EWrongMMR)]
fun destroy_append_cap_rejects_other_mmr() {
    let ctx = &mut tx_context::dummy();
    let (mut a, _admin_a, _cap_a) = setup(ctx);
    let (_b, _admin_b, cap_b) = setup(ctx);
    a.destroy_append_cap(cap_b);
    abort
}

/// The registry is per object: a cap of B is never active on A, whatever its id.
#[test]
fun caps_of_another_mmr_are_never_active() {
    let ctx = &mut tx_context::dummy();
    let (a, admin_a, cap_a) = setup(ctx);
    let (b, admin_b, cap_b) = setup(ctx);
    assert!(!a.is_append_cap_active(object::id(&cap_b)));
    assert!(!b.is_append_cap_active(object::id(&cap_a)));
    assert!(!a.is_append_cap_active(object::id(&admin_a)));
    assert_eq!(cap_a.mmr_id(), object::id(&a));
    assert_eq!(cap_b.mmr_id(), object::id(&b));
    assert_eq!(admin_b.mmr_id(), object::id(&b));
    teardown(a, admin_a, cap_a);
    teardown(b, admin_b, cap_b);
}

// ------------------------------------------------------------------------------ revoke / destroy

#[test, expected_failure(abort_code = mmr::ECapNotActive)]
fun append_rejects_revoked_cap() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.revoke_append_cap(&admin, object::id(&cap));
    assert!(!mmr.is_append_cap_active(object::id(&cap)));
    assert_eq!(mmr.append_cap_ids(), vector[]);
    mmr.append_leaves(&cap, vector[b"x"], ctx);
    abort
}

#[test, expected_failure(abort_code = mmr::ECapNotActive)]
fun revoke_rejects_unknown_cap() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, _cap) = setup(ctx);
    // a fresh id that was never minted
    let unknown = object::id_from_address(@0x1);
    assert!(!mmr.is_append_cap_active(unknown));
    mmr.revoke_append_cap(&admin, unknown);
    abort
}

#[test, expected_failure(abort_code = mmr::ECapNotActive)]
fun revoke_rejects_already_revoked_cap() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.revoke_append_cap(&admin, object::id(&cap));
    mmr.revoke_append_cap(&admin, object::id(&cap));
    abort
}

/// The admin cap's own id is not an append cap id.
#[test, expected_failure(abort_code = mmr::ECapNotActive)]
fun revoke_rejects_admin_cap_id() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, _cap) = setup(ctx);
    mmr.revoke_append_cap(&admin, object::id(&admin));
    abort
}

#[test]
fun revoke_then_mint_new_cap_works() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    // rotation: mint the replacement, revoke the old one
    let cap2 = mmr.mint_append_cap(&admin, ctx);
    mmr.revoke_append_cap(&admin, object::id(&cap));
    assert!(!mmr.is_append_cap_active(object::id(&cap)));
    assert!(mmr.is_append_cap_active(object::id(&cap2)));
    assert_eq!(mmr.append_cap_ids(), vector[object::id(&cap2)]);
    mmr.append_leaves(&cap2, vector[b"x"], ctx);
    assert_eq!(mmr.size(), 1);
    let (mmr_id, cap_id, destroyed) = only_revoked_event();
    assert_eq!(mmr_id, object::id(&mmr));
    assert_eq!(cap_id, object::id(&cap));
    assert!(!destroyed);
    destroy(cap2);
    teardown(mmr, admin, cap);
}

#[test]
fun destroy_append_cap_deactivates_it() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    let cap_id = object::id(&cap);
    mmr.destroy_append_cap(cap);
    assert!(!mmr.is_append_cap_active(cap_id));
    assert_eq!(mmr.append_cap_ids(), vector[]);
    let (mmr_id, event_cap_id, destroyed) = only_revoked_event();
    assert_eq!(mmr_id, object::id(&mmr));
    assert_eq!(event_cap_id, cap_id);
    assert!(destroyed);
    destroy(mmr);
    destroy(admin);
}

#[test]
fun destroy_revoked_append_cap_is_silent() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    let cap_id = object::id(&cap);
    mmr.revoke_append_cap(&admin, cap_id);
    mmr.destroy_append_cap(cap);
    // exactly one event: the revoke
    let (_, event_cap_id, destroyed) = only_revoked_event();
    assert_eq!(event_cap_id, cap_id);
    assert!(!destroyed);
    destroy(mmr);
    destroy(admin);
}

/// A destroyed cap's id cannot be revoked again (the registry entry is gone).
#[test, expected_failure(abort_code = mmr::ECapNotActive)]
fun revoke_rejects_destroyed_cap() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    let cap_id = object::id(&cap);
    mmr.destroy_append_cap(cap);
    mmr.revoke_append_cap(&admin, cap_id);
    abort
}

// ------------------------------------------------------------------------------ cap limit

#[test]
fun mint_up_to_the_cap_limit() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin) = mmr::new(b"log".to_string(), ctx);
    64u64.do!(|_| destroy(mmr.mint_append_cap(&admin, ctx)));
    assert_eq!(mmr.append_cap_ids().length(), 64);
    assert_eq!(event::events_by_type<mmr::AppendCapMintedEvent>().length(), 64);
    destroy(mmr);
    destroy(admin);
}

/// Every one of 64 active caps appends once; the last anchor names the last cap.
#[test]
fun every_active_cap_can_append() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin) = mmr::new(b"log".to_string(), ctx);
    let caps = vector::tabulate!(64, |_| mmr.mint_append_cap(&admin, ctx));
    assert_eq!(mmr.append_cap_ids().length(), 64);
    caps.do_ref!(|cap| assert!(mmr.is_append_cap_active(object::id(cap))));
    64u64.do!(|i| assert_eq!(mmr.append_leaves(&caps[i], vector[b"x"], ctx), i));
    assert_eq!(mmr.leaf_count(), 64);
    // 64 leaves fill one perfect tree of 127 nodes
    assert_eq!(mmr.size(), 127);
    assert_eq!(mmr.anchor_count(), 64);
    assert_eq!(mmr.anchor(127).cap_id(), object::id(&caps[63]));
    caps.destroy!(|cap| destroy(cap));
    destroy(mmr);
    destroy(admin);
}

#[test, expected_failure(abort_code = mmr::ETooManyAppendCaps)]
fun mint_rejects_too_many_caps() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin) = mmr::new(b"log".to_string(), ctx);
    64u64.do!(|_| destroy(mmr.mint_append_cap(&admin, ctx)));
    // the 65th
    let _cap = mmr.mint_append_cap(&admin, ctx);
    abort
}

#[test]
fun rotate_at_cap_limit_revoke_then_mint() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    63u64.do!(|_| destroy(mmr.mint_append_cap(&admin, ctx)));
    assert_eq!(mmr.append_cap_ids().length(), 64);
    // README rotation order at the limit: revoke first, then mint
    mmr.revoke_append_cap(&admin, object::id(&cap));
    let new_cap = mmr.mint_append_cap(&admin, ctx);
    assert_eq!(mmr.append_cap_ids().length(), 64);
    assert!(mmr.is_append_cap_active(object::id(&new_cap)));
    assert!(!mmr.is_append_cap_active(object::id(&cap)));
    mmr.append_leaves(&new_cap, vector[b"x"], ctx);
    assert_eq!(mmr.size(), 1);
    destroy(new_cap);
    teardown(mmr, admin, cap);
}

/// Burning an active cap at the limit frees its slot: the next mint succeeds without a revoke.
#[test]
fun destroy_at_cap_limit_frees_a_slot() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    let extra = vector::tabulate!(63, |_| mmr.mint_append_cap(&admin, ctx));
    assert_eq!(mmr.append_cap_ids().length(), 64);
    let cap_id = object::id(&cap);
    mmr.destroy_append_cap(cap);
    assert_eq!(mmr.append_cap_ids().length(), 63);
    let new_cap = mmr.mint_append_cap(&admin, ctx);
    assert_eq!(mmr.append_cap_ids().length(), 64);
    assert!(mmr.is_append_cap_active(object::id(&new_cap)));
    assert!(!mmr.is_append_cap_active(cap_id));
    extra.destroy!(|c| destroy(c));
    destroy(new_cap);
    destroy(mmr);
    destroy(admin);
}

// ------------------------------------------------------------------------------ seal

#[test, expected_failure(abort_code = mmr::ESealed)]
fun append_rejects_sealed() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.seal(&admin);
    assert!(mmr.is_sealed());
    let events = event::events_by_type<mmr::MMRSealedEvent>();
    assert_eq!(events.length(), 1);
    let (event_mmr_id, size, root) = mmr::sealed_event_fields_for_testing(&events[0]);
    assert_eq!(event_mmr_id, object::id(&mmr));
    assert_eq!(size, 23);
    assert_eq!(root, mmr.root());
    mmr.append_leaves(&cap, vector[b"y"], ctx);
    abort
}

#[test, expected_failure(abort_code = mmr::ESealed)]
fun mint_rejects_sealed() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, _cap) = setup(ctx);
    mmr.seal(&admin);
    let _cap2 = mmr.mint_append_cap(&admin, ctx);
    abort
}

#[test]
fun sealed_mmr_still_verifies() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.append_leaves(&cap, mmr_prover::leaves(13), ctx);
    mmr.seal(&admin);
    // sealing twice changes nothing and emits nothing: one event, for the transition
    mmr.seal(&admin);
    assert!(mmr.is_sealed());
    assert_eq!(event::events_by_type<mmr::MMRSealedEvent>().length(), 1);
    let ns = mmr_prover::build(13);
    assert_eq!(ns.root(), mmr.root());
    let (path, left, right) = ns.single_proof(16);
    assert!(mmr.verify(16, b"9", path, left, right));
    assert!(mmr.verify_at_anchor(23, 16, b"9", path, left, right));
    assert_eq!(mmr.anchor(23).size(), 23);
    assert_eq!(mmr.root_at(23), mmr.root());
    // an already minted cap can still be destroyed
    let cap_id = object::id(&cap);
    mmr.destroy_append_cap(cap);
    assert!(!mmr.is_append_cap_active(cap_id));
    destroy(mmr);
    destroy(admin);
}

// ------------------------------------------------------------------------------ versioning

#[test, expected_failure(abort_code = mmr::EWrongVersion)]
fun wrong_version_blocks_revoke_seal() {
    // revoke is version-gated (seal is covered by `wrong_version_blocks_seal`)
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.set_version_for_testing(0);
    mmr.revoke_append_cap(&admin, object::id(&cap));
    abort
}

#[test, expected_failure(abort_code = mmr::EWrongVersion)]
fun wrong_version_blocks_seal() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, _cap) = setup(ctx);
    mmr.set_version_for_testing(0);
    mmr.seal(&admin);
    abort
}

/// The version guard runs before the admin check (`assert_admin` order: `assert_version`, then
/// `EWrongMMR`): a foreign admin on an un-migrated object still fails with `EWrongVersion`.
#[test, expected_failure(abort_code = mmr::EWrongVersion)]
fun wrong_version_is_checked_before_admin_identity() {
    let ctx = &mut tx_context::dummy();
    let (mut a, _admin_a, _cap_a) = setup(ctx);
    let (_b, admin_b, _cap_b) = setup(ctx);
    a.set_version_for_testing(0);
    a.seal(&admin_b);
    abort
}

#[test]
fun destroy_append_cap_works_on_old_version() {
    let ctx = &mut tx_context::dummy();
    let (mut mmr, admin, cap) = setup(ctx);
    mmr.set_version_for_testing(0);
    let cap_id = object::id(&cap);
    mmr.destroy_append_cap(cap);
    assert!(!mmr.is_append_cap_active(cap_id));
    let (_, event_cap_id, destroyed) = only_revoked_event();
    assert_eq!(event_cap_id, cap_id);
    assert!(destroyed);
    destroy(mmr);
    destroy(admin);
}

// ------------------------------------------------------------------------------ shared flow

#[test]
fun shared_flow_second_sender_verifies() {
    let alice = @0xA11CE;
    let bob = @0xB0B;
    let mut scenario = test_scenario::begin(alice);
    // Alice creates and shares her log
    mmr::create(b"alice".to_string(), scenario.ctx());
    scenario.next_tx(alice);
    let mut alice_mmr = scenario.take_shared<MMR>();
    let alice_admin = scenario.take_from_sender<AdminCap>();
    let alice_cap = alice_mmr.mint_append_cap(&alice_admin, scenario.ctx());
    alice_mmr.append_leaves(&alice_cap, mmr_prover::leaves(13), scenario.ctx());
    let alice_mmr_id = object::id(&alice_mmr);
    test_scenario::return_shared(alice_mmr);
    scenario.return_to_sender(alice_admin);
    transfer::public_transfer(alice_cap, alice);
    // Bob reads the shared object and verifies without any capability
    scenario.next_tx(bob);
    let alice_mmr = scenario.take_shared_by_id<MMR>(alice_mmr_id);
    let ns = mmr_prover::build(13);
    assert_eq!(ns.root(), alice_mmr.root());
    let (path, left, right) = ns.single_proof(16);
    assert!(alice_mmr.verify(16, b"9", path, left, right));
    assert!(!alice_mmr.verify(16, b"8", path, left, right));
    assert!(alice_mmr.verify_at_anchor(23, 16, b"9", path, left, right));
    // Bob owns no cap of Alice's log (her cap is owned by Alice)
    assert!(!test_scenario::has_most_recent_for_sender<AppendCap>(&scenario));
    test_scenario::return_shared(alice_mmr);
    // Bob creates his own log with his own cap
    mmr::create(b"bob".to_string(), scenario.ctx());
    scenario.next_tx(bob);
    let mut bob_mmr = scenario.take_shared_by_id<MMR>(
        test_scenario::most_recent_id_shared<MMR>().destroy_some(),
    );
    assert!(object::id(&bob_mmr) != alice_mmr_id);
    let bob_admin = scenario.take_from_sender<AdminCap>();
    let bob_cap = bob_mmr.mint_append_cap(&bob_admin, scenario.ctx());
    bob_mmr.append_leaves(&bob_cap, vector[b"bob-1"], scenario.ctx());
    assert_eq!(bob_mmr.size(), 1);
    // Bob's cap is not active on Alice's log (cross-use aborts: append_rejects_cap_of_another_mmr)
    let alice_mmr = scenario.take_shared_by_id<MMR>(alice_mmr_id);
    assert!(!alice_mmr.is_append_cap_active(object::id(&bob_cap)));
    test_scenario::return_shared(alice_mmr);
    test_scenario::return_shared(bob_mmr);
    scenario.return_to_sender(bob_admin);
    transfer::public_transfer(bob_cap, bob);
    scenario.end();
}
