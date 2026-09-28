/// Shared object fixtures for the test modules.
#[test_only]
module mmr::mmr_test_fixtures;

use std::unit_test::destroy;
use mmr::mmr::{Self, MMR, AdminCap, AppendCap};

/// One MMR with its AdminCap and one active AppendCap. All objects of a test must come from the
/// same `TxContext`: `tx_context::dummy()` restarts the id counter, so two dummies collide.
public fun setup(ctx: &mut TxContext): (MMR, AdminCap, AppendCap) {
    let (mut mmr, admin) = mmr::new(b"log".to_string(), ctx);
    let cap = mmr.mint_append_cap(&admin, ctx);
    (mmr, admin, cap)
}

/// Consume the three fixture objects.
public fun teardown(mmr: MMR, admin: AdminCap, cap: AppendCap) {
    destroy(mmr);
    destroy(admin);
    destroy(cap);
}
