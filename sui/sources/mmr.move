/// Merkle Mountain Range as a shared, capability-gated, append-only accumulator.
///
/// The object stores only the current peaks, root, size and leaf count (O(log n)) plus one
/// checkpoint `(size -> root, peaks, ...)` per append batch. Proof generation happens off-chain
/// from the `LeavesAppendedEvent` stream (or any node set rebuilt from it); verification happens
/// on-chain against the object's current root or against a recorded checkpoint.
///
/// Writes need an `AppendCap` minted for this MMR by its `AdminCap`; reads and verification are
/// permissionless and never version-gated. Every MMR is a shared object.
module mmr::mmr;

use std::string::String;
use sui::event;
use sui::table::{Self, Table};
use sui::vec_set::{Self, VecSet};
use mmr::mmr_proof;
use mmr::mmr_utils;

/// Method aliases (documented idiom: prefixed function + public alias).
public use fun admin_cap_mmr_id as AdminCap.mmr_id;
public use fun append_cap_mmr_id as AppendCap.mmr_id;
public use fun checkpoint_size as Checkpoint.size;
public use fun checkpoint_leaf_count as Checkpoint.leaf_count;
public use fun checkpoint_root as Checkpoint.root;
public use fun checkpoint_peaks as Checkpoint.peaks;
public use fun checkpoint_batch_index as Checkpoint.batch_index;
public use fun checkpoint_epoch as Checkpoint.epoch;
public use fun checkpoint_cap_id as Checkpoint.cap_id;

/// Package version stamped into every MMR; bump together with `migrate`.
const VERSION: u64 = 1;
/// Upper bound on active AppendCaps per MMR.
const MAX_APPEND_CAPS: u64 = 64;
/// Upper bound on `label` in bytes (`String::length()` counts bytes).
const MAX_LABEL_LENGTH: u64 = 128;

/// A capability was issued for a different MMR.
#[error]
const EWrongMMR: vector<u8> = b"Capability was not issued for this MMR";
/// AppendCap id is not in the MMR's active set (revoked or never registered).
#[error]
const ECapNotActive: vector<u8> = b"AppendCap is not active for this MMR";
/// The MMR is sealed; no more appends and no new AppendCaps.
#[error]
const ESealed: vector<u8> = b"MMR is sealed";
/// `MAX_APPEND_CAPS` AppendCaps are already active.
#[error]
const ETooManyAppendCaps: vector<u8> = b"Too many active AppendCaps";
/// `label` exceeds `MAX_LABEL_LENGTH` bytes.
#[error]
const ELabelTooLong: vector<u8> = b"Label must be at most 128 bytes";
/// `append_leaves` called with no leaves.
#[error]
const EEmptyBatch: vector<u8> = b"Batch must contain at least one leaf";
/// No append batch ended exactly at that size.
#[error]
const ENoCheckpoint: vector<u8> = b"No checkpoint recorded at this size";
/// Object version does not match the package version; run `migrate`.
#[error]
const EWrongVersion: vector<u8> = b"MMR version does not match the package version";
/// `migrate` called on an object already at the package version.
#[error]
const ENotUpgrade: vector<u8> = b"MMR is already at the package version";
/// `assert_included` received `false`.
#[error]
const ENotIncluded: vector<u8> = b"Inclusion proof failed";

// ------------------------------------------------------------------------------ objects

/// The accumulator. Always a shared object (no `store`: the only storage path is `share`).
/// State is O(log n): peaks, root, counters, plus one dynamic-field checkpoint per append batch.
///
/// Invariants (hold after every public call):
///   peaks == hashes of the nodes at get_peaks_positions(size), left to right (<= 63 entries)
///   root  == H(size, peaks); H("0") when size == 0
///   for the current size > 0: checkpoints[size].root == root and checkpoints[size].peaks == peaks
///   every key of `checkpoints` is a valid MMR size; keys strictly increase in insertion order;
///   rows are never modified or removed
///   append_caps.length() <= MAX_APPEND_CAPS
public struct MMR has key {
    id: UID,
    /// Layout/semantics version. Checked by every write; never by reads or verifiers.
    version: u64,
    /// Operator-chosen name (<= MAX_LABEL_LENGTH bytes). Identity for indexers and explorers.
    label: String,
    /// Node count.
    size: u64,
    /// Number of appended leaves. Leaf index i (0-based) sits at leaf_index_to_position(i).
    leaf_count: u64,
    /// Peak hashes, left to right.
    peaks: vector<vector<u8>>,
    /// H(size || peaks); H("0") when empty.
    root: vector<u8>,
    /// One row per non-empty append batch, keyed by the size right after the batch.
    checkpoints: Table<u64, Checkpoint>,
    /// Ids of the AppendCaps that may currently append.
    append_caps: VecSet<ID>,
    /// True once `seal` was called; no further appends are accepted.
    sealed: bool,
}

/// Historical anchor written after one append batch. Never modified or removed.
public struct Checkpoint has copy, drop, store {
    /// Node count at this checkpoint (also the table key; kept so a returned copy is self-describing).
    size: u64,
    /// Leaf count at this checkpoint.
    leaf_count: u64,
    /// H(size || peaks) at this checkpoint.
    root: vector<u8>,
    /// Peak hashes at this checkpoint, left to right.
    peaks: vector<vector<u8>>,
    /// 0-based index of the append batch that wrote this checkpoint (== checkpoints written before it).
    batch_index: u64,
    /// Sui epoch (`ctx.epoch()`) of the append transaction.
    epoch: u64,
    /// The AppendCap that wrote this batch. On-chain writer attribution: after a writer-key
    /// compromise, dispute logic in Move can tell which batches the revoked cap wrote.
    cap_id: ID,
}

/// Administrative capability of one MMR: mints and revokes AppendCaps, seals, migrates.
/// Exactly one is minted, by `new`. Hold it in multisig custody.
public struct AdminCap has key, store { id: UID, mmr_id: ID }

/// Write capability of one MMR. Valid only while its id is in the MMR's `append_caps` set.
public struct AppendCap has key, store { id: UID, mmr_id: ID }

// ------------------------------------------------------------------------------ events

/// A new MMR was created. It is shared in the same transaction.
public struct MMRCreatedEvent has copy, drop {
    mmr_id: ID,
    label: String,
    admin_cap_id: ID,
}

/// One append batch was committed and one checkpoint recorded.
public struct LeavesAppendedEvent has copy, drop {
    mmr_id: ID,
    /// The AppendCap that appended (writer audit trail).
    cap_id: ID,
    /// 0-based index of this batch (== Checkpoint.batch_index == checkpoint key order).
    batch_index: u64,
    /// 0-based leaf index of the first leaf of this batch.
    first_leaf_index: u64,
    /// Number of leaves in this batch.
    batch_leaf_count: u64,
    /// Total leaf count after this batch.
    leaf_count: u64,
    /// Node count before and after this batch. `new_size` is the checkpoint key.
    old_size: u64,
    new_size: u64,
    /// Position-bound leaf hashes H(position || data), in append order. An indexer rebuilds every
    /// internal node from these alone; raw leaves stay in the transaction inputs.
    leaf_hashes: vector<vector<u8>>,
    /// Peaks and root after this batch (the checkpoint contents).
    peaks: vector<vector<u8>>,
    root: vector<u8>,
    /// Sui epoch of the append transaction.
    epoch: u64,
}

/// An AppendCap was minted and activated.
public struct AppendCapMintedEvent has copy, drop { mmr_id: ID, cap_id: ID }

/// An AppendCap was deactivated. `destroyed` is true when the holder burned it
/// (`destroy_append_cap`), false when the admin revoked it (`revoke_append_cap`).
public struct AppendCapRevokedEvent has copy, drop { mmr_id: ID, cap_id: ID, destroyed: bool }

/// The MMR was sealed at `size` with `root`.
public struct MMRSealedEvent has copy, drop { mmr_id: ID, size: u64, root: vector<u8> }

// ------------------------------------------------------------------------------ creation and sharing

/// Create an empty MMR (root = H("0")) and its AdminCap. Emits `MMRCreatedEvent`.
/// The MMR has no `store` and no `drop`: pass it to `share` in the same transaction.
/// Aborts with `ELabelTooLong` when `label` exceeds MAX_LABEL_LENGTH bytes.
public fun new(label: String, ctx: &mut TxContext): (MMR, AdminCap) {
    assert!(label.length() <= MAX_LABEL_LENGTH, ELabelTooLong);
    let mmr = MMR {
        id: object::new(ctx),
        version: VERSION,
        label,
        size: 0,
        leaf_count: 0,
        peaks: vector[],
        root: mmr_utils::hash_with_integer(0, vector[]),
        checkpoints: table::new(ctx),
        append_caps: vec_set::empty(),
        sealed: false,
    };
    let admin_cap = AdminCap { id: object::new(ctx), mmr_id: mmr.id.to_inner() };
    event::emit(MMRCreatedEvent {
        mmr_id: mmr.id.to_inner(),
        label: mmr.label,
        admin_cap_id: admin_cap.id.to_inner(),
    });
    (mmr, admin_cap)
}

/// Share the MMR. This is the only storage path: every MMR is a shared object.
/// Only an object created in the same transaction can be shared: the call aborts at runtime
/// (`sui::transfer::ESharedNonNewObject`) when `mmr` was already shared or persisted, with no
/// state change. There is no owned mode and no un-share path for an MMR: a shared object can be
/// taken by value only by a function that deletes it, and this module has none.
public fun share(mmr: MMR) {
    transfer::share_object(mmr);
}

/// Wallet/CLI convenience: `new` + `share`, and the AdminCap goes to the sender.
/// No AppendCap is minted here; mint one with `mint_append_cap` (admin and writer roles stay
/// separate). Composable callers use `new` + `share` directly.
entry fun create(label: String, ctx: &mut TxContext) {
    let (mmr, admin_cap) = new(label, ctx);
    share(mmr);
    transfer::transfer(admin_cap, ctx.sender());
}

// ------------------------------------------------------------------------------ capability management

/// Mint an AppendCap for `mmr` and activate it. Admin only. Emits `AppendCapMintedEvent`.
/// Aborts with `ESealed` on a sealed MMR (such a cap could never append) and with
/// `ETooManyAppendCaps` when MAX_APPEND_CAPS caps are already active. When rotating at the
/// limit, revoke first, then mint.
public fun mint_append_cap(mmr: &mut MMR, admin: &AdminCap, ctx: &mut TxContext): AppendCap {
    mmr.assert_admin(admin);
    assert!(!mmr.sealed, ESealed);
    assert!(mmr.append_caps.length() < MAX_APPEND_CAPS, ETooManyAppendCaps);
    let cap = AppendCap { id: object::new(ctx), mmr_id: mmr.id.to_inner() };
    mmr.append_caps.insert(cap.id.to_inner());
    event::emit(AppendCapMintedEvent { mmr_id: mmr.id.to_inner(), cap_id: cap.id.to_inner() });
    cap
}

/// Deactivate the AppendCap with id `cap_id`. Admin only; the cap object itself is not needed,
/// so a leaked cap is dead from this transaction on without the holder's cooperation.
/// Emits `AppendCapRevokedEvent { destroyed: false }`. Aborts with `ECapNotActive` if `cap_id`
/// is not active.
public fun revoke_append_cap(mmr: &mut MMR, admin: &AdminCap, cap_id: ID) {
    mmr.assert_admin(admin);
    assert!(mmr.append_caps.contains(&cap_id), ECapNotActive);
    mmr.append_caps.remove(&cap_id);
    event::emit(AppendCapRevokedEvent { mmr_id: mmr.id.to_inner(), cap_id, destroyed: false });
}

/// Burn an AppendCap. Holder only (by possession). Deactivates it if it is still active and then
/// emits `AppendCapRevokedEvent { destroyed: true }`; burning an already revoked cap is silent.
/// Aborts with `EWrongMMR` if the cap belongs to another MMR. Not version-gated: burning only
/// removes rights, so a holder can burn a cap while the object is un-migrated.
public fun destroy_append_cap(mmr: &mut MMR, cap: AppendCap) {
    let AppendCap { id, mmr_id } = cap;
    assert!(mmr_id == mmr.id.to_inner(), EWrongMMR);
    let cap_id = id.to_inner();
    if (mmr.append_caps.contains(&cap_id)) {
        mmr.append_caps.remove(&cap_id);
        event::emit(AppendCapRevokedEvent { mmr_id, cap_id, destroyed: true });
    };
    id.delete();
}

/// Permanently stop appends. Reads and verification keep working. Admin only.
/// Emits `MMRSealedEvent`. Idempotent (sealing twice emits twice and changes nothing).
public fun seal(mmr: &mut MMR, admin: &AdminCap) {
    mmr.assert_admin(admin);
    mmr.sealed = true;
    event::emit(MMRSealedEvent { mmr_id: mmr.id.to_inner(), size: mmr.size, root: mmr.root });
}

/// Bring an MMR created by an older package version up to `VERSION`. Admin only.
/// `entry` (not `public`) so its signature may change in a later upgrade.
/// Aborts with `EWrongMMR` for a foreign admin cap and `ENotUpgrade` when the object is
/// already at (or above) `VERSION`. Like `destroy_append_cap`, it has no version guard.
entry fun migrate(mmr: &mut MMR, admin: &AdminCap) {
    assert!(admin.mmr_id == mmr.id.to_inner(), EWrongMMR);
    assert!(mmr.version < VERSION, ENotUpgrade);
    mmr.version = VERSION;
}

/// The MMR an AdminCap was issued for (method alias `admin.mmr_id()`).
public fun admin_cap_mmr_id(cap: &AdminCap): ID { cap.mmr_id }

/// The MMR an AppendCap was issued for (method alias `cap.mmr_id()`).
public fun append_cap_mmr_id(cap: &AppendCap): ID { cap.mmr_id }

// ------------------------------------------------------------------------------ append

/// Append `leaves` in order. Records one checkpoint keyed by the new size and emits one
/// `LeavesAppendedEvent`. Returns the 0-based leaf index of the first appended leaf (Move
/// callers learn the indices their records got; PTB callers may ignore it).
/// Requires an active AppendCap of this MMR. Aborts with `EWrongVersion`, `EWrongMMR`,
/// `ECapNotActive`, `ESealed`, or `EEmptyBatch`.
/// Hashing: leaf = H(position, [data]); node = H(position, [left, right]);
/// root = H(size, peaks) computed once per batch.
public fun append_leaves(
    mmr: &mut MMR,
    cap: &AppendCap,
    leaves: vector<vector<u8>>,
    ctx: &mut TxContext,
): u64 {
    mmr.assert_append_cap(cap);
    assert!(!leaves.is_empty(), EEmptyBatch);
    let old_size = mmr.size;
    let first_leaf_index = mmr.leaf_count;
    // Bound BEFORE the consuming loop: reading `leaves.length()` afterwards would make the
    // compiler copy the whole batch.
    let batch_leaf_count = leaves.length();
    let cap_id = cap.id.to_inner();
    let mut leaf_hashes = vector[];
    leaves.do!(|leaf| leaf_hashes.push_back(mmr.append_leaf(leaf)));
    // Root once per batch: intermediate roots are never observable.
    mmr.root = mmr_utils::hash_with_integer(mmr.size, mmr.peaks);
    let batch_index = mmr.checkpoints.length();
    let epoch = ctx.epoch();
    mmr.checkpoints.add(mmr.size, Checkpoint {
        size: mmr.size,
        leaf_count: mmr.leaf_count,
        root: mmr.root,
        peaks: mmr.peaks,
        batch_index,
        epoch,
        cap_id,
    });
    event::emit(LeavesAppendedEvent {
        mmr_id: mmr.id.to_inner(),
        cap_id,
        batch_index,
        first_leaf_index,
        batch_leaf_count,
        leaf_count: mmr.leaf_count,
        old_size,
        new_size: mmr.size,
        leaf_hashes,
        peaks: mmr.peaks,
        root: mmr.root,
        epoch,
    });
    first_leaf_index
}

/// Peaks-stack append of one leaf. Returns the position-bound leaf hash.
/// Does NOT update `root`; `append_leaves` hashes the root once after the batch.
/// While the node being placed is a right sibling, its left sibling is always the last peak,
/// so `peaks.pop_back()` yields it (equivalent to the v1 node-vector append).
fun append_leaf(mmr: &mut MMR, leaf: vector<u8>): vector<u8> {
    let mut position = mmr.size + 1;
    let leaf_hash = mmr_utils::hash_with_integer(position, vector[leaf]);
    let mut node_hash = leaf_hash;
    while (mmr_utils::is_right_sibling(position)) {
        let left = mmr.peaks.pop_back();
        position = position + 1;
        node_hash = mmr_utils::hash_with_integer(position, vector[left, node_hash]);
    };
    mmr.peaks.push_back(node_hash);
    mmr.size = position;
    mmr.leaf_count = mmr.leaf_count + 1;
    leaf_hash
}

// ------------------------------------------------------------------------------ verify

/// Verify an inclusion proof of `leaf` at `position` against the CURRENT root and size.
/// `path`: sibling hashes from the leaf up to its local peak, bottom-up. `left_peaks` /
/// `right_peaks`: hashes of the peaks left / right of the local peak, left to right.
/// Malformed proofs abort with `mmr_proof::E*` (see that module); a well-formed proof that does
/// not match returns false. Not version-gated: works on any MMR forever.
public fun verify(
    mmr: &MMR,
    position: u64,
    leaf: vector<u8>,
    path: vector<vector<u8>>,
    left_peaks: vector<vector<u8>>,
    right_peaks: vector<vector<u8>>,
): bool {
    mmr_proof::compute_root_trusted_size(
        mmr.size, position, leaf, path, left_peaks, right_peaks,
    ) == mmr.root
}

/// Same as `verify`, against the checkpoint recorded when the MMR had `size` nodes. All position
/// math uses `size`; the stored root is the only comparison target. Aborts with `ENoCheckpoint`
/// when no batch ended exactly at `size`. A proof issued at checkpoint `size` verifies here
/// forever, regardless of later appends. Not version-gated.
public fun verify_at_checkpoint(
    mmr: &MMR,
    size: u64,
    position: u64,
    leaf: vector<u8>,
    path: vector<vector<u8>>,
    left_peaks: vector<vector<u8>>,
    right_peaks: vector<vector<u8>>,
): bool {
    let root = mmr.root_at(size);
    mmr_proof::compute_root_trusted_size(size, position, leaf, path, left_peaks, right_peaks) == root
}

/// Verify a batch inclusion proof against the CURRENT root and size. Proof format and
/// consumption order: see `mmr_proof::verify_multiple_with_root`. Not version-gated.
public fun verify_multiple(
    mmr: &MMR,
    positions: vector<u64>,
    leaves: vector<vector<u8>>,
    siblings: vector<vector<u8>>,
    untouched_peaks: vector<vector<u8>>,
): bool {
    mmr_proof::compute_batch_root_trusted_size(
        mmr.size, positions, leaves, siblings, untouched_peaks,
    ) == mmr.root
}

/// Verify a batch inclusion proof against the checkpoint recorded at `size`.
/// Aborts with `ENoCheckpoint` when no batch ended exactly at `size`. Not version-gated.
public fun verify_multiple_at_checkpoint(
    mmr: &MMR,
    size: u64,
    positions: vector<u64>,
    leaves: vector<vector<u8>>,
    siblings: vector<vector<u8>>,
    untouched_peaks: vector<vector<u8>>,
): bool {
    let root = mmr.root_at(size);
    mmr_proof::compute_batch_root_trusted_size(size, positions, leaves, siblings, untouched_peaks) == root
}

/// PTB helper: abort with `ENotIncluded` when `verified` is false. Chain the bool result of any
/// verifier into it so a PTB reverts atomically on a failed proof.
/// This protects only the party that BUILDS the PTB: a Move contract cannot observe an earlier
/// PTB command, and any PTB can pass a pure `true` here. A contract that needs inclusion as a
/// precondition must call `verify*` itself on the pinned `&MMR` and never accept a `bool` from
/// its caller as evidence.
public fun assert_included(verified: bool) {
    assert!(verified, ENotIncluded);
}

// ------------------------------------------------------------------------------ getters

/// Current root.
public fun root(mmr: &MMR): vector<u8> { mmr.root }

/// Current node count.
public fun size(mmr: &MMR): u64 { mmr.size }

/// Current leaf count.
public fun leaf_count(mmr: &MMR): u64 { mmr.leaf_count }

/// Current peak hashes, left to right.
public fun peaks(mmr: &MMR): vector<vector<u8>> { mmr.peaks }

/// Operator-chosen label.
public fun label(mmr: &MMR): String { mmr.label }

/// Object version.
public fun version(mmr: &MMR): u64 { mmr.version }

/// True once `seal` was called.
public fun is_sealed(mmr: &MMR): bool { mmr.sealed }

/// Number of recorded checkpoints (== number of append batches).
public fun checkpoint_count(mmr: &MMR): u64 { mmr.checkpoints.length() }

/// True when a batch ended exactly at `size`.
public fun has_checkpoint(mmr: &MMR, size: u64): bool { mmr.checkpoints.contains(size) }

/// The checkpoint recorded at `size`, by value. Aborts with `ENoCheckpoint` if there is none.
public fun checkpoint(mmr: &MMR, size: u64): Checkpoint {
    assert!(mmr.checkpoints.contains(size), ENoCheckpoint);
    *mmr.checkpoints.borrow(size)
}

/// The root recorded at `size`. Aborts with `ENoCheckpoint` if there is none.
/// One `table::borrow`; only the 32-byte root is copied, never the whole row.
public fun root_at(mmr: &MMR, size: u64): vector<u8> {
    assert!(mmr.checkpoints.contains(size), ENoCheckpoint);
    mmr.checkpoints.borrow(size).root
}

/// Ids of the currently active AppendCaps.
public fun append_cap_ids(mmr: &MMR): vector<ID> { *mmr.append_caps.keys() }

/// True when `cap_id` may append to this MMR.
public fun is_append_cap_active(mmr: &MMR, cap_id: ID): bool { mmr.append_caps.contains(&cap_id) }

/// Node count at the checkpoint (alias `cp.size()`).
public fun checkpoint_size(cp: &Checkpoint): u64 { cp.size }

/// Leaf count at the checkpoint (alias `cp.leaf_count()`).
public fun checkpoint_leaf_count(cp: &Checkpoint): u64 { cp.leaf_count }

/// Root at the checkpoint (alias `cp.root()`).
public fun checkpoint_root(cp: &Checkpoint): vector<u8> { cp.root }

/// Peak hashes at the checkpoint, left to right (alias `cp.peaks()`).
public fun checkpoint_peaks(cp: &Checkpoint): vector<vector<u8>> { cp.peaks }

/// 0-based index of the append batch that wrote the checkpoint (alias `cp.batch_index()`).
public fun checkpoint_batch_index(cp: &Checkpoint): u64 { cp.batch_index }

/// Sui epoch of the append batch (alias `cp.epoch()`).
public fun checkpoint_epoch(cp: &Checkpoint): u64 { cp.epoch }

/// Id of the AppendCap that wrote the batch (alias `cp.cap_id()`).
public fun checkpoint_cap_id(cp: &Checkpoint): ID { cp.cap_id }

// ------------------------------------------------------------------------------ private

/// `EWrongVersion` unless the object is at the package version. Not called by
/// `destroy_append_cap`.
fun assert_version(mmr: &MMR) {
    assert!(mmr.version == VERSION, EWrongVersion);
}

/// `assert_version` + `EWrongMMR`.
fun assert_admin(mmr: &MMR, admin: &AdminCap) {
    mmr.assert_version();
    assert!(admin.mmr_id == mmr.id.to_inner(), EWrongMMR);
}

/// `assert_version` + `EWrongMMR` + `ECapNotActive` + `ESealed`.
fun assert_append_cap(mmr: &MMR, cap: &AppendCap) {
    mmr.assert_version();
    assert!(cap.mmr_id == mmr.id.to_inner(), EWrongMMR);
    assert!(mmr.append_caps.contains(&cap.id.to_inner()), ECapNotActive);
    assert!(!mmr.sealed, ESealed);
}

// ------------------------------------------------------------------------------ test only

/// Force an old version number so `migrate` and the version guard can be tested.
#[test_only]
public fun set_version_for_testing(mmr: &mut MMR, version: u64) {
    mmr.version = version;
}

/// Destructure an `MMRCreatedEvent` read back with `sui::event::events_by_type`.
#[test_only]
public fun created_event_fields_for_testing(e: &MMRCreatedEvent): (ID, String, ID) {
    (e.mmr_id, e.label, e.admin_cap_id)
}

/// Destructure a `LeavesAppendedEvent`: (mmr_id, cap_id, batch_index, first_leaf_index,
/// batch_leaf_count, leaf_count, old_size, new_size, leaf_hashes, peaks, root, epoch).
#[test_only]
public fun leaves_appended_event_fields_for_testing(
    e: &LeavesAppendedEvent,
): (ID, ID, u64, u64, u64, u64, u64, u64, vector<vector<u8>>, vector<vector<u8>>, vector<u8>, u64) {
    (
        e.mmr_id, e.cap_id, e.batch_index, e.first_leaf_index, e.batch_leaf_count, e.leaf_count,
        e.old_size, e.new_size, e.leaf_hashes, e.peaks, e.root, e.epoch,
    )
}

/// Destructure an `AppendCapRevokedEvent`: (mmr_id, cap_id, destroyed).
#[test_only]
public fun cap_revoked_event_fields_for_testing(e: &AppendCapRevokedEvent): (ID, ID, bool) {
    (e.mmr_id, e.cap_id, e.destroyed)
}

/// Destructure an `AppendCapMintedEvent`: (mmr_id, cap_id).
#[test_only]
public fun cap_minted_event_fields_for_testing(e: &AppendCapMintedEvent): (ID, ID) {
    (e.mmr_id, e.cap_id)
}

/// Destructure an `MMRSealedEvent`: (mmr_id, size, root).
#[test_only]
public fun sealed_event_fields_for_testing(e: &MMRSealedEvent): (ID, u64, vector<u8>) {
    (e.mmr_id, e.size, e.root)
}
