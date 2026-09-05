# Merkle Mountain Range

## Introduction

A Merkle Mountain Range (MMR) is a data structure that extends the concept of a Merkle tree to allow for efficient appending of new elements and efficient proof generation. MMRs are particularly useful in scenarios where on-chain data updates are necessary.

### Properties and Applications

1. **Append-Only**: Efficiently supports adding new elements
2. **Compact Proofs**: Proof size is logarithmic in the number of elements
3. **Verification Efficiency**: Proofs can be verified quickly
4. **No Rebalancing**: Unlike traditional Merkle trees, MMRs don't require rebalancing

## Basic Structure and Formation

In an MMR, nodes are arranged in a series of perfect binary trees (mountains) of decreasing height from left to right.
When a piece of data is to be added to the MMR it gets hashed creating a node that, using 1-based numbering and starting from the left, is added to the MMR. Whenever a left node gains a sibling, a parent node is created by hashing both children together, following sequential numbering. If the newly created parent node already has a right sibling at the same level, another parent node will be created for them, and so on.

### Visualizing an MMR

Let's look at an MMR with 13 leaves (represented by positions 1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20 and 23):

```
                               15
                              /  \
                             /    \
                            /      \
                           7        14          22
                          / \      /  \        /  \
                         /   \    /    \      /    \
                        3     6  10     13   18     21
                       / \   / \ / \   / \   / \   / \
                      1   2 4  5 8  9 11 12 16 17 19 20 23

```

## Key concepts

Clarifying a few key terms is essential for understanding MMRs and avoiding confusion during implementation, which also improves code readability.

### Position

The number assigned to each node is called its position. This numbering will be 1-based rather than 0-based as it will be on other data structs.
While this may seem arbitrary, it is crucial for the mathematical properties of MMRs, enabling operations such as calculating a node's height.
It is important not to confuse this position with the order in which data was added to the MMR—sometimes referred to as the "leaf number" or "leaf index". Leaf index `i` (0-based) sits at position `2·i − popcount(i) + 1`; the package exposes `leaf_index_to_position` and `position_to_leaf_index` for the conversion.

### Height

Each node has an associated height depending on which level of the MMR they are placed.
In this implementation height is numbered 1-based as positions are.
Based on the height of a given node, we can differentiate node types.

#### Node Types

A node on the first level, height 1, will always be a **Leaf Node**.
These nodes contain the hash of the stored data along with the position of the leaf within the structure.
The top nodes of each perfect binary tree (mountain) will be **Peak Nodes**. In our previous example peaks will be nodes 15, 22 and 23.
Intermediate nodes do not require a specific term, as their height is only relevant for traversal calculations within the MMR.
Given a node position, its height can be calculated by iterating through the binary tree it is part of.

### Size

The total amount of nodes that form the MMR, including leaves and peaks, is referred as the MMR size.

### Root

The unique identifier of a MMR at a certain point of its life, obtained by hashing together all the peaks (also known as bagging peaks) preceded by its size.

## MMR Proofs

The minimum necessary set of information from the MMR needed for checking if a piece of data was included on it.
All these elements correspond to a specific point in the MMR's lifecycle, meaning that if a proof is generated for the same data at a later time, after more leaves have been added, the proof will differ.

- Position of the leaf where the data was included.
- Local tree path hashes.
- Left hand sided peaks.
- Right hand sided peaks.
- The MMR's root hash and size the proof was issued at (the *anchor*). On Sui the anchor is never part of the proof: the verifier reads it from the shared `MMR` object or from one of its checkpoints.

Taking our initial MMR example if we want to generate a proof for the node 16, we will send the verifier the following information:
```pseudocode
position     = 16
leaf         = "9"                  // the raw data at position 16
path         = [h(n17), h(n21)]     // sibling hashes from the leaf up to its local peak
left_peaks   = [h(n15)]             // peaks left of the local peak
right_peaks  = [h(n23)]             // peaks right of the local peak
anchor       = (root = h(23, h(n15), h(n22), h(n23)), size = 23)   // read from the object
```

Understanding the concept of local tree path hashes is crucial, as they are the key element in proof generation and verification.
When verifying a proof, we compute the MMR root hash using the proof's information and the data being verified as part of the MMR.
By hashing the data to be verified, we can use the **local tree path hashes** to compute all parent node hashes, ultimately deriving the local tree peak hash. Bagging that peak with the other peaks and the size gives a root that is compared with the trusted anchor.

## Package layout

- `mmr::mmr` — the shared `MMR` object, `AdminCap`, `AppendCap`, checkpoints, events, and the
  object-bound verifiers (`verify`, `verify_at_checkpoint`, `verify_multiple`,
  `verify_multiple_at_checkpoint`) plus `assert_included`.
- `mmr::mmr_proof` — pure verifiers over a caller-supplied `(root, size)`
  (`verify_with_root`, `verify_multiple_with_root`, `compute_root`, `compute_batch_root`). They
  trust their anchor; use them only with anchors you already trust.
- `mmr::mmr_utils`, `mmr::mmr_bits` — pure position math (`leaf_index_to_position`,
  `calc_proof_positions`, `get_peaks_positions`, `is_valid_size`, ...).
- `scripts/mmr_ref.py`, `scripts/golden.py` — the off-chain reference prover in Python (node set,
  peaks, root, single and batch proofs in the verifier's consumption order, verifier mirrors) and
  the generator of the golden vectors pinned in `tests/`. `python3 scripts/golden.py --check
  tests/mmr_proof_tests.move` fails when a pinned constant drifts.

## Hashing (normative for off-chain provers)

`H` = blake2b-256 (`digest_size = 32`, unkeyed, no salt or personalization). `enc(n)` = decimal
ASCII of a u64, no padding.

```
leaf(pos, data)   = H(enc(pos) || data)
node(pos, l, r)   = H(enc(pos) || l || r)
root(size, peaks) = H(enc(size) || P_1 || ... || P_k)     peaks left to right
empty root        = H("0")
```

Positions are 1-based post-order node positions (figure above). Leaf index `i` (0-based) sits at
position `2·i − popcount(i) + 1`; size after `L` leaves is `2·L − popcount(L)`. Known answer:
leaves `"1".."13"` → size 23, peaks [15, 22, 23], root
`737ff3b5d4244e05bc4248b78002040f3d9e37a55fcdea39a57d955cdb5e79d5`; empty root
`0fd923ca5e7218c4ba3c3801c26a617ecdbfdaebb9c76ce2eca166e7855efbb8`.

Caveats: the integer prefix is not length-framed (`leaf(1, "2" || X) == leaf(12, X)`) and leaf data
is not length-framed (`leaf(q, l || r) == node(q, l, r)`). Neither is exploitable against the
verifiers (all positions are verifier-derived, non-leaf positions are rejected, the root is never
re-hashed), but do not compare hashes across roles off-chain, and prefer leaves that are exactly
32-byte commitments. Sui and Aptos share this framing (Aptos needs the same peaks fix); the Flow
original uses SHA3-256 with 8-byte big-endian integers and its roots are not comparable. The v1
testnet packages (`0xfecf92…`, `0xbfea29…`) compute wrong roots for every non-perfect size and are
deprecated; v2 is a fresh publish.

## Objects and roles

- `MMR` — one shared object per log. Anyone reads and verifies. Never owned, never wrapped.
- `AdminCap` — one per MMR, minted by `new`. Mints and revokes `AppendCap`s, seals, migrates.
  Keep it in multisig custody.
- `AppendCap` — write capability. Only ids in the MMR's active set can append; the admin revokes
  by id without the holder's cooperation. Both caps have `store`, so they can live in multisig
  custody or inside a wrapper object; a wrapper must gate every function that hands out
  `&AppendCap`, because the MMR trusts possession of the reference.
- Every non-empty `append_leaves` writes one checkpoint `size → (root, peaks, leaf_count,
  batch_index, epoch, cap_id)` and emits one `LeavesAppendedEvent`. `cap_id` names the writer
  on-chain, so a Move contract can tell which batches a later-revoked cap wrote.
- Store `(mmr_id, checkpoint size, leaf index)` next to every record.

## CLI quickstart

```
# 1. create + share; the AdminCap goes to you
sui client ptb --move-call $PKG::mmr::create '"app-7/log-42"' --gas-budget 10000000
# 2. mint a writer cap and send it to the hot key
sui client ptb --move-call $PKG::mmr::mint_append_cap @$MMR @$ADMIN --assign cap \
  --transfer-objects [cap] @$WRITER --gas-budget 10000000
# 3. append (vector<vector<u8>> of leaves)
sui client ptb --move-call $PKG::mmr::append_leaves @$MMR @$CAP "vector[vector[1u8,2u8],vector[3u8]]" --gas-budget 10000000
```

## PTB flow (TypeScript, `@mysten/sui`)

```ts
import { Transaction } from '@mysten/sui/transactions';
import { bcs } from '@mysten/sui/bcs';
const Hashes = bcs.vector(bcs.vector(bcs.u8()));   // vector<vector<u8>>

// 1. composable create: new + share, caps to their custodians
const tx = new Transaction();
const [mmr, admin] = tx.moveCall({ target: `${PKG}::mmr::new`, arguments: [tx.pure.string('app-7/log-42')] });
const cap = tx.moveCall({ target: `${PKG}::mmr::mint_append_cap`, arguments: [mmr, admin] });
tx.moveCall({ target: `${PKG}::mmr::share`, arguments: [mmr] });
tx.transferObjects([admin], OPERATOR_MULTISIG);
tx.transferObjects([cap], WRITER_HOT_KEY);
// -> MMRCreatedEvent { mmr_id, label, admin_cap_id }, AppendCapMintedEvent { mmr_id, cap_id }

// 2. append a batch of salted 32-byte commitments (<= ~496 per call: 16 KB pure-argument limit)
const tx2 = new Transaction();
tx2.moveCall({
  target: `${PKG}::mmr::append_leaves`,
  arguments: [tx2.object(MMR_ID), tx2.object(CAP_ID), tx2.pure(Hashes.serialize(commitments))],
});
// -> LeavesAppendedEvent { mmr_id, cap_id, batch_index, first_leaf_index, batch_leaf_count,
//    leaf_count, old_size, new_size, leaf_hashes, peaks, root, epoch }
// Record new_size as the checkpoint of every record in this batch; record j of the batch has
// leaf_index = first_leaf_index + j and position = 2*leaf_index - popcount(leaf_index) + 1.

// 3. prove off-chain: rebuild the node set from leaf_hashes (replay: a leaf at position p merges
//    with the previous peak while p is a right sibling; see scripts/mmr_ref.py), then
//    single: path = siblings leaf -> local peak, bottom-up; left/right = other peaks at checkpoint size
//    batch:  siblings in (mountain, height, position) order; untouched_peaks left to right

// 4. verify on-chain against the checkpoint the record names; abort the PTB on failure
const tx3 = new Transaction();
const ok = tx3.moveCall({
  target: `${PKG}::mmr::verify_at_checkpoint`,
  arguments: [
    tx3.object(MMR_ID),                       // read-only shared object
    tx3.pure.u64(checkpointSize),
    tx3.pure.u64(position),
    tx3.pure.vector('u8', commitment),
    tx3.pure(Hashes.serialize(path)),
    tx3.pure(Hashes.serialize(leftPeaks)),
    tx3.pure(Hashes.serialize(rightPeaks)),
  ],
});
tx3.moveCall({ target: `${PKG}::mmr::assert_included`, arguments: [ok] });
// ... downstream commands follow; the whole PTB reverts with ENotIncluded on a failed proof.
// This atomicity protects the party that BUILDS the PTB. A Move contract cannot see this command
// and any builder can pass a pure `true` to assert_included: a contract that needs inclusion as a
// precondition calls mmr::verify* itself on the pinned &MMR (see "Rules for integrators").

// 5. several records in one call
const okAll = tx3.moveCall({
  target: `${PKG}::mmr::verify_multiple_at_checkpoint`,
  arguments: [tx3.object(MMR_ID), tx3.pure.u64(checkpointSize),
    tx3.pure.vector('u64', positions), tx3.pure(Hashes.serialize(leaves)),
    tx3.pure(Hashes.serialize(siblings)), tx3.pure(Hashes.serialize(untouchedPeaks))],
});
tx3.moveCall({ target: `${PKG}::mmr::assert_included`, arguments: [okAll] });

// 6. rotate the writer key (operator multisig): revoke old, mint new, one PTB, object id unchanged.
//    Revoke FIRST: with MAX_APPEND_CAPS (64) caps active, a mint-first order aborts with
//    ETooManyAppendCaps. The PTB is atomic, so the order leaves no write gap.
const tx4 = new Transaction();
tx4.moveCall({ target: `${PKG}::mmr::revoke_append_cap`, arguments: [tx4.object(MMR_ID), tx4.object(ADMIN_CAP_ID), tx4.pure.id(OLD_CAP_ID)] });
const newCap = tx4.moveCall({ target: `${PKG}::mmr::mint_append_cap`, arguments: [tx4.object(MMR_ID), tx4.object(ADMIN_CAP_ID)] });
tx4.transferObjects([newCap], NEW_HOT_KEY);
```

## Proof formats

Single: `position`, `leaf`, `path` (sibling hashes from the leaf up to its local peak, bottom-up),
`left_peaks`, `right_peaks` (peaks left / right of the local peak, left to right). README MMR,
position 16: `path = [n17, n21]`, `left = [n15]`, `right = [n23]`.

Batch: `positions` strictly increasing, `leaves` in the same order, `siblings` in consumption
order (mountain by mountain left to right; inside a mountain all height-1 siblings left to right,
then height-2, ...), `untouched_peaks` = peaks of mountains with no proven leaf, left to right.
Batch `{4, 9, 16}` on the README MMR: `siblings = [n5, n8, n3, n13, n17, n21]` (note `n3` after
`n8`), `untouched_peaks = [n23]`. A batch of one leaf is the single proof with `siblings = path`,
`untouched_peaks = left ++ right`.

## Results and errors

Every verifier returns `bool`. Malformed proofs abort with a named error from `mmr::mmr_proof`
(`EPositionOutOfRange`, `ENotALeaf`, `EPathLength`, `EPeaksCount`, `EHashLength`, `EEmptyBatch`,
`ELengthMismatch`, `EPositionsNotSorted`, `EMissingProofHashes`, `ELeftoverProofHashes`,
`EInvalidSize`, `EMalformedProof`); object and capability errors come from `mmr::mmr`
(`EWrongMMR`, `ECapNotActive`, `ESealed`, `ETooManyAppendCaps`, `ELabelTooLong`, `EEmptyBatch`,
`ENoCheckpoint`, `EWrongVersion`, `ENotUpgrade`, `ENotIncluded`). Two constants share the name
`EEmptyBatch`: `verify_multiple` / `verify_multiple_at_checkpoint` abort with
`mmr_proof::EEmptyBatch`; `append_leaves` aborts with `mmr::EEmptyBatch`. Treat an abort as "bad
client or bad proof shape" and `false` as "not included". Reads without a transaction: `devInspectTransactionBlock`
on `root`, `size`, `leaf_count`, `root_at(size)`, `checkpoint(size)`, or `getObject({ showContent: true })`
(checkpoints are dynamic fields of the `checkpoints` table keyed by `u64`).

## Rules for integrators

- Pin the MMR object id at setup and verify against that id and the size the proof was issued
  at. Proofs never carry the root. `label` is a display string only: anyone can create an MMR
  with the same label, and one operator can run several MMRs. Never select an MMR by label; a
  registry that advertises a log must publish the MMR object id as part of the log's
  identity.
- Move contracts must call `verify` / `verify_at_checkpoint` / `verify_multiple*` themselves on
  the pinned `&MMR`. Never accept a `bool` (or an `assert_included` result) from the transaction
  as evidence: `assert_included` is a convenience for the party that builds the PTB, and any PTB
  can pass a pure `true` into it.
- A wrapper object that hands out `&AppendCap` must gate every function that does so; the MMR
  trusts possession of the reference.
- Proofs are not nullifiers; keep a consumed set keyed by `(mmr_id, position)` for one-shot use.
- Batches from several caps interleave in consensus order; the chain does not enforce record
  sequence numbers. Each checkpoint row names its writer (`cap_id`); after a cap revocation,
  treat the records in that cap's batches as suspect.
- Every checkpoint locks ≈ 0.003–0.004 SUI of storage deposit forever; choose the anchoring cadence
  with that budget in mind.
- Verifiers are not version-gated: an un-migrated or sealed log verifies forever.
- Check the package's upgrade status before anchoring: an upgrade can change any function body,
  so append-only history is as strong as `UpgradeCap` custody until the package is made
  immutable. The operator keeps the `UpgradeCap` in multisig custody, publishes its upgrade
  policy, and calls `sui::package::make_immutable` once the extension (consistency) verifier ships; third
  parties check package immutability or the `UpgradeCap` owner.

## Gas and storage

Computation units are the Sui unit-test meter's relative numbers (`sui move test --build-env
testnet -s csv`, sui 1.69.2; `tests/gas_probe_tests.move`, each probe minus its setup / prover
baseline).

| Operation | Units | Notes |
|---|---|---|
| `new` + `mint_append_cap` | ≈ 7 | object + Table UID + 2 caps |
| `append_leaves`, 1 leaf on empty | ≈ 17 | |
| `append_leaves`, 100 leaves in one batch | ≈ 60 K | ≈ 0.6 K per leaf |
| `append_leaves`, 500 leaves in one batch | ≈ 0.94 M | root hashed once per batch |
| `append_leaves`, 1 leaf on 500 leaves | ≈ 4.9 K | one leaf hash, ≤ 1 merge, root over ≤ 9 peaks, checkpoint row, event |
| `append_leaves`, 10 leaves on 500 leaves | ≈ 28.6 K | ≈ 2.9 K per leaf |
| `verify` (object, 200 leaves, path 7, 3 peaks) | ≈ 15.1 K | ≈ 2 K per path level; > 300 verifies fit in one transaction |
| `verify_at_checkpoint` (200 leaves) | ≈ 15.2 K | one `Table::borrow` adds ≈ 0.1 K |
| `verify_with_root` (200 leaves) | ≈ 16.7 K | pure variant; includes the `is_valid_size` check |
| `verify_with_root` (1,000 leaves, path 9, 6 peaks) | ≈ 24.1 K | |
| `verify_multiple`, 10 leaves spaced 20 apart at 200 leaves | ≈ 71 K | vs ≈ 227 K for 10 single verifies (−69 %) |
| `verify_multiple`, 100 of 200 leaves | ≈ 299 K | 3.0 K per leaf vs 16.7 K single (−82 %) |
| `verify_multiple`, 10 leaves spaced 97 apart at 1,000 leaves | ≈ 109 K | vs ≈ 241 K singles (−55 %) |
| `mint` / `revoke` / `destroy_append_cap` / `seal` | < 300 | `VecSet` scan over ≤ 64 ids |

Complexity: append O(log n) per leaf (one leaf hash, amortised one merge, `get_height` loops of
≤ 64 steps) plus one root hash over ≤ 63 peaks per batch; verify O(log n) hashes; batch verify
O(k·log n) worst case, O(k + log n) when leaves are adjacent; checkpoint lookup O(1).

Storage (BCS bytes; a 32-byte hash costs 33 inside a `vector<vector<u8>>`; `p` = peaks ≤ 63,
`c` = active caps ≤ 64): the `MMR` object is ≈ 165 + |label| + 33·p + 32·c bytes (≈ 500 B
typical, < 5 KB worst case, independent of the leaf count); one `Checkpoint` dynamic field is
≈ 182 + 33·p bytes (≈ 480 B at 9 peaks), one per batch, never deleted; `AdminCap` and `AppendCap`
are 64 bytes each; a single proof on the wire is 8 + |leaf| + 33·(path + peaks − 1) bytes (≈ 337 B
at 200 leaves). At 7,600 MIST per byte, one ≈ 480 B checkpoint row costs ≈ 0.0036 SUI, locked for
the life of the object: hourly batches ≈ 32 SUI per year per log, one batch per minute
≈ 1,900 SUI per year.

Limits that shape the API: pure argument ≤ 16 KB (≈ 496 32-byte leaves per `append_leaves` or
`verify_multiple` call; join more with `vector::append` in the PTB or split calls); object
≤ 256 KB (never approached); ≤ 1,000 dynamic-field accesses per transaction (one per
`*_at_checkpoint` call); 1,024 events per transaction (one per append).

## Deploying

v2 is a fresh package, not an upgrade of v1: it removes public functions and changes the `MMR`
layout, which an upgrade forbids. Before `sui client publish --build-env testnet`, remove the v1
publish record: delete the `[env]` / `[env.testnet]` tables from `Move.lock` (or delete the lock
file and rebuild) and make sure no `Published.toml` exists. With the record present the CLI
attempts an upgrade of the v1 package and the compatibility checker rejects it. Commit the new
publish record after publishing and keep the `UpgradeCap` in multisig custody. The v1 testnet
packages `0xfecf92…` and `0xbfea29…` are deprecated (wrong roots for every non-perfect size).

Build and test: `cd sui && sui move test --build-env testnet` (sui ≥ 1.69). Coverage:
`sui move test --build-env testnet --coverage --trace && sui move coverage summary`
(`--trace` is optional; it writes `traces/` and `.coverage_map.mvcov`, both git-ignored).

## Acknowledgments

Make sure to check the [CONTRIBUTORS](./../CONTRIBUTORS.md) file for proper credit on this!
