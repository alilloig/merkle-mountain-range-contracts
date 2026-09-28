#!/usr/bin/env python3
"""Off-chain reference implementation of the Sui `mmr` package (v2).

This module is the prover shape an integrator needs off-chain: it rebuilds the full node set of
a Merkle Mountain Range from the raw leaves (or replays the `LeavesAppendedEvent.leaf_hashes`
stream), computes peaks and roots, and produces single and batch inclusion proofs in exactly the
shape the on-chain verifiers `mmr::mmr::verify*` / `mmr::mmr_proof::*` consume. It also carries
Python mirrors of both verifiers so a generator can be checked against its own output.

Hashing (normative, shared with `mmr_utils::hash_with_integer`):

    H                 = blake2b-256 (digest_size=32, unkeyed, no salt or personalization)
    enc(n)            = decimal ASCII of a u64, no padding
    leaf(pos, data)   = H(enc(pos) || data)
    node(pos, l, r)   = H(enc(pos) || l || r)
    root(size, peaks) = H(enc(size) || P_1 || ... || P_k)     peaks left to right
    empty root        = H("0")

Positions are 1-based post-order node positions; heights are 1-based (leaves have height 1).
Leaf index i (0-based) sits at position 2*i - popcount(i) + 1; an MMR of L leaves has
2*L - popcount(L) nodes.

Proof formats:

    single  (position, leaf, path, left_peaks, right_peaks)
            path        sibling hashes from the leaf up to its local peak, bottom-up
            left_peaks  hashes of the peaks left of the local peak, left to right
            right_peaks hashes of the peaks right of the local peak, left to right

    batch   (positions, leaves, siblings, untouched_peaks)
            positions   strictly increasing 1-based leaf positions
            leaves      raw leaf data, leaves[i] belongs to positions[i]
            siblings    sibling hashes the verifier cannot derive from the batch, in CONSUMPTION
                        order: mountain by mountain left to right; inside a mountain by
                        (height, position), i.e. all height-1 siblings left to right, then
                        height-2, and so on
            untouched   hashes of the peaks whose mountain holds no batch leaf, left to right

The position math below is a literal port of `mmr_bits.move` / `mmr_utils.move` so that every
position the verifier derives on-chain is derived the same way here.
"""
from __future__ import annotations

import hashlib
import itertools
import random
from dataclasses import dataclass, field
from typing import List, Sequence, Tuple

Hash = bytes

HASH_LENGTH = 32


class ProofError(ValueError):
    """A structurally malformed proof. The Move verifiers abort with a named error constant in
    these cases; the message names that constant."""


# ---------------------------------------------------------------------------------------------
# Hashing (== mmr_utils::hash_with_integer)
# ---------------------------------------------------------------------------------------------
def blake2b256(data: bytes) -> Hash:
    return hashlib.blake2b(data, digest_size=HASH_LENGTH).digest()


def enc(number: int) -> bytes:
    """Decimal ASCII of a u64, no padding (the integer prefix is not length-framed)."""
    return str(number).encode("ascii")


def hash_with_integer(number: int, parts: Sequence[bytes]) -> Hash:
    """H(enc(number) || parts[0] || parts[1] || ...). Used for leaves, nodes and the root."""
    return blake2b256(enc(number) + b"".join(parts))


def empty_root() -> Hash:
    return hash_with_integer(0, [])


# ---------------------------------------------------------------------------------------------
# Bit helpers (== mmr_bits)
# ---------------------------------------------------------------------------------------------
def get_length(num: int) -> int:
    """Minimum number of bits needed to represent `num` (0 for 0)."""
    return num.bit_length()


def count_ones(num: int) -> int:
    return bin(num).count("1")


def are_all_ones(num: int) -> bool:
    """True when `num` has the form 2^k - 1 (the size of a perfect binary tree)."""
    return (num & (num + 1)) == 0


def create_all_ones(bits_length: int) -> int:
    assert 0 <= bits_length < 64, "Bit length must be less than 64"
    return (1 << bits_length) - 1


# ---------------------------------------------------------------------------------------------
# Position math (== mmr_utils)
# ---------------------------------------------------------------------------------------------
def jump_left(position: int) -> int:
    """Same height, further left: drop the most significant bit and add one."""
    most_significant_bit = 1 << (get_length(position) - 1)
    return position - (most_significant_bit - 1)


def get_height(position: int) -> int:
    """1-based height of the node at `position`: jump left until an all-ones position."""
    assert position > 0, "First position of a MMR node is 1"
    left_most = position
    while not are_all_ones(left_most):
        left_most = jump_left(left_most)
    return get_length(left_most)


def sibling_offset(height: int) -> int:
    """Distance between two siblings at `height`: 2^height - 1."""
    return create_all_ones(height)


def is_right_sibling(position: int) -> bool:
    """A left sibling has a node of the same height one sibling offset to its right."""
    assert position > 0, "First position of a MMR node is 1"
    height = get_height(position)
    return get_height(position + sibling_offset(height)) != height


def get_sibling_position(position: int) -> int:
    offset = sibling_offset(get_height(position))
    return position - offset if is_right_sibling(position) else position + offset


def get_parent_position(position: int) -> int:
    """A right sibling's parent is the next position; a left sibling's parent is the position
    after its right sibling."""
    return position + 1 if is_right_sibling(position) else get_sibling_position(position) + 1


def get_peaks_positions(size: int) -> List[int]:
    """All peak positions of an MMR of `size` nodes, left to right. `size` must be valid."""
    peaks: List[int] = []
    if size == 0:
        return peaks
    if are_all_ones(size):
        return [size]
    largest_tree_height = get_length(size) - 1
    tree_size = create_all_ones(largest_tree_height)
    nodes_left = size
    peak_position = 0
    while tree_size != 0:
        if nodes_left >= tree_size:
            nodes_left -= tree_size
            peak_position += tree_size
            peaks.append(peak_position)
        tree_size >>= 1
    return peaks


def is_valid_size(size: int) -> bool:
    """True when the greedy decomposition into perfect trees of strictly decreasing height
    leaves no node over. 0 is valid (empty MMR)."""
    nodes_left = size
    height = min(get_length(size), 63)
    while height > 0:
        tree_size = create_all_ones(height)
        if nodes_left >= tree_size:
            nodes_left -= tree_size
        height -= 1
    return nodes_left == 0


def size_to_leaf_count(size: int) -> int:
    """Sum of 2^(height-1) over the peaks."""
    return sum(1 << (get_height(p) - 1) for p in get_peaks_positions(size))


def leaf_count_to_size(leaf_count: int) -> int:
    return 2 * leaf_count - count_ones(leaf_count)


def leaf_index_to_position(index: int) -> int:
    """Position of the leaf with 0-based leaf index `index`."""
    return 2 * index - count_ones(index) + 1


def position_to_leaf_index(position: int) -> int:
    """0-based leaf index of the leaf at `position`."""
    assert position > 0, "First position of a MMR node is 1"
    assert get_height(position) == 1, "Position is not a leaf node"
    return size_to_leaf_count(position - 1)


def calc_proof_tree_path_positions(position: int, size: int) -> List[int]:
    """Sibling positions on the path from `position` up to its local peak, bottom-up."""
    path: List[int] = []
    if position != size:
        current = position
        while current <= size:
            path.append(get_sibling_position(current))
            current = get_parent_position(current)
        path.pop()  # the loop always stores exactly one sibling beyond the peak
    return path


def calc_proof_positions(position: int, size: int) -> Tuple[List[int], List[int], List[int]]:
    """(path positions, left peak positions, right peak positions) for a single proof."""
    path = calc_proof_tree_path_positions(position, size)
    local_peak = get_parent_position(path[-1]) if path else position
    peaks = get_peaks_positions(size)
    return path, [p for p in peaks if p < local_peak], [p for p in peaks if p > local_peak]


# ---------------------------------------------------------------------------------------------
# The node set (off-chain prover state)
# ---------------------------------------------------------------------------------------------
@dataclass
class NodeSet:
    """Full node set: `nodes[position - 1]` is the hash of the node at `position`.

    `append` is the v1 node-vector append; the on-chain `mmr::append_leaf` runs the same loop
    with the left sibling popped from the peaks stack instead of read from the node vector.
    """

    nodes: List[Hash] = field(default_factory=list)

    # -- construction -------------------------------------------------------------------------
    @property
    def size(self) -> int:
        return len(self.nodes)

    @property
    def leaf_count(self) -> int:
        return size_to_leaf_count(self.size)

    def append(self, leaf: bytes) -> int:
        """Append one raw leaf; returns its 0-based leaf index."""
        index = self.leaf_count
        self.append_leaf_hash(hash_with_integer(self.size + 1, [leaf]))
        return index

    def append_leaf_hash(self, leaf_hash: Hash) -> None:
        """Append a position-bound leaf hash H(position || data), as carried by
        `LeavesAppendedEvent.leaf_hashes` (replay path for indexers)."""
        position = self.size + 1
        node_hash = leaf_hash
        self.nodes.append(node_hash)
        while is_right_sibling(position):
            left = self.node(get_sibling_position(position))
            position += 1
            node_hash = hash_with_integer(position, [left, node_hash])
            self.nodes.append(node_hash)

    def append_all(self, leaves: Sequence[bytes]) -> None:
        for leaf in leaves:
            self.append(leaf)

    # -- reads --------------------------------------------------------------------------------
    def node(self, position: int) -> Hash:
        return self.nodes[position - 1]

    def nodes_at(self, positions: Sequence[int]) -> List[Hash]:
        return [self.node(p) for p in positions]

    def peaks_positions(self) -> List[int]:
        return get_peaks_positions(self.size)

    def peaks(self) -> List[Hash]:
        return self.nodes_at(self.peaks_positions())

    def root(self) -> Hash:
        """H(size, peaks); H("0") when empty."""
        return hash_with_integer(self.size, self.peaks())

    def leaf_positions(self) -> List[int]:
        return [leaf_index_to_position(i) for i in range(self.leaf_count)]

    # -- proofs -------------------------------------------------------------------------------
    def single_proof(self, position: int) -> Tuple[List[Hash], List[Hash], List[Hash]]:
        """(path, left_peaks, right_peaks) for the leaf at `position` at the current size."""
        path, left, right = calc_proof_positions(position, self.size)
        return self.nodes_at(path), self.nodes_at(left), self.nodes_at(right)

    def batch_proof(self, positions: Sequence[int]) -> Tuple[List[Hash], List[Hash]]:
        """(siblings, untouched_peaks) for strictly increasing leaf `positions`.

        This is the verifier's traversal (`mmr_proof::root_from_batch_proof`) with "record"
        instead of "read" at the single decision point: any change to the verifier must be
        mirrored here, and the guard is to run `verify_batch` on the output.
        """
        positions = list(positions)
        if positions != sorted(set(positions)):
            raise ValueError("positions must be strictly increasing")
        for p in positions:
            if not 1 <= p <= self.size or get_height(p) != 1:
                raise ValueError(f"{p} is not a leaf position of this MMR")
        siblings: List[Hash] = []
        untouched: List[Hash] = []
        li = 0
        for peak in self.peaks_positions():
            queue: List[int] = []
            while li < len(positions) and positions[li] <= peak:
                queue.append(positions[li])
                li += 1
            if not queue:
                untouched.append(self.node(peak))
                continue
            head = 0
            while True:
                pos = queue[head]
                head += 1
                if pos == peak:
                    break
                sibling = get_sibling_position(pos)
                if head < len(queue) and queue[head] == sibling:
                    head += 1  # derived by the verifier: nothing recorded
                else:
                    siblings.append(self.node(sibling))  # recorded in consumption order
                queue.append(get_parent_position(pos))
        return siblings, untouched


def peaks_stack_append(peaks: Sequence[Hash], size: int, leaf: bytes) -> Tuple[List[Hash], int, Hash]:
    """The on-chain append (`mmr::append_leaf`): while the node being placed is a right
    sibling, its left sibling is the last peak, so it is popped from the peaks stack. Returns
    (new peaks, new size, leaf hash). Equivalent to `NodeSet.append` without the node vector."""
    stack = list(peaks)
    position = size + 1
    leaf_hash = hash_with_integer(position, [leaf])
    node_hash = leaf_hash
    while is_right_sibling(position):
        left = stack.pop()
        position += 1
        node_hash = hash_with_integer(position, [left, node_hash])
    stack.append(node_hash)
    return stack, position, leaf_hash


# ---------------------------------------------------------------------------------------------
# Verifier mirrors (== mmr_proof::root_from_single_proof / root_from_batch_proof)
# ---------------------------------------------------------------------------------------------
def _assert_hash_lengths(hashes: Sequence[bytes]) -> None:
    for h in hashes:
        if len(h) != HASH_LENGTH:
            raise ProofError("EHashLength")


def compute_root(size: int, position: int, leaf: bytes, path: Sequence[Hash],
                 left_peaks: Sequence[Hash], right_peaks: Sequence[Hash]) -> Hash:
    """Root implied by a single proof. Check order mirrors `mmr_proof::root_from_single_proof`."""
    if not is_valid_size(size):
        raise ProofError("EInvalidSize")
    if not 1 <= position <= size:
        raise ProofError("EPositionOutOfRange")
    if get_height(position) != 1:
        raise ProofError("ENotALeaf")
    merge_path = calc_proof_tree_path_positions(position, size)
    if len(path) != len(merge_path):
        raise ProofError("EPathLength")
    local_peak = get_parent_position(merge_path[-1]) if merge_path else position
    peaks = get_peaks_positions(size)
    if len(left_peaks) != sum(1 for p in peaks if p < local_peak):
        raise ProofError("EPeaksCount")
    if len(right_peaks) != sum(1 for p in peaks if p > local_peak):
        raise ProofError("EPeaksCount")
    _assert_hash_lengths(path)
    _assert_hash_lengths(left_peaks)
    _assert_hash_lengths(right_peaks)
    node_hash = hash_with_integer(position, [leaf])
    for sibling_position, sibling_hash in zip(merge_path, path):
        children = [node_hash, sibling_hash] if is_right_sibling(sibling_position) else [sibling_hash, node_hash]
        node_hash = hash_with_integer(get_parent_position(sibling_position), children)
    return hash_with_integer(size, [*left_peaks, node_hash, *right_peaks])


def verify_single(root: Hash, size: int, position: int, leaf: bytes, path: Sequence[Hash],
                  left_peaks: Sequence[Hash], right_peaks: Sequence[Hash]) -> bool:
    return compute_root(size, position, leaf, path, left_peaks, right_peaks) == root


def compute_batch_root(size: int, positions: Sequence[int], leaves: Sequence[bytes],
                       siblings: Sequence[Hash], untouched_peaks: Sequence[Hash]) -> Hash:
    """Root implied by a batch proof. Mirrors `mmr_proof::root_from_batch_proof`."""
    if not is_valid_size(size):
        raise ProofError("EInvalidSize")
    k = len(positions)
    if k < 1:
        raise ProofError("EEmptyBatch")
    if len(leaves) != k:
        raise ProofError("ELengthMismatch")
    prev = 0
    for p in positions:
        if p <= prev:
            raise ProofError("EPositionsNotSorted")
        if p > size:
            raise ProofError("EPositionOutOfRange")
        if get_height(p) != 1:
            raise ProofError("ENotALeaf")
        prev = p
    _assert_hash_lengths(siblings)
    _assert_hash_lengths(untouched_peaks)
    computed: List[Hash] = []
    li = si = pi = 0
    for peak in get_peaks_positions(size):
        q_pos: List[int] = []
        q_hash: List[Hash] = []
        while li < k and positions[li] <= peak:
            q_pos.append(positions[li])
            q_hash.append(hash_with_integer(positions[li], [leaves[li]]))
            li += 1
        if not q_pos:
            if pi >= len(untouched_peaks):
                raise ProofError("EMissingProofHashes")
            computed.append(untouched_peaks[pi])
            pi += 1
            continue
        head = 0
        while True:
            pos, h = q_pos[head], q_hash[head]
            head += 1
            if pos == peak:
                if head != len(q_pos):
                    raise ProofError("ELeftoverProofHashes")  # drain check
                computed.append(h)
                break
            height = get_height(pos)
            right = is_right_sibling(pos)
            off = sibling_offset(height)
            sibling = pos - off if right else pos + off
            parent = pos + 1 if right else sibling + 1
            if parent > peak:
                raise ProofError("EMalformedProof")
            if head < len(q_pos) and q_pos[head] == sibling:
                sibling_hash = q_hash[head]
                head += 1
            else:
                if si >= len(siblings):
                    raise ProofError("EMissingProofHashes")
                sibling_hash = siblings[si]
                si += 1
            children = [sibling_hash, h] if right else [h, sibling_hash]
            q_pos.append(parent)
            q_hash.append(hash_with_integer(parent, children))
    if si != len(siblings) or pi != len(untouched_peaks):
        raise ProofError("ELeftoverProofHashes")
    return hash_with_integer(size, computed)


def verify_batch(root: Hash, size: int, positions: Sequence[int], leaves: Sequence[bytes],
                 siblings: Sequence[Hash], untouched_peaks: Sequence[Hash]) -> bool:
    return compute_batch_root(size, positions, leaves, siblings, untouched_peaks) == root


# ---------------------------------------------------------------------------------------------
# Fixtures shared with the Move test suite
# ---------------------------------------------------------------------------------------------
def leaf_data(n: int) -> bytes:
    """Leaf data of leaf number `n` (1-based): its decimal ASCII."""
    return enc(n)


def leaves(n: int) -> List[bytes]:
    return [leaf_data(i) for i in range(1, n + 1)]


def build(n: int) -> NodeSet:
    """Node set of leaves "1".."n"."""
    ns = NodeSet()
    ns.append_all(leaves(n))
    return ns


def leaf_position(n: int) -> int:
    """Position of leaf number `n` (1-based)."""
    return leaf_index_to_position(n - 1)


# ---------------------------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------------------------
def check_every_leaf(ns: NodeSet) -> None:
    """Every single proof and every batch-of-one proof of `ns` verifies (true with the leaf's own
    data, false with the next leaf's data; the batch of one equals the single proof)."""
    root, size = ns.root(), ns.size
    for leaf_no, position in enumerate(ns.leaf_positions(), start=1):
        assert position_to_leaf_index(position) == leaf_no - 1
        path, left, right = ns.single_proof(position)
        assert verify_single(root, size, position, leaf_data(leaf_no), path, left, right)
        assert not verify_single(root, size, position, leaf_data(leaf_no + 1), path, left, right)
        siblings, untouched = ns.batch_proof([position])
        assert siblings == path and untouched == left + right
        assert verify_batch(root, size, [position], [leaf_data(leaf_no)], siblings, untouched)


def self_check(max_leaves: int = 300, sweep_leaves: int = 1000) -> None:
    """Cross-checks, in order: the peaks-stack append (`mmr::append_leaf`) agrees with the node-vector
    append after every one of `max_leaves` incremental appends; every single proof and every
    batch-of-one proof of every MMR up to `max_leaves` leaves verifies and a wrong leaf never
    does; batch proofs of a few fixed subsets verify; every non-empty subset of 1..8 leaves
    verifies as a batch (502 batches); 50 deterministic random batches on 200 leaves verify; and
    the every-leaf sweep runs on the `sweep_leaves`-leaf MMR (the Move suite samples 75 of those
    leaves in `every_leaf_1000_*`)."""
    ns = NodeSet()
    stack: List[Hash] = []
    stack_size = 0
    for n in range(1, max_leaves + 1):
        ns.append(leaf_data(n))
        assert ns.size == leaf_count_to_size(n)
        assert is_valid_size(ns.size)
        assert ns.leaf_count == n
        # the peaks stack (what the object stores) agrees with the node vector after every leaf
        stack, stack_size, leaf_hash = peaks_stack_append(stack, stack_size, leaf_data(n))
        assert stack_size == ns.size and stack == ns.peaks()
        assert leaf_hash == ns.node(leaf_position(n))
        assert hash_with_integer(stack_size, stack) == ns.root()
        check_every_leaf(ns)
        root, size = ns.root(), ns.size
        positions = ns.leaf_positions()
        for subset in (positions[::3], positions[1::5], positions[-4:], positions):
            if not subset:
                continue
            data = [leaf_data(position_to_leaf_index(p) + 1) for p in subset]
            siblings, untouched = ns.batch_proof(subset)
            assert verify_batch(root, size, subset, data, siblings, untouched)
            bad = list(data)
            bad[0] += b"!"
            assert not verify_batch(root, size, subset, bad, siblings, untouched)
    # every non-empty subset of the leaves of the 1..8-leaf MMRs (502 batches)
    subsets = 0
    for n in range(1, 9):
        small = build(n)
        for r in range(1, n + 1):
            for combo in itertools.combinations(range(1, n + 1), r):
                positions = [leaf_position(k) for k in combo]
                data = [leaf_data(k) for k in combo]
                siblings, untouched = small.batch_proof(positions)
                assert verify_batch(small.root(), small.size, positions, data, siblings, untouched)
                bad = list(data)
                bad[0] = b"not the leaf"
                assert not verify_batch(small.root(), small.size, positions, bad, siblings, untouched)
                subsets += 1
    assert subsets == 502
    # deterministic random batches (1..40 leaves) on the 200-leaf MMR
    rng = random.Random(7)
    big = build(200)
    random_batches = 50
    for _ in range(random_batches):
        combo = sorted(rng.sample(range(1, 201), rng.randint(1, 40)))
        positions = [leaf_position(k) for k in combo]
        data = [leaf_data(k) for k in combo]
        siblings, untouched = big.batch_proof(positions)
        assert verify_batch(big.root(), big.size, positions, data, siblings, untouched)
        shifted = [leaf_data(k + 1) for k in combo]
        assert not verify_batch(big.root(), big.size, positions, shifted, siblings, untouched)
    # every leaf of the sweep MMR
    for n in range(max_leaves + 1, sweep_leaves + 1):
        ns.append(leaf_data(n))
    assert ns.leaf_count == sweep_leaves
    check_every_leaf(ns)
    print(f"self-check OK: {max_leaves} incremental appends (peaks stack == node vector), every "
          f"leaf of every MMR up to {max_leaves} leaves, every subset of 1..8 leaves, "
          f"{random_batches} random batches on 200 leaves, every leaf of the {sweep_leaves}-leaf MMR")


if __name__ == "__main__":
    self_check()
