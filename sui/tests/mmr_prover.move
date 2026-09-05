/// Test-only prover: the full node set in memory, proofs built with the production position
/// math. This is the off-chain prover shape (indexer / Walrus) kept inside the test suite.
///
/// Mirroring rule: any change to the verifier's traversal (`mmr_proof::root_from_batch_proof`)
/// must be mirrored in `batch_proof`; the guard for any generator is to run the verifier on its
/// own output.
#[test_only]
module mmr::mmr_prover;

use mmr::mmr_utils;

/// Full node set: `nodes[position - 1]` is the hash of the node at `position`.
public struct NodeSet has drop {
    nodes: vector<vector<u8>>,
}

/// An empty node set.
public fun new(): NodeSet { NodeSet { nodes: vector[] } }

/// Node-vector append (the v1 algorithm, verbatim): the REFERENCE the peaks-stack append is
/// checked against. leaf = H(pos, [data]); while is_right_sibling(pos):
/// left = nodes[get_sibling_position(pos) - 1]; pos += 1; push H(pos, [left, node]).
public fun append(ns: &mut NodeSet, leaf: vector<u8>) {
    let mut position = ns.nodes.length() + 1;
    let mut node_hash = mmr_utils::hash_with_integer(position, vector[leaf]);
    ns.nodes.push_back(node_hash);
    while (mmr_utils::is_right_sibling(position)) {
        let left = ns.nodes[mmr_utils::get_sibling_position(position) - 1];
        position = position + 1;
        node_hash = mmr_utils::hash_with_integer(position, vector[left, node_hash]);
        ns.nodes.push_back(node_hash);
    };
}

/// Append every leaf of `leaves` in order.
public fun append_all(ns: &mut NodeSet, leaves: vector<vector<u8>>) {
    leaves.do!(|leaf| ns.append(leaf));
}

/// Node count.
public fun size(ns: &NodeSet): u64 { ns.nodes.length() }

/// Leaf count (`size_to_leaf_count(size)`).
public fun leaf_count(ns: &NodeSet): u64 { mmr_utils::size_to_leaf_count(ns.size()) }

/// Hash of the node at `position` (1-based).
public fun node(ns: &NodeSet, position: u64): vector<u8> { ns.nodes[position - 1] }

/// Peak hashes, left to right (`get_hashes_from_positions(&nodes, &get_peaks_positions(size))`).
public fun peaks(ns: &NodeSet): vector<vector<u8>> {
    let positions = mmr_utils::get_peaks_positions(ns.size());
    mmr_utils::get_hashes_from_positions(&ns.nodes, &positions)
}

/// Root: `H(size, peaks)`; `H(0, [])` when empty.
public fun root(ns: &NodeSet): vector<u8> {
    mmr_utils::hash_with_integer(ns.size(), ns.peaks())
}

/// Single-leaf proof: (path, left_peaks, right_peaks) via `calc_proof_positions` +
/// `get_hashes_from_positions`.
public fun single_proof(
    ns: &NodeSet,
    position: u64,
): (vector<vector<u8>>, vector<vector<u8>>, vector<vector<u8>>) {
    let pp = mmr_utils::calc_proof_positions(position, ns.size());
    (
        mmr_utils::get_hashes_from_positions(&ns.nodes, &pp.local_tree_path_positions()),
        mmr_utils::get_hashes_from_positions(&ns.nodes, &pp.left_peaks_positions()),
        mmr_utils::get_hashes_from_positions(&ns.nodes, &pp.right_peaks_positions()),
    )
}

/// Batch proof for strictly increasing leaf `positions`: (siblings, untouched_peaks).
/// The verifier's traversal (spec F.4) with "record" instead of "read" at the single decision
/// point. Never hashes.
public fun batch_proof(
    ns: &NodeSet,
    positions: vector<u64>,
): (vector<vector<u8>>, vector<vector<u8>>) {
    let size = ns.size();
    let peaks_positions = mmr_utils::get_peaks_positions(size);
    let mut siblings = vector[];
    let mut untouched = vector[];
    let mut li = 0;
    peaks_positions.do_ref!(|peak_ref| {
        let peak = *peak_ref;
        // Positions only: the generator never hashes.
        let mut q = vector[];
        while (li < positions.length() && positions[li] <= peak) {
            q.push_back(positions[li]);
            li = li + 1;
        };
        if (q.is_empty()) {
            untouched.push_back(ns.node(peak));
        } else {
            let mut head = 0;
            loop {
                let pos = q[head];
                head = head + 1;
                if (pos == peak) break;
                let sibling = mmr_utils::get_sibling_position(pos);
                if (head < q.length() && q[head] == sibling) {
                    // Derived by the verifier: nothing recorded.
                    head = head + 1;
                } else {
                    // Recorded in consumption order.
                    siblings.push_back(ns.node(sibling));
                };
                q.push_back(mmr_utils::get_parent_position(pos));
            };
        };
    });
    (siblings, untouched)
}

// ------------------------------------------------------------------------------ fixtures

/// Leaf data of leaf number `n` (1-based): its decimal ASCII.
public fun leaf_data(n: u64): vector<u8> { n.to_string().into_bytes() }

/// Leaves "1".."n".
public fun leaves(n: u64): vector<vector<u8>> {
    vector::tabulate!(n, |i| leaf_data(i + 1))
}

/// Node set built from leaves "1".."n".
public fun build(n: u64): NodeSet {
    let mut ns = new();
    ns.append_all(leaves(n));
    ns
}

/// Position of leaf number `n` (1-based): `leaf_index_to_position(n - 1)`.
public fun leaf_position(n: u64): u64 { mmr_utils::leaf_index_to_position(n - 1) }
