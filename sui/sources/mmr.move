/// MerkleMountainRange
/// 
/// This contract implements a Merkle Mountain Range (MMR) data structure, which is an efficient 
/// append-only accumulator for cryptographic commitments. MMRs are a collection of perfect binary 
/// trees arranged as a series of "peaks" that can be efficiently appended to and proven against.
/// It uses the MMRUtil to derive all the positions needed which it then handles for hash merging and peak bagging.
/// 
/// MMRs are particularly useful for lightweight clients, as they allow verifying the inclusion of
/// elements without needing to store the entire dataset.
module mmr::mmr;

use sui::hash;
use sui::event;
use mmr::mmr_utils;
use std::address;

/// Attempting to access node 0.
#[error]
const EStartsAtOne: vector<u8> = b"First position of a MMR node is 1";
/// Attempting to generate a proof for a non-leaf node.
#[error]
const EProofOnlyLeaf: vector<u8> = b"Proofs can only be generated for lead nodes";
/// Attempting to access a node bigger than MMR size.
#[error]
const ENonExistingNode: vector<u8> = b"Node does not exists";

/// Event emitted when a public MMR is created.
public struct MMRShared has copy, drop {
    creator: address,
    id: ID
}

/// Event emitted when the MMR root is updated.
public struct MMRUpdated has copy, drop {
    root: vector<u8>,
    peaks: vector<vector<u8>>,
    new_size: u64
}

/// Proof struct that contains all necessary data for verifying the inclusion
/// of an element in the MMR without needing the entire structure.
/// 
/// The proof includes:
/// - The position of the element in the MMR.
/// - Hashes from the local tree path (for verification up to the peak).
/// - Hashes from peaks to the left and right of the element's peak.
/// - The root hash for verification.
/// - The size of the MMR when the proof was generated.
public struct Proof has copy, drop, store {
    position: u64,
    local_tree_path_hashes: vector<vector<u8>>,
    left_peaks_hashes: vector<vector<u8>>,
    right_peaks_hashes: vector<vector<u8>>,
    mmr_root: vector<u8>,
    mmr_size: u64
}

/// Return the position of the element in the MMR that this proof is for.
public fun get_position(proof: &Proof): u64 {
    proof.position
}

/// Return the root hash of the MMR at the time this proof was generated.
public fun get_mmr_root(proof: &Proof): vector<u8> {
    proof.mmr_root
}

/// Return the size of the MMR at the time this proof was generated.
public fun get_mmr_size(proof: &Proof): u64 {
    proof.mmr_size
}

/// Verify that some data exists in the MMR the proof belongs to.
public fun verify(proof: &Proof, data: vector<u8>): bool {
    // For verifying the data we need to calculate the hash for the proof position tree's peak
    // and combine it with the rest of peak hashes and MMR size to calculate the root hash
    let mut peaks_hashes= vector::empty<vector<u8>>();
    let calculated_root_hash: vector<u8>;
    // Calculate the path to follow for verification
    let merge_path = mmr_utils::calc_proof_tree_path_positions(proof.position, proof.mmr_size);
    // Hash the data with the proof position to get the initial hash
    let mut node_hash = mmr_utils::hash_with_integer(proof.position, vector::singleton(data));
    // Iterate over the merge path positions to get the tree's peak hash
    let mut parent_position: u64;
    let mut child_hashes = vector::empty<vector<u8>>();
    let mut merged_nodes: u64 = 0;
    let mut i = 0;
    while (i < merge_path.length()) {
        if (!mmr_utils::is_right_sibling(merge_path[i])) {
            child_hashes.push_back(proof.local_tree_path_hashes[merged_nodes]);
            child_hashes.push_back(node_hash);
        } else {
            child_hashes.push_back(node_hash);
            child_hashes.push_back(proof.local_tree_path_hashes[merged_nodes]);
        };
        parent_position = mmr_utils::get_parent_position(merge_path[i]);
        // The nodeHash on the last iteration will be the tree's peak hash
        node_hash = mmr_utils::hash_with_integer(parent_position, child_hashes);
        merged_nodes = merged_nodes + 1;
        child_hashes = vector::empty<vector<u8>>();
        i = i + 1;
    };
    // Collect all peak hashes for final root verification
    peaks_hashes.append(proof.left_peaks_hashes);
    peaks_hashes.push_back(node_hash);
    peaks_hashes.append(proof.right_peaks_hashes);
    // Combine all peak hashes with the MMR size to calculate the root
    calculated_root_hash = mmr_utils::hash_with_integer(proof.get_mmr_size(), peaks_hashes);
    // Check if it matches the root stored on the proof
    calculated_root_hash == proof.mmr_root
}

/// MMR object that manages the appending of elements and generation of proofs.
/// 
/// This object maintains:
/// - The current root commitment.
/// - The current peaks of the MMR.
/// - All nodes in the MMR.
public struct MMR has key, store {
    id: UID,
    root: vector<u8>,
    peaks_hashes: vector<vector<u8>>,
    nodes_hashes: vector<vector<u8>>
}

/// Initialize a new MMR object.
fun new(ctx: &mut TxContext): MMR {
    MMR {
        id: object::new(ctx),
        root: hash::blake2b256((0 as u64).to_string().as_bytes()),
        peaks_hashes: vector::empty<vector<u8>>(),
        nodes_hashes: vector::empty<vector<u8>>()
    }
}

/// Create a new private MMR object and transfer it to the caller address.
public entry fun create_mmr(ctx: &mut TxContext) {
    transfer::transfer(new(ctx), ctx.sender());
}

/// Create a new shared MMR that anyone that knows its ID can append elements to it and generate proofs from it.
/// EXPERIMENTAL: Literally anyone on chain could write to this MMR, so what would be the point?
/// TO-DO: Explore a capability based version of the MMR that allows to share it while restricting who could write to it.
public entry fun create_public_mmr(ctx: &mut TxContext) {
    let mmr = new(ctx);
    let id = object::id(&mmr);
    transfer::share_object(mmr);
    event::emit(MMRShared {
        creator: ctx.sender(),
        id: id
    });
}

/// Get the current root commitment of the MMR.
public fun get_root(mmr: &MMR): vector<u8> {
    mmr.root
}

/// Get the current peaks of the MMR.
public fun get_peaks(mmr: &MMR): vector<vector<u8>> {
    mmr.peaks_hashes
}

/// Get all nodes in the MMR.
public(package) fun get_nodes(mmr: &MMR): vector<vector<u8>> {
    mmr.nodes_hashes
}

/// Get the amount of nodes in the MMR.
public fun get_size(mmr: &MMR): u64 {
    mmr.nodes_hashes.length()
}

/// Append multiple leaf elements to the MMR.
public fun append_leaves(mmr: &mut MMR, leaves_data: vector<vector<u8>>) {
    if (leaves_data.length() == 0) {
        return
    };
    let mut i = 0;
    while (i < leaves_data.length()) {
        append_leaf(mmr, leaves_data[i]);
        i = i + 1;
    };
    event::emit(MMRUpdated {
        root: mmr.root,
        peaks: mmr.peaks_hashes,
        new_size: mmr.get_size()      
    })
}

/// Append a single leaf element to the MMR.
/// This is the core append logic that handles the creation of new nodes and merging of peaks as needed.
fun append_leaf(mmr: &mut MMR, leaf_data: vector<u8>) {
    // Calculate which new nodes and peaks will be created by appending a new leaf
    let mut child_hashes: vector<vector<u8>>;
    let peaks_positions: vector<u64>;
    // The new leaf will take the next node position
    let mut node_position = mmr.get_size() + 1;
    // Hash the leaf data with the position and store it on the list of new nodes
    let mut node_hash = mmr_utils::hash_with_integer(node_position, vector::singleton(leaf_data));
    let mut new_nodes_hashes = vector::singleton(node_hash);
    // If it is a right sibling, it will generate a new parent node. As long as the newly  
    // generated parent nodes remain right siblings, they will continue generating new parents
    while (mmr_utils::is_right_sibling(node_position)) {
        // Get the left sibling hash using the node position and combine it with the node hash
        child_hashes = vector::singleton(mmr.nodes_hashes[mmr_utils::get_sibling_position((node_position)) - 1]);
        child_hashes.push_back(node_hash);
        // Hash the siblings with the position the parent will take to create the parent node
        node_position = node_position + 1;
        node_hash = mmr_utils::hash_with_integer(node_position, child_hashes);
        // And finally add it to the list of new nodes generated by the leaf appending
        new_nodes_hashes.push_back(node_hash);
    };
    // Save the new nodeHashes to the MMR state
    mmr.nodes_hashes.append(new_nodes_hashes);
    // Get the new peak positions
    peaks_positions = mmr_utils::get_peaks_positions(mmr.get_size());
    // Update the peak hashes on the MMR state
    mmr.peaks_hashes = mmr_utils::get_hashes_from_positions(mmr.nodes_hashes, peaks_positions);
    // Finally update the MMR root bagging all the new peaks along the new MMR size
    mmr.root = mmr_utils::hash_with_integer(mmr.get_size(), mmr.peaks_hashes);
}

/// Generate a proof for the element at the specified position.
public fun generate_proof(mmr: &MMR, position: u64): Proof {
    // Check that the position that wants to get proved is correct
    assert!(position > 0, EStartsAtOne);
    assert!(mmr_utils::get_height(position) == 1, EProofOnlyLeaf);
    let size = mmr.get_size();
    assert!(position <= size, ENonExistingNode);
    // Calculate the positions of all nodes needed for the proof
    let proof_positions = mmr_utils::calc_proof_positions(position, size);
    // Create proof from the calculated positions and their corresponding hashes
    Proof {
        position: position,
        local_tree_path_hashes: proof_positions.get_local_tree_path_hashes(mmr.nodes_hashes),
        left_peaks_hashes: proof_positions.get_left_peaks_hashes(mmr.nodes_hashes),
        right_peaks_hashes: proof_positions.get_right_peaks_hashes(mmr.nodes_hashes),
        mmr_root: mmr.root,
        mmr_size: size
    }
}