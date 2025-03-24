module mmr::mmr_utils;

use sui::hash;
use mmr::mmr_bits;

/// Attempting to access node 0
#[error]
const EStartsAtOne: vector<u8> = b"First position of a MMR node is 1";

public struct ProofPositions has copy, drop {
    // Positions of nodes in the path from the element to its local peak
    local_tree_path_positions: vector<u64>,
    // Positions of peaks to the left of the element's peak
    left_peaks_positions: vector<u64>,
    // Positions of peaks to the right of the element's peak
    right_peaks_positions: vector<u64>    
}

public fun get_local_tree_path_hashes(proof_positions: &ProofPositions, nodes_hashes: vector<vector<u8>>): vector<vector<u8>> {
    get_hashes_from_positions(nodes_hashes, proof_positions.local_tree_path_positions)
}

public fun get_left_peaks_hashes(proof_positions: &ProofPositions, nodes_hashes: vector<vector<u8>>): vector<vector<u8>> {
    get_hashes_from_positions(nodes_hashes, proof_positions.left_peaks_positions)
}

public fun get_right_peaks_hashes(proof_positions: &ProofPositions, nodes_hashes: vector<vector<u8>>): vector<vector<u8>> {
    get_hashes_from_positions(nodes_hashes, proof_positions.right_peaks_positions)
}

public fun calc_proof_positions(position: u64, size: u64): ProofPositions {
    // Get the local tree path positions
    let tree_path_positions = calc_proof_tree_path_positions(position, size);
    // Peak position for the proof local tree is the parent of the last position in path if
    // the proof isn't for a leaf node
    let path_peak_position: u64;
    if (tree_path_positions.length() != 0) {
        path_peak_position = get_parent_position(tree_path_positions[tree_path_positions.length() - 1]);
    } else {
        // If is a leaf node the tree path will be empty and the peak will be itself
        path_peak_position = position;
    };
    // Get all peaks in the MMR
    let peaks_positions = get_peaks_positions(size);
    let mut left_peaks_positions = vector::empty<u64>();   
    let mut right_peaks_positions = vector::empty<u64>();
    // If MMR is not a perfect binary tree or an empty tree
    if (peaks_positions.length() > 1) {
        // Collect peaks to the left of the element's peak
        left_peaks_positions = get_left_peaks_positions(path_peak_position, peaks_positions);
        // Collect peaks to the right of the element's peak
        right_peaks_positions = get_right_peaks_positions(path_peak_position, peaks_positions);
    };
    ProofPositions {
        local_tree_path_positions: tree_path_positions,
        left_peaks_positions: left_peaks_positions,
        right_peaks_positions: right_peaks_positions,
    }
}

public fun calc_proof_tree_path_positions(proof_position: u64, size: u64): vector<u64> {
    let mut path_positions = vector::empty<u64>();
    let mut current_node_position: u64;
    let mut sibling_position: u64;
    // Handle special case when position is last node (leaf-peak)
    if (proof_position != size) {
        // navigate the binary tree from the leaf to the peak, storing each node that would be 
        // necessary to calculate the peak hash
        current_node_position = proof_position;
        while (current_node_position <= size) {
            // store the sibling position we need for computing the next level node
            sibling_position = get_sibling_position(current_node_position);
            path_positions.push_back(sibling_position);
            // calculate the parent node position for the next iteration
            current_node_position = get_parent_position(current_node_position);
        };
        // Algorithm always stores one more node than necessary so we need to trim it
        path_positions.pop_back();
    };
    path_positions
}

public fun get_peaks_positions(size: u64): vector<u64> {
    let mut peaks_positions: vector<u64> = vector::empty<u64>();
    // Empty MMR has no peaks
    if (size == 0) { return peaks_positions };
    // Check if the MMR is a perfect binary tree so the size is the position of the only peak
    if (mmr_bits::are_all_ones(size)) {
        peaks_positions.push_back(size);
    } else {
        // If the MMR is multi tree, calculate the height of the largest perfect binary tree 
        // that can fit a MMR of this size
        let largest_tree_height = mmr_bits::get_length(size) - 1;
        // Use the height to calculate the largest, and therefor leftmost, tree size
        let mut tree_size = (mmr_bits::get_length((largest_tree_height as u64)) as u64);
        // Iterate over all perfect trees inside the MMR, storing how many nodes are outside the
        // tree we store the peak position on each iteration
        let mut nodes_left = size;
        let mut peak_position = 0;
        while (tree_size != 0) {
            // If the amount of nodes left to check is smaller than the tree size, that means 
            // that that peak is not in the MMR and we just need to get the next smaller tree
            if (nodes_left >= tree_size) {
                nodes_left = nodes_left - tree_size;
                peak_position = peak_position + tree_size;
                // Peaks positions are stored from left to right
                peaks_positions.push_back(peak_position);
            };
            // Calculate the next smaller perfect binary tree size
            tree_size = tree_size >> 1;          
        };  
    };
    peaks_positions    
}

public fun get_left_peaks_positions(peak_position: u64, peaks_positions: vector<u64>): vector<u64> {
    let mut left_peaks_positions = vector::empty<u64>();
    let mut i = 0;
    while (i < peaks_positions.length()) {
        if (peaks_positions[i] < peak_position){
            left_peaks_positions.push_back(peaks_positions[i]);
        };
        i = i + 1;
    };
    left_peaks_positions
}

public fun get_right_peaks_positions(peak_position: u64, peaks_positions: vector<u64>): vector<u64> {
    let mut right_peaks_positions = vector::empty<u64>();
    let mut i = 0;
    while (i < peaks_positions.length()) {
        if (peaks_positions[i] > peak_position){
            right_peaks_positions.push_back(peaks_positions[i]);
        };
        i = i + 1;
    };
    right_peaks_positions
}

public fun get_parent_position(position: u64): u64 {
    let parent_position: u64;
    if (is_right_sibling(position)) {
        parent_position = position + 1;
    } else {
        parent_position = get_sibling_position(position) + 1;
    };
    parent_position
}

public fun get_sibling_position(position: u64): u64 {
    let sibling_position: u64;
    if (is_right_sibling(position)) {
        sibling_position = position - sibling_offset(get_height(position));
    } else {
        sibling_position = position + sibling_offset(get_height(position));
    };
    sibling_position
}

public fun is_right_sibling(position: u64): bool {
    // Ensure position is a valid MMR node
    assert!(position > 0, EStartsAtOne);
    // If the node is at the same height as the node on position + offset, its a left node
    let height = get_height(position);
    let sibling_offset = sibling_offset(height);    
    if (height == get_height(position + sibling_offset)) {
        return false
    } else {
        return true
    }
}

public fun sibling_offset(height: u8): u64 {
    mmr_bits::create_all_ones(height)
}

public fun get_height(position: u64): u8 {
    // We are looking for the leftmost node at the node level, we start our search from the position itself
    let mut left_most_node = position;
    // Leftmost nodes bit representation have all their bits set to one, if the current isn't
    // jump to the next* node on the left
    while (!mmr_bits::are_all_ones(left_most_node)) {
        left_most_node = jump_left(left_most_node)
    };
    // The height of a level can be obtained by getting the length of the binary representation
    // of the leftmost node of that level, e.g. 7(111), length 3, height 3
    mmr_bits::get_length(left_most_node)
}

public fun jump_left (position: u64): u64 {
    // Find the most significant bit position
    let most_significant_bit: u64 = 1 << (mmr_bits::get_length(position) - 1);
    // Subtract all bits to the right of the MSB
    position - (most_significant_bit - 1)
}

public fun get_hashes_from_positions(nodes_hashes: vector<vector<u8>>, positions: vector<u64>): vector<vector<u8>> {
    let mut hashes = vector::empty<vector<u8>>();
    let mut i = 0;
    while (i < positions.length()) {
        hashes.push_back(nodes_hashes[positions[i] - 1]);
        i = i + 1;
    };
    hashes
}

public fun hash_with_integer(number: u64, hashes: vector<vector<u8>>): vector<u8> {
    // Concatenate all hashes together
    let mut chain: vector<u8> = vector::empty<u8>();
    chain.append(u64_to_string(number));
    let mut i = 0;
    while (i < hashes.length()) {
        chain.append(hashes[i]);
        i = i + 1;
    };
    hash::blake2b256(&chain)
}

/// Convert a u64 to its string representation as vector<u8>
public fun u64_to_string(value: u64): vector<u8> {
    let mut temp = value;    
    let mut buffer = vector[];
    let mut i = vector::length(&buffer);
    let mut result = vector[];

    if (value == 0) {
        return vector[48] // ASCII '0'
    };
    
    while (temp > 0) {
        let remainder = temp % 10;
        temp = temp / 10;
        // Add ASCII value of the digit (48 is ASCII for '0')
        vector::push_back(&mut buffer, (remainder + 48 as u8));
    };
    
    // Reverse the buffer since we've been adding digits in reverse order
    while (i > 0) {
        i = i - 1;
        vector::push_back(&mut result, *vector::borrow(&buffer, i));
    };
    
    result
}