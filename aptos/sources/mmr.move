module mmr::mmr {

    use std::signer;
    use std::vector;
    use aptos_framework::aptos_hash;
    use aptos_framework::event;
    use aptos_framework::string_utils;
    use mmr::mmr_utils;

    #[event]
    struct MMRUpdated has drop, store {
        root: vector<u8>,
        peaks: vector<vector<u8>>,
        new_size: u64
    }

    struct Proof has copy, drop, store {
        position: u64,
        local_tree_path_hashes: vector<vector<u8>>,
        left_peaks_hashes: vector<vector<u8>>,
        right_peaks_hashes: vector<vector<u8>>,
        mmr_root: vector<u8>,
        mmr_size: u64
    }

    public fun verify(self: &Proof, data: vector<u8>): bool {
        // For verifying the data we need to calculate the hash for the proof position tree's peak
        // and combine it with the rest of peak hashes and MMR size to calculate the root hash
        let peaks_hashes = vector::empty<vector<u8>>();
        let calculated_root_hash: vector<u8>;
        // Calculate the path to follow for verification
        let merge_path = mmr_utils::calc_proof_tree_path_positions(self.position, self.mmr_size);
        // Hash the data with the proof position to get the initial hash
        let node_hash = mmr_utils::hash_with_integer(self.position, vector::singleton(data));
        // Iterate over the merge path positions to get the tree's peak hash
        let parent_position: u64;
        let child_hashes = vector::empty<vector<u8>>();
        let merged_nodes: u64 = 0;
        for (i in 0..merge_path.length()) {
            if (!mmr_utils::is_right_sibling(merge_path[i])) {
                child_hashes.push_back(self.local_tree_path_hashes[merged_nodes]);
                child_hashes.push_back(node_hash);
            } else {
                child_hashes.push_back(node_hash);
                child_hashes.push_back(self.local_tree_path_hashes[merged_nodes]);
            };
            parent_position = mmr_utils::get_parent_position(merge_path[i]);
            // The nodeHash on the last iteration will be the tree's peak hash
            node_hash = mmr_utils::hash_with_integer(parent_position, child_hashes);
            merged_nodes = merged_nodes + 1;
            child_hashes = vector::empty<vector<u8>>();
        };
        // Collect all peak hashes for final root verification
        peaks_hashes.append(self.left_peaks_hashes);
        peaks_hashes.push_back(node_hash);
        peaks_hashes.append(self.right_peaks_hashes);
        // Combine all peak hashes with the MMR size to calculate the root
        calculated_root_hash = mmr_utils::hash_with_integer(self.mmr_size, peaks_hashes);
        // Check if it matches the root stored on the proof
        calculated_root_hash == self.mmr_root
    }

    struct MMR has key, store {
        root: vector<u8>,
        peaks_hashes: vector<vector<u8>>,
        nodes_hashes: vector<vector<u8>>
    }

    fun new(): MMR {
        MMR {
            root: aptos_hash::blake2b_256(*string_utils::to_string(&(0 as u64)).bytes()),
            peaks_hashes: vector::empty<vector<u8>>(),
            nodes_hashes: vector::empty<vector<u8>>()
        }
    }

    public fun create_mmr(owner: &signer) {
        move_to(owner, new());
    }

    public fun get_mmr(owner: &signer): MMR acquires MMR {
        move_from<MMR>(signer::address_of(owner))
    }

    public fun return_mmr(mmr: MMR, owner: &signer) {
        move_to(owner, mmr);
    }

    fun get_size(self: &MMR): u64 {
        self.nodes_hashes.length()
    }

    #[test_only]
    public fun get_size_test(self: &MMR): u64 {
        self.nodes_hashes.length()
    }

    public fun append_leaves(self: &mut MMR, leaves_data: vector<vector<u8>>) {
        if (leaves_data.length() == 0) {
            return
        };
        for (i in 0..leaves_data.length()) {
            append_leaf(self, leaves_data[i]);
        };
        event::emit(MMRUpdated {
            root: self.root,
            peaks: self.peaks_hashes,
            new_size: self.get_size()      
        })
    }

    fun append_leaf(self: &mut MMR, leaf_data: vector<u8>) {
        // Calculate which new nodes and peaks will be created by appending a new leaf
        let child_hashes: vector<vector<u8>>;
        let peaks_positions: vector<u64>;
        // The new leaf will take the next node position
        let node_position = self.get_size() + 1;
        // Hash the leaf data with the position and store it on the list of new nodes
        let node_hash = mmr_utils::hash_with_integer(node_position, vector::singleton(leaf_data));
        let new_nodes_hashes = vector::singleton(node_hash);
        // If it is a right sibling, it will generate a new parent node. As long as the newly  
        // generated parent nodes remain right siblings, they will continue generating new parents
        while (mmr_utils::is_right_sibling(node_position)) {
            // Get the left sibling hash using the node position and combine it with the node hash
            child_hashes = vector::singleton(self.nodes_hashes[mmr_utils::get_sibling_position((node_position)) - 1]);
            child_hashes.push_back(node_hash);
            // Hash the siblings with the position the parent will take to create the parent node
            node_position = node_position + 1;
            node_hash = mmr_utils::hash_with_integer(node_position, child_hashes);
            // And finally add it to the list of new nodes generated by the leaf appending
            new_nodes_hashes.push_back(node_hash);
        };
        // Save the new nodeHashes to the MMR state
        self.nodes_hashes.append(new_nodes_hashes);
        // Get the new peak positions
        peaks_positions = mmr_utils::get_peaks_positions(self.get_size());
        // Update the peak hashes on the MMR state
        self.peaks_hashes = mmr_utils::get_hashes_from_positions(self.nodes_hashes, peaks_positions);
        // Finally update the MMR root bagging all the new peaks along the new MMR size
        self.root = mmr_utils::hash_with_integer(self.get_size(), self.peaks_hashes);
    }

    public fun generate_proof(self: &MMR, position: u64): Proof {
        // Check that the position that wants to get proved is correct
        assert!(position > 0);
        assert!(mmr_utils::get_height(position) == 1);
        let size = self.get_size();
        assert!(position <= size);
        // Calculate the positions of all nodes needed for the proof
        let proof_positions = mmr_utils::calc_proof_positions(position, size);
        // Create proof from the calculated positions and their corresponding hashes
        Proof {
            position: position,
            local_tree_path_hashes: proof_positions.get_local_tree_path_hashes(self.nodes_hashes),
            left_peaks_hashes: proof_positions.get_left_peaks_hashes(self.nodes_hashes),
            right_peaks_hashes: proof_positions.get_right_peaks_hashes(self.nodes_hashes),
            mmr_root: self.root,
            mmr_size: size
        }
    }
}