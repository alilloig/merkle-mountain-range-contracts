#[test_only]
module mmr::mmr_tests{

    use std::unit_test;
    use std::vector;
    use aptos_framework::string_utils;
    use mmr::mmr;

    fun get_account(): signer {
        vector::pop_back(&mut unit_test::create_signers_for_testing(1))
    }

    #[test]
    fun test_mmr_setup() {
        // Create a MMR into signer account
        let signer = get_account();
        mmr::create_mmr(&signer);
        let mmr = mmr::get_mmr(&signer);
        // Create some test leaf data
        let leaves = vector[
            b"leaf1",
            b"leaf2",
            b"leaf3"
        ];
        // Append leaves to the MMR
        mmr::append_leaves(&mut mmr, leaves);
        // Check that the MMR size corresponds to the amount of leaves created
        assert!(mmr.get_size_test() == 4);
        // Return MMR to storage
        mmr::return_mmr(mmr, &signer);
    }

    #[test]
    fun test_generate_and_verify_proofs() {
        // Create a MMR into signer account
        let signer = get_account();
        mmr::create_mmr(&signer);
        let mmr = mmr::get_mmr(&signer);
        // Create 95 leafs which will produce a 184 nodes MMR
        let leafCounter: u64 = 1;
        let leafData: vector<u8>;
        let leaves = vector::empty<vector<u8>>();
        while (leafCounter <= 95) {
            leafData = *string_utils::to_string(&leafCounter).bytes();
            leaves.push_back(leafData);
            leafCounter = leafCounter + 1;
        };
        // Append leaves to the MMR
        mmr::append_leaves(&mut mmr, leaves);
        // Check that the MMR size corresponds to the amount of leaves created
        assert!(mmr.get_size_test() == 184);

        // Create and verify proofs for multiple positions
        let proof: mmr::Proof;
        
        // Generate proof for position 1
        proof = mmr.generate_proof(1);
        // Verify proof for leaf 1 at position 1
        proof.verify(*string_utils::to_string(&(1 as u64)).bytes());

        // Generate proof for position 27
        proof = mmr.generate_proof(27);
        // Verify proof for leaf 16 at position 27
        proof.verify(*string_utils::to_string(&(16 as u64)).bytes());

        // Generate proof for position 32
        proof = mmr.generate_proof(32);
        // Verify proof
        proof.verify(*string_utils::to_string(&(17 as u64)).bytes());

        // Generate proof for position 58
        proof = mmr.generate_proof(58);
        // Verify proof
        proof.verify(*string_utils::to_string(&(32 as u64)).bytes());

        // Generate proof for position 64
        proof = mmr.generate_proof(121);
        // Verify proof
        proof.verify(*string_utils::to_string(&(33 as u64)).bytes());

        // Generate proof for position 128
        proof = mmr.generate_proof(128);
        // Verify proof
        proof.verify(*string_utils::to_string(&(65 as u64)).bytes());

        // Generate proof for position 163
        proof = mmr.generate_proof(163);
        // Verify proof
        proof.verify(*string_utils::to_string(&(84 as u64)).bytes());

        // Generate proof for position 174
        proof = mmr.generate_proof(174);
        // Verify proof for leaf 89 at position 174
        proof.verify(*string_utils::to_string(&(89 as u64)).bytes());

        // Generate proof for position 184
        proof = mmr.generate_proof(184);
        // Verify proof for leaf 95 at position 184
        proof.verify(*string_utils::to_string(&(95 as u64)).bytes());

        // Return MMR to storage
        mmr::return_mmr(mmr, &signer);
    }

    #[test]
    fun test_generate_and_verify_proofs_for_large_single_perfect_tree_mmr() {
        // Create a MMR into signer account
        let signer = get_account();
        mmr::create_mmr(&signer);
        let mmr = mmr::get_mmr(&signer);
        // Create 95 leafs which will produce a 184 nodes MMR
        let leafCounter: u64 = 1;
        let leafData: vector<u8>;
        let leaves = vector::empty<vector<u8>>();
        while (leafCounter <= 128) {
            leafData = *string_utils::to_string(&leafCounter).bytes();
            leaves.push_back(leafData);
            leafCounter = leafCounter + 1;
        };
        // Append leaves to the MMR
        mmr::append_leaves(&mut mmr, leaves);
        // Check that the MMR size corresponds to the amount of leaves created
        assert!(mmr.get_size_test() == 255);

        // Create and verify proofs for multiple positions
        let proof: mmr::Proof;

        // Generate proof for position 1
        proof = mmr.generate_proof(1);
        // Verify proof for leaf 1 at position 1
        proof.verify(*string_utils::to_string(&(1 as u64)).bytes());

        // Generate proof for position 64
        proof = mmr.generate_proof(121);
        // Verify proof
        proof.verify(*string_utils::to_string(&(33 as u64)).bytes());

        // Generate proof for position 128
        proof = mmr.generate_proof(128);
        // Verify proof
        proof.verify(*string_utils::to_string(&(65 as u64)).bytes());
    
        // Generate proof for position 248
        proof = mmr.generate_proof(248);
        // Verify proof for leaf 128 at position 248
        proof.verify(*string_utils::to_string(&(128 as u64)).bytes());

        // Return MMR to storage
        mmr::return_mmr(mmr, &signer);
    }
}