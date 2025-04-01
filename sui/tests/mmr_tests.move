#[test_only]
module mmr::mmr_tests;

use mmr::mmr;
use sui::test_scenario;
use sui::test_utils;

#[test]
fun test_mmr_setup() {
    // Create a test scenario with the owner as sender
    let owner = @0xCAFE;
    let mut scenario = test_scenario::begin(owner);
    // First transaction: Create the MMR
    {
        let ctx = test_scenario::ctx(&mut scenario);
        mmr::create_mmr(ctx);
    };
    // Second transaction: Access the MMR and append leaves
    scenario.next_tx(owner);
    {
        // Get the MMR object from the previous transaction
        let mut mmr = test_scenario::take_from_sender<mmr::MMR>(&scenario);
        // Create some test leaf data
        let leaves = vector[
            b"leaf1",
            b"leaf2",
            b"leaf3"
        ];
        // Append leaves to the MMR
        mmr::append_leaves(&mut mmr, leaves);
        // Check that the MMR size corresponds to the amount of leaves created
        test_utils::assert_eq(mmr.get_size(), 4);
        // Return the MMR to the owner
        test_scenario::return_to_sender(&scenario, mmr);
    };
    // End the scenario
    test_scenario::end(scenario);
}

#[test]
fun test_generate_and_verify_proofs() {
    
    // Create a test scenario with the owner as sender
    let owner = @0xCAFE;
    let mut scenario = test_scenario::begin(owner);
    
    // First transaction: Create the MMR
    {
        let ctx = test_scenario::ctx(&mut scenario);
        mmr::create_mmr(ctx);
    };
    
    // Second transaction: Access the MMR and append leaves
    scenario.next_tx(owner);
    {
        // Get the MMR object from the previous transaction
        let mut mmr = test_scenario::take_from_sender<mmr::MMR>(&scenario);
        // Create 95 leafs which will produce a 184 nodes MMR
        let mut leafCounter: u64 = 1;
        let mut leafData: vector<u8>;
        let mut leaves = vector::empty<vector<u8>>();
        while (leafCounter <= 95) {
            leafData = leafCounter.to_string().into_bytes();
            leaves.push_back(leafData);
            leafCounter = leafCounter + 1;
        };
        // Append leaves to the MMR
        mmr::append_leaves(&mut mmr, leaves);
        // Check that the MMR size corresponds to the amount of leaves created
        test_utils::assert_eq(mmr.get_size(), 184);
        // Return the MMR to the owner
        test_scenario::return_to_sender(&scenario, mmr);
    };
    
    // Third transaction: Generate and verify proofs for multiple positions
    scenario.next_tx(owner);    
    {
        // Get the MMR object from the previous transaction
        let mmr = test_scenario::take_from_sender<mmr::MMR>(&scenario);
        let mut proof: mmr::Proof;

        // Generate proof for position 1
        proof = mmr.generate_proof(1);
        // Verify proof for leaf 1 at position 1
        proof.verify((1 as u64).to_string().into_bytes());

        // Generate proof for position 27
        proof = mmr.generate_proof(27);
        // Verify proof for leaf 16 at position 27
        proof.verify((16 as u64).to_string().into_bytes());

        // Generate proof for position 32
        proof = mmr.generate_proof(32);
        // Verify proof
        proof.verify((17 as u64).to_string().into_bytes());

        // Generate proof for position 58
        proof = mmr.generate_proof(58);
        // Verify proof
        proof.verify((32 as u64).to_string().into_bytes());

        // Generate proof for position 64
        proof = mmr.generate_proof(121);
        // Verify proof
        proof.verify((33 as u64).to_string().into_bytes());

        // Generate proof for position 128
        proof = mmr.generate_proof(128);
        // Verify proof
        proof.verify((65 as u64).to_string().into_bytes());

        // Generate proof for position 163
        proof = mmr.generate_proof(163);
        // Verify proof
        proof.verify((84 as u64).to_string().into_bytes());

        // Generate proof for position 174
        proof = mmr.generate_proof(174);
        // Verify proof for leaf 89 at position 174
        proof.verify((89 as u64).to_string().into_bytes());

        // Generate proof for position 184
        proof = mmr.generate_proof(184);
        // Verify proof for leaf 95 at position 184
        proof.verify((95 as u64).to_string().into_bytes());

        // Return the MMR to the owner
        test_scenario::return_to_sender(&scenario, mmr);
    };

    // End the scenario
    test_scenario::end(scenario);
}

#[test]
fun test_generate_and_verify_proofs_for_large_single_perfect_tree_mmr() {
    
    // Create a test scenario with the owner as sender
    let owner = @0xCAFE;
    let mut scenario = test_scenario::begin(owner);
    
    // First transaction: Create the MMR
    {
        let ctx = test_scenario::ctx(&mut scenario);
        mmr::create_mmr(ctx);
    };
    
    // Second transaction: Access the MMR and append leaves
    scenario.next_tx(owner);
    {
        // Get the MMR object from the previous transaction
        let mut mmr = test_scenario::take_from_sender<mmr::MMR>(&scenario);
        // Create 95 leafs which will produce a 184 nodes MMR
        let mut leafCounter: u64 = 1;
        let mut leafData: vector<u8>;
        let mut leaves = vector::empty<vector<u8>>();
        while (leafCounter <= 128) {
            leafData = leafCounter.to_string().into_bytes();
            leaves.push_back(leafData);
            leafCounter = leafCounter + 1;
        };
        // Append leaves to the MMR
        mmr::append_leaves(&mut mmr, leaves);
        // Check that the MMR size corresponds to the amount of leaves created
        test_utils::assert_eq(mmr.get_size(), 255);
        // Return the MMR to the owner
        test_scenario::return_to_sender(&scenario, mmr);
    };

    // Third transaction: Generate and verify proofs
    scenario.next_tx(owner);    
    {
        // Get the MMR object from the previous transaction
        let mmr = test_scenario::take_from_sender<mmr::MMR>(&scenario);
        let mut proof: mmr::Proof;

        // Generate proof for position 1
        proof = mmr.generate_proof(1);
        // Verify proof for leaf 1 at position 1
        proof.verify((1 as u64).to_string().into_bytes());

        // Generate proof for position 64
        proof = mmr.generate_proof(121);
        // Verify proof
        proof.verify((33 as u64).to_string().into_bytes());

        // Generate proof for position 128
        proof = mmr.generate_proof(128);
        // Verify proof
        proof.verify((65 as u64).to_string().into_bytes());
   
        // Generate proof for position 248
        proof = mmr.generate_proof(248);
        // Verify proof for leaf 128 at position 248
        proof.verify((128 as u64).to_string().into_bytes());

        // Return the MMR to the owner
        test_scenario::return_to_sender(&scenario, mmr);
    };

    // End the scenario
    test_scenario::end(scenario);
}