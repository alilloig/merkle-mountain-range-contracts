import Test
import "test_helpers.cdc"
import "MMRBits"
import "MMRUtils"
import "MerkleMountainRange"

// Test accounts setup
access(all) let adminAccount = Test.getAccount(0x0000000000000007)
access(all) let account = Test.createAccount()

// Storage path for the MMR resource
access(all) let mmrStoragePath = /storage/mmrStoragePath

// Helper function to assert MMR properties through scripts
access(self) let assertMmrProperty = fun(attrKey: String, func: fun(AnyStruct)) {
    _assertScript("./scripts/mmr/check_mmr.cdc", [account.address, mmrStoragePath, attrKey], fun(scriptResult: AnyStruct?) {  
        func(scriptResult)
    })
} 

// Setup function that deploys necessary contracts for testing
access(all) fun setup() {
    _deploy("MMRBits", "../contracts/MMRBits.cdc", [])
    _deploy("MMRUtilAux", "../contracts/MMRUtilAux.cdc", [])
    _deploy("MerkleMountainRange", "../contracts/MerkleMountainRange.cdc", [])
}

// Runs before each test to set up a fresh MMR
access(all) fun beforeEach () {
    _executeTransaction("./transactions/mmr/setup.cdc", [mmrStoragePath], account)
    assertFullMMRState(size: 0, root: MMRUtilAux.hash(UInt8(0).toBigEndianBytes()), peaks: [])
}

// Cleanup after each test
access(all) fun afterEach () {
    _executeTransaction("./transactions/mmr/destroy.cdc", [mmrStoragePath], account)
}

// Helper function to assert the complete state of an MMR
access(self) fun assertFullMMRState(size: UInt64, root: [UInt8], peaks: [[UInt8]]) {
    assertMmrProperty(attrKey: "size", fun(scriptResult: AnyStruct) {
        Test.assertEqual(size, scriptResult! as! UInt64)
    })
    assertMmrProperty(attrKey: "root", fun(scriptResult: AnyStruct) {
        Test.assertEqual(root, scriptResult! as! [UInt8])
    })
    assertMmrProperty(attrKey: "peaks", fun(scriptResult: AnyStruct) {
        Test.assertEqual(peaks, scriptResult! as! [[UInt8]])
    })
}

// Utility function to convert a string to bytes
access(all) fun stringToBytes(_ str: String): [UInt8] {
    var bytes: [UInt8] = []
    for char in str.utf8 {
        bytes.append(char.toBigEndianBytes()[0])
    }
    return bytes
}

// Helper function to hash a string
access(all) fun hashBytesFromString(_ data: String): [UInt8] {
    return MMRUtilAux.hash(stringToBytes(data))
}

// Helper function to hash a string with its position
access(all) fun hashToIndexBytesFromString(_ pos: UInt64, _ data: String): [UInt8] {
    return MMRUtilAux.hashWithInteger(pos, [stringToBytes(data)])
}

// Creates a leaf string for a given position
access(self) fun createLeafString(_ pos: UInt64): String {
    return "leaf".concat(pos.toString())
}

// Tests the generation and validation of inclusion proofs
// Verifies that proofs can be generated for elements in the MMR and that these proofs can be validated
access(all) fun testGenerateAndValidateProofMultiTree() {

    // Add 95 leaves to the MMR
    var leafCounter: UInt64 = 1
    while leafCounter <= 95 {
        _executeTransaction("./transactions/mmr/append_leaves.cdc", [mmrStoragePath, [stringToBytes(createLeafString(leafCounter))]], account)
        leafCounter = leafCounter + 1
    }

    // Get the root commitment for verification
    var rootCommitment: [UInt8] = []
    assertMmrProperty(attrKey: "root", fun(scriptResult: AnyStruct) {
        rootCommitment = (scriptResult! as! [UInt8])
    })

    // Check that the MMR has 184 nodes
    var nodes: [[UInt8]] = []
    assertMmrProperty(attrKey: "nodes", fun(scriptResult: AnyStruct) {
        nodes = (scriptResult! as! [[UInt8]])
        Test.assertEqual(184, nodes.length)  // Verify expected size
    }) 

    // Test proof generation and verification for position 1
    let position1: UInt64 = 1
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position1], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 1 at position 1
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(1))))
    })
    
    
    // Test proof generation and verification for position 27
    let position27: UInt64 = 27
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position27], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 16 at position 27
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(16))))
    })

    // Test proof generation and verification for position 32
    let position32: UInt64 = 32
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position32], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 17 at position 32
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(17))))
    })

    // Test proof generation and verification for position 58
    let position58: UInt64 = 58
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position58], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 32 at position 58
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(32))))
    })

    // Test proof generation and verification for position 64
    let position64: UInt64 = 64
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position64], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 33 at position 64
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(33))))
    })

    // Test proof generation and verification for position 121
    let position121: UInt64 = 121
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position121], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 64 at position 121
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(64))))
    })

    // Test proof generation and verification for position 128
    let position128: UInt64 = 128
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position128], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 65 at position 128
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(65))))
    })

    // Test proof generation and verification for position 163
    let position163: UInt64 = 163
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position163], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 84 at position 163
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(84))))
    })

    // Test proof generation and verification for position 174
    let position174: UInt64 = 174
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position174], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 89 at position 174
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(89))))
    })

    // Test proof generation and verification for position 184
    let position184: UInt64 = 184
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position184], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 95 at position 184
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(95))))
    })
}

access(all) fun testGenerateAndValidateProofSinglePerfectTree() {
    // Add 32 leaves to the MMR
    var leafCounter: UInt64 = 1
    while leafCounter <= 32 {
        _executeTransaction("./transactions/mmr/append_leaves.cdc", [mmrStoragePath, [stringToBytes(createLeafString(leafCounter))]], account)
        leafCounter = leafCounter + 1
    }

    // Get the root commitment for verification
    var rootCommitment: [UInt8] = []
    assertMmrProperty(attrKey: "root", fun(scriptResult: AnyStruct) {
        rootCommitment = (scriptResult! as! [UInt8])
    })

    // Check that the MMR has 63 nodes
    var nodes: [[UInt8]] = []
    assertMmrProperty(attrKey: "nodes", fun(scriptResult: AnyStruct) {
        nodes = (scriptResult! as! [[UInt8]])
        Test.assertEqual(63, nodes.length)  // Verify expected size
    }) 

    // Test proof generation and verification for position 1
    let position1: UInt64 = 1
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position1], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 1 at position 1
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(1))))
    })
    
    // Test proof generation and verification for position 27
    let position27: UInt64 = 27
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position27], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 16 at position 27
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(16))))
    })

    // Test proof generation and verification for position 32
    let position32: UInt64 = 32
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position32], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 17 at position 32
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(17))))
    })

    // Test proof generation and verification for position 58
    let position58: UInt64 = 58
    _assertScript("./scripts/mmr/get_proof.cdc", [account.address, mmrStoragePath, position58], fun(scriptResult: AnyStruct?) {
        let generatedProof = scriptResult! as! MerkleMountainRange.Proof
        // Verify the proof for leaf 32 at position 58
        Test.assert(generatedProof.verify(data: stringToBytes(createLeafString(32))))
    })

}


