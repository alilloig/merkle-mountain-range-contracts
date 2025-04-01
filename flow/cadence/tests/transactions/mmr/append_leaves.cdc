import "MerkleMountainRange"

/// TEST TRANSACTION
///
/// Insert leaves into MMR
///
transaction(storagePath: StoragePath, leaves: [[UInt8]]) {
    prepare(signer: auth(BorrowValue, IssueStorageCapabilityController) &Account) {
        let mmr: &MerkleMountainRange.MMR = signer.storage.borrow<&MerkleMountainRange.MMR>(from: storagePath) 
            ?? panic("Need to have initialized the MMR into the account")

        mmr.appendLeaves(leavesData: leaves)
    }
}