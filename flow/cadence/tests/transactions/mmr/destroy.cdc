import "MerkleMountainRange"

/// TEST TRANSACTION
///
/// Destroy the MMR resource in the account
///
transaction(storagePath: StoragePath) {
    prepare(signer: auth(LoadValue, IssueStorageCapabilityController) &Account) {
        destroy signer.storage.load<@MerkleMountainRange.MMR>(from: storagePath)
    }
}