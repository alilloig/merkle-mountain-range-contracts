import "MerkleMountainRange"

/// TEST TRANSACTION
///
/// Save a new MMR resource into the account 
///
transaction(storagePath: StoragePath) {
    prepare(signer: auth(SaveValue, IssueStorageCapabilityController) &Account) {
        if signer.storage.type(at: storagePath) != nil {
            panic("TEST FAILURE: storage in use")
        }

        signer.storage.save(<- MerkleMountainRange.createMMR(), to: storagePath)
    }
}