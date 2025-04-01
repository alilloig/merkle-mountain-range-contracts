import "MerkleMountainRange"

access(all) fun main(account: Address, storagePath: StoragePath, pos: UInt64): AnyStruct {

    let mmr = 
        getAuthAccount<auth(Storage, BorrowValue) &Account>(account).storage.borrow<&MerkleMountainRange.MMR>(from: storagePath)
        ?? panic("Could not borrow MMR")

    let proof = mmr.generateProof(pos: pos)
    return proof
}