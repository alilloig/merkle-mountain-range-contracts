import "MerkleMountainRange"

access(all) fun main(account: Address, storagePath: StoragePath, attr: String): AnyStruct {

    let mmr = 
        getAuthAccount<auth(Storage, BorrowValue) &Account>(account).storage.borrow<&MerkleMountainRange.MMR>(from: storagePath)
        ?? panic("Could not borrow MMR")

    if attr == "size" {
        return mmr.getSize()
    } else if attr == "root" {
        return mmr.getRoot()
    } else if attr == "peaks" {
        return mmr.getPeaks()
    } else if attr == "nodes" {
        return mmr.getNodes()
    }
    
    panic("Must specify MMR.{attr} to return")
}