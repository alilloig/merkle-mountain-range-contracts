import Test

/* --- Executors --- */

access(all)
fun _deploy(_ name: String, _ path: String, _ arguments: [AnyStruct]) {
    let err = Test.deployContract(name: name, path: path, arguments: arguments)
    Test.expect(err, Test.beNil())
}

access(all)
fun _executeScript(_ path: String, _ args: [AnyStruct]): Test.ScriptResult {
    return Test.executeScript(Test.readFile(path), args)
}

access(all)
fun _assertScript(_ path: String, _ args: [AnyStruct], _ func: fun(AnyStruct?)) {
    let testResult = Test.executeScript(Test.readFile(path), args)
    Test.expect(testResult, Test.beSucceeded())
    assert(testResult.error == nil, message: getErrorMessage(testResult))
    func(testResult.returnValue)
}

access(all)
fun _executeTransaction(_ path: String, _ args: [AnyStruct], _ signer: Test.TestAccount): Test.TransactionResult {
    let txn = Test.Transaction(
        code: Test.readFile(path),
        authorizers: [signer.address],
        signers: [signer],
        arguments: args
    )
    let txResult = Test.executeTransaction(txn)
    Test.expect(txResult, Test.beSucceeded())
    return txResult
}


/* --- Time helper --- */

/// Moves test environment time to the provided timestamp
/// NOTE: Sometimes Test.moveTime is not exact, so caller may need to check the actual timestamp if precision is
///     critical to the use case
///
access(all)
fun moveTime(target: UFix64) {
    let now = getBlockTimestamp(at: nil) ?? panic("Problem getting current block timestamp")
    let delta = target > now ? Fix64(target - now) : Fix64(now - target)
    Test.moveTime(by: delta)
}

access(all)
fun assertResultWithinRange(_ val1: UFix64, _ val2: UFix64, delta: UFix64) {
    let diff = val1 > val2 ? val1 - val2 : val2 - val1
    assert(diff <= delta, message: "Difference in values exceeds delta=".concat(delta.toString()))
}

/* --- Script Helpers --- */

access(all)
fun typeAtStorage(_ address: Address, _ storagePath: StoragePath): Type? {
    let typeResult = _executeScript(
        "./scripts/type_at_storage.cdc",
        [address, storagePath]
    )
    assert(typeResult.error == nil, message: getErrorMessage(typeResult))
    return typeResult.returnValue as! Type?
}

access(all)
fun getBlockTimestamp(at: UInt64?): UFix64? {
    let timestampResult = _executeScript(
        "./scripts/get_block_timestamp.cdc",
        [at]
    )
    assert(timestampResult.error == nil, message: getErrorMessage(timestampResult))
    return timestampResult.returnValue as! UFix64?
}

access(all)
fun getBalance(_ address: Address): UFix64? {
    let balanceResult = _executeScript(
        "./scripts/get_balance.cdc",
        [address]
    )
    assert(balanceResult.error == nil, message: getErrorMessage(balanceResult))
    return balanceResult.returnValue as! UFix64?
}



/* --- Error Logging --- */

access(all)
fun getErrorMessage(_ res: {Test.Result}): String {
    if res.error != nil {
        return res.error?.message ?? "[ERROR] Unknown error occurred"
    }
    return ""
}