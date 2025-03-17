#[test_only]
module mmr::mmr_tests;

use mmr::mmr;

const ENotImplemented: u64 = 0;

#[test]
fun test_sui_merkle_mountain_range() {
    // pass
}

#[test, expected_failure(abort_code = ::mmr::mmr_tests::ENotImplemented)]
fun test_sui_merkle_mountain_range_fail() {
    abort ENotImplemented
}

