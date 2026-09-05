#[test_only]
module mmr::mmr_bits_tests;

use std::unit_test::assert_eq;
use mmr::mmr_bits;

#[test]
fun get_length_known_values() {
    assert_eq!(mmr_bits::get_length(0), 0);
    assert_eq!(mmr_bits::get_length(1), 1);
    assert_eq!(mmr_bits::get_length(13), 4);
    assert_eq!(mmr_bits::get_length(255), 8);
    assert_eq!(mmr_bits::get_length(std::u64::max_value!()), 64);
}

#[test]
fun count_ones_known_values() {
    assert_eq!(mmr_bits::count_ones(0), 0);
    assert_eq!(mmr_bits::count_ones(13), 3);
    assert_eq!(mmr_bits::count_ones(255), 8);
}

#[test]
fun are_all_ones_known_values() {
    assert!(mmr_bits::are_all_ones(0));
    assert!(mmr_bits::are_all_ones(1));
    assert!(mmr_bits::are_all_ones(7));
    assert!(mmr_bits::are_all_ones(15));
    assert!(!mmr_bits::are_all_ones(8));
    assert!(!mmr_bits::are_all_ones(13));
}

#[test]
fun create_all_ones_known_values() {
    assert_eq!(mmr_bits::create_all_ones(0), 0);
    assert_eq!(mmr_bits::create_all_ones(3), 7);
    assert_eq!(mmr_bits::create_all_ones(63), (1u64 << 63) - 1);
}

#[test, expected_failure(abort_code = mmr_bits::Eu64Length)]
fun create_all_ones_64_aborts() {
    mmr_bits::create_all_ones(64);
}

#[test, expected_failure(abort_code = mmr_bits::Eu64Length)]
fun create_all_ones_255_aborts() {
    mmr_bits::create_all_ones(255);
}

/// Pins the documented precondition of `are_all_ones`: `num + 1` overflows at u64::MAX.
#[test, expected_failure(arithmetic_error, location = mmr::mmr_bits)]
fun are_all_ones_u64_max_overflows() {
    mmr_bits::are_all_ones(std::u64::max_value!());
}

/// Every 2^k - 1 up to k = 63 round-trips through `create_all_ones`, `are_all_ones`,
/// `get_length` and `count_ones`; 2^k has one bit and is never all-ones for k > 0.
#[test]
fun all_ones_round_trip_every_length() {
    64u8.do!(|k| {
        let n = mmr_bits::create_all_ones(k);
        assert!(mmr_bits::are_all_ones(n));
        assert_eq!(mmr_bits::get_length(n), k);
        assert_eq!(mmr_bits::count_ones(n), k as u64);
        assert_eq!(mmr_bits::count_ones(n + 1), 1);
        if (k > 0) assert!(!mmr_bits::are_all_ones(n + 1));
    });
}
