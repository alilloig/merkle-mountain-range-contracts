/// Bitwise helpers for Merkle Mountain Range position math.
module mmr::mmr_bits;

/// Requested 64 or more one-bits; `1 << 64` does not fit a `u64`.
#[error]
const Eu64Length: vector<u8> = b"Bit length must be less than 64";

/// Return the minimum number of bits needed to represent `num` (0 for 0). Example: 13 -> 4.
public fun get_length(num: u64): u8 {
    if (num == 0) {
        return 0
    };
    let mut x = num;
    let mut count: u8 = 0;
    // Count how many right shifts are needed until the number becomes 0
    while (x > 0) {
        count = count + 1;
        x = x >> 1;
    };
    count
}

/// Return the number of one-bits in `num` (Kernighan's algorithm). Example: 13 -> 3.
public fun count_ones(num: u64): u64 {
    let mut count: u64 = 0;
    let mut n = num;
    // Classic bit-counting algorithm: remove the lowest set bit in each iteration
    while (n != 0) {
        n = n & (n - 1);  // This removes the lowest set bit
        count = count + 1;
    };
    count
}

/// Return true when `num` has the form 2^k - 1 (all one-bits from the least significant bit).
/// Such numbers are the sizes of perfect binary trees in an MMR.
public fun are_all_ones(num: u64): bool {
    (num & (num + 1)) == 0
}

/// Return the number with exactly `bits_length` least significant one-bits (2^bits_length - 1).
/// `bits_length` must be at most 63; aborts with `Eu64Length` otherwise.
public fun create_all_ones(bits_length: u8): u64 {
    assert!(bits_length < 64, Eu64Length);
    // Calculate 2^bits_length - 1, which has 'bits_length' 1s
    (1 << bits_length) - 1
}
