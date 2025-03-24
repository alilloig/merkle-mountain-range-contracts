/// Provides helper functions for doing bitwise operations needed for handling the MMR
module mmr::mmr_bits;

/// Trying to create a u64 longer than 64 bits
#[error]
const Eu64Length: vector<u8> = b"Bit length must be less than or equal to 64";

/// Calculates the minimum number of bits needed to represent a number
/// 
/// This function computes the position of the most significant bit that is set to 1.
/// For example, for 13 (1101 in binary), the function returns 4 since the highest set bit is in position 4.
/// For 0, it returns 0 as a special case since no bits are needed to represent zero.
/// This is useful in MMR operations to determine tree heights and positions.
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

/// Counts the number of 1 bits in the binary representation of a number
/// 
/// This function determines the number of set bits (1s) in the binary representation.
/// It uses Brian Kernighan's algorithm which iteratively removes the least significant set bit.
/// For example, for 13 (1101 in binary), the function returns 3 as there are three 1s.
/// In MMR operations, this can be used to count the number of elements in certain paths or structures.
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

/// Checks if a number consists of all consecutive 1 bits from the least significant bit
/// 
/// This function determines if a number has the form 2^n - 1, which in binary is a sequence
/// of n consecutive 1 bits (e.g., 7 = 111, 15 = 1111, 31 = 11111).
/// Such numbers represent perfect binary trees in the MMR structure.
/// The implementation uses a bitwise trick: for any number of form 2^n - 1,
/// performing (num & (num+1)) will always result in 0 because:
/// - num has all 1s in its lowest n bits
/// - num+1 has a single 1 in position n+1 and all 0s in lower positions
/// - Their bitwise AND will therefore be 0
public fun are_all_ones(num: u64): bool {
    (num & (num + 1)) == 0
}

/// Creates a number with a specified number of least significant bits set to 1
/// 
/// This function generates a number with exactly 'bitsLength' consecutive 1 bits starting from the LSB.
/// For example, with bitsLength=3, it returns 7 (111 in binary).
/// The result has the form 2^bitsLength - 1, which creates a value with the desired bit pattern.
/// These patterns are useful in MMR operations for creating masks or identifying perfect subtrees.
/// The function checks that the requested bit length doesn't exceed 64 (the size of u64).
public fun create_all_ones(bitsLength: u8): u64 {
    assert!(bitsLength <= 64, Eu64Length);
    // Calculate 2^bitsLength - 1, which has 'bitsLength' 1s
    (1 << bitsLength) - 1
}