/// Helper contract for all bitwise operations needed for MMR positions calculations
/// Now that this functions are called by MMRBits.{something} maybe we can remove the bit out of the names
///
access(all) contract MMRBits {

    /// Calculates the minimum number of bits needed to represent a number
    ///
    /// @param n: Number to calculate bit length for
    /// @returns Number of bits in the binary representation
    ///
    access(all) view fun getLength(_ num: UInt64): UInt64 {
        if num == 0 {
            return 0
        }
        var x = num
        var count: UInt64 = 0
        // Count how many right shifts are needed until the number becomes 0
        while x > 0 {
            count = count + 1
            x = x >> 1
        }
        return count
    }

    /// Counts the number of 1 bits in the binary representation of a number
    ///
    /// @param num: Number to count bits for
    /// @return Count of 1 bits in the binary representation
    /// 
    access(all) fun countOnes(_ num: UInt64): UInt64 {
        var count: UInt64 = 0
        var n = num
        // Classic bit-counting algorithm: remove the lowest set bit in each iteration
        while n != 0 {
            n = n & (n - 1)  // This removes the lowest set bit
            count = count + 1
        }
        return count
    }

    /// Checks if a number consists of all consecutive 1 bits from the least significant bit
    /// This function determines if a number has the form 2^n - 1, which in binary is a sequence
    /// of n consecutive 1 bits (e.g., 7 = 111, 15 = 1111, 31 = 11111).
    /// Such numbers represent perfect binary trees in the MMR structure.
    /// The implementation uses a bitwise trick: for any number of form 2^n - 1,
    /// performing (num & (num+1)) will always result in 0 because:
    /// - num has all 1s in its lowest n bits
    /// - num+1 has a single 1 in position n+1 and all 0s in lower positions
    /// - Their bitwise AND will therefore be 0
    ///
    /// @param num: The number to check
    /// @return True if the number consists of all consecutive 1 bits, false otherwise
    ///
    access(all) fun areAllOnes(_ num: UInt64): Bool {
        return (num & (num + 1)) == 0
    }

    /// Creates a number with a specified number of least significant bits set to 1
    /// e.g., createAllBitsOnes(3) => 7 (binary 111). allOnes() in MMRUtil
    ///
    /// @param bitsLength: Number of bits to set to 1
    /// @return Number with specified number of bits set to 1
    /// 
    access(all) fun createAllOnes(_ bitsLength: UInt64): UInt64 {
        assert(bitsLength <= 64, message: "bitsLength must be less than or equal to 64")
        // Calculate 2^bitsLength - 1, which has 'bitsLength' 1s
        return (1 << bitsLength) - 1
    }
    
}