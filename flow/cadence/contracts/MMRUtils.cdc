import "Crypto"
import "MMRBits"

/// Auxiliary contract with double checked functions for fixing proof generation and verification
/// behavior.
///
access(all) contract MMRUtilAux {

    /// ProofPositions struct holds all the positions needed for a proof
    /// This is used to organize the different parts of an MMR inclusion proof
    ///
    access(all) struct ProofPositions {

        // Positions of nodes in the path from the element to its local peak
        access(all) let localTreePathPositions: [UInt64]
        // Positions of peaks to the left of the element's peak
        access(all) let leftPeaksPositions: [UInt64]
        // Positions of peaks to the right of the element's peak
        access(all) let rightPeaksPositions: [UInt64]

        /// Returns the hashes for nodes in the local tree path
        ///
        /// @param nodes: Array of all node hashes in the MMR
        /// @return Array of hashes for the local tree path
        ///
        access(all) fun getLocalTreePathHashes(_ nodesHashes: [[UInt8]]): [[UInt8]] {
            return MMRUtilAux.getHashesFromPositions(nodesHashes, self.localTreePathPositions)
        }

        /// Returns the hashes for peaks to the left of the element's peak
        ///
        /// @param nodes: Array of all node hashes in the MMR
        /// @return Array of hashes for left-side peaks
        ///
        access(all) fun getLeftPeaksHashes(_ nodesHashes: [[UInt8]]): [[UInt8]] {
            return MMRUtilAux.getHashesFromPositions(nodesHashes, self.leftPeaksPositions)
        }

        /// Returns the hashes for peaks to the right of the element's peak
        ///
        /// @param nodes: Array of all node hashes in the MMR
        /// @return Array of hashes for right-side peaks
        ///
        access(all) fun getRightPeaksHashes(_ nodesHashes: [[UInt8]]): [[UInt8]] {
            return MMRUtilAux.getHashesFromPositions(nodesHashes, self.rightPeaksPositions)
        }

        /// Constructor initializes all position arrays
        ///
        /// @param peakPos: Position of the peak for the local tree containing the element
        /// @param localTreePathPositions: Positions of nodes in the path from the element to its local peak
        /// @param rightPeaksPositions: Positions of peaks to the right of the element's peak
        /// @param leftPeaksPositions: Positions of peaks to the left of the element's peak
        ///
        init(localTreePathPositions: [UInt64], leftPeaksPositions: [UInt64], rightPeaksPositions: [UInt64]) {
            self.localTreePathPositions = localTreePathPositions
            self.leftPeaksPositions = leftPeaksPositions
            self.rightPeaksPositions = rightPeaksPositions
        }
    }

    /// Calculates all positions needed for an inclusion proof
    /// This includes the local path, and peaks to the left and right
    ///
    /// @param size: Total number of nodes in the MMR
    /// @param pos: Position to generate proof for
    /// @return ProofPathPositions struct with all needed positions
    ///
    access(all) fun calcProofPositions(_ position: UInt64, _ size: UInt64): ProofPositions {
        // Get the local tree path positions
        var treePathPositions: [UInt64] = self.calcProofTreePathPositions(position, size)
        // Peak position for the proof local tree is the parent of the last position in path if
        // the proof isn't for a leaf node
        var pathPeakPosition: UInt64 = 0
        if (treePathPositions.length != 0) {
            pathPeakPosition = MMRUtilAux.getParentPosition(treePathPositions[treePathPositions.length - 1])
        } else {
            // If is a leaf node the tree path will be empty and the peak will be itself
            pathPeakPosition = position
        }
        // Get all peaks in the MMR
        let peaksPositions = self.getPeaksPositions(size)
        var leftPeaksPositions: [UInt64] = []        
        var rightPeaksPositions: [UInt64] = []
        // If MMR is not a perfect binary tree or an empty tree
        if (peaksPositions.length > 1) {
            // Collect peaks to the left of the element's peak
            leftPeaksPositions = self.getLeftPeaksPositions(pathPeakPosition, peaksPositions)
            // Collect peaks to the right of the element's peak
            rightPeaksPositions = self.getRightPeaksPositions(pathPeakPosition, peaksPositions)
        }
        return ProofPositions(
            localTreePathPositions: treePathPositions,
            leftPeaksPositions: leftPeaksPositions,
            rightPeaksPositions: rightPeaksPositions
        )
    }

    /// Calculates the proof path (node positions) to his local tree peak in a MMR.
    ///
    /// @param proofPosition: Position to generate proof for
    /// @param size: Total number of nodes in the MMR
    /// @return Array of positions for the proof path including the tree's peak
    ///
    access(all) fun calcProofTreePathPositions(_ proofPosition: UInt64, _ size: UInt64): [UInt64] {
        var pathPositions: [UInt64] = []
        var currentNodePosition: UInt64 = 0
        var siblingPosition: UInt64 = 0
        // Handle special case when position is last node (leaf-peak)
        if (proofPosition != size) {
            // navigate the binary tree from the leaf to the peak, storing each node that would be 
            // necessary to calculate the peak hash
            currentNodePosition = proofPosition
            while (currentNodePosition <= size) {
                // store the sibling position we need for computing the next level node
                siblingPosition = self.getSiblingPosition(currentNodePosition)
                pathPositions.append(siblingPosition)
                // calculate the parent node position for the next iteration
                currentNodePosition = self.getParentPosition(currentNodePosition)
            }
            // Algorithm always stores one more node than necessary so we need to trim it
            pathPositions.removeLast()
        }
        return pathPositions
    }

    /// Calculates all peak positions in an MMR of a given size
    /// Peaks are the roots of the perfect binary trees that make up the MMR
    ///
    /// @param size: Total number of nodes in the MMR
    /// @return Array of positions of all peaks in the MMR
    /// 
    access(all) fun getPeaksPositions(_ size: UInt64): [UInt64] {
        var peaksPositions: [UInt64] = []
        // Empty MMR has no peaks
        if (size == 0) { return peaksPositions }
        // Check if the MMR is a perfect binary tree so the size is the position of the only peak
        if (MMRBits.areAllOnes(size)) {
            peaksPositions.append(size)
        } else {
            // If the MMR is multi tree, calculate the height of the largest perfect binary tree 
            // that can fit a MMR of this size
            var largestTreeHeight = MMRBits.getLength(size) - 1
            // Use the height to calculate the largest, and therefor leftmost, tree size
            var treeSize = MMRBits.createAllOnes(largestTreeHeight)
            // Iterate over all perfect trees inside the MMR, storing how many nodes are outside the
            // tree we store the peak position on each iteration
            var nodesLeft = size
            var peakPosition: UInt64 = 0
            while (treeSize != 0) {
                // If the amount of nodes left to check is smaller than the tree size, that means 
                // that that peak is not in the MMR and we just need to get the next smaller tree
                if (nodesLeft >= treeSize) {
                    nodesLeft = nodesLeft - treeSize
                    peakPosition = peakPosition + treeSize
                    // Peaks positions are stored from left to right
                    peaksPositions.append(peakPosition)
                }
                // Calculate the next smaller perfect binary tree size
                treeSize = treeSize >> 1
            }
        }
        return peaksPositions
    }

    /// Collects positions of peaks to the left of a given peak
    /// 
    /// @param peakPosition: Position of the reference peak
    /// @param peaksPositions: Array of all peak positions
    /// @return Array of positions for peaks to the left
    ///
    access(all) fun getLeftPeaksPositions(_ peakPosition: UInt64, _ peaksPositions: [UInt64]): [UInt64] {
        var leftPeaksPositions: [UInt64] = []
        for peak in peaksPositions {
            if peak < peakPosition {
                leftPeaksPositions.append(peak)
            }
        }
        return leftPeaksPositions
    }

    /// Collects positions of peaks to the right of a given peak
    /// 
    /// @param peakPosition: Position of the reference peak
    /// @param peaksPositions: Array of all peak positions
    /// @return Array of positions for peaks to the right
    ///
    access(all) fun getRightPeaksPositions(_ peakPosition: UInt64, _ peaksPositions: [UInt64]): [UInt64] {
        var rightPeaksPositions: [UInt64] = []
        for peak in peaksPositions {
            if peak > peakPosition {
                rightPeaksPositions.append(peak)
            }
        }
        return rightPeaksPositions
    }

    /// Calculates the position of a node's parent in the MMR
    /// In a Merkle Mountain Range, each node (except for the peaks) has a parent.
    /// This function determines the position of the parent node by:
    /// 1. Checking if the node is a right or left sibling using isRightSibling()
    /// 2. For right siblings, the parent is at position + 1
    /// 3. For left siblings, the parent is at the right sibling's position + 1
    ///
    /// @param position: The 1-based position of the node in the MMR
    /// @return The 1-based position of the node's parent in the MMR
    ///
    access(all) fun getParentPosition(_ position: UInt64): UInt64 {
            var parentPosition: UInt64 = 0
            if (self.isRightSibling(position)) {
                parentPosition = position + 1
            } else {
                parentPosition = self.getSiblingPosition(position) + 1
            }
            return parentPosition       
    }

    /// Calculates the position of a node's sibling in the MMR
    /// In a Merkle Mountain Range, each node (except peaks) has a sibling. This function
    /// determines the position of the sibling for a given node by:
    /// 1. Checking if the node is a right or left sibling using isRightSibling()
    /// 2. Calculating the appropriate offset based on the node's height
    /// 3. Adding or subtracting the offset depending on whether the node is a left or right sibling
    ///
    /// @param position: The 1-based position of the node in the MMR
    /// @return The 1-based position of the node's sibling in the MMR
    ///
    access(all) fun getSiblingPosition(_ position: UInt64): UInt64 {
        var siblingPosition: UInt64 = 0
        if (self.isRightSibling(position)) {
            siblingPosition = position - self.siblingOffset(self.getHeight(position))
        } else {
            siblingPosition = position + self.siblingOffset(self.getHeight(position))
        }        
        return siblingPosition
    }

    /// Determines if a node is a right sibling in the MMR
    /// This function checks if a node at the given position is a right sibling by getting the 
    /// sibling offset at the node height and comparing that height with the height of the node on
    /// position plus offset
    ///
    /// @param position: The 1-based position of the node in the MMR
    /// @return True if the node is a right sibling, false if is a left one
    ///
    access(all) fun isRightSibling(_ position: UInt64): Bool {
        // Ensure position is a valid MMR node
        assert(position > 0, message: "Nodes start at 1")
        // If the node is at the same height as the node on position + offset, its a left node
        let height = self.getHeight(position)
        let siblingOffset = self.siblingOffset(height)
        if (height == self.getHeight(position + siblingOffset)) {
            return false
        } else {
            return true
        }
    }

    /// Calculates the offset to find a sibling node at a given height
    ///
    /// @param height: Height of the node
    /// @return Offset to the sibling
    ///
    access(all) fun siblingOffset(_ height: UInt64): UInt64 {
        // Using 1-based height probably we don't need this but for now is nice for readability
        return MMRBits.createAllOnes(height) 
    }

    /// Function for getting the height of a node given its position
    ///
    /// @param position: The 1-based position of the node in a MMR
    /// @return The 1-based level height of the node
    ///
    access(all) fun getHeight(_ position: UInt64): UInt64 {
        // We are looking for the leftmost node at the node level, we start our search from the position itself
        var leftMostNode = position
        // Leftmost nodes bit representation have all their bits set to one, if the current isn't
        // jump to the next* node on the left
        while !MMRBits.areAllOnes(leftMostNode) {
            leftMostNode = self.jumpLeft(leftMostNode)
        }
        // The height of a level can be obtained by getting the length of the binary representation
        // of the leftmost node of that level, e.g. 7(111), length 3, height 3
        return MMRBits.getLength(leftMostNode)
    }

    /// Navigates leftward in the MMR tree structure by removing the rightmost 1 bit and trailing zeros
    /// This function is used to traverse the MMR structure horizontally at the same height level.
    /// When called on a node position, it returns the position of another node to the left
    /// that is at the same height in the tree structure.
    /// The implementation works by:
    /// 1. Finding the most significant bit (MSB) of the position
    /// 2. Removing all bits to the right of the MSB (by subtracting them)
    /// When called recursively, this function can be used to navigate to the leftmost node
    /// at the same height level, which is useful for determining node properties in the MMR.
    /// 
    /// For example:
    /// - For position 6 (binary 110), the MSB is at position 2 (value 4), and jumpLeft returns 4
    /// - For position 11 (binary 1011), the MSB is at position 3 (value 8), and jumpLeft returns 8
    ///
    /// @param pos: The current position in the MMR
    /// @return The position of a node to the left at the same height
    ///
    access(all) fun jumpLeft (_ position: UInt64): UInt64 {
        // Find the most significant bit position
        let mostSignificantBit: UInt64 = 1 << (MMRBits.getLength(position) - 1)
        // Subtract all bits to the right of the MSB
        return position - (mostSignificantBit - 1)
    }

    /// Helper function to extract a subset of hashes at certain positions
    ///
    /// @param nodes: Array of all node hashes in the MMR
    /// @param positions: Array of positions to extract
    /// @return Array of hashes at the specified positions
    ///
    access(all) fun getHashesFromPositions(_ nodesHashes: [[UInt8]], _ positions: [UInt64]): [[UInt8]] {
        var hashes: [[UInt8]] = []
        for position in positions {
            hashes.append(nodesHashes[position - 1])
        }
        return hashes
    }

    /// Combines multiple hashes with an integer and hashes the result
    /// This is used for creating a new leaf node by hashing its data with its position, a parent 
    /// node by hashing its child nodes along its position and for calculating the root bagging all 
    /// the peaks on the MMR together with the MMR size
    ///
    /// @param number: Integer to include in the hash
    /// @param hashes: Array of hashes to combine
    /// @return A combined hash that incorporates the integer and all provided hashes
    ///
    access(all) fun hashWithInteger(_ number: UInt64, _ hashes: [[UInt8]]): [UInt8] {
        // Concatenate all hashes together
        var root: [UInt8] = []
        for hash in hashes  {
            root = root.concat(hash)
        }
        // Hash the position (converted to bytes) with the concatenated hashes
        return self.hash(number.toBigEndianBytes().concat(root))
    }

    /// Generic hash function that uses SHA3_256 by default
    /// 
    /// @parameter data: Bytes to hash
    /// @return SHA3_256 hash of the input data
    ///
    access(all) fun hash(_ data: [UInt8]): [UInt8] {
        return self.hashUsingAlgo(data, HashAlgorithm.SHA3_256)
    }
    
    /// Hash function that allows specifying the algorithm to use
    ///
    /// @param data: Bytes to hash
    /// @param algorithm: Hashing algorithm to use
    /// @returns Hash of the input data using the specified algorithm
    ///
    access(all) fun hashUsingAlgo(_ data: [UInt8], _ algorithm: HashAlgorithm): [UInt8] {
        return Crypto.hash(data, algorithm: algorithm)
    }
}