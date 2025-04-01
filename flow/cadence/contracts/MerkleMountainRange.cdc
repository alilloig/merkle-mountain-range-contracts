import "MMRUtils"

/**
 * MerkleMountainRange contract
 * 
 * This contract implements a Merkle Mountain Range (MMR) data structure, which is an efficient 
 * append-only accumulator for cryptographic commitments. MMRs are a collection of perfect binary 
 * trees arranged as a series of "peaks" that can be efficiently appended to and proven against.
 * It uses the MMRUtil to derive all the positions needed which it then handles for hash merging and peak bagging
 * 
 * MMRs are particularly useful for lightweight clients, as they allow verifying the inclusion of
 * elements without needing to store the entire dataset. The design is loosely modeled on 
 * https://github.com/jjyr/mmr.py/blob/master/mmr/mmr.py
 */
access(all) contract MerkleMountainRange {

    // Event emitted when the MMR root is updated
    access(all) event MMRRootUpdated(rootCommitment: [UInt8], peaks: [[UInt8]], newSize: UInt64)

    // Constant representing an empty or invalid root
    access(all) let NO_ROOT: [UInt8]
    
    /// Proof struct that contains all necessary data for verifying the inclusion
    /// of an element in the MMR without needing the entire structure
    /// 
    /// The proof includes:
    /// - The position of the element in the MMR
    /// - Hashes from the local tree path (for verification up to the peak)
    /// - Hashes from peaks to the left and right of the element's peak
    /// - The root hash for verification
    /// - The size of the MMR when the proof was generated
    ///
    access(all) struct Proof {

        // Position of the element this proof is for
        access(contract) let position: UInt64
        // Hashes needed to recompute the element's path to its peak
        access(contract) let localTreePathHashes: [[UInt8]]        
        // Hashes of peaks to the left of the element's peak
        access(contract) let leftPeaksHashes: [[UInt8]]
        // Hashes of peaks to the right of the element's peak
        access(contract) let rightPeaksHashes: [[UInt8]]
        // The root hash to verify against
        access(contract) let rootHash: [UInt8]
        // Size of the MMR when this proof was generated
        access(contract) let mmrSize: UInt64

        /// Returns the position of the element in the MMR that this proof is for
        /// 
        /// @return The 1-based position of the element in the MMR
        ///
        access(all) view fun getPosition(): UInt64 {
            return self.position
        }

        /// Returns the root hash of the MMR at the time this proof was generated
        /// 
        /// @return The root hash as a byte array
        ///
        access(all) view fun getRootHash(): [UInt8] {
            return self.rootHash
        }

        /// Returns the size of the MMR at the time this proof was generated
        /// 
        /// @return The total number of nodes in the MMR when the proof was created
        ///
        access(all) view fun getMMRSize(): UInt64 {
            return self.mmrSize
        }

        /// Verifies that an element exists in the MMR at the specified position
        /// 
        /// @param root: The MMR root hash to verify against
        /// @param pos: The position of the element in the MMR
        /// @param data: The data of the element to verify
        /// @return True if the element is verified to be in the MMR, false otherwise
        ///
        access(all) fun verify(data: [UInt8]): Bool {
            // For verifying the data we need to calculate the hash for the proof position tree's peak
            // and combine it with the rest of peak hashes and MMR size to calculate the root hash
            var peaksHashes: [[UInt8]] = []
            var calculatedRootHash: [UInt8] = []
            // Calculate the path to follow for verification
            let mergePath: [UInt64] = MMRUtilAux.calcProofTreePathPositions(self.position, self.mmrSize)
            // Hash the data with the proof position to get the initial hash
            var nodeHash = MMRUtilAux.hashWithInteger(self.position, [data])
            // Iterate over the merge path positions to get the tree's peak hash
            var parentPosition: UInt64 = 0
            var childHashes: [[UInt8]] = []
            var mergedNodes: UInt64 = 0
            for position in mergePath {
                if (!MMRUtilAux.isRightSibling(position)) {
                    childHashes.append(self.localTreePathHashes[mergedNodes])
                    childHashes.append(nodeHash)
                } else {
                    childHashes.append(nodeHash)
                    childHashes.append(self.localTreePathHashes[mergedNodes])
                }
                parentPosition = MMRUtilAux.getParentPosition(position)
                // The nodeHash on the last iteration will be the tree's peak hash
                nodeHash = MMRUtilAux.hashWithInteger(parentPosition, childHashes)
                mergedNodes = mergedNodes + 1
                childHashes = []
            }
            // Collect all peak hashes for final root verification
            peaksHashes.appendAll(self.leftPeaksHashes)
            peaksHashes.append(nodeHash)
            peaksHashes.appendAll(self.rightPeaksHashes)
            // Combine all peak hashes with the MMR size to calculate the root
            calculatedRootHash = MMRUtilAux.hashWithInteger(self.getMMRSize(), peaksHashes)
            // Check if it matches the root stored on the proof
            return (calculatedRootHash == self.rootHash)
        }

        init(position: UInt64, localTreePathHashes: [[UInt8]], leftPeaksHashes: [[UInt8]], rightPeaksHashes: [[UInt8]], rootHash: [UInt8], mmrSize: UInt64) {
            self.position = position
            self.localTreePathHashes = localTreePathHashes            
            self.leftPeaksHashes = leftPeaksHashes
            self.rightPeaksHashes = rightPeaksHashes
            self.mmrSize = mmrSize
            self.rootHash = rootHash
        }
    }

    /// MMR resource that manages the appending of elements and generation of proofs
    /// 
    /// This resource maintains:
    /// - The current root commitment
    /// - The current peaks of the MMR
    /// - All nodes in the MMR
    ///
    access(all) resource MMR {

        // The current root hash of the MMR
        access(self) var rootCommitment: [UInt8]
        // The current set of peak hashes in the MMR
        access(self) var peaksHashes: [[UInt8]] 
        // All nodes (hashes) in the MMR
        access(self) var nodesHashes: [[UInt8]] 

        /// Get the current root commitment of the MMR
        /// 
        /// @return The current root hash
        ///
        access(all) view fun getRoot(): [UInt8] {
            return self.rootCommitment
        }
        
        /// Get the current peaks of the MMR
        /// 
        /// @return An array of peak hashes
        ///
        access(all) view fun getPeaks(): [[UInt8]] {
            return self.peaksHashes
        }
        
        /// Get all nodes in the MMR
        /// 
        /// @return An array of all node hashes
        ///
        access(all) view fun getNodes(): [[UInt8]] {
            return self.nodesHashes
        }
        
        /// Get the size of the MMR (the number of nodes)
        /// 
        /// @return The number of nodes in the MMR
        ///
        access(all) view fun getSize(): UInt64 {                                                         
            return UInt64(self.nodesHashes.length)
        }

        /// Append multiple leaf elements to the MMR
        /// 
        /// @param leafData An array of data to append to the MMR
        ///
        access(all) fun appendLeaves(leavesData: [[UInt8]]) {
            // If no data is attempted to be appended do nothing but do not abort?
            if leavesData.length == 0 {
                return
            }
            // Append leafs to MMR
            for data in leavesData {
                self.appendLeaf(leafData: data)
            }
            // Emit event with updated MMR information
            emit MMRRootUpdated(rootCommitment: self.rootCommitment, peaks: self.peaksHashes, newSize: self.getSize())
        }

        /// Append a single leaf element to the MMR
        /// This is the core append logic that handles the creation of new nodes
        /// and merging of peaks as needed.
        /// 
        /// @param leafData The data to append to the MMR
        ///
        access(self) fun appendLeaf(leafData: [UInt8]) {
            // Calculate which new nodes and peaks will be created by appending a new leaf
            var newNodesHashes: [[UInt8]] = []
            var childHashes: [[UInt8]] = []
            var peaksPositions: [UInt64] = []
            // The new leaf will take the next node position
            var nodePosition = self.getSize() + 1
            // Hash the leaf data with the position and store it on the list of new nodes
            var nodeHash = MMRUtilAux.hashWithInteger(nodePosition, [leafData])
            newNodesHashes.append(nodeHash)
            // If it is a right sibling, it will generate a new parent node. As long as the newly  
            // generated parent nodes remain right siblings, they will continue generating new parents
            while (MMRUtilAux.isRightSibling(nodePosition)) {
                // Get the left sibling hash using the node position and combine it with the node hash
                childHashes.append(self.nodesHashes[MMRUtilAux.getSiblingPosition((nodePosition)) - 1])
                childHashes.append(nodeHash)
                // Hash the siblings with the position the parent will take to create the parent node
                nodePosition = nodePosition + 1
                nodeHash = MMRUtilAux.hashWithInteger(nodePosition, childHashes)
                // And finally add it to the list of new nodes generated by the leaf appending
                newNodesHashes.append(nodeHash)
                childHashes = []
            }
            // Save the new nodeHashes to the MMR state
            self.nodesHashes.appendAll(newNodesHashes)
            // Get the new peak positions
            peaksPositions = MMRUtilAux.getPeaksPositions(self.getSize())
            // Update the peak hashes on the MMR state
            self.peaksHashes = MMRUtilAux.getHashesFromPositions(self.nodesHashes, peaksPositions)
            // Finally update the MMR root bagging all the new peaks along the new MMR size
            self.rootCommitment = MMRUtilAux.hashWithInteger(self.getSize(), self.peaksHashes)
        }

        /// Generate a proof for an element at the specified position
        ///
        /// @param pos: The position of the element to generate a proof for
        /// @return A Proof struct containing all data needed for verification
        ///
        access(all) fun generateProof(pos: UInt64): Proof {
            // Check that the position that wants to get proved is correct
            assert(pos > 0, message: "Nodes numbering starts at 1, position must be greater than 0")
            assert(MMRUtilAux.getHeight(pos) == 1, message: "Proofs can only be generated for leaf nodes")
            let size = self.getSize()
            assert(pos <= size, message: "Can't generate proof for non-existing node")
            // Calculate the positions of all nodes needed for the proof
            let proofPositions: MMRUtilAux.ProofPositions = MMRUtilAux.calcProofPositions(pos, size)
            // Create proof from the calculated positions and their corresponding hashes
            return Proof(
                position: pos,
                localTreePathHashes: proofPositions.getLocalTreePathHashes(self.nodesHashes),
                leftPeaksHashes: proofPositions.getLeftPeaksHashes(self.nodesHashes),
                rightPeaksHashes: proofPositions.getRightPeaksHashes(self.nodesHashes),
                rootHash: self.rootCommitment,
                mmrSize: size)
        }

        init() {
            self.peaksHashes = []
            self.nodesHashes = []
            self.rootCommitment = MerkleMountainRange.NO_ROOT
        }
    }

    init() {
        // Initialize the NO_ROOT value by hashing a zero byte
        self.NO_ROOT = MMRUtilAux.hash(UInt8(0).toBigEndianBytes())
    }
    
    /// Creates and returns a new MMR resource
    /// 
    /// @return A new, empty MMR resource
    ///
    access(all) fun createMMR(): @MMR {
        return <- create MMR()
    }

}