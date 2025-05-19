# Merkle Mountain Range

## Introduction

A Merkle Mountain Range (MMR) is a data structure that extends the concept of a Merkle tree to allow for efficient appending of new elements and efficient proof generation. MMRs are particularly useful in scenarios where on-chain data updates are necessary.

### Properties and Applications

1. **Append-Only**: Efficiently supports adding new elements
2. **Compact Proofs**: Proof size is logarithmic in the number of elements
3. **Verification Efficiency**: Proofs can be verified quickly
4. **No Rebalancing**: Unlike traditional Merkle trees, MMRs don't require rebalancing

## Basic Structure and Formation

In an MMR, nodes are arranged in a series of perfect binary trees (mountains) of decreasing height from left to right. 
When a piece of data is to be added to the MMR it gets hashed creating a node that, using 1-based numbering and starting from the left, is added to the MMR. Whenever a left node gains a sibling, a parent node is created by hashing both children together, following sequential numbering. If the newly created parent node already has a right sibling at the same level, another parent node will be created for them, and so on.

### Visualizing an MMR

Let's look at an MMR with 13 leaves (represented by positions 1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20 and 23):

```
                               15
                              /  \
                             /    \
                            /      \
                           7        14          22
                          / \      /  \        /  \
                         /   \    /    \      /    \
                        3     6  10     13   18     21
                       / \   / \ / \   / \   / \   / \
                      1   2 4  5 8  9 11 12 16 17 19 20 23

```

## Key concepts

Clarifying a few key terms is essential for understanding MMRs and avoiding confusion during implementation, which also improves code readability.

### Position

The number assigned to each node is called its position. This numbering will be 1-based rather than 0-based as it will be on other data structs. 
While this may seem arbitrary, it is crucial for the mathematical properties of MMRs, enabling operations such as calculating a node's height. 
It is important not to confuse this position with the order in which data was added to the MMR—sometimes referred to as the "leaf number"—as this is not relevant to MMR implementation.

### Height 

Each node has an associated height depending on which level of the MMR they are placed.
In this implementation height is numbered 1-based as positions are.
Based on the height of a given node, we can differentiate node types.

#### Node Types

A node on the first level, height 1, will always be a **Leaf Node**.
These nodes contain the hash of the stored data along with the position of the leaf within the structure.
The top nodes of each perfect binary tree (mountain) will be **Peak Nodes**. In our previous example peaks will be nodes 15, 22 and 23.
Intermediate nodes do not require a specific term, as their height is only relevant for traversal calculations within the MMR.
Given a node position, its height can be calculated by iterating through the binary tree it is part of.

### Size

The total amount of nodes that form the MMR, including leaves and peaks, is referred as the MMR size.

### Root

The unique identifier of a MMR at a certain point of its life, obtained by hashing together all the peaks (also known as bagging peaks) preceded by its size.

## MMR Proofs

The minimum necessary set of information from the MMR needed for checking if a piece of data was included on it.
All these elements correspond to a specific point in the MMR's lifecycle, meaning that if a proof is generated for the same data at a later time, after more leaves have been added, the proof will differ.

- Position of the leaf where the data was included.
- Local tree path hashes.
- Left hand sided peaks.
- Right hand sided peaks.
- MMR's root hash and size.

Taking our initial MMR example if we want to generate a proof for the node 16, we will pack in a structure the following information:
```pseudocode
struct Proof {
   int position = 16
   [hash] localTreePathHashes = [h(n17),h(n21)]
   [hash] lhsPeaksHashes = [h(n15)]
   [hash] rhsPeaksHashes = [h(n23)]
   hash mmrRoot = h(23,h(n15),h(n22),h(n23))
   int mmrSize = 23
}
```

Understanding the concept of local tree path hashes is crucial, as they are the key element in proof generation and verification.
When verifying a proof, we compute the MMR root hash using the proof's information and the data being verified as part of the MMR.
By hashing the data to be verified, we can use the **local tree path hashes** to compute all parent node hashes, ultimately deriving the local tree peak hash.

## Acknowledgments

Make sure to check the [CONTRIBUTORS](./../CONTRIBUTORS.md) file for proper credit on this!

### Sui Testnet Package Address

[0xfecf927a5913070eebd05821b5a6d38dacc225a40e6b0865be83a3c03e4afa6f](https://suiscan.xyz/testnet/object/0xfecf927a5913070eebd05821b5a6d38dacc225a40e6b0865be83a3c03e4afa6f/contracts)
