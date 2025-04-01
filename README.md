# Merkle Mountain Range

## Introduction

A Merkle Mountain Range (MMR) is a data structure that extends the concept of a Merkle tree to allow for efficient appending of new elements and efficient proof generation. MMRs are particularly useful in blockchain and distributed systems where there's a need for verifiable append-only logs.

## Sui Move implementation

This is a just a for fun implementation of MMRs on Move, based on my own [Cadence implementation for the Flow blockchain](https://github.com/alilloig/flow-merkle-mountain-range). I aim to shoehorn this into a working Sui dapp just as a learning project and with the intention of framing MMR into an hypothetical practical application that could help refining the package architecture on how this data struct could be use by Sui dapp developers.

### Properties and Applications

1. **Append-Only**: Efficiently supports adding new elements
2. **Compact Proofs**: Proof size is logarithmic in the number of elements
3. **Verification Efficiency**: Proofs can be verified quickly
4. **No Rebalancing**: Unlike traditional Merkle trees, MMRs don't require rebalancing

## Basic Structure and Formation

In an MMR, nodes are arranged in a series of perfect binary trees (mountains) of decreasing height from left to right. 
When a piece of data is to be added to the MMR it gets hashed creating a node that using 1-based numbering and starting from the left is included in the MMR. Whenever a left node gets a sibling added, a parent node for both is created out of the hash of both child, following the sequentially numeration.

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

### Position

The number associated to each node is called node position. This numbering will be 1-based 
rather than 0-based as it will be on other data structs. While this may seem arbitrary
is a crucial aspect for the mathematical properties of MMRs allowing operations such as
obtaining the height of a node. In order to over-clarify this, we will be naming every
variable of property handling this numbering something with position in it. When we have 
to operate with this values 0-based for coding reasons, the auxiliary variables used
should be named using the index word.
(please someone that is a native english speaker write this last two sentence in a proper way)
An important note will be not to confuse this position with the order in which a piece 
of data was added to the MMR, that would be typically use to generate the node hashing 
this order along the data.

### Height and Node Types

Each node has an associated height depending on which level of the MMR they are placed.
Nodes on level 1 will always be **Leaf Nodes**, the ones containing the hashes of the actual data being logged.
The top nodes of each perfect binary tree (mountain) will be **Peak Nodes**. In our previous example peaks will be nodes 15, 22 and 23.
Given a node position, its height can be calculated by iterating through the tree.

### Size

The total amount of nodes that form the MMR

### Root

The unique identifier of a MMR at a certain point of its life, obtained by hashing together all the peaks (also known as bagging peaks). Some implementations, as this one does, include the MMR size along the peak hashes when computing the root.

### Proof Path

The list of node positions needed for a certain position to be able to calculate the hash of the peak where that leaf belongs

## Proof Generation and Verification

### MMR Proofs

An MMR proof for a leaf allows verification that the leaf is part of the MMR without requiring the entire structure.

#### Generation

#### Verification

## Example

## Acknowledgments

Make sure to check the [CONTRIBUTORS](./CONTRIBUTORS) file for proper credit on this!