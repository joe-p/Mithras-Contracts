package test

import (
	"bytes"
	"errors"

	"github.com/joe-p/Mithras-Protocol/config"
)

type Tree struct {
	subTree    [][]byte
	zeroHashes [][]byte
	depth      int
	hashFunc   config.HashFunc
	leafHashes [][]byte
}

func NewTree(c TreeConfig) *Tree {
	return &Tree{
		subTree:    c.ZeroHashes,
		zeroHashes: c.ZeroHashes,
		depth:      c.Depth,
		hashFunc:   c.HashFunc,
		leafHashes: make([][]byte, 0, 100),
	}
}

// createMerkleProof returns the Merkle proof for the leaf at the given index.
// The proof is a path that starts with the leaf value (not hashed)
// and includes the sibling hashes up to but excluding the root.
// It returns an error if the leaf value does not map to the hash at index.
func (t *Tree) createMerkleProof(
	leafValue []byte, index int) ([][]byte, error) {

	depth := t.depth
	leafHash := t.hashFunc(leafValue)
	if !bytes.Equal(t.leafHashes[index], leafHash) {
		return nil, errors.New("leaf value does not map to hash at index")
	}
	if index >= len(t.leafHashes) {
		return nil, errors.New("index out of range")
	}

	proof := make([][]byte, 1, depth+1)
	proof[0] = leafValue

	// We need to decide whether we are left and add the right sibling to
	// the proof, or we are right and add the left sibling to the proof.
	// We can do this by checking the last bit of leaf index:
	// if it's 0, we are left, if it's 1, we are right.
	// We rigth shift the index to check the next bit in the next iteration.
	currentLevel := t.leafHashes
	if len(currentLevel)%2 == 1 {
		currentLevel = append(currentLevel, t.subTree[0])
	}
	nextLevel := make([][]byte, (len(currentLevel)+1)/2)
	for i := 0; i < depth; i++ {
		if index&1 == 0 {
			proof = append(proof, currentLevel[index+1])
		} else {
			proof = append(proof, currentLevel[index-1])
		}

		for j := 0; j < len(currentLevel); j += 2 {
			nextLevel[j/2] = t.hashFunc(currentLevel[j], currentLevel[j+1])
		}
		if len(nextLevel)%2 == 1 {
			nextLevel = append(nextLevel, t.subTree[i+1])
		}

		currentLevel = nextLevel
		nextLevel = nextLevel[:len(nextLevel)/2]
		index >>= 1
	}

	return proof, nil
}

// Verify returns true if the leaf at path[0] is included in the tree.
// path is the proof returned by CreateMerkleProof.
func (t *Tree) verify(leafIndex int, path [][]byte, root []byte) bool {
	if len(path) == 0 {
		return false
	}
	leafHash := t.hashFunc(path[0])
	currentHash := leafHash

	// We do the usual left, right strategy, check comment in CreateMerkleProof
	for i := 1; i < len(path); i++ {
		if leafIndex&1 == 0 {
			currentHash = t.hashFunc(currentHash, path[i])
		} else {
			currentHash = t.hashFunc(path[i], currentHash)
		}
		leafIndex >>= 1
	}
	// if the path is consistent, we check it ends with the root hash
	return bytes.Equal(currentHash, root)
}

// getRoot returns the root of the tree
func (t *Tree) getRoot() []byte {
	return t.subTree[len(t.subTree)-1]
}

// addLeaf adds a leaf to the tree and returns the index of the leaf
func (t *Tree) addLeaf(leaf []byte) int {
	t.leafHashes = append(t.leafHashes, leaf)
	currentHash := leaf
	index := len(t.leafHashes) - 1
	var left, right []byte
	for i := 0; i < t.depth; i++ {
		if index&1 == 0 {
			t.subTree[i] = currentHash
			left = currentHash
			right = t.zeroHashes[i]
		} else {
			left = t.subTree[i]
			right = currentHash
		}
		currentHash = t.hashFunc(left, right)
		index >>= 1
	}
	t.subTree[t.depth] = currentHash
	return len(t.leafHashes) - 1
}
