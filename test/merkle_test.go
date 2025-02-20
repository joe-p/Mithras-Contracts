package test

import (
	"math"
	"slices"
	"testing"

	"github.com/giuliop/HermesVault-smartcontracts/config"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	ap "github.com/giuliop/algoplonk"
	ap_setup "github.com/giuliop/algoplonk/setup"
)

const MerkleTreeLevels = 16
const curve = ecc.BN254

type MerkleCircuit struct {
	Root  frontend.Variable `gnark:",public"`
	Index frontend.Variable
	Path  [MerkleTreeLevels + 1]frontend.Variable
}

func (c *MerkleCircuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)

	mp := merkle.MerkleProof{
		RootHash: c.Root,
		Path:     c.Path[:],
	}
	mp.VerifyProof(api, &mimc, c.Index)

	return nil
}

func TestMerkle(t *testing.T) {
	c := &MerkleCircuit{}
	cc, err := ap.Compile(c, curve, ap_setup.Trusted)
	if err != nil {
		t.Fatal(err)
	}

	tc := TreeConfig{
		Depth:     MerkleTreeLevels,
		ZeroValue: []byte{0},
		HashFunc:  config.Hash,
	}

	tc.ZeroHashes = config.GenerateZeroHashes(tc.Depth, tc.ZeroValue)
	tree := NewTree(tc)

	f := Frontend{Tree: tree}

	note := f.NewNote(100)
	index := tree.addLeaf(note.commitment)
	note.insertedIndex = index

	path, err := tree.createMerkleProof(f.MakeLeafValue(note), index)
	if err != nil {
		t.Fatal(err)
	}

	root := tree.ComputeRootFromLeaves()
	if !slices.Equal(root, tree.getRoot()) {
		t.Fatal("Root not computed correctly")
	}

	if !tree.verify(index, path, root) {
		t.Fatal("Merkle proof verification failed")
	}

	var pathForProof [MerkleTreeLevels + 1]frontend.Variable
	for i := range path {
		pathForProof[i] = path[i]
	}

	assignment := &MerkleCircuit{
		Root:  root,
		Index: index,
		Path:  pathForProof,
	}
	_, err = cc.Verify(assignment)
	if err != nil {
		t.Fatal(err)
	}
}

func (t *Tree) ComputeRootFromLeaves() []byte {
	hashFunc := t.hashFunc
	leafCount := math.Pow(2.0, float64(t.depth))
	currentLevel := make([][]byte, int(leafCount))
	copy(currentLevel, t.leafHashes)
	for i := len(t.leafHashes); i < len(currentLevel); i++ {
		currentLevel[i] = t.subTree[0]
	}
	for level := 0; level < t.depth; level++ {
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			right := currentLevel[i+1]
			currentLevel[i/2] = hashFunc(left, right)
		}
		currentLevel = currentLevel[:len(currentLevel)/2]
	}
	return currentLevel[0]
}
