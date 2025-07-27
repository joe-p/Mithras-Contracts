package config

import (
	"github.com/giuliop/HermesVault-smartcontracts/mimc"

	"github.com/consensys/gnark-crypto/ecc"
)

// setup constants
const (
	MerkleTreeLevels    = 32
	RootsCount          = 50
	Curve               = ecc.BN254
	RandomNonceByteSize = 31

	DepositMinimumAmount = 1_000_000 // microalgo, or 1 algo

	DepositMethodName    = "deposit"
	WithDrawalMethodName = "withdraw"
	NoOpMethodName       = "noop"
	CreateMethodName     = "create"
	UpdateMethodName     = "update"

	WithdrawalMethodTxnFeeArgPos = 5
)

// transaction fees required
const (
	// # top level transactions needed for logicsig verifier opcode budget
	VerifierTopLevelTxnNeeded = 8

	// fees needed for a deposit transaction group
	DepositMinFeeMultiplier = 56
	DepositOpcodeBudgetOpUp = 1100*MerkleTreeLevels + 1900

	// fees needed for a withdrawal transaction group
	// TODO: When adding the spend commitment (so now two leafs added in contract), I increased these values by even multiples
	// We should see what the true min required values are
	WithdrawalMinFeeMultiplier = 180
	WithdrawalOpcodeBudgetOpUp = 3*1100*MerkleTreeLevels + 4000

	// APP address MBR after initialization: 1_159_400 microalgos
	InitialMbr = 100_000 + // base
		2500 + 400*(5+32*RootsCount) + // roots box
		2500 + 400*(7+32*MerkleTreeLevels) // subtree box

	// MBR for each nullifier box storage
	NullifierMbr = 15_300 // 2500 + 400*32
)

type HashFunc = func(...[]byte) []byte

type TreeConfig struct {
	Depth      int
	ZeroValue  []byte
	ZeroHashes [][]byte
}

var (
	Tree TreeConfig
	Hash HashFunc
)

func init() {
	Tree = TreeConfig{
		Depth:     MerkleTreeLevels,
		ZeroValue: []byte{0},
	}
	Hash = mimc.NewMimcF(Curve)
	Tree.ZeroHashes = GenerateZeroHashes(Tree.Depth, Tree.ZeroValue)
}

func GenerateZeroHashes(depth int, zeroValue []byte) [][]byte {
	subtree := make([][]byte, depth+1)
	subtree[0] = Hash(zeroValue)
	for i := 1; i <= depth; i++ {
		subtree[i] = Hash(subtree[i-1], (subtree[i-1]))
	}
	return subtree
}
