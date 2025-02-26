package config

import (
	"github.com/giuliop/HermesVault-smartcontracts/mimc"

	"github.com/consensys/gnark-crypto/ecc"
)

// setup constants
const (
	MerkleTreeLevels    = 24
	Curve               = ecc.BN254
	RandomNonceByteSize = 31

	DepositMinimumAmount = 1e6  // 1 algo
	WithDrawalFeeDivisor = 1000 // 0.1% (we divide by this to get the fee)
	WithdrawalMinimumFee = 1e5  // 0.1 algo

	DepositMethodName    = "deposit"
	WithDrawalMethodName = "withdraw"
	NoOpMethodName       = "noop"
	CreateMethodName     = "create"
	UpdateMethodName     = "update"
)

// transaction fees required
const (
	// # top level transactions needed for logicsig verifier opcode budget
	VerifierTopLevelTxnNeeded = 8

	// fees needed for a deposit transaction group
	DepositMinFeeMultiplier = 42
	DepositOpcodeBudgetOpUp = 1100*MerkleTreeLevels + 900

	// fees needed for a withdrawal transaction group
	WithdrawalMinFeeMultiplier = 47
	WithdrawalOpcodeBudgetOpUp = 1100*MerkleTreeLevels + 3700
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
