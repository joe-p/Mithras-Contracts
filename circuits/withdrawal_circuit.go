package circuits

import (
	"runtime"

	"github.com/giuliop/HermesVault-smartcontracts/config"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const MerkleTreeLevels = config.MerkleTreeLevels

var WithdrawalCircuitPackageName string

// init sets Name to the path of this file
func init() {
	_, WithdrawalCircuitPackageName, _, _ = runtime.Caller(0) // this fil
}

type WithdrawalCircuit struct {
	WithdrawalAddress  frontend.Variable `gnark:",public"`
	WithdrawalAmount frontend.Variable `gnark:",public"`
	Fee        frontend.Variable `gnark:",public"`
	Commitment frontend.Variable `gnark:",public"`
	Nullifier  frontend.Variable `gnark:",public"`
	Root       frontend.Variable `gnark:",public"`

	// X and Y for spender pubkey
	SpenderX frontend.Variable
	SpenderY frontend.Variable
	
	// Signature is the signature of the  signed by the input keypair
	Signature eddsa.Signature
	
	// X and Y for output pubkey
	OutputX frontend.Variable
	OutputY frontend.Variable
	
	// Spend is a private uint64 used to create a new output without an on-chain transfer
	Spend frontend.Variable

	SpendableK      frontend.Variable
	SpendableR      frontend.Variable
	SpendableAmount frontend.Variable	
	SpendableIndex  frontend.Variable
	SpendablePath [MerkleTreeLevels + 1]frontend.Variable

	UnspentAmount frontend.Variable
	UnspentK     frontend.Variable
	UnspentR     frontend.Variable
}

func (c *WithdrawalCircuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)

	// hash(Amount,K) == Nullifier
	mimc.Write(c.SpendableAmount)
	mimc.Write(c.SpendableK)
	api.AssertIsEqual(c.Nullifier, mimc.Sum())

	mimc.Reset()

	// hash(hash(Change, K2, R2, OutputX, OutputY)) == Commitment
	mimc.Write(c.UnspentAmount)
	mimc.Write(c.UnspentK)
	mimc.Write(c.UnspentR)
	mimc.Write(c.OutputX)
	mimc.Write(c.OutputY)
	h := mimc.Sum()

	mimc.Reset()

	mimc.Write(h)
	api.AssertIsEqual(c.Commitment, mimc.Sum())

	mimc.Reset()

	// Verify the the Input pubkey signed the withdrawal commitment
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	pubkey := eddsa.PublicKey{}
	pubkey.A.X = c.SpenderX
	pubkey.A.Y = c.SpenderY

	err = eddsa.Verify(curve, c.Signature, c.Commitment, pubkey, &mimc)

	if err != nil {
		return err
	}

	mimc.Reset()

	// Path[0] == hash(Amount, K, R, InputX, InputY)
	mimc.Write(c.SpendableAmount)
	mimc.Write(c.SpendableK)
	mimc.Write(c.SpendableR)
	mimc.Write(c.SpenderX)
	mimc.Write(c.SpenderY)
	api.AssertIsEqual(c.SpendablePath[0], mimc.Sum())

	mimc.Reset()

	// Amount,K, is in the merkle tree at index
	mp := merkle.MerkleProof{
		RootHash: c.Root,
		Path:     c.SpendablePath[:],
	}
	mp.VerifyProof(api, &mimc, c.SpendableIndex)
	// Change == Amount - Withdrawal - Fee, and C, A, W, F are all non-negative
	// We express it by:
	// 		W <= A
	//		F <= A - W
	//		C = A - W - Fee
	totalSpent := api.Add(c.WithdrawalAmount, c.Spend)
	api.AssertIsLessOrEqual(totalSpent, c.SpendableAmount)
	api.AssertIsLessOrEqual(c.Fee, api.Sub(c.SpendableAmount, totalSpent))
	api.AssertIsEqual(c.UnspentAmount, api.Sub(c.SpendableAmount, totalSpent, c.Fee))

	return nil
}
