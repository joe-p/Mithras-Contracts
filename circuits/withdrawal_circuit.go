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
	WithdrawalAddress frontend.Variable `gnark:",public"`
	WithdrawalAmount  frontend.Variable `gnark:",public"`
	Fee               frontend.Variable `gnark:",public"`
	Nullifier         frontend.Variable `gnark:",public"`
	Root              frontend.Variable `gnark:",public"`

	UnspentCommitment frontend.Variable `gnark:",public"`
	SpentCommitment   frontend.Variable `gnark:",public"`

	SpenderAddess frontend.Variable `gnark:",public"`
	OutputAddress frontend.Variable `gnark:",public"`

	// X and Y for spender pubkey
	SpenderX frontend.Variable
	SpenderY frontend.Variable

	// Signature is the signature of the  signed by the input keypair
	Signature eddsa.Signature

	// X and Y for output pubkey
	OutputX frontend.Variable
	OutputY frontend.Variable

	SpendableK      frontend.Variable
	SpendableR      frontend.Variable
	SpendableAmount frontend.Variable
	SpendableIndex  frontend.Variable
	SpendablePath   [MerkleTreeLevels + 1]frontend.Variable

	SpentAmount frontend.Variable
	SpentK      frontend.Variable
	SpentR      frontend.Variable

	UnspentAmount frontend.Variable
	UnspentK      frontend.Variable
	UnspentR      frontend.Variable
}

// validateAddressXYConstraint validates that if address is not zero, then X and Y must be zero
func validateAddressXYConstraint(api frontend.API, address, x, y frontend.Variable) {
	addressIsZero := api.IsZero(address)
	xIsZero := api.IsZero(x)
	yIsZero := api.IsZero(y)

	// If Address != 0, then X == 0 AND Y == 0
	// This is equivalent to: Address == 0 OR (X == 0 AND Y == 0)
	xyBothZero := api.And(xIsZero, yIsZero)
	constraint := api.Or(addressIsZero, xyBothZero)
	api.AssertIsEqual(constraint, 1)
}

func (c *WithdrawalCircuit) Define(api frontend.API) error {
	// Validate spender address and XY constraints
	validateAddressXYConstraint(api, c.SpenderAddess, c.SpenderX, c.SpenderY)

	// Validate output address and XY constraints
	validateAddressXYConstraint(api, c.OutputAddress, c.OutputX, c.OutputY)

	mimc, _ := mimc.NewMiMC(api)

	// hash(Amount,K) == Nullifier
	verifyHashCommitment(api, &mimc, c.Nullifier, 1, c.SpendableAmount, c.SpendableK)

	// hash(hash(UnspentAmount, UnspentK, UnspentR, SpenderX, SpenderY)) == UnspentCommitment
	verifyHashCommitment(api, &mimc, c.UnspentCommitment, 2, c.UnspentAmount, c.UnspentK, c.UnspentR, c.SpenderX, c.SpenderY)

	// hash(hash(SpendAmount, SpendK, SpendR, OutputX, OutputY)) == SpendCommitment
	verifyHashCommitment(api, &mimc, c.SpentCommitment, 2, c.SpentAmount, c.SpentK, c.SpentR, c.OutputX, c.OutputY)

	// Verify the the Input pubkey signed the withdrawal commitment
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	pubkey := eddsa.PublicKey{}
	pubkey.A.X = c.SpenderX
	pubkey.A.Y = c.SpenderY

	err = eddsa.Verify(curve, c.Signature, c.UnspentCommitment, pubkey, &mimc)

	if err != nil {
		return err
	}

	mimc.Reset()

	// Path[0] == hash(SpendableAmount, SpendableK, SpendableR, SpenderX, SpenderY)
	verifyHashCommitment(api, &mimc, c.SpendablePath[0], 1, c.SpendableAmount, c.SpendableK, c.SpendableR, c.SpenderX, c.SpenderY)

	// SpendableAmount, SpendableK is in the merkle tree at index
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
	totalSpent := api.Add(c.WithdrawalAmount, c.SpentAmount)
	api.AssertIsLessOrEqual(totalSpent, c.SpendableAmount)
	api.AssertIsLessOrEqual(c.Fee, api.Sub(c.SpendableAmount, totalSpent))
	api.AssertIsEqual(c.UnspentAmount, api.Sub(c.SpendableAmount, totalSpent, c.Fee))

	return nil
}
