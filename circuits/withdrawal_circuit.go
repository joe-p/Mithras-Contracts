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
	Recipient  frontend.Variable `gnark:",public"`
	Withdrawal frontend.Variable `gnark:",public"`
	Fee        frontend.Variable `gnark:",public"`
	Commitment frontend.Variable `gnark:",public"`
	Nullifier  frontend.Variable `gnark:",public"`
	Root       frontend.Variable `gnark:",public"`

	// X and Y for output pubkey
	OutputX frontend.Variable `gnark:",public"`
	OutputY frontend.Variable `gnark:",public"`

	K      frontend.Variable
	R      frontend.Variable
	Amount frontend.Variable
	Change frontend.Variable
	K2     frontend.Variable
	R2     frontend.Variable
	Index  frontend.Variable

	// X and Y for input pubkey
	InputX frontend.Variable
	InputY frontend.Variable

	// Signature is the signature of the withdrawal commitment signed by the withdrawal keypair
	Signature eddsa.Signature

	Path [MerkleTreeLevels + 1]frontend.Variable
}

func (c *WithdrawalCircuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)

	// hash(Amount,K) == Nullifier
	mimc.Write(c.Amount)
	mimc.Write(c.K)
	api.AssertIsEqual(c.Nullifier, mimc.Sum())

	mimc.Reset()

	// hash(hash(Change, K2, R2, OutputX, OutputY)) == Commitment
	mimc.Write(c.Change)
	mimc.Write(c.K2)
	mimc.Write(c.R2)
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
	pubkey.A.X = c.InputX
	pubkey.A.Y = c.InputY

	err = eddsa.Verify(curve, c.Signature, c.Commitment, pubkey, &mimc)

	if err != nil {
		return err
	}

	mimc.Reset()

	// Path[0] == hash(Amount, K, R, InputX, InputY)
	mimc.Write(c.Amount)
	mimc.Write(c.K)
	mimc.Write(c.R)
	mimc.Write(c.InputX)
	mimc.Write(c.InputY)
	api.AssertIsEqual(c.Path[0], mimc.Sum())

	mimc.Reset()

	// Amount,K, is in the merkle tree at index
	mp := merkle.MerkleProof{
		RootHash: c.Root,
		Path:     c.Path[:],
	}
	mp.VerifyProof(api, &mimc, c.Index)
	// Change == Amount - Withdrawal - Fee, and C, A, W, F are all non-negative
	// We express it by:
	// 		W <= A
	//		F <= A - W
	//		C = A - W - F
	api.AssertIsLessOrEqual(c.Withdrawal, c.Amount)
	api.AssertIsLessOrEqual(c.Fee, api.Sub(c.Amount, c.Withdrawal))
	api.AssertIsEqual(c.Change, api.Sub(c.Amount, c.Withdrawal, c.Fee))

	return nil
}
