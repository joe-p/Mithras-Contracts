// Package circuits defines the zk-circuits for the application
package circuits

import (
	"runtime"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

var DepositCircuitPackageName string

// init sets Name to the path of this file
func init() {
	_, DepositCircuitPackageName, _, _ = runtime.Caller(0) // this file
}

type DepositCircuit struct {
	Amount     frontend.Variable `gnark:",public"`
	Commitment frontend.Variable `gnark:",public"`

	// X and Y for output pubkey
	OutputX frontend.Variable
	OutputY frontend.Variable

	K frontend.Variable
	R frontend.Variable
}

func (c *DepositCircuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)

	// hash(hash(Amount, K, R, OutputX, OutputY)) == Commitment
	verifyHashCommitment(api, &mimc, c.Commitment, 2, c.Amount, c.K, c.R, c.OutputX, c.OutputY)

	return nil
}
