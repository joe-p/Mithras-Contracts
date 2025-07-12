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
	OutputX frontend.Variable `gnark:",public"`
	OutputY frontend.Variable `gnark:",public"`

	K frontend.Variable
	R frontend.Variable
}

func (c *DepositCircuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)

	// hash(hash(Amount, K, R, OutputX, OutputY)) == Commitment
	mimc.Write(c.Amount)
	mimc.Write(c.K)
	mimc.Write(c.R)

	mimc.Write(c.OutputX)
	mimc.Write(c.OutputY)

	h := mimc.Sum()

	mimc.Reset()

	mimc.Write(h)
	api.AssertIsEqual(c.Commitment, mimc.Sum())

	mimc.Reset()

	return nil
}
