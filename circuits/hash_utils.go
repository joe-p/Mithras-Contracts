package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

func verifyHashCommitment(api frontend.API, mimc *mimc.MiMC, commitment frontend.Variable, iterations int, values ...frontend.Variable) {
	for _, value := range values {
		mimc.Write(value)
	}
	h := mimc.Sum()

	for i := 1; i < iterations; i++ {
		mimc.Reset()
		mimc.Write(h)
		h = mimc.Sum()
	}

	api.AssertIsEqual(commitment, h)
	mimc.Reset()
}
