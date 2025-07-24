package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/giuliop/HermesVault-smartcontracts/circuits"
	"github.com/giuliop/HermesVault-smartcontracts/config"
	"github.com/giuliop/HermesVault-smartcontracts/test"

	ap "github.com/giuliop/algoplonk"
	ap_setup "github.com/giuliop/algoplonk/setup"
	"github.com/giuliop/algoplonk/utils"
)

// func (f *Frontend) SendDeposit(from *crypto.Account, amount uint64, outputPubkey eddsa.PublicKey, inputPrivkey eddsa.PrivateKey) (
// 	*Deposit, error) {
//
// 	note, _ := f.NewNote(amount, inputPrivkey, outputPubkey)
//
// 	x := outputPubkey.A.X.Bytes()
// 	y := outputPubkey.A.Y.Bytes()
// 	assignment := &circuits.DepositCircuit{
// 		Amount:     amount,
// 		Commitment: note.commitment,
// 		K:          note.k,
// 		R:          note.r,
// 		OutputX:    x[:],
// 		OutputY:    y[:],
// 	}
// 	verifiedProof, err := f.App.DepositCc.Verify(assignment)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to verify deposit proof: %v", err)
// 	}
// 	proof := ap.MarshalProof(verifiedProof.Proof)
// 	publicInputs, err := ap.MarshalPublicInputs(verifiedProof.Witness)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshal public inputs: %v", err)
// 	}
// 	args, err := utils.ProofAndPublicInputsForAtomicComposer(proof, publicInputs)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to abi encode proof and public inputs: %v", err)
// 	}
// 	args = append(args, from.Address)

//export GetProof
func GetProof() {
	inputPrivKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	outputPrivKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	outputPubKeySig := outputPrivKey.Public()
	outputPubKey := eddsa.PublicKey{}
	outputPubKey.SetBytes(outputPubKeySig.Bytes())

	depositCircuit := circuits.DepositCircuit{}
	depositCc, err := ap.Compile(&depositCircuit, ecc.BN254, ap_setup.Trusted)
	if err != nil {
		panic(fmt.Sprintf("failed to compile deposit circuit: %v", err))
	}

	amount := uint64(100)

	app := &test.App{
		TreeConfig: test.TreeConfig{
			Depth:      config.MerkleTreeLevels,
			ZeroValue:  []byte{0},
			HashFunc:   config.Hash,
			ZeroHashes: config.GenerateZeroHashes(config.MerkleTreeLevels, []byte{0}),
		},
		DepositCc: depositCc,
	}
	frontend := &test.Frontend{
		Tree: test.NewTree(app.TreeConfig),
		App:  app,
	}

	note, _ := frontend.NewNote(100, *inputPrivKey, outputPubKey)

	fmt.Printf("note: %v\n", note)

	x := outputPubKey.A.X.Bytes()
	y := outputPubKey.A.Y.Bytes()

	assignment := &circuits.DepositCircuit{
		Amount:     amount,
		Commitment: note.Commitment,
		K:          note.K,
		R:          note.R,
		OutputX:    x[:],
		OutputY:    y[:],
	}
	verifiedProof, err := frontend.App.DepositCc.Verify(assignment)
	if err != nil {
		panic(err)
	}
	proof := ap.MarshalProof(verifiedProof.Proof)
	publicInputs, err := ap.MarshalPublicInputs(verifiedProof.Witness)
	if err != nil {
		panic(err)
	}
	args, err := utils.ProofAndPublicInputsForAtomicComposer(proof, publicInputs)
	if err != nil {
		panic(err)
	}

	fmt.Printf("args: %v\n", args)
}

func main() {}
