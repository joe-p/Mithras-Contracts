package test

import (
	"log"
	"os"
	"path/filepath"

	"github.com/joe-p/Mithras-Protocol/config"
	"github.com/joe-p/Mithras-Protocol/setup"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/giuliop/algoplonk/utils"
)

var artefactsDirPath = setup.ArtefactsDirPath

const (
	appFilename                        = setup.AppFilename
	appArc32FileName                   = setup.MainContractName + ".arc32.json"
	tssBytecodeFileName                = setup.TssName + ".tok"
	depositVerifierBytecodeFileName    = setup.DepositVerifierName + ".tok"
	withdrawalVerifierBytecodeFileName = setup.WithdrawalVerifierName + ".tok"
	treeConfigFileName                 = setup.TreeConfigFilename
	compiledDepositCircuitFileName     = setup.DepositCircuitCompiledFilename
	compiledWithdrawalCircuitFileName  = setup.WithdrawalCircuitCompiledFilename
)

type appJson struct {
	Id            uint64 `json:"id"`
	CreationBlock uint64 `json:"creationBlock"`
}

// readSetup reads the setup files from artefactsDirPath and returns an App struct for testing
func readSetup() *App {
	app := App{}
	appJson := appJson{}

	setup.DecodeJSONFile(pathTo(appFilename), &appJson)
	setup.DecodeJSONFile(pathTo(appArc32FileName), &app.Schema)
	app.Id = appJson.Id
	app.TSS = readLogicSigFromFile(tssBytecodeFileName)
	app.DepositVerifier = readLogicSigFromFile(depositVerifierBytecodeFileName)
	app.WithdrawalVerifier = readLogicSigFromFile(withdrawalVerifierBytecodeFileName)
	app.TreeConfig = readTreeConfiguration(pathTo(treeConfigFileName))

	var err error
	app.DepositCc, err = utils.DeserializeCompiledCircuit(filepath.Join(
		artefactsDirPath, compiledDepositCircuitFileName))
	if err != nil {
		log.Fatalf("Error deserializing compiled deposit circuit: %v", err)
	}
	app.WithdrawalCc, err = utils.DeserializeCompiledCircuit(filepath.Join(
		artefactsDirPath, compiledWithdrawalCircuitFileName))
	if err != nil {
		log.Fatalf("Error deserializing compiled withdrawal circuit: %v", err)
	}

	return &app
}

// readLogicSigFromFile reads the compiled logicsig file and returns an Lsig
func readLogicSigFromFile(compiledFile string) *Lsig {
	bytecode, err := os.ReadFile(pathTo(compiledFile))
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	return readLogicSig(bytecode)
}

// readLogicSig takes teal bytecode and returns a Lsig
func readLogicSig(bytecode []byte) *Lsig {
	lsigAccount, err := crypto.MakeLogicSigAccountEscrowChecked(bytecode, nil)
	if err != nil {
		log.Fatalf("Error creating  logic sig account: %v", err)
	}
	address, err := lsigAccount.Address()
	if err != nil {
		log.Fatalf("Error getting lsig address: %v", err)
	}
	return &Lsig{
		Account: lsigAccount,
		Address: address,
	}
}

// readTreeConfiguration reads the tree configuration from the given file
func readTreeConfiguration(treeConfigPath string) TreeConfig {
	treeConfig := TreeConfig{}
	setup.DecodeJSONFile(treeConfigPath, &treeConfig)
	treeConfig.HashFunc = config.Hash
	return treeConfig
}

// pathTo returns the path to the file in the artefacts directory
func pathTo(file string) string {
	return filepath.Join(artefactsDirPath, file)
}
