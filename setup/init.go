package setup

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/joe-p/Mithras-Protocol/circuits"

	"github.com/consensys/gnark/frontend"
)

const (
	ArtefactsDirName                  = "generated"
	MainContractName                  = "APP"
	TssName                           = "TSS"
	DepositVerifierName               = "DepositVerifier"
	WithdrawalVerifierName            = "WithdrawalVerifier"
	DepositCircuitCompiledFilename    = "CompiledDepositCircuit.bin"
	WithdrawalCircuitCompiledFilename = "CompiledWithdrawalCircuit.bin"
	AppFilename                       = "App.json"
	TreeConfigFilename                = "TreeConfig.json"
)

var (
	ArtefactsDirPath               string
	AppPath                        string
	MainContractSourcePath         string
	AppSchemaPath                  string
	TssSourcePath                  string
	TssTealPath                    string
	TssBytecodePath                string
	DeppositVerifierTealPath       string
	DepositVerifierBytecodePath    string
	WithdrawalVerifierTealPath     string
	WithdrawalVerifierBytecodePath string
	TreeConfigPath                 string
)

type CircuitData struct {
	Circuit        frontend.Circuit
	VerifierName   string
	DefinitionPath string
	CompiledPath   string
}

var DepositCircuitData, WithdrawalCircuitData CircuitData

func init() {
	_, filename, _, _ := runtime.Caller(0) // this file
	basePath := filepath.Dir(filename)     // the dir of this file

	ArtefactsDirPath = filepath.Join(basePath, ArtefactsDirName)
	// create artefactsDir if it does not exist
	if err := os.MkdirAll(ArtefactsDirPath, os.ModePerm); err != nil {
		panic("failed to create artefactsDir: " + err.Error())
	}

	MainContractSourcePath = filepath.Join(basePath, MainContractName+".py")
	TssSourcePath = filepath.Join(basePath, TssName+".py")
	TssTealPath = filepath.Join(ArtefactsDirPath, TssName+".teal")
	TssBytecodePath = filepath.Join(ArtefactsDirPath, TssName+".tok")
	AppPath = filepath.Join(ArtefactsDirPath, AppFilename)
	TreeConfigPath = filepath.Join(ArtefactsDirPath, TreeConfigFilename)
	AppSchemaPath = filepath.Join(ArtefactsDirPath, MainContractName+".arc32.json")
	DeppositVerifierTealPath = filepath.Join(ArtefactsDirPath, DepositVerifierName+".teal")
	DepositVerifierBytecodePath = filepath.Join(ArtefactsDirPath, DepositVerifierName+".tok")
	WithdrawalVerifierTealPath = filepath.Join(ArtefactsDirPath, WithdrawalVerifierName+".teal")
	WithdrawalVerifierBytecodePath = filepath.Join(ArtefactsDirPath, WithdrawalVerifierName+".tok")

	DepositCircuitData = CircuitData{
		Circuit:        &circuits.DepositCircuit{},
		VerifierName:   DepositVerifierName,
		DefinitionPath: circuits.DepositCircuitPackageName,
		CompiledPath:   filepath.Join(ArtefactsDirPath, DepositCircuitCompiledFilename),
	}

	WithdrawalCircuitData = CircuitData{
		Circuit:        &circuits.WithdrawalCircuit{},
		VerifierName:   WithdrawalVerifierName,
		DefinitionPath: circuits.WithdrawalCircuitPackageName,
		CompiledPath:   filepath.Join(ArtefactsDirPath, WithdrawalCircuitCompiledFilename),
	}
}
