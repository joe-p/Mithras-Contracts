// package setup is used to deploy the smart contracts to the the AVM
package setup

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/giuliop/HermesVault-smartcontracts/avm"
	"github.com/giuliop/HermesVault-smartcontracts/config"
	"github.com/giuliop/HermesVault-smartcontracts/deployed"

	"github.com/consensys/gnark-crypto/ecc"

	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/setup"
	"github.com/giuliop/algoplonk/utils"
	"github.com/giuliop/algoplonk/verifier"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

/*

To set up the application on the AVM we need to follow these steps:
  1. Generate the deposit and withdrawal verifiers from the circuits
  2. Update the APP smart contract and TSS logicsig based on the configuration
  3. Compile APP with the verifiers' addresses and deploy it to the network
  4. Compile TSS with the APP id
  5. Initialize APP with the TSS address

All generated files will be stored in the `artefactsDirPath` defined in filepaths.go.
Once setup is run for mainnet / testnet, in the deployed/mainnet and deployed/testnet folders
there will be the files that a frontend need to interact with the application:
  * App.json						: app id and block creation of the deployed APP
  * APP.arc32.json					: arc32 schema of the deployed APP
  * TSS.tok							: compiled TSS logicsig
  * DepositVerifier.tok				: compiled deposit verifier logicsig
  * WithdrawalVerifier.tok			: compiled withdrawal verifier logicsig
  * TreeConfig.json					: Tree configuration (depth, zero value, zero hashes)
  * CompiledDepositCircuit.bin 		: serialized compiled deposit circuit
  * CompiledWithdrawalCircuit.bin	: serialized compiled withdrawal circuit

The serialized compiled circuits can be deserialized with AlgoPlonk, alternatively frontends
can use directly the circuit definitions in the circuits package.
*/

type APP struct {
	Id            uint64 `json:"id"`
	CreationBlock uint64 `json:"creationBlock"`
}

// CreateApp generates and deploys all smart contracts to the AVM network and generates in
// `ArtefactsDirPath` all files needed to build frontends.
// Uses the the configuration in config/config.go
func CreateApp(network deployed.Network) {
	avm.Initialize(network)

	// check app is not already deployed by checking if the deployed dir is empty
	// (skip this check for devnet)
	if network != deployed.DevNet {
		files, err := os.ReadDir(network.DirPath())
		if err != nil {
			log.Fatalf("Error reading directory %s: %v", network.DirPath(), err)
		}
		if len(files) > 0 {
			log.Fatalf("App seems to be already deployed on %s. Deployed dir %v is not empty",
				network, network.DirPath())
		}
	}

	writeTreeConfig()

	depositVerifierAdress := generateVerifier(config.Curve, &DepositCircuitData)
	withdrawalVerifierAddress := generateVerifier(config.Curve, &WithdrawalCircuitData)

	updateConstantsInSmartContracts()

	compileMainContract(depositVerifierAdress, withdrawalVerifierAddress)

	appId := deployMainContract()
	tssBytecode := setupTSS(appId)
	tssAddress := crypto.LogicSigAddress(types.LogicSig{Logic: tssBytecode}).String()

	initMainContract(appId, tssAddress)

	log.Println("TSS address:", tssAddress)
	log.Println("Main contract address:", crypto.GetApplicationAddress(appId).String())
	log.Println("Successfully completed deployment on", network)

	exportSetupFiles(network)
	log.Println("Exported frontend setup files to", network.DirPath())
}

// generateVerifier generates a Verifier from a CircuitData and returns its address
// It will write to file the compiled circuit and the verifier logicsig in `ArtefactsDirPath`
func generateVerifier(curve ecc.ID, c *CircuitData) types.Address {
	verifierPath := filepath.Join(ArtefactsDirPath, c.VerifierName+".py")

	outdatedCircuit := utils.ShouldRecompile(c.CompiledPath, c.DefinitionPath)
	outdatedVerifier := utils.ShouldRecompile(verifierPath, c.CompiledPath)

	if outdatedCircuit || outdatedVerifier {
		compiledCircuit, err := ap.Compile(c.Circuit, curve, setup.Trusted)
		if err != nil {
			log.Fatalf("Error compiling circuit for %s: %v", c.VerifierName, err)
		}
		err = utils.SerializeCompiledCircuit(compiledCircuit, c.CompiledPath)
		if err != nil {
			log.Fatalf("Error serializing compiled circuit for %s: %v",
				c.VerifierName, err)
		}
		err = compiledCircuit.WritePuyaPyVerifier(verifierPath, verifier.LogicSig)
		if err != nil {
			log.Fatalf("Error writing %s: %v", c.VerifierName, err)
		}
		err = utils.CompileWithPuyaPy(verifierPath, "")
		if err != nil {
			log.Fatalf("Error compiling %s: %v", c.VerifierName, err)
		}
		err = utils.RenamePuyaPyOutput(verifier.DefaultFileName,
			c.VerifierName, ArtefactsDirPath)
		if err != nil {
			log.Fatalf("Error renaming %s: %v", c.VerifierName, err)
		}
	}

	verifierBytecode, err := avm.CompileTealFromFile(filepath.Join(ArtefactsDirPath,
		c.VerifierName+".teal"))
	if err != nil {
		log.Fatalf("Error compiling teal for verifier: %v", err)
	}
	err = os.WriteFile(filepath.Join(ArtefactsDirPath, c.VerifierName+".tok"),
		verifierBytecode, 0644)
	if err != nil {
		log.Fatalf("Error writing verifier bytecode: %v", err)
	}

	lsigAddress := crypto.LogicSigAddress(types.LogicSig{Logic: verifierBytecode})
	return lsigAddress
}

// compileMainContract compiles the main contract with the given verifier addresses
// It will write to file the compiled programs in `ArtefactsDirPath`
func compileMainContract(
	depositVerifierAddress types.Address,
	withdrawalVerifierAddress types.Address,
) {
	approvalTealPath := filepath.Join(ArtefactsDirPath, MainContractName+".approval.teal")
	approvalSources := []string{MainContractSourcePath, DeppositVerifierTealPath,
		WithdrawalVerifierTealPath}
	clearTealPath := filepath.Join(ArtefactsDirPath, MainContractName+".clear.teal")

	recompile := utils.ShouldRecompile(approvalTealPath, approvalSources...) ||
		utils.ShouldRecompile(clearTealPath, MainContractSourcePath)

	if recompile {
		err := utils.CompileWithPuyaPy(MainContractSourcePath, "--out-dir="+ArtefactsDirPath)
		if err != nil {
			log.Fatalf("Error compiling main contract: %v", err)
		}

		substitutions := map[string]string{
			"TMPL_DEPOSIT_VERIFIER_ADDRESS": "0x" +
				hex.EncodeToString(depositVerifierAddress[:]),
			"TMPL_WITHDRAWAL_VERIFIER_ADDRESS": "0x" +
				hex.EncodeToString(withdrawalVerifierAddress[:]),
		}
		for _, path := range []string{approvalTealPath, clearTealPath} {
			err = replaceInFile(path, substitutions)
			if err != nil {
				log.Fatalf("Error substituting in %s: %v", path, err)
			}
		}
	}
}

// deployMainContract deploys the main contract to the network and returns the app id
// Writes the app id and creation block no. to the json file specified by setup.AppFileanme
func deployMainContract() (appId uint64) {

	var err error
	deployedBlock := uint64(0)

	appId, deployedBlock, err = avm.CreateApp(MainContractName, config.CreateMethodName,
		[]any{}, ArtefactsDirPath)
	if err != nil {
		log.Fatalf("Error deploying main contract: %v", err)
	}
	app := APP{Id: appId, CreationBlock: deployedBlock}
	// check if the json exists and contains the correct app id, if not update/create it
	if _, err := os.Stat(AppPath); err == nil {
		var appOnFile APP
		DecodeJSONFile(AppPath, &appOnFile)
		if appOnFile.Id != appId {
			encodeJSONFile(AppPath, app)
		}
	} else {
		file, err := os.Create(AppPath)
		if err != nil {
			log.Fatalf("Error creating app id file: %v", err)
		}
		defer file.Close()
		encodeJSONFile(AppPath, app)
	}

	return appId
}

// setupTSS setup and compiles the TSS contract and returns the TSS address
// It will write to file the TSS teal in `ArtefactsDirPath`
func setupTSS(appId uint64) []byte {
	tssTealFilePath := filepath.Join(ArtefactsDirPath, TssName+".teal")

	if utils.ShouldRecompile(tssTealFilePath, TssSourcePath, AppPath) {
		err := utils.CompileWithPuyaPy(TssSourcePath, "--out-dir="+ArtefactsDirPath)
		if err != nil {
			log.Fatalf("Error compiling tss: %v", err)
		}
		substitutions := map[string]string{
			"TMPL_MAIN_CONTRACT_APP_ID": strconv.FormatUint(appId, 10),
		}
		err = replaceInFile(tssTealFilePath, substitutions)
		if err != nil {
			log.Fatalf("Error substituting tss template: %v", err)
		}
	}

	tssBytecode, err := avm.CompileTealFromFile(tssTealFilePath)
	if err != nil {
		log.Fatalf("Error compiling TSS teal: %v", err)
	}
	err = os.WriteFile(TssBytecodePath, tssBytecode, 0644)
	if err != nil {
		log.Fatalf("Error writing TSS bytecode: %v", err)
	}

	return tssBytecode
}

// InitContract initializes the contract with the given TSS address.
func initMainContract(appId uint64, tssAddress string) {
	// We will send a group with three transactions:
	// 1. initial funding for the main contract to cover boxes' minimum balance requirement
	// 2. initial funding for the TSS
	// 3. the init method call

	algodClient := avm.GetAlgodClient()
	signerAccount := avm.GetDefaultAccount()
	mainContractAddress := crypto.GetApplicationAddress(appId).String()

	schema, err := avm.ReadArc32Schema(AppSchemaPath)
	if err != nil {
		log.Fatalf("Error reading main contract schema: %v", err)
	}
	method, err := schema.Contract.GetMethodByName("init")
	if err != nil {
		log.Fatalf("failed to get method init: %v", err)
	}
	tssAddressBytes, err := types.DecodeAddress(tssAddress)
	if err != nil {
		log.Fatalf("Error decoding TSS address: %v", err)
	}

	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		log.Fatalf("failed to get suggested params: %v", err)
	}
	waitRounds := uint64(8)
	sp.LastRoundValid = sp.FirstRoundValid + types.Round(waitRounds)
	var atc = transaction.AtomicTransactionComposer{}

	recipients := []string{mainContractAddress, tssAddress}
	fundingAmounts := []uint64{config.InitialMbr, 100_000}
	for i := range 2 {
		txn, err := transaction.MakePaymentTxn(
			signerAccount.Address.String(),
			recipients[i],
			fundingAmounts[i],
			nil, "", sp)
		if err != nil {
			log.Fatalf("failed to make payment txn: %v", err)
		}
		txnWithSigner := transaction.TransactionWithSigner{
			Txn:    txn,
			Signer: transaction.BasicAccountTransactionSigner{Account: *signerAccount},
		}
		atc.AddTransaction(txnWithSigner)
	}

	txnParams := transaction.AddMethodCallParams{
		AppID:           appId,
		Method:          method,
		MethodArgs:      []interface{}{tssAddressBytes[:]},
		Sender:          signerAccount.Address,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          transaction.BasicAccountTransactionSigner{Account: *signerAccount},
		BoxReferences: []types.AppBoxReference{
			{AppID: appId, Name: []byte("roots")},
			{AppID: appId, Name: []byte("subtree")},
			{AppID: appId, Name: []byte("subtree")},
		},
	}

	if err := atc.AddMethodCall(txnParams); err != nil {
		log.Fatalf("failed to add method call: %v", err)
	}
	res, err := atc.Execute(algodClient, context.Background(), waitRounds)
	if err != nil {
		log.Fatalf("Error initializing main contract: %v", err)
	}

	log.Printf("Main contract initialized at transaction %s\n", res.TxIDs[2])
}

// writeTreeConfig writes the tree configuration to the TreeConfigPath
func writeTreeConfig() {
	jsonData, err := json.MarshalIndent(config.Tree, "", "    ")
	if err != nil {
		log.Fatal("Error marshalling TreeConfig: ", err)
	}
	err = os.WriteFile(TreeConfigPath, jsonData, 0644)
	if err != nil {
		log.Fatal("Error writing TreeConfig: ", err)
	}
}

// updateConstantsInSmartContracts updates the constants in the smart contracts files
func updateConstantsInSmartContracts() {
	changesMainContract := [][2]string{
		{"CURVE_MOD", config.Curve.ScalarField().String()},
		{"DEPOSIT_MINIMUM_AMOUNT", formatWithUnderscores(config.DepositMinimumAmount) + " # 1 Algo"},
		{"TREE_DEPTH", formatWithUnderscores(config.MerkleTreeLevels)},
		{"MAX_LEAVES", formatWithUnderscores(1 << config.MerkleTreeLevels)},
		{"ROOTS_COUNT", formatWithUnderscores(config.RootsCount)},
		{"INITIAL_ROOT", "\"" +
			hex.EncodeToString(config.Tree.ZeroHashes[config.MerkleTreeLevels]) + "\""},
		{"DEPOSIT_OPCODE_BUDGET_OPUP", formatWithUnderscores(config.DepositOpcodeBudgetOpUp)},
		{"WITHDRAWAL_OPCODE_BUDGET_OPUP",
			formatWithUnderscores(config.WithdrawalOpcodeBudgetOpUp)},
		{"NULLIFIER_MBR", formatWithUnderscores(config.NullifierMbr)},
	}
	err := changeValueInFile(MainContractSourcePath, changesMainContract)
	if err != nil {
		log.Printf("Error updating constants in file %s: %v\n", MainContractSourcePath, err)
	}
	err = updateZeroHashesInFile(MainContractSourcePath,
		config.Tree.ZeroHashes[:config.MerkleTreeLevels])
	if err != nil {
		log.Printf("Error updating zero hashes in file %s: %v\n", MainContractSourcePath, err)
	}
}

// exportSetupFiles copies the necessary files to initialize frontends to the network folder
func exportSetupFiles(network deployed.Network) {
	filepaths := []string{AppPath, TreeConfigPath, AppSchemaPath, TssBytecodePath,
		DepositVerifierBytecodePath, WithdrawalVerifierBytecodePath, TreeConfigPath,
		DepositCircuitData.CompiledPath, WithdrawalCircuitData.CompiledPath}
	for _, path := range filepaths {
		err := copyFile(path, filepath.Join(network.DirPath(), filepath.Base(path)))
		if err != nil {
			log.Fatalf("Error copying file %s: %v", path, err)
		}
	}
}
