package avm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/giuliop/HermesVault-smartcontracts/deployed"

	"github.com/algorand/go-algorand-sdk/v2/abi"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

var (
	algodClient       *algod.Client
	defaultAccount    *crypto.Account
	appManagerAddress types.Address
)

func Initialize(network deployed.Network) {
	initCofig(network)
	algodConfig := readAlgodConfig()
	var err error
	algodClient, err = algod.MakeClient(
		algodConfig.URL,
		algodConfig.Token,
	)
	if err != nil {
		log.Fatalf("Failed to create algod client: %v", err)
	}

	defaultAccount, err = readDefaultAccount()
	if err != nil {
		log.Fatalf("failed to get default account: %v", err)
	}
	appManagerAddress, err = types.DecodeAddress(readAppManagerAddress())
	if err != nil {
		log.Fatalf("failed to decode manager address: %v", err)
	}
}

func GetAlgodClient() *algod.Client {
	return algodClient
}

func GetDefaultAccount() (account *crypto.Account) {
	return defaultAccount
}

func GetAppManagerAddress() types.Address {
	return appManagerAddress
}

// CompileTealFromFile reads a teal file and returns a compiled b64 binary.
// A local network must be running
func CompileTealFromFile(tealFile string) ([]byte, error) {
	algodClient := GetAlgodClient()

	teal, err := os.ReadFile(tealFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s from file: %v", tealFile, err)
	}

	result, err := algodClient.TealCompile(teal).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to compile %s: %v", tealFile, err)
	}
	binary, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		log.Fatalf("failed to decode approval program: %v", err)
	}

	return binary, nil
}

// Arc32Schema defines a partial ARC32 schema
type Arc32Schema struct {
	Source struct {
		Approval string `json:"approval"`
		Clear    string `json:"clear"`
	} `json:"source"`
	State struct {
		Global struct {
			NumByteSlices uint64 `json:"num_byte_slices"`
			NumUints      uint64 `json:"num_uints"`
		} `json:"global"`
		Local struct {
			NumByteSlices uint64 `json:"num_byte_slices"`
			NumUints      uint64 `json:"num_uints"`
		} `json:"local"`
	} `json:"state"`
	Contract abi.Contract `json:"contract"`
}

// ReadArc32Schema reads an ARC32 schema from a JSON file
func ReadArc32Schema(filepath string) (
	schema *Arc32Schema, err error) {

	file, err := os.Open(filepath)
	if err != nil {
		return schema, fmt.Errorf("error opening schema file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&schema); err != nil {
		return schema, fmt.Errorf("error decoding schema file: %v", err)
	}

	return schema, nil
}

// CreateApp creates an arc4 app. It takes an appName and sourceDir to find the teal
// and schema files listed below, the methodName to call, the args for the method.
// SourceDir must contain <appName> + .approval.teal, .clear.teal , .arc32.json
func CreateApp(appName string, methodName string, args []any, sourceDir string,
) (appId uint64, confirmedBlock uint64, err error) {
	algodClient := GetAlgodClient()

	approvalBin, err := CompileTealFromFile(filepath.Join(sourceDir, appName+".approval.teal"))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read approval program: %v", err)
	}
	clearBin, err := CompileTealFromFile(filepath.Join(sourceDir, appName+".clear.teal"))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read clear program: %v", err)
	}
	schema, err := ReadArc32Schema(filepath.Join(sourceDir, appName+".arc32.json"))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read arc32 schema: %v", err)
	}

	creator := GetDefaultAccount()

	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get suggested params: %v", err)
	}
	waitRounds := uint64(8)
	sp.LastRoundValid = sp.FirstRoundValid + types.Round(waitRounds)
	method, err := schema.Contract.GetMethodByName(methodName)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get create method: %v", err)
	}
	extraPages := (uint32(len(approvalBin)) + uint32(len(clearBin))) / 2048
	if extraPages > 3 {
		return 0, 0, fmt.Errorf("approval program too large even for extra pages: "+
			"%d bytes", len(approvalBin))
	}

	var onComplete types.OnCompletion
	var sender types.Address
	onComplete = types.NoOpOC
	sender = creator.Address

	var atc transaction.AtomicTransactionComposer

	txnParams := transaction.AddMethodCallParams{
		Method:          method,
		MethodArgs:      args,
		Sender:          sender,
		SuggestedParams: sp,
		OnComplete:      onComplete,
		ApprovalProgram: approvalBin,
		ClearProgram:    clearBin,
		Signer:          transaction.BasicAccountTransactionSigner{Account: *creator},
		GlobalSchema: types.StateSchema{
			NumUint:      schema.State.Global.NumUints,
			NumByteSlice: schema.State.Global.NumByteSlices,
		},
		LocalSchema: types.StateSchema{
			NumUint:      schema.State.Local.NumUints,
			NumByteSlice: schema.State.Local.NumByteSlices,
		},
		ExtraPages: extraPages,
	}

	if err := atc.AddMethodCall(txnParams); err != nil {
		log.Fatalf("failed to add method call: %v", err)
	}
	res, err := atc.Execute(algodClient, context.Background(), waitRounds)
	if err != nil {
		log.Fatalf("Error creating main contract: %v", err)
	}
	appId = res.MethodResults[0].TransactionInfo.ApplicationIndex
	log.Printf("App %s created with id %d at transaction %s\n", appName, appId, res.TxIDs[0])

	return appId, res.ConfirmedRound, nil
}

// DeleteAppFromId deletes an app and returns the transaction id
func DeleteAppFromId(appId uint64, deleteMethodName string, appSchema *Arc32Schema) error {
	algodClient := GetAlgodClient()

	creator := GetDefaultAccount()

	sp, err := algodClient.SuggestedParams().Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %v", err)
	}
	waitRounds := uint64(8)
	sp.LastRoundValid = sp.FirstRoundValid + types.Round(waitRounds)
	deleteMethod, err := appSchema.Contract.GetMethodByName("update")
	if err != nil {
		return fmt.Errorf("failed to get update method: %v", err)
	}
	txn, err := transaction.MakeApplicationDeleteTx(
		appId, [][]byte{deleteMethod.GetSelector()}, nil, nil, nil, sp,
		creator.Address, nil, types.Digest{}, [32]byte{}, types.ZeroAddress,
	)
	if err != nil {
		return fmt.Errorf("failed to make delete txn: %v", err)
	}
	txid, stx, err := crypto.SignTransaction(creator.PrivateKey, txn)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}
	_, err = algodClient.SendRawTransaction(stx).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}
	_, err = transaction.WaitForConfirmation(algodClient, txid, waitRounds,
		context.Background())
	if err != nil {
		return fmt.Errorf("error waiting for confirmation:  %v", err)
	}

	log.Printf("App %d deleted with transaction %s\n", appId, txid)

	return nil
}

// EnsureFunded checks if the given address has at least min microalgos and if not,
// tops it up from the default account
func EnsureFunded(address string, min uint64) error {
	algodClient := GetAlgodClient()
	recipientAccount, err := algodClient.AccountInformation(address).Do(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get account information: %v", err)
	}
	if recipientAccount.Amount < uint64(min) {
		account := GetDefaultAccount()
		sp, err := algodClient.SuggestedParams().Do(context.Background())
		if err != nil {
			log.Fatalf("failed to get suggested params: %v", err)
		}
		waitRounds := uint64(4)
		sp.LastRoundValid = sp.FirstRoundValid + types.Round(waitRounds)
		txn, err := transaction.MakePaymentTxn(account.Address.String(),
			address, min-recipientAccount.Amount, nil, types.ZeroAddress.String(), sp)
		if err != nil {
			log.Fatalf("failed to make payment txn: %v", err)
		}
		txid, stx, err := crypto.SignTransaction(account.PrivateKey, txn)
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %v", err)
		}
		_, err = algodClient.SendRawTransaction(stx).Do(context.Background())
		if err != nil {
			return fmt.Errorf("failed to send transaction: %v", err)
		}
		_, err = transaction.WaitForConfirmation(algodClient, txid, waitRounds,
			context.Background())
		if err != nil {
			return fmt.Errorf("error waiting for confirmation:  %v", err)
		}
	}
	return nil
}

// MBR returns the minimum balance required for an app escrow account.
func MBR(appID uint64) int {
	algodClient := GetAlgodClient()
	appAddress := crypto.GetApplicationAddress(appID)
	accountInfo, err := algodClient.AccountInformation(appAddress.String()).
		Do(context.Background())
	if err != nil {
		log.Fatalf("failed to get account information: %v", err)
	}
	return int(accountInfo.MinBalance)
}
