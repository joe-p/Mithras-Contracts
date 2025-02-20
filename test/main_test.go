package test

import (
	"fmt"
	"testing"

	"github.com/giuliop/HermesVault-smartcontracts/avm"
	"github.com/giuliop/HermesVault-smartcontracts/config"
	"github.com/giuliop/HermesVault-smartcontracts/deployed"
	"github.com/giuliop/HermesVault-smartcontracts/setup"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// var nodeDir = filepath.Join(os.Getenv("HOME"), "dev/algorand/devnet/network/data")

func TestMain(t *testing.T) {
	setup.SetupApp(deployed.DevNet)
	f := NewAppFrontend()

	account := crypto.GenerateAccount()
	err := avm.EnsureFunded(account.Address.String(), 1000*1e6)
	if err != nil {
		t.Fatalf("Error funding account: %s", err)
	}

	deposit, err := f.SendDeposit(&account, 10*1e6)
	if err != nil {
		t.Fatalf("Error making deposit: %s", err)
	}
	fmt.Printf("Deposit made at trasactions: %v by %s\n", deposit.TxnIds,
		account.Address.String())

	// let's make a withdrawal to a funded account
	withdrawal, err := f.SendWithdrawal(&account, 5*1e6, false, 0, deposit.Note)
	if err != nil {
		t.Fatalf("Error making withdrawal: %s", err)
	}
	fmt.Printf("Withdrawal made at transactions: %v by %s with change of %v\n",
		withdrawal.TxnIds, account.Address.String(), withdrawal.Note.Amount)

	// now let's make another withdrawal to a zero balance account
	err = avm.EnsureFunded(f.App.TSS.Address.String(), 101*1e6)
	if err != nil {
		t.Fatalf("Error funding account: %s", err)
	}

	newAccount := crypto.GenerateAccount()

	withdrawal, err = f.SendWithdrawal(&newAccount, 48*1e5, false, 0, withdrawal.Note)
	if err != nil {
		t.Fatalf("Error making withdrawal: %s", err)
	}
	fmt.Printf("Withdrawal made at transactions: %v by %s with change of %v\n",
		withdrawal.TxnIds, account.Address.String(), withdrawal.Note.Amount)

	// Let's try one more withdrawal, it should fail because the last change
	// is zero
	_, err = f.SendWithdrawal(&newAccount, 1, true, 0, withdrawal.Note)
	if err != nil {
		fmt.Printf("Error making withdrawal, as expected: %s\n", err)
	} else {
		t.Fatalf("Withdrawal should have failed but it didn't")
	}

	// // now we make 100 deposits and 1 withdrawal
	// for i := 1; i <= 100; i++ {
	// 	deposit, err = f.SendDeposit(&account, 1*1e6)
	// 	if err != nil {
	// 		t.Fatalf("Error making deposit %d/100: %s", i, err)
	// 	}
	// }
	// _, err = f.SendWithdrawal(&account, 0.1*1e6, false, 0, deposit.Note)
	// if err != nil {
	// 	t.Fatalf("Error making final withdrawal: %s", err)
	// }

	// bold success :)
	fmt.Printf("\033[1m\nAll tests passed !\n\n\033[0m")

	// delete the APP
	err = avm.DeleteAppFromId(f.App.Id, config.UpdateMethodName, (f.App.Schema))
	if err != nil {
		t.Logf("Error deleting app (id %v): %s", f.App.Id, err)
	}
}
