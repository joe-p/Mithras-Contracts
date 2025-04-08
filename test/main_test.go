package test

import (
	"fmt"
	"testing"

	"github.com/giuliop/HermesVault-smartcontracts/avm"
	"github.com/giuliop/HermesVault-smartcontracts/config"
	"github.com/giuliop/HermesVault-smartcontracts/deployed"
	"github.com/giuliop/HermesVault-smartcontracts/setup"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
)

// var nodeDir = filepath.Join(os.Getenv("HOME"), "dev/algorand/devnet/network/data")

func TestMain(t *testing.T) {
	setup.CreateApp(deployed.DevNet)
	f := NewAppFrontend()

	account := crypto.GenerateAccount()
	err := avm.EnsureFunded(account.Address.String(), 10000*1e6)

	if err != nil {
		t.Fatalf("Error funding account: %s", err)
	}

	// check initial MBR is correct
	mbr := avm.MBR(f.App.Id)
	if mbr != config.InitialMbr {
		t.Fatalf("Initial MBR different than expected %d, got %d", config.InitialMbr, mbr)
	}

	depositAmount := uint64(10 * 1e6)
	deposit, err := f.SendDeposit(&account, depositAmount)
	if err != nil {
		t.Fatalf("Error making deposit: %s", err)
	}
	fmt.Printf("Deposit made at trasactions: %v by %s\n", deposit.TxnIds,
		account.Address.String())

	// let's make a withdrawal to a funded account
	firstWithdrawalAmount := uint64(5 * 1e6)
	withdrawal, err := f.SendWithdrawal(&account, firstWithdrawalAmount, false, 0,
		deposit.Note)
	if err != nil {
		t.Fatalf("Error making withdrawal: %s", err)
	}
	fmt.Printf("Withdrawal made at transactions: %v by %s with change of %v\n",
		withdrawal.TxnIds, account.Address.String(), withdrawal.Note.Amount)

	newAccount := crypto.GenerateAccount()

	// now let's make a withdrawal to a new account, withdrawing everything
	fee := config.WithdrawalMinFeeMultiplier*transaction.MinTxnFee + config.NullifierMbr
	availableToWithdraw := depositAmount - firstWithdrawalAmount - uint64(2*fee)
	withdrawal, err = f.SendWithdrawal(&newAccount, availableToWithdraw, false, 0,
		withdrawal.Note)
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

	// now we make 1 deposit and 100 withdrawal
	deposit, err = f.SendDeposit(&account, 1000*1e6)
	if err != nil {
		t.Fatalf("Error making deposit0: %s", err)
	}
	note := deposit.Note
	for i := 1; i <= 100; i++ {
		w, err := f.SendWithdrawal(&account, 0.1*1e6, false, 0, note)
		if err != nil {
			t.Fatalf("Error making withdrawal %d/100: %s", i, err)
		}
		note = w.Note
	}

	// check final MBR is as expected
	mbr = avm.MBR(f.App.Id)
	if mbr != config.InitialMbr+102*config.NullifierMbr {
		t.Fatalf("Final MBR different than expected %d, got %d", config.InitialMbr, mbr)
	}

	// bold success :)
	fmt.Printf("\033[1m\nAll tests passed !\n\n\033[0m")
}
