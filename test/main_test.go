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
	fmt.Printf("Deposit made at trasactions: %v by %s\n", deposit.TxnIds[0],
		account.Address.String())

	// let's make a withdrawal to a funded account
	firstWithdrawalAmount := uint64(5 * 1e6)
	firstWithdrawalOpts := &WithdrawalOpts{
		recipient:    account.Address,
		feeRecipient: account.Address,
		feeSigner:    transaction.BasicAccountTransactionSigner{Account: account},
		amount:       firstWithdrawalAmount,
		fromNote:     deposit.Note,
	}
	firstWithdrawal, err := f.SendWithdrawal(firstWithdrawalOpts)
	if err != nil {
		t.Fatalf("Error making withdrawal: %s", err)
	}
	fmt.Printf("Withdrawal made at transactions: %v by %s with change of %v\n",
		firstWithdrawal.TxnIds[0], account.Address.String(), firstWithdrawal.Note.Amount)

	newAccount := crypto.GenerateAccount()

	// now let's make a withdrawal to a new account using the TSS, withdrawing everything
	fee := config.WithdrawalMinFeeMultiplier*transaction.MinTxnFee + config.NullifierMbr
	availableToWithdraw := depositAmount - firstWithdrawalAmount - uint64(2*fee)
	secondWithdrawalOpts := &WithdrawalOpts{
		recipient: newAccount.Address,
		amount:    availableToWithdraw,
		fromNote:  firstWithdrawal.Note,
	}
	secondWithdrawal, err := f.SendWithdrawal(secondWithdrawalOpts)
	if err != nil {
		t.Fatalf("Error making withdrawal: %s", err)
	}
	fmt.Printf("Withdrawal made at transactions: %v by %s with change of %v\n",
		secondWithdrawal.TxnIds[0], account.Address.String(), secondWithdrawal.Note.Amount)

	// Let's try one more withdrawal, it should fail because the last change
	// is zero
	thirdWithdrawalOpts := secondWithdrawalOpts
	thirdWithdrawalOpts.amount = 1
	_, err = f.SendWithdrawal(thirdWithdrawalOpts)
	if err != nil {
		fmt.Println("Error making withdrawal, as expected")
	} else {
		t.Fatalf("Withdrawal should have failed but it didn't")
	}

	// now we make 1 deposit and 100 withdrawal
	deposit, err = f.SendDeposit(&account, 1000*1e6)
	if err != nil {
		t.Fatalf("Error making deposit: %s", err)
	}
	note := deposit.Note
	newAccount = crypto.GenerateAccount()
	withdrawalOpts := &WithdrawalOpts{
		recipient: newAccount.Address,
		amount:    0.1 * 1e6,
		fromNote:  note,
	}
	for i := 1; i <= 100; i++ {
		w, err := f.SendWithdrawal(withdrawalOpts)
		if err != nil {
			t.Fatalf("Error making withdrawal %d/100: %s", i, err)
		}
		withdrawalOpts.fromNote = w.Note
	}

	// check final MBR is as expected
	mbr = avm.MBR(f.App.Id)
	if mbr != config.InitialMbr+102*config.NullifierMbr {
		t.Fatalf("Final MBR different than expected %d, got %d", config.InitialMbr, mbr)
	}

	// bold success :)
	fmt.Printf("\033[1m\nAll tests passed !\n\n\033[0m")
}
