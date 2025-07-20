// package interact contains logic to interact with the smart contracts
package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"

	bnt "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"

	"github.com/giuliop/HermesVault-smartcontracts/avm"
	"github.com/giuliop/HermesVault-smartcontracts/circuits"
	"github.com/giuliop/HermesVault-smartcontracts/config"
	"github.com/giuliop/HermesVault-smartcontracts/encrypt"

	"github.com/algorand/go-algorand-sdk/v2/abi"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	sigEddsa "github.com/consensys/gnark/std/signature/eddsa"
	ap "github.com/giuliop/algoplonk"
	"github.com/giuliop/algoplonk/utils"
)

const (
	DepositMethod    = config.DepositMethodName
	WithDrawalMethod = config.WithDrawalMethodName
	NoOpMethod       = config.NoOpMethodName
)

type TreeConfig struct {
	Depth      int
	ZeroValue  []byte
	ZeroHashes [][]byte
	HashFunc   config.HashFunc
}

// Note represent a deposit / change in the merkle tree, where it is stored
// as Commitment
type Note struct {
	Amount        uint64
	commitment    []byte
	k             []byte
	r             []byte
	outputX       []byte // public key x coordinate
	outputY       []byte // public key y coordinate
	insertedIndex int    // -1 if not inserted, leaf index in tree otherwise
}

type EncryptedNote struct {
	EncryptedK      []byte
	EncryptedR      []byte
	EncryptedOutput []byte
	EncryptedInput  []byte
	EncryptedAmount []byte
}

func (f *Frontend) MakeNullifier(note *Note) []byte {
	return f.Tree.hashFunc(uint64ToBytes32(note.Amount), note.k)
}

func (f *Frontend) MakeLeafValue(n *Note) []byte {
	ab := uint64ToBytes32(n.Amount)
	h := f.Tree.hashFunc(ab, n.k, n.r, n.outputX, n.outputY)
	return h
}

type Deposit struct {
	FromAddress string
	TxnIds      []string
	Note        *Note
}

type Withdrawal struct {
	ToAddress string
	TxnIds    []string
	Note      *Note
}

type Frontend struct {
	Tree        *Tree
	Deposits    []*Deposit
	Withdrawals []*Withdrawal
	App         *App
}

type App struct {
	Id                 uint64
	Schema             *avm.Arc32Schema
	TSS                *Lsig
	DepositCc          *ap.CompiledCircuit
	WithdrawalCc       *ap.CompiledCircuit
	DepositVerifier    *Lsig
	WithdrawalVerifier *Lsig
	TreeConfig         TreeConfig
}

type Lsig struct {
	Account crypto.LogicSigAccount
	Address types.Address
}

// NewAppFrontend creates a new Frontend for the app looking for the setup files in setupDir
func NewAppFrontend() *Frontend {
	app := readSetup()
	return &Frontend{
		Tree: NewTree(app.TreeConfig),
		App:  app,
	}
}

func (f *Frontend) MakeCommitment(amount uint64, k, r []byte, pubkey eddsa.PublicKey) []byte {
	ab := uint64ToBytes32(amount)
	x := pubkey.A.X.Bytes()
	y := pubkey.A.Y.Bytes()

	h := f.Tree.hashFunc(ab, k, r, x[:], y[:])
	h = f.Tree.hashFunc(h)
	return h
}

// RandomBigInt returns a random big integer bigger than 1 of up to
// maxBits bits. If maxBits is less than 1, it defaults to 32.
func randomBigInt(maxBits int64) *big.Int {
	if maxBits < 1 {
		maxBits = 32
	}
	var max *big.Int = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(maxBits), nil)
	for {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		if n.Cmp(big.NewInt(2)) > 0 {
			return n
		}
	}
}

// NewRandomNonce generates a random nonce of RandomNonceByteSize bytes and returns
// a 32 byte slice padding with zeros as needed
func NewRandomNonce() []byte {
	n := randomBigInt(config.RandomNonceByteSize * 8)
	res := make([]byte, 32)
	n.FillBytes(res)
	return res
}

func (f *Frontend) NewNote(amount uint64, inputPrivKey eddsa.PrivateKey, outputPubkey eddsa.PublicKey) (*Note, *EncryptedNote) {
	// Extract scalar from inputPrivKey.Bytes().
	const pubSize = 32
	const sizeFr = 32
	privBytes := inputPrivKey.Bytes()
	scalarBytes := privBytes[pubSize : pubSize+sizeFr]
	scalar := new(big.Int).SetBytes(scalarBytes)

	// Compute shared point: scalar * outputPubkey.A.
	var sharedPoint bnt.PointAffine
	sharedPoint.ScalarMultiplication(&outputPubkey.A, scalar)

	xBytes := sharedPoint.X.Bytes()
	yBytes := sharedPoint.Y.Bytes()
	sharedSecret := f.Tree.hashFunc(xBytes[:], yBytes[:])

	kDomain := make([]byte, 32)
	rDomain := make([]byte, 32)
	kDomain[31] = 'k'
	rDomain[31] = 'r'

	// TODO: Add sender, lv, lease to the K and R hashes
	k := f.Tree.hashFunc(sharedSecret, kDomain)
	r := f.Tree.hashFunc(sharedSecret, rDomain)

	commitment := f.MakeCommitment(amount, k, r, outputPubkey)

	// Generate ephemeral key pair for ECIES encryption
	ephemeralPriv, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Errorf("failed to generate ephemeral key: %v", err))
	}

	// K, R, output, input, and amount are encrypted using ECIES
	// In this test, we are using the same pubkey and ephemeralPriv for all encrypted values
	// In an actual implementation, you could have a separate view key
	encryptedK, err := encrypt.ECIESEncrypt(k, outputPubkey, ephemeralPriv.PublicKey, *ephemeralPriv)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt k: %v", err))
	}

	encryptedR, err := encrypt.ECIESEncrypt(r, outputPubkey, ephemeralPriv.PublicKey, *ephemeralPriv)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt r: %v", err))
	}

	encryptedOutput, err := encrypt.ECIESEncrypt(outputPubkey.Bytes(), outputPubkey, ephemeralPriv.PublicKey, *ephemeralPriv)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt output public key: %v", err))
	}

	encryptedInput, err := encrypt.ECIESEncrypt(inputPrivKey.PublicKey.Bytes(), outputPubkey, ephemeralPriv.PublicKey, *ephemeralPriv)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt input public key: %v", err))
	}

	encryptedAmount, err := encrypt.ECIESEncrypt(uint64ToBytes32(amount), outputPubkey, ephemeralPriv.PublicKey, *ephemeralPriv)
	if err != nil {
		panic(fmt.Errorf("failed to encrypt amount: %v", err))
	}

	x := outputPubkey.A.X.Bytes()
	y := outputPubkey.A.Y.Bytes()

	note := &Note{
		Amount:        amount,
		commitment:    commitment,
		k:             k,
		r:             r,
		outputX:       x[:],
		outputY:       y[:],
		insertedIndex: -1,
	}

	encryptedNote := &EncryptedNote{
		EncryptedK:      encryptedK,
		EncryptedR:      encryptedR,
		EncryptedOutput: encryptedOutput,
		EncryptedInput:  encryptedInput,
		EncryptedAmount: encryptedAmount,
	}

	return note, encryptedNote
}

// uint64ToBytes32 converts a uint64 to a 32 byte array
func uint64ToBytes32(amount uint64) []byte {
	amountBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(amountBytes[24:], amount)
	return amountBytes
}

// RecoverNote attempts to decrypt and reconstruct a note from encrypted data
// using the provided private key. Returns a Note if successful.
func (f *Frontend) RecoverNote(encryptedNote *EncryptedNote, privkey eddsa.PrivateKey, insertedIndex int) (*Note, error) {
	// Decrypt k and r using the private key
	k, err := encrypt.ECIESDecrypt(encryptedNote.EncryptedK, privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt k: %v", err)
	}

	r, err := encrypt.ECIESDecrypt(encryptedNote.EncryptedR, privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt r: %v", err)
	}

	// Decrypt the output public key
	outputPubkeyBytes, err := encrypt.ECIESDecrypt(encryptedNote.EncryptedOutput, privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt output: %v", err)
	}

	// Decrypt the amount
	amountBytes, err := encrypt.ECIESDecrypt(encryptedNote.EncryptedAmount, privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt amount: %v", err)
	}

	// Convert amount bytes to uint64 (stored in last 8 bytes of 32-byte array)
	amount := binary.BigEndian.Uint64(amountBytes[24:])

	// Reconstruct the public key from bytes
	var outputPubkey eddsa.PublicKey
	_, err = outputPubkey.SetBytes(outputPubkeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct public key: %v", err)
	}

	// Extract coordinates
	outputXCoord := outputPubkey.A.X.Bytes()
	outputYCoord := outputPubkey.A.Y.Bytes()

	// Compute the commitment to verify correctness
	commitment := f.MakeCommitment(amount, k, r, outputPubkey)

	note := &Note{
		Amount:        amount,
		commitment:    commitment,
		k:             k,
		r:             r,
		outputX:       outputXCoord[:],
		outputY:       outputYCoord[:],
		insertedIndex: insertedIndex,
	}

	return note, nil
}

// TryRecoverNote attempts to recover a note without returning an error.
// Returns nil if the note cannot be recovered (e.g., wrong private key).
func (f *Frontend) TryRecoverNote(encryptedNote *EncryptedNote, privkey eddsa.PrivateKey, insertedIndex int) *Note {
	note, err := f.RecoverNote(encryptedNote, privkey, insertedIndex)
	if err != nil {
		return nil
	}
	return note
}

// SendDeposit creates a deposit transaction and sends it to the network
func (f *Frontend) SendDeposit(from *crypto.Account, amount uint64, outputPubkey eddsa.PublicKey, inputPrivkey eddsa.PrivateKey) (
	*Deposit, error) {

	note, _ := f.NewNote(amount, inputPrivkey, outputPubkey)

	x := outputPubkey.A.X.Bytes()
	y := outputPubkey.A.Y.Bytes()
	assignment := &circuits.DepositCircuit{
		Amount:     amount,
		Commitment: note.commitment,
		K:          note.k,
		R:          note.r,
		OutputX:    x[:],
		OutputY:    y[:],
	}
	verifiedProof, err := f.App.DepositCc.Verify(assignment)
	if err != nil {
		return nil, fmt.Errorf("failed to verify deposit proof: %v", err)
	}
	proof := ap.MarshalProof(verifiedProof.Proof)
	publicInputs, err := ap.MarshalPublicInputs(verifiedProof.Witness)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public inputs: %v", err)
	}
	args, err := utils.ProofAndPublicInputsForAtomicComposer(proof, publicInputs)
	if err != nil {
		return nil, fmt.Errorf("failed to abi encode proof and public inputs: %v", err)
	}
	args = append(args, from.Address)

	var atc = transaction.AtomicTransactionComposer{}

	algod := avm.GetAlgodClient()
	sp, err := algod.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %v", err)
	}
	sp.Fee = 0
	sp.FlatFee = true

	depositMethod, err := f.App.Schema.Contract.GetMethodByName(DepositMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to get method %s: %v", DepositMethod, err)
	}

	txnParams := transaction.AddMethodCallParams{
		AppID:           f.App.Id,
		Sender:          f.App.DepositVerifier.Address,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer: transaction.LogicSigAccountTransactionSigner{
			LogicSigAccount: f.App.DepositVerifier.Account},
		Method:     depositMethod,
		MethodArgs: args,
		BoxReferences: []types.AppBoxReference{
			{AppID: f.App.Id, Name: []byte("subtree")},
			{AppID: f.App.Id, Name: []byte("subtree")},
			{AppID: f.App.Id, Name: []byte("roots")},
		},
	}
	if err := atc.AddMethodCall(txnParams); err != nil {
		return nil, fmt.Errorf("failed to add %s method call: %v", DepositMethod, err)
	}

	// now let's add the payment transaction
	signer := transaction.BasicAccountTransactionSigner{Account: *from}
	txn, err := transaction.MakePaymentTxn(from.Address.String(),
		crypto.GetApplicationAddress(f.App.Id).String(), amount, nil,
		types.ZeroAddress.String(), sp,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make payment txn: %v", err)
	}
	txn.Fee = transaction.MinTxnFee * config.DepositMinFeeMultiplier
	err = atc.AddTransaction(transaction.TransactionWithSigner{Txn: txn, Signer: signer})
	if err != nil {
		return nil, fmt.Errorf("failed to add payment txn: %v", err)
	}

	// let's make the required dummy transactions to meet the verifier opcode budget.
	// these need to be top level transactions to count for lsig opcode pooling.
	// we make them app calls to count also for smart contract opcode pooling.
	txnNeeded := config.VerifierTopLevelTxnNeeded - 2 // 2 transactions already added
	noopMethod, err := f.App.Schema.Contract.GetMethodByName(NoOpMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to get method %s: %v", NoOpMethod, err)
	}
	signerTSS := transaction.LogicSigAccountTransactionSigner{
		LogicSigAccount: f.App.TSS.Account}
	senderTSS := f.App.TSS.Address

	for i := 0; i < txnNeeded; i++ {
		txnParams = transaction.AddMethodCallParams{
			AppID:           f.App.Id,
			Sender:          senderTSS,
			SuggestedParams: sp,
			OnComplete:      types.NoOpOC,
			Signer:          signerTSS,
			Method:          noopMethod,
			MethodArgs:      []interface{}{i},
		}
		if err := atc.AddMethodCall(txnParams); err != nil {
			return nil, fmt.Errorf("failed to add %s method call: %v", NoOpMethod,
				err)
		}
	}

	simRes, err := atc.Simulate(context.Background(), algod, models.SimulateRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to simulate transaction: %v", err)
	}
	// print the opcode budget used
	fmt.Printf("Deposit opcode budget used | added: %d | %d\n",
		simRes.SimulateResponse.TxnGroups[0].AppBudgetConsumed,
		simRes.SimulateResponse.TxnGroups[0].AppBudgetAdded)

	res, err := atc.Execute(algod, context.Background(), 4)
	if err != nil {
		return nil, fmt.Errorf("failed to execute transaction: %v", err)
	}
	index, root, err := parseResult(&res)
	if err != nil {
		return nil, fmt.Errorf("failed to get method result: %v", err)
	}
	// check the root onchain matches
	rootOnchain, err := f.readRootOnchain()
	if err != nil {
		return nil, fmt.Errorf("failed to read root onchain: %v", err)
	}
	if !bytes.Equal(root, rootOnchain) {
		return nil, fmt.Errorf("root mismatch: %v != %v", root, rootOnchain)
	}

	note.insertedIndex = int(index)
	f.Tree.leafHashes = append(f.Tree.leafHashes, note.commitment)

	d := &Deposit{
		FromAddress: from.Address.String(),
		TxnIds:      res.TxIDs,
		Note:        note,
	}

	f.Deposits = append(f.Deposits, d)

	return d, nil
}

type WithdrawalOpts struct {
	recipient    types.Address
	feeRecipient types.Address
	feeSigner    transaction.TransactionSigner
	amount       uint64
	fee          uint64
	noChange     bool
	fromNote     *Note
}

// SendWithdrawal creates a withdrawal transaction and sends it to the network.
// If fee is 0, the fee will be set to the default withdrawal fee.
// If feeRecipient or feeSigner are not set, the fee will be sent to the TSS account
// and the TSS used to sign the transaction.
// If noChange is true, no change will be added to the tree (to be used when the
// tree is full, otherwise the withdrawal will fail).
func (f *Frontend) SendWithdrawal(opts *WithdrawalOpts, inputPrivkey *eddsa.PrivateKey, outputPubkey eddsa.PublicKey) (*Withdrawal, error) {

	recipient, feeRecipient, feeSigner := opts.recipient, opts.feeRecipient, opts.feeSigner
	withdrawalAmount, fee := opts.amount, opts.fee
	noChange, fromNote := opts.noChange, opts.fromNote

	if fee == 0 {
		fee = config.WithdrawalMinFeeMultiplier*transaction.MinTxnFee + config.NullifierMbr
	}

	if feeRecipient.IsZero() || feeSigner == nil {
		feeRecipient = f.App.TSS.Address
		feeSigner = transaction.LogicSigAccountTransactionSigner{
			LogicSigAccount: f.App.TSS.Account,
		}
	}

	change := fromNote.Amount - withdrawalAmount - fee
	changeNote, _ := f.NewNote(change, *inputPrivkey, outputPubkey)
	commitment := changeNote.commitment

	if fromNote.insertedIndex == -1 {
		return nil, fmt.Errorf("note not inserted in the tree")
	}
	index := fromNote.insertedIndex
	leaf := f.MakeLeafValue(fromNote)

	merkleProof, err := f.Tree.createMerkleProof(leaf, index)
	if err != nil {
		return nil, fmt.Errorf("failed to create merkle proof: %v", err)
	}
	var path [config.MerkleTreeLevels + 1]frontend.Variable
	for i, v := range merkleProof {
		path[i] = v
	}

	root, err := f.GetRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to get root: %v", err)
	}

	nullifier := f.MakeNullifier(fromNote)

	hFunc := hash.MIMC_BN254.New()

	sig, err := inputPrivkey.Sign(commitment, hFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to sign withdrawal commitment: %v", err)
	}

	circuitSig := sigEddsa.Signature{}
	circuitSig.Assign(twistededwards.BN254, sig)

	inputX := inputPrivkey.PublicKey.A.X.Bytes()
	inputY := inputPrivkey.PublicKey.A.Y.Bytes()
	outputX := outputPubkey.A.X.Bytes()
	outputY := outputPubkey.A.Y.Bytes()

	assignment := &circuits.WithdrawalCircuit{
		WithdrawalAddress:  recipient[:],
		WithdrawalAmount: withdrawalAmount,
		Fee:        fee,
		Commitment: commitment,
		Nullifier:  nullifier,
		Root:       root,
		SpendableK:          fromNote.k,
		SpendableR:          fromNote.r,
		SpendableAmount:     fromNote.Amount,
		Unspent:     changeNote.Amount,
		UnspentK:         changeNote.k,
		UnspentR:         changeNote.r,
		SpendableIndex:      index,
		SpendablePath:       path,
		InputX:     inputX[:],
		InputY:     inputY[:],
		Signature:  circuitSig,
		OutputX:    outputX[:],
		OutputY:    outputY[:],
		Spend:   0, // TODO: test transfers
	}
	verifiedProof, err := f.App.WithdrawalCc.Verify(assignment)
	if err != nil {
		return nil, fmt.Errorf("failed to verify withdrawal proof: %v", err)
	}
	proof := ap.MarshalProof(verifiedProof.Proof)
	publicInputs, err := ap.MarshalPublicInputs(verifiedProof.Witness)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public inputs: %v", err)
	}
	args, err := utils.ProofAndPublicInputsForAtomicComposer(proof, publicInputs)
	if err != nil {
		return nil, fmt.Errorf("failed to abi encode proof and public inputs: %v", err)
	}
	args = append(args, recipient[:], feeRecipient[:], noChange)

	algod := avm.GetAlgodClient()
	sp, err := algod.SuggestedParams().Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get suggested params: %v", err)
	}
	sp.Fee = 0
	sp.FlatFee = true

	method, err := f.App.Schema.Contract.GetMethodByName(WithDrawalMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to get method %s: %v", WithDrawalMethod, err)
	}

	// the app call signed by the withdrawal verifier
	txnParams := transaction.AddMethodCallParams{
		AppID:           f.App.Id,
		Sender:          f.App.WithdrawalVerifier.Address,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer: transaction.LogicSigAccountTransactionSigner{
			LogicSigAccount: f.App.WithdrawalVerifier.Account},
		Method:          method,
		MethodArgs:      args,
		ForeignAccounts: []string{feeRecipient.String(), recipient.String()},
		BoxReferences: []types.AppBoxReference{
			{AppID: f.App.Id, Name: nullifier},
			{AppID: f.App.Id, Name: []byte("subtree")},
			{AppID: f.App.Id, Name: []byte("roots")},
		},
	}

	var atc = transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(txnParams); err != nil {
		return nil, fmt.Errorf("failed to add %s method call: %v", WithDrawalMethod, err)
	}

	noopMethod, err := f.App.Schema.Contract.GetMethodByName(NoOpMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to get method %s: %v", NoOpMethod, err)
	}

	sp.Fee = types.MicroAlgos(fee - config.NullifierMbr)

	// the transaction signed by the feeSigner (e.g., the TSS)
	txnParams = transaction.AddMethodCallParams{
		AppID:           f.App.Id,
		Sender:          feeRecipient,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          feeSigner,
		Method:          noopMethod,
		MethodArgs:      []any{0},
	}

	if err := atc.AddMethodCall(txnParams); err != nil {
		return nil, fmt.Errorf("failed to add %s method call: %v", NoOpMethod, err)
	}

	// additional transactions to meet the verifier opcode budget
	txnNeeded := config.VerifierTopLevelTxnNeeded - 2
	sp.Fee = 0

	txnParams = transaction.AddMethodCallParams{
		AppID:           f.App.Id,
		Sender:          feeRecipient,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          feeSigner,
		Method:          noopMethod,
	}

	for i := range txnNeeded {
		txnParams.MethodArgs = []interface{}{i}
		if err := atc.AddMethodCall(txnParams); err != nil {
			return nil, fmt.Errorf("failed to add %s method call: %v", NoOpMethod, err)
		}
	}

	simRes, err := atc.Simulate(context.Background(), algod, models.SimulateRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to simulate transaction: %v", err)
	}
	fmt.Printf("Withdrawal opcode budget used | added: %d | %d\n",
		simRes.SimulateResponse.TxnGroups[0].AppBudgetConsumed,
		simRes.SimulateResponse.TxnGroups[0].AppBudgetAdded)

	res, err := atc.Execute(algod, context.Background(), 4)
	if err != nil {
		return nil, fmt.Errorf("failed to execute transaction: %v", err)
	}

	changeIndex, _, err := parseResult(&res)
	if err != nil {
		return nil, fmt.Errorf("failed to get method result: %v", err)
	}

	changeNote.insertedIndex = int(changeIndex)
	f.Tree.leafHashes = append(f.Tree.leafHashes, changeNote.commitment)

	w := &Withdrawal{
		ToAddress: recipient.String(),
		TxnIds:    res.TxIDs,
		Note:      changeNote,
	}

	f.Withdrawals = append(f.Withdrawals, w)

	return w, nil
}

func (f *Frontend) GetRoot() ([]byte, error) {
	algod := avm.GetAlgodClient()
	appInfo, err := algod.GetApplicationByID(f.App.Id).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get app info: %v", err)
	}
	for _, kv := range appInfo.Params.GlobalState {
		k, _ := base64.StdEncoding.DecodeString(kv.Key)
		if bytes.Equal(k, []byte("root")) {
			root, err := base64.StdEncoding.DecodeString(kv.Value.Bytes)
			if err != nil {
				log.Fatalf("Error decoding root bytes from b64: %v", err)
			}
			return root, nil
		}
	}
	return nil, fmt.Errorf("root not found in global state")
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

// parseResult reads the leaf index and root returned by a deposit or withdrawal
func parseResult(res *transaction.ExecuteResult) (uint64, []byte, error) {
	results, ok := res.MethodResults[0].ReturnValue.([]interface{})
	if !ok {
		return 0, nil, fmt.Errorf("failed to parse return value")
	}
	leafIndex, ok := results[0].(uint64)
	if !ok {
		return 0, nil, fmt.Errorf("failed to parse leafIndex")
	}
	rootArray, ok := results[1].([]interface{})
	if !ok {
		return 0, nil, fmt.Errorf("failed to parse root")
	}
	root := []byte{}
	for _, v := range rootArray {
		rootByte, ok := v.(uint8)
		if !ok {
			return 0, nil, fmt.Errorf("failed to parse root byte")
		}
		root = append(root, rootByte)
	}

	return leafIndex, root[:], nil
}

// readRootOnchain reads the root from the global state of the app
func (f *Frontend) readRootOnchain() ([]byte, error) {
	algod := avm.GetAlgodClient()
	appInfo, err := algod.GetApplicationByID(f.App.Id).Do(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get app info: %v", err)
	}
	for _, kv := range appInfo.Params.GlobalState {
		k, _ := base64.StdEncoding.DecodeString(kv.Key)
		if bytes.Equal(k, []byte("root")) {
			root, err := base64.StdEncoding.DecodeString(kv.Value.Bytes)
			if err != nil {
				log.Fatalf("Error decoding root bytes from b64: %v", err)
			}
			return root, nil
		}
	}
	return nil, fmt.Errorf("root not found in global state")
}
