package test

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/giuliop/HermesVault-smartcontracts/encrypt"
)

func TestECIESEncryptDecrypt(t *testing.T) {
	// Generate a key pair
	privKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	pubKey := privKey.PublicKey

	// Test data
	testData := []byte("test secret data for k or r")

	// Generate ephemeral key pair for encryption
	ephemeralPriv, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ephemeral key: %v", err)
	}

	// Encrypt
	encrypted, err := encrypt.ECIESEncrypt(testData, pubKey, ephemeralPriv.PublicKey, *ephemeralPriv)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := encrypt.ECIESDecrypt(encrypted, ephemeralPriv.PublicKey, *privKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if string(decrypted) != string(testData) {
		t.Fatalf("Decrypted data doesn't match original. Got %s, expected %s", string(decrypted), string(testData))
	}
}

func TestNoteRecovery(t *testing.T) {
	// Create a frontend
	frontend := NewAppFrontend()

	// Generate key pairs
	inputPrivKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate input key: %v", err)
	}

	outputPrivKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate output key: %v", err)
	}
	outputPubKey := outputPrivKey.PublicKey

	// Create a note
	amount := uint64(1000)
	note, encryptedNote := frontend.NewNote(amount, *inputPrivKey, outputPubKey)

	// Try to recover the note using the output private key
	recoveredNote, err := frontend.RecoverNote(
		encryptedNote,
		*outputPrivKey,
		note.insertedIndex,
	)
	if err != nil {
		t.Fatalf("Failed to recover note: %v", err)
	}

	// Verify the recovered note matches the original
	if recoveredNote.Amount != note.Amount {
		t.Fatalf("Amount mismatch: got %d, expected %d", recoveredNote.Amount, note.Amount)
	}

	if string(recoveredNote.k) != string(note.k) {
		t.Fatalf("k value mismatch")
	}

	if string(recoveredNote.r) != string(note.r) {
		t.Fatalf("r value mismatch")
	}

	if string(recoveredNote.commitment) != string(note.commitment) {
		t.Fatalf("commitment mismatch")
	}
}

func TestNoteRecoveryWithWrongKey(t *testing.T) {
	// Create a frontend
	frontend := NewAppFrontend()

	// Generate key pairs
	inputPrivKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate input key: %v", err)
	}

	outputPrivKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate output key: %v", err)
	}
	outputPubKey := outputPrivKey.PublicKey

	// Generate a different private key (wrong key)
	wrongPrivKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	// Create a note
	amount := uint64(1000)
	note, encryptedNote := frontend.NewNote(amount, *inputPrivKey, outputPubKey)

	// Try to recover the note using the wrong private key - should fail
	recoveredNote := frontend.TryRecoverNote(
		encryptedNote,
		*wrongPrivKey,
		note.insertedIndex,
	)

	// Should return nil since decryption should fail
	if recoveredNote != nil {
		t.Fatalf("Expected recovery to fail with wrong key, but it succeeded")
	}
}
