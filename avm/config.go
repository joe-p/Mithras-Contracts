package avm

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/joe-p/Mithras-Protocol/deployed"
	"github.com/joe-p/Mithras-Protocol/encrypt"

	"github.com/algorand/go-algorand-sdk/v2/client/kmd"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"golang.org/x/crypto/ed25519"
)

type algodConfig struct {
	URL   string
	Token string
}

var devnetAlgodConfig = algodConfig{
	URL:   "http://localhost:4001",
	Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

type kmdConfig struct {
	URL      string
	Token    string
	Wallet   string
	Password string
}

var devnetKmdConfig = kmdConfig{
	URL:      "http://localhost:4002",
	Token:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	Wallet:   "unencrypted-default-wallet",
	Password: "",
}

var (
	envmap  map[string]string
	Network *deployed.Network
)

// InitConfig initializes the configuration for the network
func initCofig(network deployed.Network) {
	Network = &network
	if network == deployed.DevNet {
		return
	}

	envPath := filepath.Join(deployed.EnvDirPath, network.String()+".env")
	var err error
	envmap, err = LoadEnv(envPath)
	if err != nil {
		log.Fatalf("failed to read config file %s: %v", envPath, err)
	}
}

// readAlgodConfig reads the algod URL and token from the env file of the network
// The base dir is deployed.EnvDirPath and the env file is named <network>.env
func readAlgodConfig() *algodConfig {
	if Network == nil {
		log.Fatalf("avm config not initialized")
	}
	if *Network == deployed.DevNet {
		return &devnetAlgodConfig
	}
	algodConfig, err := readAlgodConfigFromPath(envmap["ALGOD_PATH"])
	if err != nil {
		log.Fatalf("failed to read algod config: %v", err)
	}
	return algodConfig
}

// readAlgodConfigFromPath reads the algod URL and token from the given path
// The path can either by a local path or a remote URL
func readAlgodConfigFromPath(path string) (*algodConfig, error) {
	var url, token string
	if strings.Contains(path, "http") {
		url = path
		if envmap["ALGOD_TOKEN"] != "" {
			token = envmap["ALGOD_TOKEN"]
		} else {
			token = ""
		}
	} else {
		urlPath := filepath.Join(path, "algod.net")
		urlBytes, err := os.ReadFile(urlPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read algod url: %v", err)
		}
		url = "http://" + strings.TrimSpace(string(urlBytes))

		tokenPath := filepath.Join(path, "algod.token")
		tokenBytes, err := os.ReadFile(tokenPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read algod token: %v", err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	}
	return &algodConfig{
		URL:   url,
		Token: token,
	}, nil
}

// readDefaultAccount reads the default account from the env file of the network
func readDefaultAccount() (*crypto.Account, error) {
	if Network == nil {
		log.Fatalf("avm config not initialized")
	}
	if *Network == deployed.DevNet {
		return getDevNetDefaultAccount()
	}
	encryptedPassphrase := envmap["DEFAULT_ACCOUNT_ENCRYPTED_PASSPHRASE"]
	passphrase, err := encrypt.Decrypt(encryptedPassphrase)
	if err != nil {
		log.Fatalf("failed to decrypt passphrase: %v", err)
	}
	privateKey, err := mnemonic.ToPrivateKey(passphrase)
	if err != nil {
		log.Fatalf("failed to get private key from passphrase: %v", err)
	}
	account, err := crypto.AccountFromPrivateKey(ed25519.PrivateKey(privateKey))
	if err != nil {
		log.Fatalf("failed to create account from private key: %v", err)
	}

	return &account, nil
}

func getDevNetDefaultAccount() (*crypto.Account, error) {
	kmdConfig := devnetKmdConfig
	client, err := kmd.MakeClient(
		kmdConfig.URL,
		kmdConfig.Token,
	)
	if err != nil {
		log.Fatalf("Failed to create kmd client: %s", err)
	}

	resp, err := client.ListWallets()
	if err != nil {
		return nil, fmt.Errorf("failed to list wallets: %+v", err)
	}

	var walletId string
	for _, wallet := range resp.Wallets {
		if wallet.Name == kmdConfig.Wallet {
			walletId = wallet.ID
		}
	}

	if walletId == "" {
		return nil, fmt.Errorf("no wallet named %s", kmdConfig.Wallet)
	}

	whResp, err := client.InitWalletHandle(walletId, kmdConfig.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to init wallet handle: %+v", err)
	}

	addrResp, err := client.ListKeys(whResp.WalletHandleToken)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %+v", err)
	}

	var accts []crypto.Account
	for _, addr := range addrResp.Addresses {
		expResp, err := client.ExportKey(whResp.WalletHandleToken, kmdConfig.Password, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to export key: %+v", err)
		}

		acct, err := crypto.AccountFromPrivateKey(expResp.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create account from private key: %+v", err)
		}

		accts = append(accts, acct)
	}

	return &accts[0], nil
}

// LoadEnv reads a set of key-value pairs from a file and returns them as a map
// Each line in the file can be in one of the following formats:
// - key=value
// - # comment
// - empty line
func LoadEnv(filename string) (map[string]string, error) {
	envMap := make(map[string]string)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments starting with # or //
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("Malformed line in env file: %s\n", line)
			continue // Skip malformed lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove surrounding quotes if any
		value = strings.Trim(value, `"'`)

		envMap[key] = value
	}

	return envMap, scanner.Err()
}
