package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/giuliop/HermesVault-smartcontracts/deployed"
	"github.com/giuliop/HermesVault-smartcontracts/setup"
)

func main() {
	// Ensure exactly two arguments are provided: command and networkName
	if len(os.Args) != 3 {
		fmt.Println(helpString())
		os.Exit(1)
	}

	command := os.Args[1]
	networkName := os.Args[2]

	if command != "create" {
		fmt.Printf("Invalid command: %s\n", command)
		fmt.Println("Valid commands are: create")
		os.Exit(1)
	}

	if networkName != "mainnet" && networkName != "testnet" && networkName != "devnet" {
		fmt.Printf("Invalid network: %s\n", networkName)
		fmt.Println("Valid networks are: mainnet, testnet, devnet")
		os.Exit(1)
	}

	var network deployed.Network
	switch networkName {
	case "mainnet":
		network = deployed.MainNet
	case "testnet":
		network = deployed.TestNet
	case "devnet":
		network = deployed.DevNet
	}

	logFile := initializeLog(network)
	defer logFile.Close()

	switch command {
	case "create":
		setup.CreateApp(network)
	}
}

// helpString returns the help string for the command line interface
func helpString() string {
	help := "Usage: <command> <networkName>\n"
	help += "Commands: create\n"
	help += "Networks: mainnet, testnet, devnet\n"
	return help
}

// initializeLog sets the log output to both stdout and the log file.
// It returns the log file.
func initializeLog(network deployed.Network) *os.File {
	logFilePath := network.LogFilePath()

	var logFile *os.File
	var err error
	// for devnet we rewrite the log file, for testnet and mainnet we append
	if network == deployed.DevNet {
		logFile, err = os.Create(logFilePath)
	} else {
		logFile, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)

	return logFile
}
