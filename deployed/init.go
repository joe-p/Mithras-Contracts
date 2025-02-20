package deployed

import (
	"os"
	"path/filepath"
	"runtime"
)

type Network int

const (
	MainNet Network = iota
	TestNet
	DevNet
)

func (n Network) String() string {
	return [...]string{"mainnet", "testnet", "devnet"}[n]
}

func (n Network) DirPath() string {
	return [...]string{MainNetDirPath, TestNetDirPath, DevnetDirPath}[n]
}

func (n Network) LogFilePath() string {
	return filepath.Join(LogsPath, n.String()+".log")
}

const (
	DevnetDirName  = "devnet"
	TestNetDirName = "testnet"
	MainNetDirName = "mainnet"
)

var (
	LogsPath       string
	EnvDirPath     string
	DevnetDirPath  string
	TestNetDirPath string
	MainNetDirPath string
)

func init() {
	_, filename, _, _ := runtime.Caller(0) // this file
	basePath := filepath.Dir(filename)     // the dir of this file
	EnvDirPath = basePath
	LogsPath = basePath
	DevnetDirPath = filepath.Join(basePath, DevnetDirName)
	TestNetDirPath = filepath.Join(basePath, TestNetDirName)
	MainNetDirPath = filepath.Join(basePath, MainNetDirName)
	// create the directories if they do not exist
	for _, dir := range []string{DevnetDirPath, TestNetDirPath, MainNetDirPath} {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			panic("failed to create " + dir + ": " + err.Error())
		}
	}
}
