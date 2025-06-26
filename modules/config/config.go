package config

import (
	"log"
	"os"
	"path/filepath"

	"github.com/polarysfoundation/go-server/modules/crypto"
)

type Config struct {
	Port        int
	Host        string
	SecurityKey crypto.SecurityKey
	StaticDir   string
}

func NewConfig(port int, host string, securityKey crypto.SecurityKey, staticDir string) *Config {

	return &Config{
		Port:        port,
		Host:        host,
		SecurityKey: securityKey,
		StaticDir:   staticDir,
	}
}

func DefaultConfig(passphrase string) *Config {
	var securityKey crypto.SecurityKey
	path := getPath()

	if hasKeys(path) {
		priv, pub, err := crypto.LoadSecurityKey(filepath.Join(path, "keys.key"), []byte(passphrase))
		if err != nil {
			log.Fatalf("failed to load security key: %v", err)
		}
		securityKey = crypto.SecurityKey{PrivKey: priv, PubKey: pub}
	} else {
		sk, err := crypto.NewSecurityKey()
		if err != nil {
			log.Fatalf("failed to generate new security key: %v", err)
		}
		err = crypto.SaveSecurityKey(path, sk, []byte(passphrase))
		if err != nil {
			log.Fatalf("failed to save security key: %v", err)
		}
		securityKey = sk
	}

	return NewConfig(PORT, HOST, securityKey, STATIC_DIR_PATH)
}

func hasKeys(path string) bool {
	_, err := os.Stat(filepath.Join(path, "keys.key"))
	return err == nil
}

func getPath() string {
	return filepath.Join(getDir(BASE_PATH, KEY_DIR))
}

func getDir(dir string, subdir string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("failed to get home directory: %v", err)
	}
	subDirPath := filepath.Join(homeDir, dir, subdir)

	err = os.MkdirAll(subDirPath, os.ModePerm)
	if err != nil {
		log.Fatalf("failed to create %s directory: %v", subdir, err)
	}

	return subDirPath
}


