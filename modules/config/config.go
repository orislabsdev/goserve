package config

import (
	"log"
	"os"
	"path/filepath"

	"github.com/polarysfoundation/go-server/modules/crypto"
)

type Config struct {
	Port        string
	Host        string
	SecurityKey crypto.SecurityKey
	StaticDir   string
	BackendURL  string
	Domain      string
}

func NewConfig(port string, host string, securityKey crypto.SecurityKey, staticDir string, backend string, domain string) *Config {
	if port == "" {
		port = PORT
	}
	if host == "" {
		host = HOST
	}
	if staticDir == "" {
		staticDir = STATIC_DIR_PATH
	}

	if backend == "" {
		backend = BACKEND_URL
	}

	if domain == "" {
		domain = DOMAIN
	}

	return &Config{
		Port:        port,
		Host:        host,
		SecurityKey: securityKey,
		StaticDir:   staticDir,
		BackendURL:  backend,
		Domain:      domain,
	}
}

func DefaultConfig(passphrase string) *Config {
	var securityKey crypto.SecurityKey
	path := getPath()

	if hasKeys(path) {

		securityKey = loadSecurityKey(path, passphrase)
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

	return NewConfig(PORT, HOST, securityKey, STATIC_DIR_PATH, BACKEND_URL, DOMAIN)
}

func loadSecurityKey(path string, passphrase string) crypto.SecurityKey {
	priv, pub, err := crypto.LoadSecurityKey(filepath.Join(path, "keys.key"), []byte(passphrase))
	if err != nil {
		log.Fatalf("failed to load security key: %v", err)
	}
	return crypto.SecurityKey{PrivKey: priv, PubKey: pub}
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
