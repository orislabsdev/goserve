package config

import "github.com/polarysfoundation/go-server/modules/crypto"

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

func DefaultConfig() *Config {
	securityKey, err := crypto.NewSecurityKey()
	if err != nil {
		panic(err)
	}

	return NewConfig(PORT, HOST, securityKey, STATIC_DIR_PATH)
}


func LoadSecurityKey(path string) (crypto.SecurityKey, error) {
	
}

