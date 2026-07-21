package cmd

import (
	"flag"
	"log"
	"strings"

	"github.com/orislabsdev/goserve/modules/config"
	"github.com/orislabsdev/goserve/modules/server"
)

func Run() {
	var (
		configPath = flag.String("config", "", "Path del archivo de configuración")
	)

	flag.Parse()

	var cfg *config.Config
	var err error
	if *configPath != "" && strings.HasSuffix(*configPath, ".json") {
		log.Printf("Using config file: %s", *configPath)
		cfg, err = config.LoadConfig(*configPath)
	} else if *configPath != "" && strings.HasSuffix(*configPath, ".env") {
		log.Println("Using environment variables")
		cfg, err = config.LoadFromEnv(*configPath)
	} else {
		panic("Invalid config path")
	}
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	mode := "prod"
	if cfg.DevMode {
		mode = "dev"
	}

	server.Start(cfg, mode)
}
