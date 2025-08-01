package cmd

import (
	"flag"

	"github.com/polarysfoundation/go-server/modules/config"
	"github.com/polarysfoundation/go-server/modules/server"
)

func Run() {
	var (
		mode       = flag.String("mode", "prod", "Modo del servidor: dev o prod")
		port       = flag.String("port", "", "Puerto HTTPS (opcional)")
		host       = flag.String("host", "", "Dominio o IP principal")
		staticDir  = flag.String("dir", "", "Ruta a los archivos estáticos")
		backendURL = flag.String("backend", "", "URL del backend")
		passphrase = flag.String("key-pass", "changeme", "Frase secreta para desencriptar/generar claves")
		domain     = flag.String("domain", "", "Domain of the server")
	)

	flag.Parse()

	cfg := config.DefaultConfig(*passphrase)

	// Si los flags fueron provistos, actualizan los valores por defecto
	if *port != "" {
		cfg.Port = *port
	}
	if *host != "" {
		cfg.Host = *host
	}
	if *staticDir != "" {
		cfg.StaticDir = *staticDir
	}
	if *backendURL != "" {
		cfg.BackendURL = *backendURL
	}

	if *domain != "" {
		cfg.Domain = *domain
	}

	server.Start(cfg, *mode)
}
