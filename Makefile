# Variables
BINARY_NAME = goserve
SRC = main.go
BUILD_DIR = build
GOOS ?= linux
GOARCH ?= amd64

# Versión: usa el tag de git, o el commit corto si no hay tag
# VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
# COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Paquete donde estarán las variables de versión
VERSION_PKG = main

LDFLAGS = -X '$(VERSION_PKG).Version=$(VERSION)' \
          -X '$(VERSION_PKG).Commit=$(COMMIT)' \
          -X '$(VERSION_PKG).BuildTime=$(BUILD_TIME)'

# Nombre final del binario con versión y plataforma
# BINARY_FULL = $(BINARY_NAME)_$(VERSION)-$(GOOS)
BINARY_FULL = $(BINARY_NAME)-$(GOOS)

# Argumentos por defecto del servidor
PORT ?= 443
HTTP_PORT ?= 80
STATIC_DIR ?= ./static
BACKEND_URL ?= http://localhost:4000
CERT_FILE ?= ./certs/fullchain.pem
KEY_FILE ?= ./certs/privkey.pem
DOMAIN ?= localhost

# Targets

all: build

build:
	@echo "🔨 Compilando $(BINARY_FULL) para $(GOOS)/$(GOARCH)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_FULL) $(SRC)

run:
	@echo "🚀 Ejecutando $(BINARY_FULL)..."
	./$(BUILD_DIR)/$(BINARY_FULL) \
		--dir $(STATIC_DIR) \
		--port $(PORT) \
		--http-port $(HTTP_PORT) \
		--backend $(BACKEND_URL) \
		--cert $(CERT_FILE) \
		--key $(KEY_FILE) \
		--domain $(DOMAIN)

clean:
	@echo "🧹 Limpiando..."
	@rm -rf $(BUILD_DIR)

version:
	@echo "Versión:    $(VERSION)"
	@echo "Commit:     $(COMMIT)"
	@echo "Binario:    $(BINARY_FULL)"
	@echo "Build time: $(BUILD_TIME)"

help:
	@echo "🛠️  Comandos disponibles:"
	@echo "  make build        -> Compila el binario ($(BINARY_FULL))"
	@echo "  make run          -> Ejecuta con los argumentos por defecto"
	@echo "  make version      -> Muestra la versión calculada"
	@echo "  make clean        -> Limpia binarios"
	@echo "  make help         -> Muestra esta ayuda"
	@echo ""
	@echo "🌐 Variables configurables:"
	@echo "  PORT, HTTP_PORT, STATIC_DIR, BACKEND_URL, CERT_FILE, KEY_FILE, DOMAIN"™