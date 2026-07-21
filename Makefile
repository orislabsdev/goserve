# Variables
BINARY_NAME = goserve
SRC = main.go
BUILD_DIR = build
GOOS ?= linux
GOARCH ?= amd64

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
	@echo "🔨 Compilando $(BINARY_NAME) para $(GOOS)/$(GOARCH)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC)

run:
	@echo "🚀 Ejecutando $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME) \
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

help:
	@echo "🛠️  Comandos disponibles:"
	@echo "  make build        -> Compila el binario"
	@echo "  make run          -> Ejecuta con los argumentos por defecto"
	@echo "  make clean        -> Limpia binarios"
	@echo "  make help         -> Muestra esta ayuda"
	@echo ""
	@echo "🌐 Variables configurables:"
	@echo "  PORT, HTTP_PORT, STATIC_DIR, BACKEND_URL, CERT_FILE, KEY_FILE, DOMAIN"
