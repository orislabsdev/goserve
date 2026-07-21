package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Host    string `json:"host"`
	Port    string `json:"port"`
	TLSPort string `json:"tls_port"`
	Domain  string `json:"domain"`

	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	AdminEmail  string `json:"admin_email"`

	BackendURL string `json:"backend_url"`

	// WSPath ruta del WebSocket en el backend (ej. "/ws"). Vacío = sin proxy WS.
	// Solo se activa si el path contiene "ws" (ej. /ws, /api/ws, /websocket).
	WSPath string `json:"ws_path"`

	// Rate limiting (solo producción; desactivado en dev)
	RateLimitEnabled bool `json:"rate_limit_enabled"`
	RateLimit        int  `json:"rate_limit"`
	RateBurst        int  `json:"rate_burst"`

	// Opcional: solo aceptar tráfico desde IPs de Cloudflare (RemoteAddr)
	RequireCloudflare bool `json:"require_cloudflare"`

	StaticDir string `json:"static_dir"`
	DevMode   bool   `json:"dev_mode"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error abriendo config: %w", err)
	}
	defer file.Close()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("error decodificando config: %w", err)
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

func LoadFromEnv(path string) (*Config, error) {
	if err := godotenv.Load(path); err != nil {
		return nil, err
	}

	cfg := &Config{
		Host:              getEnv("SERVER_HOST", "127.0.0.1"),
		Port:              getEnv("SERVER_PORT", "8080"),
		TLSPort:           getEnv("TLS_PORT", "443"),
		Domain:            getEnv("DOMAIN", ""),
		TLSCertFile:       getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:        getEnv("TLS_KEY_FILE", ""),
		AdminEmail:        getEnv("ADMIN_EMAIL", ""),
		BackendURL:        getEnv("BACKEND_URL", "http://127.0.0.1:4000"),
		WSPath:            getEnv("WS_PATH", ""),
		RateLimitEnabled:  getEnvBool("RATE_LIMIT_ENABLED", true),
		RateLimit:         getEnvInt("RATE_LIMIT", 50),
		RateBurst:         getEnvInt("RATE_BURST", 100),
		RequireCloudflare: getEnvBool("REQUIRE_CLOUDFLARE", false),
		StaticDir:         getEnv("STATIC_DIR", "./dist/spa"),
		DevMode:           getEnvBool("DEV_MODE", true),
	}

	applyDefaults(cfg)
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	if cfg.TLSPort == "" {
		cfg.TLSPort = "443"
	}
	if cfg.StaticDir == "" {
		cfg.StaticDir = "./dist/spa"
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 50
	}
	if cfg.RateBurst == 0 {
		cfg.RateBurst = 100
	}
	cfg.WSPath = NormalizePath(cfg.WSPath)
}

// NormalizePath asegura un path absoluto HTTP o devuelve "" si está vacío.
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// WebSocketProxyEnabled indica si debe registrarse el proxy WebSocket.
func (c *Config) WebSocketProxyEnabled() bool {
	if c.WSPath == "" {
		return false
	}
	return strings.Contains(strings.ToLower(c.WSPath), "ws")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		fmt.Sscanf(value, "%d", &intValue)
		return intValue
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		v := strings.ToLower(strings.TrimSpace(value))
		return v == "true" || v == "1" || v == "yes"
	}
	return defaultValue
}
