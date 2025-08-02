package server

import (
	"compress/gzip"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/polarysfoundation/go-server/modules/config"
)

func Start(cfg *config.Config, mode string) {
	apiProxy := proxyAPIHandler(cfg.BackendURL)

	apiHandler := corsMiddleware(cfg.Domain,
		securityHeadersMiddleware(
			loggingMiddleware(apiProxy),
		),
	)

	staticHandler := corsMiddleware(cfg.Domain,
		securityHeadersMiddleware(
			restrictToCloudflare(
				gzipMiddleware(
					loggingMiddleware(
						http.HandlerFunc(staticHandler(cfg.StaticDir, apiProxy)),
					),
				),
			),
		),
	)

	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/", staticHandler)

	// MODO DESARROLLO
	if mode == "dev" {
		addr := cfg.Host + ":" + cfg.Port
		log.Printf("[DEV] Servidor HTTP en http://%s", addr)
		server := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Error HTTP dev: %v", err)
		}
		return
	}

	// MODO PRODUCCIÓN
	useAutocert := (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "")
	addr := cfg.Host + ":443"

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	if useAutocert {
		// 🌐 Certificado automático (Cloudflare en modo Full sin Strict y proxy ☁️ desactivado)
		log.Println("[TLS] Usando autocert (Let's Encrypt)")

		certManager := autocert.Manager{
			Cache:      autocert.DirCache(".certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
		}

		// Redirección HTTP → HTTPS y validación de ACME
		go func() {
			log.Println("[HTTP] Sirviendo ACME challenge y redirigiendo HTTP → HTTPS en :80")
			if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
				log.Fatalf("Error en HTTP (ACME): %v", err)
			}
		}()

		server.TLSConfig.GetCertificate = certManager.GetCertificate
		log.Printf("[HTTPS] Servidor HTTPS (autocert) iniciado en https://%s", cfg.Domain)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Error HTTPS autocert: %v", err)
		}
	} else {
		// 🔐 Certificados proporcionados manualmente (Cloudflare en modo Full Strict)
		log.Println("[TLS] Usando certificados TLS proporcionados (Full Strict)")
		log.Printf("[HTTPS] Servidor HTTPS (cert manual) iniciado en https://%s", cfg.Domain)
		if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			log.Fatalf("Error HTTPS manual: %v", err)
		}
	}
}

// === Handlers y middleware igual que antes ===

func proxyAPIHandler(backendURL string) http.Handler {
	target, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("Backend URL inválida: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	original := proxy.Director
	proxy.Director = func(req *http.Request) {
		original(req)
		req.Host = target.Host
		req.Header.Set("X-Forwarded-Host", req.Host)
	}
	return proxy
}

func restrictToCloudflare(next http.Handler) http.Handler {
	cloudflareCIDRs := []string{
		// Cloudflare IPv4 (puedes agregar más)
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",

		// Cloudflare IPv6 (opcional)
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}

	var cloudflareNets []*net.IPNet
	for _, cidr := range cloudflareCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			cloudflareNets = append(cloudflareNets, network)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extraer IP del RemoteAddr
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		ip := net.ParseIP(host)
		if ip == nil {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		// Verificar si IP está en la lista de Cloudflare
		allowed := false
		for _, net := range cloudflareNets {
			if net.Contains(ip) {
				allowed = true
				break
			}
		}

		if !allowed {
			log.Printf("[SECURITY] IP no autorizada (no es de Cloudflare): %s", ip)
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func staticHandler(staticDir string, apiProxy http.Handler) http.HandlerFunc {
	fs := http.FileServer(http.Dir(staticDir))
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiProxy.ServeHTTP(w, r)
			return
		}

		path := filepath.Join(staticDir, r.URL.Path)

		// Si el archivo existe, lo sirve directamente
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}

		// Si la ruta tiene extensión (ej. .js), no sirve index.html: responde 404
		if strings.Contains(filepath.Base(r.URL.Path), ".") {
			http.NotFound(w, r)
			return
		}

		// Rutas tipo /dashboard, /home → sirve index.html
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
	}
}

func corsMiddleware(domain string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (strings.Contains(origin, domain) || strings.Contains(origin, "localhost")) {
			w.Header().Set("Access-Control-Allow-Origin", origin) // ← usa el origin dinámicamente
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Seguridad general del navegador
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Forzar HTTPS en el navegador (HSTS)
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		// Protección básica de contenido (opcional, según tu app)
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gzw := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzw, r)
	})
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
