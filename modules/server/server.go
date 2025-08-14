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
	apiProxy := proxyAPIHandler(cfg)

	apiHandler := corsMiddleware(cfg.Domain,
		securityHeadersMiddleware(
			loggingMiddleware(apiProxy),
		),
	)

	var handler http.Handler

	if mode == "dev" {
		handler = corsMiddleware(cfg.Domain,
			securityHeadersMiddleware(
				gzipMiddleware(
					loggingMiddleware(
						http.HandlerFunc(staticHandler(cfg.StaticDir, apiProxy)),
					),
				),
			),
		)
	} else {
		handler = corsMiddleware(cfg.Domain,
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
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/", handler)

	// MODO DESARROLLO
	if mode == "dev" {
		if cfg.Host != "127.0.0.1" {
			cfg.Host = "127.0.0.1"
		}

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

func proxyAPIHandler(cfg *config.Config) http.Handler {
	target, err := url.Parse(cfg.BackendURL)
	if err != nil {
		log.Fatalf("Backend URL inválida: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	original := proxy.Director
	proxy.Director = func(req *http.Request) {
		original(req)
		req.Host = target.Host
		req.Header.Set("X-Forwarded-Host", req.Host)

		// Token de tu configuración (solo lo conoce tu server)
		// ESTO se agrega automáticamente al hacer proxy al backend
		req.Header.Set("X-Internal-Auth", cfg.InternalSecret)

		// Autenticación ya existente si la tienes
		if cfg.AuthEnabled && cfg.AuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)
		}
	}

	// IMPORTANTE: Aplicar middleware de seguridad ANTES del proxy
	// Esto valida que la request venga del frontend, no directamente del navegador
	return frontendValidationMiddleware(cfg, proxy)
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
		referer := r.Header.Get("Referer")

		// Lista de orígenes permitidos
		allowedOrigins := []string{
			"https://" + domain,
			"https://www." + domain,
			"http://localhost:8080", // Para desarrollo
			"http://127.0.0.1:3000",
			"http://127.0.0.1:8080",
		}

		// Verificar si el origin está permitido
		originAllowed := false
		if origin != "" {
			for _, allowed := range allowedOrigins {
				if origin == allowed {
					originAllowed = true
					break
				}
			}
		}

		// Para requests sin origin (como algunos mobile apps), verificar referer
		if !originAllowed && origin == "" {
			for _, allowed := range allowedOrigins {
				if strings.HasPrefix(referer, allowed) {
					originAllowed = true
					origin = allowed // Asignar para el header de respuesta
					break
				}
			}
		}

		// Solo para rutas API, ser más estricto
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// Para API, requerir origin válido
			if !originAllowed {
				log.Printf("[CORS] Origin no permitido para API: %s (referer: %s)", origin, referer)
				http.Error(w, "403 Forbidden - Invalid Origin", http.StatusForbidden)
				return
			}

			// Verificar User-Agent para APIs (opcional - bloquear curl, wget, etc)
			userAgent := r.Header.Get("User-Agent")
			if isBlockedUserAgent(userAgent) {
				log.Printf("[CORS] User-Agent bloqueado: %s", userAgent)
				http.Error(w, "403 Forbidden - Invalid User-Agent", http.StatusForbidden)
				return
			}
		}

		// Establecer headers CORS solo si el origin está permitido
		if originAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Internal-Auth")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // Cache preflight por 24h

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Función auxiliar para bloquear ciertos User-Agents
func isBlockedUserAgent(userAgent string) bool {
	blockedAgents := []string{
		"curl",
		"wget",
		"python-requests",
		"Postman",
		"Insomnia",
		"HTTPie",
		"Go-http-client",
		"okhttp",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, blocked := range blockedAgents {
		if strings.Contains(userAgentLower, strings.ToLower(blocked)) {
			return true
		}
	}

	return false
}

/* // Cache simple para rate limiting (en producción usa Redis)
var rateLimitCache = make(map[string][]time.Time)

func isRateLimited(ip string) bool {
	now := time.Now()
	windowDuration := 1 * time.Minute
	maxRequests := 60 // 60 requests por minuto

	// Limpiar requests antiguos
	requests := rateLimitCache[ip]
	validRequests := make([]time.Time, 0)

	for _, reqTime := range requests {
		if now.Sub(reqTime) < windowDuration {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Agregar request actual
	validRequests = append(validRequests, now)
	rateLimitCache[ip] = validRequests

	return len(validRequests) > maxRequests
} */

func isValidBrowserUserAgent(userAgent string) bool {
	// User-agents válidos de navegadores principales
	validBrowsers := []string{
		"Mozilla/5.0", // Chrome, Firefox, Safari, Edge
		"WebKit",      // Safari, Chrome
		"Gecko",       // Firefox
		"Chrome",      // Chrome, Edge
		"Safari",      // Safari
		"Edge",        // Edge
	}

	for _, browser := range validBrowsers {
		if strings.Contains(userAgent, browser) {
			return true
		}
	}

	return false
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

// Middleware para validar que las requests vienen del frontend legítimo
func frontendValidationMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/* // 1. Rate limiting básico por IP
		if isRateLimited(r.RemoteAddr) {
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		} */

		// 2. Verificar que tenga headers de navegador válidos
		if !hasValidBrowserHeaders(r) {
			log.Printf("[SECURITY] Request sin headers de navegador válidos desde: %s", r.RemoteAddr)
			http.Error(w, "403 Forbidden - Invalid Headers", http.StatusForbidden)
			return
		}

		// 3. Verificar que venga de JavaScript fetch/XMLHttpRequest
		if !isValidAjaxRequest(r) {
			log.Printf("[SECURITY] Request no es AJAX válido desde: %s", r.RemoteAddr)
			http.Error(w, "403 Forbidden - Direct Access Not Allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Validar que sea una request AJAX legítima
func isValidAjaxRequest(r *http.Request) bool {
	// Debug: imprimir headers para diagnosticar
	log.Printf("[DEBUG] Method: %s, Accept: %s", r.Method, r.Header.Get("Accept"))
	log.Printf("[DEBUG] Sec-Fetch-Site: %s, Sec-Fetch-Mode: %s",
		r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Sec-Fetch-Mode"))

	accept := r.Header.Get("Accept")

	// 1. Para fetch() sin especificar Accept, viene como "*/*"
	if accept == "" {
		return false
	}

	// 2. Verificar headers de seguridad del navegador (si están presentes)
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	secFetchMode := r.Header.Get("Sec-Fetch-Mode")

	if secFetchSite != "" {
		// Si existe, debe ser same-origin o none (para localhost)
		if secFetchSite != "same-origin" && secFetchSite != "none" {
			return false
		}
	}

	if secFetchMode != "" {
		// Si existe, debe ser cors, navigate, o no-cors
		if secFetchMode != "cors" && secFetchMode != "navigate" && secFetchMode != "no-cors" {
			return false
		}
	}

	// 3. Para POST/PUT/DELETE, verificar Content-Type solo si se envía body
	if r.Method != "GET" && r.Method != "OPTIONS" && r.Method != "HEAD" {
		contentType := r.Header.Get("Content-Type")
		if contentType != "" && !strings.Contains(contentType, "application/json") {
			return false
		}
	}

	return true
}

// Versión mejorada de validación de headers de navegador
func hasValidBrowserHeaders(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")

	// Debug: imprimir headers importantes
	log.Printf("[DEBUG] User-Agent: %s", userAgent)
	log.Printf("[DEBUG] Accept: %s", accept)

	// Debe tener User-Agent de navegador
	if userAgent == "" || !isValidBrowserUserAgent(userAgent) {
		return false
	}

	// Debe tener header Accept
	if accept == "" {
		return false
	}

	// Accept puede ser "*/*" (fetch por defecto) o incluir application/json
	validAccept := strings.Contains(accept, "*/*") || 
				  strings.Contains(accept, "application/json") ||
				  strings.Contains(accept, "text/html")

	return validAccept
}