package server

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"

	"github.com/polarysfoundation/go-server/modules/config"
)

var errPathTraversal = errors.New("path traversal")

// RateLimiter limita por IP (en producción considerar Redis si hay varias réplicas).
type RateLimiter struct {
	visitors map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
	go rl.cleanupVisitors()
	return rl
}

func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = limiter
	}
	return limiter
}

func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for ip := range rl.visitors {
			delete(rl.visitors, ip)
		}
		rl.mu.Unlock()
	}
}

// CloudflareIPManager opcional: solo si REQUIRE_CLOUDFLARE=true.
type CloudflareIPManager struct {
	ipv4Nets   []*net.IPNet
	ipv6Nets   []*net.IPNet
	mu         sync.RWMutex
	lastUpdate time.Time
}

func NewCloudflareIPManager() *CloudflareIPManager {
	cm := &CloudflareIPManager{}
	cm.updateIPs()
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cm.updateIPs()
		}
	}()
	return cm
}

func (cm *CloudflareIPManager) updateIPs() {
	ipv4CIDRs := fetchCloudflareCIDRs("https://www.cloudflare.com/ips-v4", []string{
		"103.21.244.0/22", "104.16.0.0/13", "172.64.0.0/13",
	})
	ipv6CIDRs := fetchCloudflareCIDRs("https://www.cloudflare.com/ips-v6", []string{
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	})

	var ipv4Nets, ipv6Nets []*net.IPNet
	for _, cidr := range ipv4CIDRs {
		if cidr != "" {
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				ipv4Nets = append(ipv4Nets, network)
			}
		}
	}
	for _, cidr := range ipv6CIDRs {
		if cidr != "" {
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				ipv6Nets = append(ipv6Nets, network)
			}
		}
	}

	cm.mu.Lock()
	cm.ipv4Nets = ipv4Nets
	cm.ipv6Nets = ipv6Nets
	cm.lastUpdate = time.Now()
	cm.mu.Unlock()

	log.Printf("[SECURITY] Rangos Cloudflare cargados: %d IPv4, %d IPv6", len(ipv4Nets), len(ipv6Nets))
}

func fetchCloudflareCIDRs(url string, fallback []string) []string {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("[SECURITY] No se pudieron obtener IPs de Cloudflare (%s): %v", url, err)
		return fallback
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.Split(strings.TrimSpace(string(body)), "\n")
}

func (cm *CloudflareIPManager) IsCloudflareIP(ip net.IP) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	nets := cm.ipv4Nets
	if ip.To4() == nil {
		nets = cm.ipv6Nets
	}
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func Start(cfg *config.Config, mode string) {
	if err := validateConfig(cfg, mode); err != nil {
		log.Fatalf("Configuración inválida: %v", err)
	}

	dev := mode == "dev"
	var rateLimiter *RateLimiter
	if !dev && cfg.RateLimitEnabled {
		rateLimiter = NewRateLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst)
	}

	var cfManager *CloudflareIPManager
	if !dev && cfg.RequireCloudflare {
		cfManager = NewCloudflareIPManager()
		log.Println("[SECURITY] REQUIRE_CLOUDFLARE activo: solo tráfico desde IPs de Cloudflare")
	}

	backendProxy := proxyBackendHandler(cfg)
	apiHandler := buildMiddlewareChain(cfg, dev, rateLimiter, cfManager, false, backendProxy)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	if cfg.WebSocketProxyEnabled() {
		wsHandler := buildMiddlewareChain(cfg, dev, rateLimiter, cfManager, false, backendProxy)
		mux.Handle(cfg.WSPath, wsHandler)
		log.Printf("[WS] Proxy WebSocket: %s → %s", cfg.WSPath, cfg.BackendURL)
	} else if cfg.WSPath != "" {
		log.Printf("[WS] WS_PATH=%q ignorado: el path debe contener \"ws\" (ej. /ws, /websocket)", cfg.WSPath)
	}

	mux.Handle("/api/", apiHandler)

	staticHandler := buildMiddlewareChain(cfg, dev, rateLimiter, cfManager, true,
		http.HandlerFunc(serveStatic(cfg.StaticDir, cfg.WSPath)))
	mux.Handle("/", staticHandler)

	if dev {
		addr := cfg.Host + ":" + cfg.Port
		log.Printf("[DEV] Servidor HTTP en http://%s (sin restricciones de API; CORS abierto)", addr)
		log.Println("[DEV] La seguridad (JWT, CORS, etc.) la gestiona el backend")

		server := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Error HTTP dev: %v", err)
		}
		return
	}

	startProduction(cfg, mux)
}

func buildMiddlewareChain(cfg *config.Config, dev bool, rl *RateLimiter, cf *CloudflareIPManager,
	gzipEnabled bool, next http.Handler) http.Handler {
	h := loggingMiddleware(next)

	if gzipEnabled {
		h = gzipMiddleware(h)
	}

	if dev {
		h = devCORSMiddleware(h)
		return h
	}

	if rl != nil {
		h = rateLimitMiddleware(rl, true)(h)
	}
	if cf != nil {
		h = cloudflareOnlyMiddleware(cf)(h)
	}
	h = productionSecurityHeadersMiddleware(h)
	h = productionCORSMiddleware(h)
	return h
}

func startProduction(cfg *config.Config, mux http.Handler) {
	useAutocert := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""

	tlsPort := "443"
	if cfg.TLSPort != "" {
		tlsPort = strings.TrimPrefix(cfg.TLSPort, ":")
	}
	addr := cfg.Host + ":" + tlsPort

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
			},
		},
	}

	if useAutocert {
		log.Println("[TLS] Usando autocert (Let's Encrypt)")
		certManager := autocert.Manager{
			Cache:      autocert.DirCache(".certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Email:      cfg.AdminEmail,
		}

		httpServer := &http.Server{
			Addr:              ":" + cfg.Port,
			Handler:           certManager.HTTPHandler(redirectToHTTPS()),
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := httpServer.ListenAndServe(); err != nil {
				log.Fatalf("Error en HTTP (ACME): %v", err)
			}
		}()

		server.TLSConfig.GetCertificate = certManager.GetCertificate
		log.Printf("[HTTPS] Servidor en https://%s (proxy → %s)", cfg.Domain, cfg.BackendURL)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Error HTTPS autocert: %v", err)
		}
		return
	}

	log.Println("[TLS] Usando certificados TLS manuales")
	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           redirectToHTTPS(),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatalf("Error en HTTP: %v", err)
		}
	}()

	log.Printf("[HTTPS] Servidor en https://%s (proxy → %s)", cfg.Domain, cfg.BackendURL)
	if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		log.Fatalf("Error HTTPS manual: %v", err)
	}
}

func proxyBackendHandler(cfg *config.Config) http.Handler {
	target, err := url.Parse(cfg.BackendURL)
	if err != nil {
		log.Fatalf("Backend URL inválida: %v", err)
	}

	if !isPrivateIP(target.Hostname()) && target.Hostname() != "localhost" {
		log.Println("⚠️  El backend parece estar en red pública; asegúrate de que no sea accesible directamente")
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		setForwardedHeaders(req)
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[PROXY ERROR] %s %s: %v", r.Method, r.URL.Path, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// No alterar cabeceras de respuesta del backend (CORS, Set-Cookie, etc.)
		return nil
	}

	return proxy
}

// setForwardedHeaders añade X-Forwarded-* sin tocar Authorization ni el resto de cabeceras del cliente.
func setForwardedHeaders(req *http.Request) {
	// Peer directo de esta conexión (edge de Cloudflare en producción).
	peerIP := remoteAddrIP(req)
	// IP real del usuario final, resuelta a partir de las cabeceras de proxy
	// (CF-Connecting-IP / X-Real-IP / X-Forwarded-For). En producción, al estar
	// REQUIRE_CLOUDFLARE=true, estas cabeceras solo llegan desde el edge de CF.
	clientIP := getClientIP(req, true)

	if peerIP != "" {
		// X-Forwarded-For es una cadena de auditoría: cada proxy añade la IP de
		// su peer directo. Cloudflare ya colocó la IP del usuario al inicio;
		// goserve añade la IP del edge de CF que tiene enfrente.
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			req.Header.Set("X-Forwarded-For", prior+", "+peerIP)
		} else {
			req.Header.Set("X-Forwarded-For", peerIP)
		}
	}
	if clientIP != "" {
		// X-Real-IP identifica al usuario final, no al proxy intermedio.
		req.Header.Set("X-Real-IP", clientIP)
	}

	proto := "http"
	if req.TLS != nil {
		proto = "https"
	}
	if existing := req.Header.Get("X-Forwarded-Proto"); existing != "" {
		proto = existing
	}
	req.Header.Set("X-Forwarded-Proto", proto)

	if host := req.Host; host != "" {
		req.Header.Set("X-Forwarded-Host", host)
	}
}

func serveStatic(staticDir, wsPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if wsPath != "" && (r.URL.Path == wsPath || strings.HasPrefix(r.URL.Path, wsPath+"/")) {
			http.NotFound(w, r)
			return
		}

		fullPath, err := safeStaticPath(staticDir, r.URL.Path)
		if err != nil {
			if errors.Is(err, errPathTraversal) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		info, err := os.Stat(fullPath)
		if err == nil && !info.IsDir() {
			ext := filepath.Ext(fullPath)
			if ext == ".js" || ext == ".css" || ext == ".jpg" || ext == ".png" || ext == ".svg" || ext == ".webp" {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFile(w, r, fullPath)
			return
		}

		base := filepath.Base(r.URL.Path)
		if strings.Contains(base, ".") {
			http.NotFound(w, r)
			return
		}

		indexPath, err := safeStaticPath(staticDir, "/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, indexPath)
	}
}

func safeStaticPath(staticDir, requestPath string) (string, error) {
	absStatic, err := filepath.Abs(staticDir)
	if err != nil {
		return "", err
	}

	clean := filepath.Clean(requestPath)
	clean = strings.TrimPrefix(clean, string(filepath.Separator))
	if clean == "." {
		clean = ""
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errPathTraversal
	}

	full := filepath.Join(absStatic, clean)
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(absStatic, absFull)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errPathTraversal
	}

	return absFull, nil
}

func rateLimitMiddleware(rl *RateLimiter, trustForwarded bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r, trustForwarded)
			if !rl.GetLimiter(ip).Allow() {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func cloudflareOnlyMiddleware(cfm *CloudflareIPManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverIP := remoteAddrIP(r)
			parsedIP := net.ParseIP(serverIP)
			if parsedIP == nil || !cfm.IsCloudflareIP(parsedIP) {
				log.Printf("[CLOUDFLARE] rechazado RemoteAddr=%s", r.RemoteAddr)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func devCORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Origin, X-Requested-With")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func productionSecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Solo para assets estáticos servidos por este proceso; /api/ lo resuelve el backend.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func productionCORSMiddleware(next http.Handler) http.Handler {
	allowedOrigins := map[string]bool{
		"https://pigzhub.com":       true,
		"https://www.pigzhub.com":   true,
		"https://admin.pigzhub.com": true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Origin, X-Requested-With")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
		w.Header().Set("Vary", "Accept-Encoding")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gzw := &gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzw, r)
	})
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (w *gzipResponseWriter) WriteHeader(statusCode int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(statusCode)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		log.Printf("[%s] %s %d %v %s",
			r.Method, r.URL.Path, lrw.statusCode, time.Since(start), getClientIP(r, true))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := lrw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("upstream ResponseWriter does not support Hijack")
	}
	return hijacker.Hijack()
}

func redirectToHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func remoteAddrIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if ip := net.ParseIP(strings.TrimSpace(r.RemoteAddr)); ip != nil {
			return ip.String()
		}
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func getClientIP(r *http.Request, trustForwarded bool) string {
	if !trustForwarded {
		return remoteAddrIP(r)
	}

	parse := func(raw string) string {
		raw = strings.TrimSpace(raw)
		if ip := net.ParseIP(raw); ip != nil {
			return ip.String()
		}
		return ""
	}

	if ip := parse(r.Header.Get("CF-Connecting-IP")); ip != "" {
		return ip
	}
	if ip := parse(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			if ip := parse(part); ip != "" {
				return ip
			}
		}
	}
	return remoteAddrIP(r)
}

func isPrivateIP(hostname string) bool {
	if hostname == "localhost" {
		return true
	}

	ip := net.ParseIP(hostname)
	if ip == nil {
		ips, err := net.LookupIP(hostname)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func validateConfig(cfg *config.Config, mode string) error {
	if cfg.BackendURL == "" {
		return fmt.Errorf("backend_url es obligatorio")
	}

	if mode != "dev" {
		if cfg.Domain == "" {
			return fmt.Errorf("domain es obligatorio en producción")
		}
		if cfg.RateLimit <= 0 {
			cfg.RateLimit = 50
		}
		if cfg.RateBurst <= 0 {
			cfg.RateBurst = 100
		}
		if cfg.AdminEmail == "" && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
			log.Println("⚠️  ADMIN_EMAIL no configurado (recomendado para Let's Encrypt)")
		}
	}

	if _, err := url.Parse(cfg.BackendURL); err != nil {
		return fmt.Errorf("backend_url inválida: %w", err)
	}

	return nil
}
