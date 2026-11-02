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

	"github.com/orislabsdev/goserve/modules/config"
)

var errPathTraversal = errors.New("path traversal")

// ============================================================================
// RateLimiter
// ============================================================================

// RateLimiter limits requests per IP. In production with multiple replicas,
// consider using Redis or a shared store so the limit is global.
type RateLimiter struct {
	visitors map[string]*visitorEntry
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

// visitorEntry stores the limiter and the last time it was used, so we can
// clean up only idle entries without resetting active attackers.
// FIX: previously cleanupVisitors wiped ALL visitors every 10 min, which
// allowed an active attacker to get a free "reset".
type visitorEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitorEntry),
		rate:     r,
		burst:    b,
	}
	go rl.cleanupVisitors()
	return rl
}

func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.visitors[ip]
	now := time.Now()
	if !exists {
		entry = &visitorEntry{
			limiter:  rate.NewLimiter(rl.rate, rl.burst),
			lastSeen: now,
		}
		rl.visitors[ip] = entry
	} else {
		entry.lastSeen = now
	}
	return entry.limiter
}

// cleanupVisitors removes only IPs that have not made requests in the last
// 30 minutes, so an active attacker does not lose their counter.
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-30 * time.Minute)
		rl.mu.Lock()
		for ip, entry := range rl.visitors {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// ============================================================================
// CloudflareIPManager
// ============================================================================

// CloudflareIPManager holds Cloudflare IP ranges. It is only instantiated
// when REQUIRE_CLOUDFLARE=true.
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
			if _, network, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
				ipv4Nets = append(ipv4Nets, network)
			}
		}
	}
	for _, cidr := range ipv6CIDRs {
		if cidr != "" {
			if _, network, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
				ipv6Nets = append(ipv6Nets, network)
			}
		}
	}

	cm.mu.Lock()
	cm.ipv4Nets = ipv4Nets
	cm.ipv6Nets = ipv6Nets
	cm.lastUpdate = time.Now()
	cm.mu.Unlock()

	log.Printf("[SECURITY] Cloudflare ranges loaded: %d IPv4, %d IPv6", len(ipv4Nets), len(ipv6Nets))
}

// FIX: previously used http.Get (no timeout), which could block the goroutine
// indefinitely if Cloudflare did not respond.
func fetchCloudflareCIDRs(url string, fallback []string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[SECURITY] Failed to fetch Cloudflare IPs (%s): %v", url, err)
		return fallback
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[SECURITY] Failed to read Cloudflare IPs (%s): %v", url, err)
		return fallback
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
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

// ============================================================================
// Start
// ============================================================================

func Start(cfg *config.Config, mode string) {
	if err := validateConfig(cfg, mode); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	dev := mode == "dev"
	var rateLimiter *RateLimiter
	if !dev && cfg.RateLimitEnabled {
		rateLimiter = NewRateLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst)
	}

	var cfManager *CloudflareIPManager
	if !dev && cfg.RequireCloudflare {
		cfManager = NewCloudflareIPManager()
		log.Println("[SECURITY] REQUIRE_CLOUDFLARE enabled: only Cloudflare traffic is allowed")
	}

	backendProxy := proxyBackendHandler(cfg, cfManager)
	apiHandler := buildMiddlewareChain(cfg, dev, rateLimiter, cfManager, false, backendProxy)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	if cfg.WebSocketProxyEnabled() {
		wsHandler := buildMiddlewareChain(cfg, dev, rateLimiter, cfManager, false, backendProxy)
		mux.Handle(cfg.WSPath, wsHandler)
		log.Printf("[WS] WebSocket proxy: %s → %s", cfg.WSPath, cfg.BackendURL)
	} else if cfg.WSPath != "" {
		log.Printf("[WS] WS_PATH=%q ignored: path must contain \"ws\" (e.g. /ws, /websocket)", cfg.WSPath)
	}

	mux.Handle("/api/", apiHandler)

	staticHandler := buildMiddlewareChain(cfg, dev, rateLimiter, cfManager, true,
		http.HandlerFunc(serveStatic(cfg.StaticDir, cfg.WSPath)))
	mux.Handle("/", staticHandler)

	if dev {
		addr := cfg.Host + ":" + cfg.Port
		log.Printf("[DEV] HTTP server on http://%s (no API restrictions; open CORS)", addr)
		log.Println("[DEV] Security (JWT, CORS, etc.) is handled by the backend")

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
			log.Fatalf("Dev HTTP error: %v", err)
		}
		return
	}

	startProduction(cfg, mux)
}

// ============================================================================
// Middleware chain
// ============================================================================

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
		h = rateLimitMiddleware(rl, cfg.RequireCloudflare, cf)(h)
	}
	if cf != nil {
		h = cloudflareOnlyMiddleware(cf)(h)
	}
	h = productionSecurityHeadersMiddleware(h)
	h = productionCORSMiddleware(cfg)(h)
	return h
}

// ============================================================================
// startProduction
// ============================================================================

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

	// FIX: redirectToHTTPS now receives the allowed domain to avoid
	// redirecting to arbitrary hosts (Host header injection).
	httpRedirect := redirectToHTTPS(cfg.Domain)

	if useAutocert {
		log.Println("[TLS] Using autocert (Let's Encrypt)")
		certManager := autocert.Manager{
			Cache:      autocert.DirCache(".certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Email:      cfg.AdminEmail,
		}

		httpServer := &http.Server{
			Addr:              ":" + cfg.Port,
			Handler:           certManager.HTTPHandler(httpRedirect),
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[HTTP-ACME] error: %v", err)
			}
		}()

		server.TLSConfig.GetCertificate = certManager.GetCertificate
		log.Printf("[HTTPS] Server on https://%s (proxy → %s)", cfg.Domain, cfg.BackendURL)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Autocert HTTPS error: %v", err)
		}
		return
	}

	log.Println("[TLS] Using manual TLS certificates")
	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpRedirect,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[HTTP] error: %v", err)
		}
	}()

	log.Printf("[HTTPS] Server on https://%s (proxy → %s)", cfg.Domain, cfg.BackendURL)
	if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		log.Fatalf("Manual HTTPS error: %v", err)
	}
}

// ============================================================================
// Backend proxy
// ============================================================================

func proxyBackendHandler(cfg *config.Config, cf *CloudflareIPManager) http.Handler {
	target, err := url.Parse(cfg.BackendURL)
	if err != nil {
		log.Fatalf("Invalid backend URL: %v", err)
	}

	if !isPrivateIP(target.Hostname()) && target.Hostname() != "localhost" {
		log.Println("⚠️  Backend appears to be on a public network; make sure it is not directly reachable")
	}

	// CHANGED: build ReverseProxy directly instead of via
	// NewSingleHostReverseProxy. The latter sets BOTH Director and Rewrite
	// (Go ≥ 1.20), and ReverseProxy requires exactly one. Building it
	// manually avoids that pitfall and makes the behavior explicit.
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			setForwardedHeaders(pr, cfg.RequireCloudflare, cf)
		},
		Transport: &http.Transport{
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
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[PROXY ERROR] %s %s: %v", r.Method, r.URL.Path, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return proxy
}

// setForwardedHeaders rebuilds the X-Forwarded-* headers on pr.Out (the
// request actually sent to the backend). It honors the X-Forwarded-For
// already provided by Cloudflare and appends the direct peer IP (the CF edge).
//
// Requirements:
//   - pr.Out.Header already contains what SetURL/SetXForwarded left, so we
//     start from the original XFF in pr.In.Header (the one sent by
//     Cloudflare), not the one already injected by SetXForwarded into pr.Out.
func setForwardedHeaders(pr *httputil.ProxyRequest, requireCloudflare bool, cf *CloudflareIPManager) {
	in := pr.In
	out := pr.Out

	// Direct peer of this connection (the Cloudflare edge in production).
	peerIP := remoteAddrIP(in)
	// Real end-user IP, resolved from CF-Connecting-IP / X-Real-IP /
	// X-Forwarded-For. In production with REQUIRE_CLOUDFLARE=true these
	// headers only arrive from the CF edge (see getClientIP).
	clientIP := getClientIP(in, requireCloudflare, cf)

	// X-Forwarded-For is an audit chain: each proxy appends the IP of its
	// direct peer. Cloudflare already placed the user IP at the start;
	// goserve appends the IP of the CF edge it is facing.
	//
	// IMPORTANT: we read XFF from in.Header (the original), NOT from
	// out.Header (already contaminated by SetXForwarded).
	prior := strings.TrimSpace(in.Header.Get("X-Forwarded-For"))
	var xff string
	switch {
	case prior != "" && peerIP != "":
		xff = prior + ", " + peerIP
	case prior != "":
		xff = prior
	case peerIP != "":
		xff = peerIP
	}
	if xff != "" {
		out.Header.Set("X-Forwarded-For", xff)
	} else {
		out.Header.Del("X-Forwarded-For")
	}

	if clientIP != "" {
		// X-Real-IP identifies the end user, not the intermediate proxy.
		out.Header.Set("X-Real-IP", clientIP)
	}

	// X-Forwarded-Proto: local TLS > previous header > https if CF.
	// With Cloudflare, TLS terminates at CF, so in.TLS is nil; in that case
	// we trust CF's X-Forwarded-Proto and, if absent, assume https because
	// CF always serves https to the end user.
	proto := "http"
	if in.TLS != nil {
		proto = "https"
	}
	if existing := in.Header.Get("X-Forwarded-Proto"); existing != "" {
		proto = existing
	} else if requireCloudflare {
		proto = "https"
	}
	out.Header.Set("X-Forwarded-Proto", proto)

	if in.Host != "" {
		out.Header.Set("X-Forwarded-Host", in.Host)
	}
}

// ============================================================================
// Static file serving
// ============================================================================

func serveStatic(staticDir, wsPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// FIX: /api (without slash) previously fell through to static and
		// returned index.html.
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
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
			switch ext {
			case ".js", ".css", ".jpg", ".jpeg", ".png", ".svg", ".webp", ".woff", ".woff2":
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

// safeStaticPath validates that requestPath does not escape staticDir.
// FIX: in addition to the lexical check, it resolves symlinks to prevent
// a symlink inside staticDir from pointing outside the directory.
func safeStaticPath(staticDir, requestPath string) (string, error) {
	absStatic, err := filepath.Abs(staticDir)
	if err != nil {
		return "", err
	}
	// Resolve symlinks on the root directory to compare against the real path.
	if resolved, err := filepath.EvalSymlinks(absStatic); err == nil {
		absStatic = resolved
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

	// If the path exists, resolve symlinks and ensure it is still inside.
	if resolved, err := filepath.EvalSymlinks(absFull); err == nil {
		rel, err := filepath.Rel(absStatic, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", errPathTraversal
		}
		return resolved, nil
	}

	// If it does not exist yet (e.g. index.html not created), validate
	// lexically.
	rel, err := filepath.Rel(absStatic, absFull)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errPathTraversal
	}

	return absFull, nil
}

// ============================================================================
// Rate limit / Cloudflare middleware
// ============================================================================

// rateLimitMiddleware limits per IP. trustForwarded must be true ONLY if
// traffic comes from a trusted proxy (Cloudflare). If false, RemoteAddr is
// used directly to prevent X-Forwarded-For spoofing.
func rateLimitMiddleware(rl *RateLimiter, trustForwarded bool, cf *CloudflareIPManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r, trustForwarded, cf)
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
				log.Printf("[CLOUDFLARE] rejected RemoteAddr=%s", r.RemoteAddr)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// CORS / security headers
// ============================================================================

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
		// Only for static assets served by this process; /api/ is handled by
		// the backend.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// productionCORSMiddleware. CHANGED: allowed origins come from cfg
// (or a default list if cfg does not define them). Avoids hardcoding domains.
func productionCORSMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	allowedOrigins := map[string]bool{}
	for _, o := range cfg.AllowedOrigins {
		allowedOrigins[o] = true
	}
	// Conservative fallback if the config does not provide origins.
	if len(allowedOrigins) == 0 {
		allowedOrigins["https://"+cfg.Domain] = true
		allowedOrigins["https://www."+cfg.Domain] = true
	}

	return func(next http.Handler) http.Handler {
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
}

// ============================================================================
// gzip
// ============================================================================

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		// FIX: use Add instead of Set so we do not overwrite other Vary values.
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
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

// FIX: implement Flush so we do not break streaming handlers
// (SSE, chunked, etc.) if gzip is ever applied to /api/.
func (w *gzipResponseWriter) Flush() {
	_ = w.Writer.(*gzip.Writer).Flush()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ============================================================================
// logging
// ============================================================================

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		log.Printf("[%s] %s %d %v %s",
			r.Method, r.URL.Path, lrw.statusCode, time.Since(start), getClientIP(r, false, nil))
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

// FIX: Flush so we do not break streaming.
func (lrw *loggingResponseWriter) Flush() {
	if f, ok := lrw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ============================================================================
// redirectToHTTPS
// ============================================================================

// redirectToHTTPS redirects to HTTPS but ONLY if the Host belongs to the
// configured domain. Prevents an attacker from using Host: evil.com to make
// the server issue a 301 to evil.com (open redirect / phishing / HSTS theft).
func redirectToHTTPS(allowedDomain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)
		allowed := strings.ToLower(allowedDomain)
		if host != allowed && !strings.HasSuffix(host, "."+allowed) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// ============================================================================
// Helpers
// ============================================================================

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

// getClientIP returns the end-user IP.
//
// trustForwarded must be true ONLY when traffic comes from a trusted proxy
// (Cloudflare). If cf != nil, it also verifies that the direct peer is really
// a Cloudflare IP before trusting CF-Connecting-IP.
//
// CRITICAL FIX: previously trustForwarded=true was passed unconditionally,
// which allowed any client to send "CF-Connecting-IP: 1.2.3.4" and bypass the
// rate limit by creating a new limiter per request.
func getClientIP(r *http.Request, trustForwarded bool, cf *CloudflareIPManager) string {
	peer := remoteAddrIP(r)
	if !trustForwarded {
		return peer
	}

	// If we have the CF manager, only trust CF headers if the direct peer is
	// really Cloudflare. Otherwise fall back to RemoteAddr.
	trustHeaders := true
	if cf != nil {
		parsed := net.ParseIP(peer)
		trustHeaders = parsed != nil && cf.IsCloudflareIP(parsed)
	}

	if !trustHeaders {
		return peer
	}

	parse := func(raw string) string {
		raw = strings.TrimSpace(raw)
		if ip := net.ParseIP(raw); ip != nil {
			return ip.String()
		}
		// Support "[::1]:1234" in case some proxy appends a port.
		if host, _, err := net.SplitHostPort(raw); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip.String()
			}
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
	return peer
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
		return fmt.Errorf("backend_url is required")
	}

	if mode != "dev" {
		if cfg.Domain == "" {
			return fmt.Errorf("domain is required in production")
		}
		if cfg.RateLimit <= 0 {
			cfg.RateLimit = 50
		}
		if cfg.RateBurst <= 0 {
			cfg.RateBurst = 100
		}
		if cfg.AdminEmail == "" && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
			log.Println("⚠️  ADMIN_EMAIL not set (recommended for Let's Encrypt)")
		}
	}

	if _, err := url.Parse(cfg.BackendURL); err != nil {
		return fmt.Errorf("invalid backend_url: %w", err)
	}

	return nil
}
