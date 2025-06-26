package server

import (
	"compress/gzip"
	"io"
	"log"
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

	apiHandler := corsMiddleware(cfg.Host,
		loggingMiddleware(apiProxy),
	)

	staticHandler := corsMiddleware(cfg.Host,
		gzipMiddleware(
			loggingMiddleware(
				http.HandlerFunc(staticHandler(cfg.StaticDir, apiProxy)),
			),
		),
	)

	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/", staticHandler)

	if mode == "dev" {
		// 🔓 MODO DESARROLLO: solo HTTP
		addr := cfg.Port
		if cfg.Host != "" {
			addr = cfg.Host + ":" + cfg.Port
		} // o configurable desde cfg.Port si quieres
		log.Printf("[DEV] Servidor HTTP iniciado en http://localhost%s", addr)
		server := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Error en servidor dev HTTP: %v", err)
		}
		return
	}

	// 🔐 MODO PRODUCCIÓN: HTTPS con autocert + redirección desde HTTP
	certManager := autocert.Manager{
		Cache:      autocert.DirCache(".certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Host),
	}

	// Redirección HTTP a HTTPS + ACME
	go func() {
		log.Printf("[HTTP] Sirviendo challenge ACME y redirigiendo HTTP -> HTTPS en :80")
		err := http.ListenAndServe(":80", certManager.HTTPHandler(nil))
		if err != nil {
			log.Fatalf("Error en servidor HTTP para autocert: %v", err)
		}
	}()

	server := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: certManager.TLSConfig(),
	}

	log.Printf("[HTTPS] Servidor seguro iniciado en https://%s", cfg.Host)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Error en servidor HTTPS con autocert: %v", err)
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
