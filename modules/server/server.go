package server

import (
	"compress/gzip"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/polarysfoundation/go-server/modules/config"
)

func startServer(cfg *config.Config) {
	apiProxy := proxyAPIHandler(cfg.BackendURL)

	// Redirección HTTP a HTTPS
	go func() {
		log.Printf("[HTTP] Redireccionando tráfico a HTTPS desde puerto 80")
		err := http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + cfg.Host + r.RequestURI
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}))
		if err != nil {
			log.Fatalf("Error al redirigir HTTP: %v", err)
		}
	}()

	mux := http.NewServeMux()
	handler := corsMiddleware(cfg.Host,
		gzipMiddleware(
			loggingMiddleware(
				http.HandlerFunc(staticHandler(cfg.StaticDir, apiProxy)),
			),
		),
	)
	mux.Handle("/", handler)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		},
	}

	certFile := filepath.Join(config.CERT_PATH, "fullchain.pem")
	keyFile := filepath.Join(config.CERT_PATH, "privkey.pem")

	log.Printf("[HTTPS] Servidor iniciado en https://%s:%s", cfg.Host, cfg.Port)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("Error en servidor HTTPS: %v", err)
	}
}

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
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
	}
}

func corsMiddleware(domain string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://"+domain)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

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
