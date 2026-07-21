# GoServe

Un servidor HTTP/HTTPS de alto rendimiento en Go con proxy inverso, servimiento de archivos estáticos y soporte WebSocket.

## Características

- **Proxy inverso** a backend con headers de forwarding
- **Servidor de archivos estáticos** para SPAs con routing del lado del cliente
- **WebSocket proxy** para conexiones en tiempo real
- **Rate limiting** por IP con configuración adjustable
- **Filtrado de IPs de Cloudflare** para mayor seguridad
- **TLS automático** con Let's Encrypt (autocert) o certificados manuales
- **Compresión gzip** para mejorar tiempos de carga
- **Headers de seguridad** en producción
- **CORS configurable** para desarrollo y producción
- **Configuración flexible** vía JSON o variables de entorno

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/orislabsdev/goserve.git
cd goserve

# Compilar
make build

# O directamente con Go
go build -o build/goserve main.go
```

## Uso

### Configuración

GoServe puede configurarse mediante:

1. **Archivo JSON** (ejemplo en `config.example.json`)
2. **Variables de entorno** (ejemplo en `server.env.example`)

### Ejecución

```bash
# Modo desarrollo (HTTP en puerto 8080)
./build/goserve --config config.json

# O con variables de entorno
./build/goserve --config server.env
```

### Parámetros de línea de comandos

| Parámetro | Descripción |
|-----------|-------------|
| `--config` | Ruta al archivo de configuración (.json o .env) |

### Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Host del servidor | `127.0.0.1` |
| `SERVER_PORT` | Puerto HTTP | `8080` |
| `TLS_PORT` | Puerto HTTPS | `443` |
| `DOMAIN` | Dominio del sitio | (requerido en prod) |
| `TLS_CERT_FILE` | Ruta al certificado TLS | (autocert si vacío) |
| `TLS_KEY_FILE` | Ruta a la clave TLS | (autocert si vacío) |
| `ADMIN_EMAIL` | Email para Let's Encrypt | (recomendado) |
| `BACKEND_URL` | URL del backend proxy | `http://127.0.0.1:4000` |
| `WS_PATH` | Ruta WebSocket (ej: `/ws`) | (vacío = deshabilitado) |
| `RATE_LIMIT_ENABLED` | Habilitar rate limiting | `true` |
| `RATE_LIMIT` | Límite de requests por segundo | `50` |
| `RATE_BURST` | Burst máximo de requests | `100` |
| `REQUIRE_CLOUDFLARE` | Solo IPs de Cloudflare | `false` |
| `STATIC_DIR` | Directorio de archivos estáticos | `./dist/spa` |
| `DEV_MODE` | Modo desarrollo | `true` |

## Arquitectura

```
goserve/
├── main.go              # Punto de entrada
├── modules/
│   ├── cmd/             # Manejo de comandos CLI
│   ├── config/          # Configuración y carga
│   ├── crypto/          # Utilidades criptográficas
│   └── server/          # Servidor HTTP/HTTPS y middlewares
├── Makefile             # Comandos de build
└── config.example.json  # Ejemplo de configuración
```

## Desarrollo

```bash
# Ejecutar en modo desarrollo
make run

# Compilar
make build

# Limpiar
make clean
```

## Seguridad

- Rate limiting por IP en producción
- Filtro opcional de IPs de Cloudflare
- Headers de seguridad (HSTS, X-Frame-Options, etc.)
- CORS configurado por dominios permitidos
- Prevención de path traversal en archivos estáticos
- TLS 1.2+ con cipher suites seguros

## Licencia

MIT License - ver [LICENSE](LICENSE) para detalles.
