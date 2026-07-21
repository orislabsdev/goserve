# Changelog

Todas las mejoras notables en GoServe se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es/1.0.0/),
y este proyecto adherido al [Semantic Versioning](https://semver.org/lang/es/).

## [Unreleased]

### Added
- Archivo README.md con documentación completa
- Archivo LICENSE (MIT)
- Este archivo CHANGELOG

### Changed
- Refactorizar manejo de configuración para soporte JSON y variables de entorno
- Mejorar rate limiting y gestión de IPs de Cloudflare
- Actualizar module path de polarysfoundation a orislabsdev
- Mejorar manejo de certificados TLS y dominio
- Añadir headers de seguridad en middleware
- Mejorar manejo de archivos estáticos con CORS dinámico

### Fixed
- Eliminar código no utilizado y middleware innecesario
- Corregir manejo de claves de seguridad

## [0.1.0] - 2026-07-21

### Added
- Servidor HTTP/HTTPS con proxy inverso
- Servidor de archivos estáticos para SPAs
- Proxy WebSocket
- Rate limiting por IP
- Filtro de IPs de Cloudflare
- TLS automático con Let's Encrypt (autocert)
- Soporte para certificados TLS manuales
- Compresión gzip
- Headers de seguridad
- CORS configurable para desarrollo y producción
- Configuración vía JSON o variables de entorno
- Makefile para build y ejecución
