# Changelog

Todas las modificaciones notables de este proyecto se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y se adhiere a [Semantic Versioning](https://semver.org/lang/es/).

## [1.0.0] - 2026-10-14

### Añadido
- **Skill de OpenClaw (`SKILL.md`):** Definición declarativa de la skill con disparadores en lenguaje natural y políticas de aprobación.
- **Motor Core de Mantenimiento:**
  - Modos de funcionamiento estricto: `audit` (solo lectura), `ask` (aprobación requerida) y `auto` (política persistente).
  - Generación de planes deterministas con huellas SHA-256 e identificador de plan (UUIDv4) con caducidad temporal.
  - Bloqueo de concurrencia mediante `maintainer.lock` con control de PID activo.
- **Adaptadores de Inventario:**
  - Windows: Detección de versión/build, aplicaciones WinGet, desinstaladores en Registro y actualizaciones pendientes mediante Windows Update COM API.
  - WSL: Detección de distribuciones instaladas, estado running/stopped, versión de plataforma y kernel WSL, paquetes y actualizaciones `apt`/`dpkg`.
  - Gestores secundarios: Detección preliminar de pipx, npm, scoop, choco.
  - Proyectos de código: Soporte explícito para dependencias Node.js (`package.json`, `package-lock.json`) y Python (`requirements.txt`, `pyproject.toml`).
- **Fuentes de Vulnerabilidades:**
  - Integración con la API de OSV.dev con paginación, retries y control de tasa.
  - Integración con el catálogo oficial CISA KEV (Known Exploited Vulnerabilities) con caché local de 24 horas.
  - Tracker de seguridad de distribuciones Linux con reconocimiento de parches retroportados (backports) en Ubuntu y Debian para evitar falsos positivos.
  - Sistema de caché local en disco con marcas de tiempo UTC.
- **Verificación y Seguridad:**
  - Verificación post-parche comprobando versión efectiva instalada y no únicamente código de salida cero.
  - Detección de reinicios pendientes (`/var/run/reboot-required` en Linux y claves de registro en Windows).
  - Control de elevación: Las acciones que requieren privilegios de Administrador o `sudo` se registran como bloqueadas si no están delegadas, sin intentos de elevación silenciosa.
- **Informes:**
  - Generación de informes duales en JSON y Markdown en español con advertencias claras ante fallos de fuentes de datos.
- **Suite de Pruebas:**
  - Pruebas unitarias completas con fixtures para inventario, advisories, planificación, ejecución, verificación e interfaz CLI.
