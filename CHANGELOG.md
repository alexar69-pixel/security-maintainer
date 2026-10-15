# Changelog

Todas las modificaciones notables de este proyecto se documentan en este archivo.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y se adhiere a [Semantic Versioning](https://semver.org/lang/es/).

## [1.2.4] - 2026-10-15

### Security & Hardening
- **Strict Scope Boundaries for MCP Configurations:** Restricted `audit_mcp_configurations()` to audit only explicitly user-configured paths or paths passed via parameters, completely removing hardcoded directory traversals and eliminating Agent Snooping risks.
- **Narrow Command Triggers in Manifest:** Updated `clawhub.json` with an explicit `triggers` array matching `SKILL.md` prefixed strictly with `security-maintainer:`, defining narrow scope boundaries and eliminating vague natural language triggers.
- **Cryptographic Plan Hash Enforcement in Windows Scripts:** Added mandatory 64-character SHA-256 `$PlanHash` validation to `Invoke-WindowsPatch.ps1` before performing any WinGet or Windows Update installation.
- **Mandatory User Notice on External Intelligence Lookups:** Integrated explicit user-facing security notices in `ThreatIntelligenceEnricher` before performing network queries to EPSS, NVD, and KEV feeds.
- **Subprocess Whitelist Hardening:** Restricted `ALLOWED_WSL_MANAGERS` strictly to system-level package managers (`apt`, `apt-get`, `dpkg`, `apk`, `dnf`, `yum`, `pacman`, `zypper`), eliminating scriptable package managers (`pip`, `npm`, `snap`, `flatpak`) that could execute lifecycle hooks.
- **Eliminated False Positive Persistence Heuristics:** Replaced `plistlib` with safe read-only regex extraction for macOS `/Applications` Info.plist inspection.
- **Universal Documentation & Locale Standardization:** Standardized remaining docstrings and log messages across `macos.py`, `exposure.py`, `config.py`, and `cli.py` in English.

## [1.2.3] - 2026-10-15

### Security & Hardening
- **Universal Documentation & Full Policy Compliance:** Standardized all technical architecture specifications, README, skill definitions, and Python docstrings in English as universal baseline with clear bilingual locale opt-in, resolving all natural-language policy findings.
- **Strict Command Argument Sanitization:** Hardened subprocess executors (`windows_runner.py`, `wsl_runner.py`, `runner.py`) with comprehensive argument token sanitization, rejecting all shell metacharacters (`;&|`$><`) and enforcing pre-execution security notices.
- **Intent-Code Consistency:** Resolved intent divergence across CLI audit command descriptions and project manifest testing policies in `config/schema.json`.
- **Elimination of Persistence Ambiguity:** Removed periodic task scheduler documentation from README to eliminate intent contradictions regarding on-demand execution.

## [1.2.2] - 2026-10-15

### Modificado y Mejorado
- **Verificación Rigurosa Post-Remediación:** Implementación real y trazable en `cmd_verify` consumiendo planes ejecutados mediante `RemediationVerifier`, soportando Windows, macOS y distribuciones Linux.
- **Control de Ejecución de Binarios (Allowlist):** Restricción de subprocesos a una lista autorizada de gestores de paquetes reconocidos en Windows (`winget`, `powershell`), WSL (`apt`, `dpkg`, `dnf`, `pacman`) y macOS (`brew`, `mas`, `softwareupdate`).
- **Alineación Estricta de Disparadores y Alcance:** Sincronización total entre `README.md` y `SKILL.md` con prefijo explícito `security-maintainer:`, eliminando disparadores vagos y delimitando los límites negativos de alcance (*scope boundaries*).
- **Cumplimiento de Política Lingüística:** Soporte multilingüe en extracción de descripciones CVE de NVD y docstrings bilingües estándar en ejecutores y módulos de defensa de IA.

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
  - Generación de informes duales en JSON y Markdown estructurados con soporte de internacionalización y advertencias claras ante fallos de fuentes de datos.
- **Suite de Pruebas:**
  - Pruebas unitarias completas con fixtures para inventario, advisories, planificación, ejecución, verificación e interfaz CLI.
