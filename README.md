# `security-maintainer` — Skill de OpenClaw

[![CI](https://github.com/openclaw/security-maintainer/actions/workflows/ci.yml/badge.svg)](https://github.com/openclaw/security-maintainer/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Skill-orange.svg)](https://openclaw.dev)

Skill para **OpenClaw** diseñada para mantener actualizado el software de tu PC anfitrión Windows y sus distribuciones WSL, detectar vulnerabilidades conocidas (CVE, CISA KEV, OSV, advisories oficiales de distribuciones) y aplicar remediaciones autorizadas bajo un estricto modelo de control y verificación post-remediación.

---

## 1. Características Principales

- **Dos Funciones Complementarias:**
  1. *Mantenimiento Preventivo:* Detección y aplicación de actualizaciones generales disponibles, aunque no tengan un CVE asignado.
  2. *Remediación de Seguridad:* Correlación con bases de datos de vulnerabilidades oficiales (OSV.dev, CISA KEV, Distro Security Trackers), identificación del parche oficial y verificación post-instalación.
- **Diferenciación Rigurosa de Hallazgos:**
  - Actualización general disponible (sin vulnerabilidad confirmada).
  - Parche oficial de seguridad (resuelve CVEs específicos).
  - Mitigación de configuración (no altera binarios).
  - Vulnerabilidad sin parche oficial disponible.
  - Producto sin soporte / Fin de vida (EOL).
  - Bug funcional en proyectos de código propio.
- **Tres Modos de Operación:**
  - `audit` (Solo lectura): Inventaría, cruza vulnerabilidades y emite informes sin tocar el sistema.
  - `ask` (Predeterminado): Presenta un plan numerado con huella criptográfica SHA-256 y caducidad temporal (30 min); requiere aprobación explícita antes de ejecutar.
  - `auto`: Aplica automáticamente solo las acciones expresamente autorizadas por una directiva persistente.
- **Verificación Efectiva:** Un código de salida `0` no es suficiente para declarar un fallo corregido; el sistema re-inventaría el componente y comprueba la versión efectiva instalada y el estado de reinicios pendientes.
- **Portabilidad y Cero Telemetría:** Funciona con la biblioteca estándar de Python (>= 3.10), sin recopilación de datos personales ni contraseñas.

---

## 2. Entorno y Alcance

- **OpenClaw en WSL:** Diseñado específicamente para entornos donde el agente OpenClaw se ejecuta dentro de WSL (habitualmente con el usuario `openclaw`) y administra:
  - El anfitrión **Windows** (WinGet, Registro de desinstalación, Windows Update).
  - Las distribuciones **WSL** activas (`apt`, `dpkg`, `rpm`, `apk` y versión del kernel WSL).
  - **Proyectos de desarrollo** registrados explícitamente (Node.js y Python).
- **Protección de Distribuciones Detenidas:** Las distribuciones WSL detenidas no se inician automáticamente a menos que se configure explícitamente `auto_start_stopped_distros: true`.
- **Sin elevaciones de privilegios silenciosas:** Si una actualización requiere permisos de Administrador en Windows o `sudo` en WSL y no están concedidos, la acción se registra como `BLOCKED_PERMISSIONS` junto con la instrucción manual exacta.

---

## 3. Instalación

### Opción A: Desde ClawHub / OpenClaw CLI (Recomendado)

```bash
# Dentro de tu entorno WSL donde corre OpenClaw:
openclaw skills install security-maintainer
```

### Opción B: Instalación Manual desde Repositorio

```bash
# Clonar en tu directorio de skills de OpenClaw
git clone https://github.com/openclaw/security-maintainer.git ~/.openclaw/skills/security-maintainer

# Instalar dependencias en el entorno virtual de Python
cd ~/.openclaw/skills/security-maintainer
python3 -m pip install -e .
```

---

## 4. Permisos por Función

| Función | Ámbito | Nivel de Privilegios | Comportamiento si Faltan Permisos |
| :--- | :--- | :--- | :--- |
| **Auditoría e Inventario** | Windows / WSL | Usuario estándar | Permite auditar sin elevación. |
| **Actualizar Apps WinGet** | Windows | Usuario estándar / Admin | Si el instalador requiere UAC, se notifica bloqueo. |
| **Windows Update** | Windows | Administrador | Requiere terminal elevada; se marca como bloqueada. |
| **Actualizar Paquetes APT** | WSL | `sudo` (no interactivo) | Comprueba `sudo -n true`; si pide clave, se bloquea. |
| **Actualizar Proyectos Dev** | WSL / Windows | Propietario del repo | Modifica `package.json`/`requirements.txt` local. |

---

## 5. Configuración (`default_config.yaml`)

El archivo de configuración reside en `~/.security-maintainer/config.json` o se puede pasar con `--config`:

```yaml
version: "1.0.0"
mode: "ask" # 'ask' (default), 'audit' o 'auto'

windows:
  enabled: true
  allow_major_upgrades: false # Bloquea saltos 1.x -> 2.x por defecto
  allow_reboots: false        # Reinicios desatendidos desactivados
  excluded_packages:
    - "Microsoft.Edge"

wsl:
  enabled: true
  auto_start_stopped_distros: false
  allow_reboots: false
  distributions:
    OpenClawGateway:
      enabled: true
      security_updates_only: true
      configured_services:
        - "ssh"

projects:
  registered_paths:
    - "/home/openclaw/proyectos/mi-api"
  auto_run_tests: true

advisories:
  osv:
    enabled: true
    timeout_seconds: 15
  cisa_kev:
    enabled: true
    cache_ttl_hours: 24

execution:
  max_actions_per_run: 25
  plan_validity_minutes: 30
  lock_timeout_seconds: 60
```

---

## 6. Uso desde OpenClaw (Lenguaje Natural)

Puedes interactuar con la skill en lenguaje natural directamente en el chat de OpenClaw:

- *"Revisa las vulnerabilidades de mi PC y WSL"* -> Ejecuta una auditoría de solo lectura.
- *"Busca actualizaciones de todo el software"* -> Genera un plan de mantenimiento.
- *"Corrige las vulnerabilidades que tengan parche"* -> Construye el plan, muestra la huella SHA-256 y solicita confirmación.
- *"Aprobar plan <ID>"* -> Aplica las acciones aprobadas verificando la integridad de la huella.
- *"Muéstrame lo que no puedes actualizar"* -> Lista software sin soporte o que requiere intervención manual.
- *"Comprueba si quedó solucionado"* -> Re-inspecciona versiones efectivas.

---

## 7. Uso mediante Interfaz de Línea de Comandos (CLI)

```bash
# 1. Auditoría completa (solo lectura)
python3 -m security_maintainer.cli audit --all

# 2. Generar plan con huella SHA-256
python3 -m security_maintainer.cli plan --environment all

# 3. Aplicar un plan aprobado formalmente
python3 -m security_maintainer.cli apply --plan-id plan-a8f9c102 --plan-hash e3b0c442...

# 4. Verificar estado post-remediación
python3 -m security_maintainer.cli verify --environment all

# 5. Ver último informe generado
python3 -m security_maintainer.cli report
```

---

## 8. Programación de Revisiones Periódicas

Para programar auditorías automáticas periódicas (en modo de solo lectura `audit`), se recomienda utilizar el comando `/schedule` integrado de OpenClaw:

```text
/schedule cron="0 9 * * 1" prompt="Revisa las vulnerabilidades de mi PC y genera un informe de auditoría"
```

> [!IMPORTANT]
> Las auditorías periódicas programadas se ejecutan exclusivamente en modo de solo lectura (`audit`). La skill no aplica cambios automáticos ni establece procesos residentes o tareas persistentes en el sistema operativo.

---

## 9. Desinstalación

Para desinstalar la skill:

```bash
openclaw skills remove security-maintainer
```

Para eliminar los archivos de configuración local si ya no se requieren:
- En Windows: `Remove-Item -Recurse -Force "$HOME\.security-maintainer"`
- En macOS/Linux: `rm -r ~/.security-maintainer`

---

## 10. Documentación Técnica Adicional

- [Arquitectura Técnica](ARQUITECTURA.md) — Diagramas de flujo, control de estados y contención.
- [Matriz de Cobertura](COBERTURA.md) — Detalle exhaustivo de componentes gestionables, parciales y no soportados.
- [Ejemplo de Informe](EJEMPLO_INFORME.md) — Modelo ficticio de informe en Markdown.
- [Política de Seguridad](SECURITY.md) — Divulgación responsable de vulnerabilidades.
- [Licencia](LICENSE) — Licencia Apache 2.0.
