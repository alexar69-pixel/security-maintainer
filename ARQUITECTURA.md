# Arquitectura Técnica de `security-maintainer`
 
> [!WARNING]
> **Aviso de Seguridad y Alcance del Sistema:**
> `security-maintainer` opera sobre componentes de sistema operativo (Windows, macOS, distribuciones Linux/WSL) y dependencias de proyectos. Las operaciones de actualización modifican binarios o librerías del sistema. Para preservar la integridad del entorno, el modo predeterminado es estrictamente `ask` (requiere plan numerado, hash SHA-256 inmutable y confirmación explícita del usuario). Nunca aplique el modo automático (`auto`) sin haber auditado previamente el impacto en los servicios instalados.

`security-maintainer` está diseñado bajo un modelo desacoplado y determinista para operar en entornos híbridos donde el agente OpenClaw se ejecuta dentro de WSL o nativamente en el anfitrión (Windows, macOS, Linux).

## 1. Diagrama de Arquitectura de Alto Nivel

```mermaid
flowchart TD
    subgraph OpenClaw ["Entorno OpenClaw (WSL)"]
        SKILL["SKILL.md (OpenClaw Skill Interface)"]
        CLI["CLI Entrypoint (cli.py)"]
        CONFIG["ConfigManager (config.py & schema.json)"]
    end

    subgraph Core ["Motor Core de Mantenimiento"]
        INV_COORD["Coordinador de Inventario"]
        ADVISORY["Motor de Advisories (OSV, KEV, Backports)"]
        CACHE["AdvisoryCache (Disco local)"]
        PLANNER["PlannerEngine (engine.py)"]
        POLICY["PolicyEngine (policy.py)"]
        APPROVAL["ApprovalManager (approval.py)"]
        RUNNER["PlanExecutor (runner.py)"]
        LOCK["ConcurrencyLock (maintainer.lock)"]
        VERIFIER["RemediationVerifier (verifier.py)"]
        REPORTER["Reporters (JSON y Markdown)"]
    end

    subgraph Adapters ["Adaptadores por Entorno"]
        WIN_ADAPT["Windows Adapter (Get-WindowsInventory.ps1)"]
        WSL_ADAPT["WSL Adapter (inspect_wsl.sh)"]
        PROJ_ADAPT["Projects Adapter (Node/Python)"]
        PKG_ADAPT["Package Managers (pipx, npm)"]
    end

    subgraph TargetSystems ["Sistemas Gestionados"]
        WIN_HOST["Windows Host (WinGet, Registry, Windows Update)"]
        WSL_DISTROS["WSL Distros (Ubuntu, Debian, etc.)"]
        CODE_PROJECTS["Repositorios de Código Registrados"]
    end

    SKILL --> CLI
    CLI --> CONFIG
    CLI --> INV_COORD
    CLI --> PLANNER
    CLI --> RUNNER
    CLI --> REPORTER

    INV_COORD --> WIN_ADAPT
    INV_COORD --> WSL_ADAPT
    INV_COORD --> PROJ_ADAPT
    INV_COORD --> PKG_ADAPT

    WIN_ADAPT --> WIN_HOST
    WSL_ADAPT --> WSL_DISTROS
    PROJ_ADAPT --> CODE_PROJECTS

    ADVISORY --> CACHE
    PLANNER --> POLICY
    PLANNER --> APPROVAL
    RUNNER --> LOCK
    RUNNER --> VERIFIER
```

---

## 2. Flujo de Estados y Ciclo de Vida del Plan

> [!IMPORTANT]
> **Advertencia sobre Modos de Ejecución:**
> Los cambios sobre paquetes y librerías del sistema conllevan riesgos de incompatibilidad o reinicio de servicios. Se debe auditar siempre el plan antes de considerar cualquier modo no supervisado.

El motor opera bajo tres modos estrictos: `audit`, `ask` (predeterminado) y `auto`.

```mermaid
stateDiagram-v2
    [*] --> Inventario: Ejecución de Audit / Plan
    Inventario --> CruceVulnerabilidades: Recopilación de items
    CruceVulnerabilidades --> EvaluacionPoliticas: Enriquecimiento con CVE y KEV
    EvaluacionPoliticas --> GeneracionPlan: Filtrado de exclusiones y pins
    GeneracionPlan --> HashCanonica: Cálculo SHA-256 de acciones
    HashCanonica --> EsperaAprobacion: Modo 'ask' (Default)
    HashCanonica --> EjecucionInmediata: Modo 'auto' (Autorizado)

    EsperaAprobacion --> VerificacionToken: Usuario aprueba con Hash
    EsperaAprobacion --> CanceladoExpirado: Transcurren > 30 minutos

    VerificacionToken --> AdquisicionBloqueo: Huella íntegra
    VerificacionToken --> Rechazado: Huella no coincide o plan alterado

    AdquisicionBloqueo --> EjecucionSecuencial: ConcurrencyLock adquirido
    EjecucionSecuencial --> VerificacionVersion: Ejecución del gestor (código 0)
    VerificacionVersion --> FinVerificado: Versión efectiva confirmada
    VerificacionVersion --> FinDiscrepancia: Versión no coincide (Unverified)
    FinVerificado --> GeneracionInforme: Emisión JSON y Markdown
    FinDiscrepancia --> GeneracionInforme
    Rechazado --> [*]
    GeneracionInforme --> [*]
```

---

## 3. Principios de Seguridad y Contención

1. **Aislamiento de Comandos:**
   - No se utiliza `shell=True` en llamadas de subprocess de Python.
   - Los nombres de paquetes e identificadores se validan contra expresiones regulares restrictivas (`^[a-zA-Z0-9_\-\.]+$`) antes de ser transmitidos a ejecutables.
2. **Tratamiento de Datos Externos:**
   - La información obtenida de OSV.dev, GitHub Advisories o catálogos CVE se procesa estrictamente como texto/metadatos no confiables. No se interpreta código ni sintaxis de shell contenida en descripciones.
3. **Control de Privilegios:**
   - Si una acción de Windows requiere permisos de Administrador y el proceso se ejecuta como usuario estándar, la acción se marca como `BLOCKED_PERMISSIONS` y no se intenta invocar `runas` ni scripts ocultos de elevación.
   - En Linux/WSL, las operaciones de paquetes que requieran privilegios delegados verifican de antemano el acceso no interactivo (`sudo -n true`). Si se requiere elevación interactiva no delegada, la acción se bloquea inmediatamente (`BLOCKED_PERMISSIONS`) y se devuelve la instrucción para ejecución manual por el operador.
4. **Bloqueo de Concurrencia:**
   - Se utiliza un archivo de bloqueo en `~/.security-maintainer/maintainer.lock` con PID registrado y verificación de proceso activo para impedir colisiones o corrupciones de gestores de paquetes.
5. **Caducidad e Inmutabilidad de Planes:**
   - Cada plan cuenta con un identificador único y una huella SHA-256 canónica construida sobre la tupla `(action_id, target, product_id, installed_version, target_version, command, privileges)`.
   - Cualquier alteración del archivo JSON del plan invalida la huella y es rechazada inmediatamente por `ApprovalManager`.
