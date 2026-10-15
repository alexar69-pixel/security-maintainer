"""
AI & Agent Security Auditor / Auditor de seguridad para agentes de IA y modelos locales.
Detects risks based on OWASP Top 10 for LLMs / Agentic Systems and SkillSpector:
- Exposure of unauthenticated local LLM inference engines (Ollama, LM Studio, etc.)
- MCP Tool Poisoning and excessive permissions
- Prompt injection patterns in prompt/context files
- AI credential exposure in environment variables
"""

from __future__ import annotations
import os
import re
import json
import logging
import socket
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..models import AISecurityFinding, AIThreatType, SeverityLevel

logger = logging.getLogger(__name__)

# Standard ports used by local AI inference engines
KNOWN_LLM_SERVICES = {
    11434: ("Ollama", "Motor de inferencia LLM local de Ollama"),
    1234: ("LM Studio", "Servidor de modelos local de LM Studio"),
    8080: ("LocalAI / llama.cpp", "Servidor compatible con API de OpenAI"),
    8000: ("vLLM / TextGenWebUI", "Servidor de inferencia de alto rendimiento"),
    5000: ("TextGenWebUI / KoboldAI", "Interfaz web y backend de inferencia"),
}

# Instruction override and agent manipulation detection patterns
PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions)", re.IGNORECASE), "Anulación explícita de instrucciones del sistema"),
    (re.compile(r"(?i)(you\s+are\s+now\s+in\s+unrestricted\s+mode|dan\s+mode|jailbreak)", re.IGNORECASE), "Intento de evasión de restricciones (Jailbreak)"),
    (re.compile(r"(?i)(system\s*prompt\s*override|disregard\s+system\s+prompt)", re.IGNORECASE), "Intento de sobreescritura de prompt de sistema"),
    (re.compile(r"[\u200B\u200C\u200D\uFEFF]", re.UNICODE), "Caracteres Unicode invisibles de ancho cero (posible ofuscación de prompt)"),
]

# Sensitive AI environment variables that should not leak
AI_SENSITIVE_ENV_VARS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "MISTRAL_API_KEY",
    "HUGGINGFACE_TOKEN",
    "HF_TOKEN",
    "COHERE_API_KEY",
    "GROQ_API_KEY",
]


class AIAgentSecurityAuditor:
    """Audits AI agent security, local LLM exposure, and MCP tool configuration posture."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def audit_all(self, target_dirs: Optional[List[Path]] = None) -> List[AISecurityFinding]:
        """Runs all AI and agent security audits."""
        findings: List[AISecurityFinding] = []
        findings.extend(self.audit_local_llm_services())
        findings.extend(self.audit_mcp_configurations())
        findings.extend(self.audit_prompt_injections(target_dirs))
        findings.extend(self.audit_environment_secrets())
        return findings

    def audit_local_llm_services(self) -> List[AISecurityFinding]:
        """Audits local LLM inference engines listening on unauthenticated interfaces."""
        findings = []
        for port, (service_name, desc) in KNOWN_LLM_SERVICES.items():
            # Comprobar si el puerto está abierto en localhost
            is_local = self._check_socket("127.0.0.1", port)
            if is_local:
                # Comprobar si además está accesible externamente en 0.0.0.0 / IP pública
                # Intentamos conectar a la IP de red local
                try:
                    local_ip = socket.gethostbyname(socket.gethostname())
                    is_public = False
                    if local_ip and not local_ip.startswith("127."):
                        is_public = self._check_socket(local_ip, port)
                except Exception:
                    is_public = False

                if is_public:
                    findings.append(
                        AISecurityFinding(
                            threat_type=AIThreatType.UNAUTHENTICATED_LLM_SERVICE,
                            title=f"Servidor LLM {service_name} expuesto a la red local",
                            severity=SeverityLevel.HIGH,
                            target_component=f"{service_name} (Puerto {port})",
                            description=(
                                f"El servicio {desc} está escuchando en una interfaz no aislada ({local_ip}:{port}). "
                                "Cualquier dispositivo en la misma red podría enviar peticiones sin autenticación."
                            ),
                            evidence=f"Puerto {port} abierto y accesible en {local_ip}",
                            remediation_recommendation=f"Configure {service_name} para vincularse exclusivamente a 127.0.0.1 (OLLAMA_HOST=127.0.0.1)."
                        )
                    )
        return findings

    def audit_mcp_configurations(self) -> List[AISecurityFinding]:
        """Audits Model Context Protocol (MCP) server configuration files for excessive agency."""
        findings = []
        mcp_paths = [
            Path.home() / ".openclaw" / "mcp.json",
            Path.home() / ".gemini" / "antigravity" / "mcp",
            Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
            Path.home() / ".config" / "claude" / "claude_desktop_config.json"
        ]

        for p in mcp_paths:
            if not p.exists():
                continue
            
            try:
                if p.is_file():
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                        servers = data.get("mcpServers", {})
                        for s_name, s_cfg in servers.items():
                            cmd = s_cfg.get("command", "")
                            args = s_cfg.get("args", [])
                            # Detectar si un servidor MCP tiene comandos arbitrarios con bash/powershell/cmd
                            if cmd in ["bash", "sh", "powershell", "pwsh", "cmd.exe", "cmd"]:
                                findings.append(
                                    AISecurityFinding(
                                        threat_type=AIThreatType.EXCESSIVE_AGENCY,
                                        title=f"Servidor MCP '{s_name}' invoca shell directamente",
                                        severity=SeverityLevel.HIGH,
                                        target_component=f"MCP Server: {s_name}",
                                        description="El servidor MCP está configurado para ejecutar intérpretes de comandos shell directos.",
                                        evidence=f"command: {cmd}, args: {' '.join(str(a) for a in args)}",
                                        remediation_recommendation="Restrinja el servidor MCP a binarios dedicados con parámetros estrictamente validados."
                                    )
                                )
            except Exception as e:
                logger.debug(f"No se pudo analizar config MCP en {p}: {e}")

        return findings

    def audit_prompt_injections(self, search_paths: Optional[List[Path]] = None) -> List[AISecurityFinding]:
        """Audits agent instruction files and prompt contexts for prompt injection and override patterns."""
        findings = []
        paths_to_check = search_paths or [
            Path.home() / ".openclaw" / "workspace",
            Path.cwd()
        ]

        for base in paths_to_check:
            if not base.exists():
                continue

            # Buscar archivos relevantes: .md, .txt, .json
            candidates = []
            try:
                for ext in ["*.md", "*.txt"]:
                    for f in base.glob(ext):
                        if f.is_file() and f.stat().st_size < 100_000:
                            candidates.append(f)
            except Exception:
                pass

            for candidate in candidates:
                try:
                    content = candidate.read_text(encoding="utf-8", errors="ignore")
                    for pattern, desc in PROMPT_INJECTION_PATTERNS:
                        match = pattern.search(content)
                        if match:
                            findings.append(
                                AISecurityFinding(
                                    threat_type=AIThreatType.PROMPT_INJECTION,
                                    title=f"Posible inyección de prompt en {candidate.name}",
                                    severity=SeverityLevel.MEDIUM,
                                    target_component=str(candidate),
                                    description=f"Se detectó un patrón de manipulación de agente: {desc}.",
                                    evidence=match.group(0)[:80],
                                    remediation_recommendation="Verifique el origen del texto y aísle las instrucciones de usuario de las directivas de sistema."
                                )
                            )
                            break
                except Exception as e:
                    logger.debug(f"Error analizando {candidate}: {e}")

        return findings

    def audit_environment_secrets(self) -> List[AISecurityFinding]:
        """Audits runtime environment variables for exposed AI service provider credentials."""
        findings = []
        exposed_keys = []
        for var in AI_SENSITIVE_ENV_VARS:
            val = os.environ.get(var)
            if val and len(val) > 8:
                masked = val[:4] + "..." + val[-4:]
                exposed_keys.append(f"{var} ({masked})")

        if exposed_keys:
            findings.append(
                AISecurityFinding(
                    threat_type=AIThreatType.CREDENTIAL_EXPOSURE,
                    title="Variables de entorno con tokens de IA accesibles",
                    severity=SeverityLevel.LOW,
                    target_component="Environment Variables",
                    description=(
                        f"Se detectaron {len(exposed_keys)} variable(s) de entorno con claves de proveedores de IA. "
                        "Cualquier proceso o script ejecutado por el agente tiene visibilidad sobre estos secretos."
                    ),
                    evidence=", ".join(exposed_keys),
                    remediation_recommendation="Utilice almacenes de secretos seguros o limite la delegación de variables de entorno a subprocesos."
                )
            )

        return findings

    def _check_socket(self, host: str, port: int, timeout: float = 0.5) -> bool:
        """Performs a quick non-blocking socket connectivity check."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False
