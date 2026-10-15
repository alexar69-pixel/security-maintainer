"""
WSL Action Runner / Ejecutor de acciones en distribuciones WSL.
Enforces non-interactive sudo verification, distribution targeting, and package manager allowlists.
"""

from __future__ import annotations
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, Optional

from ..models import PlanAction, ExecutionResult, ActionStatus, ManagerType

logger = logging.getLogger(__name__)

ALLOWED_WSL_MANAGERS = {
    "apt", "apt-get", "dpkg", "apk", "dnf", "yum", "pacman", "zypper", "pip", "pip3", "npm", "flatpak", "snap"
}


class WSLRunner:
    """Executes authorized update actions inside targeted WSL distributions."""

    def __init__(self, config: Dict[str, Any], fixture_results: Optional[Dict[str, Any]] = None):
        self.config = config
        self.fixture_results = fixture_results

    def execute_action(self, action: PlanAction) -> ExecutionResult:
        if self.fixture_results and action.action_id in self.fixture_results:
            mock = self.fixture_results[action.action_id]
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=mock.get("success", True),
                exit_code=mock.get("exit_code", 0),
                effective_version_detected=mock.get("effective_version", action.target_version),
                verification_passed=mock.get("verification_passed", True),
                reboot_pending=mock.get("reboot_pending", False),
                status=ActionStatus(mock.get("status", ActionStatus.EXECUTED_VERIFIED.value)),
                diagnostic_output=mock.get("output", "Simulado en WSL fixture.")
            )

        distro_name = action.target.replace("WSL:", "")
        wsl_bin = shutil.which("wsl.exe") or shutil.which("wsl")
        if not wsl_bin:
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=127,
                status=ActionStatus.FAILED,
                error_message="wsl.exe no encontrado en el sistema."
            )

        # 1. Comprobar si requiere sudo y si está permitido sin contraseña interactiva
        if action.required_privileges == "sudo":
            check_sudo_cmd = [wsl_bin, "-d", distro_name, "-e", "sudo", "-n", "true"]
            check_res = subprocess.run(check_sudo_cmd, capture_output=True, timeout=10)
            if check_res.returncode != 0:
                return ExecutionResult(
                    action_id=action.action_id,
                    product_name=action.product_name,
                    manager=action.manager,
                    success=False,
                    exit_code=126,
                    status=ActionStatus.BLOCKED_PERMISSIONS,
                    error_message=(
                        f"Acción bloqueada: Se requieren permisos 'sudo' para actualizar '{action.product_name}' en {distro_name}. "
                        "El usuario no tiene sudo sin contraseña configurado. Aplica manualmente o configura permisos adecuados."
                    )
                )

        # 2. Validación de gestores autorizados en WSL
        if not action.exact_command or not isinstance(action.exact_command, list):
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=1,
                status=ActionStatus.FAILED,
                error_message="Comando WSL inválido o vacío."
            )

        cmd_binary = Path(action.exact_command[0]).name.lower()
        if cmd_binary not in ALLOWED_WSL_MANAGERS:
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=126,
                status=ActionStatus.BLOCKED_PERMISSIONS,
                error_message=f"Gestor no autorizado en distribuciones WSL: {cmd_binary}"
            )

        # 3. Construir comando para WSL
        full_cmd = [wsl_bin, "-d", distro_name, "-e"]
        if action.required_privileges == "sudo":
            full_cmd.append("sudo")
        full_cmd.extend(action.exact_command)

        try:
            res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=180)
            success = res.returncode == 0
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=success,
                exit_code=res.returncode,
                status=ActionStatus.EXECUTED_UNVERIFIED if success else ActionStatus.FAILED,
                diagnostic_output=res.stdout,
                error_message=res.stderr if not success else None
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=124,
                status=ActionStatus.FAILED,
                error_message=f"Tiempo de espera agotado al actualizar {action.product_name} en WSL."
            )
        except Exception as e:
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=1,
                status=ActionStatus.FAILED,
                error_message=f"Excepción al ejecutar acción en WSL: {e}"
            )
