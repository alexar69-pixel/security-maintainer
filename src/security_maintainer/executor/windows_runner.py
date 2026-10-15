"""
Windows Action Runner / Ejecutor de acciones en el host Windows sin elevación silenciosa.
Enforces deterministic execution, admin privilege checks, and strict binary allowlists.
"""

from __future__ import annotations
import logging
import subprocess
import shutil
import ctypes
import os
from pathlib import Path
from typing import Dict, Any, Optional

from ..models import PlanAction, ExecutionResult, ActionStatus, ManagerType

logger = logging.getLogger(__name__)

ALLOWED_WINDOWS_BINARIES = {
    "winget", "winget.exe", "powershell", "powershell.exe", "cmd.exe", "msiexec", "msiexec.exe"
}


def is_windows_admin() -> bool:
    """Checks if the current process holds Administrator rights in Windows."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class WindowsRunner:
    """Executes authorized update actions on Windows with privilege and binary controls."""

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
                diagnostic_output=mock.get("output", "Simulado en fixture.")
            )

        # 1. Comprobación de privilegios de Administrador
        if action.required_privileges == "admin":
            if not is_windows_admin():
                return ExecutionResult(
                    action_id=action.action_id,
                    product_name=action.product_name,
                    manager=action.manager,
                    success=False,
                    exit_code=126,
                    status=ActionStatus.BLOCKED_PERMISSIONS,
                    error_message=(
                        f"Acción bloqueada: Se requieren privilegios de Administrador para actualizar '{action.product_name}'. "
                        "OpenClaw no realiza elevación silenciosa. Ejecuta la terminal como Administrador o aplica manualmente."
                    )
                )

        # 2. Validación de allowlist de ejecutables para prevenir ejecución arbitraria
        if not action.exact_command or not isinstance(action.exact_command, list):
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=1,
                status=ActionStatus.FAILED,
                error_message="Comando inválido o vacío."
            )

        binary_name = Path(action.exact_command[0]).name.lower()
        if binary_name not in ALLOWED_WINDOWS_BINARIES:
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=126,
                status=ActionStatus.BLOCKED_PERMISSIONS,
                error_message=f"Ejecutable no autorizado en la lista de permitidos de Windows: {binary_name}"
            )

        # 3. Ejecución determinista
        try:
            res = subprocess.run(
                action.exact_command,
                capture_output=True,
                text=True,
                timeout=180
            )
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
                error_message=f"Tiempo de espera agotado al actualizar {action.product_name}."
            )
        except Exception as e:
            return ExecutionResult(
                action_id=action.action_id,
                product_name=action.product_name,
                manager=action.manager,
                success=False,
                exit_code=1,
                status=ActionStatus.FAILED,
                error_message=f"Error inesperado durante la ejecución: {e}"
            )
