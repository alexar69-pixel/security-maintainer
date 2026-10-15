"""
Ejecutor de acciones de actualización en el host Windows sin elevación silenciosa.
"""

from __future__ import annotations
import logging
import subprocess
import shutil
import ctypes
import os
from typing import Dict, Any, Optional

from ..models import PlanAction, ExecutionResult, ActionStatus, ManagerType

logger = logging.getLogger(__name__)


def is_windows_admin() -> bool:
    """Comprueba si el proceso actual tiene privilegios de Administrador en Windows."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class WindowsRunner:
    """Ejecuta acciones autorizadas en Windows con control estricto de privilegios y argumentos."""

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

        # 2. Ejecución determinista
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
