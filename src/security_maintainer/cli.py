"""
Punto de entrada CLI para la skill Security Maintainer de OpenClaw.
Proporciona comandos deterministas para audit, plan, apply, verify y report.
"""

from __future__ import annotations
import argparse
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from .config import ConfigManager
from .models import (
    InventoryItem,
    Vulnerability,
    ActionPlan,
    CoverageSummary,
    ActionStatus,
)
from .inventory.windows import WindowsInventoryAdapter
from .inventory.wsl import WSLInventoryAdapter
from .inventory.macos import MacOSInventoryAdapter
from .inventory.platform_detector import PlatformDetector, HostOSType, RuntimeMountType
from .inventory.package_managers import AdditionalManagersAdapter
from .inventory.projects import RegisteredProjectsAdapter
from .advisories.cache import AdvisoryCache
from .advisories.cisa_kev import CisaKevCatalog
from .advisories.vulncheck import VulnCheckKevCatalog
from .advisories.epss import EpssClient
from .advisories.nvd import NvdClient
from .advisories.msrc import MsrcClient
from .advisories.ubuntu_security import UbuntuSecurityClient
from .advisories.enricher import ThreatIntelligenceEnricher
from .advisories.distro_trackers import DistroSecurityTracker
from .advisories.osv_client import OSVClient
from .planner.engine import PlannerEngine
from .planner.approval import ApprovalManager
from .executor.runner import PlanExecutor
from .verifier.verifier import RemediationVerifier
from .reporter.json_reporter import JSONReporter
from .reporter.markdown_reporter import MarkdownReporter

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("security_maintainer")

PENDING_PLANS_DIR = Path.home() / ".security-maintainer" / "plans"


def get_components(config: Dict[str, Any], fixture_bundle: Optional[Dict[str, Any]] = None):
    cache = AdvisoryCache()
    kev = CisaKevCatalog(config, cache, fixture_bundle.get("cisa_kev") if fixture_bundle else None)
    vulncheck = VulnCheckKevCatalog(config, cache, fixture_bundle.get("vulncheck") if fixture_bundle else None)
    epss = EpssClient(config, cache, fixture_bundle.get("epss") if fixture_bundle else None)
    nvd = NvdClient(config, cache, fixture_bundle.get("nvd") if fixture_bundle else None)
    msrc = MsrcClient(config, cache, fixture_bundle.get("msrc") if fixture_bundle else None)
    ubuntu_sec = UbuntuSecurityClient(config, cache, fixture_bundle.get("ubuntu_security") if fixture_bundle else None)
    enricher = ThreatIntelligenceEnricher(config, cache, kev, vulncheck, epss, nvd, msrc, ubuntu_sec)

    distro_tracker = DistroSecurityTracker(fixture_bundle.get("distro_trackers") if fixture_bundle else None)
    osv = OSVClient(config, cache, kev, distro_tracker, fixture_bundle)
    planner = PlannerEngine(config)
    executor = PlanExecutor(config)
    verifier = RemediationVerifier(config)
    json_reporter = JSONReporter()
    md_reporter = MarkdownReporter()
    return cache, kev, vulncheck, epss, nvd, msrc, ubuntu_sec, enricher, distro_tracker, osv, planner, executor, verifier, json_reporter, md_reporter


def run_inventory(config: Dict[str, Any], target_env: str = "all", fixture_bundle: Optional[Dict[str, Any]] = None) -> List[InventoryItem]:
    items: List[InventoryItem] = []
    platform_info = PlatformDetector.detect()
    host_os = platform_info["host_os"]
    mount_type = platform_info["mount_type"]

    logger.info(f"Entorno detectado: {platform_info['description']}")

    # 1. Si el anfitrión es macOS (Apple Mac)
    if host_os == HostOSType.MACOS.value and target_env in ["all", "macos", "host"]:
        mac_adapt = MacOSInventoryAdapter(config, fixture_bundle.get("macos") if fixture_bundle else None)
        if mac_adapt.is_available():
            items.extend(mac_adapt.collect())

    # 2. Si el anfitrión es Windows (Nativo o vía WSL)
    if host_os == HostOSType.WINDOWS.value and target_env in ["all", "windows", "host"]:
        win_adapt = WindowsInventoryAdapter(config, fixture_bundle.get("windows") if fixture_bundle else None)
        if win_adapt.is_available():
            items.extend(win_adapt.collect())

    # 3. Si OpenClaw está montado en WSL o es Linux
    if (mount_type == RuntimeMountType.WSL.value or host_os == HostOSType.LINUX.value) and target_env in ["all", "wsl", "linux"]:
        wsl_adapt = WSLInventoryAdapter(config, fixture_bundle.get("wsl") if fixture_bundle else None)
        if wsl_adapt.is_available():
            items.extend(wsl_adapt.collect())

    # Gestores adicionales y proyectos
    add_adapt = AdditionalManagersAdapter(config, fixture_bundle.get("additional") if fixture_bundle else None)
    items.extend(add_adapt.collect())

    proj_adapt = RegisteredProjectsAdapter(config, fixture_bundle.get("projects") if fixture_bundle else None)
    items.extend(proj_adapt.collect())

    return items


def calculate_coverage(items: List[InventoryItem], sources_status: Dict[str, bool]) -> CoverageSummary:
    total = len(items)
    manageable = sum(1 for i in items if i.is_supported and i.update_mechanism_available and not i.requires_manual_intervention)
    unsupported = sum(1 for i in items if not i.is_supported or i.requires_manual_intervention)
    partial = total - (manageable + unsupported)

    successful = [src for src, ok in sources_status.items() if ok]
    failed = [src for src, ok in sources_status.items() if not ok]

    return CoverageSummary(
        total_components_detected=total,
        manageable_components=manageable,
        partially_manageable=partial,
        unsupported_or_manual=unsupported,
        query_sources_successful=successful,
        query_sources_failed=failed,
        is_coverage_complete=len(failed) == 0
    )


def cmd_audit(args, config: Dict[str, Any], fixture_bundle: Optional[Dict[str, Any]] = None):
    print(f"[*] Iniciando auditoría en modo de solo lectura (Entorno: {args.environment})...")
    (
        cache, kev, vulncheck, epss, nvd, msrc, ubuntu_sec, enricher,
        distro_tracker, osv, planner, executor, verifier, json_rep, md_rep
    ) = get_components(config, fixture_bundle)
    kev.load()
    vulncheck.load()

    items = run_inventory(config, args.environment, fixture_bundle)
    vuln_map: Dict[str, List[Vulnerability]] = {}

    for it in items:
        vulns = osv.query_vulnerabilities(it)
        if not vulns and kev.last_sync_success:
            vulns = kev.find_vulnerabilities_for_item(it)
        if vulns:
            vulns = enricher.enrich_vulnerabilities(vulns, it)
            vuln_map[it.id] = vulns

    sources_status = {
        "OSV.dev": not osv.last_query_failed,
        "CISA KEV": kev.last_sync_success,
        "VulnCheck KEV": vulncheck.last_sync_success,
        "FIRST EPSS": not epss.last_query_failed,
        "NIST NVD": not nvd.last_query_failed,
        "MSRC": not msrc.last_query_failed,
        "Ubuntu Security": not ubuntu_sec.last_query_failed,
    }

    coverage = calculate_coverage(items, sources_status)
    md_output = md_rep.generate_report(args.environment, "audit", coverage, items, vuln_map)
    json_rep.generate_report(args.environment, "audit", coverage, items, vuln_map)

    print(md_output)
    return 0


def cmd_plan(args, config: Dict[str, Any], fixture_bundle: Optional[Dict[str, Any]] = None):
    print(f"[*] Construyendo plan de mantenimiento y remediación para {args.environment}...")
    (
        cache, kev, vulncheck, epss, nvd, msrc, ubuntu_sec, enricher,
        distro_tracker, osv, planner, executor, verifier, json_rep, md_rep
    ) = get_components(config, fixture_bundle)
    kev.load()
    vulncheck.load()

    items = run_inventory(config, args.environment, fixture_bundle)
    vuln_map: Dict[str, List[Vulnerability]] = {}
    for it in items:
        vulns = osv.query_vulnerabilities(it)
        if not vulns and kev.last_sync_success:
            vulns = kev.find_vulnerabilities_for_item(it)
        if vulns:
            vulns = enricher.enrich_vulnerabilities(vulns, it)
            vuln_map[it.id] = vulns

    plan = planner.create_plan(items, vuln_map, args.environment)

    # Persistir plan pendiente para aprobación
    PENDING_PLANS_DIR.mkdir(parents=True, exist_ok=True)
    plan_file = PENDING_PLANS_DIR / f"{plan.plan_id}.json"
    with open(plan_file, "w", encoding="utf-8") as f:
        json.dump(plan.to_dict(), f, indent=2, ensure_ascii=False)

    sources_status = {
        "OSV.dev": not osv.last_query_failed,
        "CISA KEV": kev.last_sync_success,
        "VulnCheck KEV": vulncheck.last_sync_success,
        "FIRST EPSS": not epss.last_query_failed,
        "NIST NVD": not nvd.last_query_failed,
        "MSRC": not msrc.last_query_failed,
        "Ubuntu Security": not ubuntu_sec.last_query_failed,
    }

    coverage = calculate_coverage(items, sources_status)
    md_output = md_rep.generate_report(args.environment, config.get("mode", "ask"), coverage, items, vuln_map, plan)
    print(md_output)

    print("\n--------------------------------------------------------------------------------")
    print(f"[*] PLAN GENERADO:")
    print(f"   ID del Plan:   {plan.plan_id}")
    print(f"   Huella SHA256: {plan.plan_hash}")
    print(f"   Caduca:        {plan.expires_at}")
    print(f"   Para aplicar:  python -m security_maintainer.cli apply --plan-id {plan.plan_id} --plan-hash {plan.plan_hash}")
    print("--------------------------------------------------------------------------------\n")
    return 0


def cmd_apply(args, config: Dict[str, Any], fixture_bundle: Optional[Dict[str, Any]] = None):
    plan_id = args.plan_id
    plan_hash = args.plan_hash

    if not plan_id or not plan_hash:
        print("[!] Error: Se requieren --plan-id y --plan-hash para ejecutar una remediación autorizada.")
        return 1

    plan_file = PENDING_PLANS_DIR / f"{plan_id}.json"
    if not plan_file.exists():
        print(f"[!] Error: No se encontró el plan con ID '{plan_id}'.")
        return 1

    with open(plan_file, "r", encoding="utf-8") as f:
        plan_dict = json.load(f)

    # Reconstruir ActionPlan
    actions = []
    from .models import PlanAction, FindingCategory, ManagerType, EnvironmentType
    for a in plan_dict.get("actions", []):
        actions.append(
            PlanAction(
                action_id=a["action_id"],
                environment=EnvironmentType(a["environment"]),
                target=a["target"],
                product_name=a["product_name"],
                product_id=a["product_id"],
                manager=ManagerType(a["manager"]),
                installed_version=a["installed_version"],
                target_version=a["target_version"],
                category=FindingCategory(a["category"]),
                related_vulnerabilities=a["related_vulnerabilities"],
                exact_command=a["exact_command"],
                required_privileges=a["required_privileges"],
                expected_reboot=a["expected_reboot"],
                verification_method=a["verification_method"],
                rollback_available=a["rollback_available"],
                rollback_limitations=a["rollback_limitations"],
                status=ActionStatus(a["status"])
            )
        )

    plan = ActionPlan(
        plan_id=plan_dict["plan_id"],
        created_at=plan_dict["created_at"],
        expires_at=plan_dict["expires_at"],
        environment=plan_dict["environment"],
        mode=plan_dict["mode"],
        plan_hash=plan_dict["plan_hash"],
        actions=actions,
        is_approved=True
    )

    # 1. Validar aprobación criptográfica y caducidad
    is_valid, err_msg = ApprovalManager.verify_approval(plan, plan_hash)
    if not is_valid:
        print(f"[!] RECHAZADO: {err_msg}")
        return 2

    print(f"[*] Aprobación verificada para plan {plan_id} (Huella: {plan_hash[:12]}...).")
    cache, kev, vulncheck, epss, nvd, msrc, ubuntu_sec, enricher, distro_tracker, osv, planner, executor, verifier, json_rep, md_rep = get_components(config, fixture_bundle)

    # 2. Ejecutar acciones
    exec_results = executor.execute_plan(plan)

    # 3. Verificar resultados post-ejecución
    verified_results = []
    action_map = {a.action_id: a for a in plan.actions}
    for res in exec_results:
        act = action_map.get(res.action_id)
        if act:
            verified = verifier.verify(act, res)
            verified_results.append(verified)

    # 4. Generar informe post-remediación
    items = run_inventory(config, plan.environment, fixture_bundle)
    sources_status = {
        "OSV.dev": not osv.last_query_failed,
        "CISA KEV": kev.last_sync_success,
        "VulnCheck KEV": vulncheck.last_sync_success,
        "FIRST EPSS": not epss.last_query_failed,
        "NIST NVD": not nvd.last_query_failed,
        "MSRC": not msrc.last_query_failed,
        "Ubuntu Security": not ubuntu_sec.last_query_failed,
    }
    coverage = calculate_coverage(items, sources_status)
    md_output = md_rep.generate_report(plan.environment, "apply", coverage, items, {}, plan, verified_results)
    json_rep.generate_report(plan.environment, "apply", coverage, items, {}, plan, verified_results)

    print(md_output)

    # Limpiar plan ejecutado
    try:
        plan_file.unlink(missing_ok=True)
    except Exception:
        pass

    return 0


def cmd_verify(args, config: Dict[str, Any], fixture_bundle: Optional[Dict[str, Any]] = None):
    print(f"[*] Verificando estado post-remediación...")
    return cmd_audit(args, config, fixture_bundle)


def cmd_report(args, config: Dict[str, Any]):
    rep_dir = Path.home() / ".security-maintainer" / "reports"
    if not rep_dir.exists():
        print("No hay informes generados todavía.")
        return 0
    md_files = sorted(rep_dir.glob("report_*.md"), reverse=True)
    if not md_files:
        print("No se encontraron informes recientes.")
        return 0
    with open(md_files[0], "r", encoding="utf-8") as f:
        print(f.read())
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="security-maintainer",
        description="Mantenimiento y remediación de vulnerabilidades para Windows y distribuciones WSL."
    )
    parser.add_argument("--config", help="Ruta al archivo de configuración personalizado.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Audit
    p_audit = subparsers.add_parser("audit", help="Audita software y vulnerabilidades sin realizar cambios.")
    p_audit.add_argument("--environment", choices=["all", "windows", "wsl", "macos", "linux", "host"], default="all")
    p_audit.add_argument("--all", action="store_true")

    # Plan
    p_plan = subparsers.add_parser("plan", help="Genera un plan con huella SHA-256 en modo 'ask'.")
    p_plan.add_argument("--environment", choices=["all", "windows", "wsl", "macos", "linux", "host"], default="all")

    # Apply
    p_apply = subparsers.add_parser("apply", help="Aplica un plan previamente aprobado mediante su huella.")
    p_apply.add_argument("--plan-id", required=True)
    p_apply.add_argument("--plan-hash", required=True)

    # Verify
    p_verify = subparsers.add_parser("verify", help="Comprueba el estado del sistema y verifica versiones efectivas.")
    p_verify.add_argument("--environment", choices=["all", "windows", "wsl", "macos", "linux", "host"], default="all")

    # Report
    p_rep = subparsers.add_parser("report", help="Muestra el último informe generado.")
    p_rep.add_argument("--critical-only", action="store_true")
    p_rep.add_argument("--unsupported-only", action="store_true")

    args = parser.parse_args(argv)
    cfg_mgr = ConfigManager(args.config)
    config = cfg_mgr.config

    if args.command == "audit":
        return cmd_audit(args, config)
    elif args.command == "plan":
        return cmd_plan(args, config)
    elif args.command == "apply":
        return cmd_apply(args, config)
    elif args.command == "verify":
        return cmd_verify(args, config)
    elif args.command == "report":
        return cmd_report(args, config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
