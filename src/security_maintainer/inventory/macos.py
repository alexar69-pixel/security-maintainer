"""
Adaptador de inventario y actualizaciones para macOS (Homebrew, Mac App Store, softwareupdate y /Applications).
"""

from __future__ import annotations
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..models import (
    InventoryItem,
    EnvironmentType,
    ManagerType,
)

logger = logging.getLogger(__name__)


class MacOSInventoryAdapter:
    """Inspecciona y audita software en sistemas anfitriones Apple macOS."""

    def __init__(self, config: Dict[str, Any], fixture_data: Optional[Dict[str, Any]] = None):
        self.config = config.get("macos", {})
        self.fixture_data = fixture_data
        self.excluded = set(self.config.get("excluded_packages", []))

    def is_available(self) -> bool:
        if self.fixture_data is not None:
            return True
        import sys
        return sys.platform == "darwin"

    def collect(self) -> List[InventoryItem]:
        items: List[InventoryItem] = []
        target_name = "macOS Host"

        # 0. Sistema Operativo macOS anfitrión
        items.append(self._collect_os_info(target_name))

        # 1. Auditoría de Homebrew (Fórmulas CLI y Casks GUI)
        brew_items = self._collect_homebrew(target_name)
        items.extend(brew_items)

        # 2. Auditoría de Mac App Store vía 'mas'
        mas_items = self._collect_mas(target_name)
        items.extend(mas_items)

        # 3. Auditoría de actualizaciones oficiales de macOS (softwareupdate)
        apple_updates = self._collect_apple_updates(target_name)
        items.extend(apple_updates)

        # 4. Auditoría de aplicaciones de escritorio en /Applications (Brave, Office, etc.)
        app_items = self._collect_applications_dir(target_name, items)
        items.extend(app_items)

        return items

    def _collect_os_info(self, target_name: str) -> InventoryItem:
        if self.fixture_data and "os_info" in self.fixture_data:
            os_data = self.fixture_data["os_info"]
            caption = os_data.get("caption", "Apple macOS")
            version = os_data.get("version", "macOS")
            build = os_data.get("build_number", "")
        else:
            import platform
            ver, _, _ = platform.mac_ver()
            caption = "Apple macOS"
            version = ver or "macOS"
            build = ""
            try:
                build_proc = subprocess.run(["sw_vers", "-buildVersion"], capture_output=True, text=True, timeout=5)
                if build_proc.returncode == 0:
                    build = build_proc.stdout.strip()
            except Exception:
                pass

        full_version = f"{version} (Build {build})" if build else version
        return InventoryItem(
            environment=EnvironmentType.MACOS,
            target_name=target_name,
            name="Sistema Operativo macOS",
            id="macos-host-os",
            installed_version=full_version,
            manager=ManagerType.APPLE_UPDATE,
            is_supported=True,
            update_mechanism_available=True,
            requires_manual_intervention=False,
            notes="Sistema anfitrión macOS evaluado.",
            extra_metadata={"caption": caption, "version": version, "build": build}
        )

    def _collect_homebrew(self, target_name: str) -> List[InventoryItem]:
        items: List[InventoryItem] = []
        if self.fixture_data and "brew_outdated" in self.fixture_data:
            data = self.fixture_data["brew_outdated"]
        else:
            brew_bin = shutil.which("brew")
            if not brew_bin:
                return items
            try:
                res = subprocess.run([brew_bin, "outdated", "--json=v2"], capture_output=True, text=True, timeout=20)
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout.strip())
                else:
                    return items
            except Exception as e:
                logger.warning(f"Error consultando Homebrew en macOS: {e}")
                return items

        # Fórmulas CLI
        for formula in data.get("formulae", []):
            name = formula.get("name", "")
            if name in self.excluded:
                continue
            curr_ver = formula.get("installed_versions", ["unknown"])[0] if formula.get("installed_versions") else "unknown"
            latest_ver = formula.get("current_version")
            items.append(
                InventoryItem(
                    environment=EnvironmentType.MACOS,
                    target_name=target_name,
                    name=name,
                    id=f"brew:{name}",
                    installed_version=curr_ver,
                    latest_version=latest_ver,
                    manager=ManagerType.HOMEBREW,
                    is_supported=True,
                    update_mechanism_available=True,
                    notes="Paquete CLI gestionado por Homebrew en macOS"
                )
            )

        # Casks GUI (ej. Brave, Chrome, Zoom, VSCode)
        for cask in data.get("casks", []):
            name = cask.get("name", "")
            if name in self.excluded:
                continue
            curr_ver = cask.get("installed_versions", ["unknown"])[0] if cask.get("installed_versions") else "unknown"
            latest_ver = cask.get("current_version")
            items.append(
                InventoryItem(
                    environment=EnvironmentType.MACOS,
                    target_name=target_name,
                    name=name,
                    id=f"brew-cask:{name}",
                    installed_version=curr_ver,
                    latest_version=latest_ver,
                    manager=ManagerType.HOMEBREW,
                    is_supported=True,
                    update_mechanism_available=True,
                    notes="Aplicación GUI de macOS gestionada por Homebrew Cask"
                )
            )

        return items

    def _collect_mas(self, target_name: str) -> List[InventoryItem]:
        items: List[InventoryItem] = []
        if self.fixture_data and "mas_outdated" in self.fixture_data:
            for entry in self.fixture_data["mas_outdated"]:
                items.append(
                    InventoryItem(
                        environment=EnvironmentType.MACOS,
                        target_name=target_name,
                        name=entry.get("name", ""),
                        id=f"mas:{entry.get('id', '')}",
                        installed_version=entry.get("installed_version", "unknown"),
                        latest_version=entry.get("latest_version"),
                        manager=ManagerType.MAS,
                        is_supported=True,
                        update_mechanism_available=True,
                        notes="Aplicación de Mac App Store"
                    )
                )
            return items

        mas_bin = shutil.which("mas")
        if not mas_bin:
            return items

        try:
            res = subprocess.run([mas_bin, "outdated"], capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        app_id = parts[0]
                        app_name = " ".join(parts[1:-2])
                        curr_ver = parts[-2]
                        latest_ver = parts[-1]
                        items.append(
                            InventoryItem(
                                environment=EnvironmentType.MACOS,
                                target_name=target_name,
                                name=app_name,
                                id=f"mas:{app_id}",
                                installed_version=curr_ver,
                                latest_version=latest_ver,
                                manager=ManagerType.MAS,
                                is_supported=True,
                                update_mechanism_available=True,
                                notes="Aplicación de Mac App Store"
                            )
                        )
        except Exception:
            pass
        return items

    def _collect_apple_updates(self, target_name: str) -> List[InventoryItem]:
        items: List[InventoryItem] = []
        if self.fixture_data and "softwareupdate" in self.fixture_data:
            for entry in self.fixture_data["softwareupdate"]:
                items.append(
                    InventoryItem(
                        environment=EnvironmentType.MACOS,
                        target_name=target_name,
                        name=entry.get("name", ""),
                        id=f"apple:{entry.get('id', '')}",
                        installed_version="pending",
                        latest_version="available",
                        manager=ManagerType.APPLE_UPDATE,
                        is_supported=True,
                        update_mechanism_available=True,
                        notes="Actualización oficial del sistema operativo macOS"
                    )
                )
            return items

        if shutil.which("softwareupdate"):
            try:
                res = subprocess.run(["softwareupdate", "-l"], capture_output=True, text=True, timeout=30)
                if "No new software available" not in res.stderr and "No new software available" not in res.stdout:
                    for line in (res.stdout + res.stderr).splitlines():
                        if "*" in line:
                            title = line.replace("*", "").strip()
                            items.append(
                                InventoryItem(
                                    environment=EnvironmentType.MACOS,
                                    target_name=target_name,
                                    name=title,
                                    id=f"apple:{title.split()[0]}",
                                    installed_version="pending",
                                    latest_version="available",
                                    manager=ManagerType.APPLE_UPDATE,
                                    is_supported=True,
                                    update_mechanism_available=True,
                                    notes="Actualización oficial del sistema operativo macOS"
                                )
                            )
            except Exception:
                pass
        return items

    def _collect_applications_dir(self, target_name: str, existing_items: List[InventoryItem]) -> List[InventoryItem]:
        items: List[InventoryItem] = []
        if self.fixture_data and "applications" in self.fixture_data:
            apps_data = self.fixture_data["applications"]
            for a in apps_data:
                name = a.get("name", "")
                if name in self.excluded:
                    continue
                items.append(
                    InventoryItem(
                        environment=EnvironmentType.MACOS,
                        target_name=target_name,
                        name=name,
                        id=a.get("id", f"app:{name.lower()}"),
                        installed_version=a.get("installed_version", "unknown"),
                        manager=ManagerType.MANUAL,
                        is_supported=False,
                        update_mechanism_available=False,
                        requires_manual_intervention=True,
                        notes="Aplicación en /Applications sin gestor automatizado detectado.",
                        extra_metadata={"bundle_id": a.get("bundle_id")}
                    )
                )
            return items

        try:
            import plistlib

            existing_names = {i.name.lower() for i in existing_items}
            existing_ids = {i.id.lower() for i in existing_items}

            search_dirs = [Path("/Applications"), Path.home() / "Applications"]
            for sdir in search_dirs:
                if not sdir.exists():
                    continue
                for app_path in sdir.glob("*.app"):
                    plist_path = app_path / "Contents" / "Info.plist"
                    if not plist_path.exists():
                        continue
                    try:
                        with open(plist_path, "rb") as fp:
                            plist_data = plistlib.load(fp)
                        app_name = (
                            plist_data.get("CFBundleDisplayName")
                            or plist_data.get("CFBundleName")
                            or app_path.stem
                        )
                        bundle_id = plist_data.get("CFBundleIdentifier", app_path.stem)
                        version = (
                            plist_data.get("CFBundleShortVersionString")
                            or plist_data.get("CFBundleVersion")
                            or "unknown"
                        )
                        if app_name in self.excluded or bundle_id in self.excluded:
                            continue
                        if app_name.lower() in existing_names or bundle_id.lower() in existing_ids:
                            continue

                        items.append(
                            InventoryItem(
                                environment=EnvironmentType.MACOS,
                                target_name=target_name,
                                name=app_name,
                                id=bundle_id,
                                installed_version=str(version),
                                manager=ManagerType.MANUAL,
                                is_supported=False,
                                update_mechanism_available=False,
                                requires_manual_intervention=True,
                                notes="Aplicación en /Applications con actualizador autónomo o manual.",
                                extra_metadata={"bundle_id": bundle_id, "bundle_path": str(app_path)}
                            )
                        )
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Error analizando /Applications en macOS: {e}")

        return items
