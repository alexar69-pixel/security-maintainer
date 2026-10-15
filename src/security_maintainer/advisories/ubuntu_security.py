"""
Cliente para la API de Seguridad de Canonical / Ubuntu Security Tracker.
Permite vincular paquetes de Ubuntu con avisos oficiales USN (Ubuntu Security Notices) y verificar parches oficiales.
"""

from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from .cache import AdvisoryCache

logger = logging.getLogger(__name__)

DEFAULT_UBUNTU_API_URL = "https://ubuntu.com/security/cves.json"


class UbuntuSecurityClient:
    """Consulta la API oficial de Canonical / Ubuntu Security Notices (USN)."""

    def __init__(self, config: Dict[str, Any], cache: AdvisoryCache, fixture_data: Optional[Dict[str, Any]] = None):
        self.config = config.get("advisories", {}).get("ubuntu_security", {})
        self.cache = cache
        self.fixture_data = fixture_data
        self.base_url = self.config.get("url", DEFAULT_UBUNTU_API_URL)
        self.ttl_hours = self.config.get("cache_ttl_hours", 48)
        self.last_query_failed = False

    def get_package_advisories(self, package_name: str, release: str = "noble") -> List[Dict[str, Any]]:
        """Recupera los avisos USN y CVEs asociados a un paquete en una release de Ubuntu."""
        if not package_name:
            return []

        # 1. Modo fixtures
        if self.fixture_data and package_name in self.fixture_data:
            return self.fixture_data[package_name]

        # 2. Comprobar caché local
        cache_key = f"{package_name}_{release}"
        cached, is_valid, _ = self.cache.get("ubuntu_security", cache_key, ttl_hours=self.ttl_hours)
        if cached and is_valid:
            return cached

        # 3. Consulta HTTP remota
        url = f"{self.base_url}?package={package_name}&limit=5"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "OpenClaw-SecurityMaintainer/1.0 (+https://openclaw.dev)"}
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            cves = data.get("cves", [])
            results = []
            for item in cves:
                cve_id = item.get("id")
                usn = item.get("notices", [{}])[0].get("id") if item.get("notices") else None
                status = "unknown"
                for p in item.get("packages", []):
                    if p.get("name") == package_name:
                        for s in p.get("statuses", []):
                            if s.get("release_codename") == release:
                                status = s.get("status")
                                break
                results.append({
                    "cve_id": cve_id,
                    "usn": usn,
                    "status": status,
                    "description": item.get("description", "")
                })

            self.cache.set("ubuntu_security", cache_key, results)
            return results

        except Exception as e:
            logger.debug(f"Error consultando Ubuntu Security API para {package_name}: {e}")
            self.last_query_failed = True
            return cached if cached else []
