"""Self-security: scan KEPRYX's own dependencies for CVEs.

Sources:
  - Python deps: pip freeze inside each container → OSV.dev API
  - Container images: get image digest → Trivy DB or Docker Scout (optional)
  - System packages: dpkg -l → OSV / NVD

OSV.dev is the gold standard for OSS vulnerability data — aggregates GHSA,
PyPI Advisory DB, RustSec, npm, etc. Free, no API key, structured JSON.
"""

import logging
import re
from dataclasses import dataclass
from importlib import metadata

import httpx
from packaging.version import InvalidVersion, Version
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings

logger = logging.getLogger(__name__)

PYPI_API = "https://pypi.org/pypi"


@dataclass
class DepRecord:
    component: str
    package_type: str  # pip | container | system
    name: str
    version: str
    purl: str | None = None


@dataclass
class Finding:
    cve_id: str
    cvss: float | None
    description: str
    fixed_version: str | None
    severity: str
    aliases: list[str]


class SelfSecurityScanner:
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=30.0,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=50),
        )

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def scan_python_deps(
        self, requirements_text: str, component: str = "api"
    ) -> list[DepRecord]:
        """Parse exact pins only; ranges are not evidence of installed versions."""
        deps = []
        for line in requirements_text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([a-zA-Z0-9_\-\.\[\]]+)==([^\s;]+)", line)
            if not m:
                continue
            name = m.group(1).split("[")[0].lower()
            version = m.group(2)
            deps.append(
                DepRecord(
                    component=component,
                    package_type="pip",
                    name=name,
                    version=version,
                    purl=f"pkg:pypi/{name}@{version}",
                )
            )
        return deps

    async def scan_installed_python_deps(self, component: str = "api") -> list[DepRecord]:
        """Inventory the complete resolved environment, including transitive deps."""
        resolved: dict[str, DepRecord] = {}
        for distribution in metadata.distributions():
            name = (distribution.metadata.get("Name") or "").strip().lower()
            version = distribution.version
            if not name or not version:
                continue
            normalized = name.replace("_", "-")
            resolved[normalized] = DepRecord(
                component=component,
                package_type="pip",
                name=normalized,
                version=version,
                purl=f"pkg:pypi/{normalized}@{version}",
            )
        return sorted(resolved.values(), key=lambda dep: dep.name)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _osv_query(self, dep: DepRecord) -> dict:
        ecosystem = {"pip": "PyPI", "container": "Debian", "system": "Debian"}.get(
            dep.package_type, "PyPI"
        )
        payload = {
            "package": {"name": dep.name, "ecosystem": ecosystem},
            "version": dep.version,
        }
        r = await self.client.post(settings.OSV_BASE_URL, json=payload)
        r.raise_for_status()
        return r.json()

    async def find_vulns(self, dep: DepRecord) -> list[Finding]:
        data = await self._osv_query(dep)
        if not data:
            return []

        findings = []
        for vuln in data.get("vulns", []):
            # Extract CVE ID from aliases, fall back to OSV id
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))

            # CVSS from severity field (v3 vector or score)
            cvss = None
            for sev in vuln.get("severity", []):
                if sev.get("type") in ("CVSS_V3", "CVSS_V31"):
                    score_str = sev.get("score", "")
                    # Never infer 3.1 from a CVSS:3.1 vector as the base score.
                    if re.fullmatch(r"(?:10(?:\.0)?|[0-9](?:\.\d+)?)", score_str):
                        cvss = float(score_str)
                        break

            # Fixed version from affected.ranges
            fixed_candidates = []
            for affected in vuln.get("affected", []):
                if affected.get("package", {}).get("name", "").lower() != dep.name.lower():
                    continue
                for r in affected.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            fixed_candidates.append(ev["fixed"])

            fixed = None
            try:
                current_version = Version(dep.version)
            except InvalidVersion:
                current_version = None
            if current_version is not None:
                valid_fixes = []
                for value in fixed_candidates:
                    try:
                        candidate = Version(value)
                    except InvalidVersion:
                        continue
                    if candidate > current_version:
                        valid_fixes.append(candidate)
                if valid_fixes:
                    fixed = str(min(valid_fixes))

            sev_label = "unknown"
            if cvss is not None:
                if cvss >= 9.0:
                    sev_label = "critical"
                elif cvss >= 7.0:
                    sev_label = "high"
                elif cvss >= 4.0:
                    sev_label = "medium"
                else:
                    sev_label = "low"
            else:
                source_label = str(vuln.get("database_specific", {}).get("severity", "")).lower()
                if source_label in {"critical", "high", "medium", "moderate", "low"}:
                    sev_label = "medium" if source_label == "moderate" else source_label

            findings.append(
                Finding(
                    cve_id=cve_id,
                    cvss=cvss,
                    description=(vuln.get("summary") or vuln.get("details") or "")[:1000],
                    fixed_version=fixed,
                    severity=sev_label,
                    aliases=aliases,
                )
            )
        return findings

    async def get_latest_pypi_version(self, name: str) -> str | None:
        try:
            r = await self.client.get(f"{PYPI_API}/{name}/json")
            if r.status_code != 200:
                return None
            return r.json().get("info", {}).get("version")
        except httpx.HTTPError:
            return None
