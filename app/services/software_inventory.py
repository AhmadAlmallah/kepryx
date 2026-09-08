"""Secure software inventory parsing and advisory lookup.

The importer accepts deliberately boring, auditable CSV and XLSX files.  XLSX
is parsed as XML from a bounded ZIP archive; formulas, macros, external links,
and arbitrary workbook parts are never executed.
"""

import csv
import hashlib
import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import defusedxml.ElementTree as DefusedET
import httpx
from packaging.version import InvalidVersion, Version

from app.core.config import settings
from app.services.cve_enrichment import CVEEnricher

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_ROWS = 10_000
MAX_XLSX_ENTRIES = 1_000
MAX_XLSX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_FIELD_LENGTH = 512

_HEADER_ALIASES = {
    "solution": "solution",
    "application": "solution",
    "product": "solution",
    "parent": "solution",
    "parent_solution": "solution",
    "ecosystem": "ecosystem",
    "package_type": "ecosystem",
    "package_manager": "ecosystem",
    "type": "ecosystem",
    "package": "package",
    "component": "package",
    "library": "package",
    "name": "package",
    "version": "version",
    "installed_version": "version",
    "asset": "asset",
    "asset_name": "asset",
    "hostname": "asset",
    "environment": "environment",
    "purl": "purl",
    "cpe": "cpe",
    "component_type": "component_type",
    "direct": "direct",
    "source": "source",
}

_ECOSYSTEM_ALIASES = {
    "node": "npm",
    "nodejs": "npm",
    "npmjs": "npm",
    "python": "pypi",
    "pip": "pypi",
    "golang": "go",
    "go.mod": "go",
    "cargo": "crates.io",
    "rust": "crates.io",
    "dotnet": "nuget",
    "csharp": "nuget",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "sql server": "mssql",
    "sqlserver": "mssql",
}

_OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "nuget": "NuGet",
    "go": "Go",
    "crates.io": "crates.io",
    "packagist": "Packagist",
    "rubygems": "RubyGems",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
}


@dataclass(frozen=True)
class SoftwareRecord:
    solution: str
    ecosystem: str
    package: str
    version: str
    asset: str | None = None
    environment: str = "production"
    purl: str | None = None
    cpe: str | None = None
    component_type: str = "library"
    direct: bool = True
    source: str = "manual_import"

    @property
    def normalized_package(self) -> str:
        return normalize_package_name(self.package, self.ecosystem)

    @property
    def identity(self) -> str:
        return "|".join(
            [
                self.solution.lower(),
                self.ecosystem,
                self.normalized_package,
                self.version,
                self.asset or "",
            ]
        )


@dataclass
class ParseResult:
    records: list[SoftwareRecord] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    filename: str = ""
    sha256: str = ""


@dataclass
class Advisory:
    advisory_id: str
    cve_id: str | None
    source: str
    cvss: float | None
    severity: str
    summary: str
    fixed_version: str | None
    aliases: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


@dataclass
class ComponentAssessment:
    advisories: list[Advisory]
    latest_version: str | None
    update_available: bool
    status: str
    provider_errors: dict[str, str] = field(default_factory=dict)


def normalize_header(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", str(value).strip().lower()).strip("_")
    return _HEADER_ALIASES.get(value, value)


def normalize_package_name(name: str, ecosystem: str) -> str:
    value = str(name).strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", value).lower()
    if ecosystem == "npm":
        return value.lower()
    return re.sub(r"\s+", " ", value).strip().lower()


def normalize_ecosystem(value: str) -> str:
    value = str(value).strip().lower()
    return _ECOSYSTEM_ALIASES.get(value, value or "generic")


def _safe_text(
    value: object, field_name: str, row_number: int, max_length: int = MAX_FIELD_LENGTH
) -> str:
    result = str(value or "").strip()
    if len(result) > max_length:
        raise ValueError(f"{field_name} exceeds {max_length} characters")
    if any(ord(char) < 32 and char not in "\t" for char in result):
        raise ValueError(f"{field_name} contains a control character")
    if result.startswith(("=", "+", "-", "@")):
        # Prevent imported spreadsheet values from becoming formulas when later
        # exported to CSV.  A leading v is handled separately for versions.
        raise ValueError(f"row {row_number}: unsafe spreadsheet value in {field_name}")
    return result


def _as_bool(value: object) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return True
    if normalized in {"1", "true", "yes", "y", "direct"}:
        return True
    if normalized in {"0", "false", "no", "n", "transitive", "indirect"}:
        return False
    raise ValueError("direct must be true/false")


def _make_record(row: dict, row_number: int) -> SoftwareRecord:
    solution = _safe_text(row.get("solution"), "solution", row_number, 255)
    ecosystem = normalize_ecosystem(_safe_text(row.get("ecosystem"), "ecosystem", row_number, 64))
    package = _safe_text(row.get("package"), "package", row_number, 255)
    version = _safe_text(row.get("version"), "version", row_number, 128).lstrip("vV").strip()
    if not solution or not package or not version:
        raise ValueError("solution, ecosystem, package, and version are required")
    component_type = _safe_text(
        row.get("component_type") or "", "component_type", row_number, 32
    ).lower()
    if not component_type:
        component_type = (
            "application" if ecosystem in {"generic", "postgresql", "mssql"} else "library"
        )
    asset = _safe_text(row.get("asset") or "", "asset", row_number, 255) or None
    environment = _safe_text(row.get("environment") or "production", "environment", row_number, 64)
    purl = _safe_text(row.get("purl") or "", "purl", row_number, 512) or None
    cpe = _safe_text(row.get("cpe") or "", "cpe", row_number, 512) or None
    source = _safe_text(row.get("source") or "manual_import", "source", row_number, 64)
    return SoftwareRecord(
        solution=solution,
        ecosystem=ecosystem,
        package=package,
        version=version,
        asset=asset,
        environment=environment,
        purl=purl or build_purl(ecosystem, normalize_package_name(package, ecosystem), version),
        cpe=cpe,
        component_type=component_type,
        direct=_as_bool(row.get("direct")),
        source=source,
    )


def build_purl(ecosystem: str, package: str, version: str) -> str | None:
    namespace = {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "nuget": "nuget",
        "go": "golang",
    }.get(ecosystem)
    if not namespace:
        return None
    if ecosystem == "maven" and ":" in package:
        group, name = package.split(":", 1)
        return f"pkg:maven/{quote(group, safe='.')}/{quote(name, safe='')}@{quote(version, safe='.-_')}"
    return f"pkg:{namespace}/{quote(package, safe='@/-._')}@{quote(version, safe='.-_')}"


def _normalize_row(raw: dict) -> dict:
    normalized = {}
    for key, value in raw.items():
        canonical = normalize_header(key)
        if canonical and canonical not in normalized:
            normalized[canonical] = value
    return normalized


def _parse_rows(rows: list[dict], filename: str, payload: bytes) -> ParseResult:
    if not rows:
        return ParseResult(
            errors=[{"row": 1, "error": "file contains no data rows"}],
            filename=filename,
            sha256=hashlib.sha256(payload).hexdigest(),
        )
    headers = set(_normalize_row(rows[0]))
    missing = sorted({"solution", "ecosystem", "package", "version"} - headers)
    if missing:
        return ParseResult(
            errors=[{"row": 1, "error": f"missing required columns: {', '.join(missing)}"}],
            filename=filename,
            sha256=hashlib.sha256(payload).hexdigest(),
        )
    result = ParseResult(filename=filename, sha256=hashlib.sha256(payload).hexdigest())
    for row_number, raw in enumerate(rows, start=2):
        if row_number > MAX_ROWS + 1:
            result.errors.append(
                {"row": row_number, "error": f"maximum of {MAX_ROWS} rows exceeded"}
            )
            break
        try:
            result.records.append(_make_record(_normalize_row(raw), row_number))
        except ValueError as exc:
            result.errors.append({"row": row_number, "error": str(exc)})
    return result


def _xlsx_cell_value(cell: Any, shared_strings: list[str]) -> str:
    namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    if cell.get("f") is not None:
        raise ValueError("formulas are not accepted; export cached values as CSV")
    cell_type = cell.get("t")
    value = cell.find(f"{namespace}v")
    if cell_type == "inlineStr":
        return "".join(item.text or "" for item in cell.findall(f"{namespace}is/{namespace}t"))
    if value is None:
        return ""
    raw = value.text or ""
    if cell_type == "s":
        index = int(raw)
        if index >= len(shared_strings):
            raise ValueError("shared string index is invalid")
        return shared_strings[index]
    if cell_type == "b":
        return "true" if raw == "1" else "false"
    return raw


def _parse_xlsx_rows(payload: bytes) -> list[dict]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = archive.infolist()
        if len(members) > MAX_XLSX_ENTRIES:
            raise ValueError("XLSX contains too many archive entries")
        if sum(item.file_size for item in members) > MAX_XLSX_UNCOMPRESSED_BYTES:
            raise ValueError("XLSX uncompressed size exceeds the safety limit")
        names = {item.filename for item in members}
        if "xl/worksheets/sheet1.xml" not in names:
            raise ValueError("XLSX must contain the first worksheet")
        shared_strings: list[str] = []
        namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
        if "xl/sharedStrings.xml" in names:
            root = DefusedET.fromstring(archive.read("xl/sharedStrings.xml"))
            for item in root.findall(f"{namespace}si"):
                shared_strings.append(
                    "".join(text.text or "" for text in item.findall(f".//{namespace}t"))
                )
        sheet = DefusedET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        rows = sheet.findall(f".//{namespace}sheetData/{namespace}row")
        if not rows:
            return []
        table: list[list[str]] = []
        for row in rows[: MAX_ROWS + 1]:
            cells: dict[int, str] = {}
            for cell in row.findall(f"{namespace}c"):
                ref = cell.get("r", "A1")
                letters = re.match(r"([A-Z]+)", ref.upper())
                if not letters:
                    continue
                index = 0
                for char in letters.group(1):
                    index = index * 26 + ord(char) - 64
                cells[index - 1] = _xlsx_cell_value(cell, shared_strings)
            width = max(cells.keys(), default=-1) + 1
            table.append([cells.get(index, "") for index in range(width)])
        headers = table[0]
        return [dict(zip(headers, values, strict=False)) for values in table[1:]]


def parse_software_inventory(payload: bytes, filename: str) -> ParseResult:
    """Parse a bounded CSV/XLSX upload without executing workbook content."""
    if len(payload) > MAX_UPLOAD_BYTES:
        return ParseResult(
            errors=[{"row": 0, "error": f"file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB"}],
            filename=filename,
        )
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        if suffix == "csv":
            text = payload.decode("utf-8-sig")
            rows = list(csv.DictReader(io.StringIO(text, newline="")))
        elif suffix == "xlsx":
            rows = _parse_xlsx_rows(payload)
        else:
            return ParseResult(
                errors=[{"row": 0, "error": "only .csv and .xlsx files are accepted"}],
                filename=filename,
            )
        return _parse_rows(rows, filename, payload)
    except (UnicodeDecodeError, ValueError, zipfile.BadZipFile, DefusedET.ParseError) as exc:
        return ParseResult(
            errors=[{"row": 0, "error": f"invalid inventory file: {exc}"}],
            filename=filename,
            sha256=hashlib.sha256(payload).hexdigest(),
        )


def _numeric_cvss(value: object) -> float | None:
    try:
        score = float(str(value))
    except (TypeError, ValueError):
        return None
    return score if 0 <= score <= 10 else None


def _severity(cvss: float | None, raw: object = "") -> str:
    if cvss is not None:
        if cvss >= 9:
            return "critical"
        if cvss >= 7:
            return "high"
        if cvss >= 4:
            return "medium"
        return "low"
    value = str(raw or "").lower()
    return value if value in {"critical", "high", "medium", "moderate", "low"} else "unknown"


def _fixed_version(vuln: dict, current: str, package_name: str, ecosystem: str) -> str | None:
    try:
        current_version = Version(current)
    except InvalidVersion:
        current_version = None
    candidates: list[Version] = []
    for affected in vuln.get("affected", []):
        affected_name = affected.get("package", {}).get("name", "")
        if normalize_package_name(affected_name, ecosystem) != normalize_package_name(
            package_name, ecosystem
        ):
            continue
        for range_data in affected.get("ranges", []):
            for event in range_data.get("events", []):
                value = event.get("fixed")
                if value is None:
                    continue
                try:
                    candidate = Version(str(value))
                except InvalidVersion:
                    continue
                if current_version is None or candidate > current_version:
                    candidates.append(candidate)
    return str(min(candidates)) if candidates else None


def parse_osv_vulnerabilities(data: dict, record: SoftwareRecord) -> list[Advisory]:
    advisories: list[Advisory] = []
    for vuln in data.get("vulns", []) if isinstance(data, dict) else []:
        aliases = [str(item) for item in vuln.get("aliases", [])]
        cve_id = next((item for item in aliases if item.startswith("CVE-")), None)
        database = vuln.get("database_specific") or {}
        cvss = _numeric_cvss(database.get("cvss_score"))
        if cvss is None:
            for severity_data in vuln.get("severity", []):
                cvss = _numeric_cvss(severity_data.get("score"))
                if cvss is not None:
                    break
        advisory_id = cve_id or str(vuln.get("id") or "")
        if not advisory_id:
            continue
        advisories.append(
            Advisory(
                advisory_id=advisory_id,
                cve_id=cve_id,
                source="OSV",
                cvss=cvss,
                severity=_severity(cvss, database.get("severity")),
                summary=str(vuln.get("summary") or vuln.get("details") or "")[:2000],
                fixed_version=_fixed_version(
                    vuln, record.version, record.normalized_package, record.ecosystem
                ),
                aliases=aliases,
                details={"osv_id": vuln.get("id"), "modified": vuln.get("modified")},
            )
        )
    return advisories


def merge_advisories(advisories: list[Advisory]) -> list[Advisory]:
    """Merge duplicate advisories returned by multiple providers.

    OSV and NVD often describe the same issue with different identifiers. CVE
    aliases are the stable correlation key when available; the advisory ID is
    retained for GHSA and ecosystem-only records. The merged record preserves
    the richest score, fixed version, summary, aliases, and source provenance.
    """
    merged: dict[str, Advisory] = {}
    for advisory in advisories:
        key = advisory.cve_id or advisory.advisory_id
        existing = merged.get(key)
        if existing is None:
            merged[key] = advisory
            continue
        sources = set(existing.source.split("+")) | set(advisory.source.split("+"))
        existing.source = "+".join(sorted(sources))
        if advisory.source == "NVD" or existing.cvss is None:
            existing.cvss = advisory.cvss
            existing.severity = advisory.severity
        existing.fixed_version = existing.fixed_version or advisory.fixed_version
        existing.summary = existing.summary or advisory.summary
        existing.aliases = list(dict.fromkeys(existing.aliases + advisory.aliases))
        existing.details = {**existing.details, **advisory.details}
    return list(merged.values())


class SoftwareVulnerabilityService:
    """Query configured advisory/registry endpoints for imported components."""

    def __init__(self, client: httpx.AsyncClient | None = None):
        self.client = client or httpx.AsyncClient(
            timeout=settings.SOFTWARE_HTTP_TIMEOUT_SEC,
            limits=httpx.Limits(max_connections=20),
        )
        self._owns_client = client is None
        self.nvd = CVEEnricher()

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()
        await self.nvd.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _query_osv(self, record: SoftwareRecord) -> list[Advisory]:
        ecosystem = _OSV_ECOSYSTEMS.get(record.ecosystem)
        if not ecosystem:
            return []
        response = await self.client.post(
            settings.OSV_BASE_URL,
            json={
                "package": {"name": record.normalized_package, "ecosystem": ecosystem},
                "version": record.version,
            },
        )
        response.raise_for_status()
        return parse_osv_vulnerabilities(response.json(), record)

    async def _latest(self, record: SoftwareRecord, *, raise_errors: bool = False) -> str | None:
        try:
            if record.ecosystem == "pypi":
                response = await self.client.get(
                    f"{settings.PYPI_BASE_URL.rstrip('/')}/{quote(record.package)}/json"
                )
                response.raise_for_status()
                if response.status_code == 200:
                    return response.json().get("info", {}).get("version")
            if record.ecosystem == "npm":
                response = await self.client.get(
                    f"{settings.NPM_BASE_URL.rstrip('/')}/{quote(record.package, safe='@/')}/latest"
                )
                response.raise_for_status()
                if response.status_code == 200:
                    return response.json().get("version")
        except (httpx.HTTPError, ValueError):
            if raise_errors:
                raise
            logger.warning("Software registry lookup failed for %s", record.package)
        return None

    async def assess(self, record: SoftwareRecord) -> ComponentAssessment:
        advisories: list[Advisory] = []
        provider_errors: dict[str, str] = {}
        try:
            advisories.extend(await self._query_osv(record))
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            provider_errors["OSV"] = type(exc).__name__
            logger.warning("OSV lookup failed for %s: %s", record.package, type(exc).__name__)

        # Query NVD whenever a CPE is present. Previously this ran only when
        # OSV returned no results, which could hide NVD-only advisories.
        if record.cpe:
            try:
                for item in await self.nvd.get_cves_for_cpe(record.cpe, raise_errors=True):
                    cvss = _numeric_cvss(item.get("cvss_v3"))
                    advisory_id = str(item.get("id") or "")
                    if not advisory_id:
                        continue
                    advisories.append(
                        Advisory(
                            advisory_id=advisory_id,
                            cve_id=advisory_id if advisory_id.startswith("CVE-") else None,
                            source="NVD",
                            cvss=cvss,
                            severity=_severity(cvss),
                            summary=str(item.get("description") or "")[:2000],
                            fixed_version=None,
                            details={"matched_cpe": record.cpe},
                        )
                    )
            except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
                provider_errors["NVD"] = type(exc).__name__
                logger.warning("NVD lookup failed for %s: %s", record.package, type(exc).__name__)

        advisories = merge_advisories(advisories)
        try:
            latest = await self._latest(record, raise_errors=True)
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            provider_errors["registry"] = type(exc).__name__
            logger.warning("Registry lookup failed for %s: %s", record.package, type(exc).__name__)
            latest = None
        update_available = False
        if latest:
            try:
                update_available = Version(latest) > Version(record.version)
            except InvalidVersion:
                update_available = latest != record.version
        status = (
            "vulnerable"
            if advisories
            else "outdated"
            if update_available
            else "current"
            if latest
            else "unknown"
        )
        return ComponentAssessment(advisories, latest, update_available, status, provider_errors)
