"""Asset reconciler — merge multi-source inventory, detect shadow IT and gaps.

Priority order (most authoritative first):
  EDR (10) > NAC (9) > AD (8) > CMDB (7) > Vuln scanner (6) > DHCP (5) > Nmap (4)

Logic:
  shadow_assets   = network_scan ∖ (AD ∪ CMDB ∪ EDR)
  unmanaged       = canonical ∖ EDR
  stale           = canonical where last_seen > 30d
  drift           = services changed since last scan
  edr_dropped     = previously in EDR, now missing
"""

import logging
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, Asset

logger = logging.getLogger(__name__)

SOURCE_PRIORITY = {
    "edr_crowdstrike": 10,
    "edr_sentinelone": 10,
    "edr_defender": 10,
    "nac_cisco_ise": 9,
    "nac_aruba": 9,
    "ad_ldap": 8,
    "azure_ad": 8,
    "cmdb_servicenow": 7,
    "cmdb_jira": 7,
    "vuln_nessus": 6,
    "vuln_qualys": 6,
    "vuln_rapid7": 6,
    "dhcp_dns": 5,
    "infoblox": 5,
    "cloud_aws": 8,
    "cloud_azure": 8,
    "cloud_gcp": 8,
    "nmap_scan": 4,
    "manual": 3,
    "asset_api": 7,
}


class Reconciler:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.alerts_generated: list[Alert] = []

    async def reconcile_host(self, source: str, host_data: dict[str, Any]) -> Asset:
        """Upsert an asset reported by a source. Merges by IP+MAC, then hostname."""
        ip = host_data.get("ip")
        mac = host_data.get("mac")
        hostname = host_data.get("name") or host_data.get("hostname")

        existing = None
        ip_value = None
        if ip:
            try:
                ip_value = ip_address(str(ip))
            except ValueError:
                logger.warning("Ignoring invalid IP from %s: %s", source, ip)
        # Match by MAC first (most reliable identifier)
        if mac:
            result = await self.db.execute(select(Asset).where(Asset.mac == mac))
            existing = result.scalar_one_or_none()
        # Fall back to IP
        if not existing and ip_value:
            result = await self.db.execute(select(Asset).where(Asset.ip == ip_value))
            existing = result.scalar_one_or_none()
        # Fall back to hostname
        if not existing and hostname:
            result = await self.db.execute(select(Asset).where(Asset.name == hostname))
            existing = result.scalar_one_or_none()

        if existing:
            return await self._merge_source(existing, source, host_data)
        return await self._create_from_source(source, host_data)

    async def _merge_source(self, asset: Asset, source: str, data: dict) -> Asset:
        """Merge: higher-priority sources overwrite, equal priority enriches."""
        priority = SOURCE_PRIORITY.get(source, 1)
        sources = asset.sources or []

        # Detect drift before merging
        old_services = set(
            s.get("service")
            for svc in ((asset.attrs or {}).get("services") or [])
            for s in [svc]
            if s
        )
        new_services = set(
            s.get("service") for svc in (data.get("services") or []) for s in [svc] if s
        )
        if old_services and new_services and old_services != new_services:
            await self._raise_alert(
                "drift",
                "medium",
                f"Service drift on {asset.name}",
                f"Services changed: added={new_services - old_services}, removed={old_services - new_services}",
                asset_id=asset.id,
            )

        # Update authoritative fields if source is higher priority
        existing_priority = max([SOURCE_PRIORITY.get(s, 0) for s in sources], default=0)
        if priority >= existing_priority:
            for field in (
                "name",
                "os",
                "ip",
                "mac",
                "segment",
                "edr_status",
                "control_coverage",
                "network_exposure",
                "auth_method",
                "criticality",
                "data_classification",
            ):
                if data.get(field):
                    setattr(asset, field, data[field])

        # Always enrich list/dict fields
        if data.get("software_stack"):
            asset.software_stack = list(set((asset.software_stack or []) + data["software_stack"]))
        if data.get("cpe"):
            asset.cpe = list(set((asset.cpe or []) + data["cpe"]))
        if data.get("dependencies"):
            asset.dependencies = list(set((asset.dependencies or []) + data["dependencies"]))

        # Record source
        if source not in sources:
            sources.append(source)
        asset.sources = sources
        asset.last_seen = datetime.now(UTC)
        asset.is_stale = False
        asset.is_shadow = await self._is_shadow(asset.sources)
        asset.attrs = {**(asset.attrs or {}), "services": data.get("services", [])}

        return asset

    async def create_from_source(self, source: str, data: dict) -> Asset:
        return await self._create_from_source(source, data)

    async def _create_from_source(self, source: str, data: dict) -> Asset:
        asset = Asset(
            name=data.get("name") or data.get("hostname") or data.get("ip", "unknown"),
            type=data.get("type", "Unknown"),
            os=data.get("os") or data.get("os_guess"),
            ip=data.get("ip"),
            mac=data.get("mac"),
            segment=data.get("segment", "Unknown"),
            edr_status=data.get("edr_status", "None"),
            control_coverage=data.get("control_coverage", "none"),
            network_exposure=data.get("network_exposure", "internal"),
            auth_method=data.get("auth_method", "password"),
            criticality=data.get("criticality", "medium"),
            data_classification=data.get("data_classification", "Internal"),
            software_stack=data.get("software_stack", []),
            cpe=data.get("cpe", []),
            dependencies=data.get("dependencies", []),
            sources=[source],
        )
        asset.is_shadow = await self._is_shadow([source])
        self.db.add(asset)
        await self.db.flush()

        if asset.is_shadow:
            await self._raise_alert(
                "shadow_it",
                "high",
                f"Shadow IT detected: {asset.name}",
                f"Asset discovered by {source} only, not present in AD/CMDB/EDR. "
                f"IP={asset.ip}, MAC={asset.mac}",
                asset_id=asset.id,
                details={"source": source, "ip": str(asset.ip) if asset.ip else None},
            )
        return asset

    async def _is_shadow(self, sources: list[str]) -> bool:
        """Shadow = only network scan saw it, no authoritative source claims it."""
        authoritative = {
            "ad_ldap",
            "azure_ad",
            "cmdb_servicenow",
            "cmdb_jira",
            "edr_crowdstrike",
            "edr_sentinelone",
            "edr_defender",
            "cloud_aws",
            "cloud_azure",
            "cloud_gcp",
            "asset_api",
        }
        return not any(s in authoritative for s in sources)

    async def detect_stale_assets(self, threshold_days: int = 30) -> int:
        """Flag assets not seen in N days."""
        cutoff = datetime.now(UTC) - timedelta(days=threshold_days)
        result = await self.db.execute(
            select(Asset).where(and_(Asset.last_seen < cutoff, Asset.is_stale.is_(False)))
        )
        stale = result.scalars().all()
        for asset in stale:
            asset.is_stale = True
            await self._raise_alert(
                "stale_asset",
                "low",
                f"Stale asset: {asset.name}",
                f"Last seen {asset.last_seen.isoformat()} — exceeds {threshold_days}d threshold",
                asset_id=asset.id,
            )
        return len(stale)

    async def detect_edr_gaps(self) -> int:
        """Assets without EDR coverage."""
        result = await self.db.execute(
            select(Asset).where(
                or_(Asset.edr_status == "None", Asset.edr_status.is_(None)),
                Asset.type.in_(["Server", "Endpoint", "Workstation", "Database Server"]),
            )
        )
        gaps = result.scalars().all()
        for asset in gaps:
            await self._raise_alert(
                "edr_gap",
                "high",
                f"EDR coverage gap: {asset.name}",
                f"No EDR agent detected on {asset.type} asset",
                asset_id=asset.id,
            )
        return len(gaps)

    async def _raise_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        asset_id=None,
        details: dict | None = None,
    ):
        # Dedup: don't re-fire same alert within 24h
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        result = await self.db.execute(
            select(Alert).where(
                Alert.alert_type == alert_type,
                Alert.asset_id == asset_id,
                Alert.created_at > cutoff,
                Alert.status == "open",
            )
        )
        if result.scalar_one_or_none():
            return

        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            asset_id=asset_id,
            details=details or {},
        )
        self.db.add(alert)
        self.alerts_generated.append(alert)
