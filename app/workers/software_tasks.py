"""Daily software inventory vulnerability refresh."""

import asyncio
import logging
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models import CVE, Alert
from app.models.software import (
    SoftwareComponent,
    SoftwareFinding,
    SoftwareScanRun,
    SoftwareSolution,
)
from app.services.cve_enrichment import CVEEnricher
from app.services.software_inventory import (
    ComponentAssessment,
    SoftwareVulnerabilityService,
)
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.software_tasks.scan_software")
def scan_software(
    solution_id: str | None = None, run_id: str | None = None, mode: str = "scheduled"
):
    return run_async(_scan_software(solution_id=solution_id, run_id=run_id, mode=mode))


async def _scan_software(
    solution_id: str | None = None, run_id: str | None = None, mode: str = "scheduled"
):
    started = datetime.now(UTC)
    async with SessionLocal() as db:
        run = await db.get(SoftwareScanRun, run_id) if run_id else None
        if not run:
            run = SoftwareScanRun(
                solution_id=solution_id,
                mode=mode,
                source="OSV/NVD/registry",
                status="queued",
            )
            db.add(run)
            await db.flush()
        run.status = "running"
        run.started_at = started
        run.error = None
        scan_run_id = str(run.id)
        target_solution_id = solution_id or (str(run.solution_id) if run.solution_id else None)
        query = select(SoftwareComponent)
        if target_solution_id:
            query = query.where(SoftwareComponent.solution_id == target_solution_id)
        result = await db.execute(query.order_by(SoftwareComponent.id))
        components = result.scalars().all()
        if run.solution_id is None and solution_id:
            run.solution_id = UUID(solution_id)
        await db.commit()

    # A package/version is queried once even if it appears on several assets.
    unique_components: dict[str, SoftwareComponent] = {}
    for component in components:
        key = f"{component.ecosystem}|{component.normalized_name}|{component.version}|{component.purl}|{component.cpe}"
        unique_components.setdefault(key, component)

    assessments: dict[str, ComponentAssessment] = {}
    try:
        async with SoftwareVulnerabilityService() as service:
            semaphore = asyncio.Semaphore(settings.SOFTWARE_SCAN_CONCURRENCY)

            async def assess_one(key: str, component: SoftwareComponent):
                async with semaphore:
                    return key, await service.assess(_record_from_component(component))

            results = await asyncio.gather(
                *(assess_one(key, component) for key, component in unique_components.items())
            )
            assessments = dict(results)
    except Exception as exc:
        logger.exception("Software vulnerability scan failed; preserving prior findings")
        async with SessionLocal() as db:
            run = await db.get(SoftwareScanRun, scan_run_id)
            if run:
                run.status = "failed"
                run.error = type(exc).__name__
                run.completed_at = datetime.now(UTC)
            if target_solution_id:
                solution = await db.get(SoftwareSolution, target_solution_id)
                if solution:
                    solution.last_scan_status = "failed"
                    solution.last_scan_error = type(exc).__name__
                    solution.last_scan_at = started
            await db.commit()
        return {"status": "failed", "error": type(exc).__name__, "run_id": scan_run_id}

    cve_ids = {
        advisory.cve_id
        for assessment in assessments.values()
        for advisory in assessment.advisories
        if advisory.cve_id
    }
    feed_provider_status: dict[str, str] = {}
    feed_provider_errors: list[dict[str, str]] = []
    async with CVEEnricher() as enricher:
        try:
            kev_catalog = await enricher.load_kev_catalog(raise_errors=True)
            feed_provider_status["KEV"] = "ok"
        except Exception as exc:
            kev_catalog = {}
            feed_provider_status["KEV"] = "error"
            feed_provider_errors.append({"provider": "KEV", "error": type(exc).__name__})
            logger.warning("KEV enrichment unavailable: %s", type(exc).__name__)
        if cve_ids:
            try:
                epss = await enricher.get_epss_scores(sorted(cve_ids), raise_errors=True)
                feed_provider_status["EPSS"] = "ok"
            except Exception as exc:
                epss = {}
                feed_provider_status["EPSS"] = "error"
                feed_provider_errors.append({"provider": "EPSS", "error": type(exc).__name__})
                logger.warning("EPSS enrichment unavailable: %s", type(exc).__name__)
        else:
            epss = {}
            feed_provider_status["EPSS"] = "not_required"

    async with SessionLocal() as db:
        run = await db.get(SoftwareScanRun, scan_run_id)
        if not run:
            return {"status": "failed", "error": "scan_run_not_found", "run_id": scan_run_id}

        # The provider lookups above run after the first session closes. Reload
        # the component rows into this session before changing their aggregate
        # fields; mutating the detached instances from the first session would
        # persist new findings but silently drop status/count/version updates.
        component_ids = [component.id for component in components]
        if component_ids:
            component_result = await db.execute(
                select(SoftwareComponent).where(SoftwareComponent.id.in_(component_ids))
            )
            components = list(component_result.scalars().all())

        open_alerts_result = await db.execute(
            select(Alert).where(
                Alert.alert_type == "software_vulnerability", Alert.status == "open"
            )
        )
        existing_alert_keys = {
            (alert.details or {}).get("advisory_key")
            for alert in open_alerts_result.scalars().all()
            if (alert.details or {}).get("advisory_key")
        }
        now = datetime.now(UTC)
        total_findings = 0
        changed_findings = 0
        provider_status: dict[str, str] = dict(feed_provider_status)
        provider_errors: list[dict[str, str]] = [*feed_provider_errors]
        solution_ids = {component.solution_id for component in components}

        for component in components:
            key = f"{component.ecosystem}|{component.normalized_name}|{component.version}|{component.purl}|{component.cpe}"
            assessment = assessments[key]
            component.scan_error = None
            for provider, error_name in assessment.provider_errors.items():
                provider_status[provider] = "error"
                provider_errors.append(
                    {
                        "component_id": str(component.id),
                        "provider": provider,
                        "error": error_name,
                    }
                )
                component.scan_error = f"{provider}:{error_name}"[:128]
            if not assessment.provider_errors:
                provider_status.setdefault("OSV", "ok")
                if component.cpe:
                    provider_status.setdefault("NVD", "ok")
                if component.ecosystem in {"npm", "pypi"}:
                    provider_status.setdefault("registry", "ok")
            previous_result = await db.execute(
                select(SoftwareFinding).where(SoftwareFinding.component_id == component.id)
            )
            previous = {item.advisory_id: item for item in previous_result.scalars().all()}
            observed: set[str] = set()
            kev_count = 0
            max_cvss = None
            for advisory in assessment.advisories:
                observed.add(advisory.advisory_id)
                previous_item = previous.get(advisory.advisory_id)
                kev_available = provider_status.get("KEV") != "error"
                is_kev = (
                    bool(advisory.cve_id and advisory.cve_id in kev_catalog)
                    if kev_available
                    else bool(previous_item and previous_item.kev)
                )
                epss_available = provider_status.get("EPSS") != "error"
                epss_data = epss.get(advisory.cve_id or "", {})
                epss_score = (
                    epss_data.get("score")
                    if epss_available
                    else (previous_item.epss if previous_item else None)
                )
                if advisory.cve_id:
                    cve = await db.get(CVE, advisory.cve_id)
                    if not cve:
                        cve = CVE(id=advisory.cve_id)
                        db.add(cve)
                    cve.cvss_v3 = advisory.cvss
                    if epss_available:
                        cve.epss_score = epss_data.get("score")
                        cve.epss_percentile = epss_data.get("percentile")
                    if kev_available:
                        cve.kev = is_kev
                    cve.description = advisory.summary
                was_open = previous_item is not None and previous_item.status == "open"
                old_signature = (
                    (
                        previous_item.kev,
                        previous_item.severity,
                        previous_item.cvss,
                        previous_item.fixed_version,
                        previous_item.epss,
                    )
                    if previous_item
                    else None
                )
                if not previous_item:
                    item = SoftwareFinding(
                        id=uuid4(), component_id=component.id, advisory_id=advisory.advisory_id
                    )
                    db.add(item)
                else:
                    item = previous_item
                item.cve_id = advisory.cve_id
                item.source = advisory.source
                item.cvss = advisory.cvss
                item.epss = epss_score
                item.kev = is_kev
                item.severity = advisory.severity
                item.summary = advisory.summary
                item.fixed_version = advisory.fixed_version
                # Preserve analyst triage across refreshes. A recurring scan
                # must not reopen an acknowledged, accepted, mitigated, or
                # resolved finding merely because the advisory is still present.
                if not previous_item:
                    item.status = "open"
                item.last_seen = now
                item.details = {**advisory.details, "aliases": advisory.aliases}
                new_signature = (item.kev, item.severity, item.cvss, item.fixed_version, item.epss)
                finding_changed = not was_open or old_signature != new_signature
                if finding_changed:
                    changed_findings += 1
                total_findings += 1
                kev_count += int(is_kev)
                max_cvss = (
                    max(max_cvss or 0, advisory.cvss or 0)
                    if advisory.cvss is not None
                    else max_cvss
                )
                advisory_key = f"{component.solution_id}:{component.id}:{advisory.advisory_id}"
                if finding_changed and advisory_key not in existing_alert_keys:
                    severity = (
                        "critical"
                        if is_kev or advisory.severity == "critical"
                        else advisory.severity
                    )
                    db.add(
                        Alert(
                            alert_type="software_vulnerability",
                            severity=severity,
                            title=f"Software vulnerability: {component.package_name} {component.version}",
                            description=(
                                f"{advisory.advisory_id} affects {component.package_name} {component.version} "
                                f"in solution {component.solution_id}. "
                                "Review the advisory and upgrade or mitigate through the normal change process."
                            ),
                            asset_id=component.asset_id,
                            details={
                                "advisory_key": advisory_key,
                                "software_finding_id": str(item.id) if item.id else None,
                                "solution_id": str(component.solution_id),
                                "component_id": str(component.id),
                                "advisory_id": advisory.advisory_id,
                                "cve_id": advisory.cve_id,
                                "source": advisory.source,
                                "kev": is_kev,
                            },
                        )
                    )
                    existing_alert_keys.add(advisory_key)

            stale = delete(SoftwareFinding).where(SoftwareFinding.component_id == component.id)
            if observed:
                stale = stale.where(SoftwareFinding.advisory_id.notin_(observed))
            await db.execute(stale)
            component.latest_version = assessment.latest_version
            component.update_available = assessment.update_available
            component.status = assessment.status
            component.cve_count = len(assessment.advisories)
            component.kev_count = kev_count
            component.max_cvss = max_cvss
            component.last_checked = now

        # Recompute aggregates from persisted state, not from the upload count.
        for current_solution_id in solution_ids:
            solution = await db.get(SoftwareSolution, current_solution_id)
            if not solution:
                continue
            component_result = await db.execute(
                select(SoftwareComponent).where(
                    SoftwareComponent.solution_id == current_solution_id
                )
            )
            solution_components = component_result.scalars().all()
            solution.component_count = len(solution_components)
            solution.vulnerable_component_count = sum(
                item.status == "vulnerable" for item in solution_components
            )
            finding_count = await db.scalar(
                select(func.count(SoftwareFinding.id))
                .join(SoftwareComponent, SoftwareComponent.id == SoftwareFinding.component_id)
                .where(
                    SoftwareComponent.solution_id == current_solution_id,
                    SoftwareFinding.status == "open",
                )
            )
            solution.finding_count = finding_count or 0
            partial = bool(provider_errors)
            solution.last_scan_status = "partial" if partial else "success"
            solution.last_scan_error = "provider_errors" if partial else None
            solution.last_scan_at = started
            if not partial:
                solution.last_successful_scan_at = now

        run_status = "partial" if provider_errors else "success"
        run.status = run_status
        run.provider_status = provider_status
        run.warnings = [*(run.warnings or []), *provider_errors][:100]
        run.findings_count = total_findings
        run.components_upserted = len(components)
        run.completed_at = now
        await db.commit()
        return {
            "status": run_status,
            "run_id": scan_run_id,
            "components_scanned": len(components),
            "findings": total_findings,
            "changed_findings": changed_findings,
            "provider_errors": len(provider_errors),
        }


def _record_from_component(component: SoftwareComponent):
    from app.services.software_inventory import SoftwareRecord

    return SoftwareRecord(
        solution=str(component.solution_id),
        ecosystem=component.ecosystem,
        package=component.package_name,
        version=component.version,
        purl=component.purl,
        cpe=component.cpe,
        asset=None,
        environment=component.environment,
        component_type=component.component_type,
        direct=component.direct,
        source=component.source,
    )
