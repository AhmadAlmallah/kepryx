"""Self-security worker tasks.

The scanner inventories the resolved runtime, not requirement ranges. Update
approval produces a reviewable patch proposal; workers never mutate host source.
"""

import logging
from datetime import UTC, datetime, timedelta
from difflib import unified_diff
from pathlib import Path

from packaging.version import InvalidVersion, Version
from sqlalchemy import delete, select

from app.core.database import SessionLocal
from app.models import CVE, Alert
from app.models.self_security import (
    DependencyFinding,
    PlatformDependency,
    SelfSecuritySettings,
    UpdateProposal,
)
from app.services.ai_update_validator import assess_update
from app.services.self_security_scanner import SelfSecurityScanner
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

REQUIREMENTS_PATH = Path("/app/requirements.in")


async def _get_settings(db):
    result = await db.execute(select(SelfSecuritySettings).where(SelfSecuritySettings.id == 1))
    s = result.scalar_one_or_none()
    if not s:
        s = SelfSecuritySettings(id=1)
        db.add(s)
        await db.flush()
    # Source mutation is intentionally disabled. All changes require a PR.
    s.auto_update_enabled = False
    s.require_admin_approval = True
    return s


@celery_app.task(name="app.workers.self_security_tasks.scan_platform_deps")
def scan_platform_deps():
    return run_async(_scan_platform_deps())


async def _scan_platform_deps():
    """Inventory resolved Python packages and atomically refresh OSV findings."""
    started = datetime.now(UTC)
    async with SessionLocal() as db:
        settings_row = await _get_settings(db)
        settings_row.last_scan_status = "running"
        settings_row.last_scan_error = None
        settings_row.last_scan_at = started
        excluded = set(settings_row.excluded_packages or [])
        await db.commit()

    try:
        async with SelfSecurityScanner() as scanner:
            deps = await scanner.scan_installed_python_deps(component="api")
            if not deps:
                raise RuntimeError("resolved Python environment is empty")
            logger.info("Scanning %d resolved Python dependencies", len(deps))
            scan_results = {}
            latest_versions = {}
            for dep in deps:
                if dep.name in excluded:
                    continue
                scan_results[dep.name] = await scanner.find_vulns(dep)
                latest_versions[dep.name] = await scanner.get_latest_pypi_version(dep.name)
    except Exception as exc:
        logger.exception("Self-security scan failed; preserving prior findings")
        async with SessionLocal() as db:
            settings_row = await _get_settings(db)
            settings_row.last_scan_status = "failed"
            settings_row.last_scan_error = type(exc).__name__
            settings_row.last_scan_at = started
            await db.commit()
        return {"status": "failed", "error": type(exc).__name__}

    cve_candidates = {
        alias
        for findings in scan_results.values()
        for finding in findings
        for alias in [finding.cve_id, *finding.aliases]
        if alias.startswith("CVE-")
    }

    async with SessionLocal() as db:
        kev_ids: set[str] = set()
        if cve_candidates:
            kev_result = await db.execute(
                select(CVE.id).where(CVE.kev.is_(True), CVE.id.in_(cve_candidates))
            )
            kev_ids = set(kev_result.scalars().all())

        total_findings = 0
        critical_findings = 0
        kev_count = 0
        installed_names = {dep.name for dep in deps}
        dependency_state: dict[object, tuple[str, int]] = {}

        for dep in deps:
            result = await db.execute(
                select(PlatformDependency).where(
                    PlatformDependency.name == dep.name,
                    PlatformDependency.component == dep.component,
                )
            )
            pdep = result.scalar_one_or_none()
            if not pdep:
                pdep = PlatformDependency(
                    component=dep.component,
                    package_type=dep.package_type,
                    name=dep.name,
                    version=dep.version,
                    purl=dep.purl,
                )
                db.add(pdep)
                await db.flush()
            else:
                pdep.version = dep.version
                pdep.purl = dep.purl

            if dep.name in excluded:
                findings = []
                latest = None
            else:
                findings = scan_results[dep.name]
                latest = latest_versions[dep.name]

            existing_result = await db.execute(
                select(DependencyFinding).where(DependencyFinding.dependency_id == pdep.id)
            )
            existing = {item.cve_id: item for item in existing_result.scalars().all()}
            observed: set[str] = set()
            dep_kev_count = 0
            for finding in findings:
                observed.add(finding.cve_id)
                is_kev = any(
                    identifier in kev_ids for identifier in [finding.cve_id, *finding.aliases]
                )
                item = existing.get(finding.cve_id)
                if not item:
                    item = DependencyFinding(
                        dependency_id=pdep.id,
                        cve_id=finding.cve_id,
                    )
                    db.add(item)
                item.cvss = finding.cvss
                item.description = finding.description
                item.fixed_version = finding.fixed_version
                item.severity = finding.severity
                item.kev = is_kev
                total_findings += 1
                critical_findings += int(finding.severity == "critical")
                kev_count += int(is_kev)
                dep_kev_count += int(is_kev)

            stale_query = delete(DependencyFinding).where(
                DependencyFinding.dependency_id == pdep.id
            )
            if observed:
                stale_query = stale_query.where(DependencyFinding.cve_id.notin_(observed))
            await db.execute(stale_query)

            pdep.latest_version = latest
            pdep.cve_count = len(findings)
            pdep.kev_count = dep_kev_count
            pdep.max_cvss = max(
                (finding.cvss for finding in findings if finding.cvss is not None),
                default=None,
            )
            pdep.update_available = bool(latest and latest != dep.version)
            pdep.last_checked = datetime.now(UTC)
            dependency_state[pdep.id] = (pdep.version, pdep.cve_count)

        await db.execute(
            delete(PlatformDependency).where(
                PlatformDependency.component == "api",
                PlatformDependency.name.notin_(installed_names),
            )
        )

        # A fresh runtime scan is authoritative. Do not leave proposals based on
        # an older installed version or an advisory that is no longer present.
        pending_result = await db.execute(
            select(UpdateProposal).where(
                UpdateProposal.status.in_(["proposed", "ai_validated", "approved", "applying"])
            )
        )
        for proposal in pending_result.scalars().all():
            state = dependency_state.get(proposal.dependency_id)
            if state and (state[1] == 0 or proposal.current_version != state[0]):
                proposal.status = "rejected"
                proposal.error_message = "Superseded by a fresh resolved-runtime scan"

        settings_row = await _get_settings(db)
        settings_row.last_scan_status = "success"
        settings_row.last_scan_error = None
        settings_row.last_scan_at = started
        settings_row.last_successful_scan_at = datetime.now(UTC)
        settings_row.packages_scanned = len(deps)

        if critical_findings > 0 or kev_count > 0:
            db.add(
                Alert(
                    alert_type="self_security",
                    severity="critical" if kev_count > 0 else "high",
                    title=f"Platform dependency vulnerabilities: {total_findings} advisories",
                    description=(
                        f"The resolved runtime scan found {total_findings} advisories across "
                        f"{len(deps)} packages: {critical_findings} critical and "
                        f"{kev_count} confirmed in the synchronized CISA KEV catalog."
                    ),
                    details={
                        "total": total_findings,
                        "critical": critical_findings,
                        "kev": kev_count,
                        "packages_scanned": len(deps),
                    },
                    notification_channels=settings_row.notify_channels or ["slack"],
                )
            )
        else:
            # A clean scan closes the prior open self-security signal while
            # preserving its audit history.
            open_alerts = await db.execute(
                select(Alert).where(
                    Alert.alert_type == "self_security",
                    Alert.status == "open",
                )
            )
            for alert in open_alerts.scalars().all():
                alert.status = "resolved"
                alert.resolved_at = datetime.now(UTC)
                alert.resolved_by = "self-security-scan"
        await db.commit()
        return {
            "status": "success",
            "packages_scanned": len(deps),
            "total_findings": total_findings,
            "critical": critical_findings,
            "kev": kev_count,
        }


@celery_app.task(name="app.workers.self_security_tasks.propose_updates")
def propose_updates():
    return run_async(_propose_updates())


async def _propose_updates():
    """Create UpdateProposal records for vulnerable deps with available fixes."""
    async with SessionLocal() as db:
        settings_row = await _get_settings(db)
        scan_cutoff = datetime.now(UTC) - timedelta(hours=26)
        if (
            settings_row.last_scan_status != "success"
            or not settings_row.last_successful_scan_at
            or settings_row.last_successful_scan_at < scan_cutoff
        ):
            return {"skipped": "no_recent_successful_scan"}
        excluded = set(settings_row.excluded_packages or [])

        result = await db.execute(
            select(PlatformDependency).where(PlatformDependency.cve_count > 0)
        )
        deps = result.scalars().all()

        created = 0
        for pdep in deps:
            if pdep.name in excluded:
                continue

            # Find the minimum fixed version across all findings
            findings_result = await db.execute(
                select(DependencyFinding).where(
                    DependencyFinding.dependency_id == pdep.id,
                    DependencyFinding.suppressed.is_(False),
                )
            )
            findings = findings_result.scalars().all()
            target_versions = [f.fixed_version for f in findings if f.fixed_version]
            if not target_versions:
                pdep.update_blocked_reason = "No fixed version available upstream"
                continue

            try:
                target = str(max(Version(value) for value in target_versions))
            except InvalidVersion:
                pdep.update_blocked_reason = "Upstream fixed version is not valid PEP 440"
                continue
            cves_fixed = [f.cve_id for f in findings if f.fixed_version]

            # Skip if proposal already exists for this version
            existing = await db.execute(
                select(UpdateProposal).where(
                    UpdateProposal.dependency_id == pdep.id,
                    UpdateProposal.target_version == target,
                    UpdateProposal.status.in_(["proposed", "ai_validated", "approved", "applying"]),
                )
            )
            if existing.scalar_one_or_none():
                continue

            has_kev = any(f.kev for f in findings)
            has_critical = any(f.severity == "critical" for f in findings)
            reason = "kev_fix" if has_kev else ("cve_fix" if has_critical else "cve_fix")

            db.add(
                UpdateProposal(
                    dependency_id=pdep.id,
                    component=pdep.component,
                    package_name=pdep.name,
                    current_version=pdep.version,
                    target_version=target,
                    reason=reason,
                    cves_fixed=cves_fixed,
                    status="proposed",
                )
            )
            created += 1

        await db.commit()
        return {"proposals_created": created}


@celery_app.task(name="app.workers.self_security_tasks.ai_validate_proposals")
def ai_validate_proposals():
    return run_async(_ai_validate_proposals())


async def _ai_validate_proposals():
    """Run AI safety assessment on all pending proposals."""
    async with SessionLocal() as db:
        settings_row = await _get_settings(db)
        if not settings_row.require_ai_validation:
            return {"skipped": "ai_validation_disabled"}

        result = await db.execute(
            select(UpdateProposal).where(UpdateProposal.status == "proposed").limit(50)
        )
        proposals = result.scalars().all()

        validated = 0
        for prop in proposals:
            try:
                assessment = await assess_update(
                    package=prop.package_name,
                    current=prop.current_version,
                    target=prop.target_version,
                    reason=prop.reason,
                    cves=prop.cves_fixed or [],
                )
                prop.ai_assessment = assessment
                prop.ai_recommendation = assessment.get("recommendation", "manual_review")
                prop.ai_risk_score = float(assessment.get("risk_score", 10))
                prop.breaking_changes_detected = bool(assessment.get("breaking_changes_detected"))
                prop.compatibility_notes = assessment.get("summary", "")
                prop.status = "ai_validated"
                validated += 1
            except Exception as e:
                logger.exception(f"AI validation failed for {prop.package_name}")
                prop.ai_recommendation = "manual_review"
                prop.ai_assessment = {"_error": str(e)}
                prop.status = "ai_validated"

        await db.commit()
        return {"validated": validated}


@celery_app.task(name="app.workers.self_security_tasks.apply_approved_updates")
def apply_approved_updates(proposal_id: str | None = None):
    return run_async(_apply_approved_updates(proposal_id))


async def _apply_approved_updates(proposal_id: str | None = None):
    """Prepare reviewable patches for explicitly approved proposals."""
    async with SessionLocal() as db:
        candidates_q = select(UpdateProposal).where(UpdateProposal.status == "approved")
        if proposal_id:
            candidates_q = candidates_q.where(UpdateProposal.id == proposal_id)
        result = await db.execute(candidates_q)
        approved = list(result.scalars().all())
        prepared_count = 0
        failed_count = 0
        for prop in approved:
            try:
                ok = await _prepare_one_update(prop, db)
                if ok:
                    prepared_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                logger.exception("Update preparation crashed for %s", prop.package_name)
                prop.status = "failed"
                prop.error_message = str(e)[:1000]
                failed_count += 1

        await db.commit()
        return {"prepared_for_pr": prepared_count, "failed": failed_count}


async def _prepare_one_update(prop: UpdateProposal, db) -> bool:
    """Generate a patch artifact without mutating requirements.in."""
    if not REQUIREMENTS_PATH.exists():
        prop.status = "failed"
        prop.error_message = "requirements.in is not available for patch generation"
        return False

    original = REQUIREMENTS_PATH.read_text()
    new_content = []
    found = False
    for line in original.split("\n"):
        requirement = line.strip().lower()
        package_prefixes = (
            prop.package_name.lower() + operator for operator in ("==", ">=", "~=", "<=", ">", "<")
        )
        if any(requirement.startswith(prefix) for prefix in package_prefixes):
            new_content.append(f"{prop.package_name}=={prop.target_version}")
            found = True
        else:
            new_content.append(line)
    if not found:
        prop.status = "failed"
        prop.error_message = (
            f"{prop.package_name} is transitive or absent from requirements.in; "
            "regenerate the dependency lock in a review branch"
        )
        return False

    proposed = "\n".join(new_content)
    patch_text = "\n".join(
        unified_diff(
            original.splitlines(),
            proposed.splitlines(),
            fromfile="a/requirements.in",
            tofile="b/requirements.in",
            lineterm="",
        )
    )
    prop.rollback_snapshot = {
        "proposal_patch": patch_text,
        "previous_version": prop.current_version,
        "requires_lock_regeneration": True,
        "requires_ci": True,
    }
    prop.status = "ready_for_pr"
    prop.error_message = None
    db.add(
        Alert(
            alert_type="self_security_update_proposal",
            severity="medium",
            title=f"Dependency patch ready: {prop.package_name} {prop.target_version}",
            description=(
                "A non-mutating patch proposal is ready for a review branch. Regenerate the "
                "dependency lock, run CI and image scans, then merge through normal approval."
            ),
            details={
                "package": prop.package_name,
                "from": prop.current_version,
                "to": prop.target_version,
                "cves_fixed": prop.cves_fixed,
            },
        )
    )
    return True


@celery_app.task(name="app.workers.self_security_tasks.rollback_proposal")
def rollback_proposal(proposal_id: str):
    return run_async(_rollback_proposal(proposal_id))


async def _rollback_proposal(proposal_id: str):
    async with SessionLocal() as db:
        result = await db.execute(select(UpdateProposal).where(UpdateProposal.id == proposal_id))
        prop = result.scalar_one_or_none()
        if not prop or prop.status != "ready_for_pr":
            return {"error": "no prepared patch to cancel"}
        prop.rollback_snapshot = {}
        prop.status = "approved"
        await db.commit()
        return {"patch_cancelled": True}
