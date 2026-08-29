"""Deterministic compliance assessment and evidence lineage generation."""

import hashlib
import json
import logging
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime

from sqlalchemy import and_, select

from app.core.database import SessionLocal
from app.models import (
    Alert,
    AssessmentEvidence,
    AssessmentResult,
    AssessmentRun,
    Asset,
    ComplianceMapping,
    EvidenceItem,
    FrameworkCatalog,
    FrameworkControl,
)
from app.services.compliance_catalog import CONTROL_RULES, FRAMEWORK_CATALOGS, ControlRule
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _json_value(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)


def _has_observation(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _evidence(rule: ControlRule, asset: Asset) -> dict:
    return {
        "description": rule["desc"],
        "source": "asset_record",
        "observed": {
            name: _json_value(getattr(asset, name, None)) for name in rule["evidence_fields"]
        },
    }


def _integrity_hash(observed: Mapping[str, object]) -> str:
    canonical = json.dumps(observed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _assess(rule: ControlRule, asset: Asset) -> tuple[str, float, float, str]:
    """Return status, normalized score, rule confidence, and operator rationale."""
    observed = {name: _json_value(getattr(asset, name, None)) for name in rule["evidence_fields"]}
    present = sum(_has_observation(value) for value in observed.values())
    total = len(observed)
    try:
        compliant = bool(rule["check"](asset))
    except Exception:  # defensive: one malformed asset must not abort an assessment run
        compliant = False

    if compliant:
        status = "compliant"
        score = 1.0
    elif total > 1 and 0 < present < total:
        status = "partial"
        score = round(present / total, 2)
    else:
        status = "gap"
        score = 0.0

    availability = ", ".join(
        f"{name}={'present' if _has_observation(value) else 'missing'}"
        for name, value in observed.items()
    )
    rationale = (
        f"Deterministic asset-observation rule: {rule['desc']}. "
        f"Evidence availability: {availability}."
    )
    return status, score, 1.0, rationale


def _framework_summary(status_counts: Counter[str]) -> dict[str, int | float]:
    counts: dict[str, int | float] = defaultdict(int)
    counts.update(status_counts)
    total = sum(status_counts.values())
    applicable = total - status_counts.get("not_applicable", 0)
    counts["total"] = total
    counts["compliance_pct"] = (
        round((status_counts.get("compliant", 0) / applicable) * 100, 2) if applicable else 0
    )
    return dict(counts)


@celery_app.task(name="app.workers.compliance_tasks.run_compliance_audit")
def run_compliance_audit(initiated_by: str = "scheduler"):
    return run_async(_run_audit(initiated_by=initiated_by))


async def _run_audit(initiated_by: str = "scheduler"):
    now = datetime.now(UTC)
    async with SessionLocal() as db:
        assets = (await db.execute(select(Asset))).scalars().all()
        controls_result = await db.execute(
            select(FrameworkControl, FrameworkCatalog)
            .join(FrameworkCatalog, FrameworkCatalog.id == FrameworkControl.catalog_id)
            .where(FrameworkCatalog.active.is_(True))
            .order_by(FrameworkCatalog.code, FrameworkControl.sort_order)
        )
        controls = {
            (catalog.code, control.control_id): (control, catalog)
            for control, catalog in controls_result.all()
        }
        mappings = (await db.execute(select(ComplianceMapping))).scalars().all()
        mapping_by_key = {(m.framework, m.control_id, m.asset_id): m for m in mappings}

        run = AssessmentRun(
            framework_code="kepryx-control-bundle",
            framework_version="1.0",
            status="running",
            scope={
                "asset_count": len(assets),
                "frameworks": list(FRAMEWORK_CATALOGS),
                "control_count": sum(len(item["controls"]) for item in FRAMEWORK_CATALOGS.values()),
            },
            methodology={
                "type": "deterministic_asset_observation",
                "version": "1.0",
                "authoritative_input": "Kepryx asset records and source-labelled evidence",
                "limitations": [
                    "This is an engineering posture assessment, not a certification or audit opinion.",
                    "Controls are a small licensed-safe subset and require organization-specific evidence for assurance.",
                ],
            },
            started_at=now,
            initiated_by=initiated_by[:64],
        )
        db.add(run)
        await db.flush()

        status_counts: Counter[str] = Counter()
        framework_counts: dict[str, Counter[str]] = defaultdict(Counter)
        noncompliant_count = 0
        evidence_count = 0

        for asset in assets:
            for framework, framework_definition in FRAMEWORK_CATALOGS.items():
                for control_id, catalog_rule in framework_definition["controls"].items():
                    control_record = controls.get((framework, control_id))
                    if not control_record:
                        logger.error("Missing catalog control %s %s", framework, control_id)
                        continue
                    control, catalog = control_record
                    rule = CONTROL_RULES[framework][control_id]
                    status, score, confidence, rationale = _assess(rule, asset)
                    status_counts[status] += 1
                    framework_counts[framework][status] += 1
                    if status != "compliant":
                        noncompliant_count += 1

                    evidence_payload = _evidence(rule, asset)
                    observed = evidence_payload["observed"]
                    evidence = EvidenceItem(
                        source_type="asset_record",
                        source_ref=f"asset:{asset.id}",
                        title=f"{framework} {control_id} evidence for {asset.name}",
                        description=evidence_payload["description"],
                        observed=observed,
                        observed_at=asset.last_seen,
                        integrity_sha256=_integrity_hash(observed),
                        collector="app.workers.compliance_tasks",
                        classification="internal",
                        metadata_json={"framework": framework, "control_id": control_id},
                    )
                    assessment_result = AssessmentResult(
                        run=run,
                        control=control,
                        asset=asset,
                        status=status,
                        score=score,
                        confidence=confidence,
                        rationale=rationale,
                        rule_key=catalog_rule["rule_key"],
                        assessed_at=now,
                    )
                    assessment_link = AssessmentEvidence(
                        result=assessment_result,
                        evidence=evidence,
                        relation="supports",
                        role="primary",
                        extracted_by="deterministic_rule",
                    )
                    db.add_all([assessment_result, evidence, assessment_link])
                    await db.flush()
                    evidence_count += 1

                    mapping = mapping_by_key.get((framework, control_id, asset.id))
                    mapping_evidence = {
                        **evidence_payload,
                        "framework_version": catalog.version,
                        "assessment_run_id": str(run.id),
                        "assessment_result_id": str(assessment_result.id),
                        "evidence_id": str(evidence.id),
                        "integrity_sha256": evidence.integrity_sha256,
                    }
                    if mapping:
                        mapping.status = status
                        mapping.evidence = mapping_evidence
                        mapping.assessed_at = now
                    else:
                        mapping = ComplianceMapping(
                            framework=framework,
                            control_id=control_id,
                            asset_id=asset.id,
                            status=status,
                            evidence=mapping_evidence,
                            assessed_at=now,
                        )
                        db.add(mapping)
                        mapping_by_key[(framework, control_id, asset.id)] = mapping

                    title = f"Compliance gap: {framework} {control_id} on {asset.name}"
                    alert_result = await db.execute(
                        select(Alert).where(
                            and_(
                                Alert.alert_type == "compliance_gap",
                                Alert.asset_id == asset.id,
                                Alert.title == title,
                                Alert.status == "open",
                            )
                        )
                    )
                    alerts = alert_result.scalars().all()
                    if status == "compliant":
                        for alert in alerts:
                            alert.status = "resolved"
                            alert.resolved_at = now
                            alert.resolved_by = "compliance_audit"
                    elif asset.criticality in ("critical", "tier-1", "high"):
                        details = {
                            "framework": framework,
                            "framework_version": catalog.version,
                            "control": control_id,
                            "status": status,
                            "assessment_run_id": str(run.id),
                            "assessment_result_id": str(assessment_result.id),
                            "evidence_id": str(evidence.id),
                            "evidence": evidence_payload,
                        }
                        alert = alerts[0] if alerts else None
                        if alert:
                            alert.description = f"{rule['desc']} — {status}"
                            alert.details = details
                        else:
                            db.add(
                                Alert(
                                    alert_type="compliance_gap",
                                    severity="medium",
                                    title=title,
                                    description=f"{rule['desc']} — {status}",
                                    asset_id=asset.id,
                                    details=details,
                                )
                            )

        run.summary = {
            "assets": len(assets),
            "results": sum(status_counts.values()),
            "evidence_items": evidence_count,
            "noncompliant_results": noncompliant_count,
            "status_counts": dict(status_counts),
            "frameworks": {
                framework: _framework_summary(counts)
                for framework, counts in framework_counts.items()
            },
        }
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        await db.commit()
        logger.info(
            "Compliance assessment %s completed: %d assets, %d results, %d non-compliant",
            run.id,
            len(assets),
            sum(status_counts.values()),
            noncompliant_count,
        )
        return {
            "run_id": str(run.id),
            "audited": len(assets),
            "results": sum(status_counts.values()),
            "critical_gaps": noncompliant_count,
        }
