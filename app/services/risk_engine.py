"""Transparent weighted risk scoring engine.

The score is a bounded 1–5 weighted model.  Keeping the calculation additive is
intentional for the v0.9 preview: every component is visible to an operator and
can be reproduced from the asset and CVE evidence.  The UI and API use the same
formula and factor names.
"""

from dataclasses import dataclass
from typing import Any

CONTROL_MAP = {"full": 1, "partial": 3, "none": 5}
EXPOSURE_MAP = {"isolated": 1, "internal": 2, "dmz": 3, "cloud": 4, "internet-facing": 5}
ACCESS_MAP = {
    "mfa+pam": 1,
    "mfa": 2,
    "certificate": 2,
    "password": 4,
    "password-only": 5,
    "none": 5,
}
CRITICALITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4, "tier-1": 5}
DATA_CLASSIFICATION_MAP = {
    "public": 1,
    "internal": 2,
    "confidential": 4,
    "restricted": 5,
}

WEIGHTS = {
    "cve": 0.23,
    "kev": 0.18,
    "controls": 0.18,
    "exposure": 0.14,
    "access": 0.09,
    "criticality": 0.10,
    "data_classification": 0.08,
}


@dataclass
class RiskResult:
    score: float
    tier: str
    breakdown: dict[str, float]
    recommended_action: str
    sla_days: int


def _norm_cvss(cvss: float) -> int:
    return min(5, max(1, round((cvss / 10) * 5)))


def _norm_epss(epss: float) -> int:
    return min(5, max(1, round(epss * 5)))


def _tier(score: float) -> str:
    if score >= 4:
        return "Critical"
    if score >= 3:
        return "High"
    if score >= 2:
        return "Medium"
    if score >= 1.5:
        return "Low"
    return "Informational"


def _action_and_sla(tier: str, eol: bool, has_kev: bool) -> tuple[str, int]:
    if tier == "Critical":
        return ("Immediate patch / isolate / compensating control", 7)
    if tier == "High":
        return ("Priority patch cycle — patch or compensate", 30)
    if tier == "Medium":
        return ("Standard remediation track", 90)
    if eol:
        return ("Plan replacement / EOL migration", 180)
    if has_kev:
        return ("Apply KEV remediation", 14)
    return ("Monitor", 365)


def compute_risk(asset: dict[str, Any]) -> RiskResult:
    cves = asset.get("cves") or []
    max_cvss = max((c.get("cvss_v3") or c.get("cvss") or 0 for c in cves), default=0)
    max_epss = max((c.get("epss_score") or c.get("epss") or 0 for c in cves), default=0)
    has_kev = any(c.get("kev") for c in cves)
    has_ransomware_kev = any(c.get("kev") and c.get("kev_ransomware") for c in cves)

    cve_score = max(_norm_cvss(max_cvss), _norm_epss(max_epss)) if cves else 1
    # Ransomware-actively-exploited CVEs push KEV score to max + boost CVE score
    kev_score = 5 if has_kev else 1
    if has_ransomware_kev:
        cve_score = min(5, cve_score + 1)  # extra weight for active ransomware exploitation
    control_score = CONTROL_MAP.get(asset.get("control_coverage", "none"), 3)
    exposure_score = EXPOSURE_MAP.get(asset.get("network_exposure", "internal"), 3)
    access_score = ACCESS_MAP.get(asset.get("auth_method", "password"), 3)
    crit_score = CRITICALITY_MAP.get(asset.get("criticality", "medium"), 3)
    classification = str(asset.get("data_classification", "internal")).lower()
    classification_score = DATA_CLASSIFICATION_MAP.get(classification, 2)

    weighted = (
        cve_score * WEIGHTS["cve"]
        + kev_score * WEIGHTS["kev"]
        + control_score * WEIGHTS["controls"]
        + exposure_score * WEIGHTS["exposure"]
        + access_score * WEIGHTS["access"]
        + crit_score * WEIGHTS["criticality"]
        + classification_score * WEIGHTS["data_classification"]
    )

    score = round(weighted, 2)
    tier = _tier(score)
    action, sla = _action_and_sla(tier, asset.get("eol_status", False), has_kev)

    return RiskResult(
        score=score,
        tier=tier,
        breakdown={
            "cve": cve_score,
            "kev": kev_score,
            "controls": control_score,
            "exposure": exposure_score,
            "access": access_score,
            "criticality": crit_score,
            "data_classification": classification_score,
        },
        recommended_action=action,
        sla_days=sla,
    )
