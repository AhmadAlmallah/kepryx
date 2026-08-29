"""Licensed-safe framework metadata and deterministic assessment rules.

The catalog intentionally stores stable identifiers, short engineering objectives, and
links to the publisher. It does not redistribute normative framework text. The rules are
Kepryx's transparent asset-observation heuristics and are not a certification decision.
"""

from collections.abc import Callable
from typing import TypedDict

from app.models import Asset


class ControlRule(TypedDict):
    title: str
    objective: str
    family: str
    desc: str
    check: Callable[[Asset], bool]
    evidence_fields: tuple[str, ...]


def _fields(*names: str) -> tuple[str, ...]:
    return names


FRAMEWORK_CATALOGS: dict[str, dict] = {
    "cis-v8": {
        "version": "8.1",
        "name": "CIS Controls",
        "source_url": "https://www.cisecurity.org/controls",
        "controls": {
            "1.1": {
                "title": "Enterprise asset inventory",
                "objective": "Maintain a current record of enterprise assets.",
                "family": "Inventory",
                "rule_key": "asset_inventory",
                "desc": "Detailed asset inventory exists",
                "check": lambda a: bool(a.name and a.ip and a.os),
                "evidence_fields": _fields("name", "ip", "os"),
                "evidence_requirements": ["name", "ip", "os"],
            },
            "2.1": {
                "title": "Software inventory",
                "objective": "Track software installed on enterprise assets.",
                "family": "Inventory",
                "rule_key": "software_inventory",
                "desc": "Software inventory tracked",
                "check": lambda a: bool(a.software_stack),
                "evidence_fields": _fields("software_stack"),
                "evidence_requirements": ["software_stack"],
            },
            "4.1": {
                "title": "Secure configuration",
                "objective": "Apply secure configuration and hardening controls.",
                "family": "Configuration",
                "rule_key": "secure_configuration",
                "desc": "Encryption and hardening applied",
                "check": lambda a: a.control_coverage in ("partial", "full"),
                "evidence_fields": _fields("control_coverage"),
                "evidence_requirements": ["control_coverage"],
            },
            "6.1": {
                "title": "Access control",
                "objective": "Use strong authentication for asset access.",
                "family": "Access",
                "rule_key": "strong_authentication",
                "desc": "MFA enforced",
                "check": lambda a: "mfa" in (a.auth_method or "").lower(),
                "evidence_fields": _fields("auth_method"),
                "evidence_requirements": ["auth_method"],
            },
            "7.1": {
                "title": "Vulnerability management",
                "objective": "Maintain evidence of vulnerability scanning and patching.",
                "family": "Vulnerability",
                "rule_key": "vulnerability_management",
                "desc": "Vulnerability scanning + patching",
                "check": lambda a: bool(a.last_patch and a.last_patch != "Never"),
                "evidence_fields": _fields("last_patch"),
                "evidence_requirements": ["last_patch"],
            },
            "10.1": {
                "title": "Malware defenses",
                "objective": "Deploy and monitor endpoint malware defenses.",
                "family": "Defense",
                "rule_key": "endpoint_defense",
                "desc": "EDR/antimalware deployed",
                "check": lambda a: bool(a.edr_status and a.edr_status not in ("None", "N/A")),
                "evidence_fields": _fields("edr_status"),
                "evidence_requirements": ["edr_status"],
            },
        },
    },
    "nist-800-53": {
        "version": "Rev. 5",
        "name": "NIST SP 800-53 Security and Privacy Controls",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "controls": {
            "CM-8": {
                "title": "System component inventory",
                "objective": "Maintain an inventory of system components.",
                "family": "Configuration Management",
                "rule_key": "system_component_inventory",
                "desc": "System component inventory",
                "check": lambda a: bool(a.name and a.type and a.os),
                "evidence_fields": _fields("name", "type", "os"),
                "evidence_requirements": ["name", "type", "os"],
            },
            "AC-2": {
                "title": "Account management",
                "objective": "Use strong authentication controls for accounts.",
                "family": "Access Control",
                "rule_key": "account_management",
                "desc": "Strong auth controls",
                "check": lambda a: a.auth_method in ("mfa", "mfa+pam", "certificate"),
                "evidence_fields": _fields("auth_method"),
                "evidence_requirements": ["auth_method"],
            },
            "SI-2": {
                "title": "Flaw remediation",
                "objective": "Track timely remediation and avoid end-of-life assets.",
                "family": "System and Information Integrity",
                "rule_key": "flaw_remediation",
                "desc": "Timely patching",
                "check": lambda a: bool(
                    a.last_patch and a.last_patch != "Never" and not a.eol_status
                ),
                "evidence_fields": _fields("last_patch", "eol_status"),
                "evidence_requirements": ["last_patch", "eol_status"],
            },
            "SI-4": {
                "title": "System monitoring",
                "objective": "Deploy continuous monitoring on system components.",
                "family": "System and Information Integrity",
                "rule_key": "system_monitoring",
                "desc": "Continuous monitoring deployed",
                "check": lambda a: bool(a.edr_status and a.edr_status not in ("None", "N/A")),
                "evidence_fields": _fields("edr_status"),
                "evidence_requirements": ["edr_status"],
            },
        },
    },
    "iso-27001": {
        "version": "2022",
        "name": "ISO/IEC 27001 Information Security Management Systems",
        "source_url": "https://www.iso.org/standard/27001",
        "controls": {
            "A.8.1": {
                "title": "Asset inventory",
                "objective": "Maintain an inventory of information assets.",
                "family": "Technological controls",
                "rule_key": "asset_inventory",
                "desc": "Asset inventory maintained",
                "check": lambda a: bool(a.name and a.type),
                "evidence_fields": _fields("name", "type"),
                "evidence_requirements": ["name", "type"],
            },
            "A.8.9": {
                "title": "Configuration management",
                "objective": "Manage and document secure configuration baselines.",
                "family": "Technological controls",
                "rule_key": "configuration_management",
                "desc": "Configuration management",
                "check": lambda a: a.control_coverage != "none",
                "evidence_fields": _fields("control_coverage"),
                "evidence_requirements": ["control_coverage"],
            },
            "A.12.6": {
                "title": "Technical vulnerability management",
                "objective": "Identify and manage technical vulnerabilities.",
                "family": "Operations security",
                "rule_key": "technical_vulnerability_management",
                "desc": "Technical vuln management",
                "check": lambda a: bool(a.last_patch) and a.last_patch != "Never",
                "evidence_fields": _fields("last_patch"),
                "evidence_requirements": ["last_patch"],
            },
        },
    },
}


CONTROL_RULES: dict[str, dict[str, ControlRule]] = {
    framework: {
        control_id: {
            "title": control["title"],
            "objective": control["objective"],
            "family": control["family"],
            "desc": control["desc"],
            "check": control["check"],
            "evidence_fields": control["evidence_fields"],
        }
        for control_id, control in catalog["controls"].items()
    }
    for framework, catalog in FRAMEWORK_CATALOGS.items()
}
