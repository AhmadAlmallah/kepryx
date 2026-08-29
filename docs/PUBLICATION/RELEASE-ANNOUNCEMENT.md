# Kepryx v0.9.0 community preview

Kepryx is now prepared as an Apache-2.0 open-source community preview for asset intelligence and
risk operations.

## What is included

- FastAPI backend and same-origin operator console.
- Asset reconciliation across vendor-neutral and optional enterprise sources.
- NVD, FIRST EPSS, CISA KEV, and OSV enrichment boundaries.
- Transparent risk scoring with visible factors and remediation guidance.
- Evidence-backed CIS, NIST, and ISO subset assessments with SHA-256 lineage.
- Alerts, audit trail, HMAC webhooks, exports, GDPR paths, scoped API tokens, and self-security.
- Bounded 4D inventory graph with filters, focus scopes, timeline playback, X/Y movement, Z-depth,
  pinning, zoom, and reset.
- Optional local Ollama/Qwen3 read-only Assistant.
- Docker Compose deployment, CI, CodeQL, Dependabot, security policy, QA, SAST, and release reports.

## Evidence snapshot

| Check | Result |
|---|---|
| Tests | 154 passed |
| Application coverage | 63.54% |
| Bandit / Ruff / mypy | Passed |
| pip-audit | No known runtime vulnerabilities |
| Trivy | 0 HIGH/CRITICAL across ten rebuilt first-party images |
| Release score | 82/100 community-preview confidence |

## Honest limits

This is not certified or proven for unsupervised production use. Deeper browser mutation, real
provider credentials, load/failover, HA, customer-owned restore, and public GitHub governance remain
explicit next gates. Scan authorization is required for every real network.

The next demo will show deployment, synthetic data ingestion, authorized lab scanning, enrichment,
risk, compliance evidence, alert resolution, and integration behavior.

— Ahmad Almallah
