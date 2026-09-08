# Enterprise readiness review

Kepryx is a community preview, not an enterprise certification. This page keeps the boundary
clear between controls implemented in the repository, controls verified for the current candidate,
and deployment capabilities that require organization-specific design and testing.

## Implemented in the platform

- Role-aware API access with scoped service tokens, JWT revocation, MFA support, and management-network controls.
- Redacted audit records for security-sensitive actions.
- Bounded CSV/XLSX software ingest with formula rejection, size and row limits, SHA-256 file evidence,
  unresolved-asset reporting, and optional strict asset matching.
- Software composition analysis using OSV and CPE-backed NVD lookups, with cross-provider advisory
  correlation, EPSS/KEV context, registry freshness where a supported registry exists, and no automatic patching.
- Scan-run provenance including provider status, partial-failure warnings, timestamps, and operator identity.
- Finding lifecycle states for open, acknowledged, mitigated, accepted, and resolved findings.
- Pagination on software solutions, components, findings, and scan-run APIs.
- Docker hardening patterns: pinned bases where available, non-root services, read-only filesystems,
  dropped capabilities, resource limits, isolated networks, and health checks.
- CI gates for tests, lint, formatting, typing, secret detection, dependency auditing, migration checks,
  and container scanning.

## Verified for this working candidate

- Source-level tests and static checks were exercised locally; the last complete test run recorded
  177 passing tests. The current candidate also adds strict provider-failure regression coverage,
  and the final source gates record Ruff lint/format success, Python/JavaScript syntax success,
  dependency/secret checks from the prior audit, and demo Compose configuration success.
- The local software fixture exercises parent solutions, npm and Python packages, a CPE/NVD example,
  vulnerability findings, and registry freshness.

These results do not certify the final images or a production deployment. Docker Desktop was unavailable
during the audit, so current image builds, Trivy results, PostgreSQL migrations, Celery workers, scheduled
scans, and live browser acceptance remain unverified.

## Required before enterprise deployment

- Tenant or organization isolation across every asset, finding, alert, integration, audit, export, and
  assistant query; the preview remains single-tenant.
- SAML/OIDC SSO, directory/group mapping, conditional access, and a documented break-glass process.
- High-availability PostgreSQL/Redis, backups, restore drills, worker failure recovery, and monitored queue lag.
- A production secrets manager, key rotation, certificate lifecycle, centralized logs, metrics, and alert routing.
- Approved connector-specific data contracts, least-privilege credentials, egress policy, rate limits, and
  provider failure handling.
- Endpoint or package collectors for automatic installed-software discovery. The current feature supports
  file ingest and scheduled rechecking; it does not claim universal endpoint discovery.
- Current full CI, dependency resolution, built-image Trivy scans, authenticated API tests, browser mutation
  tests, load tests, and clean-host deployment evidence for the exact release commit.

## Release decision rule

Do not describe Kepryx as enterprise-ready solely because the feature list exists. Use “community preview”
until the required deployment controls above are implemented and independently verified in the target
organization. Use “enterprise coverage” only for the specific controls supported by current evidence.
