# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic
versioning.

## [0.9.0] - 2026-08-29

- Added GitHub publication metadata and maintainer guidance: `CITATION.cff`, `.gitattributes`, issue
  configuration, a release template, and repository security workflow metadata.
- Added versioned compliance catalogs, auditable assessment runs, graduated control statuses,
  SHA-256 evidence snapshots, result-to-evidence lineage APIs, enhanced compliance drill-down,
  and evidence-traceable PDF reporting. Added a review-only AI compliance suggestion endpoint;
  it cannot change assessment, risk, alert, or exception state.
- Added the connected same-origin operator console under `frontend/`.
- Added the supported manual asset-create API and bounded alert pagination.
- Added a vendor-neutral synthetic CSV inventory fixture using reserved documentation ranges,
  with a UI/API dry-run workflow for repeatable demonstrations.
- Added an isolated clean-host verification overlay and backup/restore evidence procedure for the
  v0.9 community-preview gate. The release gate uses a raw Trivy result; it does not rely on an
  image vulnerability allowlist.
- Added configurable HTTP/HTTPS host ports and corrected the local API hostname allowlist so the
  Windows HTTPS edge can be tested on `https://kepryx.local:8443` without changing production's
  default 80/443 mapping.
- Added the release scorecard, roadmap, demo evidence pack, diagrams, product gallery, and
  publication materials.
- Added targeted live acceptance evidence for asset create/update, NVD/EPSS/KEV enrichment,
  compliance mappings, alert resolution, authorized lab-CIDR scans, self-security scanning,
  scoped API-token use/revocation, and signed webhook delivery.
- Added an API-backed dashboard overview and bounded projected 4D inventory relationship map with
  X/Y orbit, zoom/pan/reset, risk/timeline/topology/layer layouts, time scrubbing/playback,
  pause/refresh controls, and an accessible node-list fallback.
- Added a vendor-neutral Asset Source API fixture and connector with authentication, timeout,
  rate-limit, transient-server-failure, and fail-closed credential behavior.
- Wired persisted alert notifications to the signed webhook dispatcher and return an explicit
  `503` when the optional AI ingestion provider is not configured.
- Added a provider-neutral structured-output AI adapter with local Ollama/Qwen3 support and
  explicit non-thinking mode for predictable JSON normalization; AI output cannot author CVE,
  EPSS, KEV, or final risk values.
- Added the branded, read-only Kepryx Assistant. It uses provider-native system policy, bounded
  server-side evidence retrieval, authoritative vulnerability-record boundaries, source-IP
  throttling, safe output masking, and audit events without storing prompts or answers.
- Corrected the default FIRST EPSS endpoint to `/data/v1/epss` and made the OSV query endpoint
  configurable for reproducible self-security operations.
- Hardened webhook egress with a shared global-only destination policy, URL-credential rejection,
  dispatch-time revalidation for legacy records, and clean-host Caddy guards for `/metrics` and
  documentation paths.
- Added a professional demo evidence pack with timed speaker notes, an evidence matrix,
  benchmark/positioning review, technical system and evidence-lineage diagrams, and a repeatable
  health/readiness smoke benchmark.
- Expanded executable verification to 154 tests and 63.54% measured application coverage,
  including API mutation, read models, exports, token lifecycle, scanner authorization/parsing,
  CVE enrichment, reconciliation, connector contracts, retention, and worker retry-policy paths;
  CI now enforces a 60% coverage floor.
- Rebuilt Python service images on pinned Alpine layers and rebuilt Caddy with fixed Go/module
  pins; the stale Caddy vulnerability allowlist was removed after a raw HIGH/CRITICAL scan passed.
- Added a scheduled weekly rebuild and raw container rescan so upstream base-image and module drift
  is detected before it becomes a release claim.

## [Foundation baseline] - 2026-08-25

### Added

- FastAPI asset, alert, scan, compliance, integration, export, GDPR, token, webhook, WebSocket,
  and self-security APIs.
- Celery workers for scanning, reconciliation, enrichment, notifications, retention, and
  self-security processing.
- NVD, EPSS, CISA KEV, OSV, CrowdStrike, Nessus, LDAP, AWS, and DHCP/DNS integration foundations.
- PostgreSQL migrations through `0007_evidence_compliance` and an automatic migration startup gate.
- Hash-locked production and development dependency sets.
- CI gates for Ruff, mypy, pytest, migration drift, Bandit, pip-audit, secret detection, image
  privilege checks, and Trivy.

### Security

- Replaced shared/optional signing secrets with distinct required signing and encryption keys.
- Added JWT issuer, audience, required-claim, token-type, rotation, and Redis revocation controls.
- Added per-IP fail-closed login throttling, MFA failure lockout, encrypted MFA storage, and
  single-use short-lived WebSocket tickets.
- Added scope-limited hashed API tokens, connector credential encryption/rotation, SSRF and TLS
  validation, webhook safeguards, audit redaction, and CSV formula-injection protection.
- Hardened default-profile containers with non-root users, read-only filesystems, minimal
  capabilities, no package installer in Python runtimes, pinned bases, and network separation.
- Moved Python runtimes from Debian 12 to a pinned Debian 13 base after a fresh scanner database
  exposed newly published vendor-unfixed operating-system findings.
- Made destructive retention opt-in and enforced active-scan CIDR authorization at both request
  validation and worker execution boundaries.
- Moved Prometheus to an explicit opt-in profile and removed dormant Neo4j/Grafana services that
  had no executable integration or validated dashboards.

### Changed

- Self-security now generates immutable PR patch artifacts and cannot mutate or deploy source.
- Bootstrap requires an operator-supplied password and scanning is disabled until authorized
  CIDRs are configured.
- Replaced the unsafe, functionally misleading prototype dashboard with a script-free status page.
- Public positioning corrected to an honest v0.9.0 community preview.

### Known limitations

- Single tenant; no enterprise SSO.
- Deep browser mutation coverage, load, failover, and production HTTPS evidence remain incomplete;
  local route and dashboard-visualization smoke checks are covered.
- Prometheus remains opt-in despite passing the current image gate.
- The current image scan is a point-in-time result; upstream base and module changes require the
  scheduled and pre-release raw Trivy scans to be rerun.

The repository is maintained in a private-first review state before the signed public release.
