# Foundation Remediation Evidence

Evidence date: 2026-08-28. This is a point-in-time engineering record, not a permanent security
guarantee. Re-run every gate from the exact candidate commit before release.

## Passed checks

- Ruff lint and format checks passed.
- mypy reported no issues across 69 application source files.
- 120 tests passed, including Assistant safety, API mutation, scanner, CVE enrichment,
  reconciliation, worker policy, OSV fixture, compliance assessment, webhook SSRF regression,
  and vendor-neutral connector contract/retry tests; measured application coverage was 54%.
- Bandit reported no medium/high findings across 9,845 lines across application and demo code.
- `pip-audit --strict` reported no known vulnerabilities in the hash-locked Python runtime set.
- Repository-scoped `detect-secrets-hook --baseline` reported no findings across the 179-file staged
  candidate.
  Ignored local Caddy certificate keys remain workspace artifacts under `docker/certs/` and are
  not repository inputs.
- The current PostgreSQL volume is at migration head `0007_evidence_compliance`; `alembic check`
  reports no model/schema drift. The earlier clean-host migration and restore procedure remains
  recorded against the `0006_schema_alignment` baseline.
- `alembic current` reported migration head and `alembic check` found no model/schema drift.
- The isolated clean-host overlay was rebuilt from fresh volumes. Login, UI/API, internal HTTPS,
  vendor-neutral CSV ingest, loopback discovery, compliance, and self-security all completed.
  An 18,847-byte PostgreSQL dump restored 11 assets into a separate disposable database at
  `0006_schema_alignment`.
- Live API probes returned healthy database and Redis readiness, rejected an invalid Host header,
  hid API documentation at both API and edge paths, and ran as UID 10001 on a read-only root
  filesystem without runtime pip.
- Webhook destination policy now requires globally routable IPs, rejects URL userinfo, blocks
  shared-address DNS results, and rechecks IP literals during delivery for legacy records.
- The Caddy configuration validates, HTTP requests redirect to HTTPS, and the immutable frontend
  bundle is present in the Caddy image under `/srv/frontend` with the updated CSP configuration.
  The normal local edge now delivers health and UI successfully over `https://kepryx.local:8443`
  after adding the hostname to the API allowlist and using the configurable local port mapping.
  Standard host port 443 remains the production default; public ACME/managed-certificate smoke
  testing still requires a real DNS name.
- All Caddy profiles validate, and the clean-host profile explicitly blocks `/metrics`, `/docs*`,
  `/redoc*`, and `/openapi.json*` before its SPA fallback.
- Destructive audit/asset retention returned zero while `RETENTION_DELETE_ENABLED=false`.
- A scanner worker rejected a target while `SCAN_NETWORKS` was empty.
- The vendor-neutral Asset Source API image built successfully as a non-root UID 10001 container
  and its local health endpoint returned `{"status":"ok","simulated":true}`. Its connector
  returned deterministic synthetic inventory, retried transient 503 and 429 responses, failed
  closed on invalid credentials, and returned a failure after repeated timeouts.
- The final staged candidate rebuilt the API, workers, beat, Caddy, PostgreSQL, and Asset Source
  images. Sequential raw Trivy scans with unfixed findings visible passed for every first-party
  image at HIGH/CRITICAL severity; nine current CycloneDX SBOMs were generated outside the
  repository for the release image tags. The Caddy binary is built from pinned fixed Go/module
  versions and the stale allowlist was removed.

## Targeted live acceptance evidence

- Three synthetic assets were created through the API. One was edited successfully, changing its
  risk from `3.36 High` to `2.63 Medium` before enrichment.
- The real NVD/EPSS/KEV pipeline enriched a synthetic Apache HTTP Server 2.4.49 CPE with 81 CVEs;
  the asset was rescored to `4.27 Critical`.
- Compliance execution produced a completed run over 34 assets with 442 graduated results and
  linked evidence across CIS v8, NIST 800-53, and ISO 27001, with measured compliance percentages
  and persisted gap alerts. One generated alert was resolved and verified through the API and audit
  trail.
- Authorized loopback discovery completed with one host; the service scan completed with zero
  services without an error. Self-security scanned 76 resolved packages with zero findings.
- A scoped `X-API-Key` token read the asset summary, was denied admin access, and returned `401`
  after revocation. A temporary HTTPS webhook receiver accepted four signed alert events with
  `success_200` and zero failures; it was deleted after the test to prevent future outbound posts.
- Local Ollama/Qwen3-14B AI ingestion returned `200`, created one asset, and queued enrichment.
  Qwen produced two CPEs; NVD returned 25 vulnerability records, EPSS populated all 25 records,
  and the KEV catalog matched two records. The asset was rescored `3.41 High`. This proves the
  model is used for bounded normalization while authoritative vulnerability facts still come from
  NVD/EPSS/KEV.
- Local Ollama/Qwen3-14B Assistant support returned a grounded posture answer through the
  authenticated UI, included server-generated evidence references, and refused a prompt-injection
  request for system policy, connector secrets, and scan execution.
- OSV self-security queried 76 resolved packages with HTTP 200 responses, completed successfully,
  and persisted zero findings. The local Qwen update validator also returned a structured result;
  its output remains review guidance and cannot mutate source code or author vulnerability facts.
- A deterministic OSV fixture created a high finding with fixed version `0.141.2`; its persisted
  update proposal completed the live proposed → approved → patch-ready → rollback → rejected
  lifecycle through the API and worker, then the fixture rows and generated test alert were
  removed by exact identifiers.
- The dashboard overview returned 34 assets, 115 open alerts, and 1,675 KEV CVEs. The bounded
  inventory graph returned 185 nodes and 218 relationships with NVD, EPSS, CISA KEV, and OSV
  provenance. A local browser smoke pass loaded all operator routes without the prior
  `children.filter is not a function` failure and verified graph filtering, layout reshaping,
  time scrubbing/playback, zoom/reset, and pause controls. Browser mutation evidence additionally
  verified node-picker focus, selected-only and direct-neighbor scopes, X/Y drag, Alt-drag Z-depth,
  pin/unpin, zoom, timeline playback, and reset behavior; the exact record is in
  `docs/BROWSER-MUTATION-EVIDENCE.md`.
- An isolated Docker bridge using reserved lab CIDR `198.51.100.0/28` discovered the synthetic
  asset-source target at `198.51.100.10`; the scan worker accepted the authorized CIDR and did
  not access an outside network.
- Live auth and API failure checks covered refresh rotation/replay, invalid and missing MFA codes,
  malformed JSON, validation errors, missing resources, unauthenticated Assistant access, and an
  unauthorized CIDR. A deliberately cancelled scan was recovered on the next worker run and
  recorded as failed. The synthetic authorization scope is documented in
  `docs/SCAN-AUTHORIZATION-RECORD.md`; real deployments still require customer-owned approval.

## Container vulnerability evidence

Trivy 0.67.2 used a refreshed vulnerability database and scanned high/critical findings without
hiding unfixed advisories. The release gate fails when a fixed package version exists. The raw
scan was performed against the rebuilt image tags on 2026-08-28.

| Candidate image | High | Critical | Fixable |
|---|---:|---:|---:|
| API (Python 3.12 / pinned Alpine) | 0 | 0 | 0 |
| Worker enrich (Python 3.12 / pinned Alpine) | 0 | 0 | 0 |
| Worker recon (Python 3.12 / pinned Alpine) | 0 | 0 | 0 |
| Worker self-security (Python 3.12 / pinned Alpine) | 0 | 0 | 0 |
| Beat (Python 3.12 / pinned Alpine) | 0 | 0 | 0 |
| Scanner (Python 3.12 / Alpine + nmap) | 0 | 0 | 0 |
| Caddy 2.11.4 custom build / pinned Alpine | 0 | 0 | 0 |
| PostgreSQL 16 / Alpine 3.24.1 | 0 | 0 | 0 |
| Asset Source mock (Python 3.12 / pinned Alpine) | 0 | 0 | 0 |

The Caddy image is built from the v2.11.4 source release with Go 1.26.6 and explicit fixed module
versions for `golang.org/x/net`, `golang.org/x/text`, and gRPC. The pinned Alpine runtime layer is
upgraded during the build. A sequential raw Trivy 0.67.2 scan of the rebuilt image reported zero
HIGH/CRITICAL findings; the prior 14-entry allowlist is no longer part of the release gate.

The Python runtime, scanner, beat, and Asset Source images now use a pinned Python 3.12 Alpine
base with `apk upgrade` and a non-root runtime. A sequential raw Trivy scan of each rebuilt image
reported zero HIGH/CRITICAL findings, including unfixed advisories. This is a point-in-time gate,
not a permanent CVE-free guarantee; the weekly rebuild/rescan workflow and exact release scan
remain required.

## Remaining public-launch gates and limitations

- 54% coverage is materially improved and now enforces a CI floor of 50%, but it is not a
  production-tested claim. Browser mutation E2E, additional multipart/GDPR/export paths, real
  provider behavior, load/soak, and broader failure-injection evidence remain follow-up work.
- Production backup retention/restore operations, deep browser mutation coverage, load/soak,
  failure injection,
  upgrade from representative legacy data, and HA/failover behavior are not proven. The isolated
  clean-host backup/restore smoke test is evidence for the preview path only.
- The connected frontend and dashboard relationship visualization are implemented. Local browser
  route smoke and core API mutation tests are proven; full browser mutation coverage remains
  required before making a production-tested claim.
- Public production HTTPS with a real DNS/ACME or managed certificate is not yet tested. The local
  Windows edge is verified on port 8443; Docker Desktop host port 443 reset in this environment.
- The release image set passed the 2026-08-28 raw Trivy 0.67.2 HIGH/CRITICAL scan after moving
  the Python services to pinned Alpine bases and building Caddy with fixed Go/module pins. Future
  advisories can still appear; the weekly rebuild/rescan workflow and pre-release scan are the
  controls for that drift.
- The deployment is single-host and single-tenant, with no SAML/OIDC, multi-host HA, or internal
  service mTLS.
- Private vulnerability reporting, a monitored security contact, one independent peer review, and
  a cryptographically signed release tag must be configured before the repository becomes public.
