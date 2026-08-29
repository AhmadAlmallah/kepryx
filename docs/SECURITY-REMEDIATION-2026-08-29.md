# Kepryx security remediation record

Evidence date: 2026-08-29 | Scope: exact working-tree candidate after the Luna audit remediation

This record documents the remediation work and executable evidence for the findings raised in the
release review. It is an engineering record, not a penetration-test report, certification, or
guarantee that future deployments will be secure.

## Executive result

The quoted application-level findings were remediated in the candidate source and covered by
regression tests. The Python test, SAST, dependency, secret, migration, import, Compose, and
rebuilt-image checks passed locally. The repository remains a v0.9.0 community preview: external
provider behavior, customer network ownership, public DNS/ACME, high availability, load/soak, and
GitHub governance are deployment or release controls rather than claims proven by this pass.

## Finding disposition

| Finding | Remediation | Evidence | Status |
|---|---|---|---|
| Scoped privileged API tokens bypassed the management boundary | `require_scope()` now applies the management-network check to `scans:trigger`, `alerts:resolve`, `audit:read`, `integrations:read`, and wildcard tokens. | Scope matrix and enforcement tests in `tests/unit/test_security_foundation.py`. | Resolved in source; external proxy/network policy remains deployment-owned. |
| Webhook DNS rebinding / TOCTOU SSRF | Hostnames are resolved once, every answer must be globally routable, and the verified IP is used for the connection while original Host/SNI are preserved. Redirects, URL credentials, and proxy environment variables are disabled. | `_PinnedIPTransport` contract test in `tests/unit/test_webhook_security.py`; registration and legacy-record checks retained. | Resolved in source; real destination certificate behavior still requires staging validation. |
| LDAPS certificate validation was implicit | Every LDAPS `Server` is given `Tls(validate=ssl.CERT_REQUIRED, ...)`. Operators may provide an enterprise CA bundle with `ca_certs_file`. | `_tls_config()` test in `tests/unit/test_security_foundation.py`; connector secret schema accepts the CA path. | Resolved in source; no live customer LDAP server was available for an end-to-end bind. |
| SlowAPI global limiter was configured but inactive | `SlowAPIMiddleware` is installed and the default `200/minute` limiter remains attached to `app.state`. | Middleware wiring test plus the existing per-endpoint rate-limit coverage. | Resolved in source. |
| Bulk CSV import buffered all bytes and materialized all rows | Uploads spool to disk after 1 MiB, row count is bounded while streaming, and validation/import use two passes over the spool. Only bounded duplicate state and a ten-row preview are retained. | Dry-run replay test in `tests/unit/test_bulk_import.py`; 50 MiB/10,000-row caps remain enforced. | Resolved in source; capacity planning is still required for large concurrent deployments. |
| Per-user rate limiting failed open when Redis was unavailable | Redis errors now return `503 rate_limit_service_unavailable` for the user and IP limiters. | Redis outage regression in `tests/unit/test_security_foundation.py`. | Resolved in source. |
| Scanner timeout left child processes running | A still-running nmap process is killed and awaited in `finally`, including timeout and cancellation paths. | Process kill/reap regression in `tests/unit/test_scanner.py`. | Resolved in source. |
| MFA enrollment lacked step-up reauthentication | Enrollment and confirmation require the current password; confirmation also validates a six-digit code. The UI now collects both values. | Auth tests in `tests/unit/test_auth_security.py` and JavaScript syntax validation. | Resolved in source; browser verification of the new prompt remains a manual check. |
| AI ingest lacked dedicated resource controls | The ingest endpoint has a per-user five-per-minute Redis limit; provider calls use a configured semaphore and timeout (`AI_MAX_CONCURRENCY`, `AI_TIMEOUT_SEC`). | AI timeout regression in `tests/unit/test_ai_parser.py`; configuration is documented in `.env.example`. | Resolved in source; provider-specific latency/load testing remains follow-up work. |

## Executed gates

| Gate | Result |
|---|---|
| `pytest -q --cov=app --cov-fail-under=60` | 154 passed; 63.54% application coverage |
| Ruff lint | Passed |
| Ruff format check | Passed |
| mypy | Passed across 69 application source files |
| Python compile/import | Passed |
| `pip-audit --strict --disable-pip -r requirements.txt` | No known vulnerabilities found |
| Bandit (`app/`, `demo/`) | No medium/high findings |
| Tracked-file `detect-secrets-hook` | Passed with `.secrets.baseline` |
| `docker compose config --quiet` | Passed |
| `alembic upgrade head` | Passed against the running PostgreSQL volume |
| `alembic check` | No new upgrade operations detected |
| Frontend `node --check` | Passed |
| Caddy configuration validation | Passed |
| Rebuilt image boundary checks | API, Caddy, Asset Source UID 10001; runtime API/PostgreSQL images do not include `pip`/`gosu` |
| Trivy 0.67.2, HIGH/CRITICAL, unfixed findings visible | 0 findings across 10 rebuilt local release images |
| CycloneDX SBOM generation | 10 local image SBOMs generated; CI generates and uploads six CI-image SBOMs |

The CI workflow now generates and uploads CycloneDX SBOMs for the six CI image identities in
addition to the existing SAST, dependency, secret, migration, and Trivy gates. The local ten-image
SBOM directory is intentionally ignored from source control because component hashes create
high-entropy false positives in the repository secret detector; the CI artifact remains available
for each release run.

## Remaining release controls

- Re-run these gates from the committed/tagged candidate; this document records the local
  verification used to prepare the remediation commit.
- Confirm the first GitHub Actions run is green. CodeQL is intentionally skipped while the
  repository is private on a personal plan and should be verified after public visibility or an
  organization Advanced Security setup.
- Configure an independently reviewed, protected `main`, private vulnerability reporting, secret
  scanning/push protection where available, and a signed release tag.
- Manually exercise MFA enrollment, API error responses, cancellation recovery, a customer-owned
  authorized scan range, and a real LDAPS certificate chain in isolated staging.
- Treat Trivy and pip-audit as point-in-time gates; upstream advisories can change after this date.

## Design note: why scoped `assets:write` is not management-only

The policy intentionally leaves `assets:write` usable by an approved ingest/service principal
outside the management CIDR. This supports connector and inventory-ingest workflows without
turning every source integration into an administrator network client. If a deployment uses
`assets:write` for operator control-plane actions, it should either issue the token only inside the
management network or add that scope to `MANAGEMENT_SCOPES` as a deployment-specific policy change.
