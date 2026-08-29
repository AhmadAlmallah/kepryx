# Kepryx security review

Evidence date: 2026-08-28 | Scope: staged v0.9.0 candidate and live local Compose stack

This is a release-oriented engineering and red-team review. It is not an independent penetration
test, formal certification, or guarantee that future deployments will be secure.

## Security conclusion

No unreviewed HIGH/CRITICAL dependency or image finding was present in the current locked Python
set or the nine rebuilt first-party release images. The main remaining risks are operational:
customer-owned deployment authorization, production certificate and DNS behavior, availability and
recovery evidence, real-provider integration, and public GitHub governance. The candidate is a
credible open-source community preview when those boundaries are published clearly.

## Attack surface reviewed

| Surface | Review focus | Current result |
|---|---|---|
| Browser/edge | TLS routing, host allowlist, CORS, security headers, SPA fallback | Confirmed locally; public ACME not proven |
| Auth | Password hashing, MFA, refresh rotation, replay, revocation, login throttling | Confirmed by tests and live probes |
| API | RBAC/scopes, validation, error paths, audit events | Confirmed for core mutation and failure paths |
| Connectors | Secret handling, SSRF, TLS, timeout, retry, fail closed | Confirmed by contracts and webhook/connector tests |
| Scanner | CIDR authorization at API and worker boundary | Confirmed for empty/unauthorized/authorized lab ranges |
| Workers | Queue separation, cancellation/recovery, non-root runtime | Confirmed in local evidence; HA not proven |
| Data | PostgreSQL migrations, evidence hashes, export/erasure paths | Migration/lineage and core API paths confirmed; deeper browser evidence remains |
| AI | Prompt injection, bounded packet, read-only behavior, authoritative-data boundary | Confirmed with local Qwen3 Assistant path |
| Supply chain | Locked requirements, SAST, secret scan, Trivy, SBOM | Current gates pass |

## Controls confirmed

- Distinct required `SECRET_KEY`, `JWT_SECRET`, and `ENCRYPTION_KEY` settings.
- Argon2 password hashing, MFA support, short-lived access tokens, rotating refresh tokens, and
  Redis-backed token revocation.
- Per-IP login and Assistant throttling with fail-closed behavior when the rate-limit service is
  unavailable.
- Trusted-host validation, explicit CORS origins, six configured security headers, and API docs/
  metrics restrictions at the clean edge.
- Scope-limited API tokens are hashed, revocable, and denied admin operations without the required
  scope.
- Webhook SSRF checks require globally routable destinations, reject URL credentials, check DNS
  shared-address results, and revalidate legacy records at dispatch time.
- Network scans require an explicitly configured authorized CIDR and repeat that check in the
  worker. The reserved lab scan used `198.51.100.0/28` only.
- Runtime containers use non-root users, read-only filesystems where supported, dropped Linux
  capabilities, `no-new-privileges`, pinned image/module inputs where feasible, and separated
  internal/egress networks.
- AI is advisory/read-only and cannot create authoritative CVE, EPSS, KEV, risk, compliance, or
  remediation state.

## Finding register

| ID | Finding | Severity | State | Required treatment |
|---|---|---:|---|---|
| SEC-01 | Customer deployment must define real scan authorization and network ownership | High operational | Open by design | Store written approval and change scope before scanning real CIDRs |
| SEC-02 | Public DNS, ACME/managed certificate, and external reverse-proxy behavior are not proven here | Medium | Open | Validate in a customer-owned staging deployment |
| SEC-03 | HA, worker failover, queue durability under outage, and production restore are not proven | Medium | Open | Run an operational pilot with restore and failure-injection evidence |
| SEC-04 | Real connector provider behavior and credential rotation are not proven with external accounts | Medium | Open | Add provider-specific contract tests in isolated staging |
| SEC-05 | Application coverage is 53.63%, with browser-only flows remaining | Medium | Open | Expand tests based on community usage and failure reports |
| SEC-06 | The local Docker host has old orphan Grafana/Neo4j/Vault containers outside the current Compose file | Low local | Open | Treat as host hygiene; do not call them part of this release |
| SEC-07 | GitHub branch protection, peer review, signed tag, and public vulnerability-reporting setup remain launch actions | High launch gate | Open | Complete private-first launch checklist before visibility is public |

## Supply-chain result

Trivy 0.67.2 scanned the rebuilt API, five worker/beat roles, scanner, Caddy, PostgreSQL, and
Asset Source mock images with `HIGH,CRITICAL` severity and unfixed findings visible. Each returned
0 HIGH, 0 CRITICAL, and 0 fixable findings. Nine CycloneDX SBOMs were generated for the same image
set. This result is point-in-time evidence; the scheduled weekly rebuild/rescan workflow is part of
the release control.

## Red-team judgment

The most credible abuse paths are not “the model invents a CVE.” They are operational: a deployment
operator authorizes an overly broad scan range, exposes the API outside the hardened edge, trusts a
stale connector record, runs with weak secrets, or treats a compliance percentage as certification.
The code contains meaningful controls for those paths, but deployment ownership and human review
remain part of the security boundary.

## Release recommendation

Publish as an Apache-2.0 v0.9.0 community preview with the limitations in this document, the QA
report, and `SECURITY.md`. Do not market it as certified, vendor-complete, multi-tenant, HA, or
production-autonomous. Require private-first review, a final exact-candidate scan, signed release
metadata, and a security contact before public visibility.
