# Kepryx Red-Team Review — 2026-08-27

## Scope

This is an authorized, local red-team review of the Kepryx v0.9.0 community-preview deployment. It covered the live API container, the Caddy edge, authentication and refresh-token behavior, RBAC, input/error handling, scan authorization, connector and webhook URL validation, production exposure, and selected source-level trust boundaries.

The review was performed against the running Docker Compose stack. It was not an Internet penetration test, a review of a customer environment, or a substitute for a third-party assessment.

## Executive result

No unauthenticated critical or high-severity path was demonstrated in the scoped review. Authentication, refresh-token rotation and replay rejection, MFA enforcement, role separation, scan authorization, metadata-endpoint blocking, webhook loopback blocking, hidden production API documentation, and direct API-port isolation passed the live checks.

The initial review identified two defense-in-depth findings. RT-01 and the literal-IP portion of
RT-02 are remediated in the current staged candidate; deployment firewall, VPN, and connector
egress controls remain required for real exposure.

## Remediation update

The staged candidate now enforces `MANAGEMENT_CIDRS` for privileged admin operations, honors
`X-Real-IP` only from a configured trusted proxy, blocks non-global connector IP literals unless
their CIDR is explicitly listed in `CONNECTOR_ALLOWED_CIDRS`, and validates all configured CIDR
settings at startup. The original findings below are retained as historical evidence; RT-01 and
the literal-IP portion of RT-02 are remediated in this candidate.

## Findings

### RT-01 — Management IP allowlist is not enforced

**Severity:** Medium hardening gap

**Evidence:** `app/api/deps.py:117-127` defines `check_ip_allowlist`, but the function is pass-through and no route uses it as a dependency. `docker/Caddyfile:21-23` contains only commented-out Caddy allowlist directives.

**Impact:** Kepryx does not currently enforce a management-network CIDR boundary at the application or edge layer. If the published Caddy port is reachable from an untrusted network, the API is still protected by authentication and RBAC, but the intended network-level restriction is absent.

**Recommendation:** Enforce the management CIDR policy at the deployment boundary (firewall/security group/reverse proxy) and either remove the unused dependency or implement and test it before claiming application-level allowlisting. Keep the current dedicated edge/internal network separation.

**Release disposition:** Remediated for privileged API operations in this candidate. Host firewall,
VPN, and edge policy remain required as defense in depth.

### RT-02 — Admin-configured connector endpoints can target private or loopback IPs

**Severity:** Low/Medium defense-in-depth risk

**Evidence:** `app/core/connector_secrets.py:71-86` blocks metadata and link-local endpoints but does not reject all private or loopback IP literals. A live API test created a temporary `asset_api` integration with `https://127.0.0.1`, while `https://169.254.169.254` was correctly rejected. The temporary integration was removed after testing.

**Impact:** An administrator, or an attacker who has already obtained administrator access, can configure a connector to make requests to internal services. This supports legitimate internal integrations, so it is not an unauthenticated SSRF path; it remains a meaningful blast-radius concern if an admin account or session is compromised.

**Recommendation:** Add an explicit per-connector endpoint allowlist or deployment-controlled egress policy. If private targets remain supported, document that connector egress must be restricted by network policy and test DNS/IP resolution at request time. Preserve metadata/link-local blocking.

**Release disposition:** Literal non-global targets now require explicit `CONNECTOR_ALLOWED_CIDRS`.
Hostname resolution and egress remain deployment responsibilities, so hostile or multi-tenant
environments still require network-level egress restrictions.

### RT-03 — Cryptographic Git release signing is not configured

**Severity:** Release-process gap (not an application vulnerability)

**Evidence:** Repository-local Git identity is configured as Ahmad Almallah / `ahmad.almallah.consulting@hotmail.com`. No GPG installation or SSH signing key was available on the machine, and no signing key is configured.

**Impact:** Source attribution is present, but commits and release tags cannot yet be cryptographically verified as Ahmad's.

**Recommendation:** Add a personal GPG or SSH signing key, publish its public key/fingerprint through the chosen Git hosting account, then configure signed commits/tags. Do not generate or commit private key material in this repository.

## Live evidence summary

| Check | Result |
|---|---|
| Unauthenticated assets/admin access | 401 |
| Viewer asset read / write separation | 200 / 403 |
| Analyst asset create and update | 201 / 200 |
| Analyst admin access | 403 |
| Tampered JWT | 401 |
| SQL-injection-shaped asset search | 200, no server error |
| Invalid asset body / missing asset | 422 / 404 |
| Unauthorized scan CIDR | 403 |
| Metadata connector endpoint | 422 blocked |
| Loopback connector endpoint | 422 blocked unless explicitly allowlisted |
| Loopback webhook endpoint | 422 blocked |
| Production docs and OpenAPI | 404 |
| `.env` path | 404 |
| Direct host API port | Not published |
| HTTPS health endpoint | 200 with security headers |

## Out of scope or not fully verified

- Real external provider credentials and production tenant permissions.
- Public Internet exposure, real DNS/ACME certificate issuance, and host firewall policy.
- Load, soak, HA, failover, and backup/restore operations beyond the existing isolated smoke evidence.
- Full browser mutation coverage for every UI control; the highest-value graph interaction path
  was subsequently verified in `docs/BROWSER-MUTATION-EVIDENCE.md`.
- A third-party penetration test.

## Conclusion

The current evidence supports the claim that the local v0.9.0 preview has a materially hardened
security foundation and no demonstrated unauthenticated critical/high path in this review. It does
not support a claim of CVE-free, production-certified, or penetration-tested status. RT-01 and the
literal-IP portion of RT-02 are remediated in the staged candidate; host firewall/VPN policy and
hostname egress controls remain deployment responsibilities. The rebuilt release image set also
passed the raw HIGH/CRITICAL Trivy gate; this remains a point-in-time result rather than a
permanent CVE-free claim.
