# Secure Framework

Reference framework for hardening a Kepryx deployment. Aligned to CIS Controls v8, NIST CSF 2.0, and ISO 27001 Annex A.

## Layered defense model

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 7 — Application                                       │
│  Auth, RBAC, input validation, audit, output encoding        │
├─────────────────────────────────────────────────────────────┤
│  Layer 6 — Container                                         │
│  Non-root, read-only fs, cap_drop, no-new-privileges         │
├─────────────────────────────────────────────────────────────┤
│  Layer 5 — Orchestration                                     │
│  Internal Docker network, encrypted connector credentials    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4 — Transport                                         │
│  TLS, HSTS, and operator-managed database transport controls  │
├─────────────────────────────────────────────────────────────┤
│  Layer 3 — Network                                           │
│  WAF, IP allowlist, firewall, VPN-only management            │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 — Host                                              │
│  Patched kernel, SELinux/AppArmor, Docker rootless           │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 — Physical / Cloud                                  │
│  Cloud IAM, hardware security, hypervisor patching           │
└─────────────────────────────────────────────────────────────┘
```

## Pre-production hardening checklist

### Authentication and identity

- [ ] `JWT_SECRET` is unique per environment, ≥32 random bytes
- [ ] `SECRET_KEY` separate from `JWT_SECRET`
- [ ] Default admin password changed within first 5 minutes of deploy
- [ ] MFA (TOTP) enrolled on every admin account before any other action
- [ ] Password policy thresholds reviewed (`PASSWORD_MIN_LEN`, lockout counts)
- [ ] Session timeout values match your security policy (`JWT_ACCESS_TTL_MIN`)
- [ ] Refresh token rotation enabled (default)
- [ ] OAuth/OIDC integration evaluated (roadmapped for 1.1)
- [ ] Service accounts use API keys (hashed at rest), never user credentials

### Authorization

- [ ] User roles assigned according to least privilege:
  - `viewer` for SOC analysts, auditors, executives
  - `analyst` for engineers who need to update assets and trigger scans
  - `admin` for platform owners only — minimize the count
- [ ] No shared accounts — every human gets a personal account
- [ ] Account deactivation policy documented (departing employees)
- [ ] Quarterly access review scheduled

### Network

- [ ] Caddy is the only host-exposed service (ports 80, 443)
- [ ] All other services on internal Docker network (`internal: true`)
- [ ] Firewall rules permit inbound 443 only from management subnet
- [ ] IP allowlist configured in `Caddyfile` (if not behind a VPN)
- [ ] WAF in front of Caddy for production internet exposure
- [ ] DNS records use CAA records pinning to your certificate authority
- [ ] No outbound NAT exceptions — Kepryx initiates all external connections via documented endpoints only

### Transport

- [ ] TLS 1.3 enforced (Caddy default)
- [ ] HSTS enabled; use `preload` only for a qualifying public domain with an intentional policy
- [ ] Certificate from public CA (Let's Encrypt) or your internal PKI
- [ ] No self-signed certs in production
- [ ] OCSP stapling enabled (Caddy default)
- [ ] If using managed DB: TLS to DB enforced (`?sslmode=require`)

### Secrets

- [ ] No secrets in code, no secrets in git history
- [ ] `.env` permissions restricted: `chmod 600 .env`
- [ ] `.env` excluded from backups that go offsite without encryption
- [ ] External KMS/secret delivery and key-rotation procedure defined for production
- [ ] Secret rotation procedure documented and tested
- [ ] Anthropic API key scoped to a project, not personal account
- [ ] NVD API key registered to a team email, not an individual

### Container security

- [ ] Images built from pinned base image digests, not `:latest`
- [ ] CI runs Trivy or Grype against every built image
- [ ] All Kepryx containers run as UID 10001 except scanner (`NET_RAW` needed)
- [ ] `cap_drop: [ALL]` on API; `cap_add` only what's documented
- [ ] `read_only: true` on API container; tmpfs for `/tmp` only
- [ ] `no-new-privileges: true` on all services
- [ ] Docker Bench Security scan passes
- [ ] No privileged containers
- [ ] Docker socket NOT mounted into any container

### Data protection

- [ ] PostgreSQL `pg_hba.conf` requires `scram-sha-256` (default in 16)
- [ ] Database encrypted at rest (managed services do this; for self-hosted, use LUKS/dm-crypt)
- [ ] Backup encryption (`gpg` or KMS) before storage
- [ ] Backup test restore performed at least quarterly
- [ ] PII minimization: only collect necessary user data
- [ ] Audit retention values match the approved policy; destructive deletion is explicitly enabled only after archive and restore validation
- [ ] Right-to-deletion procedure documented if subject to GDPR/CCPA

### Application

- [ ] `DEBUG=false` in production
- [ ] `/api/docs` disabled (only available with `DEBUG=true`)
- [ ] CORS origins whitelist matches your frontend domain only
- [ ] All API endpoints behind authentication except `/health`
- [ ] `/metrics` requires an admin JWT when accessed on the internal API network and is blocked at the proxy layer
- [ ] Rate limits tuned for legitimate load (default 200/min/IP)
- [ ] Input length caps on all string fields (enforced via Pydantic)

### Logging and audit

- [ ] All containers log to stdout (no in-container log files)
- [ ] Logs shipped to centralized SIEM
- [ ] Audit log retention configured per compliance requirement
- [ ] Alerts on suspicious patterns:
  - Failed login spikes
  - Admin role assignments
  - Settings changes
  - Integration credentials updates
  - Self-security update applications
- [ ] Log redaction confirmed: no secrets, no tokens, no PII in logs
- [ ] Time synchronization (chrony/ntpd) on host

### Monitoring

- [ ] Prometheus scraping configured
- [ ] Alert rules for:
  - API down for >2 min
  - Worker queue depth >1000
  - DB connection pool exhaustion
  - Failed integration runs >3 consecutive
  - Self-security critical findings
- [ ] On-call rotation defined
- [ ] Runbook entries for common alerts (see `OPERATING-NOTES.md`)

### Self-security and dependency hygiene

- [ ] Daily dependency scan enabled (`auto_scan_enabled: true`)
- [ ] AI validation required (`require_ai_validation: true`)
- [ ] Admin approval required (`require_admin_approval: true`) — at least for first 30 days
- [ ] Auto-rollback enabled (`auto_rollback_on_failure: true`)
- [ ] `excluded_packages` populated for packages that must never receive automated proposals
- [ ] Container image rescan in CI on every commit
- [ ] OSV.dev alerts configured to also fire externally (e.g., GitHub Dependabot on the repo itself)

### Compliance evidence

For SOC 2, ISO 27001, or PCI DSS audit support:
- [ ] Audit log queryable by date range and user (built-in)
- [ ] User access review report generated quarterly
- [ ] Change management evidence: every config change written to audit log
- [ ] Vulnerability management evidence: self-security findings + alerts
- [ ] Incident response: alerts → resolution timestamps via `/api/v1/alerts`
- [ ] Asset inventory completeness: cross-reference Kepryx's report against your CMDB

## Mapping to common frameworks

### CIS Controls v8

| Control | How Kepryx helps |
|---------|------------------|
| 1.1 Asset inventory | Core feature; multi-source reconciliation |
| 1.2 Unauthorized asset detection | Shadow IT detection alerts |
| 2.1 Software inventory | `software_stack` field per asset |
| 2.2 Software allowlist | Out of scope — Kepryx is detection, not enforcement |
| 4.1 Secure config baseline | Audit log of configuration state |
| 4.4 Default password change | Bootstrap forces password change |
| 5.1 Account inventory | Built-in user management |
| 5.3 Disabling dormant accounts | Manual via admin API |
| 6.3 MFA for admin | TOTP MFA available |
| 7.1 Vulnerability scanning | Nessus connector + self CVE scan |
| 7.5 Externally validated scan | Roadmap: independent scan attestation |
| 8.1 Audit log management | Built-in audit log with retention |
| 10.1 Anti-malware (EDR) | Inventory tracks EDR coverage |
| 11.1 Backup | `scripts/backup.sh` |
| 13.1 Network monitoring | nmap-based discovery |

### NIST CSF 2.0

| Function | How Kepryx helps |
|----------|------------------|
| **Identify** | Asset inventory, dependency mapping, compliance audit |
| **Protect** | Risk-prioritized remediation queue, control gap detection |
| **Detect** | Shadow IT alerts, drift detection, EDR gap detection |
| **Respond** | Notification pipeline, alert workflow, audit trail |
| **Recover** | Backup script, rollback for self-updates |
| **Govern** | RBAC, audit log, policy via admin settings |

### ISO 27001 Annex A

Built-in mappings for: A.5.9, A.5.10, A.8.1, A.8.9, A.12.6 (see `app/workers/compliance_tasks.py` for the exact rule logic).

## Incident response playbooks

### "Admin account compromised"

1. Disable the compromised account: `UPDATE users SET is_active=false WHERE username=...` directly in DB
2. Force-invalidate all sessions: rotate `JWT_SECRET` in `.env`, `docker compose restart api`
3. Review audit log for actions taken under compromised account
4. Rotate any connector credentials the admin had access to
5. Investigate compromise vector

### "Connector credentials leaked"

1. Disable the integration: `enabled=false` via API
2. Revoke the credential at the source (rotate AD password, revoke OAuth client, etc.)
3. Update Kepryx with new credentials
4. Re-test before re-enabling
5. Review audit log for unauthorized integration test/run actions

### "Self-security update broke the platform"

1. `POST /api/v1/self-security/proposals/{id}/rollback`
2. Verify `requirements.txt` reverted
3. `docker compose build api worker-* && docker compose up -d`
4. Confirm `/health` returns 200
5. Investigate why the AI validator approved a breaking update; update `excluded_packages`

### "Anomalous bulk operations"

1. Identify the source: query audit log filtered by user + timeframe
2. If automated client: examine API key permissions, rotate if needed
3. If human: contact the user, verify legitimacy
4. Consider lowering rate limits temporarily

## What this framework does NOT cover

- Endpoint security on the host running Kepryx (your problem)
- Physical access to the hardware
- Insider threat (audit log is detection, not prevention)
- Zero-day vulnerabilities in third-party deps (self-security mitigates but is reactive)
- Supply chain compromise of the Docker registry you pull from (pin digests + scan)
- Social engineering of operators (training is your problem)

A secure deployment is a continuous practice, not a one-time checklist. Re-audit every 90 days.
