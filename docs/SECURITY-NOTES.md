# Security Notes

## Trust boundaries

```text
untrusted client -> Caddy edge -> FastAPI -> PostgreSQL / Redis
                                      |
                                      +-> segregated workers -> approved external targets
```

The Docker host, key-delivery mechanism, and management network are trusted. Connector endpoints,
uploaded data, CVE sources, webhook destinations, browser input, and scan targets are untrusted.

## Implemented controls

- Argon2 password hashing and password policy enforcement
- Distinct required application, JWT, and encryption keys
- JWT issuer/audience/required-claim/type checks; short access tokens; rotating refresh tokens;
  Redis JTI revocation; active-user checks
- MFA failure lockout and encrypted MFA seeds
- Role checks plus scope-limited, hashed API tokens
- Single-use 30-second WebSocket tickets and origin checks
- Explicit Host/CORS/proxy trust, management CIDR enforcement for privileged operations, security
  headers, CSP hashes, and edge metric blocking
- Pydantic validation, ORM parameterization, CSV formula neutralization, bounded exports, and eager
  loading for async ORM safety
- Connector URL/TLS/cron validation, blocked metadata/non-global IP literals unless explicitly
  allowlisted, deployment egress requirements for hostnames, encrypted connector secrets,
  credential rotation, and legacy plaintext disablement
- HMAC webhook signing, global-only outbound destination validation, URL-credential rejection,
  DNS-rebinding checks, and dispatch-time legacy-record revalidation
- Audit IP sizing, PII redaction/hashing, retention jobs, GDPR transactional confirmation, and
  last-admin protection
- Destructive retention is disabled by default; archival markers do not prove external cold-storage
  export, so operators must verify export and restore before enabling deletion
- Non-root read-only application images, no runtime pip, minimal scanner capabilities, internal
  data networks, a fixed trusted-proxy address, and migration-before-startup ordering
- Hash-locked dependencies, SAST, dependency CVE, secret, migration, and image gates in CI
- Read-only assistant boundary: provider-native system policy, bounded server-side retrieval,
  no client-supplied context, prompt-injection handling, credential-shaped output masking,
  Redis-backed source-IP throttling, and audit events without prompt/answer content

## Deliberate limitations

- The Compose stack is a single-host baseline, not HA.
- Internal container traffic is not mutually authenticated or encrypted.
- Application-level key rotation needs an operator runbook and re-encryption procedure.
- Prometheus is opt-in and must pass a current image scan; Grafana and Neo4j-backed attack-path
  services are not bundled. The dashboard relationship map is bounded, API-backed, and not a
  substitute for a graph database or BloodHound analysis.
- The scanner can emit raw packets to reachable networks. API validation and worker execution both
  enforce `SCAN_NETWORKS` plus a host-count limit; egress segmentation remains mandatory.
- AI-assisted parsing sends operator-submitted data to the configured provider and must remain off
  where contracts or residency controls do not permit it.
- The Kepryx Assistant sends a bounded evidence packet and the operator question to the explicitly
  configured provider. It does not receive connector secrets, tokens, MFA data, raw audit details,
  or full exports. It is advisory and read-only; provider output can still be incorrect or
  manipulated, so operators must verify claims against the cited Kepryx records. A local Ollama
  provider reduces third-party data transfer but does not remove model-risk or host-trust risk.
- Exact server-derived counts and status values are returned separately as verified_facts; the
  UI displays them independently of AI prose. Common count paraphrases are corrected against the
  same snapshot, but this is defense in depth rather than a proof of answer correctness.
- Assistant requests are source-IP rate-limited at 20 per minute and audited by event type and
  message length only. The endpoint fails closed when its Redis rate-limit check is unavailable.
- Single tenancy means separate deployments are required for separate trust domains.
- Compliance mappings support evidence collection; they do not establish certification.

## Production controls outside the repository

Use enterprise secret delivery or KMS, management-plane VPN/firewall policy, hardened hosts,
central SIEM ingestion, monitored alerting, encrypted off-host backups, tested restores/failover,
independent penetration testing, privacy review, and incident/rotation runbooks before production
exposure.

The v0.9.0 posture is materially hardened but not production-certified.

## Container CVE gate

The release candidate uses pinned Python 3.12 Alpine bases with `apk upgrade` and a custom Caddy
2.11.4 build using Go 1.26.6 plus explicit fixed `x/net`, `x/text`, and gRPC module versions.
Sequential raw Trivy 0.67.2 scans on 2026-08-29 reported zero HIGH/CRITICAL findings for the
API, all workers, scanner, beat, Caddy, PostgreSQL, and Asset Source images. The former Caddy
allowlist was removed so CI now fails on any newly reported finding.

This is a point-in-time result, not a permanent CVE-free guarantee. The weekly rebuild/rescan
workflow and the pre-release exact-candidate scan are required because upstream advisories and
base image contents change.
