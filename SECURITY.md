# Security Policy

## Supported versions

| Version | Status |
|---|---|
| 0.9.x | Community-preview security fixes |
| Earlier snapshots | Unsupported |

## Report a vulnerability

Do not open a public issue. Use GitHub Private Vulnerability Reporting in the repository's
Security tab. The maintainer must enable private reporting and configure a monitored security
contact before making the repository public; until then, public release is blocked.

Include the affected version or commit, impact, reproducible steps, relevant environment details,
and whether you want public credit. Do not include real customer data or credentials.

The project aims to acknowledge reports within 72 hours and provide an initial assessment within
seven days. Remediation timing depends on severity, exploitability, and available safe fixes; these
are targets, not a contractual SLA. Coordinated disclosure is preferred.

There is no bug bounty. Good-faith research that avoids privacy violations, persistence, data
destruction, denial of service, and third-party systems is welcome.

## In scope

- Authentication, authorization, token, MFA, and API-token failures
- Credential exposure, SSRF, injection, unsafe exports, and cross-tenant assumptions
- Supply-chain or dependency issues that affect a supported Kepryx deployment
- Container, proxy, Compose, migration, webhook, and connector weaknesses
- Material gaps between documented security behavior and executable behavior

Reports that only identify an upstream CVE should explain the reachable Kepryx impact when
possible. Dependency findings are not automatically out of scope.

## Operator boundary

Kepryx assumes a patched, trusted Docker host and a dedicated management network. Operators are
responsible for approved TLS, access restrictions, external secret delivery, connector privilege
minimization, key rotation, SIEM integration, backup/restore testing, and authorized scan targets.

Kepryx is single tenant and v0.9.0 is not production-certified. See
[Deployment](docs/DEPLOYMENT.md) and [Security notes](docs/SECURITY-NOTES.md).

## Current release-image evidence

The v0.9.0 candidate uses pinned Alpine Python layers and a custom Caddy 2.11.4 build with pinned
Go/module inputs. Sequential raw Trivy 0.67.2 scans on 2026-08-29 reported zero HIGH/CRITICAL
findings for the API, workers, scanner, beat, Caddy, PostgreSQL, and Asset Source images, with
unfixed findings visible. The release gate does not rely on an image vulnerability allowlist.

Kepryx does not claim to be permanently CVE-free. Image contents and upstream advisories change;
the weekly rebuild/rescan workflow and the exact-candidate scan are required before every release.
The full scope, toolchain gates, current remediation status, and residual deployment risks are
recorded in the [security remediation record](docs/SECURITY-REMEDIATION-2026-08-29.md),
[QA notes](docs/QA-NOTES.md), and [technical architecture](docs/TECHNICAL-ARCHITECTURE.md).

Primary maintainer: Ahmad Almallah. Security contact: ahmad.almallah.consulting@hotmail.com.
