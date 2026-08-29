# Kepryx v0.9 release scorecard

This scorecard measures release confidence for an open-source community preview. It is a
decision aid, not a security certification and not a substitute for the hard gates below.

## Weighted score

| Area | Weight | Current evidence-based estimate | v0.9 target |
|---|---:|---:|---:|
| Security and supply chain | 25 | 24 | 23 |
| Demonstrable product value | 25 | 22 | 21 |
| Reliability and testing | 20 | 18 | 15 |
| Documentation and onboarding | 15 | 13 | 13 |
| Community and governance | 15 | 5 | 10 |
| **Total** | **100** | **82** | **82** |

The current estimate is conservative. It recognizes the connected operator console, deterministic
connector and OSV proposal evidence, expanded API/worker/scanner tests, raw clean image scans,
route-level and graph-mutation browser coverage, passing unit/security/toolchain gates, hardened backend, locked
Python dependencies, and migrations. It still discounts the score for incomplete browser mutation
E2E, real-provider evidence, production backup/restore operations beyond the isolated smoke test,
and the fact that the GitHub repository has not yet completed its private-first launch controls.
The target is above 80 without pretending that v0.9 is enterprise production software.

## Scoring rules

### Security and supply chain — 25

- 5: no accidental secrets; complete hash-locked dependency graph; strict dependency scan;
  fixable high/critical image findings blocked; pinned bases; non-root/read-only defaults.
- 5: authentication, RBAC, rate limits, token revocation, MFA, CORS/hosts, CSP, SSRF,
  webhook signing, and audit logging have executable evidence.
- 5: image SBOM and exact scan output archived for the release.
- 5: residual vendor-unfixed findings and demo/mock behavior are disclosed.
- 5: release process has peer review and a security contact.

### Demonstrable product value — 25

- 10: a reviewer can start, log in, inspect inventory, understand risk, and resolve an alert.
- 5: at least one connector path is proven against a deterministic or approved test source.
- 5: the UI and API show the same state, including queued versus completed operations.
- 5: the demo is reproducible without real customer data or credentials.

### Reliability and testing — 20

- 5: unit tests cover risk, password, security, scan authorization, and core helpers.
- 5: API integration tests cover auth/RBAC and the P0 route matrix.
- 5: clean migrations, clean install, health/readiness, and an isolated backup/restore smoke test
  are proven.
- 5: browser smoke and representative connector/proposal failure-path checks are repeatable.

### Documentation and onboarding — 15

- 5: README quick start works on a clean host.
- 5: deployment, operating, security, integration, and QA notes match observed behavior.
- 5: limitations, simulated data, and recovery paths are explicit.

### Community and governance — 15

- 5: Apache-2.0, authorship, contribution, code of conduct, and security reporting are clear.
- 5: private-first review, branch protection, CI, Dependabot, CodeQL, DCO, and issue templates
  are configured.
- 5: signed release tag, changelog, release notes, and a feedback loop are published.

## Hard gates

The weighted score cannot override these gates:

- No known unreviewed fixable high or critical dependency/image vulnerability at release time;
  explicitly accepted upstream residuals must be documented and gated.
- No real secrets in the working tree, fixtures, screenshots, or release history.
- Clean migration upgrade, API auth/RBAC tests, token revocation, and health/readiness pass.
- Caddy serves the exact frontend bundle with the intended CSP and same-origin API routing.
- The demo labels simulated behavior and does not claim vendor certification.
- Private vulnerability reporting and one peer review are complete before public visibility.
