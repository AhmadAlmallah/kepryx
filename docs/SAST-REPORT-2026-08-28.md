# Kepryx SAST and supply-chain report

Evidence date: 2026-08-28 | Candidate: staged v0.9.0 community preview

## Executive result

The code and dependency gates passed for the staged candidate. The result is strong enough for a
community preview, with the normal limitation that static analysis and an image scan cannot prove
the absence of every logic, deployment, or future supply-chain issue.

## Exact-candidate gate

| Tool or control | Scope | Result |
|---|---|---|
| Ruff | Application and tests | PASS: lint and formatting clean |
| mypy | 69 application source files | PASS: no issues |
| Bandit | Application and demo code, 9,845 lines | PASS: no medium/high findings |
| pytest + coverage | Unit/integration suite | PASS: 120 tests; 53.63% application coverage |
| pip-audit --strict | Hash-locked Python runtime set | PASS: no known vulnerabilities |
| detect-secrets-hook | Staged tracked files | PASS: no findings |
| Alembic | Empty upgrade/model drift | PASS: head `0007_evidence_compliance`; no drift |
| Docker Compose | Resolved configuration | PASS |
| Trivy 0.67.2 | Nine rebuilt first-party images; HIGH/CRITICAL; unfixed visible | PASS: 0/0/0 per image |
| Syft 1.51.1 | Nine rebuilt first-party images | PASS: CycloneDX SBOM generated per image |

## Image scan register

| Image family | High | Critical | Fixable |
|---|---:|---:|---:|
| API | 0 | 0 | 0 |
| Worker enrich | 0 | 0 | 0 |
| Worker recon | 0 | 0 | 0 |
| Worker self-security | 0 | 0 | 0 |
| Worker scanner | 0 | 0 | 0 |
| Beat | 0 | 0 | 0 |
| Custom Caddy | 0 | 0 | 0 |
| PostgreSQL | 0 | 0 | 0 |
| Asset Source mock | 0 | 0 | 0 |

The Caddy image is built from pinned Go/Alpine inputs with explicit module versions. Python service
images use a pinned Alpine base. The gate is a raw result and does not hide vendor-unfixed findings
behind an allowlist. Future base-image drift is addressed by the weekly rebuild/rescan workflow.

## SAST interpretation

Bandit and Ruff reduce common Python defects and consistency problems. mypy catches type-contract
drift. pip-audit covers known Python package advisories in the resolved runtime. Trivy covers known
OS/package vulnerabilities in the built images. Syft gives the release an inventory of components.
None of these replaces authorization review, abuse-case testing, browser mutation testing, provider
contract tests, or operational recovery testing.

## Artifact handling

The nine SBOM JSON files and raw Trivy JSON outputs were generated in the external working area
`C:\Temp\kepryx-sbom-2026-08-28\` and `C:\Temp\kepryx-trivy-2026-08-28-final\` to avoid mixing machine-specific scan output into the application source. Their hashes and image IDs are
recorded in [the release artifact manifest](security-artifacts/RELEASE-ARTIFACT-MANIFEST-2026-08-28.md).
Use `scripts/verify-release-artifacts.ps1` before attaching the exact files to the private GitHub
release review. Regenerate them from the exact release commit if the image digest, lock file, or
tool version changes.

## Residual SAST and supply-chain risks

- A passing point-in-time scan is not a permanent “CVE-free” status.
- Static checks do not prove tenant isolation, business authorization, or safe operator choices.
- Coverage is 53.63%, so unexecuted branches remain.
- The old orphan containers on the local Docker host are outside the canonical image set and were
  not included in release claims.

## Sign-off recommendation

Keep this report with the v0.9.0 preview evidence. Re-run all gates after any source, dependency,
Dockerfile, Compose, or CI change. A release reviewer should record the exact commit, image digests,
tool versions, and artifact hashes before public publication.
