# v0.9.0 Pre-Public Checklist

## Repository and disclosure

- [ ] Stage only canonical source; exclude local remediation scripts, archives, backups, and reports.
- [ ] Confirm `.env`, keys, certificates, database dumps, and local QA artifacts are not tracked.
- [ ] Run the tracked-file secret gate and review every allowlisted test fixture.
- [ ] Configure a real GitHub repository URL and CI badges only after the repository exists.
- [ ] Review `docs/GITHUB-REPOSITORY-SETUP.md` and configure the private-first repository settings.
- [ ] Confirm `CITATION.cff`, `.gitattributes`, issue configuration, and release template are present.
- [ ] Enable GitHub Private Vulnerability Reporting and a monitored security contact.
- [ ] Review Apache-2.0 attribution, authorship, contribution, and conduct files.

## Release gate

- [ ] `python -m pip install --require-hashes -r requirements-dev.txt`
- [ ] On Windows, run the Python gate in WSL2 or use the Docker/CI path; native Windows does not
      support the locked `uvloop` dependency pulled by `uvicorn[standard]`.
- [ ] `make verify`
- [ ] `pytest -q --cov=app --cov-fail-under=50` reports the current test count and coverage.
- [ ] `docker compose config --quiet`
- [ ] Clean build of API, workers, scanner, Caddy, and PostgreSQL succeeds.
- [ ] Raw Trivy reports zero HIGH/CRITICAL findings in all release images, including unfixed
      advisories (`--ignore-unfixed=false`); do not rely on an allowlist or a stale scan.
- [ ] Verify the exact external SBOM and Trivy artifacts against
      `docs/security-artifacts/RELEASE-ARTIFACT-MANIFEST-2026-08-28.md` with
      `pwsh scripts/verify-release-artifacts.ps1 -SbomDirectory <path> -TrivyDirectory <path>`.
- [ ] Empty PostgreSQL upgrades through migration head and `alembic check` reports no drift.
- [ ] Live probes cover health/readiness, rejected Host headers, hidden docs, auth, MFA, refresh,
      API tokens, exports, multipart import, WebSocket tickets, and Caddy's `/metrics` block.
- [ ] Backup and restore are exercised on a clean host.
- [ ] The demo follows the production connector wire protocol without presenting mock data as real.
- [ ] Use `docs/demo/DEMO-SCRIPT.md`, the focused screenshot overlays, and the diagrams for the
      recording; verify the benchmark values against the exact candidate instead of copying an
      older snapshot.

## Honest scope review

- [ ] README and release notes say **v0.9.0 community preview**, not production-ready or v1.0.
- [ ] The opt-in Prometheus image is rescanned before use.
- [ ] Known limits include single tenancy, static UI, incomplete integration/E2E/load/failover testing,
      and the absence of autonomous source mutation.
- [ ] Screenshots and metrics are reproducible and do not expose customer or local-environment data.

## Publish safely

- [ ] Push to a private GitHub repository first and require green CI.
- [ ] Obtain at least one independent code/security review.
- [ ] Enable branch protection, CodeQL, Dependabot, secret scanning, and push protection.
- [ ] Review `.github/CODEOWNERS` and confirm `@AhmadAlmallah` is the intended owner.
- [ ] Re-run the release gate from the exact candidate commit.
- [ ] Create signed tag `v0.9.0` and publish the changelog only after the checks above pass.

Do not flip the repository public while disclosure routing, secret scanning, or the clean-host
deployment/restore exercise is incomplete.
