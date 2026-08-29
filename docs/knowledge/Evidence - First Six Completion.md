---
type: evidence
status: complete-for-preview
owner: Ahmad Almallah
confidence: medium
evidence: 63 passing tests, Ruff, mypy, Bandit, pip-audit, detect-secrets hook, Compose validation, clean-host virtual-CIDR scan, live HTTPS/UI probes, rebuilt Caddy edge scan, Asset Source connector failure paths, proposal lifecycle, dashboard graph, and frontend bundle smoke
next_verification: record the full ingest-to-risk-to-webhook demo, perform a real DNS/ACME HTTPS smoke test, and complete private-first GitHub review
---
# Evidence - first six completion

The first six priorities are implemented and verified to community-preview scope:

1. The v0.9 functional contract and explicit non-goals are documented in [[../API-CONTRACT-V0.9|API-CONTRACT-V0.9]].
2. Core API health/readiness, headers, host validation, CORS, and anonymous route denial have executable tests; 63 tests pass in a clean-room run.
3. The supported CSV bulk-import path has a deterministic vendor-neutral fixture under `demo/data/asset_inventory.csv`; vendor connector contract tests remain separately isolated.
4. The repository test target and CI now run the full test tree, including integration tests.
5. Bandit, pip-audit, dependency pinning, container boundaries, and the tracked-file secret-scan hook pass for the current staged source.
6. The frontend exposes AI ingest, integration edit/enable, self-security settings/findings/suppression, and proposal reject/rollback workflows; the rebuilt localhost edge serves the login bundle with the expected CSP.
7. The dashboard now exposes API-backed operational signals and a bounded projected 4D inventory relationship map with an accessible node-list fallback. Local browser route smoke covers all 15 operator views, graph filters/layouts, time scrubbing/playback, zoom/reset, and pause interactions.
8. The vendor-neutral Asset Source connector is exercised against a deterministic fixture for success, 503/429 retry, timeout exhaustion, and invalid-credential rejection. A live deterministic OSV fixture completed proposal approval, non-mutating patch preparation, rollback, and rejection.

This is not a claim that public DNS/ACME HTTPS, exhaustive browser mutation coverage, restore operations
beyond the isolated smoke test, HA, or real vendor behavior are complete. The Caddy upstream Go
residual and those operational gates remain release evidence tasks.

Links: [[Finding - Reliability and Integration Test Debt]], [[Finding - Missing Deterministic Demo Evidence]], [[Release Gate - V0.9 Community Preview]]
