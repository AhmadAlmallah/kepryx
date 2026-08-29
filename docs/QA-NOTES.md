# QA Notes

Kepryx uses executable evidence as the release gate. Documentation and a healthy container alone
are not accepted as proof.

## Automated gate

- Ruff lint and formatting
- mypy application type checking
- pytest unit regressions with coverage output
- Python compilation and application import
- Alembic upgrade from an empty PostgreSQL database plus model/schema drift check
- Bandit medium/high SAST gate
- pip-audit against the hash-locked runtime set
- tracked-file secret detection
- clean builds of API, worker, scanner, Caddy, and PostgreSQL images
- non-root/no-pip/no-gosu runtime assertions
- Trivy gates for fixable high/critical findings plus explicit reporting of vendor-unfixed risk

Run locally with:

```bash
python -m pip install --require-hashes -r requirements-dev.txt
make verify
docker compose config --quiet
```

## Manual evidence completed for this preview candidate

- Clean-host deployment, migration, login, UI/API, HTTPS, and isolated database restore smoke test
- Vendor-neutral CSV import, risk, compliance, self-security, and authorized reserved-CIDR scan
  proof using an isolated Docker bridge
- Live asset create/update lifecycle, NVD/EPSS/KEV enrichment, compliance audit execution,
  generated compliance-gap and EDR-gap alerts, alert resolution, scoped `X-API-Key` access and
  revocation, and signed webhook delivery/resolution events
- Local browser route smoke for all 16 operator views, including the branded Assistant,
  dashboard graph filtering/pause controls,
  OSV fixture proposal approval/rollback/rejection, and Asset Source connector 503/429/timeout/
  invalid-credential paths
- Live auth edge cases covered MFA enrollment/confirmation, invalid and missing MFA codes,
  refresh rotation/replay rejection, invalid refresh tokens, and valid post-MFA login.
- Live API failure paths returned the expected validation and authorization responses for malformed
  JSON, empty request bodies, missing assets, unauthenticated Assistant access, and an unauthorized
  scan CIDR. A cancelled worker scan was recovered on the next run as an explicit failed job.
- Synthetic scan authorization is recorded in `docs/SCAN-AUTHORIZATION-RECORD.md`; no customer
  CIDR is authorized by this preview record.
- Live evidence-compliance acceptance completed after migration `0007_evidence_compliance`:
  three framework catalogs, 13 seeded control definitions, a completed run over 34 assets,
  442 results, linked evidence with 64-character SHA-256 hashes, lineage retrieval, and a
  12 KB compliance PDF response were verified through the HTTPS edge.
- Local Ollama/Qwen3 compliance AI review returned a schema-valid suggestion with
  `review_only=true` and `authoritative=false`; the result status was verified unchanged after
  the call. No AI-generated text is persisted as assessment evidence.
- Final exact-candidate gate rerun on 2026-08-28 after the evidence-compliance, SSRF/edge, and
  coverage remediations: 154 tests passed with 63.54% measured application coverage. Ruff
  lint/format, mypy, Bandit, strict pip-audit, and tracked-file secret detection passed. Fresh
  sequential Trivy scans of all ten first-party release images, including the custom Caddy
  binary and pinned Alpine Python runtime, found zero HIGH/CRITICAL findings with unfixed
  advisories visible. Current CycloneDX SBOMs were regenerated for the ten primary release
  images outside the repository.
- Final edge-route review verified `/health` and `/ready` return `200`, disabled documentation
  paths (`/docs`, `/redoc`, `/openapi.json`, and API variants) plus `/metrics` return `404`, all
  six configured HTTPS security headers are present, and the direct API port is not published.
- Webhook SSRF regression coverage verifies global-only IP destinations, rejects URL credentials,
  blocks shared-address DNS results, and rechecks legacy IP-literal records at dispatch time.
- All three Caddy profiles validate; the clean-host profile now denies `/metrics` and wildcard
  documentation paths before the SPA fallback.
- Browser mutation evidence now covers the live graph filter/layout/node-picker/focus workflow,
  X/Y drag, Alt-drag Z-depth, pin/unpin, zoom, timeline playback, and reset behavior; see
  [Browser Mutation Evidence](BROWSER-MUTATION-EVIDENCE.md).

## Remaining manual evidence before public release

- Additional browser E2E for multipart import, exports, GDPR, and compliance drill-down
- Additional browser-driven multipart, export, and GDPR mutation checks are useful follow-up
  evidence; the core API mutation/error paths are now covered by executable tests in
  `tests/integration/test_api_mutations.py`.
- Full external connector synchronization with real vendor credentials and provider-specific
  behavior; the vendor-neutral connector boundary and its retry/fail-closed behavior are proven
  without requiring third-party credentials
- Hosted-provider behavior remains an optional provider-specific path to test when credentials
  are supplied; the local Ollama/Qwen3 review-only path is verified for this preview.
- Manual browser verification remains for the enhanced compliance catalog/run/lineage controls
  and the advisory AI review modal; API and static served-file checks are complete.
- A written customer-owned CIDR authorization for any real deployment; the synthetic preview
  authorization and worker cancellation/recovery proof are complete
- Screen recording of the vendor-neutral CSV demo with synthetic/reserved data clearly labeled

## Remaining test debt

The measured 63.54% application coverage is materially better than the previous 40% but is not a
production-tested claim. Remaining priorities are browser mutation E2E, connector contract tests
against real providers, migration tests against representative legacy data, load and soak tests,
and failure-injection exercises beyond the isolated backup/restore smoke test. The new executable
coverage includes asset/alert/scan/integration/self-security API mutations, scanner parsing and
authorization, CVE enrichment, reconciliation, connector contracts, and worker retry policies.

Security-impacting defects must follow `SECURITY.md`, not a public issue.

The latest checked evidence and residual findings are recorded in
[REMEDIATION-EVIDENCE.md](REMEDIATION-EVIDENCE.md).
