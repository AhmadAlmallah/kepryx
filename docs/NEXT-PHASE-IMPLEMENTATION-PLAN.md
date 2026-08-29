# Kepryx v0.9 implementation and release plan

Status: connected UI/API slice complete; release evidence pending
Owner: Ahmad Almallah
Target: v0.9.0 community preview
Scope: connected API, operator UI, test evidence, and private-first GitHub launch

## Outcome

The next release should be a credible community preview that a reviewer can start,
authenticate to, inspect real API-backed inventory, follow risk evidence, exercise a
connector, and understand the remaining boundaries. It does not need every enterprise
feature or production HA capability.

The quality target is **80% release confidence**, not 80% line coverage. The target is
met only when the hard security gates pass and the core user journey is demonstrable.

## Current implementation baseline

Confirmed in the repository:

- FastAPI API with versioned routes for assets, alerts, integrations, scans, compliance,
  self-security, administration, exports, GDPR, tokens, webhooks, and WebSockets.
- PostgreSQL, Redis, Celery, Caddy, pinned Python dependencies, migrations, and hardened
  container defaults.
- A downloaded dark operator-console prototype that established the visual baseline but
  used a hard-coded API origin, unsafe dynamic HTML construction, and a non-functional
  asset-create path.
- A new dependency-free frontend under `frontend/` that uses the same console direction,
  same-origin requests, in-memory tokens, DOM text nodes, role-aware navigation, and the
  main read/action paths.
- A real `POST /api/v1/assets` contract and bounded alert pagination. Asset listing now
  aggregates CVE counts instead of issuing two queries per returned asset.

Still requiring evidence before a public release:

- Full API integration tests against a clean PostgreSQL/Redis stack.
- A deterministic connector/demo fixture and a repeatable ingest-to-risk walkthrough.
- Clean-install and backup-restore rehearsal.
- Final dependency and image scans against the exact release images.
- GitHub repository settings, private vulnerability reporting, peer review, and a signed
  release tag.

## Release scope

### P0: must work for v0.9

1. **Runtime delivery**
   - Caddy serves `frontend/index.html`, `frontend/app.js`, and `frontend/styles.css` from
     the immutable image.
   - `/api/*` and `/ws/*` remain same-origin reverse-proxied routes.
   - CSP permits only the shipped local script and stylesheet; no inline script, inline
     style, `eval`, or raw HTML rendering is used by the new UI.

2. **Authentication and session behavior**
   - Login, optional MFA code, refresh-token rotation, logout, and role-aware navigation
     work through the existing API.
   - Tokens remain memory-only in the preview. No `localStorage`, `sessionStorage`, or
     API-token credentials are used by the browser.
   - The server remains the authorization authority; UI hiding is only usability.

3. **Core operations**
   - Dashboard summary and admin status where the role permits it.
   - Asset search, detail, risk breakdown, CVE evidence, manual create, control updates,
     and enrichment queueing.
   - Alert list and resolve action.
   - Risk queue, compliance summary/audit trigger, integration registration/test/sync,
     self-security summary/proposals, scan history/network configuration, audit log, and
     basic user administration.

4. **Ground-truth verification**
   - Ruff, format, import checks, unit tests, secret scan, `docker compose config`, image
     scan, fresh migrations, health/readiness, authentication failure paths, and a browser
     smoke test all pass.
   - API integration tests prove the core route matrix for viewer, analyst, and admin.

### P1: useful, but not a release blocker

- Rich filtering, CSV export controls, Webhook administration, API-token administration,
  GDPR export/erasure screens, compliance control detail, and a bounded inventory relationship
  visualization. Neo4j-backed attack-path analysis remains deferred.
- Better pagination UX and server-side sorting for very large inventories.
- A dedicated BFF with HttpOnly refresh cookies and an explicit CSRF design.

### P2: defer until external users create demand

- SAML/OIDC, multi-tenancy, HA deployment, agent management, automatic source mutation,
  arbitrary AI actions, and broad enterprise workflow customization.

## Workstreams and acceptance criteria

| ID | Workstream | Acceptance evidence | Dependency |
|---|---|---|---|
| W1 | API/UI contract | Route-contract snapshot; 2xx and 4xx tests for login, assets, alerts, integrations, scans, compliance, and self-security | None |
| W2 | Frontend runtime | Same-origin Caddy smoke; browser login shell; no unsafe DOM APIs; CSP and WebSocket checks | W1 |
| W3 | Data path | Manual asset create, connector test/run, reconciliation, enrichment queue, risk summary, and alert path verified against clean DB | W1 |
| W4 | Demo fixture | Isolated deterministic fixture marked simulated; repeatable ingest and shadow-IT result; no real secrets or vendor branding claims | W3 |
| W5 | Reliability | Unit suite, API integration suite, migration-upgrade suite, backup/restore, and failure-path checks | W3 |
| W6 | Release security | Secret scan, `pip-audit --strict`, image scan, SBOM, base-image review, Compose boundary review, and final claims review | W2-W5 |
| W7 | Community launch | Private repository review, security reporting, DCO/governance files, signed tag, release notes, and issue templates | W6 |

## Execution order

1. Fix any P0 API contract or role mismatch found by integration tests.
2. Rebuild API and Caddy images; run the API/UI smoke path through Caddy.
3. Add the deterministic demo fixture and record the operator workflow.
4. Run fresh migrations, seed only synthetic data, exercise backup/restore, and archive
   the evidence.
5. Run the release-security gates against the exact image digests.
6. Push to a private GitHub repository, complete one peer review, then publish the
   community preview.

## Stop conditions

Pause the release if any of the following is true:

- A high/critical fixable dependency or image finding is present.
- Secrets or real connector credentials are present in source, fixtures, logs, screenshots,
  or git history.
- Login, role enforcement, migrations, webhook signing, SSRF controls, or token revocation
  fail their tests.
- The dashboard displays success for an operation that is only queued or simulated.
- A destructive UI action lacks explicit confirmation, audit evidence, and a documented
  recovery path.

## Definition of done

Kepryx is ready for the public preview when a fresh operator can start it from the README,
create an admin, log in through the shipped console, inspect seeded or connector-ingested
assets, understand a risk result, exercise one queued action, and reproduce the verification
commands. The README must state that this is a community preview and identify every known
production boundary.
