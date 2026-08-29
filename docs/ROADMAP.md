# Kepryx roadmap

The roadmap is intentionally narrow. Shipping a useful community preview is more valuable than
claiming a complete enterprise platform without evidence.

## Now — v0.9.0 community preview

- Connected dark operator console served by Caddy.
- API-backed login, RBAC-aware navigation, inventory, risk, alerts, compliance, integrations,
  self-security, scans, audit, exports, webhooks, API tokens, GDPR, and administration.
- AI-assisted ingest, connector edit/test/sync, self-security settings/findings/proposal
  workflows, a deterministic vendor-neutral CSV inventory fixture, and a read-only Kepryx
  Assistant grounded in bounded live evidence.
- API contract tests, connector integration tests, clean install, image/dependency evidence,
  and private-first GitHub launch.

## Next — v0.9.x

- Fix issues found by design partners.
- Add DB-backed API integration and browser E2E coverage for the highest-value workflows.
- Improve pagination, error states, accessibility, and connector observability.
- Add retrieval-quality evaluations, per-user quotas, optional conversation retention controls,
  and an explicit human-confirmation workflow before considering any assistant action tools.
- Refresh base images and dependency locks continuously.

## Later — v1.0 candidates

- SSO and stronger session architecture after a documented threat-model review.
- Multi-tenant isolation only with a tested data-boundary design.
- Higher-coverage integration and browser E2E suites.
- Optional graph/attack-path workflows backed by executable data and tests.
- Operational packaging for supported cloud and on-prem environments.

## Explicitly not promised

- Security certification, guaranteed compliance, vendor certification, automatic source mutation,
  high availability, or support for every connector feature in v0.9.
