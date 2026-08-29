# Kepryx v0.9 API and operator contract

This document freezes the supported community-preview behavior. It is an implementation
contract for the API, workers, and operator console; it is not a claim of production
certification or vendor integration certification.

## Supported v0.9 journey

1. Bootstrap an administrator without a repository-stored password.
2. Authenticate with username/password and optional MFA.
3. View an API-backed inventory and risk summary.
4. Create, update, search, enrich, and export assets.
5. Import the included vendor-neutral CSV fixture or reconcile an approved connector source.
6. Surface risk, CVE/EPSS/KEV evidence, shadow-IT indicators, and alerts.
7. Resolve alerts and record the action in the audit log.
8. Run compliance and self-security checks as queued, auditable operations.
9. Ask the optional read-only Kepryx Assistant about the current evidence-backed posture.
10. Manage scoped API tokens, signed webhooks, exports, and personal-data controls.

Compliance intelligence is exposed through `GET /api/v1/compliance/frameworks`,
`GET /api/v1/compliance/runs`, `GET /api/v1/compliance/runs/{run_id}`, and
`GET /api/v1/compliance/results/{result_id}/lineage`. A completed audit creates one run,
deterministic control results, and source-labelled evidence snapshots whose canonical observed
JSON is identified by SHA-256. Results can be `compliant`, `partial`, `gap`, `exception`,
`not_assessed`, or `not_applicable`; the current deterministic worker produces the first three
as applicable to asset observations. The compatibility `/api/v1/compliance` projection remains
available for existing clients and includes run, result, confidence, and evidence references.

`POST /api/v1/compliance/results/{result_id}/ai-review` is advisory and review-only. It receives
bounded control metadata and evidence, returns a suggested status, rationale, confidence, and
evidence gaps, and records an audit event. It never writes the result or becomes an authority.
The compliance PDF prefers the latest completed assessment run and includes framework/version,
graduated status counts, evidence coverage, and a bounded traceability table.

The dashboard overview is available at `GET /api/v1/dashboard/overview` and returns normalized
summary, scan, self-security, compliance, alert, and redacted recent-activity signals. The
bounded inventory relationship view is available at
`GET /api/v1/dashboard/graph/inventory?limit=220`; it labels asset, segment, source, dependency,
alert, and CVE nodes with evidence source and observation timestamps. The frontend projects those
three spatial dimensions and uses the observed timestamp as a fourth, time dimension for scrubbing
and playback. The frontend supports click-to-focus on a node, direct-neighbor or selected-only
scopes, node picking from a keyboard-accessible list, X/Y dragging, Alt-drag Z-depth adjustment,
pinning, and resettable layouts. These controls are local view state and do not change the API
graph. The graph is an operator visualization, not a Neo4j/BloodHound attack-path analysis.

The assistant endpoint is `POST /api/v1/assistant/chat` for viewer, analyst, and admin roles.
The request body is `{ "message": "..." }` with a maximum length of 4,000 characters. The
server retrieves a bounded, redacted packet from aggregate inventory/risk data, recent alerts,
the latest scan, compliance summaries, self-security summaries, and explicitly requested
NVD/EPSS/CISA KEV CVE records. The client cannot submit its own evidence packet. Responses
include the answer, abstention flag, provider/model label, and server-generated evidence
references. The endpoint is limited to 20 requests per source IP per 60 seconds and returns
`503 Service Unavailable` when the configured provider is disabled or unavailable.
Responses also include a verified_facts list rendered directly from the same server snapshot;
these values are the trusted display of counts/statuses, while the model prose remains advisory.

The assistant is deliberately read-only. It cannot call Kepryx tools, run scans, mutate assets,
resolve alerts, approve proposals, or make risk decisions. User input and stored record values
are treated as untrusted prompt data; credentials, tokens, connector secrets, MFA data, raw
audit details, and full exports are excluded from the model packet. AI output is guidance only.

Service tokens are presented in the `X-API-Key` header. `Authorization: Bearer` is reserved for
browser JWT sessions. AI ingestion is optional: with `AI_PROVIDER=ollama`, the API uses the
configured local Ollama model; hosted OpenAI-compatible and Anthropic providers are also
supported when explicitly configured. If the provider is disabled or unavailable, AI ingestion
returns `503 Service Unavailable` with an actionable configuration message; it does not silently
create records or return an opaque server error.

## Role contract

| Capability | Viewer | Analyst | Admin |
|---|---:|---:|---:|
| View inventory, risk, alerts, compliance | Yes | Yes | Yes |
| Create/update/enrich assets | No | Yes | Yes |
| Import assets from CSV | No | Yes | Yes |
| Resolve alerts | No | Yes | Yes |
| Trigger scans and compliance audits | No | No | Yes |
| Configure integrations and webhooks | No | No | Yes |
| Manage users, tokens, and audit log | No | No | Yes |
| Export personal data / request erasure | Own account | Own account | Any authorized account via API |

The API remains the authorization authority. UI navigation is only a usability aid and is
not a security boundary.

## Evidence contract

- A queued operation must be displayed as queued; the UI must not claim completion until a
  worker or API result confirms it.
- Connector data must be labeled by source and reconciled through the same production code
  path as real integrations.
- AI output is a normalization aid only. It may propose asset fields and CPEs, but it is not an
  authoritative vulnerability or risk source and cannot write CVE, EPSS, KEV, or final risk
  values directly.
- Asset vulnerability facts are enriched from NVD, EPSS, and the CISA KEV catalog. Platform
  dependency findings are queried from OSV. Provider responses and timestamps remain part of
  the evidence chain; an AI-generated claim is never treated as evidence by itself.
- The CSV fixture is synthetic test data using reserved documentation ranges. It does not
  represent customer data, vendor certification, or a live network source.
- Compliance assessments and mappings are evidence aids and do not constitute certification or
  legal advice. The bundled framework metadata is a licensed-safe subset; operators must load
  or reference the applicable organization-approved framework content and procedures.
- Self-security prepares reviewable dependency proposals; v0.9 does not mutate source code
  automatically.
- Assistant answers are not evidence. Only the server-generated references and the underlying
  Kepryx records can be used as evidence, and the assistant must abstain when the packet is
  insufficient.

## Explicitly deferred

- SAML/OIDC enterprise SSO.
- Multi-tenant isolation and high-availability deployment.
- Neo4j-backed graph attack-path workflows.
- Automatic source mutation or unattended dependency upgrades.
- Full connector feature parity and production certification for external vendors.

## Release acceptance

The v0.9 preview is acceptable only when the documented test commands, API contract tests,
simulated connector walkthrough, security gates, and clean-start migration checks pass. Any
unverified integration, production TLS problem, image advisory, or recovery limitation must
remain visible in the release notes.
