---
type: decision
status: accepted-for-v0.9
owner: Ahmad Almallah
confidence: high
evidence: [[../API-CONTRACT-V0.9|API contract]], frontend routes, API contract tests, and connector fixture test
next_verification: review with a design partner after the first recorded demo
---
# Decision - v0.9 functional contract

Kepryx v0.9 is an honest single-tenant community preview. The supported journey is bootstrap,
authenticated operator access, asset inventory and reconciliation, transparent risk/CVE/KEV
evidence, alerts, compliance evidence, scoped integrations, self-security review workflows,
exports, webhooks, GDPR controls, and the connected same-origin console.

The contract deliberately defers enterprise SSO, multi-tenant isolation, HA, Neo4j-backed
graph/attack-path operations, vendor certification, and automatic source mutation. The dashboard
relationship map is a bounded 4D inventory visualization (three spatial dimensions plus observed
time), not an attack-path engine. Queued work is reported as queued until a worker completes it;
demo fixture data is always synthetic and clearly labeled.

The optional Kepryx Assistant is a branded, read-only support surface. It receives only a bounded
server-built evidence packet and a sanitized question, returns validated structured output, and
exposes server-generated evidence references. It cannot execute actions or author vulnerability,
risk, compliance, or scan results. Provider-disabled or provider-failure behavior is an explicit
503, not a fabricated fallback answer.

Links: [[Release Gate - V0.9 Community Preview]], [[Decision - Connected UI Architecture]], [[../API-CONTRACT-V0.9|API contract]]
