---
type: decision
status: accepted-for-v0.9
owner: Ahmad Almallah
confidence: high
evidence: [[../API-CONTRACT-V0.9|API contract]], assistant route/service, assistant unit tests, live local-Qwen browser smoke
next_verification: add retrieval-quality and adversarial evaluation cases before enabling any action tools
---
# Decision - Assistant safety boundary

Kepryx Assistant v0.9 is a read-only operator support feature, not an autonomous agent. The
server builds a bounded evidence packet from Kepryx data after authorization. Client-supplied
context is rejected. The packet excludes credentials, API tokens, MFA data, connector secrets,
raw audit details, and full exports.

The configured provider receives a provider-native system policy plus the question and evidence
as untrusted values. It must return a small validated JSON object. The API masks common
credential-shaped output, returns server-generated evidence references, rate-limits requests,
and records only query metadata in the audit log. AI answers never become authoritative facts;
operators verify them against the cited records.

No assistant workflow may create or edit assets, resolve or suppress alerts, trigger scans,
approve proposals, dispatch webhooks, change settings, or alter risk/vulnerability facts. Any
future action capability requires a separate threat-model review, explicit confirmation, narrow
scopes, idempotency, and a tested audit trail.
