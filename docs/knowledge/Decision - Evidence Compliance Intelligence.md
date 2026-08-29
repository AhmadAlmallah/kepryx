---
type: decision
status: accepted-for-v0.9
owner: Ahmad Almallah
confidence: high
evidence: migration 0007, live assessment run, lineage API, PDF, and local AI review smoke
next_verification: browser drill-down E2E and organization-specific framework evidence import
---
# Decision - evidence and compliance intelligence

Kepryx compliance remains an engineering posture aid, not a certification engine. The
versioned catalog stores framework identifiers, versions, short objectives, publisher links,
and transparent deterministic asset-observation rules. Normative framework text is not copied
into the open-source repository.

The evidence chain is:

`framework/version -> control -> assessment run -> deterministic result -> evidence snapshot -> SHA-256 integrity reference`

Assessment results support graduated statuses (`compliant`, `partial`, `gap`, `exception`,
`not_assessed`, and `not_applicable`). The current worker deterministically produces compliant,
partial, or gap based on asset observations and preserves the existing compliance mapping as a
compatibility projection. A later organization workflow may add approved exceptions, owners,
due dates, retests, and closure evidence.

AI is review-only. The local Ollama/Qwen3 path may suggest a status, rationale, or evidence gap
from bounded control metadata and evidence, but the deterministic result remains authoritative;
the AI endpoint does not persist output or mutate result, risk, alert, or exception state.

Links: [[../API-CONTRACT-V0.9|API contract]], [[../QA-NOTES|QA notes]], [[Decision - Assistant Safety Boundary]]
