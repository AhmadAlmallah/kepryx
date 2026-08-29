---
type: decision
status: accepted-for-v0.9
owner: Ahmad Almallah
confidence: high
evidence: supplied prototype and current Caddy/API contracts
next_verification: after remaining UI-only mutation paths and the next scheduled clean-image rescan
---
# Decision - connected UI architecture

For v0.9, Kepryx uses a dependency-free static frontend under `frontend/`, served by the Caddy
image from the same origin as the API. This preserves the supplied dark operator-console baseline
without introducing a Node runtime or a new frontend dependency graph.

The browser keeps access and refresh tokens in memory only. API authorization remains server-side.
Dynamic API values are written with DOM text nodes rather than `innerHTML`. The Caddy CSP permits
only local scripts/styles and same-origin WebSocket connections.

The dashboard adds a bounded API-backed relationship map rendered with native canvas projection and
an accessible node-list fallback. It provides practical 4D exploration by combining three spatial
dimensions with observed-time scrubbing/playback, plus risk, timeline, topology, and evidence-layer
layouts. Operators can click a node to focus its direct neighborhood, drag nodes in X/Y, Alt-drag
their Z depth, pin important positions, and reset the layout. These are local view-state operations;
they do not mutate inventory relationships. It visualizes inventory provenance and security findings;
it does not claim to provide Neo4j-backed BloodHound attack-path analysis.

A BFF with HttpOnly refresh cookies is a possible v1 decision, but it requires a separate CSRF and
session threat-model review.

Links: [[../NEXT-PHASE-IMPLEMENTATION-PLAN|implementation plan]], [[../RELEASE-SCORECARD|scorecard]]
