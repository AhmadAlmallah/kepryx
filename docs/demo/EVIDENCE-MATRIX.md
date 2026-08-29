# Demo evidence matrix

This matrix keeps the public demo grounded in the current v0.9 implementation. “Proven” means
there is a checked-in test, live acceptance record, or repeatable local procedure. It does not
mean the feature is certified for every deployment.

| Demo claim | Operator surface | Evidence source | Current status | Boundary to state aloud |
|---|---|---|---|---|
| The service is reachable and ready | Login/dashboard | `/health`, `/ready`, clean-host record | Proven locally | Local HTTPS uses a test certificate; public DNS/ACME is not proven. |
| Inventory can be imported without a vendor account | Inventory → Import CSV | `demo/data/asset_inventory.csv`, import contract/tests | Proven | Fixture data is synthetic and uses reserved documentation ranges. |
| Observations are reconciled and source-labelled | Inventory/detail | reconciler, connector contract tests, source fields | Proven for preview paths | Real provider behavior still needs provider credentials and testing. |
| Risk is explainable | Risk Assessment/asset detail | risk engine tests and live Apache fixture enrichment | Proven | Score is a posture signal, not probability of compromise. |
| Vulnerability context is authoritative | Asset detail/CVE view | NVD, EPSS, CISA KEV evidence record | Proven for tested feeds | Feed availability and freshness are operational dependencies. |
| Relationship data is navigable | Dashboard graph | graph API + browser smoke | Proven for UI interactions | It is bounded inventory topology, not BloodHound attack-path analysis. |
| Compliance has traceable evidence | Compliance → run/control/lineage | migration `0007`, 442-result live run, SHA-256 evidence hashes | Proven for bundled subset | Not certification or legal advice; organization procedures still apply. |
| Self-security identifies dependency risk | Self-Security | OSV scan and proposal lifecycle | Proven for preview fixtures | Proposals are review-only; no unattended source mutation. |
| Discovery is authorization-bounded | Scans | `SCAN_NETWORKS`, synthetic authorization record, clean-test bridge | Proven in lab | Never use the demo CIDR as real network permission. |
| Alerts are actionable and auditable | Alerts/Audit Log | live generated alert, resolution, audit event | Proven for tested paths | Deep mutation, load, and long-running worker behavior remain test debt. |
| Webhooks can be verified | Webhooks/local receiver | HMAC delivery evidence | Proven locally | Endpoint ownership, secret rotation, and production egress need operational control. |
| Assistant can explain live posture | Kepryx Assistant | bounded packet, local Qwen3 acceptance | Proven as advisory path | The Assistant is read-only and is never the authority for security facts. |

## Evidence hierarchy

Use this order when answering a reviewer’s question:

1. **Live response or UI state** from the tested build.
2. **Persisted record** with source, timestamp, and audit/lineage reference.
3. **Automated test or QA command** that can reproduce the behavior.
4. **Documentation** explaining intent and limitations.

If the first three are absent, label the point as planned or unverified rather than demonstrating
it as complete.
