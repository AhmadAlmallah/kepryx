# Kepryx v0.9.0 demo script and speaker notes

This is an 8–10 minute, evidence-first walkthrough for the Kepryx community preview. It is
written for security engineers, platform engineers, and design partners who want to understand
both the product value and the engineering boundaries.

## Message to establish in the first 30 seconds

> Kepryx turns fragmented asset observations into a traceable security posture. The demo follows
> one observation from import, through reconciliation and authoritative vulnerability context, to
> risk, compliance evidence, alerting, and operator action. Synthetic data is used throughout.

Do not say “fully automated remediation”, “CVE-free”, “certified”, “enterprise-ready”, or “attack
path engine”. The release is an open-source v0.9.0 community preview.

## Recording setup

| Item | Value |
|---|---|
| Local URL | `https://kepryx.local:8443` |
| Demo source | `demo/data/asset_inventory.csv` |
| Optional source | local Asset Source mock under `demo/asset_source_mock/` |
| Scan proof range | `198.51.100.0/28` in the isolated clean-test network only |
| Data classification | synthetic/reserved documentation data |
| Starting state | disposable admin, seeded demo data, API banner reads **API connected** |
| Screen layout | browser at 1280px or wider; zoom 100%; hide terminal and credentials |

Before recording, run the preflight in [DEMO-RUNBOOK.md](../DEMO-RUNBOOK.md), confirm the health
and readiness endpoints, and verify that no `.env`, token, private certificate, or customer data
is visible. Capture the tested commit and timestamp in the recording notes.

## Storyboard

### 0:00–0:45 — Set the problem and the architecture

**Show:** [system context diagram](../diagrams/kepryx-system-context.svg).

**Say:** “Kepryx has a narrow job: reconcile observations, preserve provenance, enrich with
authoritative vulnerability facts, score transparently, and make the resulting posture
operational. Caddy is the only published edge; the API owns authorization; PostgreSQL holds
state; Redis and Celery process queued work. External feeds and connectors are inputs, not
authorities over the application.”

**Focus square:** point to the API-to-evidence boundary. Explain that the UI is an operator view,
not the security boundary.

### 0:45–1:45 — Login and operational posture

**Show:** [Dashboard screenshot](../images/product/dashboard.png).

**Do:** Sign in with the disposable bootstrap account. Point to the API-connected indicator,
asset totals, open alerts, latest scan, compliance summary, self-security status, recent changes,
and the relationship map.

**Say:** “This is a live API-backed view. Counts can change as workers finish; a queued operation
is not presented as completed. The map is a bounded inventory relationship view with three spatial
dimensions and observed time as the fourth dimension.”

**Focus area:** first the KPI strip, then the operational posture row, then the alert/recent
change panels. Do not spend more than 60 seconds here. The raw capture is supported by the
operator-focused caption in the [product gallery](../PUBLICATION/PRODUCT-GALLERY.md).

### 1:45–2:45 — Import a deterministic inventory source

**Show:** Inventory → Import CSV.

**Do:** Select `demo/data/asset_inventory.csv`. Run **Validate only (dry run)** first; show the
actual valid-row and error counts. Process the file only in the disposable demo environment.

**Say:** “This fixture contains synthetic assets and reserved documentation IPs. The same import
path is used for a real approved export; the fixture simply removes the need for vendor access.”

**Evidence to capture:** the dry-run response, then one processed asset with source metadata and
shadow-IT state. Never hard-code a count that was not observed in this run.

### 2:45–3:45 — Explain risk with evidence, not magic

**Show:** Risk Assessment, then the asset detail view.

**Do:** Open one high-risk synthetic asset. Expand the scoring breakdown and CVE evidence. If the
fixture includes the vulnerable Apache test asset, show the NVD/EPSS/KEV provenance and timestamp.

**Say:** “The score is a transparent weighted posture signal. It combines exposure, vulnerability
context, asset criticality, data classification, and confidence. A score is not a probability of
compromise. NVD supplies vulnerability records, FIRST EPSS supplies exploit-likelihood context,
and CISA KEV identifies catalogued exploited vulnerabilities; Kepryx records the source and does
not let the model invent those facts.”

**Focus square:** the score breakdown and the provenance fields. The important engineering point
is traceability from observation to decision.

### 3:45–4:45 — Show the 4D relationship map as an operator tool

**Show:** Dashboard → Inventory relationship map.

**Do:**

1. Filter to **Security findings**.
2. Choose **Risk clusters** or **Timeline layout**.
3. Click a node to focus its direct neighbors.
4. Drag a node in X/Y; Alt-drag it to change Z depth.
5. Pin one node, zoom in and out, then scrub or play the timeline.
6. Open the accessible node list as the deterministic fallback.

**Say:** “The controls are useful operator state: focus, direct-neighbor scope, layout, depth,
pinning, zoom, and time. They do not mutate inventory relationships. This is intentionally
bounded topology, not a BloodHound attack-path analysis.”

**Evidence to capture:** one focused node, one filtered state, and the time label. If the graph is
dense, use the node picker rather than zooming out until labels become unreadable.

### 4:45–6:00 — Turn observations into compliance evidence

**Show:** [Compliance screenshot](../images/product/compliance.png) and the
[evidence-lineage diagram](../diagrams/compliance-evidence-lineage.svg). Use the private
recapture listed in the [product gallery](../PUBLICATION/PRODUCT-GALLERY.md) only after it has
been regenerated with documentation-range data.

**Do:** Show the three framework summary cards. Open a completed run, select a control, inspect
its status and observed evidence, open lineage, and show the generated report action.

**Say:** “The bundled catalogs are a licensed-safe subset and an engineering aid, not a
certification engine. A result is graduated as compliant, partial, or gap when applicable. The
observed JSON is hashed, the source and timestamp are retained, and lineage connects the result
back to the asset observation. The report is useful because it preserves the evidence trail, not
because it replaces an auditor.”

**Focus area:** summary percentages first, then one control result, then the evidence/lineage
detail. Explain the difference between a posture percentage and assurance.

### 6:00–6:45 — Self-security and bounded AI assistance

**Show:** Self-Security and Kepryx Assistant.

**Do:** Show the dependency scan summary and one finding/proposal if present. Ask the Assistant:
“Which assets have open security alerts, and what evidence supports that?” Then ask a prompt that
requests a write action or secrets to demonstrate refusal.

**Say:** “OSV is used for platform dependency findings. Proposals are review-only and do not
mutate source code automatically. The Assistant receives a bounded, redacted evidence packet; it
can explain records but cannot run scans, change assets, resolve alerts, approve proposals, or
become the authority for CVE, EPSS, KEV, risk, or compliance facts.”

### 6:45–7:30 — Prove authorization and operations

**Show:** Scans, Alerts, Audit Log, and optionally a local webhook receiver.

**Do:** Show the authorized synthetic CIDR record, queue a scan if the isolated demo profile is
running, then show the resulting status. Resolve one generated alert and show the audit entry.
Optionally demonstrate a locally received signed webhook event.

**Say:** “Scanning is fail-closed. An empty allowlist blocks execution, and the worker rechecks
the boundary. The CIDR on screen is documentation-only TEST-NET-2 inside an isolated Docker
network; it is not approval to scan a real network. Alert resolution is an auditable operator
action, and webhook delivery is shown only as a local test.”

### 7:30–8:30 — Close with honest scope

**Show:** [benchmark and comparison](BENCHMARKS-AND-COMPARISON.md), then the limitations section.

**Say:** “The preview has executable evidence for the core path and hard security gates. It is
not pretending to have HA, enterprise SSO, production-scale load evidence, real-provider
certification, or a CVE-free image claim. The next value step is design-partner feedback on
onboarding, connector usefulness, evidence explainability, and operational recovery.”

## Recovery cues during recording

| If this happens | Say/do |
|---|---|
| A queued card remains pending | “This is the honest state boundary; refresh after the worker completes.” |
| No CVE result is available | Use the evidence already present; do not imply that no CVE exists. |
| The mock source is unavailable | Continue with the CSV fixture and state that the mock is optional. |
| The graph is visually dense | Apply a filter, use direct-neighbor focus, or open the accessible node list. |
| HTTPS certificate warning appears | Explain that this is the local test CA; production requires real DNS/ACME or an approved managed certificate. |
| Assistant provider is disabled | Show the bounded UI and state that AI is optional and fails closed when disabled. |

## Post-recording checklist

- Save the exact commit, image tags/digests, test evidence date, and demo profile.
- Keep the recording and raw exports outside the repository until reviewed.
- Redact credentials, bearer tokens, private certificates, customer data, and internal hostnames.
- Confirm all synthetic/mock behavior is labeled in the recording and captions.
- Add the final recording link only after it has been reviewed and approved for publication.
