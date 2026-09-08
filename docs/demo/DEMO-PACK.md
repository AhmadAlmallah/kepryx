# Kepryx v0.9.0 demo pack

This is the producer brief for a public Kepryx demonstration. It keeps the recording focused on
one evidence chain instead of turning it into a tour of every screen:

> An asset is observed, reconciled, enriched, scored, traced to evidence, and made useful to an
> operator.

The audience is security leadership, security engineers, platform engineers, and potential
contributors. The tone should be practical and direct. Kepryx is a community preview, not a
claim of enterprise certification or production scale.

## The 8–10 minute story

| Time | Scene | What the audience should understand |
|---|---|---|
| 0:00–0:45 | Problem and system context | A security decision is only as good as the asset observations behind it. |
| 0:45–1:45 | Dashboard | Kepryx connects inventory, risk, alerts, compliance, and operations in one local view. |
| 1:45–2:45 | CSV dry run and import | A vendor-neutral inventory source can be validated, normalized, and reconciled. |
| 2:45–3:45 | Risk and vulnerability context | Risk is a bounded, explainable posture signal with visible contributing factors. |
| 3:45–4:45 | Relationship map | Relationships provide context; this is not an attack-path engine. |
| 4:45–6:00 | Compliance evidence lineage | A result can be traced back to observed asset evidence and its rationale. |
| 6:00–6:45 | Self-security and Assistant | Local package findings and AI guidance are useful, but AI remains advisory. |
| 6:45–7:30 | Scan and authorization boundary | Discovery is explicitly authorized and isolated; blocked targets stay blocked. |
| 7:30–8:30 | Integrations and limitations | The demo distinguishes live provider pulls, local contracts, snapshots, and pending work. |
| 8:30–10:00 | Close and questions | Invite technical review: what would the viewer verify first? |

Use [DEMO-SCRIPT.md](DEMO-SCRIPT.md) for the exact speaker notes and operator actions. The
recommended message is: “Kepryx turns fragmented asset observations into a traceable security
posture.”

## Demo profile

The main recording uses the resource-constrained profile in [LOCAL-LAB-PLAN.md](LOCAL-LAB-PLAN.md):

- one Windows host running the Kepryx Docker stack;
- synthetic inventory with 37 assets and deliberately visible shadow candidates;
- a local Asset Source fixture using the real connector and reconciliation path;
- local response-shape snapshots for vulnerability enrichment;
- two harmless virtual scan targets on an isolated Docker test network;
- optional local Ollama assistance;
- no customer data, credentials, paid enterprise platform, or internet dependency during the core
  walkthrough.

Start and verify it with:

```powershell
python .\demo\generate_full_dataset.py
pwsh -NoProfile -File .\demo\Run-Demo.ps1
pwsh -NoProfile -File .\demo\Preflight-Demo.ps1
pwsh -NoProfile -File .\demo\Collect-DemoEvidence.ps1
```

The application URL is `https://kepryx.local:8444`. The evidence manifest is local and ignored by
Git. It records commit, fixture, service, health/readiness, and timing metadata; it is not a
credential export.

## What to call live, simulated, or pending

| Area | Honest wording for the recording |
|---|---|
| CSV import, reconciliation, risk, compliance, alerts, audit, UI | “This is a live local Kepryx workflow.” |
| Asset Source | “This uses the real connector protocol against a local vendor-neutral fixture.” |
| NVD, EPSS, CISA KEV, and OSV | “This demo uses repeatable local response-shape snapshots; it is not a fresh feed pull.” |
| Discovery | “This is a real scan worker against two authorized local containers on an isolated test network.” |
| FleetDM | “This is a live endpoint-management inventory pull” only after a successful provider test and sync. Do not call it EDR. |
| NetBox | “This is a live network inventory source-of-truth pull” only after a successful provider test and sync. It is not packet monitoring. |
| Wazuh, Elastic, Snort | Not native integrations in this demo. Do not imply that they were tested. |
| AI assistant | “Restricted local advisory guidance grounded in Kepryx evidence.” |
| Compliance | “Traceable control evidence and assessment support,” not certification. |
| Risk score | “A bounded posture signal,” not probability of breach. |

The real-provider procedure is in [REAL-INTEGRATION-LAB.md](REAL-INTEGRATION-LAB.md). If a provider
was not tested in the recording session, label it **pending validation** rather than showing a
connector catalog entry as proof.

## Materials order

Use [DEMO-MATERIALS.md](DEMO-MATERIALS.md) as the shot list. The shortest useful sequence is:

1. system-context diagram;
2. dashboard;
3. CSV dry run and one reconciled asset;
4. risk assessment and risk-weights graphic;
5. relationship map;
6. evidence-lineage capture;
7. self-security and Assistant;
8. scans and alerts;
9. optional provider evidence;
10. limitations and contribution path.

Use only the product captures indexed by [PRODUCT-GALLERY.md](../PUBLICATION/PRODUCT-GALLERY.md).
The gallery marks stale or missing captures. Do not replace a missing current capture with an old
inventory screenshot just to make the pack look complete.

## Before, during, and after the recording

- Before: follow [DEMO-CHECKLIST.md](DEMO-CHECKLIST.md), confirm the tested commit, and record the
  active profile.
- During: keep one browser window, 100% zoom, no terminal or secrets visible, and pause after
  each evidence transition.
- If a live call is slow: use the deterministic fixture and say that the provider path is
  optional. Do not improvise a successful result.
- After: save the redacted manifest, transcript, exact date/time, tested commit, and any deviations
  in [RECORDING-NOTES-TEMPLATE.md](RECORDING-NOTES-TEMPLATE.md).

## Safe close

“Kepryx is not finished, and this demo does not pretend otherwise. The point is to make the asset
and evidence chain inspectable: run it locally, challenge the assumptions, and improve the parts
that matter to your environment.”

For reviewer questions and approved answers, use [DEMO-QA-AND-CLAIMS.md](DEMO-QA-AND-CLAIMS.md).
