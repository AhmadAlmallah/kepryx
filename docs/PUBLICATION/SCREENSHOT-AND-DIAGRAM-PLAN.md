# Screenshot and diagram plan

The release visuals are organized in the [product gallery](PRODUCT-GALLERY.md). The rule is
simple: one visual should explain one operator decision, and every screenshot must be backed by
synthetic or explicitly authorized data.

## Public visual sequence

| Order | Asset | Focus area | Message |
|---:|---|---|---|
| 1 | `../images/product/dashboard.png` | Posture cards, map, alerts, recent changes | Kepryx connects inventory and daily risk operations. |
| 2 | `../images/product/assistant.png` | Bounded evidence explanation | The Assistant explains evidence without becoming an authority or write path. |
| 3 | `../images/product/risk-assessment.png` | Score breakdown and remediation queue | The risk result is a transparent posture signal, not a probability of compromise. |
| 4 | `../images/product/compliance.png` | Framework cards and control evidence | The percentage is a summary; evidence and lineage explain the result. |
| 5 | `../images/workflows/relationship-map.png` | Filter, node focus, layout, depth, and time | The map is an interactive bounded topology tool, not a static hero graphic. |
| 6 | `../images/workflows/compliance-evidence-lineage.png` | Result → evidence → asset | A reviewer can trace a control status to an observed asset value. |
| 7 | `../diagrams/kepryx-breach-to-evidence-loop.svg` | Visibility gap to evidence loop | Forgotten, exposed, or misconfigured assets create an inventory problem first. |
| 8 | `../diagrams/ingest-risk-flow.svg` | Observe → normalize → reconcile → enrich → score | Source observations are kept distinct from computed decisions. |
| 9 | `../diagrams/kepryx-deployment-security-boundaries.svg` | Caddy edge and internal services | The public edge is narrow; durable state and task traffic remain internal. |
| 10 | `../images/release-scorecard-chart.svg` | Evidence-based preview score | The score describes this candidate, not permanent production maturity. |

## Focus and annotation rules

- Use the raw product screenshots for product proof; describe the focus area in the caption.
- Use the technical diagrams for architecture and evidence-chain explanations.
- Do not use the retired dashboard/compliance focus overlays in the public repository.
- Keep one message per image. Do not shrink a busy screenshot until labels become unreadable.
- Use blue for product behavior, green for authoritative evidence, amber for operator focus, and
  red only for a problem or risk condition.
- Every caption must state when data is synthetic, documentation-only, or local-preview evidence.

## Capture procedure

1. Start the local stack using the deployment guide.
2. Log in with a disposable locally generated account; never use a documented password.
3. Load the dashboard after the import, enrichment, and audit flows complete.
4. Use reserved documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`)
   for screenshot data unless a target is explicitly authorized and isolated.
5. Keep the Kepryx wordmark, navigation, API status, and product context visible.
6. Capture Login and a completed alert-investigation/resolution workflow; both are still missing
   from the supplied set.
7. Refresh and recapture Self-Security after the current dependency scan, and recapture vendor-neutral
   Inventory data if the article is making a vendor-neutral positioning claim.
8. Inspect each image at 100% for secrets, internal identities, private ranges, stale counts, and
   browser chrome that exposes a local environment.
9. Run the tracked-file secret scan after the final image set is selected.

## Brand treatment

Use `Kepryx` and the descriptor `Asset Intelligence & Risk Platform` on first mention. Keep the
dark navy operator-console baseline and its semantic blue/green/amber/red palette. The author name
is Ahmad Almallah; do not place the author's email or any credential in a screenshot or sample.
