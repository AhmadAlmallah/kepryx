# Screenshot and diagram plan

The visuals are designed to explain one idea at a time. Use a visible focus box or circle, a short
caption, and descriptive alt text. Do not publish a screenshot that contains credentials, tokens,
real customer data, or an unauthorized target.

## Visual sequence

| Order | Asset | Focus area | Caption | Alt text |
|---:|---|---|---|---|
| 1 | `../images/dashboard-evidence.png` | Actual Dashboard: summary cards, relationship map, alerts, and recent changes | “The actual Kepryx operator view connects inventory, risk, alerts, graph exploration, and audit activity.” | “Actual dark Kepryx dashboard showing asset posture, live API status, 4D relationship map, open alerts, and recent changes.” |
| 2 | `../images/compliance-evidence.png` | Actual Compliance: framework posture and control-evidence table | “The percentage is only the summary; the control-evidence table is where an engineer starts the review.” | “Actual Kepryx compliance screen showing CIS, ISO, and NIST posture cards and observed control evidence.” |
| 3 | `../images/dashboard-focus.svg` | Product behavior in the Dashboard capture | “The annotated focus areas show where the operator reads posture, operates the graph, and follows alerts.” | “Branded annotation frame around the Kepryx dashboard posture cards, relationship map, alerts, and audit activity.” |
| 4 | `../images/compliance-focus.svg` | Evidence and lineage in the Compliance capture | “The annotated view highlights the framework summary and the evidence chain behind a control result.” | “Branded annotation frame around Kepryx compliance posture and the control-evidence table.” |
| 5 | `../diagrams/kepryx-breach-to-evidence-loop.svg` | Visibility gap to evidence loop | “A forgotten or weak asset is a visibility problem before it becomes a clean risk decision.” | “Flow from phishing, open ports, misconfiguration, and forgotten infrastructure to inventory, risk, evidence, and response.” |
| 6 | `../diagrams/ingest-risk-flow.svg` | Observe → normalize → reconcile → enrich → score | “The critical path separates source observations from computed decisions.” | “Kepryx flow from source observation through normalization, reconciliation, authoritative vulnerability enrichment, risk, and operator outputs.” |
| 7 | `../diagrams/compliance-evidence-lineage.svg` | Result → evidence → asset | “A percentage is the summary; the evidence snapshot and lineage are the explanation.” | “Compliance lineage from framework catalog and control definition to asset observation, hashed evidence, result, and report.” |
| 8 | `../diagrams/kepryx-deployment-security-boundaries.svg` | Caddy edge and internal services | “The public edge is narrow; durable state and task traffic stay internal.” | “Kepryx deployment boundary showing browser, Caddy, FastAPI, PostgreSQL, Redis, workers, scanner, and approved egress.” |
| 9 | `../images/release-scorecard-chart.svg` | 82/100 and community/governance gap | “The release score is evidence-based and intentionally not a claim of production perfection.” | “Kepryx v0.9 scorecard with 82 of 100 and the largest remaining gap in community governance.” |

## Focus-box rules

- Use blue boxes for product behavior, green boxes for authoritative evidence, amber dashed boxes
  for the explanation/focus area, and red boxes only for the problem or risk condition.
- Keep one visual message per image. If a screenshot has too many controls, crop or use a focus
  overlay rather than shrinking the entire interface.
- Add a sentence after every visual that explains why the highlighted area matters to an engineer.
- For the interactive graph, use a separate demo post or screen recording later. The article should
  explain the feature without pretending a static screenshot proves the interaction.

## Screenshot capture procedure

1. Start the local stack using the deployment guide.
2. Log in with a locally generated admin credential; never use a documented password.
3. Load the dashboard after the current seed/import flow is complete.
4. Capture the dashboard and compliance views with synthetic/reserved data only.
5. Keep the Kepryx wordmark, navigation, API status, and product context in the frame; do not crop
   the interface so tightly that the screen could be mistaken for a generic chart.
6. Apply the existing focus overlays and confirm the counts in the caption match the evidence date.
7. Inspect the image at 100% for secrets, IP scope, personal data, browser tabs, and stale claims.
8. Run the tracked-file secret scan after adding any image or publication file.

## Brand treatment

- Use the product name as `Kepryx` and the descriptor `Asset Intelligence & Risk Platform` on first
  mention.
- Keep the existing dark navy, blue, green, amber, and red semantic palette from the console. Blue
  identifies product behavior, green identifies evidence or healthy state, amber identifies a focus
  area, and red identifies risk.
- Use the raw PNG screenshots for product proof. Use the SVG focus assets as explanation plates or
  export them to PNG before uploading if the publishing platform does not render SVG reliably.
- Never add the author's email, credentials, API keys, real customer names, or unauthorized scan
  ranges to a screenshot. Ahmad Almallah remains the author; the product branding stays Kepryx.
