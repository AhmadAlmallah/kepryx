# Kepryx demo materials and shot list

This is the single materials index for the recording, article, and follow-up review. Use the
material that matches the scene; do not use an image as proof of a workflow that was not executed.

## Primary shot list

| # | Scene | Material | Status | Caption to use |
|---:|---|---|---|---|
| 1 | Opening | [System context diagram](../diagrams/kepryx-system-context.svg) | Ready | “The API owns the application boundary; sources provide observations and provenance.” |
| 2 | Dashboard | [Dashboard capture](../images/product/dashboard.png) | Preview capture | “A local API-backed operational posture view.” |
| 3 | Import | Live Inventory → Import CSV | Live path | “Validate the source before processing it.” |
| 4 | Inventory | A current live capture after the import | Recapture before publishing | “The asset record is useful only when its source and freshness are visible.” |
| 5 | Risk | [Risk assessment capture](../images/product/risk-assessment.png) and [risk-weights graphic](../diagrams/risk-scoring-weights.svg) | Ready | “Risk is explainable and bounded by visible factors.” |
| 6 | Relationships | [Relationship map](../images/workflows/relationship-map.png) | Preview capture | “Relationships add context; this is not a complete attack graph.” |
| 7 | Compliance | [Evidence lineage](../images/workflows/compliance-evidence-lineage.png) | Ready | “A control result can be traced to observed asset evidence.” |
| 8 | Compliance AI | [Advisory AI review](../images/workflows/compliance-ai-review.png) | Ready | “AI guidance is advisory and does not change the record.” |
| 9 | Self-security | [Self-security capture](../images/product/self-security.png) | Preview capture | “The platform can inspect its own dependency posture locally.” |
| 10 | Scans | [Scans capture](../images/product/scans.png) | Preview capture | “Discovery is shown only within an authorized isolated test network.” |
| 11 | Alerts and audit | [Alerts](../images/product/alerts.png) and [audit log](../images/product/audit-log.png) | Preview captures | “Operational findings and changes remain visible to the operator.” |
| 12 | Integration | NetBox or FleetDM provider screen plus the Kepryx run record | Conditional | “Live provider collection” only after current Test and Sync evidence. |
| 13 | Close | [Ingest-to-risk flow](../diagrams/ingest-risk-flow.svg) | Ready | “The value is the connected evidence chain, not another isolated dashboard.” |

## Software intelligence flow

The software feature is a bounded local demonstration path:

1. Import [`software-inventory.csv`](../../demo/data/software-inventory.csv) from the Software view.
2. Use the dry run first to show schema validation and rejected-row visibility.
3. Process the file and show the parent solution `Future`, its components, installed/latest status,
   and the open vulnerability table.
4. Open the Log4j component finding to show the CPE-to-NVD path, then show the KEV and EPSS evidence
   recorded on the finding and the corresponding software alert.
5. Trigger **Scan now** and show the scan run status. The daily scheduler repeats the same check.

The demo vulnerability source is a local synthetic snapshot. It proves the request, parsing,
matching, persistence, and alerting path; it must be described as fixture-backed evidence, not as a
live NVD, EPSS, CISA KEV, or OSV result.

## Optional supporting material

- [Compliance evidence lineage diagram](../diagrams/compliance-evidence-lineage.svg) for the evidence
  transition.
- [Release scorecard chart](../images/release-scorecard-chart.svg) only with its date and source
  clearly stated.
- [Administration](../images/product/admin.png), [webhooks](../images/product/webhooks.png),
  [privacy](../images/product/privacy-gdpr.png), and [API tokens](../images/product/api-tokens.png)
  for a separate security-boundary section, not the main story.
- [Product gallery](../PUBLICATION/PRODUCT-GALLERY.md) for the complete capture index and public
  image rules.

## Captures that must be recaptured before being advertised as complete

The current gallery explicitly identifies these gaps:

- current login screen;
- current Inventory screen using the current fixture;
- current Asset detail for the selected mail/server and database examples;
- AI-assisted ingest;
- Asset creation;
- alert investigation and resolution sequence.

If these are not recaptured in the current build, leave them out of the public article and use the
live screen only when the workflow is executed during the recording.

## Image rules for public use

- Use synthetic or reserved documentation data only.
- Prefer the dark Kepryx captures with readable labels and no browser chrome.
- Crop out terminals, local paths, credentials, tokens, and unrelated tabs.
- Add a one-sentence caption that explains the evidence or operator action.
- Do not present a connector catalog, static screenshot, or diagram as proof of a live provider pull.
- Do not use a screenshot with stale counts to support a current metric.

## Article and social use

For the Medium article, use the system-context diagram early, the risk-weights graphic after the
risk explanation, and the evidence-lineage capture before the closing section. For LinkedIn, use one
strong hero image—prefer the dashboard or system-context visual—and link to the walkthrough instead
of attaching a screenshot collage.
