# Kepryx product gallery

This is the complete screenshot index for the Kepryx v0.9.0 community preview. The captures
come from the locally running operator console and are intended to show product behavior, not a
design mockup. All values must remain synthetic before this repository becomes public.

## README hero set

Use these four images in the README and the first part of the Medium article:

1. [Dashboard](../images/product/dashboard.png) — posture, alerts, activity, and relationship map.
2. [Kepryx Assistant](../images/product/assistant.png) — bounded, read-only evidence explanation.
3. [Risk Assessment](../images/product/risk-assessment.png) — transparent risk posture and remediation queue.
4. [Compliance](../images/product/compliance.png) — framework summaries and control evidence.

## Product views

| View | Asset | Evidence purpose | Publication status |
|---|---|---|---|
| Login | Not supplied | Authentication entry point | **Missing — capture before publication** |
| Dashboard | [`dashboard.png`](../images/product/dashboard.png) | Operational posture, recent changes, alerts, and map | Review synthetic data, then publish |
| Kepryx Assistant | [`assistant.png`](../images/product/assistant.png) | Bounded, read-only answer grounded in application evidence | Publish after final prompt/data review |
| Inventory | Not included | Reconciled asset inventory and source context | **Recapture vendor-neutral data before publication** |
| Alerts | [`alerts.png`](../images/product/alerts.png) | Alert triage queue and severity context | Publish after final synthetic-data review |
| Risk Assessment | [`risk-assessment.png`](../images/product/risk-assessment.png) | Risk posture and remediation prioritization | Publish after count/date verification |
| Compliance | [`compliance.png`](../images/product/compliance.png) | CIS, ISO, and NIST posture summaries | Publish as an assessment aid, not certification |
| Integrations | [`integrations.png`](../images/product/integrations.png) | Connector registration surface | Publish; keep the screen empty or synthetic |
| Self-Security | Not included | Dependency and application security posture | **Refresh and recapture against current scan before publication** |
| Scans | [`scans.png`](../images/product/scans.png) | Authorized network discovery status and failure history | Publish only with synthetic/authorized label |
| Audit Log | [`audit-log.png`](../images/product/audit-log.png) | Operator actions and provenance | Publish after synthetic identity review |
| Admin | [`admin.png`](../images/product/admin.png) | User and administration surface | Publish after synthetic identity review |
| Exports | [`exports.png`](../images/product/exports.png) | Evidence/export operations | Publish after synthetic-data review |
| API Tokens | [`api-tokens.png`](../images/product/api-tokens.png) | Token lifecycle with prefixes only | Publish; never show a bearer token |
| Webhooks | [`webhooks.png`](../images/product/webhooks.png) | Webhook delivery configuration | Publish with placeholder endpoint only |
| Privacy & GDPR | [`privacy-gdpr.png`](../images/product/privacy-gdpr.png) | Export, erasure, and privacy controls | Publish after synthetic-data review |
| My Security | Not included | Current-user security posture | **Recapture with synthetic identity and correct MFA state before publication** |

## Workflow evidence

| Workflow | Asset | What to explain | Publication status |
|---|---|---|---|
| Relationship map | [`relationship-map.png`](../images/workflows/relationship-map.png) | Filter, focus, layout, and time exploration | Publish with interaction caveat |
| Assistant authoritative response | [`assistant-authoritative-response.png`](../images/workflows/assistant-authoritative-response.png) | Read-only answer using bounded evidence | Publish with advisory/AI caveat |
| Asset detail: mail | Not included | Asset context and vulnerability evidence | **Recapture vendor-neutral data before publication** |
| Asset detail: database | [`inventory-asset-detail-database.png`](../images/workflows/inventory-asset-detail-database.png) | Database asset context | Publish after synthetic-data review |
| AI-assisted ingest | [`inventory-ai-ingest.png`](../images/workflows/inventory-ai-ingest.png) | Proposed normalization path | Publish as a proposal, not an automatic write |
| Asset creation | [`inventory-create-asset.png`](../images/workflows/inventory-create-asset.png) | Create-asset form and validation surface | Publish as a form workflow, not completed evidence |
| Compliance assessment run | [`compliance-assessment-run.png`](../images/workflows/compliance-assessment-run.png) | Deterministic assessment execution and status | Publish after run ID/date review |
| Compliance evidence lineage | [`compliance-evidence-lineage.png`](../images/workflows/compliance-evidence-lineage.png) | Result → evidence → asset traceability | Publish with synthetic documentation-range data |
| Compliance AI review | [`compliance-ai-review.png`](../images/workflows/compliance-ai-review.png) | Advisory review of a control result | Publish with advisory caveat |
| Add integration | [`integration-add.png`](../images/workflows/integration-add.png) | Connector configuration boundary | Publish only with placeholders |
| Self-security settings | [`self-security-settings.png`](../images/workflows/self-security-settings.png) | Scan schedule and proposal policy | Publish after current-policy review |
| Authorized scan network | Not included | Allowlist and exclusions | **Recapture with reserved documentation CIDR** |
| Add user | [`admin-add-user.png`](../images/workflows/admin-add-user.png) | Role and identity administration | Publish only with synthetic identity |
| Create API token | [`api-token-create.png`](../images/workflows/api-token-create.png) | Token creation boundary | Publish only if no token value is shown |
| Register webhook | [`webhook-register.png`](../images/workflows/webhook-register.png) | Event and severity filters | Publish only with placeholder endpoint |
| Privacy retention | [`privacy-retention.png`](../images/workflows/privacy-retention.png) | Retention and anonymization policy | Publish after policy/date review |
| Alert investigation and resolution | Not supplied | Triage, resolve, and audit trail | **Missing — capture before publication** |

## Technical diagrams

Keep these diagrams in `docs/diagrams/`; they are separate from product screenshots:

- [System context](../diagrams/kepryx-system-context.svg)
- [Ingest to risk flow](../diagrams/ingest-risk-flow.svg)
- [Compliance evidence lineage](../diagrams/compliance-evidence-lineage.svg)
- [Deployment security boundaries](../diagrams/kepryx-deployment-security-boundaries.svg)
- [Breach-to-evidence loop](../diagrams/kepryx-breach-to-evidence-loop.svg)
- [Release scorecard](../images/release-scorecard-chart.svg)

## Publication gate

Before using any image in a public README, article, or social post:

- confirm every account, email, hostname, IP range, token, URL, and connector value is synthetic;
- replace private-looking addresses with `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`
  when the value is not needed to explain the product;
- remove vendor-specific sample data when the article is making a vendor-neutral positioning claim;
- refresh Self-Security and any count-based view against the exact release candidate;
- capture the missing Login and Alert investigation/resolution workflows;
- inspect each PNG at 100% and run the tracked-file secret scan after the final recapture.

The former focus-overlay SVGs and the five captures requiring recapture are deliberately not part of
the public repository. They were moved to
`C:\Data\NextGenInve\private-publication-assets\kepryx\` for private article editing only.
