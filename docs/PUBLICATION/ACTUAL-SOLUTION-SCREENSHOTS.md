# Kepryx actual-solution screenshots

These assets are the product proof for the Medium article. They are screenshots of the running
Kepryx operator console, not a UI concept or a generated mockup.

## Included captures

| Screen | File | What it proves | Data note |
|---|---|---|---|
| Dashboard | `docs/images/dashboard-evidence.png` | Inventory posture, risk cards, shadow IT, open alerts, KEV records, relationship map, and recent activity | Local synthetic preview data; captured 27 August 2026 |
| Compliance | `docs/images/compliance-evidence.png` | CIS/ISO/NIST summaries and the underlying control-evidence table | Local synthetic preview data; captured 27 August 2026 |

The dashboard capture shows 34 assets, 5 critical assets, 7 high-risk assets, 10 shadow-IT assets,
103 open alerts, 1,675 KEV records, and the interactive relationship map. The compliance capture
shows CIS v8 at 72.02%, ISO 27001 at 89.29%, and NIST 800-53 at 75%. These are evidence snapshots,
not current production guarantees; they can change after a new import, scan, enrichment run, or
compliance audit.

## Branded annotation assets

- `docs/images/dashboard-focus.svg` adds amber focus boxes and numbered callouts for the posture
  cards, 4D relationship map, alerts, and recent changes.
- `docs/images/compliance-focus.svg` adds amber focus boxes and numbered callouts for framework
  posture and the control-evidence table.

The raw PNG should appear first in the article so readers see the real product. The annotated asset
can follow when the text explains the specific workflow. If Medium does not render the SVG reliably,
export the SVG to PNG without changing the screenshot, callout labels, or Kepryx color palette.

## Publication caption set

### Dashboard

**Actual Kepryx dashboard:** the operator starts with inventory posture, risk severity, shadow IT,
open alerts, KEV coverage, the relationship map, and recent changes. The view is API-backed and uses
synthetic local preview data.

### Compliance

**Actual Kepryx compliance screen:** the framework cards summarize the latest results, while the
control-evidence table shows which asset and observed values produced each status. The screen is an
assessment aid, not a certification claim.

## Final image safety check

Before publishing, inspect every image at 100% and confirm:

- no password, token, API key, browser address containing sensitive data, or personal data is visible;
- all assets and scan ranges are synthetic, reserved, or explicitly authorized;
- the caption counts match the capture date;
- the Kepryx wordmark and product context remain visible;
- the tracked-file secret scan is clean after the images and article are finalized.
