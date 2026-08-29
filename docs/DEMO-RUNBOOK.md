# Kepryx v0.9 Community Preview Demo Runbook

This runbook records the shortest honest demonstration path for the community preview. It uses
`demo/data/asset_inventory.csv`, a vendor-neutral fixture containing synthetic assets and reserved
documentation IP ranges only. It does not require vendor credentials or access to a real network.

For a polished recording, use the [demo evidence pack](demo/README.md), especially the
[timed speaker notes](demo/DEMO-SCRIPT.md), [evidence matrix](demo/EVIDENCE-MATRIX.md),
[benchmarks and comparison](demo/BENCHMARKS-AND-COMPARISON.md), and the focused dashboard and
compliance screenshot overlays under `docs/images/`. The overlays use numbered focus squares so
the audience can follow the evidence chain instead of watching an undirected screen tour.

## Before recording

1. Start the local stack and confirm `/health` and `/ready` return `200`.
2. Bootstrap a local administrator with a disposable password.
3. Confirm the browser is using the same-origin console and that the banner says **API connected**.
4. Do not display `.env`, credentials, access tokens, private certificates, or unapproved network
   ranges in the recording.

## Scenes

1. **Login and service status** — sign in, show the connected API state, then briefly show the
   dashboard totals, operational posture, recent changes, and the inventory relationship map.
2. **Deterministic inventory import** — open **Inventory → Import CSV**, select
   `demo/data/asset_inventory.csv`, run **Validate only (dry run)**, and show the valid-row count
   and risk preview.
3. **Asset and shadow-IT view** — process the fixture in the disposable environment, open the
   inventory table, and show the normalized asset fields and shadow-IT indicators.
4. **Risk assessment** — open **Risk Assessment** and explain that the score is transparent and
   evidence-driven: exposure, vulnerability, asset criticality, data classification, and confidence
   contribute to the displayed tier. Do not describe the score as a probability of compromise.
5. **Relationship and evidence view** — on the dashboard, filter the graph to **Security
   findings**, reshape it to **Risk clusters** or **Timeline layout**, use the time slider or
   playback, click a node to focus its direct neighbors, drag it to reposition X/Y, Alt-drag it to
   change Z depth, double-click to pin/unpin it, use zoom to focus the view, pause rotation, and
   show the accessible node picker/list as the deterministic fallback. Explain that this is
   bounded inventory topology with a time dimension, not a BloodHound attack-path engine.
6. **Compliance and self-security** — open **Compliance** to show framework control evidence and
   gaps, then **Self-Security** to show dependency scan status and review-only findings.
7. **Authorized discovery proof** — open **Scans** and show only an explicitly authorized lab
   proof range such as `198.51.100.0/28` in an isolated Docker network. Do not scan a workplace,
   cloud, or home network without
   written authorization and a defined maintenance window.
8. **Operations evidence** — show **Alerts**, **Audit Log**, and optionally a local webhook
   receiver. Label any webhook delivery as a local test and explain that production delivery needs
   secret rotation and endpoint ownership validation.

## API alternative

After login, the same CSV flow can be demonstrated with:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -F "file=@demo/data/asset_inventory.csv" \
  "https://kepryx.local/api/v1/assets/import-csv?dry_run=true"
```

The expected result is a successful validation response with the fixture row count and no row
errors. Record the actual response from the tested build; do not hard-code a result that has not
been observed.

## Post-recording evidence

- Save the exact Git commit, image digests, test output, and timestamp with the recording notes.
- State clearly that this is a v0.9 community preview and list the remaining limitations: single
  tenant, no enterprise SSO, no HA, limited browser E2E/load/restore evidence, and production HTTPS
  still requiring a real DNS/ACME or managed certificate workflow.
- Remove disposable tokens, test exports, and local recordings from the repository before commit.
