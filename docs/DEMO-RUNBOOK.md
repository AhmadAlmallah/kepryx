# Kepryx v0.9 Community Preview Demo Runbook

This runbook records the shortest honest demonstration path for the community preview. It uses
`demo/data/assets-full.csv`, a vendor-neutral fixture containing 37 synthetic assets and reserved
documentation IP ranges only. It does not require vendor credentials or access to a real network.

For the complete hardware/resource decision and the real-versus-simulated evidence boundary, see
[LOCAL-LAB-PLAN.md](demo/LOCAL-LAB-PLAN.md). The primary profile does not require Wazuh, Elastic,
Snort, or a paid provider deployment.

For a polished recording, start with the [canonical demo pack](demo/DEMO-PACK.md), run the
[demo checklist](demo/DEMO-CHECKLIST.md), and use the [materials shot list](demo/DEMO-MATERIALS.md).
The [timed speaker notes](demo/DEMO-SCRIPT.md), [evidence matrix](demo/EVIDENCE-MATRIX.md),
[claims sheet](demo/DEMO-QA-AND-CLAIMS.md), [benchmarks and comparison](demo/BENCHMARKS-AND-COMPARISON.md),
and complete [product gallery](PUBLICATION/PRODUCT-GALLERY.md) provide the supporting detail.
Use the gallery captions to keep the audience focused on one evidence chain instead of watching
an undirected screen tour.

## Before recording

1. From the repository root, stop any provider lab with `pwsh -File demo/integrations/Stop-IntegrationLab.ps1`,
   then run `pwsh -File demo/Run-Demo.ps1`; it starts the isolated
   `kepryx-demo` profile and confirms `/health` and `/ready`.
2. Bootstrap a local administrator with a disposable password.
3. Confirm the browser is using the same-origin console and that the banner says **API connected**.
4. Do not display `.env`, credentials, access tokens, private certificates, or unapproved network
   ranges in the recording.

## Scenes

1. **Login and service status** — sign in, show the connected API state, then briefly show the
   dashboard totals, operational posture, recent changes, and the inventory relationship map.
2. **Deterministic inventory import** — open **Inventory → Import CSV**, select
   `demo/data/assets-full.csv`, run **Validate only (dry run)**, and show the valid-row count
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
   proof range such as `198.51.100.240/28` in an isolated Docker network. Do not scan a workplace,
   cloud, or home network without
   written authorization and a defined maintenance window.
8. **Operations evidence** — show **Alerts** and **Audit Log**. Run the HMAC contract check in
   `demo/Verify-HmacWebhook.ps1` if webhook signing is relevant, but label it as a contract check;
   the application blocks private/loopback webhook destinations by design.

## API alternative

After login, the same CSV flow can be demonstrated with:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -F "file=@demo/data/assets-full.csv" \
  "https://kepryx.local:8444/api/v1/assets/import-csv?dry_run=true"
```

The expected result is a successful validation response with the fixture row count and no row
errors. Record the actual response from the tested build; do not hard-code a result that has not
been observed.

## Post-recording evidence

- Save the exact Git commit, image digests, test output, and timestamp with the recording notes.
- Run `pwsh -File demo/Collect-DemoEvidence.ps1` and retain the generated local manifest beside
  the recording notes. It contains no credentials and is intentionally ignored by Git.
- State clearly that this is a v0.9 community preview and list the remaining limitations: single
  tenant, no enterprise SSO, no HA, limited browser E2E/load/restore evidence, and production HTTPS
  still requiring a real DNS/ACME or managed certificate workflow.
- Remove disposable tokens, test exports, and local recordings from the repository before commit.
