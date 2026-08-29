# Browser mutation evidence

Evidence date: 2026-08-28. Target: local development edge at `http://127.0.0.1:8080/` after
rebuilding the candidate images. This is a repeatable local UI interaction record, not a claim
of production browser compatibility.

## Preconditions

- API, Caddy dev edge, PostgreSQL, Redis, workers, and the synthetic Asset Source fixture were
  healthy after forced recreation from the candidate images.
- The admin test account authenticated successfully and the dashboard displayed `API connected`.
- The dashboard loaded live posture values and an inventory graph with 185 visible nodes.

## Executed checks

| Check | Result |
|---|---|
| Login and dashboard bootstrap | Passed; authenticated dashboard rendered without the prior `children.filter is not a function` failure. |
| Graph filter | Passed; `Security findings` selected and the graph re-rendered. |
| Layout reshape | Passed; `Risk clusters` selected and the graph re-rendered. |
| Node picker and focus | Passed; `WEB-DMZ-01` selected, `Selected node only` reduced the status to one node, and `Selected + direct neighbors` restored its neighborhood. |
| X/Y node movement | Passed; a canvas drag moved the selected node and marked it pinned. |
| Z-depth node movement | Passed; an `Alt`-drag on the selected node completed and retained the pinned state. |
| Pin/unpin | Passed; the control changed between `Pin node` and `Unpin node`, and the selection text reflected the state. |
| Zoom controls | Passed; two zoom-in clicks and one zoom-out click changed the live readout to `120%`. |
| Timeline scrub/playback | Passed; the range moved to the start of the available evidence window and playback entered the timeline state. |
| Reset layout | Passed; selection cleared, the map returned to `100%`, and the layout-managed default returned. |

The graph interactions are client-side exploration state and do not mutate inventory records. The
DB-backed create/update, alert resolution, scan validation, integration, self-security, connector,
enrichment, reconciliation, and worker policy mutations are covered by the executable suites in
`tests/integration/test_api_mutations.py`, `tests/integration/test_connector_contracts.py`, and
the corresponding unit suites.

## Boundary

This evidence covers the highest-value operator graph workflow through the browser. Additional UI
mutation coverage for multipart import, exports, GDPR, and compliance drill-down remains useful
follow-up work; it is not required to claim that the entire frontend has exhaustive E2E coverage.
