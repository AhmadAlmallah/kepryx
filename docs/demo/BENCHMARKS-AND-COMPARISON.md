# Benchmarks, comparison, and critical review

Evidence snapshot: 2026-08-29. Environment: local Windows Docker Desktop, Kepryx v0.9.0 preview
candidate, current staged branch, synthetic/reserved data. These are engineering observations,
not a capacity certification or a competitive product benchmark.

## Measured release evidence

See the [weighted scorecard chart](../images/release-scorecard-chart.svg) while presenting the
release posture. It makes the strongest evidence and the largest remaining launch gap visible in
one frame.

| Measure | Observed result | What it demonstrates | What it does not demonstrate |
|---|---:|---|---|
| Automated test suite | 154 passed; 63.54% application coverage | Core regressions plus read-model, export, token, notification, retention, API mutation, scanner, CVE, reconciliation, connector, worker-policy, and remediation contracts pass | Broad production coverage; browser mutation, load, and failover evidence remain limited. |
| Static typing | 69 application files, no mypy errors | Typed application surface is internally consistent | Runtime correctness for every path. |
| Bandit | No medium/high findings across 10,008 lines | No gated SAST findings in the scanned scope | Complete vulnerability discovery; SAST is one control. |
| Python dependency gate | `pip-audit --strict` clean for the hash-locked runtime set | Known runtime package CVEs are gated for this candidate | Base-image or future provider dependency risk. |
| First-party image gate | 0 HIGH/CRITICAL findings in all nine rebuilt images with unfixed advisories visible | Image findings are blocked before release and upstream drift is scheduled for rescanning | A point-in-time scan is not a permanent CVE-free guarantee. |
| Caddy image review | Custom 2.11.4 build; 0 HIGH/CRITICAL findings | Fixed Go/module pins are verified by raw Trivy | Future upstream source/module changes still require a rescan. |
| Compliance acceptance | 3 catalogs, 13 controls, 34 assets, 442 results | Evidence-backed graduated control assessment works in the preview | Certification, full framework coverage, or auditor judgment. |
| Graph acceptance | 185 nodes, 218 relationships | The dashboard can render and operate on bounded evidence topology | Neo4j/BloodHound attack-path analysis or large-scale graph capacity. |
| Self-security acceptance | 76 packages, 0 findings in the tested environment | OSV scan and review-only proposal boundary work | Absence of vulnerabilities in every future build. |
| Vulnerable asset enrichment | 81 NVD records; final score 4.27 Critical in the fixture | The evidence path can materially change risk | A universal risk truth or exploit probability. |
| Local Assistant path | Qwen3-14B produced bounded, grounded responses | Optional local AI can explain current posture | Model correctness, availability, or autonomous action. |

### Current smoke observation

The repeatable benchmark was run against `https://kepryx.local:8443` on 2026-08-28 with five
iterations per endpoint. It returned `200` for both endpoints. Median `/health` was **4.85 ms**
and median `/ready` was **5.87 ms**; the maximum `/health` sample was **120.63 ms** and the
maximum `/ready` sample was **7.07 ms**. The CSV fixture contained **10 rows**, all using reserved
documentation addresses. These numbers describe one local machine and are included to show how
to collect evidence, not to promise latency or capacity.

## Repeatable local observation

Run the following from the repository root before recording. The benchmark script measures only
health/readiness request latency and fixture size; it does not require credentials and does not
mutate the database.

```powershell
pwsh -File demo/Run-DemoBenchmark.ps1 -BaseUrl https://kepryx.local:8443 -Iterations 5
```

The script reports median and maximum request time in milliseconds, HTTP status, fixture row
count, and the timestamp. Treat the result as a single-host smoke observation. Do not compare it
to a vendor SLA or use it as a throughput claim.

## Capability-positioning comparison

This is a positioning aid for the demo, not a claim that every spreadsheet, CMDB, SIEM, or
enterprise platform has identical behavior.

| Capability | Manual spreadsheet workflow | Kepryx v0.9 preview | Enterprise platform baseline |
|---|---|---|---|
| Inventory collection | Manual exports and reconciliation | CSV plus connector contracts and reconciliation | Broad native integrations and managed ingestion |
| Source provenance | Often implicit | Source labels, timestamps, evidence snapshots | Usually available, product-specific |
| Vulnerability context | Separate tools and manual joins | NVD + EPSS + CISA KEV pipeline | Often strong, usually licensed/service-dependent |
| Risk explanation | Analyst narrative | Weighted, inspectable factors and evidence | Product-specific; may be proprietary |
| Compliance evidence | Documents and spreadsheets | Versioned subset, result status, hashes, lineage, PDF | Broader catalogs, workflow, attestation, support |
| Alert operations | Email/ticket/manual | Alert state, resolution, audit trail, HMAC webhook | Mature routing, ownership, escalation, SLA workflows |
| Relationship exploration | Static diagrams | Interactive bounded 4D inventory map | Graph and attack-path features vary by product |
| AI assistance | None or separate tool | Optional read-only bounded Assistant | Product/provider-specific controls and governance |
| HA, SSO, multi-tenancy | Not applicable | Explicitly deferred in v0.9 | Expected in many enterprise baselines |
| Evidence of operation | Analyst-maintained | Tests, live acceptance records, runbooks | Formal vendor validation and support evidence |

## Critical review

### Strongest proof points

- The end-to-end path is coherent: observation → reconciliation → authoritative enrichment → risk
  and compliance evidence → alert/audit action.
- Security boundaries are visible in the product: fail-closed scans, scoped tokens, read-only AI,
  evidence lineage, and disclosed image residuals.
- The demo does not require customer data or a vendor account. That makes the first public review
  repeatable and safe.

### Highest-value improvement after publication

1. Raise coverage beyond 63.54% with browser mutation, DB-backed edge cases, and worker idempotency tests.
2. Add one independently reviewed provider connector with a documented failure contract.
3. Produce load/soak and restore/upgrade evidence using a defined test dataset.
4. Add real deployment HTTPS evidence and a signed release tag.
5. Let design-partner feedback decide whether to invest in SSO, multi-tenancy, HA, or more
   connectors.

### Honest launch position

Kepryx is strong enough to publish as an open-source community preview and portfolio artifact.
Its differentiator is evidence explainability and security-minded workflow design, not feature
count. Keep the public promise narrow, show the working path, and make the limitations visible.
