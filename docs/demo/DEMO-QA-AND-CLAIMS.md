# Demo Q&A and claims sheet

Use these answers when a reviewer, CTO, CISO, or security engineer asks what the demo proves. They
are deliberately precise so the project is credible under technical questioning.

## What is Kepryx?

Kepryx is an open-source asset intelligence and risk platform. It reconciles asset observations,
adds vulnerability context, calculates an explainable posture signal, preserves compliance evidence,
and exposes bounded operator workflows.

It is not a replacement claim for every SIEM, EDR, vulnerability scanner, CMDB, or GRC platform.
Its value is the evidence chain between those operational concerns.

## Is Kepryx a SIEM or EDR?

No. Kepryx is the asset, risk, and evidence layer. It can ingest from approved sources and show
provenance, but the demo does not claim endpoint prevention, packet monitoring, log management, or
full detection-and-response capability.

If FleetDM is shown, call it **endpoint-management inventory**. FleetDM does not turn this demo into
an EDR demonstration.

## Are the vulnerability feeds live?

The core recording uses local response-shape snapshots for repeatability. The client code and
provider boundaries are demonstrated, but the snapshot is not evidence of current NVD, EPSS, CISA
KEV, or OSV freshness. A live-feed claim requires a separately observed configured run.

## Is the risk score an AI prediction or probability of breach?

No. It is a bounded posture signal based on documented weighted factors. The factors and weights are
visible, and the score is intended to support prioritization—not to predict breach probability.

## Is the Assistant authoritative?

No. The Assistant is restricted, local, read-only, and advisory. It is grounded in available Kepryx
evidence and does not change application data. Deterministic application records remain the source
of truth.

## Does the compliance view prove certification?

No. It shows assessment support, control status, evidence linkage, and rationale for the bundled
preview subset. It does not provide a certification, audit opinion, or organization-specific
compliance conclusion.

## Is the relationship map an attack-path engine?

No. It is a bounded relationship view across visible assets, sources, dependencies, alerts, CVEs,
segments, and time. It helps an operator explore context; it does not claim exploitability analysis
or a complete attack graph.

## Which integrations are actually proven?

| Integration path | Safe claim |
|---|---|
| CSV | Live local import, validation, normalization, and reconciliation workflow. |
| Asset Source fixture | Real connector protocol against a local vendor-neutral source contract. |
| NetBox | Live provider pull only after the current session's Test and Sync succeed. |
| FleetDM | Live endpoint-management inventory pull only after setup, enrollment, Test, and Sync succeed. |
| NVD/EPSS/KEV/OSV snapshots | Repeatable local response-shape fixture, not fresh feed evidence. |
| Wazuh/Elastic/Snort | Not claimed as native integrations in this demo. |

The connector catalog describes supported capability metadata. It is not proof that a provider was
configured or tested.

## What happens when a provider fails?

The integration run should expose a bounded operator status, duration, and safe error state without
returning connector secrets. The run is constrained by pages, assets, and timeout limits. A failed
provider run is shown as failed; it is not silently converted into a successful inventory result.

## Why use synthetic data?

The local lab has one host and cannot honestly represent a large enterprise environment. Synthetic
assets make the workflow repeatable, publishable, and safe while retaining the real application
paths. Reserved documentation ranges are used for demo IP addresses.

## Why open source?

Many teams face fragmented records and visibility gaps, while enterprise platforms can be expensive
or difficult to customize. Kepryx is an inspectable foundation that engineers can run, challenge,
adapt, and improve. That is a contribution to the problem—not a claim that open source removes the
need for professional operations.

## Approved language

- “Live local workflow” for an observed Kepryx path.
- “Fixture-backed and repeatable” for deterministic local sources.
- “Live provider pull” only after current Test and Sync evidence.
- “Advisory” for AI output.
- “Posture signal” for the risk score.
- “Assessment support” for compliance views.
- “Pending validation” when a connector was not actually tested.

## Language to avoid

- “CVE-free,” “secure by default everywhere,” or “no vulnerabilities.”
- “Certified,” “audit-ready,” or “compliant” without organization-specific scope and evidence.
- “EDR integration” for FleetDM.
- “Native Wazuh, Elastic, or Snort integration” when it has not been implemented and tested.
- “Real-time enterprise scale,” “fully automated remediation,” or “complete attack-path analysis.”
