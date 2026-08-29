![Kepryx logo](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/brand/kepryx-logo.png)

# Your Security Stack Is Only as Good as Your Asset Inventory

*Why I built Kepryx: an open-source way to connect shadow assets, vulnerability facts, risk,
compliance evidence, and daily security operations with an optional AI assistant.*

Security teams have more tools than ever. EDR, vulnerability scanners, cloud security, SIEM,
identity, network monitoring, and compliance platforms all have an important role.

But there is one question behind all of them:

**Do you really know what you have?**

One open port. One misconfigured server. One old system that everyone forgot. One endpoint that is
not covered by the security controls. One spreadsheet that was last updated months ago.

These are not theoretical situations. They are the small gaps that can become the first step of a
real incident.

## How most infrastructure breaches start

The entry point can be phishing, an exposed service, a misconfiguration, stolen credentials, or
old infrastructure. Every incident is different, so I am not saying that every breach follows the
same path.

What is familiar is what happens after the first access.

The attacker starts looking through the network and the IT environment. They search for the
weakest machine, the forgotten server, the shadow asset, the account with too much access, or the
system nobody is monitoring anymore. From there, discovery and lateral movement become easier.

This is why inventory is not only an IT administration task. It is also part of security, risk
management, compliance, and GRC requirements.

If the inventory is incomplete, the security team may not know what needs protection. If the asset
context is wrong, vulnerability findings are harder to prioritize. If the evidence is missing, a
compliance percentage is difficult to defend.

## The problem is not that security tools are missing

The market already has many good products. The problem is the gap between them.

You may have an Excel file, an asset discovery tool, a vulnerability scanner, an EDR console,
cloud accounts, DHCP/DNS records, and a compliance spreadsheet. Each one knows something about the
environment.

The engineer is then asked to create one trustworthy picture from all of them:

- What assets actually exist?
- Which assets are stale, exposed, or shadow IT?
- Which vulnerability facts are confirmed by an authoritative source?
- Why did this asset receive a high risk score?
- Which observation produced this compliance result?
- What changed after the last scan?

This takes time. It creates duplicate work. It also creates a situation where the organization has
many records but no single operational view that connects them.

Security and managing enterprise assets is a pain. This is a fact. I know it from experience. It is
also a good challenge because it sits between IT operations, security engineering, vulnerability
management, and GRC.

## The cost problem

Most inventory solutions that meet serious enterprise requirements are expensive. In many
organizations, investing in an EDR or a detection capability will make more sense than adding
another expensive inventory platform. That is a reasonable decision because EDR protects and
detects on the endpoint.

But it does not remove the need for an asset evidence layer.

You still need to reconcile what different systems report. You still need to identify assets that
are not covered. You still need to understand how vulnerability facts affect risk. You still need
to connect controls and evidence to the asset that produced them.

That is the opportunity I see for an open-source solution: a useful foundation that an engineer can
run, inspect, customize for a specific environment, use as a case study, or extend into a larger
development project without starting from zero.

## Introducing Kepryx

I am introducing **Kepryx**, an open-source Asset Intelligence & Risk Platform.

The objective was simple:

> Connect the mess of asset data and shadow assets into one centralized solution that gives IT,
> security, vulnerability management, and GRC teams a more useful operating picture.

Kepryx connects:

1. Asset observations from files, a vendor-neutral Asset Source API, network discovery, Nessus,
   LDAP, AWS, DHCP/DNS, and optional security integrations.
2. Reconciliation, so observations from different sources become one source-labelled asset view.
3. Vulnerability facts from NVD, FIRST EPSS, and the CISA Known Exploited Vulnerabilities catalog.
4. Transparent risk scoring, so the operator can see why an asset moved into a risk tier.
5. Compliance evidence for a licensed-safe subset of CIS Controls, NIST SP 800-53, and ISO/IEC
   27001 control metadata.
6. Alerts, audit events, webhooks, exports, and an interactive relationship map.
7. An optional local AI assistant that explains bounded evidence but does not become the source of
   truth.

This is not a theory or a research paper. It is a tool that took time, nights, and a lot of
security, QA, SAST, and operational testing to reach a useful starting point.

It may not be perfect. I am not presenting it as a finished enterprise product. I am presenting it
as a serious v0.9.0 community preview that people can inspect, run, test, challenge, and improve.

## What the running solution looks like

These are screenshots from the actual local Kepryx console, not design mockups. They were captured
from the verified preview build with synthetic test data. The values are point-in-time preview
data and will change when seed data, scans, enrichment jobs, or compliance audits are run again.

![Kepryx dashboard showing posture, alerts, activity, and relationship map](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/product/dashboard.png)

*Figure 1 — The dashboard brings the operational picture into one view: asset count, critical and
high-risk posture, shadow IT, open alerts, KEV coverage, recent changes, and the interactive
relationship map. The capture shows 34 assets, 5 critical assets, 7 high-risk assets, 10 shadow-IT
assets, 120 open alerts, and 1,675 KEV-linked records from the local synthetic preview run.*

![Kepryx alert triage queue](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/product/alerts.png)

*Figure 2 — Alerts connect a generated finding to severity, status, asset context, and operator
resolution. This is where the inventory becomes operational: the team can see what needs attention,
why it matters, and what action was taken.*

![Kepryx risk assessment and remediation queue](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/product/risk-assessment.png)

*Figure 3 — Risk Assessment shows the weighted evidence formula and the remediation queue. The
score is a bounded posture signal with visible inputs. It is not a probability of breach and it
does not replace analyst judgment.*

![Kepryx compliance view with framework posture and control evidence](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/product/compliance.png)

*Figure 4 — Compliance shows the framework summaries and the control-evidence table. The
percentage is only the summary; the useful part for an engineer is the path from the control to
the observed asset evidence.*

![Kepryx Assistant with a bounded evidence-based response](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/product/assistant.png)

*Figure 5 — The Assistant is read-only and evidence-bound. It can summarize the current inventory,
alerts, scans, compliance, self-security, and vulnerability posture, but it cannot execute actions,
change records, or create vulnerability truth.*

![Kepryx interactive relationship map](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/workflows/relationship-map.png)

*Figure 6 — The relationship map is an operator tool, not a static picture. Engineers can filter
relationships, select a node, focus its neighborhood, move nodes in X/Y, adjust Z-depth, pin useful
nodes, zoom, reset the layout, and scrub the captured timeline.*

Every screenshot in this article uses synthetic local QA data. Accounts, email addresses, IPs,
identifiers, counts, and placeholder URLs are fixtures. The [complete product gallery](PRODUCT-GALLERY.md)
contains the rest of the safe operator and workflow views.

## From scattered observations to one asset record

The core flow is straightforward:

```text
Source observations
        |
        v
Normalize and validate
        |
        v
Reconcile by identity and source priority
        |
        +--> vulnerability enrichment: NVD / EPSS / KEV
        |
        +--> risk signal and remediation priority
        |
        +--> compliance control evidence and lineage
        |
        +--> alerts, audit history, exports, and operator actions
```

The important point is that Kepryx does not treat every incoming value as truth. The source and
observation remain visible. Conflicts can be reviewed. The resulting record is useful because the
engineer can understand where it came from.

## Authoritative vulnerability facts, not invented answers

Vulnerability data is one of the areas where an AI model should not be trusted as the source of
truth.

Kepryx uses authoritative or purpose-built sources for the facts:

- **NVD** for vulnerability records and CVSS context.
- **FIRST EPSS** for a probability-based exploitation signal.
- **CISA KEV** for vulnerabilities known to be exploited in the wild.
- **OSV** for the application self-security dependency path.

The AI assistant can explain a bounded evidence packet. It cannot invent a CVE, silently change a
score, or turn an unverified suggestion into a confirmed vulnerability. This separation is
important: the model is an analyst aid, while the stored source record and deterministic pipeline
remain authoritative.

## How risk is calculated

The risk engine uses a bounded additive model. I chose this approach because the engineer should
be able to read the inputs and reproduce why an asset moved from one tier to another.

| Factor | Weight |
|---|---:|
| CVE severity and exploitability | 23% |
| KEV presence | 18% |
| Control coverage | 18% |
| Network exposure | 14% |
| Access method | 9% |
| Business criticality | 10% |
| Data classification | 8% |

CVSS and EPSS are normalized into the same bounded 1–5 scale. A vulnerability in the KEV catalog
receives a bounded boost. The final value produces a tier and a recommended action/SLA.

This score is a posture signal. It is not a probability of breach, and it is not a replacement for
an analyst who understands the business and the environment.

The reason for showing the formula is simple: “critical” should have a reason behind it. In a real
environment, that reason may be the combination of an internet-facing system, a KEV-linked
vulnerability, weak controls, and sensitive data—not only a label copied from another tool.

## Compliance needs a chain, not only a percentage

Compliance dashboards often show a percentage and stop there. The percentage is useful, but the
engineer also needs to know what produced it.

![Kepryx compliance evidence lineage](https://raw.githubusercontent.com/AhmadAlmallah/kepryx/main/docs/images/workflows/compliance-evidence-lineage.png)

*Figure 7 — The lineage view lets an engineer move from a control result to the assessment run,
observed asset fields, rationale, timestamp, and evidence hash. The AI review is advisory and does
not modify the deterministic result.*

For each asset/control pair, Kepryx stores the status, score, rationale, framework version,
assessment run, observed values, and a SHA-256 hash of the canonical evidence object.

The result can be:

- `compliant` when the deterministic rule passes;
- `partial` when a multi-field rule has some but not all of its evidence;
- `gap` when the rule fails or evidence is missing.

This is an evidence-backed posture aid. It is not an ISO certificate, CIS certification, NIST
attestation, or legal advice. An organization still needs approved procedures, exceptions,
sampling, retention, and auditor judgment.

## The AI assistant is useful because it has boundaries

I added support for a local Qwen3/Ollama deployment because sending complete inventory and security
records to a hosted model is not always acceptable. Local AI can be useful for a lab, a small team,
or an environment with strict data boundaries, even when the model is slower.

The Assistant is intentionally limited:

- it is read-only;
- it receives a bounded evidence packet rather than unrestricted database access;
- credentials, tokens, connector secrets, MFA data, raw audit details, and full exports are
  excluded;
- it cannot create, edit, resolve, approve, suppress, scan, or remediate records;
- it does not replace NVD, EPSS, KEV, OSV, deterministic risk, or compliance evidence.

The objective is not “AI will decide security.” The objective is to help an engineer understand the
current evidence faster while keeping decisions under human and system control.

## What I tested before calling it a preview

I did not want to rely on “the containers are running” as the only QA result.

| Area | Release-candidate result |
|---|---|
| Automated tests | 154 passing tests |
| Measured application coverage | 63.54% |
| Ruff and mypy | Passed |
| Bandit | No medium/high findings in 10,008 scanned lines |
| pip-audit | No known vulnerabilities in the locked Python runtime set |
| Secret detection | No findings in the staged tracked candidate |
| Database | Migration head `0007_evidence_compliance`; no model drift |
| Image security | Rebuilt first-party images reported zero HIGH/CRITICAL Trivy findings |
| SBOM | Nine local release-image CycloneDX SBOMs generated |
| Live acceptance | Auth, inventory, risk, enrichment, compliance, alerts, scans, self-security, Assistant, webhooks, and graph interactions tested locally |

The live platform demonstrated 34 assets, 120 open alerts, 1,675 KEV-linked CVE records, 76
dependency packages scanned, 185 graph nodes, and 218 relationships. These are local preview data
points, not a benchmark against a customer environment.

## The part I will not hide

The current scorecard is 82/100 for a v0.9.0 community preview. The score is not 100 because the
remaining work is real:

- deeper browser mutation tests for multipart import, exports, GDPR, compliance drill-down, and
  the Assistant modal;
- real external-provider contract tests with customer-owned credentials;
- load, soak, queue failure, high availability, and production restore evidence;
- public GitHub controls such as branch protection, peer review, and a signed release tag;
- customer-owned written authorization before scanning real networks.

This is the difference between a useful open-source preview and a product claiming enterprise
assurance. I prefer to show the gap clearly.

## Why open source?

I could keep Kepryx as a private product, but I think the first step should be open source.

Inventory and security operations touch many environments. One person cannot design every connector,
control mapping, and operational workflow alone. I want security and IT engineers to inspect the
code, challenge the assumptions, add integrations, improve the evidence model, and share failure
cases.

An engineer can take Kepryx and customize it for a specific environment. It can also be used as a
case study, a development project, or a foundation for a larger internal solution. That is the
special value of this approach: people do not have to buy a large platform before they can start
testing the operating model.

My goal is to build a useful community under Kepryx. As security engineers, we should contribute to
the community whenever we can. The project is released under Apache-2.0, with a security policy,
contribution guidance, issue templates, and a roadmap.

## How Kepryx adds value

Kepryx is most useful when it becomes the shared evidence layer between teams:

- IT operations can see what exists and what changed.
- Security teams can prioritize exposure and exploitability instead of only counting findings.
- Vulnerability managers can connect NVD/EPSS/KEV facts to affected assets.
- GRC teams can trace control outcomes to observations and evidence hashes.
- Engineers can filter, focus, reshape, and inspect relationships rather than only view a static
  diagram.
- Teams can run a local Assistant without sending the complete inventory to a hosted model, while
  keeping final decisions under human and system control.

It is not intended to replace every specialist tool. It is intended to reduce the gap between the
tools that already exist.

## The demo flow

The demo is designed around one evidence chain rather than a list of disconnected screens:

1. Start the community preview with Docker Compose.
2. Load the vendor-neutral synthetic Asset Source data.
3. Open the inventory and identify a shadow or weakly controlled asset.
4. Review the NVD, EPSS, and KEV-backed vulnerability facts.
5. Open Risk Assessment and inspect the score inputs and remediation priority.
6. Run the compliance assessment and trace a control result back to the asset evidence.
7. Review the alert, resolve it, and confirm the audit event.
8. Ask the read-only Assistant to summarize the same bounded evidence.
9. Explore the relationship map and show how an engineer can filter and focus the topology.

The purpose is to show how one observation becomes an operational decision, not only how a
dashboard looks.

## Conclusion

The security industry does not need another product that only says “your risk is high.” Engineers
need to know what exists, what was observed, why the system evaluated it that way, what evidence
supports the result, and what changed after action was taken.

That is the purpose of Kepryx.

It is a strong starting point, not a perfect final answer. I am releasing it as a v0.9.0 community
preview so people can review the code, run the platform, test the integrations, and tell me where
the evidence model does not match reality.

If you work in IT, security, vulnerability management, or GRC, I would like you to test it and
share your feedback. The next version should be shaped by real engineering use, not only by my
assumptions.

— Ahmad Almallah

*Kepryx v0.9.0 is a community preview. It is not certified, does not provide legal advice, and
must be tested and authorized for each deployment.*

