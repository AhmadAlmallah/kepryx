# Kepryx open-source launch plan

## Recommendation

Launch Kepryx as an open-source product under the author's identity, with a maintainer-led
community model. Do not split effort into a closed SaaS product yet. The strongest near-term
career signal is a useful, inspectable project with honest evidence, visible engineering
decisions, and a repeatable demo.

Recommended model:

- Repository: a dedicated `kepryx` repository under a Kepryx organization when available.
- Maintainer: Ahmad Almallah, named clearly in `AUTHORS`, `NOTICE`, README, and governance.
- License: Apache-2.0 for code and documentation unless a future asset has a separate license.
- GitHub settings: follow the [repository setup runbook](GITHUB-REPOSITORY-SETUP.md) for the
  private-first push, branch protection, security features, release signing, and public gate.
- Commercial path: paid deployment help, connector work, hardening reviews, support, or hosted
  operations only after external users show demand. Do not add artificial licensing friction to
  the v0.9 preview.
- Trademark: reserve the Kepryx name and logo as project identity; licensing code does not by
  itself grant trademark rights.

## Private-first launch sequence

1. Create the GitHub repository privately and push the reviewed branch.
2. Rotate every credential that has appeared in chat, screenshots, terminals, fixtures, or
   local environment files. The bootstrap process must create a new admin password.
3. Enable required status checks, branch protection, Dependabot, CodeQL, secret scanning, and
   private vulnerability reporting where the account plan supports them.
4. Add a monitored security contact and confirm that `SECURITY.md` matches the repository's
   actual reporting path.
5. Ask one independent peer to review the API security, Compose boundary, connector secrets,
   and demo claims. Record the review outcome without exposing private findings.
6. Re-run the scorecard and hard gates against the exact commit to be published.
7. Generate an SBOM, create a signed `v0.9.0` tag, publish release notes, and then make the
   repository public.

## Public positioning

Use language such as:

> Kepryx is an open-source asset intelligence and risk platform community preview. It
> reconciles inventory observations, enriches vulnerability context, and explains weighted
> risk results through an API and operator console.

Avoid claims such as “enterprise-ready,” “certified,” “fully autonomous remediation,”
“CVE-free,” or “CrowdStrike certified.” Connector support means an implemented connector
contract, not vendor endorsement.

## First 30 days after publication

- Publish one recorded demo with synthetic data.
- Triage issues weekly and label good-first-issue, documentation, bug, security, and design.
- Request feedback on onboarding, connector usefulness, risk explainability, and deployment.
- Release only small, evidence-backed patch versions.
- Convert repeated external requests into roadmap items; do not build speculative enterprise
  features immediately.

## Commercialization trigger

Consider a paid offering only when at least two independent users ask for the same operational
help, such as managed deployment, custom integrations, support, or hosted operation. Keep the
core inventory/risk engine open where practical and sell expertise and operations first.
