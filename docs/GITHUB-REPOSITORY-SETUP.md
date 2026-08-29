# GitHub repository setup

This is the maintainer runbook for publishing Kepryx as an open-source v0.9.0 community preview.
The repository files provide the technical controls; the settings below must be configured in the
GitHub repository after it is created. The current maintainer handle is `@AhmadAlmallah`.

## 1. Create privately first

1. Create a repository named `kepryx` under the maintainer's account or the future Kepryx
   organization.
2. Keep it **private** while the first push, CI run, security review, and peer review complete.
3. Use `main` as the default branch.
4. Push only the reviewed candidate branch. Do not upload `.env`, certificates, database dumps,
   local recordings, private scan output, or temporary archives.
5. Confirm the repository's About description:

   > Open-source Asset Intelligence & Risk Platform for inventory, vulnerability context,
   > transparent risk, compliance evidence, and security operations.

Suggested topics: `asset-intelligence`, `cybersecurity`, `vulnerability-management`,
`risk-assessment`, `compliance`, `devsecops`, `fastapi`, `python`, `open-source`.

## 2. Branch and pull-request controls

Configure a branch protection rule for `main`:

- Require a pull request before merging.
- Require at least one independent approving review.
- Require review of the most recent push.
- Require the CI status checks to pass before merge.
- Require conversation resolution.
- Require linear history if it fits the maintainer workflow.
- Do not allow force pushes or branch deletion.
- Keep repository administrators subject to the rule where practical.

The exact required-check names should be selected from the first successful CI run rather than
typed from memory. The repository includes `.github/CODEOWNERS` with `@AhmadAlmallah`; update it
through review if ownership changes.

### Personal-account limitation

GitHub currently reports that branch-protection rules are not enforced for this private repository
under the personal account plan; enforcement requires moving the repository to a GitHub Team or
Enterprise organization. Do not treat a saved but unenforced rule as a release control. Before the
repository becomes public or supports production deployments, move it to an organization and
verify that pull requests, required CI checks, CODEOWNERS review, conversation resolution, and
no-force-push/no-deletion rules are actively enforced on `main`.

## 3. Actions and security features

- Set Actions to allow the repository workflows and reviewed, pinned actions.
- Keep the default `GITHUB_TOKEN` permission at read-only; workflows request write access only when
  a release job genuinely needs it.
- Enable Code scanning and confirm the CodeQL workflow is producing results for `main`.
- Enable Dependabot version updates and security updates.
- Enable secret scanning and push protection if available on the account or organization plan.
- Enable private vulnerability reporting and confirm it routes to a monitored maintainer contact.
- Review `SECURITY.md` in the GitHub Security tab before making the repository public.

On the current personal private repository, GitHub reports Code scanning alerts as unavailable
because Advanced Security is organization-only. The CodeQL workflow is included but skips cleanly
until the repository is public or the organization sets the `KEPRYX_CODEQL_ENABLED=true`
repository variable. Bandit, pip-audit, secret detection, and the container gates remain active in
CI. Move the repository to a Team or Enterprise organization and confirm CodeQL alert ingestion
before claiming GitHub code-scanning coverage or enforcing it as a merge gate.

## 4. Release identity

1. Verify `pyproject.toml`, `app/main.py`, `CHANGELOG.md`, and the release notes use the same
   version.
2. Re-run the exact-candidate release gate from the commit to be tagged.
3. Create a signed annotated tag:

   ```bash
   git tag -s v0.9.0 -m "Release Kepryx v0.9.0 community preview"
   git push origin v0.9.0
   ```

4. Create the GitHub release from the matching tag using `.github/RELEASE_TEMPLATE.md`.
5. Attach only reviewed reports, SBOMs, Trivy output, and checksums that were generated from that
   exact tag commit.

If local signing is not configured, configure a verified SSH or GPG signing key before the public
release. Do not claim a signed release when the tag cannot be verified in GitHub.

## 5. Public-readiness review

Before switching visibility to public, confirm:

- `README.md` works for a clean-host reader and says v0.9.0 community preview.
- The Dashboard and Compliance screenshots are synthetic, branded, and free of credentials.
- The vendor-neutral Asset Source mock is clearly labeled as synthetic and local-only.
- No public demo text uses Falcon/CrowdStrike positioning.
- QA, SAST, security, release-scorecard, demo, and limitation documents are present.
- The article and release notes do not claim certification, permanent CVE-free status, HA, or
  autonomous remediation.
- The security contact is monitored and the reporting path is tested.
- The GitHub repository URL has been inserted only after it is known and the final secret scan is
  clean.

## 6. Post-publication maintenance

- Review Dependabot and CodeQL results weekly.
- Rebuild and rescan images before every release and through the scheduled workflow.
- Triage security reports privately and keep the public changelog accurate.
- Use issues and discussions to collect feedback on onboarding, connectors, evidence explainability,
  and operational recovery.
- Publish a patch release for verified fixes instead of silently changing the v0.9.0 evidence.

## 7. Deployment boundary

GitHub is the source, review, and CI control plane. It is not the runtime host for the full Kepryx
stack: GitHub Pages cannot run FastAPI, Celery, PostgreSQL, Redis, or the scanner. Use the
[deployment environment matrix](DEPLOYMENT-ENVIRONMENT-MATRIX.md) to select a Docker-capable
private preview or production host and to keep its secrets and network authorization separate from
the repository.
