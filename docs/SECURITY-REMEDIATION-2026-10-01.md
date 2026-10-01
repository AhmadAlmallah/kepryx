# Security remediation - 1 October 2026

## Scope and confirmed baseline

The failed [dependency gate in run 36803629449](https://github.com/AhmadAlmallah/kepryx/actions/runs/36803629449)
reported 16 advisories: 13 against PyJWT 2.13.0 and three against urllib3 2.7.0.
The following changes are isolated from the software-inventory feature so that
the default branch can receive the security fixes independently.

## Changes

- Raise the runtime security floors to `PyJWT[crypto]>=2.15.1,<3` and
  `urllib3>=2.8.0,<3`; regenerate both SHA-256-locked requirements files on
  Python 3.12. Only these two package versions change.
- Pin CodeQL init and analyze to the same v4.38.2 commit, and group subsequent
  CodeQL action updates in Dependabot. Add a test rejecting mismatched pins.
- Pin Docker build-push-action v7.4.0 and setup-buildx-action v4.4.1 using the
  exact commits from the existing dependency-update branches.
- Bring the previously unmerged edge fixes to the default-branch candidate:
  `x/crypto 0.56.0`, `grpc 1.83.2`, `x/net 0.58.0`, and `x/text 0.41.0`.
- Build security-gate images without cached layers. A cached API layer initially
  retained `libuuid 2.42.1-r0` with seven HIGH findings; refreshing the runtime
  upgrade installs `2.42.3-r1`. Keep all six image scans running after an earlier
  scan failure, while retaining the failing job status and `ignore-unfixed: false`.

## JWT advisory assessment

Kepryx passes a single configured algorithm to `jwt.decode`, verifies issuer
and audience, requires registered security claims, and creates a fresh options
dictionary for each decode. It does not use unverified decoding in application
code or mix HMAC and asymmetric algorithms in the allowed list. These boundaries
reduce the reachable attack surface but are not a reason to retain the old library.

The [critical key-confusion advisory](https://github.com/advisories/GHSA-ffc3-869f-jxw9)
lists 2.14.0 as patched; the
[pre-verification recursion advisory](https://github.com/advisories/GHSA-42vr-xj54-vc7v)
requires 2.15.0. This candidate uses 2.15.1.

[GHSA-gvp8-978c-rx2q](https://github.com/advisories/GHSA-gvp8-978c-rx2q)
still lists no patched release and an affected range ending at 2.13.0. Do not
interpret that metadata alone as proof of a fix. On the installed 2.15.1 package,
the new regression test verifies that unverified decoding does not mutate the
caller's options and that subsequent verified decoding rejects an expired token.
No advisory is ignored or allowlisted in the dependency gate.

## Executed local validation

| Check | Result |
| --- | --- |
| Hash-locked development installation and `pip check` | Passed on Python 3.12.14 |
| Full default-branch-candidate tests | 171 passed; 17 new security/policy cases |
| Application coverage | 63.62%; existing 60% gate retained |
| Ruff lint/format and mypy | Passed |
| Bandit | No medium/high findings in 10,008 lines; one low finding remains |
| `pip-audit --strict --disable-pip`, runtime and development locks | No known vulnerabilities; no ignores |
| Tracked-file secret gate and staged diff whitespace check | Passed |
| PostgreSQL migration and model drift | Head `0007_evidence_compliance`; no drift |
| Compose and workflow YAML | Validated |
| Rebuilt API, worker, scanner, edge, database, and synthetic fixture | All six passed HIGH/CRITICAL Trivy gates |
| CycloneDX SBOMs | Six generated and parsed; specification 1.6 |
| API, edge, and fixture identity | UID 10001; API has no pip executable; database has no gosu |
| Caddy configuration | Validated with the rebuilt binary |
| Isolated API/PostgreSQL/Redis smoke test | Health/readiness, login, asset read, and refresh passed |
| Invalid-token and replay checks over HTTP | Unsigned, wrong algorithm/issuer/audience, expired, refresh-as-access, and refresh replay returned 401 |

Trivy version: 0.67.2. Vulnerability database updated
`2026-10-01T01:24:14.992991033Z`, downloaded freshly for this review.
Runtime images report PyJWT 2.15.1 and urllib3 2.8.0.
Raw scan JSON and SBOMs are retained outside the source tree; CI also generates
and uploads its own six SBOMs.

## Reproduction and release boundary

Run the repository's CI workflow against this candidate. Locally, rebuild each
first-party image with `docker build --no-cache`, scan with Trivy's current
database using HIGH/CRITICAL and `ignore-unfixed=false`, and generate SBOMs from
the same image tags. Test against a dedicated database, not a live deployment.

Local validation is not a substitute for a successful GitHub CI and CodeQL run.
The default branch and existing running containers are not updated by creating
or pushing this candidate. Merge only after the required review and checks;
then rebuild/redeploy the affected containers. The existing v0.9.0 release/tag
is unchanged. This is point-in-time evidence, not a claim that the product is
free of all vulnerabilities or production-certified.
