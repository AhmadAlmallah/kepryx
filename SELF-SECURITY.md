# Kepryx Self-Security

The self-security subsystem inventories the Python environment, queries OSV, synchronizes
authoritative CISA KEV data, and creates reviewable dependency-update proposals.

## Safety boundary

The worker never writes host source, edits a lock file, invokes Docker, or deploys code. The API
also rejects attempts to enable autonomous updating or remove admin approval. An approved proposal
is converted to a patch artifact in `rollback_snapshot.proposal_patch` with status `ready_for_pr`.
An operator must review it, update the input constraint, regenerate the hash lock, run the complete
release gate, and merge through normal source control.

`apply-now` is retained as an API name for compatibility; its actual action is
`prepare_patch_for_pr`. `rollback` cancels the prepared artifact and does not modify a file.

## Evidence pipeline

```text
resolved installed packages -> OSV query -> normalized findings
                                + CISA KEV synchronization
successful scan -> proposal -> optional AI decision support -> admin approval
admin request -> immutable patch artifact -> reviewed PR -> CI -> deployment
```

The scan fails closed: proposals are not generated after incomplete or failed source queries.
Transitive installed packages are included. Versions are compared with `packaging.version`, OSV
fixed-event versions are parsed, CVSS vectors are not treated as numeric scores, and KEV status is
set only from the synchronized CISA catalog.

## API

- `GET /api/v1/self-security/summary`
- `GET /api/v1/self-security/dependencies`
- `GET /api/v1/self-security/dependencies/{id}/findings`
- `POST /api/v1/self-security/findings/{id}/suppress`
- `GET /api/v1/self-security/proposals`
- `POST /api/v1/self-security/proposals/{id}/approve`
- `POST /api/v1/self-security/proposals/{id}/reject`
- `POST /api/v1/self-security/proposals/{id}/apply-now`
- `POST /api/v1/self-security/proposals/{id}/rollback`
- `POST /api/v1/self-security/scan/trigger`
- `GET/PATCH /api/v1/self-security/settings`

All mutation endpoints require an active administrator and produce audit evidence.

## Limits

- Python package scanning is built in; container scanning is enforced separately in CI.
- AI validation is optional decision support and is never sufficient authorization.
- A proposal is not proof that an upgrade is compatible. Lock regeneration, tests, migration
  checks, image scans, and human review remain mandatory.
- Suppression is risk acceptance, not remediation; it needs an owner, rationale, and review date.
