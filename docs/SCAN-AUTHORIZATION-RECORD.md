# Synthetic scan authorization record

Status: completed for the v0.9 community-preview lab only
Evidence date: 2026-08-27
Authorization type: synthetic, non-customer, non-production

## Approved test scope

| Field | Value |
|---|---|
| Purpose | Validate the authorized network-discovery workflow and fail-closed boundary |
| Reserved CIDR | `198.51.100.0/28` |
| Synthetic target | `198.51.100.10` |
| Network | Isolated Docker clean-test bridge only |
| Data | Synthetic Asset Source fixture; no customer data |
| Expiration | On teardown of the clean-test project |

The CIDR is from the documentation-only TEST-NET-2 range. It is not a customer or LAN range and
must never be replaced with a real network without a separate written approval from the network
owner.

## Controls and evidence

- `SCAN_NETWORKS` is the execution allowlist; an empty value disables active scanning.
- API validation rejects a CIDR outside the configured boundary before queueing a job.
- Worker execution re-checks the boundary and skips database rows that are not authorized by
  `SCAN_NETWORKS`; database rows are not treated as authorization.
- The clean-host proof discovered only the synthetic target inside the reserved CIDR.
- The live cancellation proof verified that a cancelled scan is recovered as a failed job with
  `recovered stale scan after worker interruption` recorded as the reason.

## Deployment requirement

This record does not authorize scanning any customer, partner, Internet, or corporate network.
Before enabling scanning in a real deployment, replace it with a dated approval naming the
network owner, exact CIDRs, purpose, exclusions, operator, expiration, and incident contact.
