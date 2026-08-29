---
type: finding
status: remediated-pending-next-rescan
owner: Ahmad Almallah
confidence: high
evidence: docs/REMEDIATION-EVIDENCE.md, docker/Dockerfile.caddy, and sequential raw Trivy 0.67.2 scan of the rebuilt edge image
next_verification: rerun the weekly and exact-candidate raw scan after any Caddy source, Go, or module change
---
# Finding - Caddy upstream Go residual risk

The rebuilt edge image uses the Caddy 2.11.4 source release, Go 1.26.6, explicit fixed module
versions, and a pinned Alpine runtime upgraded during the image build. Sequential raw Trivy
0.67.2 scanning reports zero HIGH/CRITICAL findings. The former allowlist was removed so CI fails
closed on any new finding.

This is a point-in-time release gate for the v0.9 community preview, not a permanent CVE-free or
production-certification claim.

Links: [[Release Gate - V0.9 Community Preview]], [[../REMEDIATION-EVIDENCE|remediation evidence]]
