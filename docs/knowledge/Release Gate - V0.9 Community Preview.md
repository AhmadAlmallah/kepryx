---
type: release-gate
status: conditional-preview
owner: Ahmad Almallah
confidence: high
evidence: docs/API-CONTRACT-V0.9.md, tests/integration/, docs/REMEDIATION-EVIDENCE.md, and live edge smoke evidence
next_verification: exact release image rescan, real DNS/ACME HTTPS smoke, full demo recording, peer review, and private GitHub rehearsal
---
# Release gate - v0.9 community preview

The weighted target is at least 80/100. For this community preview, the Python/runtime images and
Alpine package layers must have no unreviewed high or critical findings in the exact raw scan. The
custom Caddy build currently passes that gate and CI fails closed on any new finding. No secrets, clean auth/
RBAC and migration evidence, Caddy/UI same-origin smoke, truthful demo labeling, private
vulnerability reporting, and one peer review remain mandatory. This is not a production or
certification claim.

Links: [[../RELEASE-SCORECARD|scorecard]], [[../NEXT-PHASE-IMPLEMENTATION-PLAN|implementation plan]]
