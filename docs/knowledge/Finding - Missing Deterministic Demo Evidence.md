---
type: finding
status: evidence-ready
owner: Ahmad Almallah
confidence: high
evidence: demo/data/asset_inventory.csv, authenticated dry-run and process results, clean-host risk/compliance evidence, and the demo runbook; connector fixtures remain separate integration tests
next_verification: record the full CSV ingest-to-risk-to-webhook walkthrough before public launch
---
# Finding - missing deterministic demo evidence

The primary v0.9 demo is now `demo/data/asset_inventory.csv`, imported through the supported CSV
bulk-ingest path. It uses reserved documentation IP ranges and demonstrates inventory, shadow-IT
classification, risk scoring, and downstream alert/compliance views without vendor services.
Vendor connector fixtures remain test-only evidence rather than the public onboarding path. The
repeatable ingest-to-risk-to-webhook path is validated; the screen recording itself is still
outstanding.

Link: [[../NEXT-PHASE-IMPLEMENTATION-PLAN|implementation plan]]
