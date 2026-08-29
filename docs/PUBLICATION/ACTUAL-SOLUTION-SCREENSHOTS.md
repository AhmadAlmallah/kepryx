# Kepryx actual-solution screenshots

The complete capture index is now maintained in the [Kepryx product gallery](PRODUCT-GALLERY.md).
These are screenshots of the running Kepryx operator console, not a UI concept or a generated
mockup.

The README hero set is intentionally limited to four strong views:

- [Dashboard](../images/product/dashboard.png)
- [Kepryx Assistant](../images/product/assistant.png)
- [Risk Assessment](../images/product/risk-assessment.png)
- [Compliance](../images/product/compliance.png)

The gallery also indexes the remaining product views and workflow evidence, including Assistant,
asset creation, risk context, compliance lineage, authorized scanning, API tokens, webhooks,
privacy, and the interactive relationship map.

## What still needs capture or recapture

- Login is not present in the supplied set.
- Alert investigation and resolution is not present as a completed workflow.
- Inventory and mail-asset captures show vendor-specific/sample context and were excluded from the
  public candidate; recapture them with the vendor-neutral fixture if they are needed.
- Compliance lineage and scan-network captures show private-looking RFC1918 values; use reserved
  documentation ranges in the final public set.
- Self-Security should be captured after the current dependency scan so its displayed package state
  agrees with the exact release evidence.
- My Security should use a synthetic publication identity and should not imply that MFA is disabled
  in the maintained release account; its current capture was excluded.

## Image safety rule

Every image must be inspected at 100%. Do not publish passwords, tokens, API keys, private
certificates, real customer data, unauthorized scan ranges, or an internal identity. Screenshots
are evidence of a local preview state, not a permanent production guarantee.
