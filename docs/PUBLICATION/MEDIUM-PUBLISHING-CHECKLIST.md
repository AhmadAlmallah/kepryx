# Medium publishing checklist

This checklist turns `KEPRYX-MEDIUM-ARTICLE.md` into a publishable article while keeping the
claims honest and the visuals professional.

## Before upload

- Replace the working title only if the final title remains direct and searchable:
  `Kepryx: the asset intelligence layer security teams are still missing`.
- Use a subtitle that states the value: `An open-source asset intelligence and risk platform for
  connecting inventory, vulnerability facts, compliance evidence, and daily operations.`
- Use `Ahmad Almallah` as the author name and the consulting email only on the GitHub contact/security
  pages, not inside screenshots or sample credentials.
- Confirm that no passwords, tokens, API keys, private hostnames, real customer data, or private
  scan ranges appear in the article, image files, or alt text.
- Keep the article labeled as a v0.9.0 community preview. Do not use “certified,” “enterprise-ready,”
  “prevents breaches,” or “AI security analyst” as an unqualified claim.

## Visual upload order

1. `../images/product/dashboard.png` — actual opening product view.
2. `../images/product/inventory.png` — actual inventory and source-context view.
3. `../images/product/risk-assessment.png` — transparent risk posture and remediation view.
4. `../images/product/compliance.png` — actual compliance view.
5. `../diagrams/kepryx-breach-to-evidence-loop.svg` — problem framing.
6. `../diagrams/ingest-risk-flow.svg` — operational pipeline.
7. `../diagrams/compliance-evidence-lineage.svg` — evidence explanation.
8. `../diagrams/kepryx-deployment-security-boundaries.svg` — architecture and trust boundaries.
9. `../images/release-scorecard-chart.svg` — honest release posture.

Medium does not resolve repository-relative image paths reliably. Upload the local files directly,
then paste the article text around the uploaded images. Preserve the captions and alt text from
`SCREENSHOT-AND-DIAGRAM-PLAN.md`.

The product PNGs are actual solution screenshots. Upload the four hero views before the diagrams so
the reader sees the product before the architecture. Keep the Kepryx wordmark, navigation, API
status, and synthetic-data context visible. Use the [complete product gallery](PRODUCT-GALLERY.md)
for the remaining views and workflow captures.

## Editorial pass

- Keep the direct first-person voice: “I built,” “I tested,” “I am not hiding the gaps.”
- Keep the breach framing probabilistic: many incidents are enabled by visibility and hygiene
  gaps; do not claim all breaches start in one way.
- Keep NVD, EPSS, KEV, and OSV described as authoritative data sources within the platform, not as
  model-generated facts.
- Keep AI described as bounded, read-only, and advisory.
- Keep the next post focused on deployment and integration; do not make the current article a full
  operations runbook.

## Link pass

- Link the GitHub repository after it exists.
- Link `SECURITY.md`, the Apache-2.0 license, the demo runbook, and the release evidence directory.
- Keep the standards and data-source links in the article: NIST CSF, NVD, FIRST EPSS, CISA KEV, OSV.
- Add a short “tested on” note with the exact preview date and local-only test-data disclaimer.

## Final safety gate

Run the exact-candidate secret scan again after inserting the final repository URL and any new
screenshots. Do not publish the article until the GitHub repository has private-first review,
security reporting enabled, and the release evidence attached.
