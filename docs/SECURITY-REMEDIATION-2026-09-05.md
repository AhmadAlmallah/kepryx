# Kepryx edge-image security remediation

Evidence date: 2026-09-05 | Scope: edge/Caddy image dependency remediation

This record addresses the two findings reported by the edge-image Trivy gate. It is an engineering
remediation record, not a certification or a guarantee that future upstream scans will remain clean.

## Finding disposition

| Finding | Affected build input | Remediation applied | Verification status |
|---|---|---|---|
| CVE-2026-56854 / GHSA-gjhq-gjfw-99mq | `golang.org/x/crypto` below `v0.55.0` | Edge builder now requests `golang.org/x/crypto@v0.56.0`. | Image rebuild and Trivy verification required in GitHub CI. |
| CVE-2026-84304 / GHSA-vp52-pcj8-j9qc | `google.golang.org/grpc` through `v1.82.1` | Edge builder now requests `google.golang.org/grpc@v1.83.2`. | Image rebuild and Trivy verification required in GitHub CI. |

The selected versions are above the fixed versions published in the upstream records: `x/crypto`
is fixed at `v0.55.0`, and gRPC is fixed at `v1.83.1`.

- [CVE-2026-56854 / GHSA-gjhq-gjfw-99mq](https://github.com/advisories/GHSA-gjhq-gjfw-99mq)
- [GO-2026-6303](https://pkg.go.dev/vuln/GO-2026-6303)
- [CVE-2026-84304 / GHSA-vp52-pcj8-j9qc](https://osv.dev/vulnerability/GHSA-vp52-pcj8-j9qc)

## Source change

The edge builder in [docker/Dockerfile.caddy](../docker/Dockerfile.caddy) now pins both modules
explicitly before `go mod tidy` and compilation. This ensures the minimum-version decision is
visible in source and applied through minimal-version selection during the build.

The final runtime image remains a separate Alpine stage with no Go compiler or module cache. The
existing non-root user, read-only filesystem, dropped capabilities, and `NET_BIND_SERVICE` boundary
remain unchanged.

## Verification gate

The following must pass on the pull request built from the remediation commit:

1. the complete CI quality, security, migration, and container-security workflow;
2. the hardened edge-image boundary checks;
3. the edge-image Trivy scan with HIGH and CRITICAL findings visible and unfixed findings included;
4. the remaining API, worker, scanner, database, and fixture image scans;
5. Caddy configuration validation and CycloneDX SBOM generation.

Docker and Go were unavailable in the local workstation session that prepared this patch, so a local
green image scan is not claimed here. The remediation is **implemented but not closed** until the
rebuilt GitHub image scan passes. Do not describe the repository as CVE-free based on this source
change alone.
