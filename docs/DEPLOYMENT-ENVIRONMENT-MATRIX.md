# Kepryx deployment environment matrix

Kepryx is currently a v0.9.0 community preview. This matrix separates the environments used to
evaluate the application from the controls required for an enterprise production deployment.
It prevents local demo settings from being mistaken for production evidence.

| Environment | Purpose | Data and network boundary | Required controls | Status |
| --- | --- | --- | --- | --- |
| Local evaluation | Engineer development and UI/API review | Synthetic data; `SCAN_NETWORKS=[]`; management bound to loopback; local Caddy certificate | Copy `.env.example` to `.env`; generate unique secrets; use the dev profile only on loopback | Supported |
| Clean-host validation | Reproducible release and recovery checks | Fresh Docker host; isolated lab CIDR only; no enterprise credentials | Apply migrations; bootstrap a disposable admin; test login, API/UI, scans, compliance, backup/restore; retain logs and artifacts | Required release gate |
| Private preview | Peer review and design-partner evaluation | Real DNS; restricted access; approved connector and scan CIDRs; synthetic or approved test data | External secret manager; managed certificate; off-host encrypted backups; central logs; least-privilege management CIDRs; incident contact | Next deployment target |
| Enterprise production | Customer-operated deployment | Customer network and data; formally authorized discovery ranges; segmented management and egress | HA database/Redis, tested RPO/RTO, key rotation, SSO/RBAC integration, WAF/VPN, monitoring/SIEM, patch process, threat model and independent assessment | Not claimed by v0.9.0 |

## Port and hostname conventions

- Local HTTP dev UI: `http://127.0.0.1:8080` when the `caddy-dev` profile is enabled.
- Local HTTPS: `https://kepryx.local:8443` when the local Caddy listener is mapped to 8443.
- Production TLS: terminate on an approved hostname with a managed or operator-managed certificate.
  Do not reuse the local certificate or local host entry.

## Boundary rules

1. Keep `SCAN_NETWORKS` empty until a written authorization defines the exact lab or customer CIDRs.
2. Keep `CONNECTOR_ALLOWED_CIDRS` limited to the connector endpoints that are explicitly approved.
3. Keep `MANAGEMENT_CIDRS` limited to the operator network; do not expose admin, metrics, or worker
   controls to the public internet.
4. Use separate secrets and databases for local, private preview, and production environments.
5. Treat a passing local or private-preview run as evidence for that environment only; it is not a
   claim that the application is highly available or certified for enterprise production.

See [Deployment](DEPLOYMENT.md) for the concrete Compose procedure and production prerequisites.
