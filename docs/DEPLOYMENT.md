# Deployment

This guide deploys the Kepryx v0.9.0 community preview on one Docker host. It is an evaluation
baseline, not a claim of high availability or production certification.

## Prerequisites

- Docker Engine 24+ with Compose v2.20+
- 4 CPU cores, 8 GB RAM, and 50 GB free disk for evaluation
- An internal management hostname and TLS plan
- Outbound HTTPS to the CVE sources and connectors you explicitly enable
- Written authorization for every CIDR that Kepryx will scan

## Configure

Copy the example file:

```bash
cp .env.example .env
```

Generate three different random values of at least 32 bytes for `SECRET_KEY`, `JWT_SECRET`,
and `ENCRYPTION_KEY`. Set strong unique values for the PostgreSQL and Redis passwords. Never
commit `.env`.

Restrict `ALLOWED_HOSTS` and `CORS_ORIGINS` to the deployment hostname. The default trusted
proxy is the Caddy address `172.29.0.2/32`; change the edge subnet and this value together if
that network conflicts with an existing route.

Set `MANAGEMENT_CIDRS` to the approved client/VPN CIDRs for administrator and other privileged
management operations. Requests outside this list are rejected after trusted-proxy processing;
do not leave the local Docker defaults in place for a real deployment. If an internal connector
must use a private IP literal, add only its explicitly authorized network to
`CONNECTOR_ALLOWED_CIDRS`. Hostname-based connectors still require deployment egress controls.

`SCAN_NETWORKS` is intentionally empty. Add only explicitly approved targets.

For local evaluation, add this hosts entry:

```text
127.0.0.1 kepryx.local
```

The supplied Caddyfile uses its internal CA. On the current Windows Docker Desktop host, use the
local `HTTPS_PORT=8443` mapping. For a public or enterprise deployment, leave `HTTPS_PORT=443`,
replace `kepryx.local` and `tls internal` with the organization's approved DNS and ACME or managed
certificate setup.

## Start and initialize

```bash
docker compose up -d --build
docker compose ps
docker compose logs migrate
curl -k "https://kepryx.local:${HTTPS_PORT:-443}/health"
docker compose exec api python -m scripts.bootstrap
```

The one-shot migration service must succeed before the API and workers start. Bootstrap asks
for an admin email and a policy-compliant password without echoing the password or writing it
to logs.

After login, enroll MFA, create only the required API tokens, and test each connector before
enabling scheduled synchronization.

## Optional services

Prometheus is disabled in the default profile:

```bash
docker compose --profile observability up -d prometheus
```

The pinned Prometheus image must pass the same current vulnerability gate before it is enabled.
Grafana and Neo4j are intentionally not bundled because no dashboards or executable graph
integration are present in this preview.

## Operational verification

```bash
docker compose ps
curl -k "https://kepryx.local:${HTTPS_PORT:-443}/health"
curl -k "https://kepryx.local:${HTTPS_PORT:-443}/ready"
docker compose run --rm migrate alembic current
docker compose run --rm migrate alembic check
```

Expected controls:

- A request with an unapproved `Host` header is rejected.
- `/metrics` requires an admin JWT on the API network and is unavailable through Caddy.
- API documentation is disabled when `DEBUG=false`.
- API, workers, scanner, Caddy, PostgreSQL, and Redis are not root processes.
- The API runtime contains no package installer.

### Local development edge

If local Caddy HTTPS is unavailable during development, use the localhost-only profile:

```bash
docker compose --profile dev-ui up -d caddy-dev
```

Then open `http://127.0.0.1:8080/`. The profile is bound to loopback, serves the immutable
frontend, and reverse-proxies API/WebSocket traffic to the backend. Do not expose this profile
as a production edge.

## Upgrade

1. Back up PostgreSQL and verify the backup is readable.
2. Review `CHANGELOG.md`, dependency-lock changes, image digests, and migration downgrade notes.
3. Build and scan images in a private environment.
4. Run migrations against a restored copy of production data.
5. Deploy with `docker compose up -d --build` and run the verification commands above.

Migration `0005_foundation_remediation` intentionally has no automatic downgrade because it
encrypts/scrubs legacy credential material. Rollback is restore-from-backup, not Alembic downgrade.

## Production prerequisites not supplied by this repository

- Redundant hosts or an orchestrator, managed PostgreSQL/Redis, tested failover, and capacity data
- External secrets delivery and key rotation procedures
- Central log/SIEM shipping, alert ownership, and on-call runbooks
- Off-host encrypted backups with regular restore exercises
- WAF/VPN/management-plane access controls and host hardening
- Independent penetration test, threat-model review, privacy assessment, and recovery exercise

Do not describe a deployment as production-ready until those controls and the missing integration,
E2E, load, failover, and restore tests are evidenced for the target environment.
