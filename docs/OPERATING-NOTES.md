# Operating Notes

Day-2 operations for Kepryx. How to run, monitor, troubleshoot, and recover.

## Service map

```
caddy            Edge reverse proxy, TLS terminator
api              FastAPI application (4 gunicorn workers)
worker-scanner   Nmap discovery and service scans (NET_RAW + NET_ADMIN only)
worker-enrich    CVE enrichment via NVD/EPSS/KEV
worker-recon     Integration sync + reconciliation + notifications
worker-selfsec   Self-security dependency scanner + AI update validator
beat             Celery beat scheduler
postgres         Asset, CVE, audit, alert storage
redis            Celery broker + cache
prometheus       Metrics scraping (optional observability profile)
```

## Starting and stopping

```bash
# Start the hardened default profile
docker compose up -d

# Optional services require separate image-risk acceptance
docker compose --profile observability up -d prometheus

# Stop without removing data
docker compose stop

# Stop and remove containers (data persists in volumes)
docker compose down

# Nuke everything including volumes — DESTROYS ALL DATA
docker compose down -v

# Restart one service after config change
docker compose restart api

# Rebuild one service after code change
docker compose up -d --build api
```

## Health checks

```bash
# Quick health
curl -k "https://kepryx.local:${HTTPS_PORT:-443}/health"

# Detailed system status (requires admin JWT)
curl -k -H "Authorization: Bearer $TOKEN" "https://kepryx.local:${HTTPS_PORT:-443}/api/v1/admin/system/status"

# Container status
docker compose ps

# Resource usage
docker stats --no-stream
```

If `/health` returns 200 but `/api/v1/admin/system/status` errors, the DB connection is down. Check `docker compose logs postgres`.

## Logs

All services log to stdout. View with:

```bash
# Live tail of all services
docker compose logs -f

# Last 100 lines from API
docker compose logs --tail 100 api

# Filter for errors
docker compose logs api 2>&1 | grep -i error

# Worker activity for a specific queue
docker compose logs -f worker-scanner
```

Recommended for production: ship logs to a SIEM via vector/fluent-bit/loki.

## Daily operations cheat sheet

| Task | Command |
|------|---------|
| Tail API logs | `docker compose logs -f api` |
| Check Celery beat schedule | `docker compose exec beat celery -A app.workers.celery_app inspect scheduled` |
| List active tasks | `docker compose exec worker-recon celery -A app.workers.celery_app inspect active` |
| Run DB backup now | `bash scripts/backup.sh` |
| Verify a connector | `curl -X POST -H "Authorization: Bearer $T" https://kepryx.local/api/v1/integrations/$ID/test` |
| Trigger network scan now | `curl -X POST -H "Authorization: Bearer $T" https://kepryx.local/api/v1/scans/trigger` |
| Open the API docs (dev only) | `https://kepryx.local/api/docs` (requires `DEBUG=true`) |
| Re-enrich one asset | `curl -X POST -H "Authorization: Bearer $T" https://kepryx.local/api/v1/assets/$ID/enrich` |
| Recompute all risk scores | `docker compose exec worker-recon celery -A app.workers.celery_app call app.workers.reconcile_tasks.rescore_assets` |
| Self-security scan now | `curl -X POST -H "Authorization: Bearer $T" https://kepryx.local/api/v1/self-security/scan/trigger` |

## Monitoring

Prometheus scrape targets are pre-configured in `docker/prometheus.yml`, but `/metrics` requires
an admin JWT in v0.9.0. Configure a short-lived service credential or a dedicated internal
metrics authentication path before enabling the optional Prometheus profile. Key metrics to alert on:

| Metric | Alert when | Reason |
|--------|------------|--------|
| `up{job="kepryx-api"}` | == 0 for 2m | API down |
| Celery queue depth | > 1000 in any queue for 5m | Worker behind |
| `pg_stat_database_xact_rollback` rate | spike | Failing transactions |
| Failed login count per IP | > 20 in 5m | Brute-force attempt |
| Self-security CRITICAL findings | > 0 | Vulnerable Kepryx |
| Alert backlog (`status=open`) | > 100 | Notifications failing |

No Grafana service is bundled in v0.9.0. The Kepryx dashboard provides the bounded operational
overview and inventory relationship map; an external visualization platform may also scrape or
query the approved Prometheus deployment.

## Database operations

```bash
# Connect to psql
docker compose exec postgres psql -U kepryx -d kepryx

# Inspect a specific asset
docker compose exec postgres psql -U kepryx -d kepryx -c "SELECT id, name, risk_tier, risk_score FROM assets WHERE name LIKE '%DC-PROD%';"

# Count alerts by type
docker compose exec postgres psql -U kepryx -d kepryx -c "SELECT alert_type, severity, count(*) FROM alerts WHERE status='open' GROUP BY 1,2 ORDER BY 3 DESC;"

# Apply pending migrations
docker compose exec api alembic upgrade head

# Roll back the last migration (DANGEROUS — data loss possible)
docker compose exec api alembic downgrade -1

# Show migration history
docker compose exec api alembic history
```

## Backup and restore

### Backup

Schedule on the host (Linux example with systemd timer or cron):

```bash
# Every 6 hours, retain 30 days
0 */6 * * * cd /opt/kepryx && bash scripts/backup.sh
```

Backups land in `/var/backups/kepryx/` by default. Ship to S3 or your archive store; the script has a commented-out `aws s3 cp` line.

### Restore

```bash
# Stop the stack
docker compose down

# Drop the existing volume
docker volume rm kepryx_postgres-data

# Bring up postgres alone
docker compose up -d postgres
sleep 30

# Restore
gunzip -c /var/backups/kepryx/kepryx_20260515_020000.sql.gz | \
  docker compose exec -T postgres psql -U kepryx -d kepryx

# Bring up the rest
docker compose up -d
```

Test this restore procedure before relying on it in production. Untested backups are theatre.

## Common failures and fixes

### "must_set" error on `docker compose up`
Cause: `.env` missing required values. Fix: copy `.env.example` to `.env` and fill in all `__generate_*__` placeholders.

### Postgres "FATAL: password authentication failed"
Cause: changed `POSTGRES_PASSWORD` after first volume creation. Fix: either restore the old password or drop the volume (`docker compose down -v`) — data loss.

### API container restarts in a loop
Run `docker compose logs api --tail 50`. Most common causes:
- Migrations not applied → `docker compose exec api alembic upgrade head`
- DB not ready → wait or check `postgres` health
- Bad `JWT_SECRET` (must be ≥32 chars) → regenerate

### Workers process tasks but assets don't appear
Run `docker compose logs worker-recon`. Most common causes:
- Connector test fails — re-run `POST /integrations/{id}/test`
- Reconciler exception on malformed connector data — check stack trace in worker logs

### "AI ingest" or "Kepryx Assistant" returns 503
Cause: the configured AI provider is disabled, unreachable, or missing its required credentials.
For local Qwen3, install/start Ollama on the host, confirm `ollama list` contains the configured
model, and use `AI_PROVIDER=ollama`, `AI_BASE_URL=http://host.docker.internal:11434`, and the
model name in `.env`. Restart with `docker compose up -d api worker-enrich worker-selfsec`.
Hosted providers are opt-in through the same provider-neutral adapter. AI only normalizes input;
NVD/EPSS/KEV remain authoritative for asset vulnerability facts and OSV remains authoritative
for platform dependency findings.

The Assistant is intentionally read-only and does not have action tools. Its endpoint is
`POST /api/v1/assistant/chat`; it retrieves a bounded evidence packet from the authenticated
operator's Kepryx deployment and returns `503` rather than a fabricated answer when the provider
is unavailable. Verify the answer against the cited Kepryx records. Requests are limited to
20 per source IP per minute.

### Nmap scans return 0 hosts
Cause: scanner worker doesn't have network reachability to the CIDR. Fix: ensure the Docker network the scanner is on has a route to your target network. Use `--network=host` for the scanner in dev (compromises isolation; do not do in production).

### Self-security update applied but containers still on old version
By design — the apply step patches `requirements.txt` but doesn't rebuild containers. Run `docker compose build && docker compose up -d` to activate.

### Celery beat missed a scheduled run
Run `docker compose logs beat | grep <task-name>`. Beat stores its schedule in `/tmp/celerybeat-schedule` which is in tmpfs and resets on restart — known design choice. For production-grade scheduling, mount a persistent volume for the beat schedule file.

## Capacity planning

| Workload | Resources at 1k assets | Resources at 10k assets | Resources at 100k assets |
|----------|------------------------|-------------------------|--------------------------|
| API | 1 vCPU, 1GB RAM | 2 vCPU, 2GB RAM | 4 vCPU, 4GB RAM |
| Postgres | 2 vCPU, 2GB RAM, 20GB disk | 4 vCPU, 8GB RAM, 200GB disk | 8 vCPU, 32GB RAM, 1TB disk |
| Redis | 0.5 vCPU, 512MB RAM | 1 vCPU, 1GB RAM | 2 vCPU, 4GB RAM |
| Scanner worker | 1 vCPU per scan parallelism | scale horizontally | scale horizontally |
| Enrichment worker | 2 vCPU (NVD rate-limited) | 4 vCPU, multiple replicas | 8 vCPU, multiple replicas |

Database growth has not yet been load-tested. Monitor actual table and index sizes, establish an approved retention policy, export/archive evidence before deletion, and validate restore procedures. Destructive retention is disabled by default.

## Scaling beyond a single host

Kepryx is shippable as a single-host Docker Compose deploy for under 10k assets. Beyond that, migrate to Kubernetes:

- API and workers: `Deployment` with HPA on CPU
- Beat: single replica (it's a singleton); use leader election if you must run multiple
- Postgres: managed (RDS, Cloud SQL, Aiven, or Patroni)
- Redis: managed (ElastiCache, Memorystore, or sentinel/cluster)
- A graph database only after an executable, tested graph integration exists

Kubernetes manifests are not shipped with v0.9.0 and have no committed release date.

## Operator runbook entries

- **Locked out admin account**: `docker compose exec postgres psql -U kepryx -d kepryx -c "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username='admin';"`
- **Disable a runaway integration**: `UPDATE integrations SET enabled=false WHERE name='<name>';`
- **Suppress a false-positive CVE finding** (self-security): `POST /api/v1/self-security/findings/{id}/suppress` with a reason
- **Force rotate JWT secret**: change `JWT_SECRET` in `.env`, `docker compose restart api`. All sessions invalidated immediately.
- **Restore from backup of a specific time**: see Backup section
- **Emergency stop all autonomous tasks**: `docker compose stop beat`. Scheduled tasks freeze; manual API triggers still work.

## When to call for help

Open a GitHub issue if:
- A documented workflow doesn't work as described
- An error message is opaque and the docs don't cover it
- You hit a bug that prevents production operation

For security issues, see `SECURITY.md` — never open public issues.
