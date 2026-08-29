# Clean-host verification

This overlay creates isolated networks and fresh project-scoped volumes so the release
candidate can be tested without using the normal Kepryx data volumes. It is a verification
harness, not a production deployment profile.

```bash
docker compose -p kepryx-clean \
  -f docker-compose.yml -f docker-compose.clean-test.yml \
  up -d --build

docker compose -p kepryx-clean \
  -f docker-compose.yml -f docker-compose.clean-test.yml \
  exec api alembic check
```

For the operational proof, bootstrap a disposable administrator, add only an explicitly authorized
reserved lab proof network such as `198.51.100.0/28`, run the CSV fixture through the UI or API,
trigger compliance and self-security jobs, and verify the scan reaches `completed`. For
backup/restore, run the
following equivalent inside the isolated PostgreSQL container; restore into a separate disposable
database, never over the source database:

```bash
docker compose -p kepryx-clean -f docker-compose.yml -f docker-compose.clean-test.yml \
  exec -T postgres sh -ec \
  'pg_dump -U kepryx --no-owner --no-acl --clean --if-exists kepryx | gzip > /tmp/kepryx.sql.gz'

# Create restore_test, then restore /tmp/kepryx.sql.gz into it and verify row counts.
# Drop restore_test before teardown.
```

The 2026-08-25 verification passed with fresh volumes: migrations reached `0006_schema_alignment`,
HTTPS/UI/API/login worked, the vendor-neutral fixture created 10 assets, the loopback scan found
one host, compliance and self-security completed, and an 18,847-byte dump restored 11 assets into
a separate database at the same migration head.

The clean edge is available at `https://kepryx.local:8444` with the internal test CA. The normal
local Windows stack uses `https://kepryx.local:8443` because Docker Desktop host port 443 resets
the current Windows TLS client; real deployments should leave `HTTPS_PORT=443` and use a real
DNS/ACME certificate. The overlay
also defines the isolated documentation-only virtual CIDR `198.51.100.0/28` and a synthetic
target at `198.51.100.10`; this is not a customer or LAN range. Only the scanner worker is attached
to that virtual network, and the API authorization boundary is overridden to that range for this
test project. Use the
temporary bootstrap credentials only for this isolated run, test login and the UI/API journey,
then exercise backup/restore before tearing the project down:

```bash
docker compose -p kepryx-clean \
  -f docker-compose.yml -f docker-compose.clean-test.yml \
  down -v
```

Never point the clean test at customer CIDRs. The default proof boundary remains empty unless
the test operator explicitly supplies an authorized range.
