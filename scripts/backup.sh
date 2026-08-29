#!/bin/bash
# Postgres backup script. Schedule via host cron or systemd timer.
# Recommended: every 6 hours, retain 30 days.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/kepryx}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILE="${BACKUP_DIR}/kepryx_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-kepryx}" \
    --no-owner --no-acl --clean --if-exists \
    "${POSTGRES_DB:-kepryx}" | gzip > "${FILE}"

# Verify backup is non-empty
if [ ! -s "${FILE}" ]; then
    echo "ERROR: backup file is empty"
    rm -f "${FILE}"
    exit 1
fi

# Prune old
find "${BACKUP_DIR}" -name "kepryx_*.sql.gz" -mtime "+${RETENTION_DAYS}" -delete

echo "Backup complete: ${FILE} ($(du -h "${FILE}" | cut -f1))"

# Optional: ship to S3
# aws s3 cp "${FILE}" "s3://your-backup-bucket/kepryx/" --sse AES256
