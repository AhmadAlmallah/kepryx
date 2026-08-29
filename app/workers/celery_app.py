"""Celery app â€” workers + beat schedule for autonomous operations."""

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "kepryx",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.scan_tasks",
        "app.workers.enrichment_tasks",
        "app.workers.reconcile_tasks",
        "app.workers.notification_tasks",
        "app.workers.compliance_tasks",
        "app.workers.self_security_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3300,
    worker_max_tasks_per_child=100,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_routes={
        "app.workers.scan_tasks.*": {"queue": "scanner"},
        "app.workers.enrichment_tasks.*": {"queue": "enrichment"},
        "app.workers.reconcile_tasks.*": {"queue": "reconciler"},
        "app.workers.notification_tasks.*": {"queue": "notifications"},
        "app.workers.compliance_tasks.*": {"queue": "reconciler"},
        "app.workers.self_security_tasks.*": {"queue": "self_security"},
    },
)

celery_app.conf.beat_schedule = {
    # Daily network discovery scan â€” 02:00 UTC
    "daily-network-discovery": {
        "task": "app.workers.scan_tasks.run_all_network_scans",
        "schedule": crontab(hour=2, minute=0),
    },
    # Hourly: pull from all enabled integrations
    "hourly-integration-sync": {
        "task": "app.workers.reconcile_tasks.sync_all_integrations",
        "schedule": crontab(minute=15),
    },
    # Every 4 hours: CVE enrichment for assets with new/changed software
    "cve-enrichment-cycle": {
        "task": "app.workers.enrichment_tasks.enrich_pending_assets",
        "schedule": crontab(minute=30, hour="*/4"),
    },
    # Daily: refresh NVD/EPSS/KEV catalogs
    "daily-cve-feeds-sync": {
        "task": "app.workers.enrichment_tasks.sync_cve_feeds",
        "schedule": crontab(hour=1, minute=0),
    },
    # Every 30 min: stale asset detection
    "stale-asset-detection": {
        "task": "app.workers.reconcile_tasks.detect_stale_and_gaps",
        "schedule": crontab(minute="*/30"),
    },
    # Every 15 min: recompute risk scores for changed assets
    "risk-rescore": {
        "task": "app.workers.reconcile_tasks.rescore_assets",
        "schedule": crontab(minute="*/15"),
    },
    # Daily: compliance audit
    "daily-compliance-audit": {
        "task": "app.workers.compliance_tasks.run_compliance_audit",
        "schedule": crontab(hour=3, minute=0),
    },
    # Every 5 min: flush pending notifications
    "notification-flush": {
        "task": "app.workers.notification_tasks.dispatch_pending",
        "schedule": crontab(minute="*/5"),
    },
    # Weekly: cleanup old audit/alert data
    "weekly-cleanup": {
        "task": "app.workers.reconcile_tasks.cleanup_old_data",
        "schedule": crontab(hour=4, minute=0, day_of_week=0),
    },
    # Daily 01:00 â€” scan KEPRYX's own dependencies for CVEs
    "self-security-scan": {
        "task": "app.workers.self_security_tasks.scan_platform_deps",
        "schedule": crontab(hour=1, minute=0),
    },
    # Daily 01:15 â€” generate update proposals for vulnerable deps
    "self-security-propose": {
        "task": "app.workers.self_security_tasks.propose_updates",
        "schedule": crontab(hour=1, minute=15),
    },
    # Daily 01:30 â€” AI-validate pending proposals
    "self-security-ai-validate": {
        "task": "app.workers.self_security_tasks.ai_validate_proposals",
        "schedule": crontab(hour=1, minute=30),
    },
    # Weekly Sunday 02:00 â€” apply approved updates within maintenance window
    "self-security-apply": {
        "task": "app.workers.self_security_tasks.apply_approved_updates",
        "schedule": crontab(hour=2, minute=0, day_of_week=0),
    },
    "enforce-retention-daily": {
        "task": "app.workers.retention_tasks.enforce_all_retention",
        "schedule": crontab(hour=3, minute=0),
    },
}
