"""Notification tasks — dispatch alerts via configured channels."""

import logging

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models import Alert, Asset
from app.services.notifications import Notifier
from app.services.webhook_dispatcher import fire_event
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.notification_tasks.dispatch_pending")
def dispatch_pending():
    return run_async(_dispatch_pending())


async def _dispatch_pending():
    async with SessionLocal() as db:
        result = await db.execute(
            select(Alert, Asset)
            .outerjoin(Asset, Alert.asset_id == Asset.id)
            .where(Alert.notified.is_(False), Alert.status == "open")
            .limit(100)
        )
        rows = result.all()
        notifier = Notifier()
        try:
            sent_count = 0
            for alert, asset in rows:
                payload = {
                    "id": str(alert.id),
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "title": alert.title,
                    "description": alert.description,
                    "asset_id": str(alert.asset_id) if alert.asset_id else None,
                    "asset_name": asset.name if asset else None,
                    "details": alert.details,
                }
                channels = await notifier.dispatch(payload)
                try:
                    # Webhook delivery is part of the notification flush so
                    # persisted alerts produce the same signed event stream
                    # as the explicit webhook test endpoint.
                    await fire_event("alert.created", alert.severity, payload)
                except Exception:
                    # A webhook receiver must not prevent other alert
                    # channels from being marked and retried normally.
                    logger.exception("Webhook dispatch failed for alert %s", alert.id)
                alert.notified = True
                alert.notification_channels = channels
                sent_count += 1
            await db.commit()
        finally:
            await notifier.close()
        return {"dispatched": sent_count}
