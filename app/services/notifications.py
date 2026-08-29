"""Notification pipeline: Slack, email, PagerDuty, syslog/CEF for SIEM."""

import logging
import smtplib
import socket
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f59e0b",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#64748b",
}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


class Notifier:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0)

    async def close(self):
        await self.client.aclose()

    async def dispatch(self, alert: dict, channels: list[str] | None = None) -> list[str]:
        """Dispatch alert to configured channels. Returns list of channels notified."""
        channels = channels or self._default_channels(alert.get("severity", "info"))
        sent = []
        for channel in channels:
            try:
                if channel == "slack" and settings.SLACK_WEBHOOK_URL:
                    await self._slack(alert)
                    sent.append("slack")
                elif channel == "email" and settings.SMTP_HOST:
                    self._email(alert)
                    sent.append("email")
                elif channel == "pagerduty" and settings.PAGERDUTY_KEY:
                    await self._pagerduty(alert)
                    sent.append("pagerduty")
                elif channel == "syslog":
                    self._syslog_cef(alert)
                    sent.append("syslog")
            except Exception as e:
                logger.error(f"Notification {channel} failed: {e}")
        return sent

    def _default_channels(self, severity: str) -> list[str]:
        if severity == "critical":
            return ["slack", "email", "pagerduty", "syslog"]
        if severity == "high":
            return ["slack", "email", "syslog"]
        if severity == "medium":
            return ["slack", "syslog"]
        return ["syslog"]

    async def _slack(self, alert: dict):
        sev = alert.get("severity", "info")
        payload = {
            "attachments": [
                {
                    "color": SEVERITY_COLORS.get(sev, "#64748b"),
                    "title": f"{SEVERITY_EMOJI.get(sev, '')} {alert.get('title')}",
                    "text": alert.get("description", ""),
                    "fields": [
                        {"title": "Severity", "value": sev.upper(), "short": True},
                        {"title": "Type", "value": alert.get("alert_type", ""), "short": True},
                        {
                            "title": "Asset",
                            "value": str(alert.get("asset_name") or alert.get("asset_id") or "—"),
                            "short": True,
                        },
                        {
                            "title": "Time",
                            "value": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                            "short": True,
                        },
                    ],
                    "footer": "KEPRYX Asset Intelligence",
                }
            ]
        }
        r = await self.client.post(settings.SLACK_WEBHOOK_URL, json=payload)
        r.raise_for_status()

    def _email(self, alert: dict):
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[KEPRYX {alert.get('severity', '').upper()}] {alert.get('title')}"
        msg["From"] = settings.SMTP_FROM
        msg["To"] = settings.SMTP_FROM  # configure recipients per env
        body = f"""
KEPRYX Security Alert

Severity:    {alert.get("severity", "").upper()}
Type:        {alert.get("alert_type")}
Title:       {alert.get("title")}
Asset:       {alert.get("asset_name") or alert.get("asset_id") or "N/A"}
Time:        {datetime.now(UTC).isoformat()}

Description:
{alert.get("description", "")}

Details:
{alert.get("details", {})}
"""
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as s:
            s.starttls()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.send_message(msg)

    async def _pagerduty(self, alert: dict):
        if alert.get("severity") not in ("critical", "high"):
            return
        payload = {
            "routing_key": settings.PAGERDUTY_KEY,
            "event_action": "trigger",
            "dedup_key": f"kepryx-{alert.get('alert_type')}-{alert.get('asset_id')}",
            "payload": {
                "summary": alert.get("title"),
                "severity": "critical" if alert.get("severity") == "critical" else "error",
                "source": "KEPRYX",
                "custom_details": alert.get("details", {}),
            },
        }
        r = await self.client.post("https://events.pagerduty.com/v2/enqueue", json=payload)
        r.raise_for_status()

    def _syslog_cef(self, alert: dict):
        """CEF format for SIEM ingestion. Sends to local syslog."""
        sev_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
        cef = (
            f"CEF:0|Anthropic|KEPRYX|1.0|"
            f"{alert.get('alert_type')}|{alert.get('title')}|"
            f"{sev_map.get(alert.get('severity', 'info'), 1)}|"
            f"src={alert.get('details', {}).get('ip', 'unknown')} "
            f"msg={alert.get('description', '').replace('|', '_')} "
            f"cs1={alert.get('asset_name', '')} cs1Label=AssetName"
        )
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(cef.encode(), ("localhost", 514))
            s.close()
        except OSError as e:
            logger.error(f"Syslog send failed: {e}")
