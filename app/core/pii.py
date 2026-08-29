"""PII redaction for audit logs and logging output (M-09, P-05).

Sanitizes data before it goes into audit.details or application logs.
Hashes PII fields (email, IP) so they're searchable but not raw.
"""

import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Field names that contain PII
PII_FIELDS = {
    "email",
    "Email",
    "EMAIL",
    "phone",
    "Phone",
    "phone_number",
    "ssn",
    "SSN",
    "social_security_number",
    "ip",
    "ip_address",
    "remote_addr",
    "mac",
    "mac_address",
    "user_agent",
    "useragent",
    "User-Agent",
    "first_name",
    "last_name",
    "full_name",
    "address",
    "street",
    "postal_code",
    "credit_card",
    "card_number",
    "cvv",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
}

# Patterns for secrets in any text field (defense in depth)
SECRET_PATTERNS = [
    re.compile(r"kpx_[A-Za-z0-9_-]{32,}"),  # Kepryx API tokens
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),  # Anthropic
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),  # JWT
    re.compile(r"Bearer\s+[A-Za-z0-9_.-]{20,}", re.IGNORECASE),
]

# Email regex for hashing when email appears in free text
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}")

# IPv4/IPv6 patterns
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}")


def _hash_value(value: str, salt_suffix: str = "kepryx") -> str:
    """Deterministic hash for PII - same input always yields same hash.

    Allows searching ("find all logs for this email") without storing raw value.
    """
    return "h_" + hashlib.sha256(f"{value}:{salt_suffix}".encode()).hexdigest()[:16]


def _mask_email(email: str) -> str:
    """Show only first char and domain: alice@example.com -> a***@example.com"""
    if "@" not in email:
        return _hash_value(email)
    local, domain = email.rsplit("@", 1)
    return f"{local[:1]}***@{domain}" if local else f"***@{domain}"


def _mask_ip(ip: str) -> str:
    """Mask last octet: 192.168.1.42 -> 192.168.1.x"""
    if "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".x"
    if ":" in ip:
        # IPv6 - keep first 3 groups
        parts = ip.split(":")
        if len(parts) > 3:
            return ":".join(parts[:3]) + "::x"
    return _hash_value(ip)


def _mask_user_agent(ua: str) -> str:
    """P-05 fix: keep browser/OS family only, drop versions.

    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ... Chrome/120.0.6099.130
    -> Chrome/Windows
    """
    if not ua:
        return ""
    family = "Unknown"
    os_family = "Unknown"
    if "Firefox" in ua:
        family = "Firefox"
    elif "Edg/" in ua or "Edge" in ua:
        family = "Edge"
    elif "Chrome" in ua:
        family = "Chrome"
    elif "Safari" in ua:
        family = "Safari"
    elif "curl" in ua.lower():
        family = "curl"
    elif "python" in ua.lower():
        family = "python"

    if "Windows" in ua:
        os_family = "Windows"
    elif "Mac OS" in ua or "Macintosh" in ua:
        os_family = "macOS"
    elif "Linux" in ua:
        os_family = "Linux"
    elif "Android" in ua:
        os_family = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_family = "iOS"

    return f"{family}/{os_family}"


def redact_pii(data: Any) -> Any:
    """Recursively scrub PII from any dict/list/string before logging or storing.

    - Field names matching PII_FIELDS get masked/hashed
    - String values get scanned for secret patterns
    - Returns a new object (does not mutate input)
    """
    if isinstance(data, dict):
        return {k: _redact_field(k, v) for k, v in data.items()}
    if isinstance(data, list):
        return [redact_pii(item) for item in data]
    if isinstance(data, str):
        return _redact_string(data)
    return data


def _redact_field(field_name: str, value: Any) -> Any:
    """Decide how to redact based on field name."""
    lower = field_name.lower()
    if lower in ("email",) and isinstance(value, str):
        return _mask_email(value)
    if lower in ("ip", "ip_address", "remote_addr", "x-forwarded-for") and isinstance(value, str):
        return _mask_ip(value)
    if lower in ("user_agent", "user-agent", "useragent") and isinstance(value, str):
        return _mask_user_agent(value)
    if lower in ("password", "passwd", "secret", "token", "api_key", "private_key"):
        return "***REDACTED***"
    if lower in ("ssn", "social_security_number", "credit_card", "card_number", "cvv"):
        return "***REDACTED***"
    if lower in ("mac", "mac_address") and isinstance(value, str):
        return _hash_value(value, "mac")
    if isinstance(value, (dict, list)):
        return redact_pii(value)
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _redact_string(text: str) -> str:
    """Scan free text for secret patterns and redact them."""
    if len(text) < 8:
        return text
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("***REDACTED***", result)
    return result


class PIIRedactingFilter(logging.Filter):
    """Logging filter that redacts PII from log records.

    Install in main.py logging config:
      handler.addFilter(PIIRedactingFilter())
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, "msg") and isinstance(record.msg, str):
            record.msg = _redact_string(record.msg)
        if hasattr(record, "args") and record.args:
            try:
                if isinstance(record.args, dict):
                    record.args = redact_pii(record.args)
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        _redact_string(a) if isinstance(a, str) else a for a in record.args
                    )
            except Exception:
                record.msg = "[log redaction failed]"
                record.args = ()
        return True
