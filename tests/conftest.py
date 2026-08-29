"""Safe defaults for local and CI test collection.

The application intentionally requires security and service settings at runtime. Tests use
synthetic values so importing a module does not depend on a developer's .env file or a live
Redis/PostgreSQL service. Integration tests that need those services provide their own fixtures.
"""

import os

_TEST_DEFAULTS = {
    "ENVIRONMENT": "test",
    "SECRET_KEY": "s" * 32,  # pragma: allowlist secret
    "JWT_SECRET": "j" * 32,  # pragma: allowlist secret
    "ENCRYPTION_KEY": "e" * 32,  # pragma: allowlist secret
    "POSTGRES_PASSWORD": "test",  # pragma: allowlist secret
    "REDIS_URL": "redis://localhost:6379/0",
    "ANTHROPIC_API_KEY": "",
    "ALLOWED_HOSTS": '["testserver", "localhost", "127.0.0.1"]',
    "CORS_ORIGINS": '["https://localhost"]',
}

for _name, _value in _TEST_DEFAULTS.items():
    os.environ.setdefault(_name, _value)
