"""Alembic environment — autogenerate from app.models metadata."""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
from app.core.config import settings
from app.core.database import Base
import app.models  # noqa: F401 - import registers all models with Base.metadata

config = context.config
config.set_main_option("sqlalchemy.url", settings.db_url_sync)

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
