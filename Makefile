.PHONY: help up down build logs install-dev test lint typecheck security verify format migrate bootstrap backup clean

help:
	@echo "Kepryx development commands"
	@echo ""
	@echo "  make up         - Start all services in background"
	@echo "  make down       - Stop all services (keep volumes)"
	@echo "  make build      - Rebuild images"
	@echo "  make logs       - Tail logs (all services)"
	@echo "  make migrate    - Apply Alembic migrations"
	@echo "  make bootstrap  - Create initial admin user"
	@echo "  make test       - Run unit tests"
	@echo "  make lint       - Run ruff lint check"
	@echo "  make typecheck  - Run mypy"
	@echo "  make security   - Run Bandit and dependency audit"
	@echo "  make verify     - Run the local release gate"
	@echo "  make format     - Auto-format code"
	@echo "  make backup     - Run database backup"
	@echo "  make clean      - DESTROY all volumes (asks confirmation)"

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

logs-api:
	docker compose logs -f api

logs-workers:
	docker compose logs -f worker-scanner worker-enrich worker-recon worker-selfsec beat

migrate:
	docker compose run --rm migrate

bootstrap:
	docker compose exec api python -m scripts.bootstrap

test:
	python -m pytest -q

install-dev:
	python -m pip install --require-hashes -r requirements-dev.txt

lint:
	ruff check app/ alembic/ scripts/ tests/ demo/
	ruff format --check app/ alembic/ scripts/ tests/ demo/

typecheck:
	mypy app/

security:
	bandit -r app/ -ll -ii --skip B101
	pip-audit --strict --disable-pip -r requirements.txt

verify: lint typecheck test security
	docker compose config --quiet

format:
	ruff format app/ alembic/ scripts/ tests/ demo/
	ruff check --fix app/ alembic/ scripts/ tests/ demo/

backup:
	bash scripts/backup.sh

status:
	docker compose ps
	@echo ""
	@curl -fsSk https://kepryx.local/health || echo "API not reachable"

clean:
	@echo "This will DESTROY all data volumes. Are you sure? [y/N]"
	@read ans && [ "$$ans" = "y" ] || (echo "Aborted"; exit 1)
	docker compose down -v
