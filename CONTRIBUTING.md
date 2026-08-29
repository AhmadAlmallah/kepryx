# Contributing to Kepryx

Thanks for your interest in making Kepryx better.

## Ground rules

- **Be respectful** in issues, PRs, and discussions.
- **No security vulnerabilities in public issues** — see `SECURITY.md`.
- **All contributions are licensed under Apache 2.0** by submission (DCO sign-off recommended).
- **Maintainer has final say** on architectural decisions.

## How to contribute

### Bugs

1. Search existing issues first.
2. If new, open an issue using the bug template with: reproduction steps, expected vs actual behavior, version, environment, logs.

### Features

1. Open a discussion or issue describing the use case before writing code.
2. Wait for maintainer ack before investing significant time.
3. Smaller, focused PRs merge faster than sprawling ones.

### Pull requests

1. Fork the repo and create a feature branch off `main`.
2. Make changes following the code style below.
3. Add tests covering your change.
4. Run the full test suite locally: `pytest tests/`
5. Run linters: `ruff check . && ruff format --check .`
6. Update `CHANGELOG.md` under `## [Unreleased]`.
7. Open a PR using the template and link the related issue.

### Commit messages

Use conventional commits format:

```
feat(scope): short description
fix(scope): short description
docs(scope): short description
refactor(scope): short description
test(scope): short description
chore(scope): short description
```

Scopes: `api`, `worker`, `connector`, `risk`, `cve`, `self-security`, `auth`, `docker`, `docs`.

Examples:
- `feat(connector): add Microsoft Defender XDR connector`
- `fix(risk): correct EPSS normalization for missing scores`
- `docs(deploy): add Kubernetes manifests`

## Code style

- **Python 3.12+**
- **Formatter**: `ruff format` (PEP 8, line length 100)
- **Linter**: `ruff check` (E, F, W, I, B, UP, S, N rules)
- **Type hints**: required for all new function signatures
- **Docstrings**: required for public functions and classes
- **Imports**: stdlib → third-party → first-party, separated by blank lines
- **Async**: use `async def` for all I/O; never block the event loop
- **Logging**: use `logging.getLogger(__name__)`, never `print`
- **Secrets**: never log, never hardcode, always from settings

### Database changes

- **Always include an Alembic migration**: `alembic revision -m "describe change"`
- Never edit existing migrations — add a new one
- Hand-write migrations rather than relying on `--autogenerate` for production-targeting PRs

### Testing

- **Unit tests** in `tests/unit/`
- **Integration tests** in `tests/integration/` (require running stack)
- New connectors must have a `test_connection` mock test
- New API endpoints must have at least a 200 path and an auth-failure path
- Risk engine and self-security module changes require unit tests of the scoring logic

### Supported development environments

The hash-locked Python toolchain is exercised in Linux CI and is also supported through WSL2.
Native Windows Python is not the canonical gate environment because the `uvicorn[standard]`
dependency set includes `uvloop`, which does not support native Windows. Windows contributors can
use the Docker quick start for the application and WSL2 for the Python checks.

## Adding a connector

1. Subclass `BaseConnector` in `app/connectors/your_connector.py`
2. Implement `fetch_inventory()` and `test_connection()`
3. Register with `@register_connector("your_name")`
4. Add to `SOURCE_PRIORITY` in `app/services/reconciler.py` if it's authoritative
5. Document config schema in the connector module docstring
6. Add an integration test with a mocked transport

## Adding a compliance framework

1. Extend `CONTROL_RULES` in `app/workers/compliance_tasks.py`
2. Add rules that take an `Asset` and return `bool`
3. Update the docs in `README.md` and `docs/`

## Release process

Maintainer-only:

1. Bump the version in `pyproject.toml`, `app/main.py`, and the admin status endpoint
2. Move `[Unreleased]` to a dated version in `CHANGELOG.md`
3. Re-run the release gate from the exact candidate commit
4. Create and push a signed semantic-version tag
5. Confirm CI and image scans pass
6. Draft the GitHub release from the matching changelog entry

## Code of conduct

This project follows the Contributor Covenant 2.1. Unacceptable behavior may be reported privately to the maintainer.

By contributing you agree to these terms and that your contributions are licensed under Apache 2.0.
