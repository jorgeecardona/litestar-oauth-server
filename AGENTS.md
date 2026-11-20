# AGENTS.md

Guidance for AI coding agents working in this repo. Humans: read README.md and CHANGELOG.md.

## Overview

litestar-oauth-server: An OAuth 2.1 authorization server plugin for Litestar: PKCE, client registration, token and refresh, with MCP-ready metadata.

Layout: `models.py` (frozen dataclasses, the data model), `stores.py` (storage protocols plus
in-memory stores), `server.py` (`AuthorizationServer`, all the rules, no HTTP), `plugin.py`
(Litestar endpoints, `bearer_guard`). The host app owns login, the consent page and the database.
Design plan for using it in Jorge's products: `../../MCP-PLAN.md`.

## Build

- `uv sync` installs dependencies. Toolchain (moon, uv) is pinned in `.prototools`; `proto install` brings it up.
- `make install-hooks` once, to enable the tracked git hooks.

## Test

- `make test` runs the suite.
- `make check` runs lint + typecheck + test (the same stage CI runs via `moon run :ci`).
- Everything in `make check` must pass before you commit.

## Style

- Format and autofix: `make format` (ruff, line length 100).
- Lint: `make lint`. Types: `make typecheck` (pyright strict on `src/`).
- Prefer frozen dataclasses and explicit types. Keep the public API typed (`py.typed`).

## Gotchas

- `CodeStore.consume` and `TokenStore.consume_refresh` must be atomic in every store. Never change
  them to read-then-write; a musil model in paas showed that double-mints a code.
- A token is valid only at its own `resource`; `verify` rejects every other. Do not loosen this.
- Wire format is snake_case JSON as the RFCs define it, not the camelCase house DTO style.
- No `dict[str, Any]` for domain data: add a frozen dataclass instead.
- Version lives as `__version__` in `src/litestar_oauth_server/__init__.py`; `pyproject.toml` reads it via `[tool.hatch.version]` (`version` is `dynamic`). The pre-commit hook auto-bumps it when `src/` changes. Do not edit versions by hand elsewhere.
- Record follow-ups in `docs/issues/`, not as scattered TODO comments.
