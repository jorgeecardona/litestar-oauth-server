# litestar-oauth-server

[![pipeline status](https://gitlab.com/cardona-oss/litestar-oauth-server/badges/main/pipeline.svg)](https://gitlab.com/cardona-oss/litestar-oauth-server/-/pipelines)
[![PyPI version](https://img.shields.io/pypi/v/litestar-oauth-server.svg)](https://pypi.org/project/litestar-oauth-server/)
[![Python versions](https://img.shields.io/pypi/pyversions/litestar-oauth-server.svg)](https://pypi.org/project/litestar-oauth-server/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://gitlab.com/cardona-oss/litestar-oauth-server/-/blob/main/LICENSE)

An OAuth 2.1 authorization server plugin for Litestar: PKCE, client registration, token and refresh, with MCP-ready metadata

## Install

```bash
pip install litestar-oauth-server
```

Requires Python 3.12+. For stores on Postgres, add the extra and a Postgres driver:

```bash
pip install "litestar-oauth-server[sqlalchemy]" "psycopg[binary]"
```

## Quickstart

```python
from litestar import Litestar, Request, get
from litestar_oauth_server import (
    AuthorizationServer, LitestarOAuth, OAuthConfig, bearer_guard, in_memory_stores, verified_token,
)

RESOURCE = "https://api.example.com/mcp"

server = AuthorizationServer(
    config=OAuthConfig(
        issuer="https://api.example.com",
        authorization_endpoint="https://app.example.com/oauth/authorize",  # your consent page
        resources=(RESOURCE,),
        scopes_supported=("things:read", "things:write"),
    ),
    stores=in_memory_stores(),  # use stores on your own database in production
)

@get("/mcp", guards=[bearer_guard(server, RESOURCE, scope="things:read")])
async def things(request: Request) -> str:
    token = verified_token(request)  # subject, binding, scopes
    return f"hello {token.subject}, pinned to {token.binding}"

app = Litestar([things], plugins=[LitestarOAuth(server)])
```

Your consent page signs the user in with your own login, then calls
`server.approve(request, Approval(subject=..., scopes=..., binding=...))` and sends the browser to
the URL it returns. See `examples/basic.py`.

## Stores on Postgres

`litestar_oauth_server.sqlalchemy` has ready stores for Postgres (SQLAlchemy 2, async). Steps:

1. Define the tables on your own `MetaData`, so your Alembic sees them. This package ships no
   migrations.
2. Build the stores from your `AsyncEngine`.

```python
from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import create_async_engine
from litestar_oauth_server import AuthorizationServer
from litestar_oauth_server.sqlalchemy import oauth_tables, sql_stores

metadata = MetaData()  # your app's metadata
tables = oauth_tables(metadata, prefix="oauth_")  # oauth_clients, oauth_codes, oauth_tokens
engine = create_async_engine("postgresql+psycopg://user:pass@localhost/app")
# `config` is the OAuthConfig of the Quickstart
server = AuthorizationServer(config=config, stores=sql_stores(engine, tables))
```

Each store method runs in its own transaction and commits. It does not join your session: if your
code rolled back after a failed exchange, a used authorization code would come back to life.
`consume` and `consume_refresh` are each one statement (`DELETE ... RETURNING` and
`UPDATE ... WHERE used_at IS NULL RETURNING`), so two exchanges of one code cannot both succeed.

Only Postgres is supported. `sql_stores` raises `ValueError` for another database. Use
`in_memory_stores()` in development.

Expired rows are never read again. Delete them from a periodic job, before
`purge_unused_clients()`:

```python
await stores.delete_expired(datetime.now(UTC))
```

## Test your own stores

`litestar_oauth_server.testing.CASES` is a contract suite for any store: a code is consumed once,
a refresh token is claimed once when two exchanges race, a family is revoked as a whole. It does
not import pytest. Each case takes an empty `Stores`:

```python
import pytest
from litestar_oauth_server.testing import CASES

@pytest.mark.anyio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
async def test_my_stores(case):
    await case(await make_empty_stores())
```

## Why litestar-oauth-server

Adding "Connect to Claude", a CLI login or a third-party integration to a Litestar API needs an
OAuth 2.1 authorization server: PKCE, client registration, token and refresh, discovery documents.
This library provides that part and leaves the login, the consent screen and the database to your
app. It is the server side an MCP connector needs, and it works the same for any other client.

## Key features

- Authorization code flow with PKCE (S256 only), public clients, refresh token rotation.
- Server metadata (RFC 8414), protected resource metadata (RFC 9728), dynamic client registration
  (RFC 7591), revocation (RFC 7009), resource indicators (RFC 8707).
- A `binding` on every token: the tenant chosen on the consent screen. The token never crosses it.
- Narrow scopes: the user approves a subset of what the client asked for (read-only first).
- Code and refresh token are single use; a reused refresh token revokes its whole family.
- Optional CORS on the OAuth routes only: `OAuthConfig(cors_origins=("https://inspector.example",))`,
  so a browser client can reach them. It applies when your app has no `cors_config` of its own.
- A rate limit on `POST /oauth/register`, per client address: 20 an hour by default
  (`register_rate_limit=("hour", 20)`, or `None` to turn it off). Behind a proxy, make the server
  read the forwarded address first (uvicorn: `--proxy-headers --forwarded-allow-ips`).
- `await server.purge_unused_clients()` deletes clients older than `unused_client_ttl` (30 days)
  that no code or token refers to. Run it from your own periodic job. Your client store opts in by
  implementing `ClientPurge.delete_unused(created_before)`.
- `server.list_clients()` and `server.delete_client(client_id)` for an admin page. Your client store
  opts in by implementing `ClientAdmin`. Tokens already issued to a deleted client stay valid until
  they expire or are revoked.
- Stores on Postgres with SQLAlchemy (extra `sqlalchemy`), and a contract test suite for your own.
- A bearer guard that answers 401 with `WWW-Authenticate: Bearer resource_metadata=...`.
- Importing the package does not import Litestar: the models, the stores and `AuthorizationServer`
  work in a package with no web code. The Litestar names load on first use. Litestar is still
  installed with the package.
- Frozen dataclasses throughout. Storage is three small protocols you implement on your database.
  They take and return any object with the right attributes (`ClientLike`, `CodeLike`,
  `TokenLike`), so your database layer does not import this package at runtime.

## Links

- **Documentation:** https://cardona-oss.gitlab.io/litestar-oauth-server/
- **Source:** https://gitlab.com/cardona-oss/litestar-oauth-server
- **Issues:** https://gitlab.com/cardona-oss/litestar-oauth-server/-/issues
- **PyPI:** https://pypi.org/project/litestar-oauth-server/
- **Changelog:** [CHANGELOG.md](https://gitlab.com/cardona-oss/litestar-oauth-server/-/blob/main/CHANGELOG.md)

## Contributing

Developer setup, the dev loop, and the release process live in
[CONTRIBUTING.md](https://gitlab.com/cardona-oss/litestar-oauth-server/-/blob/main/CONTRIBUTING.md). In short: `uv sync && make install-hooks`, then
`make check` runs the same gate CI runs.

## License

MIT © 2026 Jorge Cardona (see [LICENSE](https://gitlab.com/cardona-oss/litestar-oauth-server/-/blob/main/LICENSE)).
