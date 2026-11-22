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

Requires Python 3.12+.

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
