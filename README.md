# litestar-oauth

[![pipeline status](https://gitlab.com/cardona-oss/litestar-oauth/badges/main/pipeline.svg)](https://gitlab.com/cardona-oss/litestar-oauth/-/pipelines)
[![PyPI version](https://img.shields.io/pypi/v/litestar-oauth.svg)](https://pypi.org/project/litestar-oauth/)
[![Python versions](https://img.shields.io/pypi/pyversions/litestar-oauth.svg)](https://pypi.org/project/litestar-oauth/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An OAuth 2.1 authorization server plugin for Litestar: PKCE, client registration, token and refresh, with MCP-ready metadata

## Install

```bash
pip install litestar-oauth
```

Requires Python 3.12+.

## Quickstart

```python
from litestar import Litestar, Request, get
from litestar_oauth import (
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

## Why litestar-oauth

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
- A bearer guard that answers 401 with `WWW-Authenticate: Bearer resource_metadata=...`.
- Frozen dataclasses throughout; storage is three small protocols you implement on your database.

## Links

- **Documentation:** https://cardona-oss.gitlab.io/litestar-oauth/
- **Source:** https://gitlab.com/cardona-oss/litestar-oauth
- **Issues:** https://gitlab.com/cardona-oss/litestar-oauth/-/issues
- **PyPI:** https://pypi.org/project/litestar-oauth/
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

## Contributing

Developer setup, the dev loop, and the release process live in
[CONTRIBUTING.md](CONTRIBUTING.md). In short: `uv sync && make install-hooks`, then
`make check` runs the same gate CI runs.

## License

MIT © 2026 Jorge Cardona (see [LICENSE](LICENSE)).
