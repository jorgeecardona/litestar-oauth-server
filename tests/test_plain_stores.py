"""A host can implement the stores without importing this package at runtime (#5)."""

import ast
import asyncio
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from litestar_oauth_server import (
    Approval,
    AuthorizationRequest,
    AuthorizationServer,
    OAuthConfig,
    OAuthError,
    Stores,
    TokenRequest,
)
from litestar_oauth_server.server import pkce_challenge
from tests.conftest import REDIRECT, RESOURCE, VERIFIER, Clock
from tests.plain_stores import PlainClientStore, PlainCodeStore, PlainTokenStore


@pytest.fixture
def plain(config: OAuthConfig, clock: Clock) -> AuthorizationServer:
    stores = Stores(clients=PlainClientStore(), codes=PlainCodeStore(), tokens=PlainTokenStore())
    return AuthorizationServer(config=config, stores=stores, now=clock)


async def authorize(server: AuthorizationServer) -> str:
    client = await server.register_client(client_name="Plain", redirect_uris=(REDIRECT,))
    redirect = await server.approve(
        AuthorizationRequest(
            client_id=client.client_id,
            redirect_uri=REDIRECT,
            code_challenge=pkce_challenge(VERIFIER),
            code_challenge_method="S256",
            resource=RESOURCE,
        ),
        Approval(subject="u1", scopes=("things:read",), binding="company:9"),
    )
    return client.client_id + " " + parse_qs(urlsplit(redirect).query)["code"][0]


def code_request(client_id: str, code: str) -> TokenRequest:
    return TokenRequest(
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT,
        client_id=client_id,
        code_verifier=VERIFIER,
        resource=RESOURCE,
    )


def test_the_plain_stores_module_has_no_runtime_import_of_the_package() -> None:
    tree = ast.parse(Path(__file__).with_name("plain_stores.py").read_text())
    for node in tree.body:  # top level only: the TYPE_CHECKING block is an `if`, not an import
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("litestar_oauth_server")
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("litestar_oauth_server") for a in node.names)


@pytest.mark.anyio
async def test_a_full_exchange_works_on_plain_stores(
    plain: AuthorizationServer, clock: Clock
) -> None:
    client_id, code = (await authorize(plain)).split()
    issued = await plain.exchange(code_request(client_id, code))
    verified = await plain.verify(issued.access_token, RESOURCE)
    assert verified is not None
    assert verified.scopes == ("things:read",)
    assert (verified.subject, verified.binding) == ("u1", "company:9")

    refreshed = await plain.exchange(
        TokenRequest(
            grant_type="refresh_token", refresh_token=issued.refresh_token, client_id=client_id
        )
    )
    assert refreshed.access_token != issued.access_token
    grants = await plain.list_grants("u1")
    assert [g.client_name for g in grants] == ["Plain"]
    assert grants[0].scopes == ("things:read",)


@pytest.mark.anyio
async def test_a_code_is_single_use_on_plain_stores(plain: AuthorizationServer) -> None:
    client_id, code = (await authorize(plain)).split()
    results = await asyncio.gather(
        plain.exchange(code_request(client_id, code)),
        plain.exchange(code_request(client_id, code)),
        return_exceptions=True,
    )
    assert sum(isinstance(r, OAuthError) for r in results) == 1


@pytest.mark.anyio
async def test_a_reused_refresh_token_revokes_the_family_on_plain_stores(
    plain: AuthorizationServer, clock: Clock
) -> None:
    client_id, code = (await authorize(plain)).split()
    first = await plain.exchange(code_request(client_id, code))
    refresh = TokenRequest(
        grant_type="refresh_token", refresh_token=first.refresh_token, client_id=client_id
    )
    second = await plain.exchange(refresh)
    clock.advance(timedelta(seconds=1))
    with pytest.raises(OAuthError):
        await plain.exchange(refresh)  # the rotated token came back: theft signal
    assert await plain.verify(second.access_token, RESOURCE) is None
