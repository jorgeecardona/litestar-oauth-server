from datetime import UTC, datetime, timedelta

import pytest

from litestar_oauth import (
    AuthorizationRequest,
    AuthorizationServer,
    OAuthClient,
    OAuthConfig,
    in_memory_stores,
)
from litestar_oauth.server import pkce_challenge

RESOURCE = "https://api.example.com/mcp"
VERIFIER = "v" * 64
REDIRECT = "https://client.example.com/callback"


class Clock:
    """A clock the tests move by hand."""

    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def config() -> OAuthConfig:
    return OAuthConfig(
        issuer="https://api.example.com",
        authorization_endpoint="https://app.example.com/oauth/authorize",
        resources=(RESOURCE,),
        scopes_supported=("things:read", "things:write"),
        resource_name="Example",
    )


@pytest.fixture
def server(config: OAuthConfig, clock: Clock) -> AuthorizationServer:
    return AuthorizationServer(config=config, stores=in_memory_stores(), now=clock)


async def registered_client(server: AuthorizationServer) -> OAuthClient:
    return await server.register_client(client_name="Test client", redirect_uris=(REDIRECT,))


def request_for(client: OAuthClient, *, resource: str = RESOURCE) -> AuthorizationRequest:
    return AuthorizationRequest(
        client_id=client.client_id,
        redirect_uri=REDIRECT,
        code_challenge=pkce_challenge(VERIFIER),
        code_challenge_method="S256",
        state="xyz",
        resource=resource,
    )
