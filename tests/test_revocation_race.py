"""A revocation that races a refresh leaves no live token in the family (#11)."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime

import pytest

from litestar_oauth_server import (
    AuthorizationServer,
    OAuthConfig,
    OAuthError,
    Stores,
    TokenLike,
    TokenRequest,
    TokenResponse,
    in_memory_stores,
)
from litestar_oauth_server.stores import InMemoryTokenStore
from tests.conftest import RESOURCE
from tests.test_server import issue


@dataclass(slots=True)
class HookedTokenStore(InMemoryTokenStore):
    """Run ``before_add`` once, before the next token is inserted."""

    before_add: Callable[[], Awaitable[object]] | None = field(default=None)

    async def add(self, record: TokenLike) -> None:
        hook, self.before_add = self.before_add, None
        if hook is not None:
            await hook()
        await InMemoryTokenStore.add(self, record)

    def live(self) -> int:
        return sum(r.revoked_at is None for r in self._tokens.values())


@dataclass(slots=True)
class SlowRevokeTokenStore(InMemoryTokenStore):
    """The first revocation sees only the rows that exist when it starts, and ends late.

    This is what one SQL ``UPDATE`` under READ COMMITTED does: it does not see rows committed
    after it started, and others do not see its changes until it commits.
    """

    started: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    first: bool = True

    async def revoke_family(self, family_id: str, now: datetime) -> None:
        if not self.first:
            await InMemoryTokenStore.revoke_family(self, family_id, now)
            return
        self.first = False
        seen = {key for key, r in self._tokens.items() if r.family_id == family_id}
        self.started.set()
        await self.release.wait()
        later = {key: r for key, r in self._tokens.items() if key not in seen}
        await InMemoryTokenStore.revoke_family(self, family_id, now)
        self._tokens.update(later)  # the rows it did not see stay as they were


def server_with(config: OAuthConfig, tokens: InMemoryTokenStore) -> AuthorizationServer:
    base = in_memory_stores()
    return AuthorizationServer(
        config=config, stores=Stores(clients=base.clients, codes=base.codes, tokens=tokens)
    )


def refresh_of(issued: TokenResponse, client_id: str) -> TokenRequest:
    return TokenRequest(
        grant_type="refresh_token", refresh_token=issued.refresh_token, client_id=client_id
    )


async def assert_family_is_dead(server: AuthorizationServer, *responses: TokenResponse) -> None:
    # Read only: a second use of an old refresh token would revoke the family and hide the bug.
    for response in responses:
        assert await server.verify(response.access_token, RESOURCE) is None
    assert await server.list_grants("u1") == ()


@pytest.mark.anyio
async def test_a_replay_during_a_rotation_leaves_no_live_token(config: OAuthConfig) -> None:
    tokens = HookedTokenStore()
    server = server_with(config, tokens)
    client_id, first = await issue(server)
    replay: list[str] = []

    async def reuse() -> None:
        with pytest.raises(OAuthError) as caught:
            await server.exchange(refresh_of(first, client_id))
        replay.append(caught.value.error)

    tokens.before_add = reuse  # between the claim of R1 and the insert of the new tokens
    with pytest.raises(OAuthError) as caught:
        await server.exchange(refresh_of(first, client_id))
    assert (replay, caught.value.error) == (["invalid_grant"], "invalid_grant")
    await assert_family_is_dead(server, first)
    assert tokens.live() == 0


@pytest.mark.anyio
async def test_a_revocation_still_running_when_the_tokens_are_inserted(config: OAuthConfig) -> None:
    tokens = SlowRevokeTokenStore()
    server = server_with(config, tokens)
    client_id, first = await issue(server)
    verified = await server.verify(first.access_token, RESOURCE)
    assert verified is not None

    revoking = asyncio.create_task(server.revoke_family(verified.family_id))
    await tokens.started.wait()
    second = await server.exchange(refresh_of(first, client_id))  # not yet visible: succeeds
    tokens.release.set()
    await revoking
    await assert_family_is_dead(server, first, second)


@pytest.mark.anyio
async def test_the_revocation_endpoint_beats_a_running_refresh_too(config: OAuthConfig) -> None:
    tokens = SlowRevokeTokenStore()
    server = server_with(config, tokens)
    client_id, first = await issue(server)

    revoking = asyncio.create_task(server.revoke(first.access_token))
    await tokens.started.wait()
    second = await server.exchange(refresh_of(first, client_id))
    tokens.release.set()
    await revoking
    await assert_family_is_dead(server, first, second)


@pytest.mark.anyio
async def test_a_revocation_that_ends_before_the_insert_stops_the_refresh(
    config: OAuthConfig,
) -> None:
    tokens = HookedTokenStore()
    server = server_with(config, tokens)
    client_id, first = await issue(server)
    verified = await server.verify(first.access_token, RESOURCE)
    assert verified is not None

    tokens.before_add = lambda: server.revoke_family(verified.family_id)
    with pytest.raises(OAuthError) as caught:
        await server.exchange(refresh_of(first, client_id))
    assert caught.value.error == "invalid_grant"
    await assert_family_is_dead(server, first)
    assert tokens.live() == 0
