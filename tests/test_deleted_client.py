"""A client that is no longer in the client store gets nothing new (#13)."""

from dataclasses import replace
from datetime import timedelta

import pytest

from litestar_oauth_server import (
    AuthorizationServer,
    OAuthClient,
    OAuthConfig,
    OAuthError,
    Stores,
    in_memory_stores,
)
from litestar_oauth_server.stores import InMemoryClientStore
from tests.conftest import RESOURCE, Clock, registered_client, request_for
from tests.test_device import APPROVAL, device_client, error_of, poll
from tests.test_revocation_race import refresh_of
from tests.test_server import READ, code_from, code_request, issue


async def restore(server: AuthorizationServer, client: OAuthClient) -> None:
    await server.add_client(
        client_name=client.client_name,
        redirect_uris=client.redirect_uris,
        client_id=client.client_id,
        grant_types=client.grant_types,
    )


@pytest.mark.anyio
async def test_a_deleted_client_cannot_refresh(server: AuthorizationServer) -> None:
    client_id, issued = await issue(server)
    client = await server.describe_client(client_id)
    await server.delete_client(client_id)

    assert await error_of(server, refresh_of(issued, client_id)) == "invalid_client"
    # The access token lives until it expires, as ``delete_client`` says.
    assert await server.verify(issued.access_token, RESOURCE) is not None

    # The refusal consumed and revoked nothing.
    await restore(server, client)
    assert await server.exchange(refresh_of(issued, client_id))


@pytest.mark.anyio
async def test_a_deleted_client_cannot_exchange_a_code(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    code = code_from(await server.approve(request_for(client), READ))
    await server.delete_client(client.client_id)

    request = code_request(client.client_id, code)
    assert await error_of(server, request) == "invalid_client"

    await restore(server, client)
    assert await server.exchange(request)


class FailingClientStore(InMemoryClientStore):
    broken: bool = False

    async def get(self, client_id: str) -> OAuthClient | None:
        if self.broken:
            raise ConnectionError("the client store is down")
        return await super().get(client_id)


@pytest.mark.anyio
async def test_a_failing_client_store_does_not_burn_the_refresh_token(
    config: OAuthConfig, clock: Clock
) -> None:
    clients = FailingClientStore()
    base = in_memory_stores()
    server = AuthorizationServer(
        config=config,
        stores=Stores(clients=clients, codes=base.codes, tokens=base.tokens),
        now=clock,
    )
    client_id, issued = await issue(server)

    clients.broken = True
    with pytest.raises(ConnectionError):
        await server.exchange(refresh_of(issued, client_id))
    clients.broken = False

    assert await server.exchange(refresh_of(issued, client_id))


@pytest.mark.anyio
async def test_an_unknown_client_id_leaves_another_clients_token_usable(
    server: AuthorizationServer,
) -> None:
    client_id, issued = await issue(server)

    assert await error_of(server, refresh_of(issued, "oc_nobody")) == "invalid_client"
    assert await server.exchange(refresh_of(issued, client_id))


@pytest.fixture
def device_server(config: OAuthConfig, clock: Clock) -> AuthorizationServer:
    config = replace(config, device_verification_uri="https://app.example.com/device")
    return AuthorizationServer(config=config, stores=in_memory_stores(), now=clock)


@pytest.mark.anyio
async def test_the_verification_page_does_not_know_a_deleted_clients_code(
    device_server: AuthorizationServer,
) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id, resource=RESOURCE)
    await device_server.delete_client(client_id)

    for call in (
        device_server.describe_device(started.user_code),
        device_server.approve_device(started.user_code, APPROVAL),
        device_server.deny_device(started.user_code),
    ):
        with pytest.raises(OAuthError) as caught:
            await call
        assert caught.value.status == 404


@pytest.mark.anyio
@pytest.mark.parametrize("approved", [False, True])
async def test_a_deleted_client_cannot_poll(
    device_server: AuthorizationServer, clock: Clock, *, approved: bool
) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id, resource=RESOURCE)
    if approved:
        await device_server.approve_device(started.user_code, APPROVAL)
    await device_server.delete_client(client_id)
    clock.advance(timedelta(seconds=5))

    assert await error_of(device_server, poll(client_id, started)) == "invalid_client"
