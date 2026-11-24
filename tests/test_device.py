"""The device authorization grant (RFC 8628, #6)."""

import asyncio
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from litestar import Litestar
from litestar.testing import TestClient

from litestar_oauth_server import (
    GRANT_DEVICE_CODE,
    Approval,
    AuthorizationServer,
    DeviceAuthorization,
    LitestarOAuth,
    OAuthConfig,
    OAuthError,
    Stores,
    TokenRequest,
    TokenResponse,
    format_user_code,
    in_memory_stores,
    normalize_user_code,
)
from tests.conftest import RESOURCE, Clock

VERIFICATION = "https://app.example.com/device"
DEVICE_GRANTS = (GRANT_DEVICE_CODE, "refresh_token")


@pytest.fixture
def device_config(config: OAuthConfig) -> OAuthConfig:
    return replace(config, device_verification_uri=VERIFICATION)


@pytest.fixture
def device_server(device_config: OAuthConfig, clock: Clock) -> AuthorizationServer:
    return AuthorizationServer(config=device_config, stores=in_memory_stores(), now=clock)


async def device_client(server: AuthorizationServer) -> str:
    client = await server.add_client(client_name="CLI", grant_types=DEVICE_GRANTS)
    return client.client_id


def poll(client_id: str, started: DeviceAuthorization, *, resource: str = "") -> TokenRequest:
    return TokenRequest(
        grant_type=GRANT_DEVICE_CODE,
        device_code=started.device_code,
        client_id=client_id,
        resource=resource,
    )


async def error_of(server: AuthorizationServer, request: TokenRequest) -> str:
    with pytest.raises(OAuthError) as caught:
        await server.exchange(request)
    return caught.value.error


APPROVAL = Approval(subject="u1", scopes=("things:read",), binding="company:9")


@pytest.mark.anyio
async def test_a_full_device_flow(device_server: AuthorizationServer, clock: Clock) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(
        client_id=client_id, scope="things:read things:write", resource=RESOURCE
    )
    assert started.verification_uri == VERIFICATION
    assert started.verification_uri_complete == f"{VERIFICATION}?user_code={started.user_code}"
    assert (started.expires_in, started.interval) == (900, 5)
    assert len(started.user_code) == 9
    assert started.user_code[4] == "-"

    assert await error_of(device_server, poll(client_id, started)) == "authorization_pending"

    typed = started.user_code.lower().replace("-", " ")  # the user types it loosely
    seen = await device_server.describe_device(typed)
    assert (seen.client_name, seen.scopes, seen.resource) == (
        "CLI",
        ("things:read", "things:write"),
        RESOURCE,
    )
    await device_server.approve_device(typed, APPROVAL)

    clock.advance(timedelta(seconds=5))
    issued = await device_server.exchange(poll(client_id, started, resource=RESOURCE))
    verified = await device_server.verify(issued.access_token, RESOURCE)
    assert verified is not None
    assert (verified.subject, verified.binding, verified.scopes) == (
        "u1",
        "company:9",
        ("things:read",),
    )
    assert verified.client_id == client_id

    refreshed = await device_server.exchange(
        TokenRequest(
            grant_type="refresh_token", refresh_token=issued.refresh_token, client_id=client_id
        )
    )
    assert isinstance(refreshed, TokenResponse)


@pytest.mark.anyio
async def test_polling_too_fast_gets_slow_down_and_a_longer_interval(
    device_server: AuthorizationServer, clock: Clock
) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id)
    assert await error_of(device_server, poll(client_id, started)) == "authorization_pending"
    assert await error_of(device_server, poll(client_id, started)) == "slow_down"  # interval 10
    clock.advance(timedelta(seconds=5))
    assert await error_of(device_server, poll(client_id, started)) == "slow_down"  # interval 15
    clock.advance(timedelta(seconds=15))
    assert await error_of(device_server, poll(client_id, started)) == "authorization_pending"


@pytest.mark.anyio
async def test_an_expired_code_says_expired_token_then_unknown_after_purge(
    device_server: AuthorizationServer, clock: Clock
) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id)
    clock.advance(timedelta(minutes=16))
    assert await error_of(device_server, poll(client_id, started)) == "expired_token"
    with pytest.raises(OAuthError):
        await device_server.describe_device(started.user_code)
    assert await device_server.purge_expired_devices() == 1
    assert await error_of(device_server, poll(client_id, started)) == "invalid_grant"


@pytest.mark.anyio
async def test_a_denied_device_says_access_denied_once(device_server: AuthorizationServer) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id)
    await device_server.deny_device(started.user_code)
    assert await error_of(device_server, poll(client_id, started)) == "access_denied"
    assert await error_of(device_server, poll(client_id, started)) == "invalid_grant"


@pytest.mark.anyio
async def test_an_approved_code_gives_one_token_pair_even_when_polled_at_once(
    device_server: AuthorizationServer,
) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id)
    await device_server.approve_device(started.user_code, APPROVAL)
    results = await asyncio.gather(
        *(device_server.exchange(poll(client_id, started)) for _ in range(8)),
        return_exceptions=True,
    )
    issued = [r for r in results if isinstance(r, TokenResponse)]
    refused = [r for r in results if isinstance(r, OAuthError)]
    assert len(issued) == 1
    assert {r.error for r in refused} == {"invalid_grant"}


@pytest.mark.anyio
async def test_a_user_code_can_be_decided_once(device_server: AuthorizationServer) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id)
    await device_server.approve_device(started.user_code, APPROVAL)
    with pytest.raises(OAuthError):
        await device_server.deny_device(started.user_code)
    with pytest.raises(OAuthError):
        await device_server.approve_device(started.user_code, APPROVAL)
    with pytest.raises(OAuthError):
        await device_server.describe_device(started.user_code)


@pytest.mark.anyio
async def test_the_wrong_client_cannot_use_a_device_code(
    device_server: AuthorizationServer,
) -> None:
    client_id = await device_client(device_server)
    other = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id)
    await device_server.approve_device(started.user_code, APPROVAL)
    assert await error_of(device_server, poll(other, started)) == "invalid_grant"
    assert await error_of(device_server, replace(poll(client_id, started), device_code="x")) == (
        "invalid_grant"
    )
    issued = await device_server.exchange(poll(client_id, started))  # the real owner still can
    assert issued.access_token


@pytest.mark.anyio
async def test_only_a_client_that_asked_for_the_device_grant_may_start_one(
    device_server: AuthorizationServer,
) -> None:
    plain = await device_server.add_client(
        client_name="Web", redirect_uris=("https://client.example.com/cb",)
    )
    with pytest.raises(OAuthError) as caught:
        await device_server.start_device_authorization(client_id=plain.client_id)
    assert caught.value.error == "unauthorized_client"
    with pytest.raises(OAuthError) as unknown:
        await device_server.start_device_authorization(client_id="nope")
    assert unknown.value.error == "invalid_client"


@pytest.mark.anyio
async def test_scopes_and_resource_are_checked(device_server: AuthorizationServer) -> None:
    client_id = await device_client(device_server)
    with pytest.raises(OAuthError) as bad_scope:
        await device_server.start_device_authorization(client_id=client_id, scope="nope")
    assert bad_scope.value.error == "invalid_scope"
    with pytest.raises(OAuthError) as bad_resource:
        await device_server.start_device_authorization(
            client_id=client_id, resource="https://other.example.com"
        )
    assert bad_resource.value.error == "invalid_target"

    started = await device_server.start_device_authorization(
        client_id=client_id, scope="things:read"
    )
    wider = Approval(subject="u1", scopes=("things:read", "things:write"), binding="b")
    with pytest.raises(OAuthError) as too_wide:
        await device_server.approve_device(started.user_code, wider)
    assert too_wide.value.error == "invalid_scope"
    await device_server.approve_device(started.user_code, APPROVAL)  # still pending: allowed

    other = await device_server.start_device_authorization(client_id=client_id, resource=RESOURCE)
    await device_server.approve_device(other.user_code, APPROVAL)
    assert await error_of(
        device_server, poll(client_id, other, resource="https://x.example.com")
    ) == ("invalid_target")


@pytest.mark.anyio
async def test_without_requested_scopes_the_user_may_approve_any_supported_ones(
    device_server: AuthorizationServer,
) -> None:
    client_id = await device_client(device_server)
    started = await device_server.start_device_authorization(client_id=client_id)
    both = Approval(subject="u1", scopes=("things:read", "things:write"), binding="b")
    await device_server.approve_device(started.user_code, both)
    issued = await device_server.exchange(poll(client_id, started))
    assert issued.scope == "things:read things:write"


@pytest.mark.anyio
async def test_the_grant_is_off_without_a_verification_uri(
    server: AuthorizationServer,
) -> None:
    assert server.device_enabled is False
    with pytest.raises(OAuthError) as caught:
        await server.start_device_authorization(client_id="x")
    assert caught.value.error == "unsupported_grant_type"
    request = TokenRequest(grant_type=GRANT_DEVICE_CODE, device_code="d", client_id="x")
    assert await error_of(server, request) == "unsupported_grant_type"
    with pytest.raises(OAuthError) as registration:
        await server.register_client(client_name="CLI", grant_types=DEVICE_GRANTS)
    assert registration.value.error == "invalid_client_metadata"


def test_a_verification_uri_needs_a_device_store(device_config: OAuthConfig) -> None:
    stores = in_memory_stores()
    without = Stores(clients=stores.clients, codes=stores.codes, tokens=stores.tokens)
    with pytest.raises(ValueError, match="device"):
        AuthorizationServer(config=device_config, stores=without)


@pytest.mark.anyio
async def test_registration_rules_for_grant_types(device_server: AuthorizationServer) -> None:
    default = await device_server.register_client(
        client_name="Web", redirect_uris=("https://client.example.com/cb",)
    )
    assert default.grant_types == ("authorization_code", "refresh_token")
    cli = await device_server.register_client(client_name="CLI", grant_types=DEVICE_GRANTS)
    assert cli.grant_types == DEVICE_GRANTS
    assert cli.redirect_uris == ()
    with pytest.raises(OAuthError) as no_redirect:
        await device_server.register_client(client_name="Web")
    assert no_redirect.value.error == "invalid_redirect_uri"
    for bad in (("implicit",), ("refresh_token",)):
        with pytest.raises(OAuthError) as caught:
            await device_server.register_client(client_name="X", grant_types=bad)
        assert caught.value.error == "invalid_client_metadata"


@pytest.mark.anyio
async def test_a_pending_device_keeps_its_client_from_being_purged(
    device_server: AuthorizationServer, clock: Clock
) -> None:
    client_id = await device_client(device_server)
    idle = await device_client(device_server)
    await device_server.start_device_authorization(client_id=client_id)
    clock.advance(timedelta(days=60))
    assert await device_server.purge_unused_clients() == 1
    assert await device_server.stores.clients.get(client_id) is not None
    assert await device_server.stores.clients.get(idle) is None


def test_user_codes_are_normalized_and_shown_with_a_dash() -> None:
    assert normalize_user_code(" wdjb-mjht ") == "WDJBMJHT"
    assert normalize_user_code("WDJB MJHT!") == "WDJBMJHT"
    assert normalize_user_code("a1e0") == ""  # vowels and digits are not in the alphabet
    assert format_user_code("WDJBMJHT") == "WDJB-MJHT"


# -- over HTTP ----------------------------------------------------------------------------------


@pytest.fixture
def http(device_server: AuthorizationServer) -> Iterator[TestClient[Any]]:
    with TestClient(Litestar([], plugins=[LitestarOAuth(device_server)])) as client:
        yield client


def test_the_metadata_announces_the_device_grant(http: TestClient[Any]) -> None:
    body = http.get("/.well-known/oauth-authorization-server").json()
    assert (
        body["device_authorization_endpoint"]
        == "https://api.example.com/oauth/device_authorization"
    )
    assert GRANT_DEVICE_CODE in body["grant_types_supported"]


def test_the_metadata_and_route_are_absent_without_the_grant(config: OAuthConfig) -> None:
    off = AuthorizationServer(config=config, stores=in_memory_stores())
    with TestClient(Litestar([], plugins=[LitestarOAuth(off)])) as client:
        body = client.get("/.well-known/oauth-authorization-server").json()
        assert (
            "device_authorization_endpoint" not in body
            or body["device_authorization_endpoint"] is None
        )
        assert GRANT_DEVICE_CODE not in body["grant_types_supported"]
        assert (
            client.post("/oauth/device_authorization", data={"client_id": "x"}).status_code == 404
        )


def test_a_device_client_registers_and_logs_in_over_http(
    http: TestClient[Any], device_server: AuthorizationServer
) -> None:
    registered = http.post(
        "/oauth/register", json={"client_name": "CLI", "grant_types": list(DEVICE_GRANTS)}
    )
    assert registered.status_code == 201
    assert registered.json()["grant_types"] == list(DEVICE_GRANTS)
    assert registered.json()["response_types"] == []
    client_id = registered.json()["client_id"]

    started = http.post(
        "/oauth/device_authorization",
        data={"client_id": client_id, "scope": "things:read", "resource": RESOURCE},
    )
    assert started.status_code == 200
    assert started.headers["cache-control"] == "no-store"
    body = started.json()
    assert set(body) == {
        "device_code",
        "user_code",
        "verification_uri",
        "verification_uri_complete",
        "expires_in",
        "interval",
    }

    form = {
        "grant_type": GRANT_DEVICE_CODE,
        "device_code": body["device_code"],
        "client_id": client_id,
    }
    pending = http.post("/oauth/token", data=form)
    assert pending.status_code == 400
    assert pending.json()["error"] == "authorization_pending"

    asyncio.run(device_server.approve_device(body["user_code"], APPROVAL))
    issued = http.post("/oauth/token", data=form)
    assert issued.status_code == 200
    assert issued.json()["token_type"] == "Bearer"
    assert issued.json()["scope"] == "things:read"


def test_the_device_endpoint_answers_errors_as_oauth_errors(http: TestClient[Any]) -> None:
    unknown = http.post("/oauth/device_authorization", data={"client_id": "nope"})
    assert unknown.status_code == 400
    assert unknown.json()["error"] == "invalid_client"
    missing = http.post("/oauth/device_authorization", data={})
    assert missing.status_code == 400
