from dataclasses import replace
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

from litestar_oauth_server import (
    Approval,
    AuthorizationServer,
    OAuthConfig,
    OAuthError,
    TokenRequest,
    TokenResponse,
)
from tests.conftest import REDIRECT, RESOURCE, VERIFIER, Clock, registered_client, request_for

READ = Approval(subject="u1", scopes=("things:read",), binding="company:1")


def code_from(redirect: str) -> str:
    return parse_qs(urlsplit(redirect).query)["code"][0]


def code_request(client_id: str, code: str, **over: str) -> TokenRequest:
    fields = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": client_id,
        "code_verifier": VERIFIER,
        "resource": RESOURCE,
    }
    fields.update(over)
    return TokenRequest(**fields)


async def issue(
    server: AuthorizationServer, approval: Approval = READ
) -> tuple[str, TokenResponse]:
    client = await registered_client(server)
    redirect = await server.approve(request_for(client), approval)
    return client.client_id, await server.exchange(
        code_request(client.client_id, code_from(redirect))
    )


@pytest.mark.anyio
async def test_full_flow_issues_a_token_bound_to_the_resource(server: AuthorizationServer) -> None:
    client_id, tokens = await issue(server)
    assert tokens.token_type == "Bearer"
    assert tokens.scope == "things:read"
    verified = await server.verify(tokens.access_token, RESOURCE)
    assert verified is not None
    assert verified.subject == "u1"
    assert verified.binding == "company:1"
    assert verified.client_id == client_id


@pytest.mark.anyio
async def test_redirect_carries_state(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    redirect = await server.approve(request_for(client), READ)
    assert parse_qs(urlsplit(redirect).query)["state"] == ["xyz"]


@pytest.mark.anyio
async def test_code_is_single_use(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    code = code_from(await server.approve(request_for(client), READ))
    await server.exchange(code_request(client.client_id, code))
    with pytest.raises(OAuthError) as excinfo:
        await server.exchange(code_request(client.client_id, code))
    assert excinfo.value.error == "invalid_grant"


@pytest.mark.anyio
async def test_wrong_verifier_fails_and_burns_the_code(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    code = code_from(await server.approve(request_for(client), READ))
    with pytest.raises(OAuthError, match="PKCE"):
        await server.exchange(code_request(client.client_id, code, code_verifier="w" * 64))
    with pytest.raises(OAuthError, match="already used"):
        await server.exchange(code_request(client.client_id, code))


@pytest.mark.anyio
async def test_code_expires(server: AuthorizationServer, clock: Clock) -> None:
    client = await registered_client(server)
    code = code_from(await server.approve(request_for(client), READ))
    clock.advance(timedelta(minutes=6))
    with pytest.raises(OAuthError, match="expired"):
        await server.exchange(code_request(client.client_id, code))


@pytest.mark.anyio
async def test_code_for_another_client_is_rejected(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    other = await registered_client(server)
    code = code_from(await server.approve(request_for(client), READ))
    with pytest.raises(OAuthError, match="different client"):
        await server.exchange(code_request(other.client_id, code))


@pytest.mark.anyio
async def test_unregistered_redirect_is_rejected(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    bad = replace(request_for(client), redirect_uri="https://evil.example.com/cb")
    with pytest.raises(OAuthError, match="redirect_uri"):
        await server.approve(bad, READ)


@pytest.mark.anyio
async def test_plain_pkce_is_rejected(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    plain = replace(request_for(client), code_challenge=VERIFIER, code_challenge_method="plain")
    with pytest.raises(OAuthError, match="S256"):
        await server.approve(plain, READ)


@pytest.mark.anyio
async def test_unknown_resource_is_rejected(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    with pytest.raises(OAuthError) as excinfo:
        await server.approve(request_for(client, resource="https://other.example.com/x"), READ)
    assert excinfo.value.error == "invalid_target"


@pytest.mark.anyio
async def test_unknown_scope_is_rejected(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    with pytest.raises(OAuthError) as excinfo:
        await server.approve(request_for(client), Approval(subject="u1", scopes=("admin",)))
    assert excinfo.value.error == "invalid_scope"


@pytest.mark.anyio
async def test_token_is_rejected_at_another_resource(server: AuthorizationServer) -> None:
    _, tokens = await issue(server)
    assert await server.verify(tokens.access_token, "https://api.example.com/other") is None


@pytest.mark.anyio
async def test_access_token_expires(server: AuthorizationServer, clock: Clock) -> None:
    _, tokens = await issue(server)
    clock.advance(timedelta(hours=2))
    assert await server.verify(tokens.access_token, RESOURCE) is None


@pytest.mark.anyio
async def test_refresh_token_is_not_accepted_as_access_token(server: AuthorizationServer) -> None:
    _, tokens = await issue(server)
    assert await server.verify(tokens.refresh_token, RESOURCE) is None


@pytest.mark.anyio
async def test_refresh_rotates(server: AuthorizationServer) -> None:
    client_id, tokens = await issue(server)
    fresh = await server.exchange(
        TokenRequest(
            grant_type="refresh_token", refresh_token=tokens.refresh_token, client_id=client_id
        )
    )
    assert fresh.refresh_token != tokens.refresh_token
    assert await server.verify(fresh.access_token, RESOURCE) is not None


@pytest.mark.anyio
async def test_reused_refresh_token_revokes_the_family(server: AuthorizationServer) -> None:
    client_id, tokens = await issue(server)
    request = TokenRequest(
        grant_type="refresh_token", refresh_token=tokens.refresh_token, client_id=client_id
    )
    fresh = await server.exchange(request)
    with pytest.raises(OAuthError):
        await server.exchange(request)  # the stolen, already rotated token comes back
    assert await server.verify(fresh.access_token, RESOURCE) is None
    assert await server.verify(tokens.access_token, RESOURCE) is None


@pytest.mark.anyio
async def test_revoke_ends_the_family(server: AuthorizationServer) -> None:
    _, tokens = await issue(server)
    await server.revoke(tokens.refresh_token)
    assert await server.verify(tokens.access_token, RESOURCE) is None


@pytest.mark.anyio
async def test_revoke_of_unknown_token_is_not_an_error(server: AuthorizationServer) -> None:
    await server.revoke("nope")


@pytest.mark.anyio
async def test_list_grants_shows_the_binding_and_scopes(server: AuthorizationServer) -> None:
    await issue(server)
    grants = await server.list_grants("u1")
    assert len(grants) == 1
    assert grants[0].binding == "company:1"
    assert grants[0].scopes == ("things:read",)
    assert grants[0].client_name == "Test client"
    await server.revoke_family(grants[0].family_id)
    assert await server.list_grants("u1") == ()


@pytest.mark.anyio
async def test_loopback_redirect_may_change_port(server: AuthorizationServer) -> None:
    client = await server.register_client(
        client_name="CLI", redirect_uris=("http://127.0.0.1/callback",)
    )
    request = replace(request_for(client), redirect_uri="http://127.0.0.1:53211/callback")
    assert (await server.approve(request, READ)).startswith("http://127.0.0.1:53211/callback?code=")


@pytest.mark.anyio
async def test_plain_http_redirect_is_not_registrable(server: AuthorizationServer) -> None:
    with pytest.raises(OAuthError) as excinfo:
        await server.register_client(client_name="x", redirect_uris=("http://example.com/cb",))
    assert excinfo.value.error == "invalid_redirect_uri"


@pytest.mark.anyio
async def test_registration_can_be_disabled(config: OAuthConfig, clock: Clock) -> None:
    from litestar_oauth_server import in_memory_stores

    closed = AuthorizationServer(
        config=replace(config, registration_enabled=False), stores=in_memory_stores(), now=clock
    )
    with pytest.raises(OAuthError) as excinfo:
        await closed.register_client(client_name="x", redirect_uris=(REDIRECT,))
    assert excinfo.value.status == 403
    # a pre-registered client still works
    await closed.add_client(client_name="Fixed", redirect_uris=(REDIRECT,), client_id="fixed")


def test_config_needs_a_resource_and_a_scope() -> None:
    with pytest.raises(ValueError, match="resources"):
        OAuthConfig(issuer="i", authorization_endpoint="a", resources=(), scopes_supported=("s",))
    with pytest.raises(ValueError, match="scopes"):
        OAuthConfig(issuer="i", authorization_endpoint="a", resources=("r",), scopes_supported=())


@pytest.mark.anyio
async def test_deny_redirects_with_access_denied_and_state(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    redirect = await server.deny(replace(request_for(client), state="xyz"))
    query = parse_qs(urlsplit(redirect).query)
    assert redirect.startswith(REDIRECT)
    assert query == {"error": ["access_denied"], "state": ["xyz"]}


@pytest.mark.anyio
async def test_deny_refuses_an_unregistered_redirect(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    with pytest.raises(OAuthError) as caught:
        await server.deny(replace(request_for(client), redirect_uri="https://evil.example/cb"))
    assert caught.value.error == "invalid_request"


@pytest.mark.anyio
async def test_validate_request_returns_the_client(server: AuthorizationServer) -> None:
    client = await registered_client(server)
    assert (await server.validate_request(request_for(client))).client_id == client.client_id


@pytest.mark.anyio
async def test_a_verified_token_names_its_grant(server: AuthorizationServer) -> None:
    _, tokens = await issue(server)
    verified = await server.verify(tokens.access_token, RESOURCE)
    grants = await server.list_grants("u1")
    assert verified is not None
    assert [g.family_id for g in grants] == [verified.family_id]
