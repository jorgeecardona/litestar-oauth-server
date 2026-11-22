from collections.abc import Iterator
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from litestar import Litestar, Request, get
from litestar.config.cors import CORSConfig
from litestar.testing import TestClient

from litestar_oauth_server import (
    Approval,
    AuthorizationServer,
    LitestarOAuth,
    OAuthConfig,
    VerifiedToken,
    bearer_guard,
    in_memory_stores,
    protected_resource_metadata_url,
    verified_token,
)
from litestar_oauth_server.server import pkce_challenge
from tests.conftest import REDIRECT, RESOURCE, VERIFIER


@pytest.fixture
def http(config: OAuthConfig) -> Iterator[tuple[TestClient[Any], AuthorizationServer]]:
    server = AuthorizationServer(config=config, stores=in_memory_stores())
    guard = bearer_guard(server, RESOURCE)
    write_guard = bearer_guard(server, RESOURCE, scope="things:write")

    @get("/mcp", guards=[guard], sync_to_thread=False)
    def read_things(request: Request[Any, Any, Any]) -> dict[str, str]:
        token: VerifiedToken = verified_token(request)
        return {"subject": token.subject, "binding": token.binding}

    @get("/mcp/write", guards=[write_guard], sync_to_thread=False)
    def write_things() -> str:
        return "ok"

    app = Litestar([read_things, write_things], plugins=[LitestarOAuth(server)])
    with TestClient(app) as client:
        yield client, server


def get_token(client: TestClient[Any], server: AuthorizationServer, scopes: tuple[str, ...]) -> str:
    registered = client.post(
        "/oauth/register", json={"client_name": "T", "redirect_uris": [REDIRECT]}
    )
    assert registered.status_code == 201
    client_id = registered.json()["client_id"]
    import asyncio

    from litestar_oauth_server import AuthorizationRequest

    redirect = asyncio.run(
        server.approve(
            AuthorizationRequest(
                client_id=client_id,
                redirect_uri=REDIRECT,
                code_challenge=pkce_challenge(VERIFIER),
                code_challenge_method="S256",
                resource=RESOURCE,
            ),
            Approval(subject="u1", scopes=scopes, binding="company:9"),
        )
    )
    code = parse_qs(urlsplit(redirect).query)["code"][0]
    response = client.post(
        "/oauth/token",
        content=(
            f"grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}"
            f"&client_id={client_id}&code_verifier={VERIFIER}&resource={RESOURCE}"
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return str(response.json()["access_token"])


def test_metadata_documents(http: tuple[TestClient[Any], AuthorizationServer]) -> None:
    client, _ = http
    server_meta = client.get("/.well-known/oauth-authorization-server").json()
    assert server_meta["code_challenge_methods_supported"] == ["S256"]
    assert server_meta["registration_endpoint"] == "https://api.example.com/oauth/register"
    resource_meta = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource_meta["resource"] == RESOURCE
    assert resource_meta["authorization_servers"] == ["https://api.example.com"]


def test_metadata_url_is_inserted_before_the_path() -> None:
    assert (
        protected_resource_metadata_url("https://api.example.com/mcp/")
        == "https://api.example.com/.well-known/oauth-protected-resource/mcp"
    )
    assert (
        protected_resource_metadata_url("https://api.example.com")
        == "https://api.example.com/.well-known/oauth-protected-resource"
    )


def test_missing_token_gets_401_with_resource_metadata(
    http: tuple[TestClient[Any], AuthorizationServer],
) -> None:
    client, _ = http
    response = client.get("/mcp")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == (
        'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"'
    )


def test_bad_token_says_invalid_token(http: tuple[TestClient[Any], AuthorizationServer]) -> None:
    client, _ = http
    response = client.get("/mcp", headers={"authorization": "Bearer nope"})
    assert response.status_code == 401
    assert 'error="invalid_token"' in response.headers["www-authenticate"]


def test_valid_token_reaches_the_handler_with_its_binding(
    http: tuple[TestClient[Any], AuthorizationServer],
) -> None:
    client, server = http
    token = get_token(client, server, ("things:read",))
    response = client.get("/mcp", headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"subject": "u1", "binding": "company:9"}


def test_read_token_cannot_write(http: tuple[TestClient[Any], AuthorizationServer]) -> None:
    client, server = http
    token = get_token(client, server, ("things:read",))
    response = client.get("/mcp/write", headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert 'error="insufficient_scope"' in response.headers["www-authenticate"]


def test_write_token_can_write(http: tuple[TestClient[Any], AuthorizationServer]) -> None:
    client, server = http
    token = get_token(client, server, ("things:read", "things:write"))
    assert client.get("/mcp/write", headers={"authorization": f"Bearer {token}"}).status_code == 200


def test_token_errors_are_oauth_objects(http: tuple[TestClient[Any], AuthorizationServer]) -> None:
    client, _ = http
    response = client.post(
        "/oauth/token",
        content="grant_type=authorization_code&code=bad",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    odd = client.post("/oauth/token", content="%%%", headers={"content-type": "text/plain"})
    assert odd.json()["error"] == "unsupported_grant_type"


def test_bad_registration_is_an_oauth_error(
    http: tuple[TestClient[Any], AuthorizationServer],
) -> None:
    client, _ = http
    response = client.post(
        "/oauth/register",
        json={"client_name": "x", "redirect_uris": ["http://evil.example.com/cb"]},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"


def test_revoke_endpoint_kills_the_token(http: tuple[TestClient[Any], AuthorizationServer]) -> None:
    client, server = http
    token = get_token(client, server, ("things:read",))
    revoked = client.post(
        "/oauth/revoke",
        content=f"token={token}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert revoked.status_code == 200
    assert client.get("/mcp", headers={"authorization": f"Bearer {token}"}).status_code == 401


# CORS (#1): cors_origins answers preflight and sets headers on the OAuth routes only.

OAUTH_PATHS = ("/.well-known/oauth-authorization-server", "/oauth/register", "/oauth/token")
PREFLIGHT = {"Origin": "https://inspector.example.com", "Access-Control-Request-Method": "POST"}


def cors_client(
    config: OAuthConfig, origins: tuple[str, ...], *, own_cors: bool = False
) -> TestClient[Any]:
    server = AuthorizationServer(
        config=replace(config, cors_origins=origins), stores=in_memory_stores()
    )

    @get("/other", sync_to_thread=False)
    def other() -> str:
        return "ok"

    cors_config = CORSConfig(allow_origins=["https://app.example.com"]) if own_cors else None
    app = Litestar([other], plugins=[LitestarOAuth(server)], cors_config=cors_config)
    return TestClient(app)


@pytest.mark.parametrize(
    ("path", "method"),
    [(OAUTH_PATHS[0], "GET"), (OAUTH_PATHS[1], "POST"), (OAUTH_PATHS[2], "POST")],
)
def test_listed_origin_passes_the_preflight(config: OAuthConfig, path: str, method: str) -> None:
    with cors_client(config, ("https://inspector.example.com",)) as client:
        response = client.options(path, headers=PREFLIGHT)
    assert response.status_code == 204
    assert response.headers["access-control-allow-origin"] == "https://inspector.example.com"
    assert response.headers["vary"] == "Origin"
    assert method in response.headers["access-control-allow-methods"]


def test_preflight_echoes_the_requested_headers(config: OAuthConfig) -> None:
    headers = {**PREFLIGHT, "Access-Control-Request-Headers": "content-type, authorization"}
    with cors_client(config, ("*",)) as client:
        response = client.options("/oauth/token", headers=headers)
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-allow-headers"] == "content-type, authorization"


def test_unlisted_origin_gets_no_cors_headers(config: OAuthConfig) -> None:
    with cors_client(config, ("https://other.example.com",)) as client:
        preflight = client.options("/oauth/token", headers=PREFLIGHT)
        actual = client.get(OAUTH_PATHS[0], headers={"Origin": PREFLIGHT["Origin"]})
    assert preflight.status_code == 204
    assert "access-control-allow-origin" not in preflight.headers
    assert actual.status_code == 200
    assert "access-control-allow-origin" not in actual.headers


def test_actual_requests_carry_the_allow_origin_header(config: OAuthConfig) -> None:
    with cors_client(config, ("https://inspector.example.com",)) as client:
        metadata = client.get(OAUTH_PATHS[0], headers={"Origin": PREFLIGHT["Origin"]})
        registered = client.post(
            "/oauth/register",
            json={"client_name": "T", "redirect_uris": [REDIRECT]},
            headers={"Origin": PREFLIGHT["Origin"]},
        )
    for response in (metadata, registered):
        assert response.headers["access-control-allow-origin"] == PREFLIGHT["Origin"]


def test_other_routes_stay_closed(config: OAuthConfig) -> None:
    with cors_client(config, ("*",)) as client:
        response = client.get("/other", headers={"Origin": PREFLIGHT["Origin"]})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_no_cors_origins_adds_no_headers(config: OAuthConfig) -> None:
    with cors_client(config, ()) as client:
        response = client.get(OAUTH_PATHS[0], headers={"Origin": PREFLIGHT["Origin"]})
    assert "access-control-allow-origin" not in response.headers


def test_the_apps_own_cors_config_decides(
    config: OAuthConfig, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING", logger="litestar_oauth_server"):
        client = cors_client(config, ("*",), own_cors=True)
    with client:
        response = client.options("/oauth/token", headers=PREFLIGHT)
    assert response.status_code == 400  # Litestar's own CORS middleware, not ours
    assert "cors_origins is ignored" in caplog.text
