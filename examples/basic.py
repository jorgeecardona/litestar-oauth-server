"""A Litestar API with an OAuth server and one protected endpoint.

Run it with:  uv run litestar --app examples.basic:app run

The consent page is the host app's job. Here a plain endpoint stands in for it: it receives the
user's decision and returns the redirect URL carrying the code. In a real app this sits behind
your own login, and ``subject`` and ``binding`` come from the signed-in user.
"""

from dataclasses import dataclass
from typing import Any

from litestar import Litestar, Request, get, post

from litestar_oauth import (
    Approval,
    AuthorizationRequest,
    AuthorizationServer,
    LitestarOAuth,
    OAuthConfig,
    bearer_guard,
    in_memory_stores,
    verified_token,
)

RESOURCE = "http://localhost:8000/api"

server = AuthorizationServer(
    config=OAuthConfig(
        issuer="http://localhost:8000",
        authorization_endpoint="http://localhost:8000/consent",
        resources=(RESOURCE,),
        scopes_supported=("notes:read", "notes:write"),
        resource_name="Notes",
    ),
    stores=in_memory_stores(),  # replace with stores on your own database
)


@dataclass(frozen=True, slots=True)
class ConsentDecision:
    request: AuthorizationRequest
    scopes: tuple[str, ...]
    company_id: str


@post("/consent", status_code=200)
async def consent(data: ConsentDecision) -> dict[str, str]:
    # Real app: require a signed-in user, check they may grant access to ``company_id``.
    redirect = await server.approve(
        data.request,
        Approval(subject="user-1", scopes=data.scopes, binding=f"company:{data.company_id}"),
    )
    return {"redirect": redirect}


@get("/api", guards=[bearer_guard(server, RESOURCE, scope="notes:read")], sync_to_thread=False)
def notes(request: Request[Any, Any, Any]) -> dict[str, str]:
    token = verified_token(request)
    return {"subject": token.subject, "company": token.binding}


app = Litestar([consent, notes], plugins=[LitestarOAuth(server)])
