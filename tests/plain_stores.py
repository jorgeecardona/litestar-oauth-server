"""Stores written the way a host's database layer would write them (#5).

This module imports nothing from ``litestar_oauth_server`` at runtime. It has its own record
classes, one with a list for ``scopes`` and a plain string for ``kind``, as an ORM row would.
``tests/test_plain_stores.py`` checks that, and drives them through a full exchange.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # for the type checker only: nothing is imported at runtime
    from litestar_oauth_server import ClientLike, CodeLike, TokenLike


@dataclass(frozen=True)
class Client:
    client_id: str
    client_name: str
    redirect_uris: list[str]
    created_at: datetime


@dataclass(frozen=True)
class Code:
    code_hash: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    subject: str
    binding: str
    scopes: list[str]
    resource: str
    expires_at: datetime


@dataclass(frozen=True)
class Token:
    token_hash: str
    kind: str
    family_id: str
    client_id: str
    subject: str
    binding: str
    scopes: list[str]
    resource: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None


class PlainClientStore:
    def __init__(self) -> None:
        self.rows: dict[str, Client] = {}

    async def add(self, client: ClientLike) -> None:
        self.rows[client.client_id] = Client(
            client.client_id, client.client_name, list(client.redirect_uris), client.created_at
        )

    async def get(self, client_id: str) -> Client | None:
        return self.rows.get(client_id)


class PlainCodeStore:
    def __init__(self) -> None:
        self.rows: dict[str, Code] = {}

    async def add(self, record: CodeLike) -> None:
        r = record
        self.rows[r.code_hash] = Code(
            r.code_hash,
            r.client_id,
            r.redirect_uri,
            r.code_challenge,
            r.subject,
            r.binding,
            list(r.scopes),
            r.resource,
            r.expires_at,
        )

    async def consume(self, code_hash: str) -> Code | None:
        return self.rows.pop(code_hash, None)


class PlainTokenStore:
    def __init__(self) -> None:
        self.rows: dict[str, Token] = {}

    async def add(self, record: TokenLike) -> None:
        r = record
        self.rows[r.token_hash] = Token(
            r.token_hash,
            str(r.kind),
            r.family_id,
            r.client_id,
            r.subject,
            r.binding,
            list(r.scopes),
            r.resource,
            r.created_at,
            r.expires_at,
            r.used_at,
            r.revoked_at,
        )

    async def get(self, token_hash: str) -> Token | None:
        return self.rows.get(token_hash)

    async def consume_refresh(self, token_hash: str, now: datetime) -> Token | None:
        row = self.rows.get(token_hash)
        if row is None or row.kind != "refresh" or row.used_at is not None:
            return None
        self.rows[token_hash] = replace(row, used_at=now)
        return row

    async def revoke_family(self, family_id: str, now: datetime) -> None:
        for key, row in list(self.rows.items()):
            if row.family_id == family_id and row.revoked_at is None:
                self.rows[key] = replace(row, revoked_at=now)

    async def list_for_subject(self, subject: str) -> tuple[Token, ...]:
        found = [
            r
            for r in self.rows.values()
            if r.subject == subject
            and r.kind == "refresh"
            and r.revoked_at is None
            and r.used_at is None
        ]
        return tuple(sorted(found, key=lambda r: r.created_at, reverse=True))
