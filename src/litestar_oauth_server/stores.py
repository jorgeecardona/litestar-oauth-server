"""Storage protocols and an in-memory implementation.

The host app implements ``ClientStore``, ``CodeStore`` and ``TokenStore`` on its own database.
The stores take and return ``ClientLike``, ``CodeLike`` and ``TokenLike``: any object with those
attributes (a dataclass or an ORM row of the host), so the host's database layer does not import
this package at runtime (#5). Import the ``*Like`` names under ``if TYPE_CHECKING`` if you want
them for type checking.
Two operations must be atomic, because the security of the server rests on them:

- ``CodeStore.consume``: return the record and delete it in one step, or return ``None``. Two
  concurrent exchanges of one code must never both succeed.
- ``TokenStore.consume_refresh``: mark a refresh token used in one step and return it only if it
  was unused. A second use of the same refresh token is a theft signal: the server then revokes
  the whole family.

In SQL both are one ``UPDATE ... WHERE used_at IS NULL RETURNING ...`` (or ``DELETE ... RETURNING``).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol

from litestar_oauth_server.models import (
    ClientLike,
    CodeLike,
    CodeRecord,
    OAuthClient,
    TokenKind,
    TokenLike,
    TokenRecord,
)


class ClientStore(Protocol):
    async def add(self, client: ClientLike) -> None: ...

    async def get(self, client_id: str) -> ClientLike | None: ...


class CodeStore(Protocol):
    async def add(self, record: CodeLike) -> None: ...

    async def consume(self, code_hash: str) -> CodeLike | None:
        """Atomically return and delete the record. ``None`` if absent or already consumed."""
        ...


class TokenStore(Protocol):
    async def add(self, record: TokenLike) -> None: ...

    async def get(self, token_hash: str) -> TokenLike | None: ...

    async def consume_refresh(self, token_hash: str, now: datetime) -> TokenLike | None:
        """Atomically mark a refresh token used. Return it only if it was unused before."""
        ...

    async def revoke_family(self, family_id: str, now: datetime) -> None:
        """Revoke every token of the family (access and refresh)."""
        ...

    async def list_for_subject(self, subject: str) -> tuple[TokenLike, ...]:
        """The current (unused, not revoked) refresh token of each family of the subject, newest first.

        The server drops expired ones.
        """
        ...


@dataclass(frozen=True, slots=True)
class Stores:
    clients: ClientStore
    codes: CodeStore
    tokens: TokenStore


@dataclass(slots=True)
class InMemoryClientStore:
    """For tests and local development. Not shared between processes."""

    _clients: dict[str, OAuthClient] = field(default_factory=dict[str, OAuthClient])

    async def add(self, client: ClientLike) -> None:
        self._clients[client.client_id] = OAuthClient.of(client)

    async def get(self, client_id: str) -> OAuthClient | None:
        return self._clients.get(client_id)


@dataclass(slots=True)
class InMemoryCodeStore:
    _codes: dict[str, CodeRecord] = field(default_factory=dict[str, CodeRecord])

    async def add(self, record: CodeLike) -> None:
        self._codes[record.code_hash] = CodeRecord.of(record)

    async def consume(self, code_hash: str) -> CodeRecord | None:
        # No await between read and delete, so this is atomic on one event loop.
        return self._codes.pop(code_hash, None)


@dataclass(slots=True)
class InMemoryTokenStore:
    _tokens: dict[str, TokenRecord] = field(default_factory=dict[str, TokenRecord])

    async def add(self, record: TokenLike) -> None:
        self._tokens[record.token_hash] = TokenRecord.of(record)

    async def get(self, token_hash: str) -> TokenRecord | None:
        return self._tokens.get(token_hash)

    async def consume_refresh(self, token_hash: str, now: datetime) -> TokenRecord | None:
        record = self._tokens.get(token_hash)
        if record is None or record.kind is not TokenKind.REFRESH or record.used_at is not None:
            return None
        self._tokens[token_hash] = replace(record, used_at=now)
        return record

    async def revoke_family(self, family_id: str, now: datetime) -> None:
        for key, record in list(self._tokens.items()):
            if record.family_id == family_id and record.revoked_at is None:
                self._tokens[key] = replace(record, revoked_at=now)

    async def list_for_subject(self, subject: str) -> tuple[TokenRecord, ...]:
        found = [
            r
            for r in self._tokens.values()
            if r.subject == subject
            and r.kind is TokenKind.REFRESH
            and r.revoked_at is None
            and r.used_at is None
        ]
        return tuple(sorted(found, key=lambda r: r.created_at, reverse=True))


def in_memory_stores() -> Stores:
    return Stores(
        clients=InMemoryClientStore(),
        codes=InMemoryCodeStore(),
        tokens=InMemoryTokenStore(),
    )
