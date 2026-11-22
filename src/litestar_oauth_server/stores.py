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

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol, runtime_checkable

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


@runtime_checkable
class ClientPurge(Protocol):
    """Optional: a ``ClientStore`` that can delete clients nobody used (#2).

    Registration is open, so rows pile up. ``AuthorizationServer.purge_unused_clients`` calls this
    when the client store has it, and raises ``TypeError`` when it does not.
    """

    async def delete_unused(self, created_before: datetime) -> int:
        """Delete clients created before ``created_before`` that no code or token refers to.

        Return how many were deleted. In SQL: ``DELETE ... WHERE created_at < :t AND NOT EXISTS``
        a code and NOT EXISTS a token of the client.
        """
        ...


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
    # Client ids that a code or token refers to. ``in_memory_stores`` wires it to the other stores.
    _in_use: Callable[[], set[str]] = field(default=set[str])

    async def add(self, client: ClientLike) -> None:
        self._clients[client.client_id] = OAuthClient.of(client)

    async def get(self, client_id: str) -> OAuthClient | None:
        return self._clients.get(client_id)

    async def delete_unused(self, created_before: datetime) -> int:
        in_use = self._in_use()
        doomed = [
            c.client_id
            for c in self._clients.values()
            if c.created_at < created_before and c.client_id not in in_use
        ]
        for client_id in doomed:
            del self._clients[client_id]
        return len(doomed)


@dataclass(slots=True)
class InMemoryCodeStore:
    _codes: dict[str, CodeRecord] = field(default_factory=dict[str, CodeRecord])

    async def add(self, record: CodeLike) -> None:
        self._codes[record.code_hash] = CodeRecord.of(record)

    async def consume(self, code_hash: str) -> CodeRecord | None:
        # No await between read and delete, so this is atomic on one event loop.
        return self._codes.pop(code_hash, None)

    def client_ids(self) -> set[str]:
        """The clients that a stored code refers to."""
        return {c.client_id for c in self._codes.values()}


@dataclass(slots=True)
class InMemoryTokenStore:
    _tokens: dict[str, TokenRecord] = field(default_factory=dict[str, TokenRecord])

    async def add(self, record: TokenLike) -> None:
        self._tokens[record.token_hash] = TokenRecord.of(record)

    async def get(self, token_hash: str) -> TokenRecord | None:
        return self._tokens.get(token_hash)

    def client_ids(self) -> set[str]:
        """The clients that a stored token refers to."""
        return {t.client_id for t in self._tokens.values()}

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
    codes = InMemoryCodeStore()
    tokens = InMemoryTokenStore()

    def in_use() -> set[str]:
        return codes.client_ids() | tokens.client_ids()

    return Stores(clients=InMemoryClientStore(_in_use=in_use), codes=codes, tokens=tokens)
