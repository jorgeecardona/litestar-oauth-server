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

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol, runtime_checkable

from litestar_oauth_server.models import (
    ClientLike,
    CodeLike,
    CodeRecord,
    DeviceDecision,
    DeviceLike,
    DeviceRecord,
    DeviceStatus,
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


@runtime_checkable
class ClientAdmin(Protocol):
    """Optional: a ``ClientStore`` that can list and delete clients, for an admin page (#2).

    ``AuthorizationServer.list_clients`` and ``delete_client`` call it when the client store has
    it, and raise ``TypeError`` when it does not.
    """

    async def list_clients(self, *, limit: int, offset: int) -> Sequence[ClientLike]:
        """A page of clients, newest first."""
        ...

    async def delete(self, client_id: str) -> bool:
        """Delete one client. Return whether it existed."""
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


class DeviceStore(Protocol):
    """Device authorizations (RFC 8628, #6). Two operations must be atomic, like the code store.

    - ``decide``: move a record from pending to approved or denied once. Two concurrent decisions
      on one user code must not both succeed.
    - ``consume_decided``: return the record and delete it in one step, only when it is decided.
      Two concurrent polls must not both get the approved record, or two token pairs are issued.

    ``user_code`` is unique. In SQL: a unique index, ``UPDATE ... WHERE status = 'pending' AND
    expires_at > :now RETURNING ...`` and ``DELETE ... WHERE status <> 'pending' RETURNING ...``.
    """

    async def add(self, record: DeviceLike) -> None: ...

    async def get(self, device_hash: str) -> DeviceLike | None: ...

    async def get_by_user_code(self, user_code: str) -> DeviceLike | None: ...

    async def decide(
        self, user_code: str, decision: DeviceDecision, now: datetime
    ) -> DeviceLike | None:
        """Atomically set the decision of a pending, unexpired record. ``None`` if there is none.

        Store ``decision.status.value`` and the other fields (as ``approved_scopes`` for the
        scopes). Return the record as it is after the update.
        """
        ...

    async def record_poll(self, device_hash: str, now: datetime, interval: int) -> None:
        """Remember that the client polled at ``now``, and the interval it must keep from now on."""
        ...

    async def consume_decided(self, device_hash: str) -> DeviceLike | None:
        """Atomically return and delete the record if it is approved or denied, else ``None``."""
        ...

    async def delete_expired(self, now: datetime) -> int:
        """Delete the records that expired before ``now``. Return how many."""
        ...


@dataclass(frozen=True, slots=True)
class Stores:
    """The stores of a server. ``devices`` is only needed for the device grant (#6)."""

    clients: ClientStore
    codes: CodeStore
    tokens: TokenStore
    devices: DeviceStore | None = field(default=None, kw_only=True)


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

    async def list_clients(self, *, limit: int, offset: int) -> Sequence[ClientLike]:
        newest_first = sorted(self._clients.values(), key=lambda c: c.created_at, reverse=True)
        return newest_first[offset : offset + limit]

    async def delete(self, client_id: str) -> bool:
        return self._clients.pop(client_id, None) is not None

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


@dataclass(slots=True)
class InMemoryDeviceStore:
    _records: dict[str, DeviceRecord] = field(default_factory=dict[str, DeviceRecord])

    async def add(self, record: DeviceLike) -> None:
        self._records[record.device_hash] = DeviceRecord.of(record)

    async def get(self, device_hash: str) -> DeviceRecord | None:
        return self._records.get(device_hash)

    async def get_by_user_code(self, user_code: str) -> DeviceRecord | None:
        return next((r for r in self._records.values() if r.user_code == user_code), None)

    async def decide(
        self, user_code: str, decision: DeviceDecision, now: datetime
    ) -> DeviceRecord | None:
        # No await between read and write, so this is atomic on one event loop.
        record = await self.get_by_user_code(user_code)
        if record is None or record.status is not DeviceStatus.PENDING or record.expires_at <= now:
            return None
        decided = replace(
            record,
            status=decision.status,
            subject=decision.subject,
            binding=decision.binding,
            approved_scopes=decision.scopes,
        )
        self._records[record.device_hash] = decided
        return decided

    async def record_poll(self, device_hash: str, now: datetime, interval: int) -> None:
        record = self._records.get(device_hash)
        if record is not None:
            self._records[device_hash] = replace(record, last_poll_at=now, interval=interval)

    async def consume_decided(self, device_hash: str) -> DeviceRecord | None:
        record = self._records.get(device_hash)
        if record is None or record.status is DeviceStatus.PENDING:
            return None
        return self._records.pop(device_hash)

    async def delete_expired(self, now: datetime) -> int:
        doomed = [key for key, r in self._records.items() if r.expires_at < now]
        for key in doomed:
            del self._records[key]
        return len(doomed)

    def client_ids(self) -> set[str]:
        """The clients that a stored device authorization refers to."""
        return {r.client_id for r in self._records.values()}


def in_memory_stores() -> Stores:
    codes = InMemoryCodeStore()
    tokens = InMemoryTokenStore()
    devices = InMemoryDeviceStore()

    def in_use() -> set[str]:
        return codes.client_ids() | tokens.client_ids() | devices.client_ids()

    return Stores(
        clients=InMemoryClientStore(_in_use=in_use), codes=codes, tokens=tokens, devices=devices
    )
