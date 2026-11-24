"""SQLAlchemy stores for Postgres (extra ``sqlalchemy``, #7).

Install with ``pip install "litestar-oauth-server[sqlalchemy]"`` and a Postgres driver of your own
choice (``psycopg`` or ``asyncpg``). The rest of the package does not import SQLAlchemy.

1. Call ``oauth_tables(metadata)`` with your own ``MetaData``. Your Alembic then sees the three
   tables, and this package ships no migrations.
2. Call ``sql_stores(engine, tables)`` with an ``AsyncEngine`` to get the stores.

Each store method runs in its own transaction and commits. It never joins a session of the host:
a host that rolls back after an ``OAuthError`` would otherwise un-burn an authorization code that
failed a check, and allow another attempt at the PKCE verifier.

Only Postgres is supported, and ``sql_stores`` refuses any other dialect. The two operations the
security of the server rests on are each one statement:

- ``SqlCodeStore.consume``: ``DELETE ... RETURNING``;
- ``SqlTokenStore.consume_refresh``: ``UPDATE ... WHERE used_at IS NULL RETURNING``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    Index,
    MetaData,
    String,
    Table,
    delete,
    exists,
    insert,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert

from litestar_oauth_server.models import (
    ClientLike,
    CodeLike,
    CodeRecord,
    OAuthClient,
    TokenKind,
    TokenLike,
    TokenRecord,
)
from litestar_oauth_server.stores import Stores

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.engine import Row
    from sqlalchemy.ext.asyncio import AsyncEngine


@dataclass(frozen=True, slots=True)
class OAuthTables:
    """The three tables, created on the host's ``MetaData`` by ``oauth_tables``."""

    clients: Table
    codes: Table
    tokens: Table


def oauth_tables(metadata: MetaData, *, prefix: str = "oauth_") -> OAuthTables:
    """Define the client, code and token tables on ``metadata`` and return them.

    The host's naming conventions and schema apply. Names are ``{prefix}clients``,
    ``{prefix}codes`` and ``{prefix}tokens``. There is no foreign key from codes or tokens to
    clients: deleting a client leaves its tokens valid until they expire.
    """
    clients = Table(
        f"{prefix}clients",
        metadata,
        Column("client_id", String, primary_key=True),
        Column("client_name", String, nullable=False),
        Column("redirect_uris", JSON, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Index(f"ix_{prefix}clients_created_at", "created_at"),
    )
    codes = Table(
        f"{prefix}codes",
        metadata,
        Column("code_hash", String, primary_key=True),
        Column("client_id", String, nullable=False),
        Column("redirect_uri", String, nullable=False),
        Column("code_challenge", String, nullable=False),
        Column("subject", String, nullable=False),
        Column("binding", String, nullable=False),
        Column("scopes", JSON, nullable=False),
        Column("resource", String, nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Index(f"ix_{prefix}codes_client_id", "client_id"),
        Index(f"ix_{prefix}codes_expires_at", "expires_at"),
    )
    tokens = Table(
        f"{prefix}tokens",
        metadata,
        Column("token_hash", String, primary_key=True),
        Column("kind", String, nullable=False),
        Column("family_id", String, nullable=False),
        Column("client_id", String, nullable=False),
        Column("subject", String, nullable=False),
        Column("binding", String, nullable=False),
        Column("scopes", JSON, nullable=False),
        Column("resource", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("used_at", DateTime(timezone=True)),
        Column("revoked_at", DateTime(timezone=True)),
        CheckConstraint("kind IN ('access', 'refresh')", name=f"ck_{prefix}tokens_kind"),
        Index(f"ix_{prefix}tokens_family_id", "family_id"),
        Index(f"ix_{prefix}tokens_subject", "subject"),
        Index(f"ix_{prefix}tokens_client_id", "client_id"),
        Index(f"ix_{prefix}tokens_expires_at", "expires_at"),
    )
    return OAuthTables(clients=clients, codes=codes, tokens=tokens)


def _aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value


def _client(row: Row[Any]) -> OAuthClient:
    return OAuthClient(
        client_id=row.client_id,
        client_name=row.client_name,
        redirect_uris=tuple(row.redirect_uris),
        created_at=row.created_at,
    )


def _code(row: Row[Any]) -> CodeRecord:
    return CodeRecord(
        code_hash=row.code_hash,
        client_id=row.client_id,
        redirect_uri=row.redirect_uri,
        code_challenge=row.code_challenge,
        subject=row.subject,
        binding=row.binding,
        scopes=tuple(row.scopes),
        resource=row.resource,
        expires_at=row.expires_at,
    )


def _token(row: Row[Any]) -> TokenRecord:
    return TokenRecord(
        token_hash=row.token_hash,
        kind=TokenKind(row.kind),
        family_id=row.family_id,
        client_id=row.client_id,
        subject=row.subject,
        binding=row.binding,
        scopes=tuple(row.scopes),
        resource=row.resource,
        created_at=row.created_at,
        expires_at=row.expires_at,
        used_at=row.used_at,
        revoked_at=row.revoked_at,
    )


@dataclass(frozen=True, slots=True)
class SqlClientStore:
    """Clients in Postgres. Also implements ``ClientPurge`` and ``ClientAdmin``."""

    engine: AsyncEngine
    tables: OAuthTables

    async def add(self, client: ClientLike) -> None:
        """Insert the client, or replace the one with the same ``client_id``."""
        values = {
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": list(client.redirect_uris),
            "created_at": _aware(client.created_at, "created_at"),
        }
        statement = pg_insert(self.tables.clients).values(values)
        statement = statement.on_conflict_do_update(
            index_elements=["client_id"], set_={k: v for k, v in values.items() if k != "client_id"}
        )
        async with self.engine.begin() as conn:
            await conn.execute(statement)

    async def get(self, client_id: str) -> OAuthClient | None:
        clients = self.tables.clients
        async with self.engine.begin() as conn:
            row = (
                await conn.execute(select(clients).where(clients.c.client_id == client_id))
            ).first()
        return None if row is None else _client(row)

    async def list_clients(self, *, limit: int, offset: int) -> Sequence[OAuthClient]:
        """A page of clients, newest first."""
        clients = self.tables.clients
        query = select(clients).order_by(clients.c.created_at.desc()).limit(limit).offset(offset)
        async with self.engine.begin() as conn:
            rows = (await conn.execute(query)).all()
        return [_client(row) for row in rows]

    async def delete(self, client_id: str) -> bool:
        """Delete one client. Return whether it existed."""
        clients = self.tables.clients
        statement = delete(clients).where(clients.c.client_id == client_id)
        async with self.engine.begin() as conn:
            return (await conn.execute(statement)).rowcount > 0

    async def delete_unused(self, created_before: datetime) -> int:
        """Delete clients created before ``created_before`` that no code or token refers to."""
        clients, codes, tokens = self.tables.clients, self.tables.codes, self.tables.tokens
        statement = delete(clients).where(
            clients.c.created_at < created_before,
            ~exists().where(codes.c.client_id == clients.c.client_id),
            ~exists().where(tokens.c.client_id == clients.c.client_id),
        )
        async with self.engine.begin() as conn:
            return (await conn.execute(statement)).rowcount


@dataclass(frozen=True, slots=True)
class SqlCodeStore:
    """Authorization codes in Postgres."""

    engine: AsyncEngine
    tables: OAuthTables

    async def add(self, record: CodeLike) -> None:
        statement = insert(self.tables.codes).values(
            code_hash=record.code_hash,
            client_id=record.client_id,
            redirect_uri=record.redirect_uri,
            code_challenge=record.code_challenge,
            subject=record.subject,
            binding=record.binding,
            scopes=list(record.scopes),
            resource=record.resource,
            expires_at=_aware(record.expires_at, "expires_at"),
        )
        async with self.engine.begin() as conn:
            await conn.execute(statement)

    async def consume(self, code_hash: str) -> CodeRecord | None:
        """Delete the code and return it in one statement. ``None`` if absent or consumed."""
        codes = self.tables.codes
        statement = delete(codes).where(codes.c.code_hash == code_hash).returning(*codes.c)
        async with self.engine.begin() as conn:
            row = (await conn.execute(statement)).first()
        return None if row is None else _code(row)

    async def delete_expired(self, now: datetime) -> int:
        """Delete the codes that expired before ``now``. Return how many."""
        codes = self.tables.codes
        async with self.engine.begin() as conn:
            return (await conn.execute(delete(codes).where(codes.c.expires_at < now))).rowcount


@dataclass(frozen=True, slots=True)
class SqlTokenStore:
    """Access and refresh tokens in Postgres."""

    engine: AsyncEngine
    tables: OAuthTables

    async def add(self, record: TokenLike) -> None:
        statement = insert(self.tables.tokens).values(
            token_hash=record.token_hash,
            kind=TokenKind(record.kind).value,
            family_id=record.family_id,
            client_id=record.client_id,
            subject=record.subject,
            binding=record.binding,
            scopes=list(record.scopes),
            resource=record.resource,
            created_at=_aware(record.created_at, "created_at"),
            expires_at=_aware(record.expires_at, "expires_at"),
            used_at=record.used_at,
            revoked_at=record.revoked_at,
        )
        async with self.engine.begin() as conn:
            await conn.execute(statement)

    async def get(self, token_hash: str) -> TokenRecord | None:
        tokens = self.tables.tokens
        async with self.engine.begin() as conn:
            row = (
                await conn.execute(select(tokens).where(tokens.c.token_hash == token_hash))
            ).first()
        return None if row is None else _token(row)

    async def consume_refresh(self, token_hash: str, now: datetime) -> TokenRecord | None:
        """Mark a refresh token used and return it, only if it was unused. One statement.

        The returned record is the row after the update, so its ``used_at`` is ``now``.
        """
        tokens = self.tables.tokens
        statement = (
            update(tokens)
            .where(
                tokens.c.token_hash == token_hash,
                tokens.c.kind == TokenKind.REFRESH.value,
                tokens.c.used_at.is_(None),
            )
            .values(used_at=now)
            .returning(*tokens.c)
        )
        async with self.engine.begin() as conn:
            row = (await conn.execute(statement)).first()
        return None if row is None else _token(row)

    async def revoke_family(self, family_id: str, now: datetime) -> None:
        """Revoke every token of the family that is not revoked yet."""
        tokens = self.tables.tokens
        statement = (
            update(tokens)
            .where(tokens.c.family_id == family_id, tokens.c.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        async with self.engine.begin() as conn:
            await conn.execute(statement)

    async def list_for_subject(self, subject: str) -> tuple[TokenRecord, ...]:
        """The current refresh token of each family of the subject, newest first."""
        tokens = self.tables.tokens
        query = (
            select(tokens)
            .where(
                tokens.c.subject == subject,
                tokens.c.kind == TokenKind.REFRESH.value,
                tokens.c.revoked_at.is_(None),
                tokens.c.used_at.is_(None),
            )
            .order_by(tokens.c.created_at.desc())
        )
        async with self.engine.begin() as conn:
            rows = (await conn.execute(query)).all()
        return tuple(_token(row) for row in rows)

    async def delete_expired(self, now: datetime) -> int:
        """Delete the tokens that expired before ``now``. Return how many."""
        tokens = self.tables.tokens
        async with self.engine.begin() as conn:
            return (await conn.execute(delete(tokens).where(tokens.c.expires_at < now))).rowcount


@dataclass(frozen=True, slots=True)
class SqlStores(Stores):
    """``Stores`` made of the three SQL stores, with the cleanup of expired rows."""

    clients: SqlClientStore
    codes: SqlCodeStore
    tokens: SqlTokenStore

    async def delete_expired(self, now: datetime) -> int:
        """Delete expired codes and tokens. Return how many rows. Run it from a periodic job.

        Expired rows are never read again, but each one keeps its client from counting as unused.
        Run this before ``purge_unused_clients``.
        """
        return await self.codes.delete_expired(now) + await self.tokens.delete_expired(now)


def sql_stores(engine: AsyncEngine, tables: OAuthTables) -> SqlStores:
    """The stores for ``engine``, on the tables from ``oauth_tables``.

    Raises:
        ValueError: if the engine is not Postgres.
    """
    if engine.dialect.name != "postgresql":
        raise ValueError(
            f"sql_stores supports Postgres only, not {engine.dialect.name!r}; "
            "use in_memory_stores() for development"
        )
    # READ COMMITTED: under a stricter level the loser of two concurrent consumes raises a
    # serialization error instead of getting ``None``. The option copy shares the host's pool.
    pinned = engine.execution_options(isolation_level="READ COMMITTED")
    return SqlStores(
        clients=SqlClientStore(pinned, tables),
        codes=SqlCodeStore(pinned, tables),
        tokens=SqlTokenStore(pinned, tables),
    )
