"""The SQLAlchemy stores (#7), against a real Postgres.

If ``OAUTH_TEST_POSTGRES_URL`` is set (CI sets it to a GitLab service), the tests use that
database and rebuild the three tables before each test. Otherwise they start a container with
pytest-servex, which needs Docker.
"""

import os
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest
from pytest_servex import PostgresDatabase
from sqlalchemy import MetaData, create_engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from litestar_oauth_server.sqlalchemy import SqlStores, oauth_tables, sql_stores
from litestar_oauth_server.testing import CASES, Case, sample_code, sample_token

TABLES = oauth_tables(MetaData())


@pytest.fixture(scope="session")
def servex_postgres_prepare() -> Callable[[str], None]:
    """Create the three tables once; every worker database starts as a copy of the result."""

    def prepare(url: str) -> None:
        engine = create_engine(url.replace("postgresql://", "postgresql+psycopg://", 1))
        TABLES.clients.metadata.create_all(engine)
        engine.dispose()

    return prepare


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def engine(request: pytest.FixtureRequest) -> AsyncIterator[AsyncEngine]:
    url = os.environ.get("OAUTH_TEST_POSTGRES_URL")
    if url is None:
        database: PostgresDatabase = request.getfixturevalue("servex_postgres_clean")
        url = database.sqlalchemy_url()
    # A pool of at least 2, or the concurrent cases would run one after the other.
    created = create_async_engine(url, pool_size=10)
    metadata = TABLES.clients.metadata
    async with created.begin() as conn:
        await conn.run_sync(metadata.drop_all)
        await conn.run_sync(metadata.create_all)
    yield created
    await created.dispose()


@pytest.fixture
def stores(engine: AsyncEngine) -> SqlStores:
    return sql_stores(engine, TABLES)


@pytest.mark.anyio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
async def test_the_store_contract(stores: SqlStores, case: Case) -> None:
    await case(stores)


@pytest.mark.anyio
async def test_delete_expired_removes_only_expired_rows(stores: SqlStores) -> None:
    await stores.codes.add(sample_code("live"))
    await stores.tokens.add(sample_token("live"))
    assert await stores.delete_expired(datetime(2026, 1, 1, tzinfo=UTC)) == 0
    assert await stores.delete_expired(datetime(2030, 1, 1, tzinfo=UTC)) == 2
    assert await stores.codes.consume("live") is None
    assert await stores.tokens.get("live") is None


@pytest.mark.anyio
async def test_a_naive_datetime_is_refused(stores: SqlStores) -> None:
    naive = sample_token("t1").created_at.replace(tzinfo=None)
    with pytest.raises(ValueError, match="timezone-aware"):
        await stores.tokens.add(replace(sample_token("t1"), created_at=naive))


def test_another_dialect_is_refused() -> None:
    engine = cast("AsyncEngine", SimpleNamespace(dialect=SimpleNamespace(name="mysql")))
    with pytest.raises(ValueError, match="Postgres only"):
        sql_stores(engine, TABLES)
