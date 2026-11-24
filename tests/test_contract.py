"""The store contract (#7), run on the in-memory stores and on the plain stores of #5."""

from collections.abc import Callable

import pytest

from litestar_oauth_server import Stores, in_memory_stores
from litestar_oauth_server.testing import CASES, Case
from tests.plain_stores import (
    PlainClientStore,
    PlainCodeStore,
    PlainDeviceStore,
    PlainTokenStore,
)


def plain_stores() -> Stores:
    return Stores(
        clients=PlainClientStore(),
        codes=PlainCodeStore(),
        tokens=PlainTokenStore(),
        devices=PlainDeviceStore(),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("make", [in_memory_stores, plain_stores], ids=["in-memory", "plain"])
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
async def test_the_store_contract(make: Callable[[], Stores], case: Case) -> None:
    await case(make())
