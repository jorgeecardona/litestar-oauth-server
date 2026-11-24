"""A contract test suite for stores (#7).

Run it against your own ``ClientStore``, ``CodeStore`` and ``TokenStore`` to check what the server
relies on: a code is consumed once, a refresh token is claimed once even when two exchanges race,
a family is revoked as a whole. This module does not import pytest. With pytest:

```python
import pytest
from litestar_oauth_server.testing import CASES

@pytest.mark.anyio
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
async def test_my_stores(case):
    await case(await make_empty_stores())
```

Each case takes a ``Stores`` that is empty and raises ``AssertionError`` when the contract is
broken. Give every case its own empty ``Stores``. The cases for ``ClientPurge`` and
``ClientAdmin`` run only when the client store has those methods, and return at once otherwise.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from litestar_oauth_server.models import (
    GRANT_DEVICE_CODE,
    CodeRecord,
    DeviceDecision,
    DeviceRecord,
    DeviceStatus,
    OAuthClient,
    TokenKind,
    TokenRecord,
)
from litestar_oauth_server.stores import ClientAdmin, ClientPurge, Stores

type Case = Callable[[Stores], Awaitable[None]]

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(minutes=5)
RACERS = 8  # concurrent callers in a race
ROUNDS = 25  # races per case: one race can pass by luck


def _expect(condition: bool, message: str) -> None:  # noqa: FBT001
    if not condition:
        raise AssertionError(message)


def sample_client(
    client_id: str = "c1",
    *,
    created_at: datetime = NOW,
    grant_types: tuple[str, ...] = ("authorization_code", "refresh_token"),
) -> OAuthClient:
    return OAuthClient(
        client_id=client_id,
        client_name="Test client",
        redirect_uris=("https://client.example.com/cb", "http://127.0.0.1:8080/cb"),
        created_at=created_at,
        grant_types=grant_types,
    )


def sample_device(
    device_hash: str = "d1",
    *,
    user_code: str = "WDJBMJHT",
    client_id: str = "c1",
    expires_at: datetime = LATER,
) -> DeviceRecord:
    return DeviceRecord(
        device_hash=device_hash,
        user_code=user_code,
        client_id=client_id,
        scopes=("things:read", "things:write"),
        resource="https://api.example.com/mcp",
        expires_at=expires_at,
        interval=5,
    )


def sample_code(code_hash: str = "h1", client_id: str = "c1") -> CodeRecord:
    return CodeRecord(
        code_hash=code_hash,
        client_id=client_id,
        redirect_uri="https://client.example.com/cb",
        code_challenge="challenge",
        subject="u1",
        binding="company:9",
        scopes=("things:read", "things:write"),
        resource="https://api.example.com/mcp",
        expires_at=LATER,
    )


def sample_token(
    token_hash: str = "t1",
    *,
    kind: TokenKind = TokenKind.REFRESH,
    family_id: str = "f1",
    client_id: str = "c1",
    subject: str = "u1",
    created_at: datetime = NOW,
) -> TokenRecord:
    return TokenRecord(
        token_hash=token_hash,
        kind=kind,
        family_id=family_id,
        client_id=client_id,
        subject=subject,
        binding="company:9",
        scopes=("things:read",),
        resource="https://api.example.com/mcp",
        created_at=created_at,
        expires_at=LATER,
    )


async def client_roundtrip(stores: Stores) -> None:
    """A stored client comes back with the same values, and an unknown id gives ``None``."""
    await stores.clients.add(sample_client())
    found = await stores.clients.get("c1")
    if found is None:
        raise AssertionError("a stored client was not found")
    _expect(OAuthClient.of(found) == sample_client(), "the client changed in storage")
    _expect(await stores.clients.get("nope") is None, "an unknown client was found")


async def code_roundtrip(stores: Stores) -> None:
    """A stored code is returned by ``consume`` with the same values, and only once."""
    await stores.codes.add(sample_code())
    first = await stores.codes.consume("h1")
    if first is None:
        raise AssertionError("a stored code was not found")
    _expect(CodeRecord.of(first) == sample_code(), "the code changed in storage")
    _expect(await stores.codes.consume("h1") is None, "a code was consumed twice")
    _expect(await stores.codes.consume("nope") is None, "an unknown code was consumed")


async def code_consume_is_atomic(stores: Stores) -> None:
    """Concurrent ``consume`` calls on one code: exactly one gets it."""
    for round_ in range(ROUNDS):
        code_hash = f"race-{round_}"
        await stores.codes.add(sample_code(code_hash))
        results = await asyncio.gather(*(stores.codes.consume(code_hash) for _ in range(RACERS)))
        winners = [r for r in results if r is not None]
        _expect(len(winners) == 1, f"{len(winners)} callers consumed one code (round {round_})")


async def token_roundtrip(stores: Stores) -> None:
    """A stored token comes back with the same values, and an unknown hash gives ``None``."""
    await stores.tokens.add(sample_token())
    found = await stores.tokens.get("t1")
    if found is None:
        raise AssertionError("a stored token was not found")
    _expect(TokenRecord.of(found) == sample_token(), "the token changed in storage")
    _expect(await stores.tokens.get("nope") is None, "an unknown token was found")


async def refresh_is_claimed_once(stores: Stores) -> None:
    """``consume_refresh`` claims a refresh token once, and never claims an access token."""
    await stores.tokens.add(sample_token("r1"))
    await stores.tokens.add(sample_token("a1", kind=TokenKind.ACCESS))
    claimed = await stores.tokens.consume_refresh("r1", LATER)
    if claimed is None:
        raise AssertionError("an unused refresh token was not claimed")
    _expect(claimed.token_hash == "r1", "the wrong token was claimed")
    _expect(await stores.tokens.consume_refresh("r1", LATER) is None, "a refresh token was reused")
    _expect(await stores.tokens.consume_refresh("a1", LATER) is None, "an access token was claimed")
    access = await stores.tokens.get("a1")
    _expect(access is not None and access.used_at is None, "an access token was marked used")
    _expect(await stores.tokens.consume_refresh("nope", LATER) is None, "an unknown token claimed")
    used = await stores.tokens.get("r1")
    _expect(used is not None and used.used_at == LATER, "a claim did not set used_at")


async def refresh_claim_is_atomic(stores: Stores) -> None:
    """Concurrent ``consume_refresh`` calls on one token: exactly one gets it."""
    for round_ in range(ROUNDS):
        token_hash = f"race-{round_}"
        await stores.tokens.add(sample_token(token_hash, family_id=f"family-{round_}"))
        results = await asyncio.gather(
            *(stores.tokens.consume_refresh(token_hash, LATER) for _ in range(RACERS))
        )
        winners = [r for r in results if r is not None]
        _expect(len(winners) == 1, f"{len(winners)} callers claimed one token (round {round_})")


async def family_is_revoked_as_a_whole(stores: Stores) -> None:
    """``revoke_family`` marks every token of the family, and no other token."""
    await stores.tokens.add(sample_token("r1"))
    await stores.tokens.add(sample_token("a1", kind=TokenKind.ACCESS))
    await stores.tokens.add(sample_token("other", family_id="f2"))
    await stores.tokens.revoke_family("f1", LATER)
    for token_hash in ("r1", "a1"):
        record = await stores.tokens.get(token_hash)
        _expect(record is not None and record.revoked_at == LATER, f"{token_hash} not revoked")
    other = await stores.tokens.get("other")
    _expect(other is not None and other.revoked_at is None, "another family was revoked")


async def list_for_subject_gives_current_refresh_tokens(stores: Stores) -> None:
    """Only unused, unrevoked refresh tokens of the subject, newest first."""
    await stores.tokens.add(sample_token("old", family_id="f1", created_at=NOW))
    await stores.tokens.add(
        sample_token("new", family_id="f2", created_at=NOW + timedelta(minutes=1))
    )
    await stores.tokens.add(sample_token("access", kind=TokenKind.ACCESS, family_id="f3"))
    await stores.tokens.add(sample_token("used", family_id="f4"))
    await stores.tokens.add(sample_token("revoked", family_id="f5"))
    await stores.tokens.add(sample_token("someone-else", family_id="f6", subject="u2"))
    await stores.tokens.consume_refresh("used", LATER)
    await stores.tokens.revoke_family("f5", LATER)
    found = await stores.tokens.list_for_subject("u1")
    _expect([t.token_hash for t in found] == ["new", "old"], "wrong tokens or order")


async def unused_clients_are_purged(stores: Stores) -> None:
    """``ClientPurge``: delete old clients that no code, token or device refers to."""
    if not isinstance(stores.clients, ClientPurge):
        return
    old = NOW - timedelta(days=60)
    await stores.clients.add(sample_client("idle", created_at=old))
    await stores.clients.add(sample_client("with-code", created_at=old))
    await stores.clients.add(sample_client("with-token", created_at=old))
    await stores.clients.add(sample_client("recent", created_at=NOW))
    await stores.codes.add(sample_code("h1", client_id="with-code"))
    await stores.tokens.add(sample_token("t1", client_id="with-token"))
    kept = ["with-code", "with-token", "recent"]
    if stores.devices is not None:
        await stores.clients.add(sample_client("with-device", created_at=old))
        await stores.devices.add(sample_device(client_id="with-device"))
        kept.append("with-device")
    deleted = await stores.clients.delete_unused(NOW - timedelta(days=30))
    _expect(deleted == 1, f"{deleted} clients deleted, expected 1")
    _expect(await stores.clients.get("idle") is None, "an idle client survived")
    for client_id in kept:
        _expect(await stores.clients.get(client_id) is not None, f"{client_id} was deleted")


async def clients_can_be_listed_and_deleted(stores: Stores) -> None:
    """``ClientAdmin``: pages are newest first, and ``delete`` says whether the client existed."""
    if not isinstance(stores.clients, ClientAdmin):
        return
    for index in range(3):
        await stores.clients.add(
            sample_client(f"c{index}", created_at=NOW + timedelta(minutes=index))
        )
    page = await stores.clients.list_clients(limit=2, offset=0)
    _expect([c.client_id for c in page] == ["c2", "c1"], "the first page is wrong")
    rest = await stores.clients.list_clients(limit=2, offset=2)
    _expect([c.client_id for c in rest] == ["c0"], "the second page is wrong")
    _expect(await stores.clients.delete("c1") is True, "delete of an existing client said no")
    _expect(await stores.clients.delete("c1") is False, "delete of a missing client said yes")


async def client_keeps_its_grant_types(stores: Stores) -> None:
    """A client's ``grant_types`` come back as stored (the device grant is opt-in per client)."""
    grants = (GRANT_DEVICE_CODE, "refresh_token")
    await stores.clients.add(sample_client("device-client", grant_types=grants))
    found = await stores.clients.get("device-client")
    if found is None:
        raise AssertionError("a stored client was not found")
    _expect(OAuthClient.of(found).grant_types == grants, "grant_types changed in storage")


async def device_roundtrip(stores: Stores) -> None:
    """``DeviceStore``: a stored authorization is found by device hash and by user code."""
    if stores.devices is None:
        return
    await stores.devices.add(sample_device())
    found = await stores.devices.get("d1")
    if found is None:
        raise AssertionError("a stored device authorization was not found")
    _expect(DeviceRecord.of(found) == sample_device(), "the device record changed in storage")
    by_code = await stores.devices.get_by_user_code("WDJBMJHT")
    _expect(by_code is not None and by_code.device_hash == "d1", "not found by user code")
    _expect(await stores.devices.get("nope") is None, "an unknown device hash was found")
    _expect(await stores.devices.get_by_user_code("NOPE") is None, "an unknown code was found")


async def device_decide_is_atomic(stores: Stores) -> None:
    """Concurrent ``decide`` calls on one user code: exactly one wins, and its values stay."""
    if stores.devices is None:
        return
    devices = stores.devices
    for round_ in range(ROUNDS):
        code = f"RACE{round_}"
        await devices.add(sample_device(f"race-{round_}", user_code=code))
        decisions = [
            DeviceDecision(DeviceStatus.APPROVED, f"user-{n}", "company:9", ("things:read",))
            for n in range(RACERS)
        ]
        results = await asyncio.gather(*(devices.decide(code, d, NOW) for d in decisions))
        winners = [r for r in results if r is not None]
        _expect(len(winners) == 1, f"{len(winners)} callers decided one code (round {round_})")
        stored = await devices.get(f"race-{round_}")
        _expect(stored is not None and stored.subject == winners[0].subject, "decision was mixed")


async def device_decide_refuses_expired_and_decided(stores: Stores) -> None:
    """``decide`` changes only a pending record that has not expired."""
    if stores.devices is None:
        return
    devices = stores.devices
    approve = DeviceDecision(DeviceStatus.APPROVED, "u1", "company:9", ("things:read",))
    deny = DeviceDecision(DeviceStatus.DENIED)
    await devices.add(sample_device("old", user_code="OLD", expires_at=NOW - timedelta(minutes=1)))
    _expect(await devices.decide("OLD", approve, NOW) is None, "an expired record was decided")
    await devices.add(sample_device("live", user_code="LIVE"))
    _expect(await devices.decide("LIVE", approve, NOW) is not None, "a pending record was refused")
    _expect(await devices.decide("LIVE", deny, NOW) is None, "a decided record was decided again")
    stored = await devices.get("live")
    if stored is None:
        raise AssertionError("a decided record disappeared")
    _expect(stored.status == "approved", "the first decision was lost")
    _expect(tuple(stored.approved_scopes) == ("things:read",), "the approved scopes were lost")
    _expect(await devices.decide("NOPE", approve, NOW) is None, "an unknown code was decided")


async def device_decided_is_consumed_once(stores: Stores) -> None:
    """``consume_decided`` ignores a pending record, and gives a decided one to exactly one caller."""
    if stores.devices is None:
        return
    devices = stores.devices
    await devices.add(sample_device("d1", user_code="ONE"))
    _expect(await devices.consume_decided("d1") is None, "a pending record was consumed")
    _expect(await devices.get("d1") is not None, "a pending record was deleted")
    approve = DeviceDecision(DeviceStatus.APPROVED, "u1", "company:9", ("things:read",))
    await devices.decide("ONE", approve, NOW)
    first = await devices.consume_decided("d1")
    _expect(first is not None and first.subject == "u1", "an approved record was not consumed")
    _expect(await devices.get("d1") is None, "a consumed record was kept")
    for round_ in range(ROUNDS):
        await devices.add(sample_device(f"race-{round_}", user_code=f"RACE{round_}"))
        await devices.decide(f"RACE{round_}", approve, NOW)
        results = await asyncio.gather(
            *(devices.consume_decided(f"race-{round_}") for _ in range(RACERS))
        )
        winners = [r for r in results if r is not None]
        _expect(len(winners) == 1, f"{len(winners)} callers consumed one record (round {round_})")
    await devices.add(sample_device("denied", user_code="NO"))
    await devices.decide("NO", DeviceDecision(DeviceStatus.DENIED), NOW)
    denied = await devices.consume_decided("denied")
    _expect(denied is not None and denied.status == "denied", "a denied record was not consumed")


async def device_poll_and_expiry(stores: Stores) -> None:
    """``record_poll`` is stored, and ``delete_expired`` removes only expired records."""
    if stores.devices is None:
        return
    devices = stores.devices
    await devices.add(sample_device("live", user_code="LIVE"))
    await devices.add(sample_device("old", user_code="OLD", expires_at=NOW - timedelta(minutes=1)))
    slower = 10
    await devices.record_poll("live", LATER, slower)
    polled = await devices.get("live")
    if polled is None:
        raise AssertionError("a polled record disappeared")
    _expect(polled.last_poll_at == LATER, "the poll time was lost")
    _expect(polled.interval == slower, "the interval was lost")
    deleted = await devices.delete_expired(NOW)
    _expect(deleted == 1, f"{deleted} records deleted, expected 1")
    _expect(await devices.get("old") is None, "an expired record survived")
    _expect(await devices.get("live") is not None, "a live record was deleted")


CASES: tuple[Case, ...] = (
    client_roundtrip,
    code_roundtrip,
    code_consume_is_atomic,
    token_roundtrip,
    refresh_is_claimed_once,
    refresh_claim_is_atomic,
    family_is_revoked_as_a_whole,
    list_for_subject_gives_current_refresh_tokens,
    unused_clients_are_purged,
    clients_can_be_listed_and_deleted,
    client_keeps_its_grant_types,
    device_roundtrip,
    device_decide_is_atomic,
    device_decide_refuses_expired_and_decided,
    device_decided_is_consumed_once,
    device_poll_and_expiry,
)
"""Every case of the contract, in order."""
