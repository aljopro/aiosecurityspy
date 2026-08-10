"""Event stream exercised against a real in-process ``aiohttp`` server.

The stubbed lifecycle tests prove the stream's own logic, but they cannot prove
that CR-only framing survives real HTTP chunking, real transfer encoding, and
the installed ``aiohttp``'s own buffering -- which is precisely where a client
that assumed LF termination would hang. This module closes that gap by serving
the recorded fixture, byte for byte, from a real server.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Final

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer as AiohttpTestServer  # aliased: pytest collects `Test*`

from aiosecurityspy import SecuritySpyClient, SecuritySpyEventStream

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from aiosecurityspy import StreamEvent

FIXTURE: Final = Path(__file__).parent / "fixtures" / "event_stream.bin"

USERNAME = "viewer"
PASSWORD = "sentinel-pass-live"  # noqa: S105 - leak-detection sentinel, not a real credential

#: Heartbeat interval used throughout, in seconds; three of these is the
#: silence deadline. Small enough that nothing in this module waits on wall time.
TICK: Final = 0.02

PATIENCE: Final = 5.0


@pytest_asyncio.fixture
async def stream_server() -> AsyncIterator[AiohttpTestServer]:
    """Serve the recorded fixture as a chunked, CR-framed event stream.

    The fixture is written in deliberately awkward slices so a record boundary
    falls mid-chunk, and each slice is flushed separately: this is the real
    chunking a stub cannot reproduce.
    """

    async def handle_stream(request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse()
        await response.prepare(request)
        raw = FIXTURE.read_bytes()
        step = 37  # coprime with the record lengths, so boundaries land mid-record
        for start in range(0, len(raw), step):
            await response.write(raw[start : start + step])
            await asyncio.sleep(0)
        # Hold the response open: the event stream is a response that never
        # ends, and closing it immediately would test the wrong thing.
        await asyncio.sleep(PATIENCE)
        return response

    async def handle_unauthorized(_: web.Request) -> web.Response:
        return web.Response(status=401)

    app = web.Application()
    app.router.add_get("/++eventStream", handle_stream)
    app.router.add_get("/++systemInfo", handle_unauthorized)
    server = AiohttpTestServer(app)
    await server.start_server()
    try:
        yield server
    finally:
        await server.close()


def make_client(session: aiohttp.ClientSession, server: AiohttpTestServer) -> SecuritySpyClient:
    return SecuritySpyClient(
        session,
        "127.0.0.1",
        server.port or 0,
        username=USERNAME,
        password=PASSWORD,
        timeout=5.0,
    )


async def until(condition: Callable[[], bool]) -> None:
    """Yield to the loop until `condition` holds, failing rather than hanging.

    The conditions are properties of the stream under test rather than signals
    it emits, so polling the loop is what actually observes them.
    """
    async with asyncio.timeout(PATIENCE):
        while not condition():  # noqa: ASYNC110 - polling a property, not awaiting a signal
            await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_real_cr_framing_survives_real_chunking(stream_server: AiohttpTestServer) -> None:
    """The whole point of the module: no LF byte exists, and nothing hangs."""
    assert b"\n" not in FIXTURE.read_bytes()
    events: list[StreamEvent] = []

    async with aiohttp.ClientSession() as session:
        stream = make_client(session, stream_server).event_stream(on_event=events.append)
        await stream.connect()
        await until(lambda: len(events) == 14)  # noqa: PLR2004 - 15 records, one malformed
        await stream.disconnect()
        assert session.closed is False

    assert [event.event_number for event in events] == list(range(14))
    assert [event.event_type for event in events][:3] == ["MOTION", "CLASSIFY", "TRIGGER_M"]
    # The `X` record survived the real transport as "not camera-specific".
    assert any(event.camera is None and event.event_type == "NULL" for event in events)
    # The `FILE` path kept its embedded spaces across the chunk boundaries.
    file_event = next(event for event in events if event.event_type == "FILE")
    assert file_event.info == "/Volumes/Cam/2026-08-09/Front Door 01.m4v"


@pytest.mark.asyncio
async def test_real_lifecycle_callbacks_fire_over_a_real_socket(
    stream_server: AiohttpTestServer,
) -> None:
    order: list[str] = []
    events: list[StreamEvent] = []

    async with aiohttp.ClientSession() as session:
        stream = make_client(session, stream_server).event_stream(
            on_event=events.append,
            on_connected=lambda: order.append("connected"),
            on_disconnected=lambda: order.append("disconnected"),
            on_reconnected=lambda: order.append("reconnected"),
        )
        await stream.connect()
        await until(lambda: len(events) == 14)  # noqa: PLR2004 - the whole fixture
        assert stream.connected is True
        await stream.disconnect()

    assert order == ["connected"]


@pytest.mark.asyncio
async def test_real_401_fires_auth_failed_and_pauses_reconnection() -> None:
    """A real 401 must pause the retry loop rather than hammering the server."""
    attempts = 0
    failures = 0

    async def handle(_: web.Request) -> web.Response:
        nonlocal attempts
        attempts += 1
        return web.Response(status=401)

    def note_failure() -> None:
        nonlocal failures
        failures += 1

    app = web.Application()
    app.router.add_get("/++eventStream", handle)
    server = AiohttpTestServer(app)
    await server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            stream = make_client(session, server).event_stream(
                on_event=lambda _event: None, on_auth_failed=note_failure
            )
            await stream.connect()
            await until(lambda: failures == 1)
            await asyncio.sleep(0.05)  # ample time for a retry that must not happen
            assert stream.paused is True
            await stream.disconnect()
    finally:
        await server.close()

    assert attempts == 1
    assert failures == 1


@pytest.mark.asyncio
async def test_real_server_error_is_retried_rather_than_raised() -> None:
    """A non-2xx status is a transport failure: backoff, never an exception."""
    attempts = 0

    async def handle(_: web.Request) -> web.Response:
        nonlocal attempts
        attempts += 1
        return web.Response(status=500)

    app = web.Application()
    app.router.add_get("/++eventStream", handle)
    server = AiohttpTestServer(app)
    await server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            connection = make_client(session, server)._connection  # noqa: SLF001 - tuning the heartbeat needs the seam
            stream = SecuritySpyEventStream(
                connection,
                on_event=lambda _event: None,
                heartbeat_interval=TICK,
                backoff_initial=TICK,
                backoff_max=TICK,
            )
            await stream.connect()
            await until(lambda: attempts >= 3)  # noqa: PLR2004 - "keeps retrying"
            await stream.disconnect()
    finally:
        await server.close()

    assert stream.connected is False


@pytest.mark.asyncio
async def test_real_heartbeat_loss_is_declared_on_a_silent_socket() -> None:
    """Socket silence, not `NULL` counting, is what declares a loss."""
    losses = 0
    connects = 0

    async def handle(request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b"20260809175335 0 7 MOTION_END\r")
        await asyncio.sleep(PATIENCE)  # then say nothing at all
        return response

    app = web.Application()
    app.router.add_get("/++eventStream", handle)
    server = AiohttpTestServer(app)
    await server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            connection = make_client(session, server)._connection  # noqa: SLF001 - tuning the heartbeat needs the seam

            def note_loss() -> None:
                nonlocal losses
                losses += 1

            def note_connect() -> None:
                nonlocal connects
                connects += 1

            stream = SecuritySpyEventStream(
                connection,
                on_event=lambda _event: None,
                on_connected=note_connect,
                on_disconnected=note_loss,
                heartbeat_interval=TICK,
                backoff_initial=TICK,
                backoff_max=TICK,
            )
            await stream.connect()
            await until(lambda: losses >= 1)
            await stream.disconnect()
    finally:
        await server.close()

    assert connects == 1
    assert losses >= 1
