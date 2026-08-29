"""Lifecycle coverage for SecuritySpyEventStream against a stubbed session.

The stub exists to make the timing-dependent constraints assertable: it can
deliver a record split across an arbitrary chunk boundary, go silent on demand,
fail a chosen number of connect attempts, or answer 401 -- none of which a real
server does to order.

Nothing here sleeps for real time. The heartbeat deadline and the backoff bounds
are constructor parameters, so the tests configure them in milliseconds and the
whole module runs in well under a second.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final, Self, cast

import aiohttp
import pytest

from aiosecurityspy import SecuritySpyEventStream, StreamEvent
from aiosecurityspy.connection import ConnectionSettings

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence
    from types import TracebackType

HOST = "nvr.example.com"
PORT = 8001
USERNAME = "sentinel-user-9d3f"
PASSWORD = "sentinel-pass-4a71"  # noqa: S105 - leak-detection sentinel, not a real credential

#: Heartbeat interval used throughout, in seconds. Three of these is the
#: silence deadline, so loss is declared ~30 ms after the socket goes quiet.
TICK: Final = 0.01

#: Upper bound on how long a test waits for a condition before failing. Only a
#: failure path ever waits this long.
PATIENCE: Final = 5.0

#: Sentinel chunk meaning "the socket goes silent here and never speaks again".
SILENCE: Final = object()

MOTION_RECORD: Final = b"20260809175335 0 7 MOTION 10 20 30 40\r"
NULL_RECORD: Final = b"20260809175336 1 X NULL\r"

#: The camera number the synthetic MOTION record carries.
CAMERA: Final = 7

#: Both records of a two-record chunk.
BOTH_RECORDS: Final = 2


class FakeContent:
    """Stand-in for ``response.content`` that hands out scripted chunks."""

    def __init__(self, chunks: Sequence[bytes | object]) -> None:
        """Store the script. A ``SILENCE`` entry never returns."""
        self._chunks = list(chunks)

    async def read(self, _limit: int = -1) -> bytes:
        """Return the next scripted chunk, or block forever on ``SILENCE``."""
        if not self._chunks:
            return b""  # end of stream
        chunk = self._chunks.pop(0)
        if chunk is SILENCE:
            # Long enough that only the heartbeat deadline can end the wait.
            await asyncio.sleep(3600)
        assert isinstance(chunk, bytes)
        return chunk


class FakeResponse:
    """Stand-in for a streaming aiohttp response."""

    def __init__(self, status: int, chunks: Sequence[bytes | object]) -> None:
        """Record the status and the scripted body."""
        self.status = status
        self.content = FakeContent(chunks)
        self.released = False

    async def __aenter__(self) -> Self:
        """Enter the response context, as aiohttp's own response does."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Record that the response was released on the way out."""
        self.released = True


class FakeSession:
    """Stand-in for ``aiohttp.ClientSession`` that scripts one attempt at a time."""

    def __init__(self, attempts: Iterable[FakeResponse | BaseException]) -> None:
        """Store one scripted outcome per connect attempt.

        The final entry repeats, so a stream that keeps retrying keeps getting
        the last outcome rather than exhausting the script.
        """
        self._attempts = list(attempts)
        self.calls: list[dict[str, object]] = []
        self.closed = False

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        """Return the next scripted response, or raise the next scripted error."""
        self.calls.append({"url": url, **kwargs})
        outcome = self._attempts[0] if len(self._attempts) == 1 else self._attempts.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def make_stream(  # noqa: PLR0913 - one keyword per lifecycle callback, mirroring the API under test
    session: FakeSession,
    *,
    on_event: Callable[[StreamEvent], None] | None = None,
    on_connected: Callable[[], None] | None = None,
    on_disconnected: Callable[[], None] | None = None,
    on_reconnected: Callable[[], None] | None = None,
    on_auth_failed: Callable[[], None] | None = None,
    max_record_bytes: int = 64,
) -> SecuritySpyEventStream:
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    return SecuritySpyEventStream(
        connection,
        on_event=on_event or (lambda _event: None),
        on_connected=on_connected,
        on_disconnected=on_disconnected,
        on_reconnected=on_reconnected,
        on_auth_failed=on_auth_failed,
        heartbeat_interval=TICK,
        backoff_initial=TICK,
        backoff_max=TICK,
        max_record_bytes=max_record_bytes,
    )


async def until(condition: Callable[[], bool]) -> None:
    """Yield to the loop until `condition` holds, failing rather than hanging.

    An `asyncio.Event` is the usual answer to this shape, but the conditions
    here are properties of the stream under test rather than signals it emits,
    so polling the loop is what actually observes them. `sleep(0)` yields
    without advancing the clock, so this costs no wall time.
    """
    async with asyncio.timeout(PATIENCE):
        while not condition():  # noqa: ASYNC110 - polling a property, not awaiting a signal
            await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_records_split_across_chunk_boundaries_reassemble() -> None:
    """A record cut mid-field by TCP must produce exactly one correct event."""
    events: list[StreamEvent] = []
    session = FakeSession([FakeResponse(200, [b"20260809175335 0 7 MOT", b"ION 10 20 30 40\r"])])
    stream = make_stream(session, on_event=events.append)

    await stream.connect()
    await until(lambda: len(events) == 1)
    await stream.disconnect()

    assert events[0].event_type == "MOTION"
    assert events[0].camera == CAMERA
    assert events[0].info == "10 20 30 40"


@pytest.mark.asyncio
async def test_multiple_records_in_one_chunk_are_all_delivered_in_order() -> None:
    events: list[StreamEvent] = []
    session = FakeSession([FakeResponse(200, [MOTION_RECORD + NULL_RECORD])])
    stream = make_stream(session, on_event=events.append)

    await stream.connect()
    await until(lambda: len(events) == BOTH_RECORDS)
    await stream.disconnect()

    assert [event.event_type for event in events] == ["MOTION", "NULL"]
    assert [event.camera for event in events] == [CAMERA, None]


@pytest.mark.asyncio
async def test_a_trailing_partial_record_is_discarded_not_half_decoded() -> None:
    session = FakeSession([FakeResponse(200, [MOTION_RECORD + b"20260809175336 1 X NU"])])
    events: list[StreamEvent] = []
    stream = make_stream(session, on_event=events.append)

    await stream.connect()
    await until(lambda: len(events) == 1)
    await stream.disconnect()

    assert [event.event_type for event in events] == ["MOTION"]


@pytest.mark.asyncio
async def test_an_over_long_unterminated_record_is_dropped_and_the_stream_continues() -> None:
    """No CR in sight means this is not the event stream; the buffer must not grow."""
    events: list[StreamEvent] = []
    # The dropped record's own tail arrives before the next separator. It must
    # be discarded too: resuming at an arbitrary byte would emit that tail as
    # though it were a whole record.
    session = FakeSession([FakeResponse(200, [b"x" * 500, b"tail-of-the-junk\r" + MOTION_RECORD])])
    stream = make_stream(session, on_event=events.append, max_record_bytes=64)

    await stream.connect()
    await until(lambda: len(events) == 1)
    await stream.disconnect()

    assert events[0].event_type == "MOTION"
    assert [event.raw for event in events] == [MOTION_RECORD.rstrip(b"\r").decode()]


@pytest.mark.asyncio
async def test_heartbeat_loss_fires_disconnected_exactly_once() -> None:
    """Socket silence past three heartbeats is a loss, and it is reported once."""
    losses = 0
    connects = 0

    def note_loss() -> None:
        nonlocal losses
        losses += 1

    def note_connect() -> None:
        nonlocal connects
        connects += 1

    session = FakeSession(
        [
            FakeResponse(200, [MOTION_RECORD, SILENCE]),
            # Every later attempt fails, so the only loss is the first one and
            # a second `disconnected` would be a real bug rather than a race.
            aiohttp.ClientConnectionError("refused"),
        ]
    )
    stream = make_stream(session, on_connected=note_connect, on_disconnected=note_loss)

    await stream.connect()
    await until(lambda: losses == 1)
    # Let several further backoff cycles run; none may report another loss.
    await until(lambda: len(session.calls) >= 4)  # noqa: PLR2004 - "several more attempts"
    await stream.disconnect()

    assert losses == 1
    assert connects == 1
    assert stream.connected is False


@pytest.mark.asyncio
async def test_a_reconnect_fires_reconnected_rather_than_connected() -> None:
    """`connected` marks the first success of the object's life, and only that."""
    order: list[str] = []
    session = FakeSession(
        [
            FakeResponse(200, [MOTION_RECORD]),  # ends -> lost connection
            FakeResponse(200, [NULL_RECORD, SILENCE]),
        ]
    )
    stream = make_stream(
        session,
        on_connected=lambda: order.append("connected"),
        on_disconnected=lambda: order.append("disconnected"),
        on_reconnected=lambda: order.append("reconnected"),
    )

    await stream.connect()
    await until(lambda: "reconnected" in order)
    await stream.disconnect()

    assert order[:3] == ["connected", "disconnected", "reconnected"]
    assert order.count("connected") == 1


@pytest.mark.asyncio
async def test_transport_failures_retry_indefinitely_and_never_raise() -> None:
    session = FakeSession([aiohttp.ClientConnectionError("refused")])
    stream = make_stream(session)

    await stream.connect()
    await until(lambda: len(session.calls) >= 5)  # noqa: PLR2004 - "keeps retrying"
    await stream.disconnect()

    assert stream.connected is False


@pytest.mark.asyncio
async def test_an_os_error_on_connect_is_also_retried() -> None:
    session = FakeSession([OSError("host is down")])
    stream = make_stream(session)

    await stream.connect()
    await until(lambda: len(session.calls) >= 3)  # noqa: PLR2004 - "keeps retrying"
    await stream.disconnect()


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.asyncio
async def test_auth_failure_fires_the_callback_and_pauses_reconnection(status: int) -> None:
    """AD-11/AD-18: the library pauses rather than hammering a rejected credential."""
    failures = 0

    def note_failure() -> None:
        nonlocal failures
        failures += 1

    session = FakeSession([FakeResponse(status, [])])
    stream = make_stream(session, on_auth_failed=note_failure)

    await stream.connect()
    await until(lambda: failures == 1)
    # Give the loop ample opportunity to retry. It must not.
    for _ in range(50):
        await asyncio.sleep(0)

    assert failures == 1
    assert len(session.calls) == 1
    assert stream.paused is True
    await stream.disconnect()


@pytest.mark.asyncio
async def test_resume_restarts_a_paused_stream() -> None:
    events: list[StreamEvent] = []
    session = FakeSession([FakeResponse(401, []), FakeResponse(200, [MOTION_RECORD, SILENCE])])
    stream = make_stream(session, on_event=events.append)

    await stream.connect()
    await until(lambda: stream.paused)
    await stream.resume()
    await until(lambda: len(events) == 1)

    assert stream.paused is False
    assert stream.connected is True
    await stream.disconnect()


@pytest.mark.asyncio
async def test_resume_before_a_pause_is_a_no_op() -> None:
    session = FakeSession([FakeResponse(200, [SILENCE])])
    stream = make_stream(session)

    await stream.resume()
    assert session.calls == []
    await stream.disconnect()


@pytest.mark.asyncio
async def test_connect_is_idempotent() -> None:
    session = FakeSession([FakeResponse(200, [SILENCE])])
    stream = make_stream(session)

    await stream.connect()
    await until(lambda: stream.connected)
    await stream.connect()
    await stream.connect()
    await asyncio.sleep(0)

    assert len(session.calls) == 1
    await stream.disconnect()


@pytest.mark.asyncio
async def test_disconnect_is_idempotent_and_leaves_nothing_behind() -> None:
    """FR-33: no task, timer, socket or pending response survives disconnect()."""
    before = asyncio.all_tasks()
    response = FakeResponse(200, [MOTION_RECORD, SILENCE])
    session = FakeSession([response])
    stream = make_stream(session)

    await stream.disconnect()  # before any connect: must be safe
    await stream.connect()
    await until(lambda: stream.connected)
    await stream.disconnect()
    await stream.disconnect()

    assert stream.connected is False
    assert response.released is True
    assert asyncio.all_tasks() == before


@pytest.mark.asyncio
async def test_disconnect_does_not_report_a_loss_the_caller_asked_for() -> None:
    losses = 0

    def note_loss() -> None:
        nonlocal losses
        losses += 1

    session = FakeSession([FakeResponse(200, [SILENCE])])
    stream = make_stream(session, on_disconnected=note_loss)

    await stream.connect()
    await until(lambda: stream.connected)
    await stream.disconnect()

    assert losses == 0


@pytest.mark.asyncio
async def test_reconnecting_after_an_explicit_disconnect_reports_a_reconnect() -> None:
    """AD-10: any gap needs reconciliation, so the second connect is a reconnect."""
    order: list[str] = []
    session = FakeSession([FakeResponse(200, [SILENCE]), FakeResponse(200, [SILENCE])])
    stream = make_stream(
        session,
        on_connected=lambda: order.append("connected"),
        on_reconnected=lambda: order.append("reconnected"),
    )

    await stream.connect()
    await until(lambda: order == ["connected"])
    await stream.disconnect()
    await stream.connect()
    await until(lambda: order == ["connected", "reconnected"])
    await stream.disconnect()


@pytest.mark.asyncio
async def test_a_raising_event_callback_is_swallowed_and_delivery_continues() -> None:
    seen: list[str] = []

    def explode(event: StreamEvent) -> None:
        seen.append(event.event_type)
        if len(seen) == 1:
            msg = "consumer bug"
            raise ValueError(msg)

    session = FakeSession([FakeResponse(200, [MOTION_RECORD + NULL_RECORD, SILENCE])])
    stream = make_stream(session, on_event=explode)

    await stream.connect()
    await until(lambda: len(seen) == BOTH_RECORDS)

    assert seen == ["MOTION", "NULL"]
    assert stream.connected is True
    await stream.disconnect()


@pytest.mark.asyncio
async def test_a_raising_lifecycle_callback_is_swallowed() -> None:
    events: list[StreamEvent] = []

    def explode() -> None:
        msg = "consumer bug"
        raise ValueError(msg)

    session = FakeSession([FakeResponse(200, [MOTION_RECORD, SILENCE])])
    stream = make_stream(session, on_connected=explode, on_event=events.append)

    await stream.connect()
    await until(lambda: len(events) == 1)

    assert stream.connected is True
    await stream.disconnect()


@pytest.mark.asyncio
async def test_async_callbacks_are_awaited() -> None:
    seen: list[str] = []

    async def on_event(event: StreamEvent) -> None:
        seen.append(event.event_type)

    async def on_connected() -> None:
        seen.append("connected")

    session = FakeSession([FakeResponse(200, [MOTION_RECORD, SILENCE])])
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    stream = SecuritySpyEventStream(
        connection,
        on_event=on_event,
        on_connected=on_connected,
        heartbeat_interval=TICK,
        backoff_initial=TICK,
        backoff_max=TICK,
    )

    await stream.connect()
    await until(lambda: seen == ["connected", "MOTION"])
    await stream.disconnect()


@pytest.mark.asyncio
async def test_the_stream_request_is_long_lived_but_bounded_on_connect() -> None:
    """A total timeout would tear down a healthy stream on a schedule."""
    session = FakeSession([FakeResponse(200, [SILENCE])])
    stream = make_stream(session)

    await stream.connect()
    await until(lambda: stream.connected)
    await stream.disconnect()

    call = session.calls[0]
    timeout = call["timeout"]
    assert isinstance(timeout, aiohttp.ClientTimeout)
    assert timeout.total is None
    assert timeout.sock_connect == 30.0  # noqa: PLR2004 - the library's default timeout
    assert call["url"] == f"http://{HOST}:{PORT}/++eventStream"
    assert call["params"] == {"version": "3"}
    assert call["allow_redirects"] is False
    assert call["ssl"] is True


@pytest.mark.asyncio
async def test_the_injected_session_is_never_closed() -> None:
    session = FakeSession([FakeResponse(200, [MOTION_RECORD])])
    stream = make_stream(session)

    await stream.connect()
    await stream.disconnect()

    assert session.closed is False


@pytest.mark.asyncio
async def test_the_credential_travels_as_basic_auth_never_in_the_url() -> None:
    """AD-13: the URL is credential-free and `repr` cannot leak either."""
    session = FakeSession([FakeResponse(200, [SILENCE])])
    stream = make_stream(session)

    await stream.connect()
    await until(lambda: stream.connected)
    await stream.disconnect()

    call = session.calls[0]
    assert PASSWORD not in str(call["url"])
    assert USERNAME not in str(call["url"])
    headers = cast("dict[str, str]", call["headers"])
    assert headers["Authorization"] == aiohttp.encode_basic_auth(USERNAME, PASSWORD)
    assert PASSWORD not in repr(stream)
    assert PASSWORD not in repr(
        ConnectionSettings.create(
            cast("aiohttp.ClientSession", session),
            HOST,
            PORT,
            username=USERNAME,
            password=PASSWORD,
        )
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"heartbeat_interval": 0},
        {"heartbeat_misses": 0},
        {"backoff_initial": -1.0},
        {"backoff_max": 0},
        {"max_record_bytes": 0},
    ],
)
def test_non_positive_tuning_is_rejected_at_construction(kwargs: dict[str, float]) -> None:
    session = FakeSession([])
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(ValueError, match="must be a positive, finite number"):
        SecuritySpyEventStream(connection, on_event=lambda _event: None, **kwargs)  # type: ignore[arg-type]  # one bad value per case


# --- Review regressions ----------------------------------------------------
# Each test below pins a defect the original implementation shipped with and
# the 256-test suite could not see.


def make_tuned_stream(
    session: FakeSession,
    *,
    on_event: Callable[[StreamEvent], None] | None = None,
    backoff_initial: float = 1.0,
    backoff_max: float = 100.0,
    backoff_multiplier: float = 2.0,
) -> SecuritySpyEventStream:
    """Build a stream whose backoff sequence is deterministic and observable."""
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    return SecuritySpyEventStream(
        connection,
        on_event=on_event or (lambda _event: None),
        heartbeat_interval=TICK,
        backoff_initial=backoff_initial,
        backoff_max=backoff_max,
        backoff_multiplier=backoff_multiplier,
        backoff_jitter=0.0,  # deterministic: the sequence is the assertion
    )


def record_delays(stream: SecuritySpyEventStream, delays: list[float]) -> None:
    """Replace the backoff sleep with a recorder that costs no wall time."""

    async def fake_sleep(seconds: float) -> None:
        delays.append(seconds)
        await asyncio.sleep(0)

    stream._sleep = fake_sleep  # type: ignore[method-assign]  # noqa: SLF001 - the timing seam under test


@pytest.mark.asyncio
async def test_backoff_grows_on_consecutive_failures() -> None:
    delays: list[float] = []
    session = FakeSession([aiohttp.ClientConnectionError("refused")])
    stream = make_tuned_stream(session)
    record_delays(stream, delays)

    await stream.connect()
    await until(lambda: len(delays) >= 4)  # noqa: PLR2004 - four spacings is enough to see growth
    await stream.disconnect()

    assert delays[:4] == [1.0, 2.0, 4.0, 8.0]


@pytest.mark.asyncio
async def test_backoff_is_capped_at_the_ceiling() -> None:
    delays: list[float] = []
    session = FakeSession([aiohttp.ClientConnectionError("refused")])
    stream = make_tuned_stream(session, backoff_max=4.0)
    record_delays(stream, delays)

    await stream.connect()
    await until(lambda: len(delays) >= 5)  # noqa: PLR2004 - past the point the ceiling binds
    await stream.disconnect()

    assert delays[:5] == [1.0, 2.0, 4.0, 4.0, 4.0]


@pytest.mark.asyncio
async def test_backoff_resets_after_a_successful_connection() -> None:
    """A server that drops the stream repeatedly must not creep up to the ceiling.

    Without the reset, `delay` only ever grows: ten healthy reconnects put the
    stream at the 300 s ceiling, where it stays for the life of the process.
    """
    delays: list[float] = []
    session = FakeSession(
        [
            aiohttp.ClientConnectionError("refused"),
            aiohttp.ClientConnectionError("refused"),
            FakeResponse(200, [MOTION_RECORD]),  # succeeds, then ends
            aiohttp.ClientConnectionError("refused"),
        ]
    )
    stream = make_tuned_stream(session)
    record_delays(stream, delays)

    await stream.connect()
    await until(lambda: len(delays) >= 4)  # noqa: PLR2004 - two failures, the success, then one more
    await stream.disconnect()

    # 1, 2 while failing; then the successful attempt returns the delay to 1.
    assert delays[:4] == [1.0, 2.0, 1.0, 2.0]


@pytest.mark.asyncio
async def test_disconnect_from_inside_a_callback_stops_exactly_one_reader() -> None:
    """`disconnect()` on the reader task cannot await itself.

    Awaiting would deadlock; suppressing the resulting CancelledError left the
    reader alive, after which a later `connect()` ran two concurrent readers
    against the same server.
    """
    before = asyncio.all_tasks()
    seen: list[str] = []
    stream: SecuritySpyEventStream | None = None
    # Held so the self-disconnect task is not garbage-collected mid-flight.
    _self_disconnects: set[asyncio.Task[None]] = set()

    def on_event(event: StreamEvent) -> None:
        seen.append(event.event_type)
        assert stream is not None
        # Self-disconnect: this callback runs *on* the reader task.
        _self_disconnects.add(asyncio.get_running_loop().create_task(stream.disconnect()))

    session = FakeSession(
        [FakeResponse(200, [MOTION_RECORD, SILENCE]), FakeResponse(200, [SILENCE])]
    )
    stream = make_stream(session, on_event=on_event)

    await stream.connect()
    await until(lambda: len(seen) == 1)
    await until(lambda: not stream.connected)
    await until(lambda: asyncio.all_tasks() == before)

    # One connect attempt happened, and the reader really is gone.
    assert len(session.calls) == 1

    # A later connect() must start exactly one new reader, not a second one
    # alongside a survivor.
    await stream.connect()
    await until(lambda: stream.connected)
    assert len(session.calls) == 2  # noqa: PLR2004 - one per connect, never two per connect
    await stream.disconnect()
    assert asyncio.all_tasks() == before


@pytest.mark.asyncio
async def test_a_slow_auth_handler_cannot_be_raced_into_a_second_reader() -> None:
    """`_task` must stay awaitable until the auth handler has actually finished."""
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_auth_handler() -> None:
        entered.set()
        await release.wait()

    session = FakeSession([FakeResponse(401, []), FakeResponse(200, [SILENCE])])
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    stream = SecuritySpyEventStream(
        connection,
        on_event=lambda _event: None,
        on_auth_failed=slow_auth_handler,
        heartbeat_interval=TICK,
        backoff_initial=TICK,
        backoff_max=TICK,
    )

    await stream.connect()
    await entered.wait()
    # The handler is mid-flight. A resume() arriving now must not start a
    # second reader alongside the one still running the handler.
    resuming = asyncio.get_running_loop().create_task(stream.resume())
    await asyncio.sleep(0)
    release.set()
    await resuming
    await until(lambda: stream.connected)

    assert len(session.calls) == 2  # noqa: PLR2004 - the 401, then the resumed attempt
    await stream.disconnect()


@pytest.mark.asyncio
async def test_concurrent_lifecycle_calls_are_serialized() -> None:
    """Interleaved connect/disconnect must not leave a reader behind a False flag."""
    before = asyncio.all_tasks()
    session = FakeSession([FakeResponse(200, [SILENCE])])
    stream = make_stream(session)

    await asyncio.gather(
        stream.connect(),
        stream.connect(),
        stream.disconnect(),
        stream.connect(),
        stream.disconnect(),
    )
    await asyncio.sleep(0)

    # Whatever the interleaving, the reported state and the real state agree.
    assert stream.connected is False
    assert asyncio.all_tasks() == before


@pytest.mark.asyncio
async def test_connect_declines_while_paused_and_only_resume_reopens_it() -> None:
    """AD-18: an auth pause has exactly one door out of it."""
    session = FakeSession([FakeResponse(401, []), FakeResponse(200, [SILENCE])])
    stream = make_stream(session)

    await stream.connect()
    await until(lambda: stream.paused)

    await stream.connect()
    await asyncio.sleep(0)
    assert len(session.calls) == 1
    assert stream.paused is True

    await stream.resume()
    await until(lambda: stream.connected)
    assert len(session.calls) == 2  # noqa: PLR2004 - the 401, then the resumed attempt
    await stream.disconnect()


@pytest.mark.asyncio
async def test_a_pause_survives_disconnect() -> None:
    """Disconnecting must not discard the "credentials were rejected" signal."""
    session = FakeSession([FakeResponse(401, [])])
    stream = make_stream(session)

    await stream.connect()
    await until(lambda: stream.paused)
    await stream.disconnect()

    assert stream.paused is True
    await stream.connect()
    await asyncio.sleep(0)
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_the_read_buffer_never_exceeds_the_configured_cap() -> None:
    """The cap is a promise about memory, so the read size respects it too."""
    session = FakeSession([FakeResponse(200, [SILENCE])])
    stream = make_stream(session, max_record_bytes=128)
    reads: list[int] = []

    original = FakeContent.read

    async def spy(self: FakeContent, limit: int = -1) -> bytes:
        reads.append(limit)
        return await original(self, limit)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(FakeContent, "read", spy)
        await stream.connect()
        await until(lambda: len(reads) >= 1)
        await stream.disconnect()

    assert reads[0] == 128  # noqa: PLR2004 - the configured cap, not the 64 KiB default


@pytest.mark.parametrize(
    "kwargs",
    [
        {"heartbeat_interval": float("nan")},
        {"backoff_initial": float("nan")},
        {"backoff_max": float("inf")},
    ],
)
def test_non_finite_tuning_is_rejected_at_construction(kwargs: dict[str, float]) -> None:
    """NaN passes every `<= 0` check and then fails inside the event loop."""
    session = FakeSession([])
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(ValueError, match="must be a positive, finite number"):
        SecuritySpyEventStream(connection, on_event=lambda _event: None, **kwargs)  # type: ignore[arg-type]  # one bad value per case


@pytest.mark.parametrize("jitter", [1.0, -0.1, float("nan")])
def test_an_out_of_range_jitter_fraction_is_rejected(jitter: float) -> None:
    session = FakeSession([])
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(ValueError, match="finite fraction"):
        SecuritySpyEventStream(connection, on_event=lambda _event: None, backoff_jitter=jitter)


@pytest.mark.asyncio
async def test_jitter_only_ever_shortens_a_delay() -> None:
    delays: list[float] = []
    session = FakeSession([aiohttp.ClientConnectionError("refused")])
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    stream = SecuritySpyEventStream(
        connection,
        on_event=lambda _event: None,
        heartbeat_interval=TICK,
        backoff_initial=1.0,
        backoff_max=1.0,
        backoff_jitter=0.25,
    )
    record_delays(stream, delays)

    await stream.connect()
    await until(lambda: len(delays) >= 20)  # noqa: PLR2004 - enough samples to see the spread
    await stream.disconnect()

    floor = 1.0 - 0.25  # backoff_initial less the full jitter fraction
    assert all(floor <= delay <= 1.0 for delay in delays)
    assert len(set(delays)) > 1, "a fixed delay would mean the jitter is not applied"
