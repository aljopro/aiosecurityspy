"""The SecuritySpy event-stream client: framing, heartbeat, backoff (AD-11).

The whole stream lifecycle lives in the library rather than in each consumer:
CR-only framing, a socket-silence watchdog, indefinite exponential backoff, and
four explicit lifecycle callbacks. A consumer supplies callbacks and calls
:meth:`SecuritySpyEventStream.connect` and
:meth:`~SecuritySpyEventStream.disconnect`; it never sees a socket, a retry
counter, or a raw line.

No exception escapes this module. Transport failures become backoff, and a
consumer callback that raises is logged and swallowed so one bad handler cannot
take the stream down with it.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import math
import random
from datetime import UTC
from typing import TYPE_CHECKING, Final

import aiohttp

from .const import (
    BACKOFF_INITIAL,
    BACKOFF_JITTER,
    BACKOFF_MAX,
    BACKOFF_MULTIPLIER,
    ENDPOINT_EVENT_STREAM,
    EVENT_STREAM_VERSION,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_MISSES_BEFORE_LOSS,
    STREAM_MAX_RECORD_BYTES,
)
from .events import parse_event_line

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from datetime import tzinfo

    from .connection import ConnectionSettings
    from .events import StreamEvent

__all__ = ["EventCallback", "LifecycleCallback", "SecuritySpyEventStream"]

_LOGGER: Final = logging.getLogger(__name__)

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_OK_MIN: Final = 200
_HTTP_OK_MAX: Final = 299

#: Record separator. CR (0x0D) **only** -- the stream contains zero LF bytes
#: (research §3.1), which is why this module frames records itself: any
#: line-oriented reader waiting on an LF would simply never return.
_RECORD_SEPARATOR: Final = b"\r"

#: Bytes requested per read. Only an upper bound: aiohttp returns whatever has
#: arrived, which is exactly the incremental behaviour a live stream needs.
_READ_CHUNK_BYTES: Final = 64 * 1024

#: Callback invoked with each decoded event.
type EventCallback = Callable[[StreamEvent], Awaitable[None] | None]

#: Callback invoked for a lifecycle transition. It takes no arguments so a
#: consumer cannot come to depend on transport details leaking through it.
type LifecycleCallback = Callable[[], Awaitable[None] | None]


class _AuthFailureError(Exception):
    """Internal signal: the server rejected the credentials (401/403).

    Never escapes this module. It exists so the read path can unwind to the
    retry loop, which then pauses instead of retrying (AD-11 + AD-18).
    """


class SecuritySpyEventStream:
    """A self-managing reader of ``++eventStream?version=3``.

    Construct one through :meth:`~aiosecurityspy.SecuritySpyClient.event_stream`
    rather than directly: the client already holds the validated transport
    state this object needs.

    Lifecycle:

    - ``connected`` fires on the first successful connect of this object's life.
    - ``reconnected`` fires on every later successful connect. A consumer
      ``disconnect()``/``connect()`` pair therefore also yields ``reconnected``,
      which is correct: the consumer must reconcile after any gap (AD-10).
    - ``disconnected`` fires exactly once per lost connection.
    - ``auth_failed`` fires on 401/403, after which reconnection **pauses**
      until :meth:`resume` is called. The library never re-authenticates and
      never counts auth failures (AD-18).
    """

    def __init__(  # noqa: PLR0913 - four independent lifecycle callbacks plus tuning; all keyword-only
        self,
        connection: ConnectionSettings,
        *,
        on_event: EventCallback,
        on_connected: LifecycleCallback | None = None,
        on_disconnected: LifecycleCallback | None = None,
        on_reconnected: LifecycleCallback | None = None,
        on_auth_failed: LifecycleCallback | None = None,
        server_timezone: tzinfo = UTC,
        heartbeat_interval: float = HEARTBEAT_INTERVAL,
        heartbeat_misses: int = HEARTBEAT_MISSES_BEFORE_LOSS,
        backoff_initial: float = BACKOFF_INITIAL,
        backoff_max: float = BACKOFF_MAX,
        backoff_multiplier: float = BACKOFF_MULTIPLIER,
        backoff_jitter: float = BACKOFF_JITTER,
        max_record_bytes: int = STREAM_MAX_RECORD_BYTES,
    ) -> None:
        """Create a stream bound to one validated connection.

        Args:
            connection: Validated transport state, shared with the client.
            on_event: Called with every decoded event. May be sync or async.
            on_connected: Called once, on the first-ever successful connect.
            on_disconnected: Called once per lost connection.
            on_reconnected: Called on every successful connect after the first.
            on_auth_failed: Called when the server answers 401 or 403.
            server_timezone: Timezone of the server's wall-clock timestamps.
                **[ASSUMPTION]** No endpoint exposes it, so this defaults to
                UTC; see :func:`~aiosecurityspy.parse_event_line`.
            heartbeat_interval: Expected seconds between ``NULL`` heartbeats.
            heartbeat_misses: Heartbeats missed before the connection is
                declared lost. The product of the two is the silence deadline.
            backoff_initial: First reconnect delay, in seconds. The delay
                returns to this value after every successful connection, so a
                server that drops the stream periodically does not creep up to
                the ceiling and stay there.
            backoff_max: Ceiling on the reconnect delay, in seconds.
            backoff_multiplier: Growth factor applied after each *consecutive*
                failed attempt.
            backoff_jitter: Fraction of the delay removed at random, in
                ``[0, 1)``. Zero makes the delay sequence deterministic.
            max_record_bytes: Cap on one unterminated record before the read
                buffer is dropped.

        Raises:
            ValueError: A tuning value is not a positive, finite number, or
                the jitter fraction is outside ``[0, 1)``. These are caller
                mistakes and surface immediately rather than as a stream that
                silently never reconnects.

        """
        for label, value in (
            ("heartbeat_interval", heartbeat_interval),
            ("heartbeat_misses", heartbeat_misses),
            ("backoff_initial", backoff_initial),
            ("backoff_max", backoff_max),
            ("backoff_multiplier", backoff_multiplier),
            ("max_record_bytes", max_record_bytes),
        ):
            # `isfinite` as well as `> 0`, because NaN passes every comparison:
            # a NaN silence deadline reaches `asyncio.timeout()` and fails deep
            # inside the event loop rather than here, at the caller's mistake.
            if not math.isfinite(value) or value <= 0:
                msg = f"{label} must be a positive, finite number"
                raise ValueError(msg)
        if not math.isfinite(backoff_jitter) or not 0 <= backoff_jitter < 1:
            msg = "backoff_jitter must be a finite fraction in [0, 1)"
            raise ValueError(msg)

        self._connection = connection
        self._on_event = on_event
        self._on_connected = on_connected
        self._on_disconnected = on_disconnected
        self._on_reconnected = on_reconnected
        self._on_auth_failed = on_auth_failed
        self._server_timezone = server_timezone
        self._silence_timeout = heartbeat_interval * heartbeat_misses
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._backoff_multiplier = backoff_multiplier
        self._backoff_jitter = backoff_jitter
        self._max_record_bytes = max_record_bytes

        self._task: asyncio.Task[None] | None = None
        # An Event rather than a bool because the reader checks it after every
        # await, and a plain attribute would let a type checker assume it
        # cannot have changed across those suspension points.
        self._stopping = asyncio.Event()
        self._connected = False
        self._ever_connected = False
        self._paused = False
        # Serializes connect/disconnect/resume. Without it two coroutines can
        # interleave between the "is a reader running?" check and the
        # create_task that answers it, leaving a live reader behind a
        # `connected` property that reports False.
        self._lifecycle_lock = asyncio.Lock()

    @property
    def connected(self) -> bool:
        """Whether the stream currently holds a live response."""
        return self._connected

    @property
    def paused(self) -> bool:
        """Whether reconnection is paused awaiting :meth:`resume` after a 401/403."""
        return self._paused

    async def connect(self) -> None:
        """Start reading the event stream, retrying until it succeeds.

        Idempotent: calling it while the reader is already running does
        nothing. It returns as soon as the reader task is scheduled rather than
        waiting for the first successful connection, because backoff is
        indefinite (AD-11) and a caller that waited could wait forever. Use
        ``on_connected`` to learn when the stream is live.

        Declines while the stream is paused by an authentication failure: only
        :meth:`resume` reopens that door, so a consumer cannot accidentally
        restart a rejected credential through the ordinary entry point
        (AD-18).
        """
        async with self._lifecycle_lock:
            if self._paused:
                _LOGGER.debug(
                    "Event stream is paused after an authentication failure; "
                    "call resume() to restart it"
                )
                return
            self._start()

    async def disconnect(self) -> None:
        """Stop reading and release everything this object owns.

        Idempotent, including before any :meth:`connect`. On return no task,
        timer, socket or pending response remains (FR-33). The caller's session
        is untouched: it is not this library's to close.

        Safe to call from inside a consumer callback, which runs *on the reader
        task*: the reader cannot await its own completion, so in that case the
        cancellation is requested and unwinds as the callback returns.

        ``on_disconnected`` is deliberately **not** fired here -- it reports a
        *lost* connection, and the caller who asked for this one to end already
        knows. A pause caused by an authentication failure survives: the
        credential is still rejected, and forgetting that here would let a
        later ``connect()`` walk straight back into it.
        """
        async with self._lifecycle_lock:
            self._stopping.set()
            task = self._task
            if task is None:
                self._connected = False
                return
            if not task.done():
                task.cancel()
            if task is asyncio.current_task():
                # Called from a consumer callback, so this *is* the reader.
                # Awaiting it would deadlock, and suppressing the resulting
                # CancelledError would leave the reader alive -- after which a
                # later connect() would start a second one. Let the cancellation
                # unwind naturally instead, and leave `_task` in place so
                # connect() can see it is not finished yet.
                self._connected = False
                return
            # Awaiting is what makes "no task remains" true rather than merely
            # requested: cancel() only schedules the cancellation.
            with contextlib.suppress(asyncio.CancelledError):
                await task
            self._task = None
            self._connected = False

    async def resume(self) -> None:
        """Resume reconnection after an authentication failure paused it.

        The consumer calls this once it believes the credentials will work --
        after the user corrects them, for instance. The library never decides
        that for itself (AD-18). A no-op unless the stream is paused.
        """
        async with self._lifecycle_lock:
            if not self._paused:
                return
            self._paused = False
            # A pause is only ever set on the reader's way out, so the task
            # still referenced here is already terminating -- it may just be
            # part-way through a slow `on_auth_failed` handler. Waiting for it
            # is what stops the restart below from becoming a second reader
            # running alongside the first.
            task = self._task
            if task is not None and not task.done() and task is not asyncio.current_task():
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if self._task is task:
                self._task = None
            self._start()

    def _start(self) -> None:
        """Create the reader task if one is not already running.

        Called only with the lifecycle lock held. `_task` is never cleared by
        the reader itself, so a finished task is still visible here and the
        "is one running?" question is answered by `done()` alone.
        """
        task = self._task
        if task is not None and not task.done():
            # Includes the re-entrant case, where a consumer callback calls
            # connect() on the very task it is running on.
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="aiosecurityspy-event-stream")

    async def _run(self) -> None:
        """Own the connect/read/backoff cycle for the object's whole life."""
        delay = self._backoff_initial
        while not self._stopping.is_set():
            try:
                await self._read_stream()
            except asyncio.CancelledError:
                raise
            except _AuthFailureError:
                # Pause rather than loop: retrying a rejected credential just
                # locks the account out, and only the consumer can fix it.
                # `_task` is deliberately not cleared here: this coroutine is
                # still running, and a disconnect() or resume() arriving during
                # a slow async handler must still find something to await
                # rather than starting a second reader.
                self._paused = True
                await self._invoke(self._on_auth_failed)
                return
            except Exception as err:  # noqa: BLE001 - a long-lived reader must survive anything the transport raises
                _LOGGER.debug("Event stream attempt failed: %s", type(err).__name__)
            else:
                # A stream that ends without error is still a lost connection.
                _LOGGER.debug("Event stream ended")
            # Read before `_mark_disconnected` clears it. Backoff exists to
            # space out *consecutive* failures; a connection that worked and
            # then dropped proves the server is reachable, so the next attempt
            # starts from the initial delay again. Without this reset, a server
            # that drops the stream every few minutes climbs to the ceiling and
            # never comes back down.
            reached_the_server = self._connected
            await self._mark_disconnected()
            if self._stopping.is_set():
                return
            if reached_the_server:
                delay = self._backoff_initial
            await self._sleep(self._next_delay(delay))
            delay = min(delay * self._backoff_multiplier, self._backoff_max)

    def _next_delay(self, delay: float) -> float:
        """Apply jitter so every client does not return in lockstep after a restart."""
        if not self._backoff_jitter:
            return delay
        # Not a security decision: this is retry spacing, not a secret.
        return delay * (1.0 - self._backoff_jitter * random.random())  # noqa: S311 - retry jitter, not cryptography

    async def _sleep(self, seconds: float) -> None:
        """Wait out one backoff delay.

        A seam of its own so a test can observe the delay sequence without
        waiting on wall time; the reader has no other reason to sleep.
        """
        await asyncio.sleep(seconds)

    async def _read_stream(self) -> None:
        """Open one stream response and read it until it fails or ends.

        Raises:
            _AuthFailureError: The server answered 401 or 403.
            aiohttp.ClientError: Any transport failure, including a non-2xx
                status; the caller turns it into backoff.
            TimeoutError: The socket went silent past the heartbeat deadline.

        """
        url = self._connection.build_url(ENDPOINT_EVENT_STREAM)
        _LOGGER.debug("Opening event stream on %s:%s", self._connection.host, self._connection.port)
        async with self._connection.session.get(
            url,
            params={"version": EVENT_STREAM_VERSION},
            headers={"Authorization": self._connection.auth_header},
            ssl=self._connection.verify_ssl,
            # No total timeout: this response is designed never to end. The
            # connect phase stays bounded so a wrong host still fails fast, and
            # liveness is enforced by the per-read heartbeat deadline below.
            timeout=self._connection.stream_timeout(),
            # A different port is a different origin, so aiohttp strips the
            # Authorization header across SecuritySpy's HTTP-to-HTTPS redirect;
            # following it would turn a wrong-scheme mistake into a 401 that
            # blames the user's password.
            allow_redirects=False,
        ) as response:
            if response.status in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
                raise _AuthFailureError
            if not _HTTP_OK_MIN <= response.status <= _HTTP_OK_MAX:
                msg = f"event stream returned HTTP {response.status}"
                raise aiohttp.ClientResponseError(
                    response.request_info, response.history, status=response.status, message=msg
                )
            await self._mark_connected()
            await self._consume(response.content)

    async def _consume(self, content: aiohttp.StreamReader) -> None:
        """Read bytes, split them on CR, and deliver each complete record.

        Raises:
            TimeoutError: No byte arrived within the heartbeat deadline. Any
                traffic resets it, so a busy camera proves liveness just as
                well as a ``NULL`` heartbeat does (research §3.5).

        """
        buffer = bytearray()
        # True while the tail of a dropped over-long record is still arriving.
        # Resuming at an arbitrary byte would emit that tail as if it were a
        # whole record, so everything up to the next separator is discarded.
        resyncing = False
        # Never ask for more than the cap in one go, so a single read cannot
        # carry the buffer far past the size the cap promises.
        read_size = min(_READ_CHUNK_BYTES, self._max_record_bytes)
        while True:
            # The watchdog is a deadline on each read rather than a timer
            # counting NULL records: three missed heartbeats' worth of total
            # socket silence is the loss condition (AD-11).
            async with asyncio.timeout(self._silence_timeout):
                chunk = await content.read(read_size)
            if not chunk:
                # The server closed the stream. Whatever is still buffered is a
                # partial record by definition and is dropped rather than
                # emitted half-decoded.
                if buffer:
                    _LOGGER.debug("Discarding %d buffered bytes at stream end", len(buffer))
                return
            buffer += chunk
            while (index := buffer.find(_RECORD_SEPARATOR)) != -1:
                record = bytes(buffer[:index])
                del buffer[: index + 1]
                if resyncing:
                    _LOGGER.debug("Discarding %d bytes of an over-long record", len(record))
                    resyncing = False
                    continue
                await self._deliver(record)
            if len(buffer) > self._max_record_bytes:
                # No separator in sight and the partial record is past the cap:
                # this is not the event stream. Drop it rather than growing
                # without bound, and stay out of sync until the next separator
                # gives a real record boundary to restart from.
                _LOGGER.debug("Dropping %d unterminated buffered bytes", len(buffer))
                buffer.clear()
                resyncing = True

    async def _deliver(self, record: bytes) -> None:
        """Decode one framed record and hand it to the consumer."""
        # `errors="replace"`: a camera named with a mangled byte must not end a
        # stream that is otherwise healthy. A stray LF is stripped defensively
        # -- the research says there are none, but a future server build adding
        # CRLF must not produce empty or leading-newline records.
        text = record.decode("utf-8", errors="replace").strip("\n")
        if not text:
            return
        event = parse_event_line(text, server_timezone=self._server_timezone)
        if event is None:
            return
        await self._invoke_event(event)

    async def _mark_connected(self) -> None:
        """Record a live connection and fire ``connected`` or ``reconnected``."""
        self._connected = True
        if self._ever_connected:
            await self._invoke(self._on_reconnected)
        else:
            self._ever_connected = True
            await self._invoke(self._on_connected)

    async def _mark_disconnected(self) -> None:
        """Fire ``disconnected`` exactly once per lost connection."""
        if not self._connected:
            return
        self._connected = False
        await self._invoke(self._on_disconnected)

    async def _invoke(self, callback: LifecycleCallback | None) -> None:
        """Call a lifecycle callback, tolerating both sync and async handlers."""
        if callback is None:
            return
        try:
            result = callback()
            if inspect.isawaitable(result):
                await result
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Event stream lifecycle callback raised")

    async def _invoke_event(self, event: StreamEvent) -> None:
        """Call the event callback, tolerating both sync and async handlers."""
        try:
            result = self._on_event(event)
            if inspect.isawaitable(result):
                await result
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Event stream callback raised for a %s event", event.event_type)

    def __repr__(self) -> str:
        """Return a representation that cannot leak credentials."""
        return (
            f"SecuritySpyEventStream(host={self._connection.host!r}, "
            f"port={self._connection.port}, connected={self._connected}, "
            f"paused={self._paused})"
        )

    __str__ = __repr__
