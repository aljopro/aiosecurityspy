"""The library's two standing credential claims, executed rather than asserted in prose.

Story 1.7 does not repair the way credentials are handled -- they already travel
as an ``auth=`` kwarg, out of every URL, and settings payloads are already never
logged. What it does is make those claims *run*: a full session drives every
public request path, healthy and failing, with the whole ``aiosecurityspy``
logger tree captured at level 0, and every URL the library builds or sends is
checked for userinfo and credential-shaped parameters.

Self-contained by house rule: there is no ``conftest.py``, so the stub server
lives here. It serves the real recorded shapes for every endpoint at once,
because a sweep that only exercised one of them would not be a sweep.
"""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
from base64 import b64encode
from datetime import date
from typing import TYPE_CHECKING, Any, Final, Self, cast
from urllib.parse import parse_qsl, quote, urlsplit

import aiohttp
import pytest

import aiosecurityspy
from aiosecurityspy import (
    ARM_OVERRIDE_ARMED_2_HOURS,
    ENDPOINT_CAPTURE_LIST,
    ENDPOINT_EVENT_STREAM,
    ENDPOINT_SETTINGS_CAMERAS,
    ENDPOINT_SYSTEM_INFO,
    CameraSettingsPatch,
    CaptureModes,
    SecuritySpyClient,
    SecuritySpyError,
    is_credential_key,
)
from aiosecurityspy.connection import ConnectionSettings

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType

HOST: Final = "nvr.example.com"
PORT: Final = 8001

#: The *connection* credential, held by the client and the stream.
USERNAME: Final = "sentinel-user-9d3f"
PASSWORD: Final = "sentinel-pass-4a71"  # noqa: S105 - leak-detection sentinel, not a real credential

#: The *device* credential the settings page carries in plaintext (research §8.3).
#: Distinct from the connection credential so a failure says which one leaked.
DEVICE_USERNAME: Final = "device-user-77f1"
DEVICE_PASSWORD: Final = "device-pass-22b9"  # noqa: S105 - leak-detection sentinel, not a real credential

#: An ordinary, non-credential settings value. It is on this list because the
#: rule is that the settings *payload* is never logged -- not merely the two
#: fields of it that happen to be passwords.
PAYLOAD_MARKER: Final = "payload-marker-5c0e"

#: Everything that must never appear in a log line, an exception or a URL.
SENTINELS: Final = (USERNAME, PASSWORD, DEVICE_USERNAME, DEVICE_PASSWORD, PAYLOAD_MARKER)

CAMERA: Final = 3
DAY: Final = date(2026, 8, 9)

#: The floor the log sweep must clear before its "nothing leaked" search means
#: anything. The three phases together emit 21 at the time of writing, so the
#: guard survives an ordinary logging change while still failing loudly if the
#: library ever goes quiet and the search runs over an empty haystack -- which a
#: bare ``caplog.text.strip()`` would not, since one stray line satisfies it.
MINIMUM_DEBUG_RECORDS: Final = 12

#: Every endpoint constant the package exports, ``ENDPOINT_PREFIX`` aside. Named
#: exactly rather than counted: a ``>= 2`` guard would pass with four of the five
#: gone from ``__all__`` and the URL claim silently untested for them.
EXPECTED_ENDPOINT_NAMES: Final = frozenset(
    {
        "ENDPOINT_CAPTURE_LIST",
        "ENDPOINT_EVENT_STREAM",
        "ENDPOINT_SETTINGS_CAMERAS",
        "ENDPOINT_SET_SCHEDULE",
        "ENDPOINT_SYSTEM_INFO",
    }
)

MOTION_RECORD: Final = b"20260809175335 0 3 MOTION 10 20 30 40\r"

#: Sentinel chunk meaning "this socket goes quiet and stays quiet".
SILENCE: Final = object()

#: Upper bound on how long a test waits for a condition. Only a failure path
#: ever waits this long.
PATIENCE: Final = 5.0

SYSTEM_INFO: Final = {
    "system": {
        "server": {"uuid": "abc", "version": "6.20", "camera-count": "1", "bonjour-name": "nvr"},
        "cameralist": {"camera": [{"number": "3", "name": "Driveway", "connected": True}]},
    }
}


def settings_page() -> dict[str, object]:
    """Build a ``++settings-cameras`` body: curated keys plus plaintext credentials."""
    return {
        "name": "Driveway",
        "overlayText": PAYLOAD_MARKER,
        "brightness": 128,
        "contrast": 100,
        "motionSensitivity": 55,
        "mcTriggerMotion": True,
        "username": DEVICE_USERNAME,
        "password": DEVICE_PASSWORD,
    }


CAPTURE_LIST: Final = [
    {"c": 3, "f": "2026-08-09", "s": 63319, "d": 30, "t": 1, "o": 1, "n": PAYLOAD_MARKER}
]


class BufferedContent:
    """Stand-in for ``response.content`` on an ordinary request."""

    CHUNK: Final = 64

    def __init__(self, raw: bytes) -> None:
        """Store the canned bytes."""
        self._raw = raw
        self._pos = 0

    async def read(self, limit: int = -1) -> bytes:
        """Return at most ``limit`` bytes, deliberately fragmented."""
        take = len(self._raw) - self._pos if limit < 0 else min(limit, self.CHUNK)
        chunk = self._raw[self._pos : self._pos + take]
        self._pos += len(chunk)
        return chunk


class StreamContent:
    """Stand-in for ``response.content`` on the long-lived event stream."""

    def __init__(self, chunks: Sequence[bytes | object]) -> None:
        """Store the script. A ``SILENCE`` entry never returns."""
        self._chunks = list(chunks)

    async def read(self, _limit: int = -1) -> bytes:
        """Return the next scripted chunk, or block until cancelled."""
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if chunk is SILENCE:
            await asyncio.sleep(PATIENCE * 100)
        assert isinstance(chunk, bytes)
        return chunk


class FakeResponse:
    """Minimal stand-in for an aiohttp response, buffered or streaming."""

    def __init__(self, status: int, body: bytes | Sequence[bytes | object]) -> None:
        """Store the canned status and body."""
        self.status = status
        self.content: BufferedContent | StreamContent
        if isinstance(body, bytes):
            self._raw: bytes | None = body
            self.content = BufferedContent(body)
        else:
            self._raw = None
            self.content = StreamContent(body)

    @property
    def content_length(self) -> int | None:
        """The declared body length, or ``None`` for a stream."""
        return None if self._raw is None else len(self._raw)

    def get_encoding(self) -> str:
        """Return the charset the response declares."""
        return "utf-8"

    async def __aenter__(self) -> Self:
        """Enter the response context."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Leave the response context without suppressing anything."""


class FakeServer:
    """Serves every endpoint at once and records every call made to it."""

    def __init__(self, status: int = 200, *, body: str | None = None) -> None:
        """Configure the status every route answers with.

        Args:
            status: The HTTP status to answer with. Anything but 200 makes every
                path a failing path, which is half of what the sweep drives.
            body: When given, the body every route answers with, regardless of
                the endpoint. Used to drive the undecodable-body failures.

        """
        self.status = status
        self.body = body
        #: ``(method, url, kwargs)`` per request, in order.
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Record a GET and answer it."""
        self.calls.append(("GET", url, kwargs))
        return self._respond(url)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Record a POST and answer it."""
        self.calls.append(("POST", url, kwargs))
        return self._respond(url)

    def _respond(self, url: str) -> FakeResponse:
        """Answer with the recorded shape for the endpoint in ``url``."""
        if url.endswith(ENDPOINT_EVENT_STREAM):
            # One real record, then silence: the reader stays connected until the
            # test disconnects it, so no backoff sleep is ever reached.
            return FakeResponse(self.status, [MOTION_RECORD, SILENCE])
        if self.body is not None:
            return FakeResponse(self.status, self.body.encode())
        if url.endswith(ENDPOINT_SYSTEM_INFO):
            return FakeResponse(self.status, json.dumps(SYSTEM_INFO).encode())
        if url.endswith(ENDPOINT_SETTINGS_CAMERAS):
            return FakeResponse(self.status, json.dumps(settings_page()).encode())
        if url.endswith(ENDPOINT_CAPTURE_LIST):
            return FakeResponse(self.status, json.dumps(CAPTURE_LIST).encode())
        return FakeResponse(self.status, b"OK")


def make_client(server: FakeServer) -> SecuritySpyClient:
    return SecuritySpyClient(
        cast("aiohttp.ClientSession", server), HOST, PORT, username=USERNAME, password=PASSWORD
    )


async def until(condition: Callable[[], bool]) -> None:
    """Yield to the loop until ``condition`` holds, failing rather than hanging."""
    async with asyncio.timeout(PATIENCE):
        while not condition():  # noqa: ASYNC110 - polling a property, not awaiting a signal
            await asyncio.sleep(0)


async def drive_every_path(server: FakeServer) -> list[SecuritySpyError]:
    """Run every public request path plus a stream session against ``server``.

    Returns:
        Every library error raised along the way. On a healthy server that is
        an empty list; on a failing one it is one error per path, and each of
        them is a haystack the credential search runs over.

    """
    client = make_client(server)
    errors: list[SecuritySpyError] = []
    calls: tuple[Callable[[], Any], ...] = (
        client.async_get_server_info,
        lambda: client.async_get_camera_settings(CAMERA),
        lambda: client.async_set_camera_settings(
            CAMERA, CameraSettingsPatch(overlay_text=PAYLOAD_MARKER)
        ),
        lambda: client.async_set_camera_arming(
            CAMERA, CaptureModes(motion=True), override=ARM_OVERRIDE_ARMED_2_HOURS
        ),
        lambda: client.async_get_captures([CAMERA], start_date=DAY, end_date=DAY),
    )
    for call in calls:
        try:
            await call()
        except SecuritySpyError as err:
            errors.append(err)

    events: list[object] = []
    auth_failed = asyncio.Event()
    stream = client.event_stream(on_event=events.append, on_auth_failed=auth_failed.set)
    await stream.connect()
    # Either outcome ends the wait: a healthy server delivers the MOTION record,
    # a rejecting one pauses the reader through `on_auth_failed`.
    await until(lambda: bool(events) or auth_failed.is_set())
    await stream.disconnect()
    return errors


def rendered(errors: list[SecuritySpyError]) -> str:
    """Render every error the way a consumer's crash report would."""
    parts: list[str] = []
    for err in errors:
        parts.extend(
            [str(err), repr(err), "".join(traceback.format_exception(err)), repr(err.__cause__)]
        )
    return "\n".join(parts)


# --- the whole-library log and exception sweep -------------------------------


@pytest.mark.asyncio
async def test_no_credential_reaches_a_log_line_an_exception_or_a_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Every public path, healthy and failing, under the whole logger tree at level 0.

    Four distinct sentinels are in play: the connection credential the client
    and the stream hold, the device credential the settings page carries in
    plaintext (research §8.3), and a perfectly ordinary settings value -- because
    the rule is that the settings *payload* is never logged, not merely its two
    password-shaped fields.
    """
    # `at_level(0, logger="aiosecurityspy")` alone captures *nothing*: level 0 is
    # NOTSET, which means "inherit", and the root logger caplog attaches its
    # handler to sits at WARNING -- so every debug line would be dropped before
    # the handler saw it and the search below would run over an empty string.
    # Dropping root to DEBUG as well is what makes "at any level" a real sweep,
    # and it widens the net to any logger the library might grow later.
    with caplog.at_level(logging.DEBUG), caplog.at_level(0, logger="aiosecurityspy"):
        succeeding = await drive_every_path(FakeServer())
        # Every path again, failing: rejected credentials, then a body that is
        # neither JSON nor a settings page.
        rejected = await drive_every_path(FakeServer(401))
        undecodable = await drive_every_path(FakeServer(body="<html>not securityspy</html>"))

    # Asserted per phase, not over the combined list: if the 401 phase silently
    # stopped raising -- the exact regression it exists to catch -- a non-empty
    # combined list would still be satisfied by the undecodable-body phase.
    assert rejected, "the rejected-credential phase must actually have raised"
    assert undecodable, "the undecodable-body phase must actually have raised"
    errors = succeeding + rejected + undecodable
    haystack = f"{caplog.text}\n{rendered(errors)}"
    for sentinel in SENTINELS:
        assert sentinel not in haystack, sentinel
    # Not a tautology: one stray line from anywhere would satisfy a bare
    # `caplog.text.strip()`, so count the library's own debug records instead.
    # The floor sits well under the 21 the three phases actually emit, so an
    # ordinary logging change does not break it, while staying far above what a
    # single stray line could reach.
    debug_records = [
        record
        for record in caplog.records
        if record.levelno == logging.DEBUG and record.name.startswith("aiosecurityspy")
    ]
    assert len(debug_records) >= MINIMUM_DEBUG_RECORDS, len(debug_records)


# --- the URL claim -----------------------------------------------------------


def assert_url_carries_no_credential(url: str, params: dict[str, Any]) -> None:
    """Assert one request's URL and parameters carry nothing credential-shaped."""
    parts = urlsplit(url)
    assert "@" not in parts.netloc, f"userinfo in {url}"
    named = [*parse_qsl(parts.query, keep_blank_values=True), *params.items()]
    for name, value in named:
        assert not is_credential_key(str(name)), f"{name} in {url}"
        # Every sentinel, not just the connection pair: a device credential
        # carried under a name this predicate does not recognise is exactly the
        # leak a name-only check cannot see.
        assert str(value) not in SENTINELS, f"{name} in {url}"
    for sentinel in SENTINELS:
        assert sentinel not in url
        # A credential the library encoded on its way into a URL is still that
        # credential; research §7's own example is a base64 `auth=` parameter.
        assert quote(sentinel) not in url
        assert b64encode(sentinel.encode()).decode() not in url


def test_no_url_the_library_builds_can_carry_a_credential() -> None:
    """Every exported endpoint constant, through the one URL builder.

    ``build_url`` and ``base_url`` are the only two URL-building expressions in
    the library, so every URL the library composes itself is covered here. What
    a real :class:`aiohttp.ClientSession` does downstream of that -- yarl's
    encoding, a redirect it follows -- is aiohttp's contract, not this one, and
    is exercised against a real socket in ``test_stream_transport.py``.
    """
    connection = ConnectionSettings.create(
        cast("aiohttp.ClientSession", FakeServer()),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    endpoints = {
        name
        for name in aiosecurityspy.__all__
        if name.startswith("ENDPOINT_") and name != "ENDPOINT_PREFIX"
    }
    # Exact, not a count: the sweep is only a sweep if it swept everything, and a
    # constant dropped from `__all__` must fail here rather than quietly shrink it.
    assert endpoints == EXPECTED_ENDPOINT_NAMES
    for name in sorted(endpoints):
        assert_url_carries_no_credential(connection.build_url(getattr(aiosecurityspy, name)), {})
    assert_url_carries_no_credential(connection.base_url, {})


@pytest.mark.asyncio
async def test_no_url_the_client_or_the_stream_sends_carries_a_credential() -> None:
    """The credential travels as an ``Authorization`` header, on every request, without exception.

    The URL is the observable half of that claim: a reverse proxy, a ``Referer``
    header and an access log all record it, and research §7 records a
    credential-bearing URL being echoed verbatim by an external tool.
    """
    server = FakeServer()
    await drive_every_path(server)

    assert server.calls, "the sweep must have issued requests"
    for _method, url, kwargs in server.calls:
        assert_url_carries_no_credential(url, dict(kwargs.get("params") or {}))
        # The other half: it did travel, just not in the URL.
        assert kwargs["headers"]["Authorization"] == aiohttp.encode_basic_auth(USERNAME, PASSWORD)
    # The stream is not an exception to any of it.
    assert any(url.endswith(ENDPOINT_EVENT_STREAM) for _, url, _ in server.calls)
