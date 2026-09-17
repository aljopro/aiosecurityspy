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
from datetime import UTC, date
from typing import TYPE_CHECKING, Any, Final, Self, cast
from urllib.parse import parse_qsl, quote, urlsplit

import aiohttp
import pytest

import aiosecurityspy
from aiosecurityspy import (
    ARM_OVERRIDE_ARMED_2_HOURS,
    ENDPOINT_CAM_STATUS,
    ENDPOINT_CAPTURE_LIST,
    ENDPOINT_EVENT_STREAM,
    ENDPOINT_GET_FILE,
    ENDPOINT_GET_FILE_HIGH_BANDWIDTH,
    ENDPOINT_GET_FILE_LOW_BANDWIDTH,
    ENDPOINT_GET_PREVIEW,
    ENDPOINT_IMAGE,
    ENDPOINT_SETTINGS_CAMERAS,
    ENDPOINT_SYSTEM_INFO,
    CameraSettingsPatch,
    CaptureModes,
    SecuritySpyClient,
    SecuritySpyError,
    is_credential_key,
)
from aiosecurityspy.connection import _ConnectionSettings
from aiosecurityspy.models import Capture, ServerInfo

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

#: A SecuritySpy 6.22b9+ per-account API key, used as the Basic-auth password
#: (Story 1.21's spike). Shaped like a real key (`API_` + 32 base62 chars, 36
#: total) but not one -- proves a key-shaped credential never leaks either.
API_KEY: Final = "API_" + "9f3a7c1e5b2d4f608a1c3e5f7b9d1c3e"

#: A username distinct from `USERNAME`, used only with `API_KEY`. If the key
#: path ever leaked a username through code the password path does not
#: exercise, this sentinel -- not `USERNAME` -- would be the one to appear,
#: making the two credential types distinguishable in a failure.
KEY_USERNAME: Final = "key-user-3b8a"

#: Everything that must never appear in a log line, an exception or a URL.
SENTINELS: Final = (
    USERNAME,
    PASSWORD,
    DEVICE_USERNAME,
    DEVICE_PASSWORD,
    PAYLOAD_MARKER,
    API_KEY,
    KEY_USERNAME,
)

CAMERA: Final = 3
DAY: Final = date(2026, 8, 9)

#: The floor the log sweep must clear before its "nothing leaked" search means
#: anything. The five phases (password-authenticated healthy/rejected/
#: undecodable, plus key-authenticated healthy/rejected) together emit well
#: over this at the time of writing, so the guard survives an ordinary
#: logging change while still failing loudly if the library ever goes quiet
#: and the search runs over an empty haystack -- which a bare
#: ``caplog.text.strip()`` would not, since one stray line satisfies it.
MINIMUM_DEBUG_RECORDS: Final = 12

#: Every endpoint constant the package exports, ``ENDPOINT_PREFIX`` aside. Named
#: exactly rather than counted: a ``>= 2`` guard would pass with four of the five
#: gone from ``__all__`` and the URL claim silently untested for them.
EXPECTED_ENDPOINT_NAMES: Final = frozenset(
    {
        "ENDPOINT_CAM_STATUS",
        "ENDPOINT_CAPTURE_LIST",
        "ENDPOINT_EVENT_STREAM",
        "ENDPOINT_GET_FILE",
        "ENDPOINT_GET_FILE_HIGH_BANDWIDTH",
        "ENDPOINT_GET_FILE_LOW_BANDWIDTH",
        "ENDPOINT_GET_PREVIEW",
        "ENDPOINT_IMAGE",
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

CAM_STATUS: Final = [
    {"num": 3, "enabled": True, "online": True, "open": False, "err": "", "errDesc": ""}
]

#: A JPEG/movie-shaped body for the capture preview and file endpoints. Content,
#: not shape, is what the sweep cares about: neither is decoded, only redacted.
PREVIEW_BYTES: Final = b"\xff\xd8\xff\xe0" + b"\x00" * 16
FILE_BYTES: Final = b"\x00\x00\x00\x1c" + b"\x00" * 16


#: A plain, non-sentinel filename. The path/filename is caller-supplied and
#: legitimately travels in the URL byte for byte -- it is not credential- or
#: PII-shaped, so it must NOT be one of `SENTINELS`, or the whole-library "no
#: sentinel reaches a URL" sweep below would fail on a value that was never
#: supposed to be hidden in the first place.
CAPTURE_FILENAME: Final = "M+2026-08-09_17-35-19_C.jpg"


def make_capture() -> Capture:
    """Build a `Capture` for exercising the preview and file fetch paths.

    Independent of `CAPTURE_LIST`/`async_get_captures`: the preview and file
    fetches build their URL from the `Capture` the caller passes in, not from
    a server-returned one, and both failing phases (401, undecodable body)
    must still be able to exercise them even though `async_get_captures`
    itself raises before returning anything in those phases.
    """
    return Capture(
        camera=CAMERA,
        start=None,
        duration=None,
        capture_type=1,
        object_classes=frozenset(),
        filename=CAPTURE_FILENAME,
        folder_date="2026-08-09",
        file_size_mb=None,
        tag_id=None,
        archived=False,
        unread=False,
        path=f"{CAMERA}/2026-08-09/{CAPTURE_FILENAME}",
    )


#: ``(url suffix, JSON body)`` pairs `FakeServer._respond` checks in order, kept
#: as a table rather than a chain of `if`s so a new endpoint costs one row.
_ENDPOINT_BODIES: Final[tuple[tuple[str, object], ...]] = (
    (ENDPOINT_SYSTEM_INFO, SYSTEM_INFO),
    (ENDPOINT_SETTINGS_CAMERAS, settings_page()),
    (ENDPOINT_CAPTURE_LIST, CAPTURE_LIST),
    (ENDPOINT_CAM_STATUS, CAM_STATUS),
)


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
    """Minimal stand-in for an aiohttp response, buffered or streaming.

    Supports both ways the client obtains one: ``async with session.get(...) as
    response`` (``_request``/``_request_bytes``, via ``__aenter__``) and
    ``response = await session.get(...)`` (``_stream_bytes``, via ``__await__``)
    -- the same instance answers either protocol, since ``FakeServer.get``
    itself is synchronous and returns one object regardless of which the
    caller uses.
    """

    def __init__(
        self,
        status: int,
        body: bytes | Sequence[bytes | object],
        content_type: str = "application/json",
    ) -> None:
        """Store the canned status, body and content type."""
        self.status = status
        self.content_type = content_type
        self.content: BufferedContent | StreamContent
        if isinstance(body, bytes):
            self._raw: bytes | None = body
            self.content = BufferedContent(body)
        else:
            self._raw = None
            self.content = StreamContent(body)
        self._released = False

    @property
    def content_length(self) -> int | None:
        """The declared body length, or ``None`` for a stream."""
        return None if self._raw is None else len(self._raw)

    def get_encoding(self) -> str:
        """Return the charset the response declares."""
        return "utf-8"

    def release(self) -> None:
        """Mark the response released, mirroring aiohttp's own no-arg release."""
        self._released = True

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

    def __await__(self) -> Any:  # noqa: ANN401 - mirrors aiohttp's own awaitable get()
        """Support ``response = await session.get(...)``, used by ``_stream_bytes``."""

        # `-> FakeResponse`, not `-> Self`: a nested function's return type isn't
        # bound to the enclosing method's `Self` typevar, so mypy --strict sees
        # a mismatch between the two here even though the value is `self`.
        async def _return() -> FakeResponse:
            return self

        return _return().__await__()


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
        # The preview/file paths carry a literal embedded `?` and per-component
        # percent-encoding (research §4.3), so they never land on a clean
        # `endswith` match the way the JSON endpoints below do.
        if ENDPOINT_GET_PREVIEW in url or ENDPOINT_IMAGE in url:
            return FakeResponse(self.status, PREVIEW_BYTES, content_type="image/jpeg")
        file_endpoints = (
            ENDPOINT_GET_FILE,
            ENDPOINT_GET_FILE_HIGH_BANDWIDTH,
            ENDPOINT_GET_FILE_LOW_BANDWIDTH,
        )
        if any(endpoint in url for endpoint in file_endpoints):
            return FakeResponse(self.status, FILE_BYTES, content_type="video/quicktime")
        for suffix, payload in _ENDPOINT_BODIES:
            if url.endswith(suffix):
                return FakeResponse(self.status, json.dumps(payload).encode())
        return FakeResponse(self.status, b"OK")


def make_client(server: FakeServer) -> SecuritySpyClient:
    return SecuritySpyClient(
        cast("aiohttp.ClientSession", server), HOST, PORT, username=USERNAME, password=PASSWORD
    )


def make_client_with_key(server: FakeServer) -> SecuritySpyClient:
    """Build a client authenticated with an API key instead of a password.

    Story 1.21: a SecuritySpy 6.22b9+ API key sits in the same Basic-auth
    password slot a real password would. This drives it through the same
    paths ``make_client`` does, so ``API_KEY`` is a genuine credential in
    flight for the sweep below rather than a declared-but-unused sentinel.
    Uses ``KEY_USERNAME``, not ``USERNAME``, so a leak under this path is
    distinguishable from a leak under the password path.
    """
    return SecuritySpyClient(
        cast("aiohttp.ClientSession", server), HOST, PORT, username=KEY_USERNAME, password=API_KEY
    )


async def until(condition: Callable[[], bool]) -> None:
    """Yield to the loop until ``condition`` holds, failing rather than hanging."""
    async with asyncio.timeout(PATIENCE):
        while not condition():  # noqa: ASYNC110 - polling a property, not awaiting a signal
            await asyncio.sleep(0)


async def drain_capture_file(client: SecuritySpyClient) -> None:
    """Fetch and fully drain a capture file, so the URL and the streamed body both run."""
    stream = await client.async_get_capture_file(make_capture())
    async with stream:
        async for _chunk in stream:
            pass


async def drive_every_path(
    server: FakeServer, client_factory: Callable[[FakeServer], SecuritySpyClient] = make_client
) -> list[SecuritySpyError]:
    """Run every public request path plus a stream session against ``server``.

    ``client_factory`` defaults to a username/password client; pass
    ``make_client_with_key`` to run the same sweep with an API key as the
    credential instead (Story 1.21).

    Returns:
        Every library error raised along the way. On a healthy server that is
        an empty list; on a failing one it is one error per path, and each of
        them is a haystack the credential search runs over.

    """
    client = client_factory(server)
    errors: list[SecuritySpyError] = []
    calls: tuple[Callable[[], Any], ...] = (
        client.async_get_server_info,
        client.async_get_camera_status,
        lambda: client.async_get_camera_settings(CAMERA),
        lambda: client.async_set_camera_settings(
            CAMERA, CameraSettingsPatch(overlay_text=PAYLOAD_MARKER)
        ),
        lambda: client.async_set_camera_arming(
            CAMERA, CaptureModes(motion=True), override=ARM_OVERRIDE_ARMED_2_HOURS
        ),
        lambda: client.async_get_captures(
            [CAMERA], start_date=DAY, end_date=DAY, server_timezone=UTC
        ),
        lambda: client.async_get_capture_preview(make_capture()),
        lambda: client.async_get_camera_image(
            ServerInfo.from_api(SYSTEM_INFO), CAMERA, width=320, quality=50
        ),
        lambda: drain_capture_file(client),
    )
    for call in calls:
        try:
            await call()
        except SecuritySpyError as err:
            errors.append(err)

    events: list[object] = []
    auth_failed = asyncio.Event()
    stream = client.event_stream(
        on_event=events.append, on_auth_failed=auth_failed.set, server_timezone=UTC
    )
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

    Five distinct sentinels are in play: the connection credential the client
    and the stream hold, the device credential the settings page carries in
    plaintext (research §8.3), a perfectly ordinary settings value -- because
    the rule is that the settings *payload* is never logged, not merely its two
    password-shaped fields -- and a SecuritySpy 6.22b9+ API key, driven through
    its own key-authenticated pass (Story 1.21).
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
        # Same sweep again, authenticated with an API key instead of a
        # password (Story 1.21) -- proves a key-shaped credential leaks no
        # more than a password does, on both a healthy and a rejecting server.
        key_succeeding = await drive_every_path(FakeServer(), make_client_with_key)
        key_rejected = await drive_every_path(FakeServer(401), make_client_with_key)

    # Asserted per phase, not over the combined list: if the 401 phase silently
    # stopped raising -- the exact regression it exists to catch -- a non-empty
    # combined list would still be satisfied by the undecodable-body phase.
    assert not succeeding, "the healthy-server phase must not raise"
    assert rejected, "the rejected-credential phase must actually have raised"
    assert undecodable, "the undecodable-body phase must actually have raised"
    assert not key_succeeding, "the key-authenticated healthy-server phase must not raise"
    assert key_rejected, "the key-rejected phase must actually have raised"
    errors = succeeding + rejected + undecodable + key_succeeding + key_rejected
    haystack = f"{caplog.text}\n{rendered(errors)}"
    for sentinel in SENTINELS:
        assert sentinel not in haystack, sentinel
    # Not a tautology: one stray line from anywhere would satisfy a bare
    # `caplog.text.strip()`, so count the library's own debug records instead.
    # The floor sits well under what the five phases actually emit, so an
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
    connection = _ConnectionSettings.create(
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
async def test_no_rtsp_url_the_library_builds_can_carry_a_credential() -> None:
    """``unsecured_stream_url`` and every relay ``stream_url``, through the same claim.

    Neither builder goes through ``build_url``, so the sweep above cannot see
    them; each is swept here for every visible camera, on a started relay.
    """
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", FakeServer()),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    info = aiosecurityspy.ServerInfo.from_api(
        {
            "system": {
                "server": {
                    "uuid": "abc",
                    "version": "6.21",
                    "http-enabled": True,
                    "http-port": 8000,
                },
                "cameralist": {"camera": [{"number": n} for n in (0, 3, 11)]},
            }
        }
    )
    assert info.rtsp_port is not None
    assert set(info.cameras) == {0, 3, 11}
    for number in info.cameras:
        assert_url_carries_no_credential(client.unsecured_stream_url(info, number), {})
    relays = (
        client.create_rtsp_relay(info),
        client.create_rtsp_relay(
            info,
            bind_host="0.0.0.0",  # noqa: S104 - the advertised-host path is the one swept
            advertised_host="relay.example.com",
        ),
    )
    for relay in relays:
        async with relay:
            for number in info.cameras:
                assert_url_carries_no_credential(relay.stream_url(number), {})


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
