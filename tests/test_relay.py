"""The RTSP relay, replaying the three committed ffmpeg captures over real sockets.

Each capture is parsed into its request/response exchanges. A fake upstream
built on :func:`asyncio.start_server` answers with the captured responses and
records what it received; a raw consumer sends the captured requests,
re-addressed to the relay. Together they prove the rewrite rules against what
SecuritySpy actually sent rather than against a guess.

Self-contained by house rule: no ``conftest.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
from base64 import b64encode
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Final, cast

import aiohttp
import pytest

from aiosecurityspy import (
    Camera,
    RtspRelay,
    SecuritySpyClient,
    SecuritySpyPermissionError,
    ServerInfo,
)
from aiosecurityspy import relay as relay_module
from test_credential_containment import PASSWORD, SENTINELS, USERNAME

FIXTURES: Final = Path(__file__).parent / "fixtures"
ALLOWED: Final = "rtsp_handshake_cam_allowed.log"
DENIED: Final = "rtsp_handshake_cam_denied.log"
BASIC_AUTH: Final = "rtsp_handshake_cam_allowed_basic_auth.log"

CAMERA: Final = 4
HIDDEN_CAMERA: Final = 5
PATIENCE: Final = 5.0
FRAME_COUNT: Final = 3
OVERSIZED: Final = 9000

#: What the captured server called itself; must never reach a consumer.
CAPTURED_HOST: Final = "securityspy.local"
CAPTURED_UPSTREAM_URL: Final = re.compile(r"rtsp:/{1,2}securityspy\.local:8000/stream\?[^\s/]*")

_TRACE_PREFIX: Final = re.compile(r"^\[rtsp @ 0x[0-9a-f]+\] ")
_RESPONSE_LINE: Final = re.compile(r"^\[rtsp @ 0x[0-9a-f]+\] line='(.*)'$")


# --- capture parsing ----------------------------------------------------------


@dataclass
class Exchange:
    """One captured request and, when the capture shows one, its response."""

    request: list[str]
    response: list[str] = field(default_factory=list)
    body: bytes = b""

    @property
    def method(self) -> str:
        """The request's RTSP method."""
        return self.request[0].split(" ", 1)[0]

    def request_header(self, name: str) -> str | None:
        """Return one captured request header's value, or ``None``."""
        for line in self.request[1:]:
            key, _, value = line.partition(":")
            if key.strip().lower() == name.lower():
                return value.strip()
        return None

    def response_bytes(self) -> bytes:
        """Return the captured response as it went over the wire."""
        return ("\r\n".join(self.response) + "\r\n\r\n").encode("latin-1") + self.body


def parse_capture(name: str) -> list[Exchange]:
    """Parse an ffmpeg ``-loglevel trace`` capture into exchanges.

    A request block follows a line ending ``Sending:`` and ends at a blank
    line. A response head is the run of ``line='...'`` records up to
    ``line=''``; everything else (byte-by-byte ``ret=1 c=..`` records, their
    wrapped ``]`` continuation lines, ``Last message repeated`` and decoder
    chatter) is noise. The SDP body follows a ``SDP:`` line; ffmpeg prints it
    with LF line ends plus one trailing newline of its own, so it is rebuilt
    with CRLF and checked against the captured ``Content-Length``.
    """
    lines = (FIXTURES / name).read_text(encoding="utf-8").split("\n")
    exchanges: list[Exchange] = []
    index = 0
    in_head = False
    while index < len(lines):
        line = lines[index]
        if line.endswith("Sending:"):
            request: list[str] = []
            index += 1
            while index < len(lines) and lines[index] != "":
                request.append(lines[index])
                index += 1
            exchanges.append(Exchange(request))
            in_head = False
        elif (match := _RESPONSE_LINE.match(line)) is not None:
            value = match[1]
            if value == "":
                in_head = False
            else:
                if not in_head:
                    in_head = True
                    assert not exchanges[-1].response, "two responses for one request"
                exchanges[-1].response.append(value)
        elif _TRACE_PREFIX.match(line) and line.endswith("SDP:"):
            sdp: list[str] = []
            index += 1
            while index < len(lines) and lines[index] != "":
                sdp.append(lines[index])
                index += 1
            exchanges[-1].body = ("\r\n".join(sdp) + "\r\n\r\n").encode("latin-1")
        index += 1
    for exchange in exchanges:
        declared = next(
            (
                int(value.split(":", 1)[1])
                for value in exchange.response
                if value.lower().startswith("content-length:")
            ),
            0,
        )
        assert declared == len(exchange.body), (exchange.method, declared, len(exchange.body))
    return exchanges


def test_captures_parse_into_the_expected_exchanges() -> None:
    methods = {
        name: [e.method for e in parse_capture(name)] for name in (ALLOWED, DENIED, BASIC_AUTH)
    }
    assert methods[ALLOWED] == ["OPTIONS", "DESCRIBE", "SETUP", "SETUP", "PLAY", "TEARDOWN"]
    assert methods[DENIED] == ["OPTIONS", "DESCRIBE", "DESCRIBE"]
    assert methods[BASIC_AUTH] == ["OPTIONS", "DESCRIBE", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]
    allowed = parse_capture(ALLOWED)
    assert any(v.startswith("Content-Base: rtsp:/securityspy") for v in allowed[1].response)
    assert allowed[1].body.startswith(b"v=0\r\n")
    assert sum(v.count("url=rtsp:/") for v in allowed[4].response) == 2  # noqa: PLR2004
    assert allowed[5].response == []  # TEARDOWN's response is not in the capture


def relayed_exchanges(name: str) -> list[Exchange]:
    """Return the exchanges a relay will actually produce for one capture.

    The relay always authenticates, so the basic-auth capture's first
    ``DESCRIBE`` -- ffmpeg probing *without* a credential and being challenged --
    has no counterpart: that request is dropped along with its ``401``.
    """
    exchanges = parse_capture(name)
    if any(e.request_header("Authorization") for e in exchanges):
        exchanges = [
            e for e in exchanges if e.method == "OPTIONS" or e.request_header("Authorization")
        ]
    return exchanges


# --- harness ------------------------------------------------------------------


class FakeUpstream:
    """A SecuritySpy stand-in that answers with captured responses, in order."""

    def __init__(self, exchanges: list[Exchange], frames: list[bytes] | None = None) -> None:
        """Serve ``exchanges``' responses, then ``frames`` after ``PLAY``."""
        self.responses = [e for e in exchanges if e.response]
        self.frames = frames or []
        self.requests: list[tuple[str, list[tuple[str, str]]]] = []
        self.received_frames: list[bytes] = []
        self.connections = 0
        self.close_after_play = False
        self.server: asyncio.Server | None = None
        self.port = 0
        self.done = asyncio.Event()

    async def start(self) -> None:
        """Listen on a free loopback port."""
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        """Stop listening."""
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        pending = list(self.responses)
        try:
            while True:
                message = await read_message(reader)
                if message is None:
                    break
                if isinstance(message, bytes):
                    self.received_frames.append(message)
                    continue
                start, headers, _ = message
                self.requests.append((start, headers))
                if not pending:
                    break  # TEARDOWN: the capture ends here
                writer.write(pending.pop(0).response_bytes())
                if start.startswith("PLAY "):
                    for frame in self.frames:
                        writer.write(frame)
                    if self.close_after_play:
                        await writer.drain()
                        break
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            self.done.set()


async def read_message(
    reader: asyncio.StreamReader,
) -> bytes | tuple[str, list[tuple[str, str]], bytes] | None:
    """Read one ``$`` frame or RTSP message, independently of the relay's own framing."""
    first = await reader.read(1)
    if not first:
        return None
    if first == b"$":
        prefix = await reader.readexactly(3)
        return first + prefix + await reader.readexactly(int.from_bytes(prefix[1:], "big"))
    head = (first + await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
    start, *rest = head[:-4].split("\r\n")
    headers = [(k.strip(), v.strip()) for k, _, v in (line.partition(":") for line in rest)]
    length = next((int(v) for k, v in headers if k.lower() == "content-length"), 0)
    return start, headers, await reader.readexactly(length)


def header(headers: list[tuple[str, str]], name: str) -> str | None:
    return next((v for k, v in headers if k.lower() == name.lower()), None)


def make_frame(channel: int, payload: bytes) -> bytes:
    return b"$" + bytes([channel]) + len(payload).to_bytes(2, "big") + payload


#: Frames whose payloads contain things a careless rewrite would touch.
UPSTREAM_FRAMES: Final = [
    make_frame(0, bytes(range(256)) * 5 + b"rtsp:/securityspy.local:8000/stream?x"),
    make_frame(2, b"\r\n\r\nRTSP/1.0 200 OK\r\n\r\n"),
    make_frame(0, b"$\x00\xff\xff" + b"\x00" * 1400),
]
CONSUMER_FRAME: Final = make_frame(1, b"\x80\xc9\x00\x01rtcp-receiver-report")


def server_info(port: int | None, cameras: tuple[int, ...] = (CAMERA,)) -> ServerInfo:
    decoded: dict[int, Camera] = {}
    for number in cameras:
        camera = Camera.from_api({"number": number})
        assert camera is not None
        decoded[number] = camera
    return ServerInfo(
        uuid="relay-test",
        name="nvr",
        version="6.21",
        version_info=(6, 21),
        camera_count=len(decoded),
        cameras=MappingProxyType(decoded),
        rtsp_port=port,
    )


def make_client(timeout: float = PATIENCE) -> SecuritySpyClient:
    return SecuritySpyClient(
        cast("aiohttp.ClientSession", object()),
        "127.0.0.1",
        username=USERNAME,
        password=PASSWORD,
        timeout=timeout,
    )


def readdress(line: str, relay_url: str) -> str:
    """Point one captured request line at the relay instead of SecuritySpy."""
    return CAPTURED_UPSTREAM_URL.sub(relay_url, line)


@dataclass
class Replay:
    """What the consumer received, per request, plus the frames after PLAY."""

    responses: list[tuple[str, list[tuple[str, str]], bytes]]
    frames: list[bytes]
    closed: bool


async def replay(
    exchanges: list[Exchange],
    relay_url: str,
    *,
    frames_expected: int = 0,
    expect_close: bool = True,
) -> Replay:
    """Send each captured request to the relay and read what comes back."""
    host, port = relay_url.removeprefix("rtsp://").split("/", 1)[0].rsplit(":", 1)
    reader, writer = await asyncio.open_connection(host, int(port))
    responses: list[tuple[str, list[tuple[str, str]], bytes]] = []
    frames: list[bytes] = []
    try:
        for exchange in exchanges:
            request = [readdress(exchange.request[0], relay_url), *exchange.request[1:]]
            writer.write(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))
            await writer.drain()
            if not exchange.response:
                break
            message = await asyncio.wait_for(read_message(reader), PATIENCE)
            assert isinstance(message, tuple), message
            responses.append(message)
            if exchange.method == "PLAY":
                writer.write(CONSUMER_FRAME)
                await writer.drain()
                while len(frames) < frames_expected:
                    frame = await asyncio.wait_for(read_message(reader), PATIENCE)
                    assert isinstance(frame, bytes), frame
                    frames.append(frame)
        # A replay that stops mid-session leaves the connection open by design
        # (a 403 is not a reason to close), so only wait for EOF when due. A
        # reset is also a close: a write racing the relay's own close earns an
        # RST rather than a clean EOF.
        try:
            closed = expect_close and await asyncio.wait_for(reader.read(1), PATIENCE) == b""
        except ConnectionResetError:
            closed = True
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()
    return Replay(responses, frames, closed)


async def raw_exchange(url_port: int, payload: bytes) -> bytes:
    """Send raw bytes to the relay and return everything until it closes."""
    reader, writer = await asyncio.open_connection("127.0.0.1", url_port)
    try:
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), PATIENCE)
    finally:
        writer.close()
        await writer.wait_closed()


def relay_id(url: str) -> str:
    return url.rsplit("/", 1)[1]


def assert_consumer_saw_only_relay_urls(result: Replay, relay_url: str) -> None:
    host_port = relay_url.removeprefix("rtsp://").split("/", 1)[0]
    for start, headers, body in result.responses:
        text = "\n".join([start, *(f"{k}: {v}" for k, v in headers)]) + body.decode("latin-1")
        assert CAPTURED_HOST not in text
        assert ":8000" not in text
        assert "auth=" not in text
        assert "REDACTED" not in text
        for name in ("WWW-Authenticate", "SS-UUID", "Server"):
            assert header(headers, name) is None, name
        for url in re.findall(r"rtsp:/+[^\s;,]+", text):
            assert url.startswith(f"rtsp://{host_port}/{relay_id(relay_url)}"), url


def assert_upstream_saw_only_the_header(upstream: FakeUpstream) -> None:
    expected = aiohttp.encode_basic_auth(USERNAME, PASSWORD)
    assert upstream.requests
    for start, headers in upstream.requests:
        url = start.split(" ")[1]
        assert url.startswith(
            f"rtsp://127.0.0.1:{upstream.port}/stream?cameraNum={CAMERA}&vcodec=h26x&acodec=src"
        ), url
        assert "@" not in url
        assert "auth=" not in url
        assert header(headers, "Authorization") == expected
        assert [k for k, _ in headers].count("Authorization") == 1


# --- scenarios (each a matrix row; the leak sweep runs them all) ---------------


async def scenario_default_start_replays_the_allowed_capture() -> None:
    upstream = FakeUpstream(relayed_exchanges(ALLOWED), UPSTREAM_FRAMES)
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            url = relay.stream_url(CAMERA)
            assert re.fullmatch(rf"rtsp://127\.0\.0\.1:{relay.bound_port}/[A-Za-z0-9_-]{{22}}", url)
            result = await replay(
                relayed_exchanges(ALLOWED), url, frames_expected=len(UPSTREAM_FRAMES)
            )
            await asyncio.wait_for(upstream.done.wait(), PATIENCE)
    finally:
        await upstream.stop()

    assert [r[0] for r in result.responses] == ["RTSP/1.0 200 OK"] * 5
    assert_consumer_saw_only_relay_urls(result, url)
    describe_headers = result.responses[1][1]
    # The single-slash Content-Base is rewritten to the relay, well-formed.
    assert header(describe_headers, "Content-Base") == url
    assert header(describe_headers, "Content-Length") == str(len(result.responses[1][2]))
    assert result.responses[1][2] == relayed_exchanges(ALLOWED)[1].body
    # Both RTP-Info urls, each keeping its track suffix.
    rtp_info = header(result.responses[4][1], "RTP-Info")
    assert rtp_info == (f"url={url}/trackID=0;seq=0;rtptime=0,url={url}/trackID=1;seq=0;rtptime=0")
    # Pass-through headers survive, CSeq and Session included.
    assert [header(r[1], "CSeq") for r in result.responses] == ["1", "2", "3", "4", "5"]
    assert header(result.responses[2][1], "Session") == "1"
    # Frames round-trip byte-identically, both ways.
    assert result.frames == UPSTREAM_FRAMES
    assert upstream.received_frames == [CONSUMER_FRAME]
    assert result.closed, "TEARDOWN's upstream close must close the consumer"
    assert_upstream_saw_only_the_header(upstream)
    assert [s.split(" ")[1].rsplit("src", 1)[1] for s, _ in upstream.requests] == [
        "",
        "",
        "/trackID=0",
        "/trackID=1",
        "",
        "",
    ]
    assert header(upstream.requests[3][1], "Session") == "1"
    assert header(upstream.requests[2][1], "Transport") == "RTP/AVP/TCP;unicast;interleaved=0-1"


async def scenario_basic_auth_capture_replays() -> None:
    upstream = FakeUpstream(relayed_exchanges(BASIC_AUTH), UPSTREAM_FRAMES[:1])
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            url = relay.stream_url(CAMERA)
            result = await replay(relayed_exchanges(BASIC_AUTH), url, frames_expected=1)
            await asyncio.wait_for(upstream.done.wait(), PATIENCE)
    finally:
        await upstream.stop()
    assert [r[0] for r in result.responses] == ["RTSP/1.0 200 OK"] * 4
    assert_consumer_saw_only_relay_urls(result, url)
    assert header(result.responses[1][1], "Content-Base") == url
    assert header(result.responses[3][1], "RTP-Info") == f"url={url}/trackID=0;seq=0;rtptime=0"
    assert result.frames == UPSTREAM_FRAMES[:1]
    # The consumer's own `Authorization: Basic REDACTED_AUTH` was replaced.
    assert_upstream_saw_only_the_header(upstream)


async def scenario_upstream_401_becomes_403() -> None:
    upstream = FakeUpstream(parse_capture(DENIED))
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            url = relay.stream_url(CAMERA)
            result = await replay(parse_capture(DENIED)[:2], url, expect_close=False)
    finally:
        await upstream.stop()
    assert result.responses[0][0] == "RTSP/1.0 200 OK"
    status, headers, _ = result.responses[1]
    assert status == "RTSP/1.0 403 Forbidden"
    assert header(headers, "WWW-Authenticate") is None
    assert header(headers, "CSeq") == "2"
    assert_consumer_saw_only_relay_urls(result, url)


async def scenario_repeated_and_new_relay() -> None:
    client = make_client()
    async with client.create_rtsp_relay(server_info(1)) as first:
        assert first.stream_url(CAMERA) == first.stream_url(CAMERA)
        async with client.create_rtsp_relay(server_info(1)) as second:
            assert relay_id(first.stream_url(CAMERA)) != relay_id(second.stream_url(CAMERA))


async def scenario_camera_not_visible() -> None:
    async with make_client().create_rtsp_relay(server_info(1)) as relay:
        with pytest.raises(SecuritySpyPermissionError) as caught:
            relay.stream_url(HIDDEN_CAMERA)
        assert caught.value.permission == "live_video"
        assert relay._ids == {}  # noqa: SLF001 - no identifier was issued
        for sentinel in SENTINELS:
            assert sentinel not in str(caught.value)


async def scenario_unknown_identifier() -> None:
    upstream = FakeUpstream(relayed_exchanges(ALLOWED))
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            relay.stream_url(CAMERA)
            port = relay.bound_port
            request = f"OPTIONS rtsp://127.0.0.1:{port}/bogus-id-7f3a RTSP/1.0\r\nCSeq: 7\r\n\r\n"
            reply = await raw_exchange(port, request.encode())
    finally:
        await upstream.stop()
    assert reply == b"RTSP/1.0 404 Not Found\r\nCSeq: 7\r\n\r\n"
    assert upstream.connections == 0


async def scenario_udp_setup() -> None:
    upstream = FakeUpstream(relayed_exchanges(ALLOWED))
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            url = relay.stream_url(CAMERA)
            request = (
                f"SETUP {url}/trackID=0 RTSP/1.0\r\nCSeq: 3\r\n"
                "Transport: RTP/AVP;unicast;client_port=5000-5001\r\n\r\n"
            )
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.bound_port)
            writer.write(request.encode())
            await writer.drain()
            message = await asyncio.wait_for(read_message(reader), PATIENCE)
            writer.close()
            await writer.wait_closed()
    finally:
        await upstream.stop()
    assert message == ("RTSP/1.0 461 Unsupported Transport", [("CSeq", "3")], b"")
    assert upstream.connections == 0
    assert upstream.requests == []


async def scenario_upstream_unreachable() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = int(probe.getsockname()[1])
    async with make_client().create_rtsp_relay(server_info(closed_port)) as relay:
        url = relay.stream_url(CAMERA)
        request = f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\n\r\n"
        reply = await raw_exchange(relay.bound_port, request.encode())
    assert reply == b"RTSP/1.0 503 Service Unavailable\r\nCSeq: 2\r\n\r\n"


async def scenario_upstream_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    async def never(*_args: object) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        await asyncio.sleep(PATIENCE * 2)
        raise AssertionError  # pragma: no cover

    async def bounded(
        host: str, port: int, deadline: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        assert deadline == 0.1  # noqa: PLR2004 - the client's own timeout is used
        async with asyncio.timeout(deadline):
            return await never(host, port)

    with monkeypatch.context() as patch:
        patch.setattr(relay_module, "_open_upstream", bounded)
        async with make_client(timeout=0.1).create_rtsp_relay(server_info(1)) as relay:
            url = relay.stream_url(CAMERA)
            reply = await raw_exchange(
                relay.bound_port, f"OPTIONS {url} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode()
            )
    assert reply == b"RTSP/1.0 503 Service Unavailable\r\nCSeq: 1\r\n\r\n"


async def scenario_connection_loss() -> None:
    exchanges = relayed_exchanges(ALLOWED)
    upstream = FakeUpstream(exchanges, UPSTREAM_FRAMES[:1])
    upstream.close_after_play = True
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            url = relay.stream_url(CAMERA)
            # Upstream closes mid-PLAY: the consumer sees its frame, then EOF.
            result = await replay(exchanges[:5], url, frames_expected=1)
            assert result.closed
            # The consumer disconnecting closes upstream, and the relay still serves.
            upstream.done.clear()
            upstream.close_after_play = False
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.bound_port)
            first = [readdress(exchanges[0].request[0], url), *exchanges[0].request[1:]]
            writer.write(("\r\n".join(first) + "\r\n\r\n").encode())
            await writer.drain()
            assert isinstance(await asyncio.wait_for(read_message(reader), PATIENCE), tuple)
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(upstream.done.wait(), PATIENCE)
            again = await replay(exchanges[:1], url, expect_close=False)
            assert again.responses[0][0] == "RTSP/1.0 200 OK"
    finally:
        await upstream.stop()


async def scenario_oversized_and_malformed() -> None:
    async with make_client().create_rtsp_relay(server_info(1)) as relay:
        assert await raw_exchange(relay.bound_port, b"A" * OVERSIZED) == b""
        assert await raw_exchange(relay.bound_port, b"GARBAGE\r\nCSeq: 1\r\n\r\n") == b""
        url = relay.stream_url(CAMERA)
        headless = f"OPTIONS {url} RTSP/1.0\r\nno colon here\r\n\r\n".encode()
        assert await raw_exchange(relay.bound_port, headless) == b""


async def scenario_wildcard_bind_and_advertised_host() -> None:
    client = make_client()
    for wildcard in ("0.0.0.0", "::"):  # noqa: S104 - asserting the refusal
        with pytest.raises(ValueError, match="advertised_host"):
            client.create_rtsp_relay(server_info(1), bind_host=wildcard)
    upstream = FakeUpstream(relayed_exchanges(BASIC_AUTH))
    await upstream.start()
    try:
        relay = client.create_rtsp_relay(
            server_info(upstream.port),
            bind_host="0.0.0.0",  # noqa: S104 - a non-loopback bind is the point
            advertised_host="127.0.0.1",
        )
        async with relay:
            url = relay.stream_url(CAMERA)
            assert url.startswith(f"rtsp://127.0.0.1:{relay.bound_port}/")
            # A consumer that addresses the relay by another name gets relay URLs
            # under the host it addressed.
            other = url.replace("127.0.0.1", "localhost")
            result = await replay(relayed_exchanges(BASIC_AUTH)[:2], other, expect_close=False)
    finally:
        await upstream.stop()
    assert header(result.responses[1][1], "Content-Base") == other


async def scenario_http_disabled() -> None:
    client = make_client()
    with pytest.raises(ValueError, match="server is not serving RTSP"):
        client.create_rtsp_relay(server_info(None))
    with pytest.raises(ValueError, match="server is not serving RTSP"):
        client.unsecured_stream_url(server_info(None), CAMERA)


# --- one test per matrix row --------------------------------------------------


@pytest.mark.asyncio
async def test_default_start_replays_the_allowed_capture() -> None:
    await scenario_default_start_replays_the_allowed_capture()


@pytest.mark.asyncio
async def test_basic_auth_capture_replays_with_the_relays_own_header() -> None:
    await scenario_basic_auth_capture_replays()


@pytest.mark.asyncio
async def test_repeated_stream_url_is_stable_and_a_new_relay_differs() -> None:
    await scenario_repeated_and_new_relay()


@pytest.mark.asyncio
async def test_camera_not_visible_issues_no_identifier() -> None:
    await scenario_camera_not_visible()


@pytest.mark.asyncio
async def test_unknown_identifier_is_404_and_nothing_goes_upstream() -> None:
    await scenario_unknown_identifier()


@pytest.mark.asyncio
async def test_udp_setup_is_461_and_not_forwarded() -> None:
    await scenario_udp_setup()


@pytest.mark.asyncio
async def test_upstream_401_reaches_the_consumer_as_403_without_a_challenge() -> None:
    await scenario_upstream_401_becomes_403()


@pytest.mark.asyncio
async def test_upstream_unreachable_is_503() -> None:
    await scenario_upstream_unreachable()


@pytest.mark.asyncio
async def test_upstream_connect_timeout_is_503(monkeypatch: pytest.MonkeyPatch) -> None:
    await scenario_upstream_times_out(monkeypatch)


@pytest.mark.asyncio
async def test_connection_loss_closes_the_other_side_and_the_relay_keeps_serving() -> None:
    await scenario_connection_loss()


@pytest.mark.asyncio
async def test_oversized_or_malformed_message_closes_the_connection() -> None:
    await scenario_oversized_and_malformed()


@pytest.mark.asyncio
async def test_wildcard_bind_needs_an_advertised_host() -> None:
    await scenario_wildcard_bind_and_advertised_host()


@pytest.mark.asyncio
async def test_http_disabled_produces_neither_url_nor_relay() -> None:
    await scenario_http_disabled()


def test_stream_url_before_start_is_refused() -> None:
    relay = make_client().create_rtsp_relay(server_info(1))
    with pytest.raises(RuntimeError):
        relay.stream_url(CAMERA)
    assert "127.0.0.1" in repr(relay)


def test_bad_bind_port_is_refused() -> None:
    client = make_client()
    with pytest.raises(TypeError):
        client.create_rtsp_relay(server_info(1), bind_port=cast("int", "8554"))
    with pytest.raises(ValueError, match="bind_port"):
        client.create_rtsp_relay(server_info(1), bind_port=70000)


@pytest.mark.asyncio
async def test_unbindable_address_raises_oserror_without_naming_a_stream() -> None:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = int(taken.getsockname()[1])
        relay = make_client().create_rtsp_relay(server_info(1), bind_port=port)
        with pytest.raises(OSError) as caught:  # noqa: PT011 - the documented exception
            await relay.async_start()
    assert "stream" not in str(caught.value)
    for sentinel in SENTINELS:
        assert sentinel not in str(caught.value)


def test_unsecured_stream_url_is_credential_free_and_scoped() -> None:
    client = make_client()
    info = server_info(8000)
    assert client.unsecured_stream_url(info, CAMERA) == (
        "rtsp://127.0.0.1:8000/stream?cameraNum=4&vcodec=h26x&acodec=src"
    )
    with pytest.raises(SecuritySpyPermissionError):
        client.unsecured_stream_url(info, HIDDEN_CAMERA)
    assert isinstance(client.create_rtsp_relay(info), RtspRelay)


# --- review hardening: one identifier is one camera, and nothing hangs ----------


async def scenario_suffix_cannot_steer_the_upstream_query() -> None:
    upstream = FakeUpstream(relayed_exchanges(ALLOWED))
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(
            server_info(upstream.port, (CAMERA, HIDDEN_CAMERA))
        ) as relay:
            url = relay.stream_url(CAMERA)
            for suffix in ("/&cameraNum=5", "/trackID=0/x", "/?cameraNum=5", "/trackID=0&a=b"):
                request = f"DESCRIBE {url}{suffix} RTSP/1.0\r\nCSeq: 2\r\n\r\n"
                reply = await raw_exchange(relay.bound_port, request.encode())
                assert reply == b"RTSP/1.0 404 Not Found\r\nCSeq: 2\r\n\r\n", suffix
    finally:
        await upstream.stop()
    assert upstream.connections == 0


async def scenario_unrelayed_method_is_refused_locally() -> None:
    upstream = FakeUpstream(relayed_exchanges(ALLOWED))
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            url = relay.stream_url(CAMERA)
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.bound_port)
            writer.write(f"SET_PARAMETER {url} RTSP/1.0\r\nCSeq: 9\r\n\r\n".encode())
            await writer.drain()
            message = await asyncio.wait_for(read_message(reader), PATIENCE)
            writer.close()
            await writer.wait_closed()
    finally:
        await upstream.stop()
    assert isinstance(message, tuple)
    assert message[0] == "RTSP/1.0 405 Method Not Allowed"
    assert header(message[1], "CSeq") == "9"
    assert "SET_PARAMETER" not in (header(message[1], "Public") or "")
    assert upstream.connections == 0


async def scenario_options_star_is_answered_but_bounded() -> None:
    async with make_client().create_rtsp_relay(server_info(1)) as relay:
        payload = b"".join(
            f"OPTIONS * RTSP/1.0\r\nCSeq: {n}\r\n\r\n".encode()
            for n in range(relay_module.MAX_UNBOUND_REQUESTS + 2)
        )
        reply = await raw_exchange(relay.bound_port, payload)
    assert reply.count(b"RTSP/1.0 200 OK") == relay_module.MAX_UNBOUND_REQUESTS
    assert b"Public: OPTIONS, DESCRIBE" in reply


async def scenario_rewrites_use_the_port_the_consumer_addressed() -> None:
    exchanges = relayed_exchanges(BASIC_AUTH)[:2]
    upstream = FakeUpstream(exchanges)
    await upstream.start()
    try:
        async with make_client().create_rtsp_relay(server_info(upstream.port)) as relay:
            url = relay.stream_url(CAMERA)
            forwarded = url.replace(f":{relay.bound_port}/", ":18554/")
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.bound_port)
            responses = []
            for exchange in exchanges:
                request = [readdress(exchange.request[0], forwarded), *exchange.request[1:]]
                writer.write(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))
                await writer.drain()
                responses.append(await asyncio.wait_for(read_message(reader), PATIENCE))
            writer.close()
            await writer.wait_closed()
    finally:
        await upstream.stop()
    describe = responses[1]
    assert isinstance(describe, tuple)
    assert header(describe[1], "Content-Base") == forwarded


async def scenario_quiet_consumer_is_closed_before_play() -> None:
    async with make_client(timeout=0.2).create_rtsp_relay(server_info(1)) as relay:
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.bound_port)
        try:
            assert await asyncio.wait_for(reader.read(), PATIENCE) == b""
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()


async def scenario_playing_stream_outlives_the_timeout() -> None:
    timeout = 0.2
    exchanges = relayed_exchanges(ALLOWED)
    upstream = FakeUpstream(exchanges)
    await upstream.start()
    try:
        async with make_client(timeout=timeout).create_rtsp_relay(
            server_info(upstream.port)
        ) as relay:
            url = relay.stream_url(CAMERA)
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.bound_port)
            for exchange in exchanges[:5]:
                request = [readdress(exchange.request[0], url), *exchange.request[1:]]
                writer.write(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))
                await writer.drain()
                assert isinstance(await asyncio.wait_for(read_message(reader), PATIENCE), tuple)
            # Quiet for several timeouts after PLAY, as a consumer between keep-alives is.
            await asyncio.sleep(timeout * 4)
            teardown = [readdress(exchanges[5].request[0], url), *exchanges[5].request[1:]]
            writer.write(("\r\n".join(teardown) + "\r\n\r\n").encode("latin-1"))
            await writer.drain()
            await asyncio.wait_for(upstream.done.wait(), PATIENCE)
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
    finally:
        await upstream.stop()
    assert upstream.requests[-1][0].startswith("TEARDOWN ")
    assert len(upstream.requests) == len(exchanges)


@pytest.mark.asyncio
async def test_a_suffix_cannot_reach_another_camera_or_path() -> None:
    await scenario_suffix_cannot_steer_the_upstream_query()


@pytest.mark.asyncio
async def test_an_unrelayed_method_is_405_and_not_forwarded() -> None:
    await scenario_unrelayed_method_is_refused_locally()


@pytest.mark.asyncio
async def test_options_star_is_answered_locally_and_bounded() -> None:
    await scenario_options_star_is_answered_but_bounded()


@pytest.mark.asyncio
async def test_rewrites_use_the_port_the_consumer_addressed() -> None:
    await scenario_rewrites_use_the_port_the_consumer_addressed()


@pytest.mark.asyncio
async def test_a_quiet_consumer_is_closed_before_play() -> None:
    await scenario_quiet_consumer_is_closed_before_play()


@pytest.mark.asyncio
async def test_a_playing_stream_is_not_closed_by_the_timeout() -> None:
    await scenario_playing_stream_outlives_the_timeout()


@pytest.mark.asyncio
async def test_a_closed_upstream_is_never_reopened() -> None:
    relay = make_client().create_rtsp_relay(server_info(1))
    session = relay_module._RelaySession(  # noqa: SLF001 - the flag has no public observer
        relay,
        cast("asyncio.StreamReader", object()),
        cast("asyncio.StreamWriter", object()),
    )
    session._upstream_closed = True  # noqa: SLF001
    request = relay_module._Message("OPTIONS rtsp://h:1/x RTSP/1.0", [], b"")  # noqa: SLF001
    assert await session._handle_request(request) is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_bind_on_several_ports_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[bool] = []

    class FakeSocket:
        def __init__(self, port: int) -> None:
            self.port = port

        def getsockname(self) -> tuple[str, int]:
            return ("::1", self.port)

    class FakeServer:
        sockets = (FakeSocket(40001), FakeSocket(40002))

        def close(self) -> None:
            closed.append(True)

        async def wait_closed(self) -> None:
            return None

    async def start_server(*_args: object, **_kwargs: object) -> FakeServer:
        return FakeServer()

    monkeypatch.setattr(asyncio, "start_server", start_server)
    relay = make_client().create_rtsp_relay(server_info(1), bind_host="localhost")
    with pytest.raises(ValueError, match="single address"):
        await relay.async_start()
    assert closed == [True]
    with pytest.raises(RuntimeError):
        _ = relay.bound_port


def test_stream_url_rejects_a_non_integer_like_unsecured_stream_url() -> None:
    client = make_client()
    info = server_info(8000)
    for bad in (cast("int", "4"), cast("int", True), -1):  # noqa: FBT003 - a bool must be refused
        with pytest.raises(ValueError, match="camera"):
            client.unsecured_stream_url(info, bad)
    relay = client.create_rtsp_relay(info)
    relay._bound_port = 1  # noqa: SLF001 - no socket is needed to validate
    for bad in (cast("int", "4"), cast("int", True), -1):  # noqa: FBT003 - a bool must be refused
        with pytest.raises(ValueError, match="camera_number"):
            relay.stream_url(bad)


@pytest.mark.asyncio
async def test_hardening_scenarios_log_nothing_secret(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    issued: list[str] = []
    original = RtspRelay.stream_url

    def recording(self: RtspRelay, camera_number: int) -> str:
        url = original(self, camera_number)
        issued.append(relay_id(url))
        return url

    monkeypatch.setattr(RtspRelay, "stream_url", recording)
    with caplog.at_level(logging.DEBUG), caplog.at_level(0, logger="aiosecurityspy"):
        await scenario_suffix_cannot_steer_the_upstream_query()
        await scenario_unrelayed_method_is_refused_locally()
        await scenario_options_star_is_answered_but_bounded()
        await scenario_rewrites_use_the_port_the_consumer_addressed()
        await scenario_quiet_consumer_is_closed_before_play()
        await scenario_playing_stream_outlives_the_timeout()

    assert issued
    assert any(r.name == "aiosecurityspy.relay" for r in caplog.records)
    for value in (
        *SENTINELS,
        aiohttp.encode_basic_auth(USERNAME, PASSWORD),
        b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode(),
        "Authorization",
        "cameraNum",
        "trackID",
        "rtsp:",
        "18554",
        *issued,
    ):
        assert value not in caplog.text, value


# --- AC4: nothing secret or stream-addressing reaches a log record ---------------


@pytest.mark.asyncio
async def test_no_scenario_logs_a_credential_identifier_or_path(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    issued: list[str] = []
    original = RtspRelay.stream_url

    def recording(self: RtspRelay, camera_number: int) -> str:
        url = original(self, camera_number)
        issued.append(relay_id(url))
        return url

    monkeypatch.setattr(RtspRelay, "stream_url", recording)
    # Root at DEBUG as well: see the containment sweep for why level 0 alone
    # captures nothing.
    with caplog.at_level(logging.DEBUG), caplog.at_level(0, logger="aiosecurityspy"):
        await scenario_default_start_replays_the_allowed_capture()
        await scenario_basic_auth_capture_replays()
        await scenario_upstream_401_becomes_403()
        await scenario_repeated_and_new_relay()
        await scenario_camera_not_visible()
        await scenario_unknown_identifier()
        await scenario_udp_setup()
        await scenario_upstream_unreachable()
        await scenario_upstream_times_out(monkeypatch)
        await scenario_connection_loss()
        await scenario_oversized_and_malformed()
        await scenario_wildcard_bind_and_advertised_host()
        await scenario_http_disabled()

    relay_records = [r for r in caplog.records if r.name == "aiosecurityspy.relay"]
    assert len(relay_records) >= 10, len(relay_records)  # noqa: PLR2004 - not an empty haystack
    levels = {r.levelno for r in relay_records}
    assert {logging.DEBUG, logging.INFO, logging.WARNING} <= levels
    text = caplog.text
    forbidden = [
        *SENTINELS,
        aiohttp.encode_basic_auth(USERNAME, PASSWORD),
        b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode(),
        "Authorization",
        "bogus-id-7f3a",
        "cameraNum",
        "trackID",
        "rtsp:",
        *issued,
    ]
    assert issued
    for value in forbidden:
        assert value not in text, value
