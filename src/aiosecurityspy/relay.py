"""A local RTSP relay that hands out stream addresses carrying no credential.

SecuritySpy's RTSP stream needs the account credential, and the only ways an
ordinary RTSP consumer (ffmpeg, go2rtc, VLC, Frigate) can supply it put it in
the URL -- ``user:pass@`` or ``auth=`` -- where tools echo it into logs. This
relay sits in between: the consumer is given ``rtsp://<relay>/<id>``, where
``<id>`` is an unguessable per-camera token, and the relay opens the upstream
connection itself, authenticating with an ``Authorization: Basic`` header only.

Everything SecuritySpy echoes back that names its own address -- ``Content-Base``,
``Content-Location``, every ``url=`` in ``RTP-Info``, and any URL in an SDP
body -- is rewritten to the relay's address, including SecuritySpy's malformed
single-slash ``rtsp:/host:port/...`` form. Interleaved ``$`` frames are copied
untouched in both directions; RTP payloads are never parsed.

The credential is attached to requests the relay composes, never to anything
the consumer chose. An identifier grants exactly one camera: the only path
allowed after it is a ``/trackID=N`` control, only the methods and headers a
player needs are forwarded, request bodies are not, and a header carrying a
line break or other control character closes the connection. Only allowlisted
response headers reach the consumer, so nothing else can name the server, and
a redirect is answered as a gateway error rather than followed around the relay.

Only RTSP over TCP (interleaved) is supported: no UDP, no RTSPS, no fan-out.
The upstream leg is cleartext RTSP on the LAN, as SecuritySpy offers no RTSPS.

Log records never contain the credential, a relay identifier or a requested
path: an identifier *is* access to a camera, and a path contains one.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import secrets
from typing import TYPE_CHECKING, Final, Self, cast

from .connection import validate_host
from .const import PERM_LIVEVIDEO, PERMISSION_NAMES
from .exceptions import SecuritySpyPermissionError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import TracebackType

    from .connection import _ConnectionSettings

__all__ = ["RtspRelay"]

_LOGGER: Final = logging.getLogger(__name__)

#: Longest RTSP message head (start line plus headers) accepted from either side.
MAX_HEAD_BYTES: Final = 8 * 1024
#: Longest RTSP message body accepted from either side. SDP bodies are a few
#: hundred bytes; the cap only bounds memory against a hostile peer.
MAX_BODY_BYTES: Final = 1024 * 1024
#: Requests answered locally (``OPTIONS *``, a refused method) before a
#: connection has named a stream.
MAX_UNBOUND_REQUESTS: Final = 4
#: Consumer connections one relay serves at once. Each playing connection holds
#: an authenticated upstream socket, so the cap also bounds SecuritySpy's load.
MAX_CONNECTIONS: Final = 16
#: Longest a connection may stay open before naming a stream, in seconds (or
#: the client's timeout, if shorter). Keeps a peer holding no identifier from
#: occupying connection slots for long.
UNBOUND_SECONDS: Final = 5.0

#: Highest first channel of an interleaved pair, so the pair stays in 0-255.
_MAX_CHANNEL: Final = 254
_INTERLEAVED_PAIR_RE: Final = re.compile(r"interleaved=(\d{1,3})-(\d{1,3})", re.IGNORECASE)

_HEAD_END: Final = b"\r\n\r\n"
_INTERLEAVED_MARKER: Final = 0x24  # "$"
_RTSP_VERSION: Final = "RTSP/1.0"
_REQUEST_LINE_PARTS: Final = 3
_STATUS_UNAUTHORIZED: Final = "401"
_MAX_PORT: Final = 65535

#: The methods a player needs, and the only ones forwarded with the credential.
#: SecuritySpy's ``Public`` header lists all but ``GET_PARAMETER``, which
#: consumers use as a keep-alive.
_RELAYED_METHODS: Final = (
    "OPTIONS",
    "DESCRIBE",
    "SETUP",
    "PLAY",
    "PAUSE",
    "TEARDOWN",
    "GET_PARAMETER",
)
#: Consumer request headers forwarded upstream: those the captured ffmpeg
#: sessions send, plus the RTSP playback-rate headers. Everything else is
#: dropped, and the relay adds its own ``Authorization``.
_FORWARDED_REQUEST_HEADERS: Final = frozenset(
    {
        "cseq",
        "session",
        "transport",
        "range",
        "accept",
        "user-agent",
        "x-dynamic-rate",
        "bandwidth",
        "scale",
        "speed",
    }
)
#: SecuritySpy response headers passed to the consumer: those in the captured
#: exchanges that neither challenge for a credential nor identify the server.
#: ``Content-Length`` is always recomputed.
_FORWARDED_RESPONSE_HEADERS: Final = frozenset(
    {
        "cseq",
        "session",
        "transport",
        "range",
        "rtp-info",
        "content-base",
        "content-location",
        "content-type",
        "public",
        "cache-control",
        "pragma",
        "date",
        "expires",
        "ss-ptz",
        "x-accept-retransmit",
        "x-accept-dynamic-rate",
        "x-retransmit",
        "x-dynamic-rate",
        "x-transport-options",
    }
)

#: Any RTSP URL, in both the well-formed ``rtsp://`` and SecuritySpy's
#: single-slash ``rtsp:/`` spelling. The authority is followed, when present,
#: by SecuritySpy's ``/stream?query`` -- the query stops at ``/`` so a
#: ``/trackID=0`` suffix survives the rewrite.
_UPSTREAM_URL_RE: Final = re.compile(
    r"rtsp:/{1,2}[^\s/;,\"'<>]+(?:/stream(?:\?[^\s;,/\"'<>]*)?)?", re.IGNORECASE
)
#: A consumer request URL: authority, identifier, and at most a ``/trackID=N``
#: control or a bare trailing slash. Any other suffix would be appended to the
#: upstream query string -- ``/cameraNum=9`` included -- so it does not match
#: and is refused like an unknown identifier.
_REQUEST_URL_RE: Final = re.compile(
    r"^rtsp:/{1,2}(?P<authority>[^\s/]+)/(?P<id>[A-Za-z0-9_-]+)"
    r"(?:/(?:trackID=(?P<track>\d{1,3}))?)?$",
    re.IGNORECASE,
)
#: The authority a consumer addressed, restricted to characters a host or port
#: can contain so nothing else reaches a rewritten header.
_AUTHORITY_RE: Final = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(?P<port>\d{1,5}))?$"
)
#: A byte that must never appear inside a start line, header name or value:
#: every C0 control but horizontal tab, and DEL. A lone CR or LF is how a
#: second request is smuggled inside one header.
_CONTROL_RE: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_HEADER_NAME_RE: Final = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_INTERLEAVED_RE: Final = re.compile(r"interleaved=(\d{1,3})(?:-(\d{1,3}))?", re.IGNORECASE)
_CSEQ_RE: Final = re.compile(r"^\d{1,10}$")
_TOKEN_BYTES: Final = 16


class _MalformedMessageError(Exception):
    """A peer sent something that is not a well-formed, bounded RTSP message."""


class _Message:
    """One parsed RTSP message: a start line, ordered headers and a body."""

    __slots__ = ("body", "headers", "start_line")

    def __init__(self, start_line: str, headers: list[tuple[str, str]], body: bytes) -> None:
        self.start_line = start_line
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def to_bytes(self) -> bytes:
        headers = [(k, v) for k, v in self.headers if k.lower() != "content-length"]
        if self.body:
            headers.append(("Content-Length", str(len(self.body))))
        lines = [self.start_line, *(f"{key}: {value}" for key, value in headers)]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + self.body


async def _read_message(reader: asyncio.StreamReader) -> bytes | _Message | None:
    """Read one interleaved frame (returned raw) or one RTSP message.

    Returns ``None`` on a clean end of stream between messages.

    Raises:
        _MalformedMessageError: The head is oversized or unparseable, carries a
            control character, or the body is over :data:`MAX_BODY_BYTES`.
        asyncio.IncompleteReadError: The peer closed mid-message.

    """
    first = await reader.read(1)
    if not first:
        return None
    if first[0] == _INTERLEAVED_MARKER:
        prefix = await reader.readexactly(3)
        length = int.from_bytes(prefix[1:3], "big")
        return first + prefix + await reader.readexactly(length)
    head = bytearray(first)
    while not head.endswith(_HEAD_END):
        if len(head) >= MAX_HEAD_BYTES:
            raise _MalformedMessageError
        chunk = await reader.read(1)
        if not chunk:
            raise asyncio.IncompleteReadError(bytes(head), None)
        head += chunk
    text = bytes(head[: -len(_HEAD_END)]).decode("latin-1")
    start_line, *header_lines = text.split("\r\n")
    if _CONTROL_RE.search(start_line):
        raise _MalformedMessageError
    headers: list[tuple[str, str]] = []
    for line in header_lines:
        name, sep, value = line.partition(":")
        name = name.strip()
        if not sep or not _HEADER_NAME_RE.match(name) or _CONTROL_RE.search(value):
            raise _MalformedMessageError
        headers.append((name, value.strip()))
    if sum(1 for name, _ in headers if name.lower() == "content-length") > 1:
        raise _MalformedMessageError
    message = _Message(start_line, headers, b"")
    declared = message.header("Content-Length")
    if declared is not None:
        if not declared.isascii() or not declared.isdigit():
            raise _MalformedMessageError
        length = int(declared)
        if length > MAX_BODY_BYTES:
            raise _MalformedMessageError
        message.body = await reader.readexactly(length)
    return message


def _is_wildcard(host: str) -> bool:
    candidate = host.strip().strip("[]")
    if not candidate:
        return True
    try:
        return ipaddress.ip_address(candidate).is_unspecified
    except ValueError:
        return False


async def _open_upstream(
    host: str, port: int, deadline: float
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open the upstream TCP connection, bounded by the client's timeout."""
    async with asyncio.timeout(deadline):
        return await asyncio.open_connection(host, port, limit=MAX_HEAD_BYTES * 2)


async def _drain(writer: asyncio.StreamWriter, deadline: float) -> None:
    """Flush, bounded: a peer that stops reading must not stall the other side forever."""
    async with asyncio.timeout(deadline):
        await writer.drain()


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


def _status_code(message: _Message) -> str:
    parts = message.start_line.split(" ", 2)
    return parts[1] if len(parts) >= 2 else ""  # noqa: PLR2004 - version, code


def _interleaved_transport(header: str) -> str | None:
    """Return the single transport the relay sends upstream for a SETUP, or ``None``.

    The consumer's header is never forwarded: it may list a UDP transport (even
    one with a ``destination=``) ahead of the TCP one. The relay takes the first
    ``RTP/AVP/TCP`` entry carrying an ``interleaved=a-(a+1)`` pair and rebuilds
    exactly that, so SecuritySpy is only ever offered interleaved TCP.
    """
    for spec in header.split(","):
        params = [param.strip() for param in spec.split(";")]
        if params[0].upper() != "RTP/AVP/TCP":
            continue
        for param in params[1:]:
            found = _INTERLEAVED_PAIR_RE.fullmatch(param)
            if found is None:
                continue
            first, second = int(found[1]), int(found[2])
            if first <= _MAX_CHANNEL and second == first + 1:
                return f"RTP/AVP/TCP;unicast;interleaved={first}-{second}"
    return None


def _simple_response(
    status: str, request: _Message | None, extra: Iterable[tuple[str, str]] = ()
) -> bytes:
    headers: list[tuple[str, str]] = []
    cseq = request.header("CSeq") if request is not None else None
    if cseq is not None and _CSEQ_RE.match(cseq):
        headers.append(("CSeq", cseq))
    headers.extend(extra)
    return _Message(f"{_RTSP_VERSION} {status}", headers, b"").to_bytes()


class RtspRelay:
    """Relay SecuritySpy live video to RTSP consumers without handing out a credential.

    Construct one with :meth:`SecuritySpyClient.create_rtsp_relay
    <aiosecurityspy.SecuritySpyClient.create_rtsp_relay>`, start it, then hand
    each consumer :meth:`stream_url`. Each consumer connection gets its own
    upstream connection; when either side closes, so does the other. At most
    :data:`MAX_CONNECTIONS` consumer connections are served at once.

    Example:
        >>> async def main(client, server_info) -> None:
        ...     async with client.create_rtsp_relay(server_info) as relay:
        ...         url = relay.stream_url(4)  # rtsp://127.0.0.1:<port>/<id>

    """

    def __init__(  # noqa: PLR0913 - upstream identity plus the three bind choices; the latter are keyword-only
        self,
        connection: _ConnectionSettings,
        rtsp_port: int,
        cameras: Iterable[int],
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        advertised_host: str | None = None,
    ) -> None:
        """Prepare a relay; nothing listens until :meth:`async_start`.

        Args:
            connection: The client's validated connection settings -- the
                relay's only source of the upstream host and credential.
            rtsp_port: The server's RTSP port (:attr:`ServerInfo.rtsp_port`).
            cameras: The camera numbers the account may view live.
            bind_host: Local address to listen on. Loopback by default.
            bind_port: Local port to listen on; ``0`` picks a free one.
            advertised_host: Host placed in :meth:`stream_url`. Required when
                ``bind_host`` is a wildcard such as ``0.0.0.0``, since a
                wildcard is not an address a consumer can connect to.

        Raises:
            ValueError: ``bind_host`` is a wildcard and no ``advertised_host``
                was given, or a host or port is unusable.
            TypeError: ``bind_port`` is not an integer.

        """
        if isinstance(bind_port, bool) or not isinstance(cast("object", bind_port), int):
            msg = "bind_port must be an integer"
            raise TypeError(msg)
        if not 0 <= bind_port <= _MAX_PORT:
            msg = "bind_port must be between 0 and 65535"
            raise ValueError(msg)
        if advertised_host is None:
            if _is_wildcard(bind_host):
                msg = "advertised_host is required when bind_host is a wildcard address"
                raise ValueError(msg)
            _, url_host = validate_host(bind_host)
        else:
            _, url_host = validate_host(advertised_host)
        self._connection = connection
        self._rtsp_port = rtsp_port
        self._cameras = frozenset(cameras)
        self._bind_host = bind_host
        self._bind_port = bind_port
        self._advertised_url_host = url_host
        self._ids: dict[int, str] = {}
        self._server: asyncio.Server | None = None
        self._bound_port: int | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    def __repr__(self) -> str:
        """Return a representation carrying no credential, identifier or path."""
        return f"RtspRelay(bind_host={self._bind_host!r}, bound_port={self._bound_port})"

    __str__ = __repr__

    @property
    def bound_port(self) -> int:
        """The local port the relay is listening on.

        Raises:
            RuntimeError: The relay has not been started.

        """
        if self._bound_port is None:
            msg = "the relay is not started"
            raise RuntimeError(msg)
        return self._bound_port

    async def async_start(self) -> None:
        """Start listening.

        Raises:
            OSError: ``bind_host``/``bind_port`` cannot be bound. The message
                names neither a stream nor a credential.
            ValueError: ``bind_host`` resolved to several addresses that were
                given different ports (``bind_port=0`` with a name such as
                ``localhost``), so no single relay port exists to advertise.

        """
        if self._server is not None:
            return
        server = await asyncio.start_server(
            self._handle_consumer, self._bind_host, self._bind_port, limit=MAX_HEAD_BYTES * 2
        )
        ports = {int(sock.getsockname()[1]) for sock in server.sockets}
        if len(ports) != 1:
            server.close()
            await server.wait_closed()
            msg = "bind_host must resolve to a single address when bind_port is 0"
            raise ValueError(msg)
        self._server = server
        self._bound_port = ports.pop()

    async def async_stop(self) -> None:
        """Stop listening and close every relayed connection."""
        server, self._server = self._server, None
        if server is None:
            return
        server.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await server.wait_closed()
        self._bound_port = None

    async def __aenter__(self) -> Self:
        """Start the relay."""
        await self.async_start()
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        """Stop the relay."""
        await self.async_stop()

    def stream_url(self, camera_number: int) -> str:
        """Return the credential-free relay URL for one camera.

        The identifier is issued on first request and fixed for the relay's
        life; a different relay issues a different one.

        Raises:
            ValueError: ``camera_number`` is not a non-negative integer.
            SecuritySpyPermissionError: The camera is not among those the
                account may view live. No identifier is issued.
            RuntimeError: The relay has not been started.

        """
        supplied: object = camera_number
        if not isinstance(supplied, int) or isinstance(supplied, bool) or supplied < 0:
            msg = "camera_number must be a non-negative integer"
            raise ValueError(msg)
        if camera_number not in self._cameras:
            raise SecuritySpyPermissionError(PERMISSION_NAMES[PERM_LIVEVIDEO], camera_number)
        port = self.bound_port
        token = self._ids.get(camera_number)
        if token is None:
            token = secrets.token_urlsafe(_TOKEN_BYTES)
            self._ids[camera_number] = token
        return f"rtsp://{self._advertised_url_host}:{port}/{token}"

    # --- per-connection work ----------------------------------------------------

    def _camera_for(self, token: str) -> int | None:
        found: int | None = None
        for camera, issued in self._ids.items():
            if secrets.compare_digest(issued, token):
                found = camera
        return found

    def _upstream_base(self, camera: int) -> str:
        return (
            f"rtsp://{self._connection.url_host}:{self._rtsp_port}"
            f"/stream?cameraNum={camera}&vcodec=h26x&acodec=src"
        )

    async def _handle_consumer(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if len(self._tasks) >= MAX_CONNECTIONS:
            _LOGGER.info("Relay refused a connection: already serving the maximum")
            writer.write(_simple_response("503 Service Unavailable", None))
            with contextlib.suppress(Exception):
                await _drain(writer, self._connection.timeout)
            await _close_writer(writer)
            return
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        session = _RelaySession(self, reader, writer)
        try:
            await session.run()
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001 - a per-connection failure must never escape
            _LOGGER.debug("Relayed connection ended with %s", type(err).__name__)
        finally:
            await session.close()
            if task is not None:
                self._tasks.discard(task)


class _RelaySession:
    """One consumer connection and, once opened, its upstream connection."""

    def __init__(
        self, relay: RtspRelay, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._relay = relay
        self._reader = reader
        self._writer = writer
        self._timeout = relay._connection.timeout  # noqa: SLF001 - one module
        self._upstream_writer: asyncio.StreamWriter | None = None
        self._upstream_closed = False
        self._camera: int | None = None
        self._consumer_host = relay._advertised_url_host  # noqa: SLF001 - one module
        self._consumer_port: int | None = None
        self._pump: asyncio.Task[None] | None = None
        self._unbound_requests = 0
        #: Forwarded requests awaiting SecuritySpy's answer, by CSeq.
        self._pending: dict[int, str] = {}
        self._last_cseq = -1
        #: Interleaved channels a successful SETUP negotiated; only these carry
        #: consumer frames upstream.
        self._channels: set[int] = set()
        self._playing = False
        self._read_deadline: asyncio.Timeout | None = None

    async def close(self) -> None:
        pump, self._pump = self._pump, None
        if pump is not None and pump is not asyncio.current_task():
            pump.cancel()
            with contextlib.suppress(BaseException):
                await pump
        upstream, self._upstream_writer = self._upstream_writer, None
        await _close_writer(upstream)
        await _close_writer(self._writer)

    def _read_timeout(self, unbound_deadline: float) -> asyncio.Timeout:
        # Before a stream is named, the whole connection has one deadline, so
        # repeated local answers cannot hold it open. Until the stream plays, a
        # consumer that goes quiet -- or waits on an answer that never comes --
        # is closed after the client's timeout. Once playing, keep-alives may be
        # tens of seconds apart.
        if self._playing:
            return asyncio.timeout(None)
        if self._camera is None:
            return asyncio.timeout_at(unbound_deadline)
        return asyncio.timeout(self._timeout)

    async def run(self) -> None:
        unbound_deadline = asyncio.get_running_loop().time() + min(self._timeout, UNBOUND_SECONDS)
        try:
            while True:
                async with self._read_timeout(unbound_deadline) as deadline:
                    self._read_deadline = deadline
                    message = await _read_message(self._reader)
                self._read_deadline = None
                if message is None:
                    _LOGGER.debug("Consumer closed a relayed connection")
                    return
                if isinstance(message, bytes):
                    upstream = self._upstream_writer
                    if upstream is None or message[1] not in self._channels:
                        _LOGGER.debug("Consumer sent an interleaved frame on no negotiated channel")
                        return
                    upstream.write(message)
                    await _drain(upstream, self._timeout)
                    continue
                if not await self._handle_request(message):
                    return
        except _MalformedMessageError:
            _LOGGER.info("Relay closed a connection after a malformed or oversized message")
        except TimeoutError:
            _LOGGER.info("Relay closed a connection that went quiet or stopped reading")
        except asyncio.IncompleteReadError, ConnectionError:
            _LOGGER.debug("Consumer connection lost")

    async def _refuse(
        self, status: str, request: _Message | None, extra: Iterable[tuple[str, str]] = ()
    ) -> None:
        self._writer.write(_simple_response(status, request, extra))
        with contextlib.suppress(ConnectionError, TimeoutError):
            await _drain(self._writer, self._timeout)

    async def _answer_locally(
        self, status: str, request: _Message, extra: Iterable[tuple[str, str]]
    ) -> bool:
        """Answer without going upstream. Returns ``False`` to close."""
        await self._refuse(status, request, extra)
        if self._camera is None:
            self._unbound_requests += 1
            if self._unbound_requests >= MAX_UNBOUND_REQUESTS:
                _LOGGER.info("Relay closed a connection that never named a stream")
                return False
        return True

    async def _handle_request(self, request: _Message) -> bool:  # noqa: PLR0911 - each refusal is its own early exit
        """Answer, refuse, or map and forward one consumer request. Returns ``False`` to close."""
        if self._upstream_closed:
            return False
        parts = request.start_line.split(" ")
        if len(parts) != _REQUEST_LINE_PARTS or parts[2] != _RTSP_VERSION:
            _LOGGER.info("Relay closed a connection after a malformed or oversized message")
            return False
        method, url, version = parts
        verb = method.upper()
        public = [("Public", ", ".join(_RELAYED_METHODS))]
        if verb == "OPTIONS" and url == "*":
            return await self._answer_locally("200 OK", request, public)
        if verb not in _RELAYED_METHODS:
            _LOGGER.info("Relay refused an RTSP method it does not relay")
            return await self._answer_locally("405 Method Not Allowed", request, public)
        match = _REQUEST_URL_RE.match(url)
        camera = self._relay._camera_for(match["id"]) if match else None  # noqa: SLF001
        if match is None or camera is None or self._camera not in {None, camera}:
            _LOGGER.info("Relay refused a request for an unknown stream")
            await self._refuse("404 Not Found", request)
            return False
        forwarded = [
            k.lower() for k, _ in request.headers if k.lower() in _FORWARDED_REQUEST_HEADERS
        ]
        cseq = request.header("CSeq")
        if (
            len(forwarded) != len(set(forwarded))
            or cseq is None
            or not _CSEQ_RE.match(cseq)
            or int(cseq) <= self._last_cseq
        ):
            # CSeq pairs a response with its request, and that pairing decides
            # when a stream is playing: a missing or reused one could forge it.
            # A repeated header would let a second value slip past the check
            # made on the first, so any repeat is refused.
            _LOGGER.info("Relay closed a connection after a repeated header or a bad CSeq")
            await self._refuse("400 Bad Request", request)
            return False
        transport: str | None = None
        if verb == "SETUP":
            transport = _interleaved_transport(request.header("Transport") or "")
            if transport is None:
                _LOGGER.info("Relay refused a SETUP that did not ask for interleaved TCP")
                await self._refuse("461 Unsupported Transport", request)
                return True
        self._remember_authority(match["authority"])
        if self._upstream_writer is None and not await self._connect(camera, request):
            return False
        upstream = self._upstream_writer
        if upstream is None:  # pragma: no cover - `_connect` set it or returned False
            return False
        sequence = int(cseq)
        self._last_cseq = sequence
        self._pending[sequence] = verb
        track = match["track"]
        suffix = f"/trackID={int(track)}" if track is not None else ""
        headers = [
            (k, v)
            for k, v in request.headers
            if k.lower() in _FORWARDED_REQUEST_HEADERS and k.lower() != "transport"
        ]
        if transport is not None:
            headers.append(("Transport", transport))
        headers.append(("Authorization", self._relay._connection.auth_header))  # noqa: SLF001
        target = self._relay._upstream_base(camera) + suffix  # noqa: SLF001
        upstream.write(_Message(f"{method} {target} {version}", headers, b"").to_bytes())
        await _drain(upstream, self._timeout)
        return True

    def _remember_authority(self, authority_text: str) -> None:
        """Rewrite to the host and port the consumer addressed, e.g. through NAT."""
        authority = _AUTHORITY_RE.match(authority_text)
        if authority is None:
            return
        self._consumer_host = authority["host"]
        port = authority["port"]
        if port is not None and 1 <= int(port) <= _MAX_PORT:
            self._consumer_port = int(port)

    async def _connect(self, camera: int, request: _Message) -> bool:
        connection = self._relay._connection  # noqa: SLF001 - one module
        try:
            reader, writer = await _open_upstream(
                connection.host,
                self._relay._rtsp_port,  # noqa: SLF001 - one module
                connection.timeout,
            )
        except (OSError, TimeoutError) as err:
            _LOGGER.warning(
                "Relay could not reach SecuritySpy's RTSP service (%s)", type(err).__name__
            )
            await self._refuse("503 Service Unavailable", request)
            return False
        self._camera = camera
        self._upstream_writer = writer
        self._pump = asyncio.create_task(self._pump_upstream(reader))
        return True

    async def _pump_upstream(self, reader: asyncio.StreamReader) -> None:
        """Copy upstream to the consumer, rewriting RTSP responses."""
        try:
            while True:
                message = await _read_message(reader)
                if message is None:
                    _LOGGER.debug("SecuritySpy closed a relayed connection")
                    break
                if isinstance(message, bytes):
                    self._writer.write(message)
                else:
                    if not message.start_line.startswith(_RTSP_VERSION + " "):
                        _LOGGER.info("Relay closed a connection after a malformed upstream message")
                        break
                    self._note_response(message)
                    self._writer.write(self._rewrite_response(message).to_bytes())
                await _drain(self._writer, self._timeout)
        except _MalformedMessageError:
            _LOGGER.info("Relay closed a connection after a malformed or oversized message")
        except asyncio.IncompleteReadError, ConnectionError:
            _LOGGER.debug("Upstream connection lost")
        except Exception as err:  # noqa: BLE001 - a per-connection failure must never escape
            _LOGGER.debug("Upstream pump ended with %s", type(err).__name__)
        # Either side closing closes the other, and a closed upstream is never
        # reopened: ending the consumer's read loop is done by closing its
        # transport, which `run` observes as EOF.
        self._upstream_closed = True
        self._pump = None
        upstream, self._upstream_writer = self._upstream_writer, None
        await _close_writer(upstream)
        self._writer.close()

    def _note_response(self, response: _Message) -> None:
        """Settle the pending request this answers: a SETUP's channels, a PLAY's start."""
        cseq = response.header("CSeq")
        # Compared as numbers: a server may echo "01" as "1", and a player may pad.
        sequence = int(cseq) if cseq is not None and _CSEQ_RE.match(cseq) else None
        verb = self._pending.pop(sequence, None) if sequence is not None else None
        if verb is None or not _status_code(response).startswith("2"):
            return
        if verb == "SETUP":
            found = _INTERLEAVED_RE.search(response.header("Transport") or "")
            if found is not None:
                first = int(found[1])
                last = int(found[2]) if found[2] is not None else first
                self._channels.update(range(first, min(last, first + 1) + 1))
        elif verb == "PLAY" and self._channels:
            self._playing = True
            deadline = self._read_deadline
            if deadline is not None and not deadline.expired():
                deadline.reschedule(None)

    def _relay_base(self) -> str:
        camera = self._camera
        token = self._relay._ids[camera] if camera is not None else ""  # noqa: SLF001
        port = self._consumer_port if self._consumer_port is not None else self._relay.bound_port
        return f"rtsp://{self._consumer_host}:{port}/{token}"

    def _rewrite_response(self, response: _Message) -> _Message:
        base = self._relay_base()

        def rewrite(text: str) -> str:
            return _UPSTREAM_URL_RE.sub(lambda _match: base, text)

        status = _status_code(response)
        start_line = response.start_line
        if status == _STATUS_UNAUTHORIZED:
            _LOGGER.warning(
                "SecuritySpy refused the relayed stream (401); the account's credential "
                "or its live-video access to this camera may have changed"
            )
            start_line = f"{_RTSP_VERSION} 403 Forbidden"
        elif status.startswith("3"):
            # A redirect would send the consumer to SecuritySpy directly, around
            # the relay and with no credential; it is answered as a gateway error.
            _LOGGER.warning("SecuritySpy answered a relayed request with a redirect")
            start_line = f"{_RTSP_VERSION} 502 Bad Gateway"
        headers = [
            (name, rewrite(value))
            for name, value in response.headers
            if name.lower() in _FORWARDED_RESPONSE_HEADERS
        ]
        body = response.body
        if body:
            body = rewrite(body.decode("latin-1")).encode("latin-1")
        return _Message(start_line, headers, body)
