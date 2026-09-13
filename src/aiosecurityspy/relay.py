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
single-slash ``rtsp:/host:port/...`` form. Headers that would prompt for a
credential or identify the server are dropped. Interleaved ``$`` frames are
copied untouched in both directions; RTP payloads are never parsed.

An identifier grants exactly one camera: the only path allowed after it is a
track control such as ``/trackID=0``, and only the methods a player needs are
forwarded, so a consumer cannot steer the credential at anything else.

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
#: connection has named a stream. Bounds how long a consumer holding no
#: identifier can keep a connection open.
MAX_UNBOUND_REQUESTS: Final = 4

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

#: Headers never passed to the consumer: a challenge would prompt it for a
#: credential, and the other two identify the server.
_DROPPED_RESPONSE_HEADERS: Final = frozenset({"www-authenticate", "ss-uuid", "server"})
#: Response headers whose value may carry an upstream URL.
_URL_HEADERS: Final = frozenset({"content-base", "content-location", "rtp-info"})

#: Any RTSP URL, in both the well-formed ``rtsp://`` and SecuritySpy's
#: single-slash ``rtsp:/`` spelling. The authority is followed, when present,
#: by SecuritySpy's ``/stream?query`` -- the query stops at ``/`` so a
#: ``/trackID=0`` suffix survives the rewrite.
_UPSTREAM_URL_RE: Final = re.compile(
    r"rtsp:/{1,2}[^\s/;,\"'<>]+(?:/stream(?:\?[^\s;,/\"'<>]*)?)?", re.IGNORECASE
)
#: A consumer request URL: authority, identifier, and at most a track control
#: (``/trackID=0``) or a bare trailing slash. Anything else -- a second path
#: segment, ``?``, ``&`` -- would be appended to the upstream query string, so
#: it does not match and is refused like an unknown identifier.
_REQUEST_URL_RE: Final = re.compile(
    r"^rtsp:/{1,2}(?P<authority>[^\s/]+)/(?P<id>[A-Za-z0-9_-]+)"
    r"(?P<suffix>/(?:[A-Za-z]+=\d{1,5})?)?$",
    re.IGNORECASE,
)
#: The authority a consumer addressed, restricted to characters a host or port
#: can contain so nothing else reaches a rewritten header.
_AUTHORITY_RE: Final = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::(?P<port>\d{1,5}))?$"
)
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
        _MalformedMessageError: The head is oversized or unparseable, or the
            body is over :data:`MAX_BODY_BYTES`.
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
    try:
        text = bytes(head[: -len(_HEAD_END)]).decode("latin-1")
    except UnicodeDecodeError as err:  # pragma: no cover - latin-1 decodes every byte
        raise _MalformedMessageError from err
    start_line, *header_lines = text.split("\r\n")
    headers: list[tuple[str, str]] = []
    for line in header_lines:
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            raise _MalformedMessageError
        headers.append((name.strip(), value.strip()))
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


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


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
    upstream connection; when either side closes, so does the other.

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
        self._play_cseqs: set[str] = set()
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

    async def run(self) -> None:
        try:
            while True:
                # Until the stream is playing, a consumer that goes quiet --
                # never sending a request, or waiting on a response SecuritySpy
                # never sends -- is closed after the client's timeout. Once
                # playing, keep-alives may be tens of seconds apart.
                async with asyncio.timeout(None if self._playing else self._timeout) as deadline:
                    self._read_deadline = deadline
                    message = await _read_message(self._reader)
                self._read_deadline = None
                if message is None:
                    _LOGGER.debug("Consumer closed a relayed connection")
                    return
                if isinstance(message, bytes):
                    if self._upstream_writer is None:
                        _LOGGER.debug("Consumer sent an interleaved frame before any stream")
                        return
                    self._upstream_writer.write(message)
                    await self._upstream_writer.drain()
                    continue
                if not await self._handle_request(message):
                    return
        except _MalformedMessageError:
            _LOGGER.info("Relay closed a connection after a malformed or oversized message")
        except TimeoutError:
            _LOGGER.info("Relay closed a connection that went quiet before its stream started")
        except asyncio.IncompleteReadError, ConnectionError:
            _LOGGER.debug("Consumer connection lost")

    async def _refuse(
        self, status: str, request: _Message | None, extra: Iterable[tuple[str, str]] = ()
    ) -> None:
        self._writer.write(_simple_response(status, request, extra))
        with contextlib.suppress(ConnectionError):
            await self._writer.drain()

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
        if verb == "SETUP":
            transport = request.header("Transport") or ""
            if "RTP/AVP/TCP" not in transport.upper() or "interleaved=" not in transport.lower():
                _LOGGER.info("Relay refused a SETUP that did not ask for interleaved TCP")
                await self._refuse("461 Unsupported Transport", request)
                return True
        self._remember_authority(match["authority"])
        if self._upstream_writer is None and not await self._connect(camera, request):
            return False
        upstream = self._upstream_writer
        if upstream is None:  # pragma: no cover - `_connect` set it or returned False
            return False
        cseq = request.header("CSeq")
        if verb == "PLAY" and cseq is not None:
            self._play_cseqs.add(cseq)
        suffix = match["suffix"] or ""
        if suffix == "/":
            suffix = ""
        headers = [(k, v) for k, v in request.headers if k.lower() != "authorization"]
        headers.append(("Authorization", self._relay._connection.auth_header))  # noqa: SLF001
        target = self._relay._upstream_base(camera) + suffix  # noqa: SLF001
        mapped = _Message(f"{method} {target} {version}", headers, request.body)
        upstream.write(mapped.to_bytes())
        await upstream.drain()
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
                    self._note_play_response(message)
                    self._writer.write(self._rewrite_response(message).to_bytes())
                await self._writer.drain()
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

    def _note_play_response(self, response: _Message) -> None:
        """Mark the stream playing once SecuritySpy accepts a relayed ``PLAY``."""
        parts = response.start_line.split(" ", 2)
        cseq = response.header("CSeq")
        if len(parts) < 2 or not parts[1].startswith("2") or cseq not in self._play_cseqs:  # noqa: PLR2004
            return
        self._playing = True
        if self._read_deadline is not None:
            self._read_deadline.reschedule(None)

    def _relay_base(self) -> str:
        camera = self._camera
        token = self._relay._ids[camera] if camera is not None else ""  # noqa: SLF001
        port = self._consumer_port if self._consumer_port is not None else self._relay.bound_port
        return f"rtsp://{self._consumer_host}:{port}/{token}"

    def _rewrite_response(self, response: _Message) -> _Message:
        base = self._relay_base()

        def rewrite(text: str) -> str:
            return _UPSTREAM_URL_RE.sub(lambda _match: base, text)

        parts = response.start_line.split(" ", 2)
        start_line = response.start_line
        if len(parts) >= 2 and parts[1] == _STATUS_UNAUTHORIZED:  # noqa: PLR2004
            _LOGGER.warning(
                "SecuritySpy refused the relayed stream (401); the account's credential "
                "or its live-video access to this camera may have changed"
            )
            start_line = f"{_RTSP_VERSION} 403 Forbidden"
        headers: list[tuple[str, str]] = []
        for name, value in response.headers:
            lowered = name.lower()
            if lowered in _DROPPED_RESPONSE_HEADERS:
                continue
            headers.append((name, rewrite(value) if lowered in _URL_HEADERS else value))
        body = response.body
        if body:
            body = rewrite(body.decode("latin-1")).encode("latin-1")
        return _Message(start_line, headers, body)
