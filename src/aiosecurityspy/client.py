"""Authenticated REST client over a caller-injected ``aiohttp`` session.

The caller owns the session. This library never constructs, configures or
closes one, so :class:`SecuritySpyClient` deliberately has no ``close()`` and no
async-context-manager protocol.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Final, cast

import aiohttp

from .connection import ConnectionSettings
from .const import (
    CAPTURE_FILTER_ALL,
    CAPTURE_FILTERS,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    ENDPOINT_CAPTURE_LIST,
    ENDPOINT_SYSTEM_INFO,
    capture_filter_for_class,
)
from .exceptions import SecuritySpyAuthError, SecuritySpyConnectError
from .models import Capture, ServerInfo
from .stream import SecuritySpyEventStream

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from datetime import tzinfo

    from .stream import EventCallback, LifecycleCallback

__all__ = ["SecuritySpyClient"]

_LOGGER: Final = logging.getLogger(__name__)

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403
_HTTP_OK_MIN: Final = 200
_HTTP_OK_MAX: Final = 299
_HTTP_REDIRECT_MIN: Final = 300
_HTTP_REDIRECT_MAX: Final = 399

#: Upper bound on a response body, in bytes. `++systemInfo` for a fully-loaded
#: server is a few kilobytes; anything of this size is a wrong endpoint or a
#: misbehaving server, and buffering it inside a Home Assistant process is worse
#: than failing. The request timeout bounds duration, not bytes.
_MAX_BODY_BYTES: Final = 8 * 1024 * 1024

#: Unreachable fallback for the newest-first sort key, which only ever runs
#: over captures whose `start` is not None. It exists so the key function is
#: total for the type checker rather than needing a cast. Deliberately not
#: named for the Unix epoch: AD-15 forbids an epoch standing in for an absent
#: time, and this is the floor of the representable range, not 1970.
_SORT_FLOOR: Final = datetime.min.replace(tzinfo=UTC)


#: Keys a wrapped `++caplist` array has been seen or is plausibly sent under.
#: Checked before the "exactly one list" fallback so an error envelope cannot
#: win by ordering.
_CAPTURE_LIST_KEYS: Final = ("captures", "caplist", "files", "file")


def _validated_camera_numbers(cameras: Iterable[int]) -> tuple[int, ...]:
    """Return the requested camera numbers, sorted and de-duplicated.

    Sorting and de-duplicating makes the emitted ``cams`` parameter a function
    of the *set* of cameras rather than of the caller's iteration order, so the
    request is byte-identical across calls and testable.

    Raises:
        ValueError: A camera number is not a non-negative integer. No message
            quotes the offending value.

    """
    numbers: set[int] = set()
    for camera in cameras:
        # The static type says `int`, but this is a public entry point and a
        # `bool` or a string camera number would otherwise reach the wire as a
        # query for something else entirely. The cast widens the static type so
        # the runtime check is not eliminated as dead.
        if not isinstance(cast("object", camera), int) or isinstance(camera, bool) or camera < 0:
            message = "camera numbers must be non-negative integers"
            raise ValueError(message)
        numbers.add(camera)
    return tuple(sorted(numbers))


def _are_plain_dates(*values: date) -> bool:
    """Return whether every bound is a ``date`` and none is a ``datetime``.

    ``datetime`` subclasses ``date``, so a ``datetime`` satisfies the
    annotation and the range comparison, then serialises as a full ISO instant
    -- a ``startDate`` the server cannot match against a folder date. The cast
    widens the static type so the runtime check is not eliminated as dead.
    """
    return all(
        isinstance(cast("object", value), date) and not isinstance(value, datetime)
        for value in values
    )


def _resolve_capture_filter(object_class: str | None, capture_filter: int | None) -> int:
    """Resolve the ``filter`` query value from the two mutually exclusive forms.

    Raises:
        ValueError: The class has no server-side filter, or the raw filter
            value is not one SecuritySpy defines. An out-of-range value is
            rejected rather than sent: the server is not documented to
            validate it, and a filter it ignores returns the *whole* history
            while looking like a narrow query.

    """
    if object_class is not None:
        # Server-side (research §4.2). There is deliberately no fetch-everything
        # fallback: filtering the `o` bitmask locally would transfer the whole
        # day's history for every camera to reach the same answer.
        return capture_filter_for_class(object_class)
    if capture_filter is None:
        return CAPTURE_FILTER_ALL
    # The cast widens the static type so the runtime check is not eliminated as
    # dead; `bool` is excluded because True would otherwise mean filter 1.
    if (
        not isinstance(cast("object", capture_filter), int)
        or isinstance(capture_filter, bool)
        or capture_filter not in CAPTURE_FILTERS
    ):
        message = "capture_filter must be one of the CAPTURE_FILTER_* values"
        raise ValueError(message)
    return capture_filter


def _capture_entries(payload: object) -> list[object] | None:
    """Locate the capture array in a ``++caplist`` body, or return ``None``.

    Research §4 records a bare JSON array, but the envelope has only been read
    off one server version, so a mapping wrapping the array under a *named* key
    is accepted too. Any other list in the body is ignored rather than guessed
    at: taking whatever list turned up first would let ``{"error": [...],
    "captures": [...]}`` decode the wrong array, and would report an envelope
    whose only list is a list of error strings as "no captures" instead of as
    the failure it is. Anything else is not a capture list.
    """
    if isinstance(payload, list):
        return list(payload)  # pyright: ignore[reportUnknownArgumentType]
    if isinstance(payload, dict):
        for key in _CAPTURE_LIST_KEYS:
            named = payload.get(key)  # pyright: ignore[reportUnknownVariableType]
            if isinstance(named, list):
                return list(named)  # pyright: ignore[reportUnknownArgumentType]
    return None


def _tiebreak(capture: Capture) -> tuple[int, str, str, int, int]:
    """Total ordering key for captures the primary key cannot separate.

    Every field a caller can observe participates, so two entries share a key
    only when they are indistinguishable, and the documented determinism does
    not quietly fall back to the server's ordering.
    """
    return (
        capture.camera,
        capture.filename,
        capture.folder_date,
        capture.capture_type if capture.capture_type is not None else -1,
        capture.file_size if capture.file_size is not None else -1,
    )


def _ordered_newest_first(captures: list[Capture]) -> tuple[Capture, ...]:
    """Order captures newest first, deterministically.

    The server's ordering is not part of the contract, so it is imposed here.
    Captures with no reconstructable start sort last: they are unorderable in
    time, and putting them first would make "the most recent capture" wrong.
    """
    dated = [capture for capture in captures if capture.start is not None]
    undated = [capture for capture in captures if capture.start is None]
    # Two stable passes: the tiebreak first, then the primary key. Python's sort
    # is stable even with reverse=True, so equal starts keep the tiebreak order.
    dated.sort(key=_tiebreak)
    dated.sort(key=lambda capture: capture.start or _SORT_FLOOR, reverse=True)
    undated.sort(key=_tiebreak)
    return (*dated, *undated)


class SecuritySpyClient:
    """An async client for the SecuritySpy HTTP API.

    Credentials are held once, on the client, and are sent only as
    :class:`aiohttp.BasicAuth`. They never appear in a URL, a log line, an
    exception message, a ``repr`` or a traceback (AD-13).

    Example:
        >>> import aiohttp, asyncio
        >>> async def main() -> None:
        ...     async with aiohttp.ClientSession() as session:
        ...         client = SecuritySpyClient(
        ...             session, "nvr.example.com", username="viewer", password="secret"
        ...         )
        ...         info = await client.async_get_server_info()
        ...         print(info.version, len(info.cameras))

    """

    def __init__(  # noqa: PLR0913 - connection parameters are irreducible; the credential and transport flags are keyword-only
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int = DEFAULT_PORT,
        *,
        username: str,
        password: str,
        use_https: bool = False,
        verify_ssl: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Create a client bound to one SecuritySpy server.

        Args:
            session: The caller's session. It is used as-is and is never
                closed, reconfigured, or replaced by this library.
            host: Hostname or IP address of the SecuritySpy server.
            port: Web-server port. Defaults to SecuritySpy's HTTP port.
            username: SecuritySpy account name. Use a least-privileged account.
            password: SecuritySpy account password.
            use_https: Whether to speak TLS to the server.
            verify_ssl: Whether to verify the server certificate. This is a
                constructor flag applied per request rather than session state,
                because the session is not this library's to configure.
            timeout: Total per-request timeout in seconds. Every request
                carries one so a wrong-host TLS handshake fails rather than
                hanging.

        Raises:
            ValueError: The host, port, timeout or credential is unusable.
                These are caller mistakes, not server failures, so they surface
                immediately at construction rather than as an opaque transport
                error later. No message quotes the offending value.
            TypeError: ``port`` is not an integer.

        """
        # Validation, URL construction and credential handling live in
        # `connection.py` so the event stream shares exactly one definition of
        # them rather than re-deriving transport state (AD-13).
        self._connection = ConnectionSettings.create(
            session,
            host,
            port,
            username=username,
            password=password,
            use_https=use_https,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    @property
    def host(self) -> str:
        """The configured host."""
        return self._connection.host

    @property
    def port(self) -> int:
        """The configured port."""
        return self._connection.port

    @property
    def base_url(self) -> str:
        """The server's base URL. It never contains credentials."""
        return self._connection.base_url

    def event_stream(  # noqa: PLR0913 - four independent lifecycle callbacks plus tuning; all keyword-only
        self,
        *,
        on_event: EventCallback,
        on_connected: LifecycleCallback | None = None,
        on_disconnected: LifecycleCallback | None = None,
        on_reconnected: LifecycleCallback | None = None,
        on_auth_failed: LifecycleCallback | None = None,
        server_timezone: tzinfo = UTC,
    ) -> SecuritySpyEventStream:
        """Create an event-stream reader bound to this client's server.

        The stream is not started: call
        :meth:`~aiosecurityspy.SecuritySpyEventStream.connect` on the result.
        It reuses this client's validated host, credential, TLS flag and
        timeout, so there is one construction path and no duplicated
        validation.

        Args:
            on_event: Called with every decoded event. May be sync or async.
            on_connected: Called once, on the first-ever successful connect.
            on_disconnected: Called once per lost connection.
            on_reconnected: Called on every successful connect after the first.
            on_auth_failed: Called on 401/403, after which reconnection pauses
                until ``resume()`` is called.
            server_timezone: Timezone of the server's wall-clock timestamps.
                **[ASSUMPTION]** No SecuritySpy endpoint exposes it, so this
                defaults to UTC.

        Returns:
            A stopped :class:`~aiosecurityspy.SecuritySpyEventStream`.

        """
        return SecuritySpyEventStream(
            self._connection,
            on_event=on_event,
            on_connected=on_connected,
            on_disconnected=on_disconnected,
            on_reconnected=on_reconnected,
            on_auth_failed=on_auth_failed,
            server_timezone=server_timezone,
        )

    def __repr__(self) -> str:
        """Return a representation that cannot leak credentials."""
        return (
            f"SecuritySpyClient(host={self._connection.host!r}, "
            f"port={self._connection.port}, scheme={self._connection.scheme!r}, "
            f"verify_ssl={self._connection.verify_ssl})"
        )

    __str__ = __repr__

    async def async_get_server_info(self) -> ServerInfo:
        """Read the server and camera inventory from ``++systemInfo``.

        Raises:
            SecuritySpyConnectError: The server was unreachable, timed out,
                failed TLS, answered with an unexpected status, or sent a body
                that was not JSON.
            SecuritySpyAuthError: The credentials were rejected (401/403).
            SecuritySpyUnsupportedVersionError: The server is older than the
                supported minimum, or the payload shape is not locatable.

        Returns:
            The decoded server info, including ``cameras`` keyed by camera
            number.

        """
        payload = await self._request_json(ENDPOINT_SYSTEM_INFO, {"format": "json"})
        return ServerInfo.from_api(payload)

    async def async_get_captures(  # noqa: PLR0913 - the camera set, the two date bounds and the two filter forms are irreducible; everything but `cameras` is keyword-only
        self,
        cameras: Iterable[int],
        *,
        start_date: date,
        end_date: date,
        object_class: str | None = None,
        capture_filter: int | None = None,
        server_timezone: tzinfo = UTC,
    ) -> tuple[Capture, ...]:
        """Read capture history for many cameras in **one** request.

        This is the persistent counterpart to the event stream: ``++caplist``
        is SecuritySpy's stored record, so an answer derived from it is correct
        after a restart. The camera list is batched into a single ``cams``
        parameter and the object-class filter is applied *by the server*, so
        the request count is one -- never one per camera, and never cameras x
        classes.

        The date range is required and is not widened or defaulted: a bounded
        lookback window is the consumer's policy, not this library's. It is
        also the only bound on the response, which is read into memory whole
        and capped: a wide window over many cameras with no filter can exceed
        that cap and fail with "server response body was too large". Narrowing
        the window or the filter is the fix; the endpoint offers no paging.

        Args:
            cameras: Camera numbers to query. Sorted and de-duplicated, so the
                request is deterministic regardless of the caller's ordering.
            start_date: First folder date to include. A ``datetime`` is
                rejected: the server matches folder dates, not instants.
            end_date: Last folder date to include. **[ASSUMPTION]** Both bounds
                are treated as inclusive. Research §4 records only a
                same-day query, which is consistent with an inclusive end but
                does not establish it.
            object_class: Restrict to one object class, filtered server-side.
                SecuritySpy offers a filter for ``human``, ``vehicle`` and
                ``animal`` only. Note that these filters select *motion-capture
                movies* of that class (research §4.2): a JPG capture or a
                continuous recording carrying the same class in its ``o``
                bitmask is not returned by them.
            capture_filter: A raw ``filter`` value for the non-class filters
                (``CAPTURE_FILTER_MOVIES``, ``CAPTURE_FILTER_CONTINUOUS``, and
                so on). Mutually exclusive with ``object_class``.
            server_timezone: Timezone of the server's wall clock, used to turn
                ``f`` plus seconds-since-midnight into a UTC instant.
                **[ASSUMPTION]** No SecuritySpy endpoint exposes it, so this
                defaults to UTC.

        Raises:
            ValueError: A caller mistake -- a non-integer or negative camera
                number, a ``datetime`` or non-date bound, ``start_date`` after
                ``end_date``, an object class the server has no filter for, a
                ``capture_filter`` SecuritySpy does not define, or both filter
                forms at once. Raised before any request is issued.
                No message quotes the offending value.
            SecuritySpyConnectError: The server was unreachable, timed out,
                answered with an unexpected status, or sent a body that was
                neither a list of captures nor a mapping containing one.
            SecuritySpyAuthError: The credentials were rejected (401/403).

        Returns:
            The decoded captures, newest first. Empty when nothing matched.

        """
        if object_class is not None and capture_filter is not None:
            message = "pass either object_class or capture_filter, not both"
            raise ValueError(message)
        # `datetime` is a subclass of `date`, so a `datetime` satisfies both the
        # annotation and the comparison below and would then serialise as a full
        # ISO instant -- a `startDate` the server cannot match. Reject it rather
        # than truncate: a caller who passed a time meant something by it.
        if not _are_plain_dates(start_date, end_date):
            # ValueError, not TypeError: this method documents every caller
            # mistake as a ValueError, and the constructor already sets that
            # precedent for a wrong host or timeout.
            message = "start_date and end_date must be dates, not datetimes"
            raise ValueError(message)
        if start_date > end_date:
            message = "start_date must not be after end_date"
            raise ValueError(message)
        numbers = _validated_camera_numbers(cameras)
        filter_value = _resolve_capture_filter(object_class, capture_filter)

        if not numbers:
            # Nothing to ask about. Short-circuiting here rather than sending an
            # empty `cams` keeps the "one request covers many cameras" rule from
            # degenerating into "one request that means every camera".
            return ()

        payload = await self._request_json(
            ENDPOINT_CAPTURE_LIST,
            {
                # The trailing comma is not cosmetic: the server's own client
                # sends it (research §4) and this is a recorded wire shape.
                "cams": "".join(f"{number}," for number in numbers),
                "startDate": start_date.isoformat(),
                "endDate": end_date.isoformat(),
                "filter": str(filter_value),
            },
        )
        return self._decode_captures(payload, server_timezone)

    def _decode_captures(self, payload: object, server_timezone: tzinfo) -> tuple[Capture, ...]:
        """Decode a ``++caplist`` body into ordered captures."""
        entries = _capture_entries(payload)
        if entries is None:
            # The body is deliberately not echoed: it can contain device
            # credentials (research §8.3).
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                "server response was not a capture list",
            )
        captures: list[Capture] = []
        for entry in entries:
            if not isinstance(entry, dict):
                _LOGGER.debug("Skipping non-object capture entry")
                continue
            mapping = {str(key): item for key, item in entry.items()}  # pyright: ignore[reportUnknownVariableType]
            capture = Capture.from_api(mapping, server_timezone=server_timezone)
            if capture is not None:
                captures.append(capture)
        return _ordered_newest_first(captures)

    async def _request_json(self, path: str, params: Mapping[str, str] | None = None) -> object:
        """Issue one authenticated GET and return its parsed JSON body.

        This is the single transport seam: URL construction, BasicAuth, the
        per-request SSL flag, the timeout, status-to-exception mapping and JSON
        parsing all happen exactly once, here.
        """
        url = self._connection.build_url(path)
        _LOGGER.debug(
            "Requesting %s from %s:%s", path, self._connection.host, self._connection.port
        )
        try:
            async with self._connection.session.get(
                url,
                params=dict(params or {}),
                auth=self._connection.auth,
                ssl=self._connection.verify_ssl,
                timeout=self._connection.request_timeout(),
                # SecuritySpy 301-redirects plain HTTP to its HTTPS *port*, and
                # a different port is a different origin, so aiohttp strips the
                # Authorization header when following it (verified against
                # aiohttp 3.12). Following the redirect therefore cannot
                # succeed -- it just turns a "wrong scheme" mistake into a 401
                # that blames the user's password. Surface the redirect instead.
                # Note that not following it is no credential safeguard either:
                # over plain HTTP the Basic credential is already on the wire,
                # which is why the README recommends HTTPS.
                allow_redirects=False,
            ) as response:
                status = response.status
                if status in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
                    raise SecuritySpyAuthError(self._connection.host, self._connection.port, status)
                if _HTTP_REDIRECT_MIN <= status <= _HTTP_REDIRECT_MAX:
                    # Almost always "you asked for http, this server wants
                    # https". Say so, rather than reporting a bare 301.
                    raise SecuritySpyConnectError(
                        self._connection.host,
                        self._connection.port,
                        f"server redirected (HTTP {status}); if the server uses TLS, "
                        "construct the client with use_https=True",
                    )
                if not _HTTP_OK_MIN <= status <= _HTTP_OK_MAX:
                    raise SecuritySpyConnectError(
                        self._connection.host,
                        self._connection.port,
                        f"unexpected HTTP status {status}",
                    )
                declared = response.content_length
                if declared is not None and declared > _MAX_BODY_BYTES:
                    raise SecuritySpyConnectError(
                        self._connection.host,
                        self._connection.port,
                        "server response body was too large",
                    )
                # Accumulate rather than issuing one `read(n)`: StreamReader.read
                # returns whatever is currently buffered, not n bytes, so a
                # single call silently truncates any body that spans more than
                # one buffer fill. Reading one byte past the cap is what enforces
                # it -- a chunked response declares no Content-Length at all.
                chunks: list[bytes] = []
                total = 0
                while chunk := await response.content.read(_MAX_BODY_BYTES + 1 - total):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > _MAX_BODY_BYTES:
                        raise SecuritySpyConnectError(
                            self._connection.host,
                            self._connection.port,
                            "server response body was too large",
                        )
                raw = b"".join(chunks)
                body = raw.decode(response.get_encoding())
        except RuntimeError as err:
            # aiohttp's get_encoding() raises RuntimeError when the response
            # declares no charset and is not application/json, because we read
            # through response.content and never populate response._body. A
            # wrong-port server answering text/html hits this on every call, and
            # it must not escape as a bare RuntimeError.
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                "server response encoding was not determinable",
            ) from err
        except (UnicodeDecodeError, LookupError) as err:
            # A body that will not decode -- or that declares a charset Python
            # does not know -- is a broken server, not a Python bug; it must not
            # escape as a bare ValueError or LookupError.
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                "server response was not decodable text",
            ) from err
        except TimeoutError as err:
            raise SecuritySpyConnectError(
                self._connection.host, self._connection.port, "request timed out"
            ) from err
        except aiohttp.ClientError as err:
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                f"transport failure ({type(err).__name__})",
            ) from err
        except OSError as err:
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                f"connection failure ({type(err).__name__})",
            ) from err

        try:
            return json.loads(body)
        except ValueError as err:
            # The body is deliberately not echoed: it can contain device
            # credentials (research §8.3).
            raise SecuritySpyConnectError(
                self._connection.host, self._connection.port, "server response was not valid JSON"
            ) from err
