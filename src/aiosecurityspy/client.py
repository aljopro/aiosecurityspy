"""Authenticated REST client over a caller-injected ``aiohttp`` session.

The caller owns the session. This library never constructs, configures or
closes one, so :class:`SecuritySpyClient` deliberately has no ``close()`` and no
async-context-manager protocol.
"""

from __future__ import annotations

import json
import logging
import ssl
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any, Final, NoReturn, cast
from urllib.parse import quote

import aiohttp

from .connection import ConnectionSettings
from .const import (
    CAPTURE_FILE_BANDWIDTH_STANDARD,
    CAPTURE_FILTER_ALL,
    CAPTURE_FILTERS,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    ENDPOINT_CAM_STATUS,
    ENDPOINT_CAPTURE_LIST,
    ENDPOINT_GET_PREVIEW,
    ENDPOINT_SET_SCHEDULE,
    ENDPOINT_SETTINGS_CAMERAS,
    ENDPOINT_SYSTEM_INFO,
    PERM_FILES,
    PERM_SCHED,
    PERM_SETTINGS,
    PERMISSION_NAMES,
    SETTINGS_FORM_SENTINEL,
    capture_filter_for_class,
)
from .exceptions import (
    SecuritySpyAuthError,
    SecuritySpyCertificateError,
    SecuritySpyConnectError,
    SecuritySpyError,
    SecuritySpyPermissionError,
)
from .models import (
    SETTINGS_PAGE_KEY_QUORUM,
    SETTINGS_PAGE_KEYS,
    ArmOverride,
    CameraSettings,
    CameraSettingsPatch,
    CameraStatus,
    Capture,
    CaptureFileBandwidth,
    CapturePreview,
    ServerInfo,
    arm_override,
    capture_file_bandwidth,
)
from .stream import SecuritySpyEventStream

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable, Mapping
    from datetime import tzinfo

    from .models import CaptureModes
    from .stream import EventCallback, LifecycleCallback

__all__ = ["SecuritySpyClient"]

_LOGGER: Final = logging.getLogger(__name__)

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403

#: The permission name reported when a `403` lands on an endpoint whose
#: required permission this library does not know. `SecuritySpyPermissionError`
#: takes a required `permission: str` -- there is no unnamed/optional form to
#: fall back to -- so this is the one honest thing to say: the account lacks
#: *some* permission, and which one is not knowable from the status code alone.
_PERMISSION_UNKNOWN: Final = "unknown"
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

#: Content type every ``settings-*`` write carries (research §8.0).
_FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"

#: Size of one chunk yielded by :class:`CaptureFileStream`, in bytes. Named
#: rather than inlined so the memory bound the streaming API is built on is a
#: reviewable constant, not a literal buried in a read loop: a recording can be
#: gigabytes, and this is the only thing keeping any of it out of the process.
_STREAM_CHUNK_BYTES: Final = 64 * 1024


class CaptureFileStream:
    """An async-iterable stream of bytes from a capture file fetch.

    The response body is never fully buffered: bytes are read and yielded in
    bounded chunks of :data:`_STREAM_CHUNK_BYTES`. Iteration wraps transport
    errors into :class:`~aiosecurityspy.SecuritySpyConnectError` and releases
    the response when the body is exhausted or on error.

    A consumer that does not drain the stream must release it explicitly,
    either with ``await stream.aclose()`` or by using it as an async context
    manager::

        async with await client.async_get_capture_file(capture) as stream:
            async for chunk in stream:
                ...

    Relying on garbage collection is not enough: a stream that is created and
    never iterated never builds the generator whose ``finally`` releases the
    response, so the connection would stay checked out of the caller's pool.
    """

    def __init__(
        self,
        response: aiohttp.ClientResponse,
        host: str,
        port: int,
        content_type: str,
    ) -> None:
        """Store the response and connection details."""
        self._response = response
        self._host = host
        self._port = port
        self.content_type = content_type
        self._released = False
        self._iterated = False

    def _release(self) -> None:
        """Release the response if not already released."""
        if not self._released:
            self._released = True
            self._response.release()

    async def aclose(self) -> None:
        """Release the underlying response.

        Idempotent, and safe to call whether or not the stream was iterated.
        """
        self._release()

    async def __aenter__(self) -> CaptureFileStream:
        """Return the stream itself, for use in an ``async with`` block."""
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Release the response on leaving the ``async with`` block."""
        await self.aclose()

    def __aiter__(self) -> AsyncIterator[bytes]:
        """Return the async iterator over the response body.

        Raises:
            RuntimeError: Iteration was already started. The body is consumed
                as it is read, so a second pass could only yield the unread
                remainder -- silently producing a truncated file. A caller that
                needs the bytes twice must buffer them, and a caller retrying a
                failed transfer must issue a new request. This is a caller
                mistake, so it stays outside the typed hierarchy, matching the
                convention stated in :mod:`aiosecurityspy.exceptions`.

        """
        if self._iterated:
            message = (
                "this CaptureFileStream has already been iterated; its body is "
                "consumed as it is read, so re-iterating would truncate. Issue "
                "a new async_get_capture_file call instead."
            )
            raise RuntimeError(message)
        self._iterated = True
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[bytes]:
        """Yield bounded chunks of the response body, catching transport errors."""
        try:
            while True:
                chunk = await self._response.content.read(_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                yield chunk
        except (aiohttp.ClientError, TimeoutError, OSError) as err:
            raise SecuritySpyConnectError(
                self._host,
                self._port,
                f"stream failure ({type(err).__name__})",
            ) from err
        finally:
            self._release()


def _tls_reason(err: BaseException) -> str:
    """Return a short, credential-free description of a TLS failure.

    OpenSSL's own reason -- ``CERTIFICATE_VERIFY_FAILED``,
    ``CERTIFICATE_HAS_EXPIRED``, ``WRONG_VERSION_NUMBER`` -- is the one detail
    that tells an expired certificate apart from a hostname mismatch or from
    TLS spoken to a plain-HTTP port, and it is a fixed OpenSSL constant, so it
    carries nothing user-supplied. aiohttp wraps the underlying
    :class:`ssl.SSLError` rather than carrying the reason itself, under
    ``certificate_error`` for a certificate rejection and ``os_error`` for every
    other connector failure, so both are unwrapped before giving up.

    Args:
        err: The exception raised by the transport.

    Returns:
        The OpenSSL reason, or the exception's type name when there is none.

    """
    for attribute in ("certificate_error", "os_error"):
        inner = getattr(err, attribute, None)
        reason = getattr(inner, "reason", None)
        if isinstance(reason, str) and reason:
            return reason
    reason = getattr(err, "reason", None)
    if isinstance(reason, str) and reason:
        return reason
    return type(err).__name__


def _validated_camera_number(camera: int) -> int:
    """Return one validated camera number.

    The single camera-number rule for the whole client: the plural
    :func:`_validated_camera_numbers` is built from it.

    Raises:
        ValueError: The camera number is not a non-negative integer. The static
            type says ``int``, but this is a public entry point and a ``bool``
            or a string would otherwise address something else entirely on a
            *write*. The cast widens the static type so the runtime check is not
            eliminated as dead. No message quotes the offending value.

    """
    if not isinstance(cast("object", camera), int) or isinstance(camera, bool) or camera < 0:
        message = "camera numbers must be non-negative integers"
        raise ValueError(message)
    return camera


def _validated_camera_numbers(cameras: Iterable[int]) -> tuple[int, ...]:
    """Return the requested camera numbers, sorted and de-duplicated.

    Sorting and de-duplicating makes the emitted ``cams`` parameter a function
    of the *set* of cameras rather than of the caller's iteration order, so the
    request is byte-identical across calls and testable.

    Raises:
        ValueError: A camera number is not a non-negative integer. No message
            quotes the offending value.

    """
    # One validation rule, in one place: `_validated_camera_number` carries the
    # runtime `bool`/negative check and the reason it has to survive the static
    # type. Two copies could drift into disagreeing about what a camera number
    # is on the read path and the write path.
    return tuple(sorted({_validated_camera_number(camera) for camera in cameras}))


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


def _camera_status_entries(payload: object) -> list[object] | None:
    """Locate the status array in a ``++camStatus`` body, or return ``None``.

    Research §2.2 records a bare JSON array (``[{num, enabled, online, open,
    err, errDesc}]``); nothing else is documented, so unlike
    :func:`_capture_entries` this accepts only that shape rather than guessing
    at a wrapped envelope no observation supports.
    """
    if isinstance(payload, list):
        return list(payload)  # pyright: ignore[reportUnknownArgumentType]
    return None


def _tiebreak(capture: Capture) -> tuple[int, str, str, int, float]:
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
        capture.file_size_mb if capture.file_size_mb is not None else -1,
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

    Credentials are held once, on the client, and are sent only as a
    pre-encoded ``Authorization: Basic`` header. They never appear in a URL,
    a log line, an exception message, a ``repr`` or a traceback (AD-13).

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
        server_timezone: tzinfo,
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
                ``systemInfo.server`` publishes this as ``seconds-from-gmt``
                (see :attr:`ServerInfo.utc_offset`); there is no correct
                default, so it must be supplied.

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

        This is also the disambiguating probe :meth:`_map_status` issues on a
        `401` from another endpoint (research §5.9): the account is known to
        be able to reach this endpoint whenever its credentials are valid at
        all, so a clean success here on the heels of someone else's `401`
        means that `401` was a permission denial, not rejected credentials.

        A `401` from *this* call is never itself disambiguated: probing
        ``++systemInfo`` with another read of ``++systemInfo`` would answer
        nothing new and could recurse, so this call always passes
        ``disambiguate=False`` down to the shared status mapping. That also
        means calling this method directly issues exactly one request even
        when it 401s.

        Raises:
            SecuritySpyConnectError: The server was unreachable, timed out,
                failed TLS, answered with an unexpected status, or sent a body
                that was not JSON.
            SecuritySpyAuthError: The credentials were rejected (401).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403).
            SecuritySpyUnsupportedVersionError: The server is older than the
                supported minimum, or the payload shape is not locatable.

        Returns:
            The decoded server info, including ``cameras`` keyed by camera
            number.

        """
        payload = await self._request_json(
            ENDPOINT_SYSTEM_INFO, {"format": "json"}, disambiguate=False
        )
        return ServerInfo.from_api(payload)

    async def async_get_camera_status(self) -> tuple[CameraStatus, ...]:
        """Read the cheap per-camera health poll from ``++camStatus``.

        This is the low-cost alternative to :meth:`async_get_server_info`: the
        response is 794 B for 11 cameras versus ``++systemInfo``'s 27 KB
        (research §2.2), so a consumer that only needs to notice a camera going
        offline, closing, or erroring can poll this on every cycle instead of
        decoding the full inventory.

        ``[ASSUMPTION]`` This endpoint is called without ``format=json``,
        unlike :meth:`async_get_server_info`, because the one capture of it the
        project holds returns JSON unconditionally (research addendum §8.12).
        If a live server turns out to honour ``format`` here too, this call
        raises :class:`SecuritySpyConnectError` on every poll and the parameter
        must be added. A stub pins the request shape -- the client tests assert
        this call sends no query parameters -- but only a live server can
        settle whether that shape is the right one.

        Raises:
            SecuritySpyConnectError: The server was unreachable, timed out,
                answered with an unexpected status, or sent a body that was not
                a JSON array.
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- 401 is endpoint-dependent).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403), or a `401` that a
                disambiguating probe confirmed was a permission denial rather
                than rejected credentials.

        Returns:
            The decoded per-camera status, one entry per camera the server
            reported. An entry with no usable camera number is skipped; the
            rest still decode.

        """
        payload = await self._request_json(ENDPOINT_CAM_STATUS)
        entries = _camera_status_entries(payload)
        if entries is None:
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                "server response was not a camera status list",
            )
        statuses: list[CameraStatus] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                _LOGGER.debug(
                    "Skipping camStatus entry %d: expected an object, got %s",
                    index,
                    type(entry).__name__,
                )
                continue
            mapping = {str(key): item for key, item in entry.items()}  # pyright: ignore[reportUnknownVariableType]
            status = CameraStatus.from_api(mapping)
            if status is not None:
                statuses.append(status)
        return tuple(statuses)

    async def async_get_captures(  # noqa: PLR0913 - the camera set, the two date bounds and the two filter forms are irreducible; everything but `cameras` is keyword-only
        self,
        cameras: Iterable[int],
        *,
        start_date: date,
        end_date: date,
        object_class: str | None = None,
        capture_filter: int | None = None,
        server_timezone: tzinfo,
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
                ``systemInfo.server`` publishes this as ``seconds-from-gmt``
                (see :attr:`ServerInfo.utc_offset`); there is no correct
                default, so it must be supplied.

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
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- 401 is endpoint-dependent).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403), or a `401` that a
                disambiguating probe confirmed was a permission denial rather
                than rejected credentials.

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

    async def async_get_capture_preview(self, capture: Capture) -> CapturePreview:
        """Fetch the JPEG thumbnail for a capture from ``++getpreview``.

        The URL is derived entirely from the ``Capture``: no caller-supplied
        path, folder date, or raw query parameter. The ``archive`` flag is
        taken from ``capture.archived``.

        Args:
            capture: The capture whose preview to fetch.

        Raises:
            SecuritySpyConnectError: The server was unreachable, timed out,
                answered with an unexpected status, or sent a body exceeding
                the 8 MiB preview cap.
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- ``++getpreview`` answers a
                missing 'files' permission with 401, not 403).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403), or a `401` that a
                disambiguating probe confirmed was a permission denial rather
                than rejected credentials.

        Returns:
            The JPEG thumbnail bytes and content type.

        """
        if not capture.path:
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                "capture has no addressable file path",
            )
        archive = 1 if capture.archived else 0
        # The getpreview URL uses a literal second '?' (research §4.3): the
        # archive flag is part of the path string, not a separate query param.
        # The filename is percent-encoded per the existing precedent in client.py.
        encoded_path = "/".join(quote(part, safe="") for part in capture.path.split("/", 2))
        path = f"{ENDPOINT_GET_PREVIEW}?/{encoded_path}?archive={archive}"
        body, content_type = await self._request_bytes(
            path, permission=PERMISSION_NAMES[PERM_FILES], camera_number=capture.camera
        )
        return CapturePreview(data=body, content_type=content_type)

    async def async_get_capture_file(
        self,
        capture: Capture,
        *,
        bandwidth: CaptureFileBandwidth | int = CAPTURE_FILE_BANDWIDTH_STANDARD,
        archive: bool | None = None,
    ) -> CaptureFileStream:
        """Fetch the recorded file for a capture from ``++getfile``.

        The path is derived entirely from the ``Capture``: no caller-supplied
        folder date or raw query parameter. The ``archive`` flag defaults to
        ``capture.archived`` but can be overridden.

        The returned stream is an async iterable that yields the body in bounded
        chunks without ever buffering the full file. Its ``content_type``
        indicates the media type (e.g. ``"video/quicktime"``).

        Args:
            capture: The capture whose file to fetch.
            bandwidth: The bandwidth variant. Accepts a
                ``CAPTURE_FILE_BANDWIDTH_*`` constant or a
                :class:`~aiosecurityspy.CaptureFileBandwidth` record. Defaults
                to standard bandwidth.
            archive: Override the ``archive`` flag. ``None`` (the default) uses
                ``capture.archived``; an explicit ``True`` or ``False``
                overrides it.

        Raises:
            ValueError: ``bandwidth`` is not a valid bandwidth selector.
                Raised before any request is issued.
            SecuritySpyConnectError: The server was unreachable, timed out,
                answered with an unexpected status, or the connection dropped
                mid-stream.
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- ``++getfile``/``++getfilehb``/
                ``++getfilelb`` answer a missing 'files' permission with 401,
                not 403).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403), or a `401` that a
                disambiguating probe confirmed was a permission denial rather
                than rejected credentials.

        Returns:
            An async-iterable stream whose ``content_type`` is the media type
            and whose iteration yields bounded chunks of the file body.

        """
        if not capture.path:
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                "capture has no addressable file path",
            )
        bw = (
            bandwidth
            if isinstance(bandwidth, CaptureFileBandwidth)
            else capture_file_bandwidth(bandwidth)
        )
        archive_flag = capture.archived if archive is None else archive
        params = {"archive": "1" if archive_flag else "0"}
        return await self._stream_bytes(
            bw.endpoint,
            params,
            path_suffix=capture.path,
            permission=PERMISSION_NAMES[PERM_FILES],
            camera_number=capture.camera,
        )

    def _request_kwargs(self, timeout: aiohttp.ClientTimeout) -> dict[str, Any]:
        """Return the shared per-request kwargs, so no verb can drift.

        Credentials, the TLS flag and the redirect policy are decided here once
        for every request this library issues. ``allow_redirects=False``:
        SecuritySpy 301-redirects plain HTTP to its HTTPS *port*, and a
        different port is a different origin, so aiohttp strips the
        Authorization header when following it -- turning a "wrong scheme"
        mistake into a 401 that blames the user's password.
        """
        return {
            "ssl": self._connection.verify_ssl,
            "timeout": timeout,
            "allow_redirects": False,
        }

    async def _map_status(
        self,
        status: int,
        *,
        permission: str | None = None,
        camera_number: int | None = None,
        disambiguate: bool = True,
    ) -> None:
        """Map an HTTP status to this library's typed exceptions.

        The single place that decides what a status means. Every transport path
        -- buffered text, buffered bytes and streamed bytes -- calls this, so a
        401 or a stray redirect cannot come to mean different things depending
        on which accessor the caller reached for.

        `401` is **endpoint-dependent** and is not reliably "credentials
        rejected". Verified against a live 6.21 server (research §5.9): an
        account with a valid password but a missing permission gets `401` --
        not `403` -- from ``++getfile``, ``++getfilehb``, ``++getfilelb``,
        ``++getpreview`` and ``++ssSetSchedule``, byte-identical to what a
        genuinely wrong password produces on the same endpoints. `403` remains
        reliable: verified for the settings pages (research §4.1, §5.2), it
        means the credentials were *accepted* and the account merely lacks a
        permission bit. Neither the response body (a fixed string, no
        permission named in it) nor the reason phrase (unreliable -- a `403`
        arrives as `403 OK`) is consulted; the status code alone decides
        (research §7.1).

        Because a `401` cannot be told apart from its response alone, a `401`
        (unless ``disambiguate`` is ``False``) triggers one follow-up read of
        ``++systemInfo`` -- an endpoint the account is known to be allowed to
        reach if its credentials are valid at all. A clean success there means
        the credentials are fine and this was a permission denial, reclassified
        as :class:`SecuritySpyPermissionError`. Any other outcome -- another
        `401`, or the probe itself failing to give a clean answer -- leaves the
        original :class:`SecuritySpyAuthError` verdict unchanged; an
        inconclusive probe must never upgrade or downgrade the verdict.

        Args:
            status: The HTTP status code the server answered with.
            permission: The permission name implied by the endpoint that was
                called, when the caller knows one (e.g. `"settings"` for a
                `settings-*` write). ``None`` when it does not.
            camera_number: The camera the request targeted, when known.
            disambiguate: Whether a `401` may trigger the ``++systemInfo``
                probe described above. ``True`` for every endpoint except
                ``++systemInfo`` itself, which always passes ``False``:
                probing ``++systemInfo`` with another read of ``++systemInfo``
                would answer nothing new, so this is what stops the probe
                from ever triggering a second probe of itself.

        Raises:
            SecuritySpyAuthError: The credentials were rejected (401), or the
                401 was ambiguous and the disambiguating probe could not
                confirm it was a permission denial.
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403), or a `401` that the
                disambiguating probe confirmed was a permission denial rather
                than rejected credentials.
            SecuritySpyConnectError: The server redirected, or answered with a
                status outside the 2xx range.

        """
        if status == _HTTP_UNAUTHORIZED:
            if disambiguate and await self._probe_confirms_permission_denial():
                raise SecuritySpyPermissionError(
                    permission if permission is not None else _PERMISSION_UNKNOWN,
                    camera_number,
                )
            raise SecuritySpyAuthError(self._connection.host, self._connection.port, status)
        if status == _HTTP_FORBIDDEN:
            raise SecuritySpyPermissionError(
                permission if permission is not None else _PERMISSION_UNKNOWN,
                camera_number,
            )
        if _HTTP_REDIRECT_MIN <= status <= _HTTP_REDIRECT_MAX:
            # Almost always "you asked for http, this server wants https".
            # Say so, rather than reporting a bare 301.
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

    async def _probe_confirms_permission_denial(self) -> bool:
        """Disambiguate a `401` with one follow-up read of ``++systemInfo``.

        Called only from :meth:`_map_status`'s `401` branch, and never on
        ``++systemInfo``'s own `401` -- :meth:`async_get_server_info` always
        calls the shared status mapping with ``disambiguate=False``, which is
        what stops this probe from ever triggering a second probe of itself.
        Adds exactly one request, and only on an already-failed call -- a
        successful response never reaches here.

        No result is cached and none is returned to the caller beyond the
        boolean verdict: the moment a probe's payload were retained or reused,
        it would become the kind of hidden state story 1.13 forbids acquiring
        behind a caller's back.

        Returns:
            ``True`` when the probe cleanly succeeded, meaning the credentials
            are valid and the original `401` was a permission denial.
            ``False`` for every other outcome -- another `401`, a `403`, a
            connect or TLS failure, an unexpected status, or a body that would
            not decode -- none of which is a clean confirmation, so the
            original :class:`SecuritySpyAuthError` verdict must stand.

        """
        try:
            await self.async_get_server_info()
        except SecuritySpyError:
            return False
        return True

    def _raise_transport_error(self, err: BaseException) -> NoReturn:
        """Re-raise a transport failure as this library's typed equivalent.

        The single place that decides what a TLS, timeout or socket failure
        means. Order matters and is the reason this is one function rather than
        an except-ladder repeated per call site: ``aiohttp.ClientSSLError`` is a
        subclass of both ``aiohttp.ClientError`` and ``OSError``, and
        ``ssl.SSLError`` is an ``OSError`` too, so a certificate failure tested
        late would be swallowed whole by a generic clause.

        Raises:
            SecuritySpyCertificateError: The server's certificate failed
                verification -- the one failure the caller can answer by
                turning verification off.
            SecuritySpyConnectError: Every other TLS, timeout, transport or
                socket failure.

        """
        if isinstance(err, aiohttp.ClientConnectorCertificateError | ssl.SSLCertVerificationError):
            # Deliberately narrow: only a failed *verification* is a certificate
            # problem the caller can answer by turning verification off. Both
            # forms are caught because a TLS failure raised outside aiohttp's
            # connector wrapper arrives as the bare `ssl` exception.
            raise SecuritySpyCertificateError(
                self._connection.host, self._connection.port, _tls_reason(err)
            ) from err
        if isinstance(err, aiohttp.ClientSSLError | ssl.SSLError):
            # Reported separately from the certificate case because the advice
            # differs: speaking TLS to a plain-HTTP listener raises
            # `WRONG_VERSION_NUMBER` here, and disabling certificate
            # verification does not help it.
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                f"the TLS handshake failed ({_tls_reason(err)}); if the server speaks "
                "plain HTTP on this port, connect without TLS or use the server's "
                "HTTPS port",
            ) from err
        if isinstance(err, TimeoutError):
            raise SecuritySpyConnectError(
                self._connection.host, self._connection.port, "request timed out"
            ) from err
        if isinstance(err, aiohttp.ClientError):
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                f"transport failure ({type(err).__name__})",
            ) from err
        if isinstance(err, OSError):
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                f"connection failure ({type(err).__name__})",
            ) from err
        raise err

    def _check_declared_length(self, declared: int | None) -> None:
        """Reject a body the server declares as larger than the cap, before reading it.

        Raises:
            SecuritySpyConnectError: The declared ``Content-Length`` exceeds the cap.

        """
        if declared is not None and declared > _MAX_BODY_BYTES:
            raise SecuritySpyConnectError(
                self._connection.host,
                self._connection.port,
                "server response body was too large",
            )

    async def _request_bytes(
        self,
        path: str,
        *,
        permission: str | None = None,
        camera_number: int | None = None,
    ) -> tuple[bytes, str]:
        """Issue one authenticated GET and return the raw body bytes + content type.

        Used by ``async_get_capture_preview`` for a buffered read with the
        existing 8 MiB cap. No text decode.

        The ``archive`` flag of a preview is baked into ``path`` itself
        (research §4.3's double-``?`` form), so this helper deliberately takes
        no ``params``: a caller passing one would put the flag in both the path
        and the query, and SecuritySpy's last-``?`` parser would silently pick
        the wrong one.

        Raises:
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- 401 is endpoint-dependent).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403), or a `401` that a
                disambiguating probe confirmed was a permission denial rather
                than rejected credentials.
            SecuritySpyConnectError: The server redirected, answered with an
                unexpected status, sent a body over the cap, or the transport
                failed.

        """
        url = self._connection.build_url(path)
        _LOGGER.debug(
            "Requesting %s from %s:%s", path, self._connection.host, self._connection.port
        )
        try:
            async with self._connection.session.get(
                url,
                headers={"Authorization": self._connection.auth_header},
                **self._request_kwargs(self._connection.request_timeout()),
            ) as response:
                if not _HTTP_OK_MIN <= response.status <= _HTTP_OK_MAX:
                    # Release before interpreting the status: on a 401 the
                    # mapping below fires a second request to disambiguate
                    # it, and that must not run while this failed response
                    # is still holding a connection out of the caller's pool.
                    response.release()
                await self._map_status(
                    response.status, permission=permission, camera_number=camera_number
                )
                self._check_declared_length(response.content_length)
                content_type = response.content_type or "application/octet-stream"
                chunks: list[bytes] = []
                chunk = b""
                total = 0
                result = b""
                try:
                    while chunk := await response.content.read(_MAX_BODY_BYTES + 1 - total):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > _MAX_BODY_BYTES:
                            raise SecuritySpyConnectError(
                                self._connection.host,
                                self._connection.port,
                                "server response body was too large",
                            )
                    result = b"".join(chunks)
                finally:
                    chunks.clear()
                    chunk = b""
                return result, content_type
        except (aiohttp.ClientError, TimeoutError, OSError) as err:
            self._raise_transport_error(err)

    async def _stream_bytes(
        self,
        endpoint: str,
        params: Mapping[str, str],
        *,
        path_suffix: str,
        permission: str | None = None,
        camera_number: int | None = None,
    ) -> CaptureFileStream:
        """Issue one authenticated GET and return an async-iterable stream.

        The response is never fully buffered: bytes are read and yielded in
        bounded chunks. ``media_timeout()`` leaves ``total`` unbounded so a
        large transfer is not cut short, while bounding ``sock_read`` so a
        server that stalls mid-body cannot hang the reader forever.

        ``path_suffix`` is percent-encoded here, per component: it carries a
        capture's filename, which encodes the camera's name and is therefore
        user-influenced. ``Capture.path`` is documented as *not* URL-encoded,
        so a ``?`` or ``#`` in a camera name would otherwise truncate the path
        and corrupt the query.

        Raises:
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- 401 is endpoint-dependent).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks a required permission (403), or a `401` that a
                disambiguating probe confirmed was a permission denial rather
                than rejected credentials.
            SecuritySpyConnectError: The server redirected, answered with an
                unexpected status, or the transport failed.

        """
        encoded_suffix = "/".join(quote(part, safe="") for part in path_suffix.split("/", 2))
        path = f"{endpoint}/{encoded_suffix}"
        url = self._connection.build_url(path)
        _LOGGER.debug(
            "Requesting %s from %s:%s", path, self._connection.host, self._connection.port
        )
        try:
            response = await self._connection.session.get(
                url,
                headers={"Authorization": self._connection.auth_header},
                params=dict(params),
                **self._request_kwargs(self._connection.media_timeout()),
            )
        except (aiohttp.ClientError, TimeoutError, OSError) as err:
            self._raise_transport_error(err)
        if not _HTTP_OK_MIN <= response.status <= _HTTP_OK_MAX:
            # Release before interpreting the status: on a 401 the mapping
            # below fires a second request to disambiguate it, and that must
            # not run while this failed response is still holding a
            # connection out of the caller's pool.
            response.release()
        await self._map_status(response.status, permission=permission, camera_number=camera_number)
        content_type = response.content_type or "application/octet-stream"
        return CaptureFileStream(
            response, self._connection.host, self._connection.port, content_type
        )

    async def async_get_camera_settings(self, camera_number: int) -> CameraSettings:
        """Read one camera's settings page (research §8.0).

        ⚠️ The raw payload contains the camera's device ``username`` and
        ``password`` in plaintext (research §8.3). It is dropped at decode and
        never logged at any level, including debug: the returned
        :class:`~aiosecurityspy.CameraSettings` carries only the curated,
        credential-free fields this library declares.

        Args:
            camera_number: The camera to read. ``cameraNum`` is *required* by
                this endpoint -- omitting it returns HTTP 500.

        Raises:
            ValueError: ``camera_number`` is not a non-negative integer. Raised
                before any request is issued.
            SecuritySpyConnectError: The server was unreachable, timed out,
                answered with an unexpected status, or sent a body that was not
                a settings object.
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- 401 is endpoint-dependent).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks the 'settings' permission (403), or a `401` that
                a disambiguating probe confirmed was a permission denial
                rather than rejected credentials.

        Returns:
            The decoded, credential-free settings.

        """
        number = _validated_camera_number(camera_number)
        payload = await self._request_json(
            ENDPOINT_SETTINGS_CAMERAS,
            {"cameraNum": str(number), "format": "json"},
            permission=PERMISSION_NAMES[PERM_SETTINGS],
            camera_number=number,
        )
        # The body is deliberately not echoed, and no local may still be holding
        # it on *any* exit: this endpoint's payload carries the camera's device
        # password in plaintext (research §8.3), and a traceback frame is
        # rendered verbatim by Sentry, `cgitb` and `pytest --showlocals`.
        # Dropping the raw dict from the returned model is not enough on its
        # own, and neither is dropping it on the branches we happen to expect --
        # a raise from inside `from_api` would leave the payload in the frame.
        # `finally` is what makes the guarantee unconditional.
        mapping: dict[str, object] = {}
        try:
            if isinstance(payload, dict):
                mapping = {str(key): value for key, value in payload.items()}  # pyright: ignore[reportUnknownVariableType]
            # A single overlapping key is not evidence that this is a settings
            # page; see `SETTINGS_PAGE_KEY_QUORUM`.
            if len(SETTINGS_PAGE_KEYS & mapping.keys()) < SETTINGS_PAGE_KEY_QUORUM:
                raise SecuritySpyConnectError(
                    self._connection.host,
                    self._connection.port,
                    "server response was not a settings object",
                )
            return CameraSettings.from_api(mapping, camera_number=number)
        finally:
            payload = None
            mapping = {}
            del payload, mapping

    async def async_set_camera_settings(
        self, camera_number: int, patch: CameraSettingsPatch
    ) -> None:
        """Write **only** the fields set on ``patch`` (research §8.0).

        The write is partial and verified safe as such: every untouched key on
        the ~120-key page keeps its value, so there is no read-modify-write and
        no race window. Three rules make this request work, and all three live
        here rather than at a call site:

        1. The request goes to the **bare** path -- the query form returns 404.
        2. ``cameraNum`` travels in the *body*, not the query string.
        3. The body opens with the literal ``formData`` sentinel, and booleans
           are written as ``1``/``0`` even though they read back as JSON
           ``true``/``false``.

        Args:
            camera_number: The camera to write.
            patch: The fields to change. ``None`` means "leave alone".

        Raises:
            ValueError: ``camera_number`` is not a non-negative integer, or the
                patch is empty. Raised before any request is issued.
            SecuritySpyConnectError: The server was unreachable, timed out, or
                answered with an unexpected status.
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- 401 is endpoint-dependent).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks the 'settings' permission (403), or a `401` that
                a disambiguating probe confirmed was a permission denial
                rather than rejected credentials.

        """
        number = _validated_camera_number(camera_number)
        fields = patch.form_fields()
        # Assembled as an ordered string, never handed to aiohttp as a dict:
        # the sentinel must come first and aiohttp would choose its own order.
        parts = [SETTINGS_FORM_SENTINEL, f"cameraNum={number}"]
        # `quote(..., safe="")`, i.e. `encodeURIComponent`, and deliberately *not*
        # plus-encoding: research §8.0's observed body is `overlayText=Front%20Gate`, so
        # the reference client percent-encodes a space. `%20` decodes to a space under a
        # URI decoder *and* a form decoder, while `+` only does under the latter -- and
        # which one the server uses is unknown.
        # `safe=""` leaves nothing unescaped, so `&`, `=`, `+` and `%` in a value cannot
        # forge a field separator, and a literal `+` round-trips as `%2B`.
        parts.extend(f"{key}={quote(value, safe='')}" for key, value in fields.items())
        # The patch itself is not logged: it can carry a camera name or an
        # overlay string, and settings payloads are never logged (research §8.3).
        _LOGGER.debug("Writing %s settings field(s) to camera %s", len(fields), number)
        await self._post_form(
            ENDPOINT_SETTINGS_CAMERAS,
            "&".join(parts),
            permission=PERMISSION_NAMES[PERM_SETTINGS],
            camera_number=number,
        )

    async def async_set_camera_enabled(self, camera_number: int, *, enabled: bool) -> None:
        """Enable or disable a camera (FR-16, research §5.5).

        Takes a camera in or out of service through the same verified
        partial-write path as :meth:`async_set_camera_settings`, writing the
        single ``enabled`` field. ``enabled`` is an id-only checkbox key on the
        settings page, which is why it is absent from the named-field list in
        research §8.1 (verification §5.5).

        Args:
            camera_number: The camera to enable or disable.
            enabled: The new state. ``False`` takes the camera out of service.

        Raises:
            ValueError: ``camera_number`` is not a non-negative integer. Raised
                before any request is issued.
            SecuritySpyConnectError: The server was unreachable, timed out, or
                answered with an unexpected status.
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial (research §5.9 -- 401 is endpoint-dependent).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks the 'settings' permission (403), or a `401` that
                a disambiguating probe confirmed was a permission denial
                rather than rejected credentials.

        """
        number = _validated_camera_number(camera_number)
        await self.async_set_camera_settings(number, CameraSettingsPatch(enabled=enabled))

    async def async_set_camera_arming(
        self,
        camera_number: int,
        modes: CaptureModes,
        *,
        override: ArmOverride | int,
    ) -> None:
        """Apply an override to a selected set of capture modes (research §5.14).

        ``mode`` selects **which** of the three capture modes a write applies to
        -- the target -- and ``override`` is the value applied to exactly those
        modes. It is not an armed state: there is no mode combination that
        "disarms all three", and an empty target is refused before any request,
        because the server answers ``200 OK`` having done nothing and no caller
        could detect it.

        The ``schedule`` query parameter is **never sent** (AD-7).
        ``++ssSetSchedule`` accepts one that permanently reassigns the camera's
        schedule; this library has no method that does that, and schedule ids
        read back from ``++systemInfo`` are read-only data. The override is
        *transient and bounded*: it suspends the schedule for a stated duration,
        after which the schedule resumes.

        ``200 OK`` means the request was *accepted*, not that anything was
        applied: the server returns ``OK`` even for a write that changed no
        field (verified live, research §5.14), and this library performs no
        read-back to confirm an effect.

        To disarm a mode, target it and apply one of the
        ``ARM_OVERRIDE_DISARMED_*`` overrides (or ``ARM_OVERRIDE_NONE`` to
        clear an override and let the schedule rule); there is no all-false
        target. Note that ``modes`` read back from ``++systemInfo`` are the
        camera's *armed state* -- re-targeting those booleans is a different
        instruction than restoring that state, so the two are not
        interchangeable without reinterpretation.

        Args:
            camera_number: The camera whose capture modes to write.
            modes: The capture modes the write targets. At least one must be
                true; an all-false set raises before any request.
            override: The value to apply to the selected modes. **Required,
                and deliberately without a default**: ``override`` is the only
                value this method ever applies (``schedule`` is never sent,
                AD-7), so a defaulted call would target modes, apply nothing,
                and return ``200 OK`` having done nothing -- the undetectable
                no-op an empty target is refused for. Passing
                ``ARM_OVERRIDE_UNCHANGED`` is still legal, but it is now an
                explicit "leave the existing override alone" the caller states
                rather than one the signature supplies. Accepts an
                ``ARM_OVERRIDE_*`` value or the typed
                :class:`~aiosecurityspy.ArmOverride` record.

        Raises:
            ValueError: ``camera_number`` is not a non-negative integer, no
                capture modes are targeted, or the override is not a value
                research §5.2 publishes. Raised before any request is issued.
            SecuritySpyConnectError: The server was unreachable, timed out, or
                answered with an unexpected status.
            SecuritySpyAuthError: The credentials were rejected (401), or a
                401 that a disambiguating probe could not confirm was a
                permission denial. Verified live: ``++ssSetSchedule`` answers a
                missing 'schedule' permission with 401, not 403 (research
                §5.9).
            SecuritySpyPermissionError: The credentials were accepted but the
                account lacks the 'schedule' permission -- reported as `403`
                on some servers, but verified live as `401` on 6.21
                (research §5.9), reclassified here by the disambiguating
                probe.

        """
        number = _validated_camera_number(camera_number)
        target = modes.mode_string
        # An empty mode set targets no capture modes, and the server answers
        # `200 OK` even for a write that changed no field -- so the resulting
        # no-op would be undetectable downstream. Refuse it here, before any
        # request is issued.
        if target == "":
            message = (
                "no capture modes targeted: an empty mode set would return "
                "200 OK having done nothing"
            )
            raise ValueError(message)
        # Every override goes through `arm_override`, whichever branch it
        # arrived on. `ArmOverride` is public and freely constructible, so a
        # hand-built `ArmOverride(value=15, ...)` would otherwise reach the wire
        # unvalidated -- exactly the undocumented value this method promises to
        # reject, arriving through the typed door rather than the int one.
        record = arm_override(override.value if isinstance(override, ArmOverride) else override)
        await self._request_text(
            ENDPOINT_SET_SCHEDULE,
            {
                "cameraNum": str(number),
                "mode": target,
                "override": str(record.value),
            },
            permission=PERMISSION_NAMES[PERM_SCHED],
            camera_number=number,
        )

    async def _request_json(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        permission: str | None = None,
        camera_number: int | None = None,
        disambiguate: bool = True,
    ) -> object:
        """Issue one authenticated GET and return its parsed JSON body.

        A thin wrapper over :meth:`_request`; the only thing it adds is the
        JSON parse.
        """
        body = await self._request(
            path,
            params=params,
            permission=permission,
            camera_number=camera_number,
            disambiguate=disambiguate,
        )
        try:
            return json.loads(body)
        except ValueError as err:
            # The body is deliberately not echoed *and* not left in the frame:
            # it can contain device credentials (research §8.3), and a
            # traceback renderer that prints locals would publish them.
            del body
            raise SecuritySpyConnectError(
                self._connection.host, self._connection.port, "server response was not valid JSON"
            ) from err

    async def _request_text(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        permission: str | None = None,
        camera_number: int | None = None,
    ) -> str:
        """Issue one authenticated GET whose body is not JSON, and return it.

        Used by endpoints that acknowledge a write without a documented body
        shape. The response still goes through the shared status mapping and
        byte cap; only the JSON parse is skipped.
        """
        return await self._request(
            path,
            params=params,
            strict_encoding=False,
            permission=permission,
            camera_number=camera_number,
        )

    async def _post_form(
        self,
        path: str,
        body: str,
        *,
        permission: str | None = None,
        camera_number: int | None = None,
    ) -> str:
        """POST an already-assembled ``application/x-www-form-urlencoded`` body.

        ``body`` is a string, never a mapping: SecuritySpy's settings pages
        require the literal ``formData`` sentinel *first* (research §8.0), and
        handing aiohttp a dict would let it choose its own ordering.
        """
        return await self._request(
            path,
            form_body=body,
            strict_encoding=False,
            permission=permission,
            camera_number=camera_number,
        )

    async def _request(  # noqa: PLR0913 - the transport seam's own kwargs plus the permission context threaded from call sites
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        form_body: str | None = None,
        strict_encoding: bool = True,
        permission: str | None = None,
        camera_number: int | None = None,
        disambiguate: bool = True,
    ) -> str:
        """Issue one authenticated request and return its decoded body text.

        This is the single transport seam. URL construction, the Authorization
        header, the per-request SSL flag, the timeout, redirect handling, status-to-exception
        mapping, the response byte cap and the never-echo-the-body rule all
        happen exactly once, here, for every verb this library speaks.

        Args:
            path: The endpoint path, without a leading slash.
            params: Query parameters. A settings write passes none: the query
                form of ``++settings-cameras`` returns 404.
            form_body: When given, the request is a ``POST`` carrying this
                pre-assembled form-urlencoded body. Otherwise it is a ``GET``.
            strict_encoding: Whether an undeterminable response charset is a
                failure. It is for JSON, where the body has to be parsed. For a
                write acknowledgement the body is not interpreted at all, so a
                charset-less ``text/plain`` receipt must not turn a successful
                write into a reported failure.

        """
        url = self._connection.build_url(path)
        _LOGGER.debug(
            "Requesting %s from %s:%s", path, self._connection.host, self._connection.port
        )
        # Shared kwargs, so no verb can drift on credentials, TLS or timeout.
        # Note that not following the redirect is no credential safeguard: over
        # plain HTTP the Basic credential is already on the wire, which is why
        # the README recommends HTTPS.
        shared: dict[str, Any] = {
            "params": dict(params or {}),
            **self._request_kwargs(self._connection.request_timeout()),
        }
        try:
            context = (
                self._connection.session.get(
                    url, headers={"Authorization": self._connection.auth_header}, **shared
                )
                if form_body is None
                else self._connection.session.post(
                    url,
                    data=form_body.encode("utf-8"),
                    headers={
                        "Authorization": self._connection.auth_header,
                        "Content-Type": _FORM_CONTENT_TYPE,
                    },
                    **shared,
                )
            )
            async with context as response:
                await self._map_status(
                    response.status,
                    permission=permission,
                    camera_number=camera_number,
                    disambiguate=disambiguate,
                )
                self._check_declared_length(response.content_length)
                # Accumulate rather than issuing one `read(n)`: StreamReader.read
                # returns whatever is currently buffered, not n bytes, so a
                # single call silently truncates any body that spans more than
                # one buffer fill. Reading one byte past the cap is what enforces
                # it -- a chunked response declares no Content-Length at all.
                chunks: list[bytes] = []
                raw = b""
                # Bound up front so the `finally` can clear it unconditionally:
                # the walrus below binds a *chunk* of the payload in this frame
                # too, and one uncleared local is the whole leak.
                chunk = b""
                total = 0
                try:
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
                    body = self._decode_body(raw, response, strict_encoding=strict_encoding)
                finally:
                    # A `++settings-cameras` body carries the camera's device
                    # password in plaintext (research §8.3). Every failure exit
                    # from the read -- the byte cap, an undecodable body, a
                    # dropped connection mid-stream -- raises from inside *this*
                    # frame, so `chunks` and `raw` would stay bound as frame
                    # locals holding the whole payload for any traceback handler
                    # that captures them. The scrub in `async_get_camera_settings`
                    # runs a frame away and cannot reach these. Unconditional,
                    # for the same reason that scrub is: a branch-local clear is
                    # one new exit path away from being no clear at all.
                    chunks.clear()
                    raw = b""
                    chunk = b""
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
        except (aiohttp.ClientError, TimeoutError, OSError) as err:
            # Ordering of the TLS / timeout / socket cases lives in
            # `_raise_transport_error`, shared with the byte and stream paths.
            self._raise_transport_error(err)

        return body

    @staticmethod
    def _decode_body(raw: bytes, response: Any, *, strict_encoding: bool) -> str:  # noqa: ANN401 - the stubbed session in the tests supplies its own response object
        """Decode a response body using the charset the response declares.

        When ``strict_encoding`` is false and aiohttp cannot determine a
        charset, the body is decoded as UTF-8 with replacement rather than
        failing: that path is only taken for bodies this library does not
        parse, and a write that succeeded must not be reported as a failure
        because its receipt lacked a ``charset`` parameter.
        """
        if strict_encoding:
            return raw.decode(response.get_encoding())
        try:
            encoding = response.get_encoding()
        except RuntimeError, LookupError:
            return raw.decode("utf-8", errors="replace")
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError, LookupError:
            return raw.decode("utf-8", errors="replace")
