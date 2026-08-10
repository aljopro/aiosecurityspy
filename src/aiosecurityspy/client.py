"""Authenticated REST client over a caller-injected ``aiohttp`` session.

The caller owns the session. This library never constructs, configures or
closes one, so :class:`SecuritySpyClient` deliberately has no ``close()`` and no
async-context-manager protocol.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC
from typing import TYPE_CHECKING, Final

import aiohttp

from .connection import ConnectionSettings
from .const import DEFAULT_PORT, DEFAULT_TIMEOUT, ENDPOINT_SYSTEM_INFO
from .exceptions import SecuritySpyAuthError, SecuritySpyConnectError
from .models import ServerInfo
from .stream import SecuritySpyEventStream

if TYPE_CHECKING:
    from collections.abc import Mapping
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
