"""Authenticated REST client over a caller-injected ``aiohttp`` session.

The caller owns the session. This library never constructs, configures or
closes one, so :class:`SecuritySpyClient` deliberately has no ``close()`` and no
async-context-manager protocol.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from typing import TYPE_CHECKING, Final

import aiohttp

from .const import DEFAULT_PORT, DEFAULT_TIMEOUT, ENDPOINT_SYSTEM_INFO
from .exceptions import SecuritySpyAuthError, SecuritySpyConnectError
from .models import ServerInfo

if TYPE_CHECKING:
    from collections.abc import Mapping

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

#: Hostnames are validated against an allowlist rather than a denylist: a
#: denylist of "characters that break a URL" is impossible to get right, and a
#: near-miss puts caller-controlled text into the URL we build.
_HOSTNAME_RE: Final = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


def _validate_host(host: str) -> tuple[str, str]:
    """Validate a host and return ``(canonical_host, url_host)``.

    ``url_host`` is the form safe to interpolate into a URL: an IPv6 literal is
    bracketed, because ``http://::1:8000`` is not a parseable URL.

    Raises:
        ValueError: The host is empty, over-long, or contains any character
            outside ``[A-Za-z0-9._-]`` -- which is what rejects a scheme, port,
            userinfo, path or whitespace. This is a character allowlist, not the
            full DNS grammar: it is what keeps caller-controlled text out of the
            URL, and it does not reject every malformed hostname (an empty label
            such as ``a..b`` still passes and simply fails to resolve).

    """
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate:
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            text = parsed.compressed
            return text, f"[{text}]" if parsed.version == 6 else text  # noqa: PLR2004 - IP version
    if not candidate or not _HOSTNAME_RE.match(candidate):
        # Deliberately does not echo the value: it is caller-supplied text and
        # a userinfo-bearing host would contain a password.
        msg = "host must be a bare hostname or IP address, without scheme, port or path"
        raise ValueError(msg)
    return candidate, candidate


def _validate_credentials(username: str, password: str) -> None:
    """Reject credentials HTTP Basic auth cannot carry.

    Both checks exist to keep the credential out of a traceback: aiohttp raises
    ``UnicodeEncodeError`` at *request* time for a non-latin-1 credential, and
    that exception's ``args`` contain the password itself.

    Raises:
        ValueError: The username contains ``':'`` (forbidden by RFC 7617) or a
            credential is not encodable as latin-1. Neither message quotes the
            value.

    """
    if ":" in username:
        msg = "username must not contain ':' (HTTP Basic auth cannot encode it)"
        raise ValueError(msg)
    for label, value in (("username", username), ("password", password)):
        try:
            value.encode("latin-1")
        except UnicodeEncodeError:
            msg = f"{label} must be encodable as latin-1 for HTTP Basic auth"
            raise ValueError(msg) from None


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
        self._host, self._url_host = _validate_host(host)
        # `isinstance(True, int)` is True and a float port formats straight into
        # the URL, so a type check has to precede the range check: otherwise
        # port=8000.5 yields "http://host:8000.5" and every request fails
        # opaquely. Type annotations do not constrain runtime callers such as a
        # config flow reading user input.
        if isinstance(port, bool) or not isinstance(port, int):
            msg = "port must be an integer"
            raise TypeError(msg)
        if not 1 <= port <= 65535:  # noqa: PLR2004 - the TCP port range is not a magic number
            msg = "port must be between 1 and 65535"
            raise ValueError(msg)
        if not math.isfinite(timeout) or timeout <= 0:
            # aiohttp reads `total=0` as "no timeout", and `inf`/`nan` slip past
            # a bare `<= 0` check while leaving the request effectively
            # unbounded -- either would void the guarantee that a wrong-host TLS
            # handshake fails rather than hangs.
            msg = "timeout must be a positive, finite number of seconds"
            raise ValueError(msg)
        _validate_credentials(username, password)
        self._session = session
        self._port = port
        self._auth = aiohttp.BasicAuth(username, password)
        self._verify_ssl = verify_ssl
        self._scheme = "https" if use_https else "http"
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    @property
    def host(self) -> str:
        """The configured host."""
        return self._host

    @property
    def port(self) -> int:
        """The configured port."""
        return self._port

    @property
    def base_url(self) -> str:
        """The server's base URL. It never contains credentials."""
        return f"{self._scheme}://{self._url_host}:{self._port}"

    def __repr__(self) -> str:
        """Return a representation that cannot leak credentials."""
        return (
            f"SecuritySpyClient(host={self._host!r}, port={self._port}, "
            f"scheme={self._scheme!r}, verify_ssl={self._verify_ssl})"
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
        url = f"{self.base_url}/{path}"
        _LOGGER.debug("Requesting %s from %s:%s", path, self._host, self._port)
        try:
            async with self._session.get(
                url,
                params=dict(params or {}),
                auth=self._auth,
                ssl=self._verify_ssl,
                timeout=self._timeout,
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
                    raise SecuritySpyAuthError(self._host, self._port, status)
                if _HTTP_REDIRECT_MIN <= status <= _HTTP_REDIRECT_MAX:
                    # Almost always "you asked for http, this server wants
                    # https". Say so, rather than reporting a bare 301.
                    raise SecuritySpyConnectError(
                        self._host,
                        self._port,
                        f"server redirected (HTTP {status}); if the server uses TLS, "
                        "construct the client with use_https=True",
                    )
                if not _HTTP_OK_MIN <= status <= _HTTP_OK_MAX:
                    raise SecuritySpyConnectError(
                        self._host, self._port, f"unexpected HTTP status {status}"
                    )
                declared = response.content_length
                if declared is not None and declared > _MAX_BODY_BYTES:
                    raise SecuritySpyConnectError(
                        self._host, self._port, "server response body was too large"
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
                            self._host, self._port, "server response body was too large"
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
                self._host, self._port, "server response encoding was not determinable"
            ) from err
        except (UnicodeDecodeError, LookupError) as err:
            # A body that will not decode -- or that declares a charset Python
            # does not know -- is a broken server, not a Python bug; it must not
            # escape as a bare ValueError or LookupError.
            raise SecuritySpyConnectError(
                self._host, self._port, "server response was not decodable text"
            ) from err
        except TimeoutError as err:
            raise SecuritySpyConnectError(self._host, self._port, "request timed out") from err
        except aiohttp.ClientError as err:
            raise SecuritySpyConnectError(
                self._host, self._port, f"transport failure ({type(err).__name__})"
            ) from err
        except OSError as err:
            raise SecuritySpyConnectError(
                self._host, self._port, f"connection failure ({type(err).__name__})"
            ) from err

        try:
            return json.loads(body)
        except ValueError as err:
            # The body is deliberately not echoed: it can contain device
            # credentials (research §8.3).
            raise SecuritySpyConnectError(
                self._host, self._port, "server response was not valid JSON"
            ) from err
