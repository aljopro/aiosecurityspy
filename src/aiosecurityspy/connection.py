"""Validated transport state shared by every SecuritySpy consumer in this library.

The REST client and the event stream both need the same things: a validated
host, a port, a scheme, a credential, the per-request TLS flag and a timeout.
Deriving those twice is how two code paths end up disagreeing about what a valid
host is -- and how a credential-bearing URL gets built in a second place. This
module is that single place (AD-13): credentials live here as a pre-encoded
``Authorization`` header value and never enter a URL.

The module is internal. Nothing here is re-exported from the package.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from typing import Final

import aiohttp

from .const import DEFAULT_PORT, DEFAULT_TIMEOUT

__all__ = ["ConnectionSettings", "validate_credentials", "validate_host"]

_MIN_PORT: Final = 1
_MAX_PORT: Final = 65535

#: Hostnames are validated against an allowlist rather than a denylist: a
#: denylist of "characters that break a URL" is impossible to get right, and a
#: near-miss puts caller-controlled text into the URL we build.
_HOSTNAME_RE: Final = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")

_IPV6_VERSION: Final = 6


def validate_host(host: str) -> tuple[str, str]:
    """Validate a host and return ``(canonical_host, url_host)``.

    ``url_host`` is the form safe to interpolate into a URL: an IPv6 literal is
    bracketed, because ``http://::1:8000`` is not a parseable URL.

    Args:
        host: The caller-supplied host string.

    Returns:
        The canonical host and the URL-safe host.

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
            return text, f"[{text}]" if parsed.version == _IPV6_VERSION else text
    if not candidate or not _HOSTNAME_RE.match(candidate):
        # Deliberately does not echo the value: it is caller-supplied text and
        # a userinfo-bearing host would contain a password.
        msg = "host must be a bare hostname or IP address, without scheme, port or path"
        raise ValueError(msg)
    return candidate, candidate


def validate_credentials(username: str, password: str) -> None:
    """Reject credentials HTTP Basic auth cannot carry.

    Both checks exist to keep the credential out of a traceback: aiohttp raises
    ``UnicodeEncodeError`` at *request* time for a non-latin-1 credential, and
    that exception's ``args`` contain the password itself.

    Args:
        username: The SecuritySpy account name.
        password: The SecuritySpy account password.

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


@dataclass(frozen=True, slots=True)
class ConnectionSettings:
    """Everything needed to address one SecuritySpy server, validated once.

    Frozen so a client and any stream it spawns cannot drift apart, and so the
    credential cannot be swapped after construction. ``__repr__`` is overridden
    because a naively-added field could otherwise print the credential; today
    that is ``auth_header``, which already carries only the base64 encoding.
    """

    session: aiohttp.ClientSession
    host: str
    url_host: str
    port: int
    scheme: str
    #: A ready-to-send ``Authorization: Basic ...`` header value. Built once by
    #: :func:`aiohttp.encode_basic_auth` rather than carried as an
    #: :class:`aiohttp.BasicAuth`, which aiohttp deprecates in favor of this
    #: header form ahead of its removal in aiohttp 4.0.
    auth_header: str
    verify_ssl: bool
    timeout: float

    @classmethod
    def create(  # noqa: PLR0913 - connection parameters are irreducible; all but the first two are keyword-only
        cls,
        session: aiohttp.ClientSession,
        host: str,
        port: int = DEFAULT_PORT,
        *,
        username: str,
        password: str,
        use_https: bool = False,
        verify_ssl: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> ConnectionSettings:
        """Validate caller-supplied connection parameters and freeze them.

        Args:
            session: The caller's session. It is used as-is and is never
                closed, reconfigured, or replaced by this library.
            host: Hostname or IP address of the SecuritySpy server.
            port: Web-server port. Defaults to SecuritySpy's HTTP port.
            username: SecuritySpy account name.
            password: SecuritySpy account password.
            use_https: Whether to speak TLS to the server.
            verify_ssl: Whether to verify the server certificate.
            timeout: Total per-request timeout in seconds.

        Returns:
            The validated settings.

        Raises:
            ValueError: The host, port, timeout or credential is unusable. No
                message quotes the offending value.
            TypeError: ``port`` is not an integer.

        """
        canonical_host, url_host = validate_host(host)
        # `isinstance(True, int)` is True and a float port formats straight into
        # the URL, so a type check has to precede the range check: otherwise
        # port=8000.5 yields "http://host:8000.5" and every request fails
        # opaquely. Type annotations do not constrain runtime callers such as a
        # config flow reading user input.
        if isinstance(port, bool) or not isinstance(port, int):
            msg = "port must be an integer"
            raise TypeError(msg)
        if not _MIN_PORT <= port <= _MAX_PORT:
            msg = "port must be between 1 and 65535"
            raise ValueError(msg)
        if not math.isfinite(timeout) or timeout <= 0:
            # aiohttp reads `total=0` as "no timeout", and `inf`/`nan` slip past
            # a bare `<= 0` check while leaving the request effectively
            # unbounded -- either would void the guarantee that a wrong-host TLS
            # handshake fails rather than hangs.
            msg = "timeout must be a positive, finite number of seconds"
            raise ValueError(msg)
        validate_credentials(username, password)
        return cls(
            session=session,
            host=canonical_host,
            url_host=url_host,
            port=port,
            scheme="https" if use_https else "http",
            auth_header=aiohttp.encode_basic_auth(username, password),
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    @property
    def base_url(self) -> str:
        """The server's base URL. It never contains credentials."""
        return f"{self.scheme}://{self.url_host}:{self.port}"

    def build_url(self, path: str) -> str:
        """Build an absolute URL for one endpoint path.

        Args:
            path: An endpoint path such as ``"++systemInfo"``, without a
                leading slash.

        Returns:
            The absolute URL. Credentials are never interpolated into it; they
            travel as :attr:`auth_header` in an ``Authorization`` header.

        """
        return f"{self.base_url}/{path}"

    def request_timeout(self) -> aiohttp.ClientTimeout:
        """Return the bounded total timeout used for ordinary requests."""
        return aiohttp.ClientTimeout(total=self.timeout)

    def stream_timeout(self) -> aiohttp.ClientTimeout:
        """Return the timeout used for the long-lived event-stream response.

        ``total`` is deliberately ``None``: the event stream is a response that
        never ends, so a total deadline would tear it down on a schedule. The
        connect phases stay bounded so a wrong host or a black-holed TLS
        handshake still fails rather than hanging.
        """
        return aiohttp.ClientTimeout(total=None, connect=self.timeout, sock_connect=self.timeout)

    def __repr__(self) -> str:
        """Return a representation that cannot leak credentials."""
        return (
            f"ConnectionSettings(host={self.host!r}, port={self.port}, "
            f"scheme={self.scheme!r}, verify_ssl={self.verify_ssl})"
        )

    __str__ = __repr__
