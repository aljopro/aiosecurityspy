"""Typed exception hierarchy for :mod:`aiosecurityspy` (AD-6).

Every failure *originating from the server or the transport* is a
:class:`SecuritySpyError` subclass: no ``aiohttp`` exception, ``TimeoutError``,
``JSONDecodeError``, ``KeyError`` or ``ValueError`` is allowed to escape a
request or a decode. Caller mistakes are the deliberate exception --
:class:`~aiosecurityspy.SecuritySpyClient` validates its arguments and raises
``ValueError`` from its constructor, because a bad host or credential is a
programming error rather than a runtime condition to be handled.

None of these exceptions carry credentials. They are constructed from a host,
a port, a status code or a version string only, so neither ``str()``, ``repr()``
nor a traceback frame can leak a username or password (AD-13).
"""

from __future__ import annotations

__all__ = [
    "SecuritySpyAuthError",
    "SecuritySpyCertificateError",
    "SecuritySpyConnectError",
    "SecuritySpyError",
    "SecuritySpyPermissionError",
    "SecuritySpyUnsupportedVersionError",
]


class SecuritySpyError(Exception):
    """Base class for every error raised by this library."""

    def __repr__(self) -> str:
        """Return a credential-free representation."""
        return f"{type(self).__name__}({str(self)!r})"


class SecuritySpyConnectError(SecuritySpyError):
    """A transient transport failure: unreachable host, timeout, TLS or bad body.

    Callers may retry this class of failure.
    """

    def __init__(self, host: str, port: int, reason: str) -> None:
        """Record the endpoint that failed and a credential-free reason."""
        self.host = host
        self.port = port
        self.reason = reason
        super().__init__(f"Cannot reach SecuritySpy at {host}:{port}: {reason}")


class SecuritySpyCertificateError(SecuritySpyConnectError):
    """TLS was spoken, and the server's certificate failed *verification*.

    Deliberately a *subclass* of :class:`SecuritySpyConnectError` rather than a
    sibling: every consumer that already catches a connect error keeps working
    unchanged, while a consumer that wants to name the certificate specifically
    opts in by testing this type **first**. Any ``except`` or ``isinstance``
    chain handling both must therefore put this one ahead of its parent.

    Raised only for a genuine certificate-validation failure -- an expired
    certificate, an unknown issuer, a name that does not match the address
    used. Every other TLS failure stays a plain :class:`SecuritySpyConnectError`
    (see :mod:`aiosecurityspy.client`), because this error's whole value is that
    turning verification off is a real remedy for it, and for a handshake that
    failed for some other reason it is not.
    """

    def __init__(self, host: str, port: int, reason: str) -> None:
        """Record the endpoint and a credential-free description of the failure.

        Args:
            host: The host that was contacted.
            port: The port that was contacted.
            reason: A short, credential-free OpenSSL reason such as
                ``CERTIFICATE_VERIFY_FAILED``, or the exception's type name when
                no reason is available.

        """
        super().__init__(
            host,
            port,
            f"the server's TLS certificate could not be verified ({reason}); it may "
            "have expired, been issued by an unknown authority, or been issued for a "
            "different name than the address used to connect -- certificate "
            "verification can be disabled to accept it anyway",
        )


class SecuritySpyAuthError(SecuritySpyError):
    """The server rejected the supplied credentials (HTTP 401 or 403).

    The library never counts auth failures, persists auth state, or initiates
    reauthentication; that is the consumer's job (AD-6, AD-18).
    """

    def __init__(self, host: str, port: int, status: int) -> None:
        """Record the endpoint and the rejecting status code, never the credentials."""
        self.host = host
        self.port = port
        self.status = status
        super().__init__(
            f"SecuritySpy at {host}:{port} rejected the supplied credentials (HTTP {status})"
        )


class SecuritySpyPermissionError(SecuritySpyError):
    """The account authenticated but lacks the permission a request requires."""

    def __init__(self, permission: str, camera_number: int | None = None) -> None:
        """Record the missing permission and, when relevant, the camera it applies to."""
        self.permission = permission
        self.camera_number = camera_number
        where = "" if camera_number is None else f" for camera {camera_number}"
        super().__init__(f"SecuritySpy account lacks the {permission!r} permission{where}")


class SecuritySpyUnsupportedVersionError(SecuritySpyError):
    """The server is too old, or its payload shape cannot be located.

    This is a permanent incompatibility: retrying will not help.
    """

    def __init__(self, found: str | None, required: str) -> None:
        """Record the version found on the server (if any) and the minimum required."""
        self.found = found
        self.required = required
        found_text = "unknown" if found is None else found
        super().__init__(
            f"SecuritySpy server version {found_text} is not supported; "
            f"version {required} or newer is required"
        )
