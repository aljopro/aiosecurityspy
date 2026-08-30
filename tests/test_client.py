"""Transport coverage for SecuritySpyClient against a stubbed aiohttp session."""

from __future__ import annotations

import contextlib
import json
import ssl
import traceback
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self, cast
from zoneinfo import ZoneInfo

import aiohttp
import pytest
import yarl

from aiosecurityspy import (
    ARM_OVERRIDE_ARMED_2_HOURS,
    CAPTURE_FILE_BANDWIDTH_HIGH,
    CAPTURE_FILE_BANDWIDTH_LOW,
    CAPTURE_FILE_BANDWIDTH_STANDARD,
    CAPTURE_FILTER_ALL,
    CAPTURE_FILTER_ANIMAL,
    CAPTURE_FILTER_CONTINUOUS,
    CAPTURE_FILTER_HUMAN,
    CAPTURE_FILTER_MOVIES,
    CAPTURE_FILTER_VEHICLE,
    DEFAULT_TIMEOUT,
    PERM_FILES,
    PERM_SCHED,
    PERMISSION_NAMES,
    CameraSettingsPatch,
    CaptureFileStream,
    CaptureModes,
    SecuritySpyAuthError,
    SecuritySpyCertificateError,
    SecuritySpyClient,
    SecuritySpyConnectError,
    SecuritySpyError,
    SecuritySpyPermissionError,
    SecuritySpyUnsupportedVersionError,
)
from aiosecurityspy import client as client_module
from aiosecurityspy.models import Capture, ServerInfo, capture_file_bandwidth

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

FIXTURES = Path(__file__).parent / "fixtures"
HOST = "nvr.example.com"
PORT = 8001
USERNAME = "sentinel-user-9d3f"
PASSWORD = "sentinel-pass-4a71"  # noqa: S105 - leak-detection sentinel, not a real credential
DEFAULT_TIMEOUT_SECONDS = 30.0
CUSTOM_TIMEOUT_SECONDS = 2.5
TWO_STATUSES = 2


def fixture_body() -> str:
    return (FIXTURES / "system_info.json").read_text()


class FakeContent:
    """Minimal stand-in for `response.content`, which is read with a byte cap.

    Deliberately fragments: `aiohttp.StreamReader.read(n)` returns whatever is
    currently buffered rather than n bytes, so a stub that hands back the whole
    body in one call cannot catch a caller that reads only once. Chunking at a
    small size means every body of more than `CHUNK` bytes exercises the
    accumulation loop, and the position tracking means a caller that never
    advances loops forever rather than silently truncating.
    """

    #: Small enough that the ordinary fixture body spans several reads.
    CHUNK = 64

    def __init__(self, raw: bytes) -> None:
        """Store the canned bytes."""
        self._raw = raw
        self._pos = 0

    async def read(self, limit: int = -1) -> bytes:
        """Return at most `limit` bytes from the current position, then advance."""
        take = len(self._raw) - self._pos if limit < 0 else min(limit, self.CHUNK)
        chunk = self._raw[self._pos : self._pos + take]
        self._pos += len(chunk)
        return chunk


class FakeResponse:
    """Minimal stand-in for an aiohttp response."""

    #: Overridden by tests that need a body the declared encoding cannot decode.
    encoding = "utf-8"

    def __init__(self, status: int, body: str) -> None:
        """Store the canned status and body."""
        self.status = status
        self._raw = self.encode_body(body)
        self.content = FakeContent(self._raw)

    @staticmethod
    def encode_body(body: str) -> bytes:
        """Encode the canned body the way a well-behaved server would."""
        return body.encode("utf-8")

    @property
    def content_length(self) -> int | None:
        """The declared body length, as aiohttp reports it."""
        return len(self._raw)

    def get_encoding(self) -> str:
        """Return the charset the response declares."""
        return self.encoding

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


class RaisingContext:
    """An async context manager that fails on entry, like a connector error."""

    def __init__(self, error: BaseException) -> None:
        """Store the error to raise on entry."""
        self._error = error

    async def __aenter__(self) -> FakeResponse:
        """Raise the configured transport error."""
        raise self._error

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Leave the context without suppressing anything."""

    def __await__(self) -> Any:  # noqa: ANN401
        """Support ``await session.get(...)`` in addition to ``async with``."""

        async def _raise() -> None:
            raise self._error

        return _raise().__await__()


class FakeSession:
    """Records how the client called it, and never closes itself."""

    def __init__(
        self,
        status: int = 200,
        body: str = "",
        error: BaseException | None = None,
    ) -> None:
        """Configure the canned response or the transport error to raise."""
        self._status = status
        self._body = body
        self._error = error
        self.closed = False
        self.calls: list[tuple[str, dict[str, Any]]] = []
        #: The verb of each recorded call, positionally aligned with ``calls``.
        self.methods: list[str] = []
        self.response_factory: type[FakeResponse] = FakeResponse

    def get(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Record the call and return an async context manager."""
        return self._record("GET", url, kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Record a POST and return an async context manager.

        The settings write is the library's first non-GET request, and a stub
        that cannot observe the verb would let a POST reach an undefined
        attribute instead of being recorded. Both verbs land in ``calls``.
        """
        return self._record("POST", url, kwargs)

    def _record(self, method: str, url: str, kwargs: dict[str, Any]) -> Any:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Append the call and build the canned response or error."""
        self.methods.append(method)
        self.calls.append((url, kwargs))
        if self._error is not None:
            return RaisingContext(self._error)
        return self.response_factory(self._status, self._body)

    async def close(self) -> None:  # pragma: no cover - must never be called
        """Mark the session closed; the library must never reach this."""
        self.closed = True


def make_client(
    session: FakeSession,
    port: int = PORT,
    *,
    host: str = HOST,
    username: str = USERNAME,
    password: str = PASSWORD,
    **kwargs: Any,  # noqa: ANN401 - passthrough to the client's own signature
) -> SecuritySpyClient:
    return SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        host,
        port,
        username=username,
        password=password,
        **kwargs,
    )


def connector_error() -> aiohttp.ClientError:
    return aiohttp.ClientConnectionError(f"cannot connect to host {HOST}:{PORT}")


class FakeCertificateError(aiohttp.ClientConnectorCertificateError):
    """A real `ClientConnectorCertificateError`, minus the private ConnectionKey.

    aiohttp's own constructor reads `connection_key.host`, so building one
    outside a connector means reaching into private plumbing. Subclassing gives
    the genuine type -- which is what the client's `except` clause matches on --
    with the `certificate_error` attribute production carries.
    """

    def __init__(self, message: str, reason: str = "CERTIFICATE_VERIFY_FAILED") -> None:
        """Build the error, carrying an inner `ssl` error like the real one."""
        Exception.__init__(self, message)
        inner = ssl.SSLCertVerificationError(1, message)
        inner.reason = reason
        # `certificate_error` is a read-only property over this attribute.
        self._certificate_error = inner
        # Kept separately from `args`: aiohttp's own `__init__` re-assigns
        # `args` to `(ConnectionKey, Exception)`, so the declared element type
        # there is not `str`.
        self._message = message

    def __str__(self) -> str:
        """Render from the message, not from aiohttp's unset `_conn_key`.

        aiohttp's own `__str__` formats the private `ConnectionKey` this fake
        deliberately does not build, so without this override any *failing*
        assertion below would blow up in pytest's traceback rendering -- an
        `AttributeError` in place of the real failure.
        """
        return self._message


def certificate_error() -> aiohttp.ClientError:
    return FakeCertificateError(f"certificate verify failed for {HOST}")


def bare_certificate_error() -> ssl.SSLCertVerificationError:
    """Build a certificate rejection raised outside aiohttp's connector wrapper.

    `ssl.SSLCertVerificationError` is an `OSError` but not an
    `aiohttp.ClientError`, so it reaches the client through a different door
    than the aiohttp family and has to be caught explicitly to land on the same
    error type.
    """
    err = ssl.SSLCertVerificationError(1, f"certificate verify failed for {HOST}")
    err.reason = "CERTIFICATE_VERIFY_FAILED"
    return err


class FakeHandshakeError(aiohttp.ClientConnectorSSLError):
    """A TLS failure that is *not* a certificate rejection.

    This is what speaking TLS to SecuritySpy's plain-HTTP port raises -- the
    likeliest mistake once the form grows an HTTPS toggle, since the port field
    still defaults to the HTTP listener. Built the same way as
    `FakeCertificateError`, and for the same reason.
    """

    def __init__(self, message: str) -> None:
        """Build the error, carrying the inner `ssl` error under `os_error`."""
        Exception.__init__(self, message)
        inner = ssl.SSLError(1, message)
        inner.reason = "WRONG_VERSION_NUMBER"
        # `os_error` is a read-only property over this attribute.
        self._os_error = inner
        self._message = message

    def __str__(self) -> str:
        """Render from the message; see `FakeCertificateError.__str__`."""
        return self._message


def handshake_error() -> aiohttp.ClientError:
    return FakeHandshakeError("[SSL: WRONG_VERSION_NUMBER] wrong version number")


# --- happy path -------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_returns_server_info() -> None:
    session = FakeSession(200, fixture_body())
    info = await make_client(session).async_get_server_info()
    assert info.version == "6.20"
    assert set(info.cameras) == {0, 1, 7}


@pytest.mark.asyncio
async def test_request_shape() -> None:
    session = FakeSession(200, fixture_body())
    await make_client(session).async_get_server_info()
    url, kwargs = session.calls[0]
    assert url == f"http://{HOST}:{PORT}/++systemInfo"
    assert kwargs["params"] == {"format": "json"}
    assert kwargs["headers"]["Authorization"] == aiohttp.encode_basic_auth(USERNAME, PASSWORD)
    assert isinstance(kwargs["timeout"], aiohttp.ClientTimeout)
    assert kwargs["timeout"].total == DEFAULT_TIMEOUT_SECONDS


@pytest.mark.asyncio
async def test_https_scheme_when_requested() -> None:
    session = FakeSession(200, fixture_body())
    client = make_client(session, use_https=True)
    await client.async_get_server_info()
    assert session.calls[0][0].startswith("https://")
    assert client.base_url == f"https://{HOST}:{PORT}"


@pytest.mark.asyncio
async def test_custom_timeout_is_applied() -> None:
    session = FakeSession(200, fixture_body())
    await make_client(session, timeout=CUSTOM_TIMEOUT_SECONDS).async_get_server_info()
    assert session.calls[0][1]["timeout"].total == CUSTOM_TIMEOUT_SECONDS


# --- session ownership and ssl flag ----------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("verify", [True, False])
async def test_verify_ssl_is_passed_per_request(verify: bool) -> None:  # noqa: FBT001 - parametrized flag
    session = FakeSession(200, fixture_body())
    await make_client(session, verify_ssl=verify).async_get_server_info()
    assert session.calls[0][1]["ssl"] is verify


def test_client_has_no_close_or_context_manager() -> None:
    client = make_client(FakeSession(200, fixture_body()))
    assert not hasattr(client, "close")
    assert not hasattr(client, "__aenter__")
    assert not hasattr(client, "__aexit__")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        # `None` means "load the fixture", resolved inside the test so a missing
        # fixture is a test failure rather than a collection error.
        (200, None, None),
        (401, "", None),
        (500, "", None),
        (200, "<html>not json</html>", None),
        (200, "", aiohttp.ClientConnectionError("boom")),
    ],
)
async def test_injected_session_is_never_closed(
    status: int, body: str | None, error: BaseException | None
) -> None:
    session = FakeSession(status, fixture_body() if body is None else body, error)
    client = make_client(session)
    with contextlib.suppress(SecuritySpyError):
        await client.async_get_server_info()
    assert session.closed is False


# --- error mapping ----------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_failure_maps_to_auth_error() -> None:
    status = 401
    session = FakeSession(status, "")
    with pytest.raises(SecuritySpyAuthError) as err:
        await make_client(session).async_get_server_info()
    assert err.value.status == status
    assert f"{HOST}:{PORT}" in str(err.value)


@pytest.mark.asyncio
async def test_permission_denied_maps_to_permission_error_not_auth_error() -> None:
    # Verified against a live 6.21 server (research §4.1, §5.2, §7.1): 403 means
    # the credentials were *accepted* and the account merely lacks a
    # permission bit, not that the credentials were rejected.
    session = FakeSession(403, "")
    with pytest.raises(SecuritySpyPermissionError):
        await make_client(session).async_get_server_info()


@pytest.mark.asyncio
async def test_permission_denied_is_not_caught_by_auth_error_handler() -> None:
    """A consumer catching only SecuritySpyAuthError must not see a 403."""
    session = FakeSession(403, "")
    try:
        await make_client(session).async_get_server_info()
    except SecuritySpyAuthError:
        pytest.fail("403 must not raise SecuritySpyAuthError")
    except SecuritySpyPermissionError:
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 404, 500, 503])
async def test_non_auth_bad_status_maps_to_connect_error(status: int) -> None:
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(FakeSession(status, "")).async_get_server_info()
    assert str(status) in str(err.value)


@pytest.mark.asyncio
async def test_non_json_body_maps_to_connect_error_without_echoing_it() -> None:
    secret_body = "<html>device-secret-in-here</html>"  # noqa: S105 - body content, not a credential
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(FakeSession(200, secret_body)).async_get_server_info()
    assert "device-secret-in-here" not in str(err.value)
    assert "not valid JSON" in str(err.value)


@pytest.mark.asyncio
async def test_connector_error_maps_to_connect_error_with_cause() -> None:
    original = connector_error()
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(FakeSession(error=original)).async_get_server_info()
    assert err.value.__cause__ is original
    assert err.value.host == HOST
    assert err.value.port == PORT


@pytest.mark.asyncio
async def test_timeout_maps_to_connect_error() -> None:
    original = TimeoutError()
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(FakeSession(error=original)).async_get_server_info()
    assert "timed out" in str(err.value)
    assert err.value.__cause__ is original


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory",
    [certificate_error, bare_certificate_error],
    ids=["aiohttp-certificate-error", "bare-certificate-error"],
)
async def test_certificate_error_maps_to_certificate_error(
    factory: Callable[[], BaseException],
) -> None:
    """A rejected certificate is its own type, and still a connect error.

    The subclass relationship is the whole compatibility story: a consumer that
    only knows `SecuritySpyConnectError` keeps catching this, while one that
    wants to name the certificate tests the subclass first.
    """
    original = factory()
    with pytest.raises(SecuritySpyCertificateError) as err:
        await make_client(FakeSession(error=original)).async_get_server_info()

    assert isinstance(err.value, SecuritySpyConnectError)
    assert err.value.__cause__ is original
    assert err.value.host == HOST
    assert err.value.port == PORT
    assert f"{HOST}:{PORT}" in str(err.value)
    # The message must send the user to the certificate, not to their password:
    # a mismatch reported as an auth or network fault is the failure this type
    # exists to prevent.
    assert "certificate" in str(err.value)
    assert "CERTIFICATE_VERIFY_FAILED" in str(err.value)
    assert "credential" not in str(err.value)
    assert "password" not in str(err.value)


@pytest.mark.asyncio
async def test_handshake_failure_is_not_reported_as_a_certificate_problem() -> None:
    """A non-certificate TLS failure must not advise disabling verification.

    Speaking TLS to a plain-HTTP listener raises `WRONG_VERSION_NUMBER` with
    verification on *and* off, so reporting it as a rejected certificate sends
    the user to a setting that cannot fix it.
    """
    original = handshake_error()
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(FakeSession(error=original)).async_get_server_info()

    assert not isinstance(err.value, SecuritySpyCertificateError)
    assert err.value.__cause__ is original
    assert "WRONG_VERSION_NUMBER" in str(err.value)
    assert "plain HTTP" in str(err.value)
    assert "certificate" not in str(err.value)


@pytest.mark.asyncio
async def test_tls_failure_without_a_reason_falls_back_to_the_type_name() -> None:
    """A TLS error carrying no OpenSSL reason still names something usable.

    A bare `ssl.SSLError` is not a certificate rejection, so it must stay on the
    handshake branch: `"SSLError" in ...` alone would also be satisfied by the
    string `SSLCertVerificationError`, which is exactly the misrouting this
    asserts against.
    """
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(FakeSession(error=ssl.SSLError("no reason here"))).async_get_server_info()
    assert not isinstance(err.value, SecuritySpyCertificateError)
    assert "(SSLError)" in str(err.value)


@pytest.mark.asyncio
async def test_os_error_maps_to_connect_error() -> None:
    with pytest.raises(SecuritySpyConnectError):
        await make_client(FakeSession(error=OSError("no route to host"))).async_get_server_info()


@pytest.mark.asyncio
async def test_old_server_maps_to_unsupported_version() -> None:
    body = json.dumps({"system": {"server": {"version": "5.2", "uuid": "a"}}})
    with pytest.raises(SecuritySpyUnsupportedVersionError) as err:
        await make_client(FakeSession(200, body)).async_get_server_info()
    assert "5.2" in str(err.value)
    assert "6.0" in str(err.value)


@pytest.mark.asyncio
async def test_unlocatable_payload_maps_to_unsupported_version() -> None:
    with pytest.raises(SecuritySpyUnsupportedVersionError):
        await make_client(FakeSession(200, '{"unexpected": true}')).async_get_server_info()


# --- credential containment -------------------------------------------------


def failure_rows() -> list[tuple[str, Callable[[], FakeSession]]]:
    """One labelled session factory per failure row of the I/O matrix.

    Parametrized rather than looped so one failing row cannot mask the rest and
    the report names the row that broke.
    """
    old_server = json.dumps({"system": {"server": {"version": "5.0", "uuid": "a"}}})
    return [
        ("401", lambda: FakeSession(401, "")),
        ("403", lambda: FakeSession(403, "")),
        ("500", lambda: FakeSession(500, "")),
        ("body-with-password", lambda: FakeSession(200, f"<html>{PASSWORD}</html>")),
        ("old-server", lambda: FakeSession(200, old_server)),
        ("unlocatable-payload", lambda: FakeSession(200, '{"unexpected": true}')),
        ("connector-error", lambda: FakeSession(error=connector_error())),
        ("timeout", lambda: FakeSession(error=TimeoutError())),
        ("certificate-error", lambda: FakeSession(error=certificate_error())),
        ("bare-certificate-error", lambda: FakeSession(error=bare_certificate_error())),
        ("handshake-error", lambda: FakeSession(error=handshake_error())),
        ("os-error", lambda: FakeSession(error=OSError("boom"))),
    ]


FAILURE_ROWS = failure_rows()
FAILURE_IDS = [label for label, _ in FAILURE_ROWS]
FAILURE_FACTORIES = [factory for _, factory in FAILURE_ROWS]


@pytest.mark.asyncio
@pytest.mark.parametrize("factory", FAILURE_FACTORIES, ids=FAILURE_IDS)
async def test_every_mapped_error_is_a_securityspy_error(
    factory: Callable[[], FakeSession],
) -> None:
    with pytest.raises(SecuritySpyError):
        await make_client(factory()).async_get_server_info()


@pytest.mark.asyncio
@pytest.mark.parametrize("factory", FAILURE_FACTORIES, ids=FAILURE_IDS)
async def test_no_error_surface_leaks_credentials(factory: Callable[[], FakeSession]) -> None:
    client = make_client(factory())
    with pytest.raises(SecuritySpyError) as err:
        await client.async_get_server_info()
    surfaces = [
        str(err.value),
        repr(err.value),
        "".join(traceback.format_exception(err.value)),
    ]
    for surface in surfaces:
        assert USERNAME not in surface
        assert PASSWORD not in surface


@pytest.mark.asyncio
async def test_client_repr_and_url_never_carry_credentials() -> None:
    session = FakeSession(200, fixture_body())
    client = make_client(session)
    await client.async_get_server_info()
    surfaces = [repr(client), str(client), client.base_url, session.calls[0][0]]
    for surface in surfaces:
        assert USERNAME not in surface
        assert PASSWORD not in surface
        assert "@" not in surface
        assert "auth=" not in surface


@pytest.mark.asyncio
async def test_server_info_repr_never_carries_credentials() -> None:
    info = await make_client(FakeSession(200, fixture_body())).async_get_server_info()
    surfaces = [repr(info), str(info), *(repr(cam) for cam in info.cameras.values())]
    for surface in surfaces:
        assert USERNAME not in surface
        assert PASSWORD not in surface


# --- constructor validation and body decoding -------------------------------


@pytest.mark.parametrize(
    "host",
    ["", "http://nvr", "nvr/", f"{USERNAME}:{PASSWORD}@nvr", "nvr example"],
)
def test_unusable_host_is_rejected_at_construction(host: str) -> None:
    """A host carrying userinfo or a scheme would put credentials in the URL."""
    with pytest.raises(ValueError, match="host"):
        SecuritySpyClient(
            cast("aiohttp.ClientSession", FakeSession()),
            host,
            username=USERNAME,
            password=PASSWORD,
        )


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_out_of_range_port_is_rejected_at_construction(port: int) -> None:
    with pytest.raises(ValueError, match="port"):
        make_client(FakeSession(), port=port)


@pytest.mark.parametrize(
    ("label", "port"),
    [("float", 8000.5), ("bool", True), ("string", "8000")],
)
def test_non_integer_port_is_rejected_at_construction(label: str, port: object) -> None:
    """A float or bool port formats straight into the URL: `http://host:8000.5`."""
    del label
    with pytest.raises(TypeError, match="port must be an integer"):
        make_client(FakeSession(), port=cast("int", port))


@pytest.mark.parametrize(
    ("label", "timeout"),
    [
        ("zero", 0.0),
        ("negative", -1.0),
        ("infinity", float("inf")),
        ("nan", float("nan")),
    ],
)
def test_unusable_timeout_is_rejected_at_construction(label: str, timeout: float) -> None:
    """`total=0` reads as "no timeout"; inf/nan slip past a bare `<= 0` check."""
    del label
    with pytest.raises(ValueError, match="timeout"):
        make_client(FakeSession(), timeout=timeout)


@pytest.mark.asyncio
async def test_undecodable_body_maps_to_connect_error() -> None:
    """Decoding the body raises UnicodeDecodeError, a ValueError, on a bad charset."""

    class UndecodableResponse(FakeResponse):
        @staticmethod
        def encode_body(body: str) -> bytes:
            del body
            return b"\xff\xfe not utf-8"

    session = FakeSession(200, "")
    session.response_factory = UndecodableResponse
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(session).async_get_server_info()
    assert "not decodable" in str(err.value)
    assert isinstance(err.value.__cause__, UnicodeDecodeError)


@pytest.mark.asyncio
async def test_unknown_declared_charset_maps_to_connect_error() -> None:
    """A charset Python does not know raises LookupError, which must not escape."""

    class BogusCharsetResponse(FakeResponse):
        encoding = "definitely-not-a-charset"

    session = FakeSession(200, "{}")
    session.response_factory = BogusCharsetResponse
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(session).async_get_server_info()
    assert "not decodable" in str(err.value)
    assert isinstance(err.value.__cause__, LookupError)


@pytest.mark.asyncio
async def test_oversized_body_is_refused_rather_than_buffered() -> None:
    """The timeout bounds duration, not bytes; a huge body must fail fast."""

    class HugeResponse(FakeResponse):
        @staticmethod
        def encode_body(body: str) -> bytes:
            del body
            return b"x" * (client_module._MAX_BODY_BYTES + 1)  # noqa: SLF001 - the cap under test

    session = FakeSession(200, "")
    session.response_factory = HugeResponse
    with pytest.raises(SecuritySpyConnectError, match="too large"):
        await make_client(session).async_get_server_info()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [100, 199, 400, 500])
async def test_only_2xx_is_treated_as_success(status: int) -> None:
    """1xx and non-auth 4xx/5xx are not success; only 200-299 reach the parse."""
    session = FakeSession(status, fixture_body())
    with pytest.raises(SecuritySpyConnectError, match="unexpected HTTP status"):
        await make_client(session).async_get_server_info()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [300, 301, 302, 307, 399])
async def test_redirects_are_reported_as_a_scheme_hint(status: int) -> None:
    """A 3xx is almost always "you asked for http, this server wants https"."""
    session = FakeSession(status, fixture_body())
    with pytest.raises(SecuritySpyConnectError, match="use_https=True") as err:
        await make_client(session).async_get_server_info()
    assert f"HTTP {status}" in str(err.value)


@pytest.mark.parametrize(
    "host",
    [
        "nvr.example.com",
        "192.168.1.5",
        "::1",
        "[2001:db8::1]",
        "nvr-01",
    ],
)
def test_valid_hosts_are_accepted(host: str) -> None:
    session = FakeSession(200, fixture_body())
    client = make_client(session, host=host)
    assert client.base_url.endswith(f":{client.port}")


@pytest.mark.parametrize(
    ("label", "host"),
    [
        ("empty", ""),
        ("port-suffix", "nvr:9999"),
        ("scheme", "http://nvr"),
        ("userinfo", "user:pass@nvr"),
        ("path", "nvr/api"),
        ("space", "nvr host"),
        ("tab", "nvr\tx"),
        ("newline", "nvr\nx"),
        ("query", "nvr?x=1"),
        ("fragment", "nvr#x"),
        ("zone-id", "192.168.1.5%eth0"),
        ("too-long", "a" * 300),
    ],
)
def test_invalid_hosts_are_rejected_and_never_echoed(label: str, host: str) -> None:
    """An allowlist, not a denylist: caller text must never reach the URL."""
    del label
    session = FakeSession(200, fixture_body())
    with pytest.raises(ValueError, match="host must be") as err:
        make_client(session, host=host)
    # `host not in message` is vacuous for the empty host (every string contains
    # "") and trivially true for a repeated-character host, so assert the exact
    # canned text instead: nothing caller-supplied can be in it by construction.
    assert (
        str(err.value) == "host must be a bare hostname or IP address, without scheme, port or path"
    )


def test_ipv6_host_is_bracketed_in_the_url() -> None:
    """`http://::1:8000` is not a parseable URL; the literal must be bracketed."""
    session = FakeSession(200, fixture_body())
    client = make_client(session, host="::1")
    assert client.base_url == f"http://[::1]:{client.port}"


@pytest.mark.parametrize(
    ("label", "username", "password"),
    [
        ("colon-in-username", "us:er", "secret-sentinel"),
        ("non-latin1-password", "user", "pa€ss-sentinel"),
        ("non-latin1-username", "u€ser", "secret-sentinel"),
    ],
)
def test_unencodable_credentials_are_rejected_without_echoing_them(
    label: str, username: str, password: str
) -> None:
    """Rejected here because aiohttp raises UnicodeEncodeError at request time.

    That exception's ``args`` carry the password itself, so it must never be
    reachable (AD-13).
    """
    del label
    session = FakeSession(200, fixture_body())
    with pytest.raises(ValueError, match=r"must (not contain|be encodable)") as err:
        make_client(session, username=username, password=password)
    surfaces = (str(err.value), repr(err.value), repr(err.value.args))
    for surface in surfaces:
        assert password not in surface
        assert username not in surface


@pytest.mark.asyncio
async def test_redirects_are_not_followed() -> None:
    """Following SecuritySpy's http->https redirect strips auth, so don't.

    A different port is a different origin, so aiohttp drops the Authorization
    header across the hop; the redirect target then 401s and the user is told
    their password is wrong. Reporting the redirect is the honest diagnosis.
    """
    session = FakeSession(200, fixture_body())
    await make_client(session).async_get_server_info()
    assert session.calls[0][1]["allow_redirects"] is False


# --- capture history: request shape and ordering (spec 1.4) -----------------

START_DATE = date(2026, 8, 9)
END_DATE = date(2026, 8, 10)
CAPLIST_URL = f"http://{HOST}:{PORT}/++caplist"
FIXTURE_CAPTURE_COUNT = 5
NEWEST_START = datetime(2026, 8, 9, 17, 35, 19, tzinfo=UTC)


def caplist_body() -> str:
    return (FIXTURES / "caplist.json").read_text()


async def get_captures(
    session: FakeSession,
    cameras: list[int] | None = None,
    **kwargs: Any,  # noqa: ANN401 - passthrough to the method's own signature
) -> tuple[Any, ...]:
    client = make_client(session)
    kwargs.setdefault("server_timezone", UTC)
    return await client.async_get_captures(
        [1] if cameras is None else cameras,
        start_date=kwargs.pop("start_date", START_DATE),
        end_date=kwargs.pop("end_date", END_DATE),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_captures_issue_exactly_one_batched_request() -> None:
    session = FakeSession(200, caplist_body())
    await get_captures(session, [4, 1, 1])
    assert len(session.calls) == 1
    url, kwargs = session.calls[0]
    assert url == CAPLIST_URL
    # Sorted, de-duplicated, and with research §4's trailing comma.
    assert kwargs["params"]["cams"] == "1,4,"
    assert kwargs["params"]["startDate"] == "2026-08-09"
    assert kwargs["params"]["endDate"] == "2026-08-10"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("object_class", "expected"),
    [
        ("human", CAPTURE_FILTER_HUMAN),
        ("vehicle", CAPTURE_FILTER_VEHICLE),
        ("animal", CAPTURE_FILTER_ANIMAL),
    ],
)
async def test_object_class_is_filtered_server_side(object_class: str, expected: int) -> None:
    session = FakeSession(200, caplist_body())
    await get_captures(session, object_class=object_class)
    assert session.calls[0][1]["params"]["filter"] == str(expected)


@pytest.mark.asyncio
async def test_no_class_filter_sends_filter_all() -> None:
    session = FakeSession(200, caplist_body())
    await get_captures(session)
    assert session.calls[0][1]["params"]["filter"] == str(CAPTURE_FILTER_ALL)


@pytest.mark.asyncio
@pytest.mark.parametrize("raw_filter", [CAPTURE_FILTER_MOVIES, CAPTURE_FILTER_CONTINUOUS])
async def test_raw_capture_filter_is_passed_through(raw_filter: int) -> None:
    session = FakeSession(200, caplist_body())
    await get_captures(session, capture_filter=raw_filter)
    assert session.calls[0][1]["params"]["filter"] == str(raw_filter)


@pytest.mark.asyncio
async def test_no_local_bitmask_filtering_happens() -> None:
    """`filter=` is the whole filter. Everything the server returned comes back."""
    session = FakeSession(200, caplist_body())
    captures = await get_captures(session, [1, 4, 7], object_class="human")
    assert len(captures) == FIXTURE_CAPTURE_COUNT
    assert any(not capture.object_classes for capture in captures)


# --- argument validation ----------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_object_class_raises_before_any_request() -> None:
    session = FakeSession(200, caplist_body())
    with pytest.raises(ValueError, match="animal, human, vehicle"):
        await get_captures(session, object_class="delivery_van")
    assert session.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"start_date": END_DATE, "end_date": START_DATE}, "start_date"),
        ({"object_class": "human", "capture_filter": CAPTURE_FILTER_MOVIES}, "not both"),
        ({"capture_filter": -1}, "capture_filter"),
        ({"capture_filter": True}, "capture_filter"),
    ],
)
async def test_bad_arguments_raise_before_any_request(kwargs: dict[str, Any], match: str) -> None:
    session = FakeSession(200, caplist_body())
    with pytest.raises(ValueError, match=match):
        await get_captures(session, **kwargs)
    assert session.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cameras", [[-1], [0, -3], ["1"], [True], [1.0]])
async def test_bad_camera_numbers_raise_before_any_request(cameras: list[Any]) -> None:
    session = FakeSession(200, caplist_body())
    with pytest.raises(ValueError, match="non-negative integers"):
        await get_captures(session, cameras)
    assert session.calls == []


@pytest.mark.asyncio
async def test_empty_camera_list_issues_no_request() -> None:
    session = FakeSession(200, caplist_body())
    assert await get_captures(session, []) == ()
    assert session.calls == []


@pytest.mark.asyncio
async def test_camera_zero_is_a_real_camera() -> None:
    session = FakeSession(200, "[]")
    await get_captures(session, [0])
    assert session.calls[0][1]["params"]["cams"] == "0,"


# --- body shapes ------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_result_is_an_empty_tuple() -> None:
    session = FakeSession(200, "[]")
    assert await get_captures(session) == ()


@pytest.mark.asyncio
async def test_embedded_list_body_decodes() -> None:
    session = FakeSession(200, json.dumps({"captures": json.loads(caplist_body())}))
    captures = await get_captures(session)
    assert len(captures) == FIXTURE_CAPTURE_COUNT


@pytest.mark.asyncio
@pytest.mark.parametrize("body", ['"a string"', "42", "null", "{}", '{"error": "nope"}'])
async def test_unusable_body_raises_connect_error_without_echoing_it(body: str) -> None:
    session = FakeSession(200, body)
    with pytest.raises(SecuritySpyConnectError) as excinfo:
        await get_captures(session)
    assert "nope" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_skippable_entries_are_dropped_and_the_rest_decode() -> None:
    session = FakeSession(200, caplist_body())
    captures = await get_captures(session, [1, 4, 7])
    # The fixture holds seven entries: a bare string and a `c`-less object go.
    assert len(captures) == FIXTURE_CAPTURE_COUNT
    assert sorted({capture.camera for capture in captures}) == [1, 4, 7]


@pytest.mark.asyncio
async def test_auth_rejection_surfaces_from_the_shared_seam() -> None:
    session = FakeSession(401, "")
    with pytest.raises(SecuritySpyAuthError):
        await get_captures(session)


@pytest.mark.asyncio
async def test_permission_rejection_surfaces_from_the_shared_seam() -> None:
    session = FakeSession(403, "")
    with pytest.raises(SecuritySpyPermissionError):
        await get_captures(session)


# --- ordering ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_captures_come_back_newest_first_with_undated_last() -> None:
    entries = json.loads(caplist_body())
    session = FakeSession(200, json.dumps(list(reversed(entries))))
    captures = await get_captures(session, [1, 4, 7])
    assert captures[0].start == NEWEST_START
    dated = [capture.start for capture in captures if capture.start is not None]
    assert dated == sorted(dated, reverse=True)
    assert captures[-1].start is None


#: The movie fixture entry's `m` (research §5.6): a fractional megabyte count.
FIXTURE_MOVIE_SIZE_MB = 0.945


@pytest.mark.asyncio
async def test_client_path_preserves_the_fractional_size() -> None:
    # The movie fixture entry carries `m: 0.945`; the full client path must
    # decode it, not drop or reinterpret it. The fixture is the load-bearing
    # part of this story, and only a client-path assertion proves it survives.
    session = FakeSession(200, caplist_body())
    captures = await get_captures(session, [1, 4, 7])
    movie = next(c for c in captures if c.filename.startswith("09-08-2026 17-35-19"))
    assert movie.file_size_mb == FIXTURE_MOVIE_SIZE_MB


@pytest.mark.asyncio
async def test_ordering_is_independent_of_server_ordering() -> None:
    entries = json.loads(caplist_body())
    forward = FakeSession(200, json.dumps(entries))
    backward = FakeSession(200, json.dumps(list(reversed(entries))))
    assert await get_captures(forward, [1, 4, 7]) == await get_captures(backward, [1, 4, 7])


@pytest.mark.asyncio
async def test_equal_starts_break_ties_by_camera_then_filename() -> None:
    same = {"f": "2026-08-09", "s": 10, "t": 1}
    session = FakeSession(
        200,
        json.dumps(
            [
                {**same, "c": 2, "n": "b.m4v"},
                {**same, "c": 1, "n": "z.m4v"},
                {**same, "c": 1, "n": "a.m4v"},
                {**same, "c": 2, "n": "a.m4v"},
            ]
        ),
    )
    captures = await get_captures(session, [1, 2])
    assert [(c.camera, c.filename) for c in captures] == [
        (1, "a.m4v"),
        (1, "z.m4v"),
        (2, "a.m4v"),
        (2, "b.m4v"),
    ]


@pytest.mark.asyncio
async def test_server_timezone_is_applied_to_capture_starts() -> None:
    session = FakeSession(200, caplist_body())
    captures = await get_captures(session, server_timezone=ZoneInfo("America/Chicago"))
    assert captures[0].start == datetime(2026, 8, 9, 22, 35, 19, tzinfo=UTC)


# --- review regressions (spec 1.4 review pass) ------------------------------


@pytest.mark.asyncio
async def test_error_envelope_does_not_win_over_the_named_capture_array() -> None:
    """A body carrying both an error list and the captures must decode the captures.

    Taking the first list-valued entry made this dict-insertion-order dependent:
    the server's captures were dropped and the caller was told, indistinguishably
    from a quiet day, that nothing matched.
    """
    session = FakeSession(
        200,
        json.dumps({"error": ["server busy"], "captures": json.loads(caplist_body())}),
    )
    captures = await get_captures(session)
    assert len(captures) == FIXTURE_CAPTURE_COUNT


@pytest.mark.asyncio
async def test_ambiguous_envelope_is_a_failure_rather_than_no_captures() -> None:
    """Two unnamed lists cannot be disambiguated, so this is not a capture list."""
    session = FakeSession(200, json.dumps({"a": [{"c": 1}], "b": [{"c": 2}]}))
    with pytest.raises(SecuritySpyConnectError):
        await get_captures(session)


@pytest.mark.asyncio
async def test_an_error_list_alone_is_a_failure_not_an_empty_result() -> None:
    session = FakeSession(200, json.dumps({"result": "error", "detail": ["denied"]}))
    with pytest.raises(SecuritySpyConnectError) as excinfo:
        await get_captures(session)
    assert "denied" not in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["start_date", "end_date"])
async def test_a_datetime_bound_is_rejected_before_any_request(field: str) -> None:
    """`datetime` subclasses `date`, so it passes the annotation and the range check.

    It would then serialise as a full ISO instant, which the server cannot match
    against a folder date -- a silently wrong query rather than a failure.
    """
    session = FakeSession(200, caplist_body())
    with pytest.raises(ValueError, match="dates"):
        await get_captures(session, None, **{field: datetime(2026, 8, 9, 12, tzinfo=UTC)})
    assert session.calls == []


@pytest.mark.asyncio
async def test_a_non_date_bound_is_rejected_before_any_request() -> None:
    session = FakeSession(200, caplist_body())
    with pytest.raises(ValueError, match="dates"):
        await get_captures(session, start_date=cast("Any", "2026-08-09"))
    assert session.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("raw_filter", [8, 99, -1])
async def test_an_undefined_capture_filter_is_rejected(raw_filter: int) -> None:
    """A filter SecuritySpy does not define may be ignored, returning everything."""
    session = FakeSession(200, caplist_body())
    with pytest.raises(ValueError, match="CAPTURE_FILTER"):
        await get_captures(session, capture_filter=raw_filter)
    assert session.calls == []


@pytest.mark.asyncio
async def test_ties_the_camera_and_filename_cannot_separate_stay_deterministic() -> None:
    same = {"f": "2026-08-09", "s": 10, "c": 1, "n": "a.m4v"}
    entries = [{**same, "m": 20}, {**same, "m": 10}]
    forward = FakeSession(200, json.dumps(entries))
    backward = FakeSession(200, json.dumps(list(reversed(entries))))
    assert await get_captures(forward, [1]) == await get_captures(backward, [1])


@pytest.mark.asyncio
async def test_fractional_sizes_still_separate_ties_deterministically() -> None:
    # Sizes sharing an integer part: a `_tiebreak` that truncated floats to ints
    # would collapse both keys to 20 and break the determinism assertion below.
    same = {"f": "2026-08-09", "s": 10, "c": 1, "n": "a.m4v"}
    entries = [{**same, "m": 20.5}, {**same, "m": 20.25}]
    forward = FakeSession(200, json.dumps(entries))
    backward = FakeSession(200, json.dumps(list(reversed(entries))))
    assert await get_captures(forward, [1]) == await get_captures(backward, [1])


@pytest.mark.asyncio
async def test_unsized_capture_keeps_a_distinct_ordering_key() -> None:
    # The `-1` sentinel for a missing size must stay out of range of every real
    # value, including a genuine zero-size capture: if it were `0`, the unsized
    # capture and the zero-size one would share a key and the server's ordering
    # would decide the result.
    same = {"f": "2026-08-09", "s": 10, "c": 1, "n": "a.m4v"}
    entries = [{**same, "m": 0}, {**same}]
    forward = FakeSession(200, json.dumps(entries))
    backward = FakeSession(200, json.dumps(list(reversed(entries))))
    assert await get_captures(forward, [1]) == await get_captures(backward, [1])


@pytest.mark.asyncio
async def test_the_stub_records_a_post_alongside_its_gets() -> None:
    """The settings write is the first non-GET verb this stub has ever seen.

    Both verbs land in the same ``calls`` list, so an assertion written against
    a GET keeps working and a POST is no longer invisible to it.
    """
    session = FakeSession(200, "{}")
    client = make_client(session)
    await client.async_set_camera_settings(3, CameraSettingsPatch(brightness=10))

    assert session.methods == ["POST"]
    assert len(session.calls) == 1
    assert session.calls[0][0].endswith("/++settings-cameras")


# --- camera status: cheap health poll (spec 1.8) -----------------------------

CAM_STATUS_URL = f"http://{HOST}:{PORT}/++camStatus"


def cam_status_body(entries: list[dict[str, Any]]) -> str:
    return json.dumps(entries)


@pytest.mark.asyncio
async def test_camera_status_happy_path_decodes_every_entry() -> None:
    session = FakeSession(
        200,
        cam_status_body(
            [
                {
                    "num": 0,
                    "enabled": True,
                    "online": True,
                    "open": False,
                    "err": "",
                    "errDesc": "",
                },
                {
                    "num": 1,
                    "enabled": True,
                    "online": False,
                    "open": True,
                    "err": "e",
                    "errDesc": "d",
                },
            ]
        ),
    )
    statuses = await make_client(session).async_get_camera_status()
    assert len(statuses) == TWO_STATUSES
    first, second = statuses
    assert first.number == 0
    assert first.enabled is True
    assert first.online is True
    assert first.open is False
    assert first.error is None
    assert first.error_description is None
    assert second.number == 1
    assert second.online is False
    assert second.open is True
    assert second.error == "e"
    assert second.error_description == "d"


@pytest.mark.asyncio
async def test_camera_status_request_shape() -> None:
    session = FakeSession(200, cam_status_body([]))
    await make_client(session).async_get_camera_status()
    url, kwargs = session.calls[0]
    assert url == CAM_STATUS_URL
    assert kwargs["headers"]["Authorization"] == aiohttp.encode_basic_auth(USERNAME, PASSWORD)
    # The endpoint is called without `format=json`, unlike `++systemInfo`; the
    # docstring records that as an assumption, so pin it rather than let a
    # silently-added parameter pass.
    assert not kwargs["params"]


@pytest.mark.asyncio
async def test_camera_status_entry_with_no_usable_number_is_skipped() -> None:
    session = FakeSession(
        200,
        cam_status_body(
            [
                {"num": "x", "enabled": True, "online": True, "open": False},
                {"num": 2, "enabled": True, "online": True, "open": False},
            ]
        ),
    )
    statuses = await make_client(session).async_get_camera_status()
    assert [status.number for status in statuses] == [2]


@pytest.mark.asyncio
async def test_camera_status_non_object_entry_is_skipped() -> None:
    session = FakeSession(200, '["nonsense", {"num": 3}]')
    statuses = await make_client(session).async_get_camera_status()
    assert [status.number for status in statuses] == [3]


@pytest.mark.asyncio
async def test_camera_status_empty_array_is_an_empty_tuple() -> None:
    session = FakeSession(200, cam_status_body([]))
    assert await make_client(session).async_get_camera_status() == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("body", ['"a string"', "42", "null", "{}"])
async def test_camera_status_non_array_body_raises_connect_error(body: str) -> None:
    session = FakeSession(200, body)
    with pytest.raises(SecuritySpyConnectError):
        await make_client(session).async_get_camera_status()


@pytest.mark.asyncio
async def test_camera_status_auth_failure_maps_to_auth_error() -> None:
    session = FakeSession(401, "")
    with pytest.raises(SecuritySpyAuthError):
        await make_client(session).async_get_camera_status()


# --- visible cameras: permission-scoped list + health (spec 1.18, gap G8) ----

SYSTEM_INFO_URL = f"http://{HOST}:{PORT}/++systemInfo"


def restricted_system_info_body(*, permitted_number: int) -> str:
    """Build a minimal ``++systemInfo`` body reporting one member camera."""
    return json.dumps(
        {
            "server": {
                "version": "6.20",
                "uuid": "1D3A5C7E-9B21-4F60-8A44-0C2E6F1B7D93",
                "camera-count": "1",
            },
            "camera": [
                {
                    "number": str(permitted_number),
                    "name": "Driveway",
                    "connected": "yes",
                    "enabled": "yes",
                    "permissions": "1",
                }
            ],
        }
    )


@pytest.mark.asyncio
async def test_visible_cameras_restricted_account_drops_non_member_rows(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An account permitted only camera 1 of eleven, per gap G8.

    ``++camStatus`` returns every camera on the server regardless of
    permission; membership from ``++systemInfo`` is exactly camera 1. The
    other ten must appear in no returned value and no log record -- this is
    the row that protects story 2.7.
    """
    other_numbers = tuple(range(11))
    session = SequencedFakeSession(
        [
            (200, restricted_system_info_body(permitted_number=1)),
            (
                200,
                cam_status_body(
                    [
                        {"num": number, "enabled": True, "online": True, "open": False}
                        for number in other_numbers
                    ]
                ),
            ),
        ]
    )
    with caplog.at_level("DEBUG"):
        views = await make_client(session).async_get_visible_cameras()
    assert len(session.calls) == TWO_STATUSES
    assert session.calls[0][0] == SYSTEM_INFO_URL
    assert session.calls[1][0] == CAM_STATUS_URL
    numbers = {view.camera.number for view in views}
    assert numbers == {1}
    # Only the models-layer intersection log is in scope here -- transport
    # logs legitimately mention the host/port, which contain digits.
    intersection_messages = [
        record.getMessage() for record in caplog.records if record.name == "aiosecurityspy.models"
    ]
    assert intersection_messages == [
        "Discarded 10 camStatus row(s) for cameras outside this account's membership"
    ]


@pytest.mark.asyncio
async def test_visible_cameras_unknown_status_row_is_discarded_and_only_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A camStatus row with no matching member is discarded, never raises."""
    session = SequencedFakeSession(
        [
            (200, fixture_body()),
            (
                200,
                cam_status_body(
                    [
                        {"num": 0, "enabled": True, "online": True, "open": False},
                        {"num": 1, "enabled": True, "online": True, "open": False},
                        {"num": 7, "enabled": True, "online": True, "open": False},
                        {"num": 99, "enabled": True, "online": True, "open": False},
                    ]
                ),
            ),
        ]
    )
    with caplog.at_level("DEBUG"):
        views = await make_client(session).async_get_visible_cameras()
    assert {view.camera.number for view in views} == {0, 1, 7}
    # Only the models-layer intersection log is in scope here -- transport
    # logs legitimately mention the host/port, which contain digits.
    intersection_messages = [
        record.getMessage() for record in caplog.records if record.name == "aiosecurityspy.models"
    ]
    combined = "\n".join(intersection_messages)
    assert "99" not in combined


@pytest.mark.asyncio
async def test_visible_cameras_ordinary_account_returns_all_members_with_status() -> None:
    session = SequencedFakeSession(
        [
            (200, fixture_body()),
            (
                200,
                cam_status_body(
                    [
                        {"num": 0, "enabled": True, "online": True, "open": False},
                        {"num": 1, "enabled": True, "online": False, "open": True, "err": "e"},
                        {"num": 7, "enabled": False, "online": False, "open": False},
                    ]
                ),
            ),
        ]
    )
    views = await make_client(session).async_get_visible_cameras()
    by_number = {view.camera.number: view for view in views}
    assert set(by_number) == {0, 1, 7}
    assert by_number[0].status is not None
    assert by_number[0].status.online is True
    assert by_number[1].status is not None
    assert by_number[1].status.error == "e"
    assert by_number[7].status is not None
    assert by_number[7].status.enabled is False


@pytest.mark.asyncio
async def test_refresh_camera_status_issues_only_camstatus() -> None:
    """A caller that already holds membership refreshes health with one call."""
    session = FakeSession(
        200, cam_status_body([{"num": 0, "enabled": True, "online": True, "open": False}])
    )
    client = make_client(session)
    server_info = ServerInfo.from_api(json.loads(fixture_body()))
    views = await client.async_refresh_camera_status(server_info)
    assert len(session.calls) == 1
    assert session.calls[0][0] == CAM_STATUS_URL
    by_number = {view.camera.number: view for view in views}
    assert set(by_number) == {0, 1, 7}
    assert by_number[0].status is not None
    assert by_number[0].status.online is True
    assert by_number[1].status is None
    assert by_number[7].status is None


# --- capture media fetch: preview and file (spec 1.9) ------------------------

PREVIEW_URL = f"http://{HOST}:{PORT}/++getpreview"
FILE_URL = f"http://{HOST}:{PORT}/++getfile"
FILE_HB_URL = f"http://{HOST}:{PORT}/++getfilehb"
FILE_LB_URL = f"http://{HOST}:{PORT}/++getfilelb"
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 100  # minimal JPEG header + padding
JPEG_CONTENT_TYPE = "image/jpeg"
MOVIE_BYTES = b"\x00\x00\x00\x1c" + b"\x00" * 200  # minimal ftyp-like header + padding
MOVIE_CONTENT_TYPE = "video/quicktime"
MP4_CONTENT_TYPE = "video/mp4"


def make_capture(
    *,
    camera: int = 4,
    folder_date: str = "2026-08-09",
    filename: str = "M+2026-08-09_17-35-19_C.jpg",
    archived: bool = False,
) -> Capture:
    """Build a Capture with a usable path for media fetch tests."""
    return Capture(
        camera=camera,
        start=datetime(2026, 8, 9, 17, 35, 19, tzinfo=UTC),
        duration=timedelta(seconds=10),
        capture_type=1,
        object_classes=frozenset(),
        filename=filename,
        folder_date=folder_date,
        file_size_mb=1024.0,
        tag_id=0,
        archived=archived,
        unread=False,
        path=f"{camera}/{folder_date}/{filename}",
    )


class FakeStreamContent:
    """Minimal stand-in for response.content that yields chunks for streaming."""

    CHUNK = 64

    def __init__(self, raw: bytes) -> None:
        """Store the canned bytes."""
        self._raw = raw
        self._pos = 0
        # Every `limit` the reader asked for. The fake answers with less than it
        # was asked for -- a real StreamReader does too -- so the only way to
        # verify the chunk bound the streaming API promises is to assert on what
        # was requested, not on what came back.
        self.limits: list[int] = []

    async def read(self, limit: int = -1) -> bytes:
        """Return at most `limit` bytes from the current position, then advance."""
        self.limits.append(limit)
        take = len(self._raw) - self._pos if limit < 0 else min(limit, self.CHUNK)
        chunk = self._raw[self._pos : self._pos + take]
        self._pos += len(chunk)
        return chunk


class FailAfterContent(FakeStreamContent):
    """A content reader that fails after a set number of successful reads.

    The matrix calls for a drop that happens *after* bytes are already flowing;
    a fake that raises on the first read never exercises the partially-consumed
    generator.
    """

    def __init__(self, raw: bytes, fail_after: int) -> None:
        """Store the body and the number of reads to allow first."""
        super().__init__(raw)
        self._fail_after = fail_after
        self._reads = 0

    async def read(self, limit: int = -1) -> bytes:
        """Return a chunk, then fail once the allowance is spent."""
        if self._reads >= self._fail_after:
            message = "connection dropped mid-body"
            raise aiohttp.ClientPayloadError(message)
        self._reads += 1
        return await super().read(limit)


class FakeStreamResponse:
    """Minimal stand-in for a streaming response."""

    def __init__(
        self,
        status: int,
        body: bytes,
        content_type: str,
        declared_length: int | None = None,
    ) -> None:
        """Store the canned status, body, content type and declared length."""
        self.status = status
        self.content_type = content_type
        self.content = FakeStreamContent(body)
        self._released = False
        self._declared_length = declared_length

    def release(self) -> None:
        """Mark the response as released."""
        self._released = True

    @property
    def released(self) -> bool:
        """Whether the response has been released."""
        return self._released

    @property
    def content_length(self) -> int | None:
        """The declared body length, as aiohttp reports it."""
        return self._declared_length

    def get_encoding(self) -> str:
        """Return the charset the response declares."""
        return "utf-8"

    async def __aenter__(self) -> Self:
        """Enter the response context."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Leave the response context without suppressing anything."""


class AwaitableFakeStreamResponse:
    """Wraps a FakeStreamResponse so ``await session.get(...)`` works."""

    def __init__(self, response: FakeStreamResponse) -> None:
        """Store the response to yield."""
        self._response = response

    def __await__(self) -> Any:  # noqa: ANN401
        """Support ``await session.get(...)``."""

        async def _return() -> FakeStreamResponse:
            return self._response

        return _return().__await__()

    async def __aenter__(self) -> FakeStreamResponse:
        """Enter the response context."""
        return self._response

    async def __aexit__(self, *args: object) -> None:
        """Leave the response context without suppressing anything."""


class FakeStreamSession:
    """A session that returns streaming responses."""

    def __init__(
        self,
        status: int = 200,
        body: bytes = b"",
        content_type: str = "application/octet-stream",
        error: BaseException | None = None,
        declared_length: int | None = None,
    ) -> None:
        """Configure the canned response or the transport error to raise."""
        self._status = status
        self._body = body
        self._content_type = content_type
        self._error = error
        self._declared_length = declared_length
        self.responses: list[FakeStreamResponse] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.methods: list[str] = []

    def get(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401
        """Record the call and return an awaitable or error context."""
        self.methods.append("GET")
        self.calls.append((url, kwargs))
        if self._error is not None:
            return RaisingContext(self._error)
        response = FakeStreamResponse(
            self._status, self._body, self._content_type, self._declared_length
        )
        self.responses.append(response)
        return AwaitableFakeStreamResponse(response)

    def post(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401
        """Record a POST and return an awaitable or error context."""
        return self.get(url, **kwargs)

    async def close(self) -> None:  # pragma: no cover
        """Mark the session closed; the library must never reach this."""


# --- async_get_capture_preview tests ---


@pytest.mark.asyncio
async def test_preview_url_has_double_question_mark() -> None:
    """The getpreview URL uses a literal second '?' for the archive flag."""
    session = FakeStreamSession(200, JPEG_BYTES, JPEG_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = make_capture()
    preview = await client.async_get_capture_preview(capture)
    assert preview.data == JPEG_BYTES
    assert preview.content_type == JPEG_CONTENT_TYPE
    url, kwargs = session.calls[0]
    # The URL should contain the double '?' pattern: ++getpreview?/4/...?archive=0
    assert "++getpreview?/" in url
    assert "?archive=0" in url
    assert "params" not in kwargs


@pytest.mark.asyncio
async def test_preview_archived_true_sends_archive_1() -> None:
    session = FakeStreamSession(200, JPEG_BYTES, JPEG_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = make_capture(archived=True)
    preview = await client.async_get_capture_preview(capture)
    assert preview.data == JPEG_BYTES
    url, _ = session.calls[0]
    assert "?archive=1" in url


@pytest.mark.asyncio
async def test_preview_encodes_filename() -> None:
    session = FakeStreamSession(200, JPEG_BYTES, JPEG_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = make_capture(filename="M+2026-08-09 17-35-19 C.jpg")
    await client.async_get_capture_preview(capture)
    url, _ = session.calls[0]
    assert "%2B" in url  # '+' is percent-encoded
    assert "%20" in url  # space is percent-encoded


@pytest.mark.asyncio
async def test_preview_auth_failure() -> None:
    session = FakeStreamSession(401, b"")
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(SecuritySpyAuthError):
        await client.async_get_capture_preview(make_capture())


@pytest.mark.asyncio
async def test_preview_unexpected_status() -> None:
    session = FakeStreamSession(404, b"")
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(SecuritySpyConnectError, match="404"):
        await client.async_get_capture_preview(make_capture())


@pytest.mark.asyncio
async def test_preview_empty_path_raises() -> None:
    session = FakeStreamSession(200, JPEG_BYTES, JPEG_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    # A capture with empty path (e.g. bad filename)
    capture = Capture(
        camera=4,
        start=None,
        duration=None,
        capture_type=1,
        object_classes=frozenset(),
        filename="",
        folder_date="2026-08-09",
        file_size_mb=None,
        tag_id=None,
        archived=False,
        unread=False,
        path="",
    )
    with pytest.raises(SecuritySpyConnectError, match="no addressable file path"):
        await client.async_get_capture_preview(capture)


@pytest.mark.asyncio
async def test_preview_transport_error_wrapped() -> None:
    session = FakeStreamSession(error=aiohttp.ClientConnectionError("boom"))
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(SecuritySpyConnectError, match="transport failure"):
        await client.async_get_capture_preview(make_capture())


# --- async_get_capture_file tests ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("bandwidth", "expected_url"),
    [
        (CAPTURE_FILE_BANDWIDTH_STANDARD, FILE_URL),
        (CAPTURE_FILE_BANDWIDTH_HIGH, FILE_HB_URL),
        (CAPTURE_FILE_BANDWIDTH_LOW, FILE_LB_URL),
    ],
    ids=["standard", "high", "low"],
)
async def test_file_bandwidth_selects_correct_endpoint(bandwidth: int, expected_url: str) -> None:
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = make_capture()
    stream = await client.async_get_capture_file(capture, bandwidth=bandwidth)
    assert stream.content_type == MOVIE_CONTENT_TYPE
    url, _ = session.calls[0]
    assert url.startswith(expected_url)
    assert "/4/2026-08-09/" in url


@pytest.mark.parametrize(
    ("bandwidth", "served_content_type"),
    [
        (CAPTURE_FILE_BANDWIDTH_STANDARD, MOVIE_CONTENT_TYPE),
        (CAPTURE_FILE_BANDWIDTH_HIGH, MOVIE_CONTENT_TYPE),
        (CAPTURE_FILE_BANDWIDTH_LOW, MP4_CONTENT_TYPE),
    ],
)
@pytest.mark.asyncio
async def test_file_reports_the_served_content_type(
    bandwidth: int, served_content_type: str
) -> None:
    """The stream reports the content type the server sent, for every bandwidth."""
    session = FakeStreamSession(200, MOVIE_BYTES, served_content_type)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    stream = await client.async_get_capture_file(make_capture(), bandwidth=bandwidth)
    assert stream.content_type == served_content_type


@pytest.mark.asyncio
async def test_file_content_type_is_not_dictated_by_bandwidth() -> None:
    """The bandwidth selector never overrides what the server actually served.

    The library reports the response header rather than a table keyed on the
    bandwidth variant, so a server that answers the low-bandwidth endpoint with
    QuickTime is reported as QuickTime -- not silently relabelled ``video/mp4``.
    """
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    stream = await client.async_get_capture_file(
        make_capture(), bandwidth=CAPTURE_FILE_BANDWIDTH_LOW
    )
    assert stream.content_type == MOVIE_CONTENT_TYPE


@pytest.mark.asyncio
async def test_file_content_type_falls_back_when_server_sends_none() -> None:
    """A response with no content type reports the octet-stream fallback."""
    session = FakeStreamSession(200, MOVIE_BYTES, "")
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    stream = await client.async_get_capture_file(make_capture())
    assert stream.content_type == "application/octet-stream"


@pytest.mark.asyncio
async def test_file_archive_default_from_capture() -> None:
    """archive=None uses capture.archived."""
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = make_capture(archived=True)
    await client.async_get_capture_file(capture)
    _, kwargs = session.calls[0]
    assert kwargs["params"]["archive"] == "1"


@pytest.mark.asyncio
async def test_file_archive_override_true() -> None:
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = make_capture(archived=False)
    await client.async_get_capture_file(capture, archive=True)
    _, kwargs = session.calls[0]
    assert kwargs["params"]["archive"] == "1"


@pytest.mark.asyncio
async def test_file_archive_override_false() -> None:
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = make_capture(archived=True)
    await client.async_get_capture_file(capture, archive=False)
    _, kwargs = session.calls[0]
    assert kwargs["params"]["archive"] == "0"


@pytest.mark.asyncio
async def test_file_auth_failure() -> None:
    session = FakeStreamSession(401, b"")
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(SecuritySpyAuthError):
        await client.async_get_capture_file(make_capture())


@pytest.mark.asyncio
async def test_file_unexpected_status() -> None:
    session = FakeStreamSession(404, b"")
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(SecuritySpyConnectError, match="404"):
        await client.async_get_capture_file(make_capture())


@pytest.mark.asyncio
async def test_file_empty_path_raises() -> None:
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    capture = Capture(
        camera=4,
        start=None,
        duration=None,
        capture_type=1,
        object_classes=frozenset(),
        filename="",
        folder_date="2026-08-09",
        file_size_mb=None,
        tag_id=None,
        archived=False,
        unread=False,
        path="",
    )
    with pytest.raises(SecuritySpyConnectError, match="no addressable file path"):
        await client.async_get_capture_file(capture)


@pytest.mark.asyncio
async def test_file_invalid_bandwidth_raises_before_request() -> None:
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(ValueError, match="CAPTURE_FILE_BANDWIDTH"):
        await client.async_get_capture_file(make_capture(), bandwidth=99)
    assert session.calls == []


@pytest.mark.asyncio
async def test_file_transport_error_wrapped() -> None:
    session = FakeStreamSession(error=aiohttp.ClientConnectionError("boom"))
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(SecuritySpyConnectError, match="transport failure"):
        await client.async_get_capture_file(make_capture())


@pytest.mark.asyncio
async def test_file_accepts_typed_bandwidth_record() -> None:
    """A CaptureFileBandwidth record works as well as a raw constant."""
    session = FakeStreamSession(200, MOVIE_BYTES, MP4_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    bw = capture_file_bandwidth(CAPTURE_FILE_BANDWIDTH_LOW)
    stream = await client.async_get_capture_file(make_capture(), bandwidth=bw)
    assert stream.content_type == "video/mp4"
    url, _ = session.calls[0]
    assert url.startswith(FILE_LB_URL)


# --- CaptureFileStream iteration tests ---


def make_stream(
    response: FakeStreamResponse, content_type: str = "text/plain"
) -> CaptureFileStream:
    """Build a stream over a fake response, casting at the single seam."""
    return CaptureFileStream(cast("aiohttp.ClientResponse", response), HOST, PORT, content_type)


@pytest.mark.asyncio
async def test_stream_yields_all_bytes() -> None:
    """The stream yields all bytes from the response."""
    body = b"hello world"
    response = FakeStreamResponse(200, body, "text/plain")
    stream = make_stream(response, "text/plain")
    chunks = [chunk async for chunk in stream]
    assert b"".join(chunks) == body


@pytest.mark.asyncio
async def test_stream_content_type() -> None:
    """The stream exposes the response content type."""
    response = FakeStreamResponse(200, b"data", "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    assert stream.content_type == "video/quicktime"


@pytest.mark.asyncio
async def test_stream_releases_response_on_completion() -> None:
    """The stream releases the response when iteration completes."""
    response = FakeStreamResponse(200, b"data", "text/plain")
    stream = make_stream(response, "text/plain")
    async for _ in stream:
        pass
    assert response._released is True  # noqa: SLF001 - test internal state


@pytest.mark.asyncio
async def test_stream_wraps_transport_error() -> None:
    """Transport errors during iteration are wrapped in SecuritySpyConnectError."""

    class RaisingContent:
        """Content that raises on read."""

        async def read(self, limit: int = -1) -> bytes:  # noqa: ARG002
            error = aiohttp.ClientConnectionError("connection lost")
            raise error

    response = FakeStreamResponse(200, b"", "text/plain")
    response.content = RaisingContent()  # type: ignore[assignment]
    stream = make_stream(response, "text/plain")
    with pytest.raises(SecuritySpyConnectError, match="stream failure"):
        async for _ in stream:
            pass


@pytest.mark.asyncio
async def test_stream_wraps_timeout_error() -> None:
    """Timeout errors during iteration are wrapped in SecuritySpyConnectError."""

    class TimeoutContent:
        """Content that raises TimeoutError on read."""

        async def read(self, limit: int = -1) -> bytes:  # noqa: ARG002
            error = TimeoutError("read timed out")
            raise error

    response = FakeStreamResponse(200, b"", "text/plain")
    response.content = TimeoutContent()  # type: ignore[assignment]
    stream = make_stream(response, "text/plain")
    with pytest.raises(SecuritySpyConnectError, match="stream failure"):
        async for _ in stream:
            pass


@pytest.mark.asyncio
async def test_stream_wraps_os_error() -> None:
    """OS errors during iteration are wrapped in SecuritySpyConnectError."""

    class OSErrorContent:
        """Content that raises OSError on read."""

        async def read(self, limit: int = -1) -> bytes:  # noqa: ARG002
            error = OSError("connection reset")
            raise error

    response = FakeStreamResponse(200, b"", "text/plain")
    response.content = OSErrorContent()  # type: ignore[assignment]
    stream = make_stream(response, "text/plain")
    with pytest.raises(SecuritySpyConnectError, match="stream failure"):
        async for _ in stream:
            pass


@pytest.mark.asyncio
async def test_stream_releases_on_error() -> None:
    """The stream releases the response even when iteration fails."""

    class RaisingContent:
        """Content that raises on read."""

        async def read(self, limit: int = -1) -> bytes:  # noqa: ARG002
            error = aiohttp.ClientConnectionError("connection lost")
            raise error

    response = FakeStreamResponse(200, b"", "text/plain")
    response.content = RaisingContent()  # type: ignore[assignment]
    stream = make_stream(response, "text/plain")
    with contextlib.suppress(SecuritySpyConnectError):
        async for _ in stream:
            pass
    assert response._released is True  # noqa: SLF001 - test internal state


@pytest.mark.asyncio
async def test_stream_yields_chunked_data() -> None:
    """The stream fragments reads at 64 bytes, exercising the accumulation loop."""
    body = b"x" * 200  # spans 4 chunks at 64 bytes each
    response = FakeStreamResponse(200, body, "application/octet-stream")
    stream = make_stream(response, "application/octet-stream")
    chunks = [chunk async for chunk in stream]
    assert b"".join(chunks) == body
    assert len(chunks) >= 3  # at least 3 chunks at 64 bytes each  # noqa: PLR2004


# --- credential containment for media fetch ---


@pytest.mark.asyncio
async def test_media_fetch_credentials_never_in_url() -> None:
    session = FakeStreamSession(200, JPEG_BYTES, JPEG_CONTENT_TYPE)
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    await client.async_get_capture_preview(make_capture())
    url, kwargs = session.calls[0]
    assert USERNAME not in url
    assert PASSWORD not in url
    assert kwargs["headers"]["Authorization"] == aiohttp.encode_basic_auth(USERNAME, PASSWORD)


@pytest.mark.asyncio
async def test_media_fetch_auth_error_never_leaks_credentials() -> None:
    session = FakeStreamSession(401, b"")
    client = SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )
    with pytest.raises(SecuritySpyError) as err:
        await client.async_get_capture_preview(make_capture())
    surfaces = [
        str(err.value),
        repr(err.value),
        "".join(traceback.format_exception(err.value)),
    ]
    for surface in surfaces:
        assert USERNAME not in surface
        assert PASSWORD not in surface


# --- Review-driven coverage: encoding, caps, redirects, stream lifecycle ---


def make_media_client(session: FakeStreamSession) -> SecuritySpyClient:
    """Build a client over a fake streaming session."""
    return SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )


@pytest.mark.asyncio
async def test_file_url_percent_encodes_the_filename() -> None:
    """The file endpoint encodes the filename, exactly as the preview endpoint does.

    `Capture.path` is documented as *not* URL-encoded, and a filename encodes the
    camera's name, so a `?` would otherwise truncate the path and swallow the
    archive query.
    """
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = make_media_client(session)
    capture = make_capture(filename="M+2026-08-09_17-35-19_Front? Door #2.mov")
    await client.async_get_capture_file(capture)
    url, _ = session.calls[0]
    assert "?" not in url.removeprefix(f"http://{HOST}:{PORT}/")
    assert "#" not in url
    assert "%3F" in url
    assert "%23" in url
    assert "%2B" in url
    assert url.startswith(f"{FILE_URL}/4/2026-08-09/")


@pytest.mark.asyncio
async def test_file_url_encodes_spaces_in_the_filename() -> None:
    """A space in a camera name is encoded rather than sent raw."""
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = make_media_client(session)
    await client.async_get_capture_file(make_capture(filename="M 2026 back yard.mov"))
    url, _ = session.calls[0]
    assert " " not in url
    assert "%20" in url


@pytest.mark.asyncio
async def test_file_url_keeps_the_path_separators() -> None:
    """Encoding is per component: the three path separators survive."""
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = make_media_client(session)
    await client.async_get_capture_file(make_capture())
    url, _ = session.calls[0]
    assert url.startswith(f"{FILE_URL}/4/2026-08-09/M%2B2026-08-09_17-35-19_C.jpg")


@pytest.mark.asyncio
async def test_preview_url_survives_real_url_construction() -> None:
    """Yarl must not re-encode the literal second '?' the archive flag rides on.

    Every other preview test asserts the string the client handed to the session,
    which is recorded before aiohttp parses it. This one pushes that string
    through real yarl construction, the way aiohttp does, so a re-encoding of the
    `?` -- which would silently return the non-archived preview for every
    archived capture -- cannot pass unnoticed.
    """
    session = FakeStreamSession(200, JPEG_BYTES, JPEG_CONTENT_TYPE)
    client = make_media_client(session)
    await client.async_get_capture_preview(make_capture(archived=True))
    url, _ = session.calls[0]
    built = yarl.URL(url)
    assert built.path.endswith("/++getpreview")
    assert built.query_string.endswith("?archive=1")
    assert str(built).endswith("?archive=1")


@pytest.mark.asyncio
async def test_preview_rejects_a_body_over_the_cap() -> None:
    """A preview body past the 8 MiB cap is a typed failure, not a buffered blob."""
    oversized = b"\xff" * (client_module._MAX_BODY_BYTES + 64)  # noqa: SLF001 - the cap under test
    session = FakeStreamSession(200, oversized, JPEG_CONTENT_TYPE)
    client = make_media_client(session)
    with pytest.raises(SecuritySpyConnectError, match="too large"):
        await client.async_get_capture_preview(make_capture())


@pytest.mark.asyncio
async def test_preview_rejects_an_oversized_declared_length() -> None:
    """A declared Content-Length past the cap fails before the body is read."""
    session = FakeStreamSession(
        200,
        JPEG_BYTES,
        JPEG_CONTENT_TYPE,
        declared_length=client_module._MAX_BODY_BYTES + 1,  # noqa: SLF001 - the cap under test
    )
    client = make_media_client(session)
    with pytest.raises(SecuritySpyConnectError, match="too large"):
        await client.async_get_capture_preview(make_capture())
    assert session.responses[0].content.limits == []


@pytest.mark.asyncio
async def test_preview_accepts_a_body_exactly_at_the_cap() -> None:
    """The cap is inclusive: a body of exactly the limit is not rejected."""
    exact = b"\xff" * client_module._MAX_BODY_BYTES  # noqa: SLF001 - the cap under test
    session = FakeStreamSession(200, exact, JPEG_CONTENT_TYPE)
    client = make_media_client(session)
    preview = await client.async_get_capture_preview(make_capture())
    assert len(preview.data) == client_module._MAX_BODY_BYTES  # noqa: SLF001 - the cap under test


@pytest.mark.parametrize("status", [301, 302, 307, 308])
@pytest.mark.asyncio
async def test_preview_maps_a_redirect(status: int) -> None:
    """A redirect on the preview endpoint names the TLS fix rather than a bare 3xx."""
    session = FakeStreamSession(status, b"", "text/html")
    client = make_media_client(session)
    with pytest.raises(SecuritySpyConnectError, match="use_https=True"):
        await client.async_get_capture_preview(make_capture())


@pytest.mark.parametrize("status", [301, 302, 307, 308])
@pytest.mark.asyncio
async def test_file_maps_a_redirect_and_releases(status: int) -> None:
    """A redirect on the file endpoint is typed, and does not leak the response."""
    session = FakeStreamSession(status, b"", "text/html")
    client = make_media_client(session)
    with pytest.raises(SecuritySpyConnectError, match="use_https=True"):
        await client.async_get_capture_file(make_capture())
    assert session.responses[0].released is True


@pytest.mark.parametrize("status", [401, 403, 404, 500])
@pytest.mark.asyncio
async def test_file_releases_the_response_on_every_status_failure(status: int) -> None:
    """No status failure may leave a connection checked out of the caller's pool."""
    session = FakeStreamSession(status, b"", "text/html")
    client = make_media_client(session)
    with pytest.raises((SecuritySpyAuthError, SecuritySpyPermissionError, SecuritySpyConnectError)):
        await client.async_get_capture_file(make_capture())
    assert session.responses[0].released is True


@pytest.mark.asyncio
async def test_file_uses_a_bounded_socket_read_timeout() -> None:
    """The media timeout bounds sock_read: a stalled body must not hang forever.

    The event stream deliberately has no read deadline because it never ends. A
    file transfer does end, so a server that sends headers and then stalls has to
    fail rather than block the reader while holding the connection.
    """
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = make_media_client(session)
    await client.async_get_capture_file(make_capture())
    _, kwargs = session.calls[0]
    timeout = kwargs["timeout"]
    assert timeout.total is None
    assert timeout.sock_read == DEFAULT_TIMEOUT


@pytest.mark.asyncio
async def test_stream_reads_in_bounded_chunks() -> None:
    """Every read is bounded by the documented chunk size, never unbounded."""
    response = FakeStreamResponse(200, b"x" * 500, "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    async for _ in stream:
        pass
    assert response.content.limits
    # Asserted against an absolute ceiling, not against the constant itself: a
    # test that only compares the reads to `_STREAM_CHUNK_BYTES` passes just as
    # happily when that constant is raised to 64 MiB, which would defeat the
    # memory bound this whole streaming API exists to provide.
    one_mib = 1024 * 1024
    assert all(0 < limit <= one_mib for limit in response.content.limits)


@pytest.mark.asyncio
async def test_stream_aclose_releases_a_stream_that_was_never_iterated() -> None:
    """A stream the caller inspects and drops must still release its connection."""
    response = FakeStreamResponse(200, MOVIE_BYTES, "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    assert stream.content_type == "video/quicktime"
    await stream.aclose()
    assert response.released is True


@pytest.mark.asyncio
async def test_stream_aclose_is_idempotent() -> None:
    """Closing twice, or closing a drained stream, is safe."""
    response = FakeStreamResponse(200, b"data", "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    async for _ in stream:
        pass
    await stream.aclose()
    await stream.aclose()
    assert response.released is True


@pytest.mark.asyncio
async def test_stream_context_manager_releases_on_early_break() -> None:
    """Breaking out mid-iteration inside `async with` still releases the response."""
    response = FakeStreamResponse(200, b"y" * 500, "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    async with stream:
        async for _ in stream:
            break
    assert response.released is True


@pytest.mark.asyncio
async def test_stream_context_manager_releases_on_error() -> None:
    """An exception raised inside the block still releases the response."""
    response = FakeStreamResponse(200, b"data", "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    sentinel = "caller blew up"
    with pytest.raises(ValueError, match=sentinel):
        async with stream:
            raise ValueError(sentinel)
    assert response.released is True


@pytest.mark.asyncio
async def test_stream_rejects_a_second_iteration() -> None:
    """Re-iterating is caller misuse, and must not look like a transport fault.

    The body is consumed as it is read, so a second pass could only yield the
    unread remainder -- a silently truncated file.
    """
    response = FakeStreamResponse(200, b"z" * 200, "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    async for _ in stream:
        pass
    with pytest.raises(RuntimeError, match="already been iterated"):
        async for _ in stream:
            pass


@pytest.mark.asyncio
async def test_stream_rejects_a_second_iteration_after_a_partial_read() -> None:
    """The guard holds when the first pass stopped early, too."""
    response = FakeStreamResponse(200, b"z" * 500, "video/quicktime")
    stream = make_stream(response, "video/quicktime")
    async for _ in stream:
        break
    with pytest.raises(RuntimeError, match="already been iterated"):
        async for _ in stream:
            pass


@pytest.mark.asyncio
async def test_stream_wraps_a_failure_after_some_chunks_were_yielded() -> None:
    """A mid-stream drop, once bytes are already flowing, is still typed."""
    response = FakeStreamResponse(200, b"a" * 500, "video/quicktime")
    allowed_reads = 2
    response.content = FailAfterContent(b"a" * 500, fail_after=allowed_reads)
    stream = make_stream(response, "video/quicktime")
    received: list[bytes] = []

    async def drain() -> None:
        async for chunk in stream:
            received.append(chunk)  # noqa: PERF401 - the partial read is the assertion

    with pytest.raises(SecuritySpyConnectError, match="stream failure"):
        await drain()
    assert len(received) == allowed_reads
    assert response.released is True


@pytest.mark.parametrize("bandwidth", ["high", None, 3.0, object()])
@pytest.mark.asyncio
async def test_file_rejects_a_non_bandwidth_selector(bandwidth: object) -> None:
    """A wrong-typed bandwidth is a ValueError before any request is issued."""
    session = FakeStreamSession(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)
    client = make_media_client(session)
    with pytest.raises(ValueError, match="CAPTURE_FILE_BANDWIDTH"):
        await client.async_get_capture_file(make_capture(), bandwidth=cast("Any", bandwidth))
    assert session.calls == []


def test_event_stream_server_timezone_is_a_required_keyword_argument() -> None:
    """No default exists: omitting it is a runtime `TypeError`, not a wrong instant."""
    session = FakeSession()
    client = make_client(session)
    with pytest.raises(TypeError):
        client.event_stream(on_event=lambda _event: None)  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_async_get_captures_server_timezone_is_a_required_keyword_argument() -> None:
    """No default exists: omitting it is a runtime `TypeError`, not a wrong instant."""
    session = FakeSession()
    client = make_client(session)
    with pytest.raises(TypeError):
        await client.async_get_captures(  # type: ignore[call-arg]
            [1], start_date=START_DATE, end_date=END_DATE
        )


SCHEDULE_TEST_CAMERA = 4
LIVE_ONLY_TEST_CAMERA = 5


# --- Story 1.14: a 401 can mean permission, not bad credentials (research §5.9) ---
#
# SecuritySpy 6.21 answers a permission denial with 401 -- not 403 -- on
# ++getfile, ++getfilehb, ++getfilelb, ++getpreview and ++ssSetSchedule, and
# that 401 is byte-identical to a genuinely wrong password. `_map_status`
# disambiguates any 401 with one follow-up read of ++systemInfo: the two
# requests hit the same stubbed transport, so the single canned status the
# existing `FakeSession`/`FakeStreamSession` return for every call cannot
# represent them differently. The two `Sequenced*` fakes below answer a
# different canned response per successive call instead.


class SequencedFakeSession(FakeSession):
    """Answers each successive `get`/`post` with the next item in a list.

    An item is either an ``(status, body)`` pair, answered as a `FakeResponse`,
    or a `BaseException`, raised as a connector error would be.
    """

    def __init__(self, responses: list[tuple[int, str] | BaseException]) -> None:
        """Store the queue of canned responses, one per call."""
        super().__init__()
        self._responses = list(responses)

    def _record(self, method: str, url: str, kwargs: dict[str, Any]) -> Any:  # noqa: ANN401
        """Append the call and return the next queued response or error."""
        self.methods.append(method)
        self.calls.append((url, kwargs))
        index = len(self.calls) - 1
        assert index < len(self._responses), f"unexpected extra request #{index + 1}: {url}"
        item = self._responses[index]
        if isinstance(item, BaseException):
            return RaisingContext(item)
        status, body = item
        return self.response_factory(status, body)


class SequencedFakeStreamSession(FakeStreamSession):
    """Answers each successive `get` with the next item in a list.

    An item is either an ``(status, body, content_type)`` triple, answered as
    a `FakeStreamResponse`, or a `BaseException`, raised as a connector error
    would be. Used for the media accessors, which share the streaming
    transport with the disambiguating ``++systemInfo`` probe.
    """

    def __init__(self, responses: list[tuple[int, bytes, str] | BaseException]) -> None:
        """Store the queue of canned responses, one per call."""
        super().__init__()
        self._responses = list(responses)

    def get(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401
        """Record the call and return the next queued response or error."""
        self.methods.append("GET")
        self.calls.append((url, kwargs))
        index = len(self.calls) - 1
        assert index < len(self._responses), f"unexpected extra request #{index + 1}: {url}"
        item = self._responses[index]
        if isinstance(item, BaseException):
            return RaisingContext(item)
        status, body, content_type = item
        response = FakeStreamResponse(status, body, content_type)
        self.responses.append(response)
        return AwaitableFakeStreamResponse(response)


@pytest.mark.asyncio
async def test_permitted_fetch_issues_no_probe() -> None:
    """A successful media fetch is never slowed or probed: exactly one request."""
    session = SequencedFakeStreamSession([(200, MOVIE_BYTES, MOVIE_CONTENT_TYPE)])
    client = make_media_client(session)
    stream = await client.async_get_capture_file(make_capture())
    assert stream.content_type == MOVIE_CONTENT_TYPE
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_schedule_write_401_without_perm_sched_is_reclassified() -> None:
    """++ssSetSchedule's 401 for a missing 'schedule' permission is not an auth failure.

    Verified live (research §5.9): a mask-839 account (no PERM_SCHED bit) gets
    401 from ++ssSetSchedule while ++systemInfo answers 200 in the same second.
    """
    session = SequencedFakeSession([(401, ""), (200, fixture_body())])
    client = make_client(session)
    with pytest.raises(SecuritySpyPermissionError) as err:
        await client.async_set_camera_arming(
            SCHEDULE_TEST_CAMERA,
            CaptureModes(continuous=True),
            override=ARM_OVERRIDE_ARMED_2_HOURS,
        )
    assert err.value.permission == PERMISSION_NAMES[PERM_SCHED]
    assert err.value.camera_number == SCHEDULE_TEST_CAMERA
    assert len(session.calls) == TWO_STATUSES


@pytest.mark.asyncio
async def test_live_only_getfile_401_is_reclassified_to_permission_error() -> None:
    """A Live-only account's ++getfile 401 is a permission denial, not bad credentials.

    Verified live (research §5.9): the byte-identical 401 that ++getfile,
    ++getfilehb and ++getfilelb answer with for a Live-only account is
    reclassified once ++systemInfo confirms the credentials are fine.
    """
    session = SequencedFakeStreamSession(
        [(401, b"", ""), (200, fixture_body().encode(), "application/json")]
    )
    client = make_media_client(session)
    capture = make_capture(camera=LIVE_ONLY_TEST_CAMERA)
    with pytest.raises(SecuritySpyPermissionError) as err:
        await client.async_get_capture_file(capture)
    assert err.value.permission == PERMISSION_NAMES[PERM_FILES]
    assert err.value.camera_number == LIVE_ONLY_TEST_CAMERA
    assert len(session.calls) == TWO_STATUSES


@pytest.mark.asyncio
async def test_live_only_getpreview_401_is_reclassified_to_permission_error() -> None:
    """Same reclassification as ++getfile, for ++getpreview's camera."""
    session = SequencedFakeStreamSession(
        [(401, b"", ""), (200, fixture_body().encode(), "application/json")]
    )
    client = make_media_client(session)
    capture = make_capture(camera=LIVE_ONLY_TEST_CAMERA)
    with pytest.raises(SecuritySpyPermissionError) as err:
        await client.async_get_capture_preview(capture)
    assert err.value.permission == PERMISSION_NAMES[PERM_FILES]
    assert err.value.camera_number == LIVE_ONLY_TEST_CAMERA
    assert len(session.calls) == TWO_STATUSES


@pytest.mark.asyncio
async def test_genuinely_wrong_password_stays_an_auth_error() -> None:
    """A second 401 from the probe means the credentials really are bad."""
    session = SequencedFakeStreamSession([(401, b"", ""), (401, b"", "")])
    client = make_media_client(session)
    with pytest.raises(SecuritySpyAuthError) as err:
        await client.async_get_capture_file(make_capture())
    assert err.value.status == client_module._HTTP_UNAUTHORIZED  # noqa: SLF001 - the mapped status under test
    assert len(session.calls) == TWO_STATUSES


@pytest.mark.asyncio
async def test_inconclusive_probe_leaves_the_original_verdict_unchanged() -> None:
    """A probe that cannot cleanly answer must never upgrade or downgrade the verdict.

    The original 401 is a `SecuritySpyAuthError` here even though the true
    cause is unknowable -- an inconclusive probe (timeout, TLS, connection
    failure) is not evidence either way, so the verdict the media endpoint
    itself gave stands.
    """
    session = SequencedFakeStreamSession([(401, b"", ""), TimeoutError("probe timed out")])
    client = make_media_client(session)
    with pytest.raises(SecuritySpyAuthError):
        await client.async_get_capture_file(make_capture())
    assert len(session.calls) == TWO_STATUSES


@pytest.mark.asyncio
async def test_probe_itself_401_does_not_recurse() -> None:
    """A direct ++systemInfo 401 is never disambiguated: it would probe itself.

    Calling `async_get_server_info` directly and getting a 401 must raise
    immediately, issuing exactly one request -- probing ++systemInfo with
    another read of ++systemInfo would answer nothing new.
    """
    session = SequencedFakeSession([(401, "")])
    client = make_client(session)
    with pytest.raises(SecuritySpyAuthError):
        await client.async_get_server_info()
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_settings_403_is_unchanged_and_issues_no_probe() -> None:
    """The settings pages' 403 is unaffected: it is already unambiguous."""
    session = SequencedFakeSession([(403, "")])
    client = make_client(session)
    with pytest.raises(SecuritySpyPermissionError):
        await client.async_set_camera_settings(4, CameraSettingsPatch(overlay_text="x"))
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_streamed_media_401_releases_the_connection_before_reclassifying() -> None:
    """A reclassified 401 must not leak the pooled connection either.

    Preserves the existing release-before-raise ordering (`_stream_bytes`
    releases its response as soon as the status ladder raises) for the
    reclassified path, not only for the plain-401 path.
    """
    session = SequencedFakeStreamSession(
        [(401, b"", ""), (200, fixture_body().encode(), "application/json")]
    )
    client = make_media_client(session)
    with pytest.raises(SecuritySpyPermissionError):
        await client.async_get_capture_file(make_capture())
    assert session.responses[0].released is True


class ReleaseOrderCheckingStreamSession(SequencedFakeStreamSession):
    """Fails the test if the probe request is issued before the prior response is released.

    The disambiguating probe is a second live HTTP request; if it fires while
    the original 401'd response is still holding a connection out of the
    caller's pool, that is a resource leak even though the response is
    eventually released once the exception propagates.
    """

    def get(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401
        """Assert every already-issued response was released before this call."""
        for response in self.responses:
            assert response.released, (
                "probe request issued while a prior response was still held open"
            )
        return super().get(url, **kwargs)


@pytest.mark.asyncio
async def test_streamed_media_401_releases_the_connection_before_probing() -> None:
    """The probe must not run while the original 401'd response is still held open.

    Distinct from `test_streamed_media_401_releases_the_connection_before_reclassifying`:
    that test only checks release happens before the exception is raised, which
    is also satisfied if release happens after the probe completes. This test
    pins down that release happens before the probe request is even issued, so
    the two requests never concurrently hold connections out of the pool.
    """
    session = ReleaseOrderCheckingStreamSession(
        [(401, b"", ""), (200, fixture_body().encode(), "application/json")]
    )
    client = make_media_client(session)
    with pytest.raises(SecuritySpyPermissionError):
        await client.async_get_capture_file(make_capture())


@pytest.mark.asyncio
async def test_buffered_media_401_releases_the_connection_before_probing() -> None:
    """Same release-before-probe guarantee for the buffered accessor.

    `async_get_capture_preview` reads a response inside an `async with` block
    rather than returning a live stream; the probe must still not run while
    that response is held open.
    """
    session = ReleaseOrderCheckingStreamSession(
        [(401, b"", ""), (200, fixture_body().encode(), "application/json")]
    )
    client = make_media_client(session)
    with pytest.raises(SecuritySpyPermissionError):
        await client.async_get_capture_preview(make_capture())
