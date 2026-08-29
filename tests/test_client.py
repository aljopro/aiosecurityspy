"""Transport coverage for SecuritySpyClient against a stubbed aiohttp session."""

from __future__ import annotations

import contextlib
import json
import ssl
import traceback
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self, cast
from zoneinfo import ZoneInfo

import aiohttp
import pytest

from aiosecurityspy import (
    CAPTURE_FILTER_ALL,
    CAPTURE_FILTER_ANIMAL,
    CAPTURE_FILTER_CONTINUOUS,
    CAPTURE_FILTER_HUMAN,
    CAPTURE_FILTER_MOVIES,
    CAPTURE_FILTER_VEHICLE,
    CameraSettingsPatch,
    SecuritySpyAuthError,
    SecuritySpyCertificateError,
    SecuritySpyClient,
    SecuritySpyConnectError,
    SecuritySpyError,
    SecuritySpyUnsupportedVersionError,
)
from aiosecurityspy import client as client_module

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
@pytest.mark.parametrize("status", [401, 403])
async def test_auth_failure_maps_to_auth_error(status: int) -> None:
    session = FakeSession(status, "")
    with pytest.raises(SecuritySpyAuthError) as err:
        await make_client(session).async_get_server_info()
    assert err.value.status == status
    assert f"{HOST}:{PORT}" in str(err.value)


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
@pytest.mark.parametrize("status", [401, 403])
async def test_auth_rejection_surfaces_from_the_shared_seam(status: int) -> None:
    session = FakeSession(status, "")
    with pytest.raises(SecuritySpyAuthError):
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
