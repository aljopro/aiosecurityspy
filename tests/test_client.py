"""Transport coverage for SecuritySpyClient against a stubbed aiohttp session."""

from __future__ import annotations

import contextlib
import json
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self, cast

import aiohttp
import pytest

from aiosecurityspy import (
    SecuritySpyAuthError,
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
        self.response_factory: type[FakeResponse] = FakeResponse

    def get(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Record the call and return an async context manager."""
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


class FakeCertificateError(aiohttp.ClientSSLError):
    """A real `aiohttp.ClientSSLError` subclass, minus the private ConnectionKey.

    `aiohttp.ClientConnectorCertificateError` can only be built from aiohttp's
    internal `ConnectionKey`, so this stands in for the family the client must
    catch without reaching into private plumbing.
    """

    def __init__(self, message: str) -> None:
        """Build the error with a plain message."""
        Exception.__init__(self, message)


def certificate_error() -> aiohttp.ClientError:
    return FakeCertificateError(f"certificate verify failed for {HOST}")


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
    assert isinstance(kwargs["auth"], aiohttp.BasicAuth)
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
async def test_certificate_error_maps_to_connect_error() -> None:
    with pytest.raises(SecuritySpyConnectError) as err:
        await make_client(FakeSession(error=certificate_error())).async_get_server_info()
    assert f"{HOST}:{PORT}" in str(err.value)


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
