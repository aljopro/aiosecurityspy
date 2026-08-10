"""Transport seam exercised against a real ``aiohttp`` client and server.

Every other client test drives a stubbed session, which proves the client's own
logic but cannot prove that the kwargs it passes (``params``, ``ssl``,
``timeout``, ``auth``, ``allow_redirects``) are ones the installed ``aiohttp``
actually honours, or that the ``++systemInfo`` path survives URL normalization.
This module closes that gap with a real in-process server.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import TYPE_CHECKING

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer as AiohttpTestServer  # aliased: pytest collects `Test*`

from aiosecurityspy import SecuritySpyAuthError, SecuritySpyClient, SecuritySpyConnectError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

USERNAME = "viewer"
PASSWORD = "sentinel-pass-live"  # noqa: S105 - leak-detection sentinel, not a real credential
SYSTEM_INFO = {
    "system": {
        "server": {"uuid": "SS-LIVE", "version": "6.20", "camera-count": "1"},
        "cameralist": {"camera": [{"number": "3", "name": "Gate", "permissions": "1"}]},
    }
}


class Recorder:
    """Captures what the real server saw, so the client's request can be asserted."""

    def __init__(self) -> None:
        """Start with nothing recorded."""
        self.path: str | None = None
        self.query: dict[str, str] = {}
        self.authorization: str | None = None


@pytest_asyncio.fixture
async def recorder() -> Recorder:
    return Recorder()


@pytest_asyncio.fixture
async def server(recorder: Recorder) -> AsyncIterator[AiohttpTestServer]:
    """Run a real aiohttp server that answers ``/++systemInfo``."""

    async def handle_system_info(request: web.Request) -> web.Response:
        recorder.path = request.path
        recorder.query = dict(request.query)
        recorder.authorization = request.headers.get("Authorization")
        if recorder.authorization != _expected_authorization():
            return web.Response(status=401)
        return web.json_response(SYSTEM_INFO)

    async def handle_slow(_: web.Request) -> web.Response:
        await asyncio.sleep(5)
        return web.Response(text="too late")

    app = web.Application()
    app.router.add_get("/++systemInfo", handle_system_info)
    app.router.add_get("/++slow", handle_slow)
    test_server = AiohttpTestServer(app)
    await test_server.start_server()
    try:
        yield test_server
    finally:
        await test_server.close()


def _expected_authorization() -> str:
    token = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    return f"Basic {token}"


def make_client(
    session: aiohttp.ClientSession,
    server: AiohttpTestServer,
    *,
    password: str = PASSWORD,
    timeout: float = 5.0,
) -> SecuritySpyClient:
    return SecuritySpyClient(
        session,
        "127.0.0.1",
        server.port or 0,
        username=USERNAME,
        password=password,
        timeout=timeout,
    )


@pytest.mark.asyncio
async def test_real_request_reaches_the_endpoint_and_decodes(
    server: AiohttpTestServer, recorder: Recorder
) -> None:
    async with aiohttp.ClientSession() as session:
        info = await make_client(session, server).async_get_server_info()

    assert recorder.path == "/++systemInfo", "the ++ prefix must survive URL handling"
    assert recorder.query == {"format": "json"}
    assert recorder.authorization == _expected_authorization()
    assert info.uuid == "SS-LIVE"
    assert set(info.cameras) == {3}


@pytest.mark.asyncio
async def test_real_session_is_still_usable_afterwards(server: AiohttpTestServer) -> None:
    """The library must not close or exhaust the caller's session."""
    async with aiohttp.ClientSession() as session:
        client = make_client(session, server)
        await client.async_get_server_info()
        await client.async_get_server_info()
        assert session.closed is False
    assert session.closed is True  # closed by the caller's own context manager


@pytest.mark.asyncio
async def test_real_401_maps_to_auth_error(server: AiohttpTestServer) -> None:
    async with aiohttp.ClientSession() as session:
        client = make_client(session, server, password="wrong")  # noqa: S106 - deliberately wrong
        with pytest.raises(SecuritySpyAuthError):
            await client.async_get_server_info()


@pytest.mark.asyncio
async def test_real_timeout_bounds_a_slow_server(server: AiohttpTestServer) -> None:
    """The per-request ClientTimeout is what makes "fails rather than hangs" true."""
    async with aiohttp.ClientSession() as session:
        client = make_client(session, server, timeout=0.2)
        with pytest.raises(SecuritySpyConnectError) as err:
            await client._request_json("++slow")  # noqa: SLF001 - the seam under test
    assert "timed out" in str(err.value)


@pytest.mark.asyncio
async def test_real_non_json_body_maps_to_connect_error() -> None:
    async def handle(_: web.Request) -> web.Response:
        return web.Response(text="<html>not json</html>")

    app = web.Application()
    app.router.add_get("/++systemInfo", handle)
    plain = AiohttpTestServer(app)
    await plain.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(SecuritySpyConnectError, match="not valid JSON"):
                await make_client(session, plain).async_get_server_info()
    finally:
        await plain.close()


def test_live_payload_shape_matches_the_offline_fixture() -> None:
    """The live-server payload and the offline fixture must share one envelope.

    If they drift, the offline tests stop proving anything about the shape the
    real transport actually carries.
    """
    fixture_path = Path(__file__).parent / "fixtures" / "system_info.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert set(fixture) == set(SYSTEM_INFO) == {"system"}
    assert set(fixture["system"]) >= {"server", "cameralist"}
    assert set(SYSTEM_INFO["system"]) == {"server", "cameralist"}
    assert {"uuid", "version", "camera-count"} <= set(fixture["system"]["server"])
    assert isinstance(fixture["system"]["cameralist"]["camera"], list)


@pytest.mark.asyncio
async def test_real_redirect_is_reported_rather_than_followed() -> None:
    """A real 3xx surfaces as a scheme hint, not as a credential failure."""

    async def handle(_: web.Request) -> web.Response:
        return web.Response(status=301, headers={"Location": "/++systemInfo"})

    app = web.Application()
    app.router.add_get("/++systemInfo", handle)
    redirecting = AiohttpTestServer(app)
    await redirecting.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(SecuritySpyConnectError, match="use_https=True"):
                await make_client(session, redirecting).async_get_server_info()
    finally:
        await redirecting.close()


@pytest.mark.asyncio
async def test_real_large_body_is_read_completely() -> None:
    """A body spanning many stream reads must not be truncated.

    `StreamReader.read(n)` returns whatever is buffered, not n bytes, so a
    single read silently truncates a large `++systemInfo` and the client then
    blames the server for malformed JSON. This is the regression guard: the
    payload is far larger than one buffer fill but far under the byte cap.
    """
    cameras = [
        {
            "number": str(i),
            "name": f"camera-{i}-{'n' * 60}",
            "connected": "yes",
            "enabled": "yes",
            "permissions": "0",
        }
        for i in range(2000)
    ]
    payload = {
        "system": {
            "server": {"uuid": "u", "version": "6.0", "camera-count": str(len(cameras))},
            "cameralist": {"camera": cameras},
        }
    }
    assert len(json.dumps(payload)) > 256 * 1024

    async def handle(_: web.Request) -> web.Response:
        return web.json_response(payload)

    app = web.Application()
    app.router.add_get("/++systemInfo", handle)
    big = AiohttpTestServer(app)
    await big.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            info = await make_client(session, big).async_get_server_info()
        assert len(info.cameras) == len(cameras)
    finally:
        await big.close()


@pytest.mark.asyncio
async def test_real_response_without_a_charset_maps_to_connect_error() -> None:
    """A charset-less non-JSON body must not raise aiohttp's RuntimeError.

    `get_encoding()` raises `RuntimeError` when the body has not been buffered
    into `response._body` and no charset was declared -- exactly the wrong-port
    / error-page case -- and that must stay inside the typed hierarchy.
    """

    async def handle(_: web.Request) -> web.Response:
        return web.Response(body=b"<html>not securityspy</html>", content_type="text/html")

    app = web.Application()
    app.router.add_get("/++systemInfo", handle)
    plain = AiohttpTestServer(app)
    await plain.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(SecuritySpyConnectError):
                await make_client(session, plain).async_get_server_info()
    finally:
        await plain.close()
