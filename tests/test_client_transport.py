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

from aiosecurityspy import (
    ARM_OVERRIDE_ARMED_2_HOURS,
    CameraSettingsPatch,
    CaptureModes,
    SecuritySpyAuthError,
    SecuritySpyClient,
    SecuritySpyConnectError,
)

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


@pytest.mark.asyncio
async def test_real_settings_write_reaches_the_bare_path_with_the_sentinel_body() -> None:
    """The stub cannot prove aiohttp honours a bare-path POST with a string body.

    Three things are only true if the real client library cooperates: the path
    stays bare (research §8.0 -- the query form 404s), the content type is the
    urlencoded one, and the body arrives byte-for-byte with ``formData`` first.
    """
    seen: dict[str, str] = {}

    async def handle(request: web.Request) -> web.Response:
        seen["path"] = request.path
        seen["query"] = request.query_string
        seen["content_type"] = request.headers.get("Content-Type", "")
        seen["body"] = (await request.read()).decode()
        # Decoded by the *server's* own form parser, not ours: the point of this
        # case is that a real form decoder recovers the original value from the
        # percent-encoded body -- `%20` is a space under a form decoder and under
        # a URI decoder alike, which `+` is not.
        form = await request.post()
        seen["camera_num"] = str(form["cameraNum"])
        seen["overlay_text"] = str(form["overlayText"])
        return web.json_response({"camUpdate": {"num": "3"}})

    app = web.Application()
    app.router.add_post("/++settings-cameras", handle)
    settings_server = AiohttpTestServer(app)
    await settings_server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            await make_client(session, settings_server).async_set_camera_settings(
                3, CameraSettingsPatch(overlay_text="Front Gate")
            )
    finally:
        await settings_server.close()

    assert seen["path"] == "/++settings-cameras"
    assert seen["query"] == "", "the query form of this endpoint returns 404"
    assert seen["content_type"] == "application/x-www-form-urlencoded"
    assert seen["body"] == "formData&cameraNum=3&overlayText=Front%20Gate"
    assert seen["body"].startswith("formData")
    assert seen["camera_num"] == "3", "cameraNum travels in the body, not the query string"
    assert seen["overlay_text"] == "Front Gate", "the server's own form parser recovers the value"


@pytest.mark.asyncio
async def test_real_reserved_characters_survive_a_real_form_parser() -> None:
    """A value full of reserved bytes round-trips through a real form decoder.

    ``&`` and ``=`` must not forge a field separator, non-ASCII must arrive as
    percent-encoded UTF-8, and a literal ``+`` must come back as a ``+`` -- which
    it only does because the value was sent as ``%2B`` rather than plus-encoded.
    """
    hostile = "Front & Back = 100% Grüße+more"
    seen: dict[str, str] = {}

    async def handle(request: web.Request) -> web.Response:
        seen["body"] = (await request.read()).decode()
        form = await request.post()
        seen["keys"] = ",".join(sorted(form))
        seen["name"] = str(form["name"])
        return web.json_response({"camUpdate": {"num": "3"}})

    app = web.Application()
    app.router.add_post("/++settings-cameras", handle)
    settings_server = AiohttpTestServer(app)
    await settings_server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            await make_client(session, settings_server).async_set_camera_settings(
                3, CameraSettingsPatch(name=hostile)
            )
    finally:
        await settings_server.close()

    assert seen["body"].isascii(), "no raw non-ASCII byte reaches the wire"
    assert seen["keys"] == "cameraNum,formData,name", "no reserved byte forged an extra field"
    assert seen["name"] == hostile


@pytest.mark.asyncio
async def test_real_arming_carries_mode_and_override_and_never_a_schedule() -> None:
    """``++ssSetSchedule`` is misleadingly named: no schedule is ever assigned."""
    seen: dict[str, dict[str, str]] = {}

    async def handle(request: web.Request) -> web.Response:
        seen["query"] = dict(request.query)
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/++ssSetSchedule", handle)
    arming_server = AiohttpTestServer(app)
    await arming_server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            await make_client(session, arming_server).async_set_camera_arming(
                3,
                CaptureModes(continuous=True, motion=True, actions=True),
                override=ARM_OVERRIDE_ARMED_2_HOURS,
            )
    finally:
        await arming_server.close()

    assert seen["query"] == {"cameraNum": "3", "mode": "CMA", "override": "6"}
    assert "schedule" not in seen["query"]


@pytest.mark.asyncio
async def test_real_disarming_all_three_sends_a_present_but_empty_mode() -> None:
    """All-false is an instruction, not a missing value.

    It is the library's one semantic that differs from every other client. The
    stub cannot prove it survives yarl's query encoding to a real socket, and a
    dropped ``mode=`` would silently leave the camera armed.
    """
    seen: dict[str, str] = {}

    async def handle(request: web.Request) -> web.Response:
        seen["query_string"] = request.query_string
        seen["mode"] = request.query["mode"]
        return web.Response(text="OK")

    app = web.Application()
    app.router.add_get("/++ssSetSchedule", handle)
    arming_server = AiohttpTestServer(app)
    await arming_server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            await make_client(session, arming_server).async_set_camera_arming(
                3,
                CaptureModes(continuous=False, motion=False, actions=False),
            )
    finally:
        await arming_server.close()

    assert seen["mode"] == ""
    assert "mode=" in seen["query_string"]


@pytest.mark.asyncio
async def test_real_charsetless_write_receipt_does_not_fail_a_successful_write() -> None:
    """A write that the server accepted must not be reported as a failure.

    A charset-less, non-JSON receipt makes aiohttp's ``get_encoding()`` raise;
    for a body this library never parses, that must not become an error.
    """

    async def handle(_: web.Request) -> web.Response:
        return web.Response(body=b"OK", content_type="text/plain")

    app = web.Application()
    app.router.add_get("/++ssSetSchedule", handle)
    arming_server = AiohttpTestServer(app)
    await arming_server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            await make_client(session, arming_server).async_set_camera_arming(
                3, CaptureModes(motion=True)
            )
    finally:
        await arming_server.close()


@pytest.mark.asyncio
async def test_real_settings_read_sends_the_required_camera_number() -> None:
    """Omitting ``cameraNum`` returns HTTP 500 from a real server (research §8.0)."""
    seen: dict[str, dict[str, str]] = {}

    async def handle(request: web.Request) -> web.Response:
        seen["query"] = dict(request.query)
        if "cameraNum" not in request.query:
            return web.Response(status=500)
        # A representative slice of the real ~120-key page: enough curated keys
        # to clear `SETTINGS_PAGE_KEY_QUORUM`, which a two-key stub would not.
        return web.json_response(
            {
                "name": "Gate",
                "overlayText": "Front Gate",
                "motionSensitivity": 50,
                "mcTriggerMotionH": True,
            }
        )

    app = web.Application()
    app.router.add_get("/++settings-cameras", handle)
    settings_server = AiohttpTestServer(app)
    await settings_server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            settings = await make_client(session, settings_server).async_get_camera_settings(3)
    finally:
        await settings_server.close()

    assert seen["query"] == {"cameraNum": "3", "format": "json"}
    assert settings.overlay_text == "Front Gate"


@pytest.mark.asyncio
async def test_real_write_rejection_maps_to_a_typed_error() -> None:
    async def handle(_: web.Request) -> web.Response:
        return web.Response(status=401)

    app = web.Application()
    app.router.add_post("/++settings-cameras", handle)
    settings_server = AiohttpTestServer(app)
    await settings_server.start_server()
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(SecuritySpyAuthError):
                await make_client(session, settings_server).async_set_camera_settings(
                    3, CameraSettingsPatch(brightness=100)
                )
    finally:
        await settings_server.close()
