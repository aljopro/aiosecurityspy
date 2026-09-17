"""Questions only a real SecuritySpy server can answer.

Every test here is marked ``live`` and skips unless ``aiosecurityspy/.env``
supplies a server, so the offline suite -- and CI, and any clone -- is
unaffected. See ``.env.example`` for the variables.

These exist because a family of decoding and refusal questions cannot be
settled offline without guessing at the answer, and a fixture authored to match
a guess is precisely how Epic 1 acquired nine bugfix stories. The deferred-work
ledger records each of them as "needs a live server":

* **DW 1.6a** -- both settings and arming writes discard the response body and
  treat any 2xx as success. A server that answers 200 with an error page, or
  silently ignores a write from an unprivileged account, is today
  indistinguishable from one that applied it. On a security product "the camera
  is disarmed" returning cleanly when nothing changed is the expensive failure.
* **T10** -- ``ARM_OVERRIDE_UNCHANGED`` (-1) is annotated in research §5.2 as a
  *client* sentinel, yet it is the default for ``async_set_camera_arming`` and is
  transmitted on every arming call that does not name an override.
* **Per-camera permissions** -- the library models the mask per camera rather
  than per account. Nothing has confirmed it varies within one account.
* **Bit 1 (value 2)** -- set on live cameras and named nowhere
  (``securityspy-6.21-verification.md`` §4.1).

Credentials are never asserted on, logged, or written to a fixture; a failure
here must be diagnosable from status codes and shapes alone.
"""

from __future__ import annotations

import asyncio
import base64
import shutil
import sys
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import TYPE_CHECKING

import aiohttp
import pytest
import pytest_asyncio

import live_env
from aiosecurityspy import (
    ARM_OVERRIDE_ARMED_1_HOUR,
    ARM_OVERRIDE_UNCHANGED,
    PERM_CAMCONTROL,
    PERM_SCHED,
    PERM_SETTINGS,
    CameraSettingsPatch,
    CaptureModes,
    SecuritySpyAuthError,
    SecuritySpyClient,
    SecuritySpyPermissionError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from aiosecurityspy import ServerInfo

pytestmark = pytest.mark.live

#: Bit 1 is set on live cameras on 6.21 and is named in no published table.
UNNAMED_BIT_1 = 2

#: Bounded lookback for the media probe; FR-4 forbids unbounded history queries.
CAPTURE_LOOKBACK_DAYS = 7


def _report(message: str) -> None:
    """Record an observation for the operator running these tests.

    These tests exist to *learn* wire facts, not only to assert them, so the
    observation is the deliverable. Written to stdout so `pytest -s` surfaces it
    without a logging handler having to be configured first.
    """
    sys.stdout.write(f"{message}\n")


def _client(session: aiohttp.ClientSession, role: str) -> SecuritySpyClient:
    """Build a client for one configured role, skipping when it is not set up."""
    host = live_env.get("SECURITYSPY_HOST")
    if host is None:
        pytest.skip("SECURITYSPY_HOST is not set; see aiosecurityspy/.env.example")
    account = live_env.credentials(role)
    if account is None:
        pytest.skip(f"SECURITYSPY_{role}_USER/_PASS are not set")
    username, password = account
    return SecuritySpyClient(
        session,
        host,
        live_env.get_int("SECURITYSPY_PORT") or 8001,
        username=username,
        password=password,
        use_https=live_env.flag("SECURITYSPY_USE_HTTPS"),
        verify_ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
        timeout=15.0,
    )


@pytest_asyncio.fixture
async def session() -> AsyncIterator[aiohttp.ClientSession]:
    """One caller-provided session, as the library requires."""
    async with aiohttp.ClientSession() as open_session:
        yield open_session


def _test_camera() -> int:
    number = live_env.get_int("SECURITYSPY_TEST_CAMERA")
    if number is None:
        pytest.skip("SECURITYSPY_TEST_CAMERA is not set")
    return number


def _client_with_key_as_password(session: aiohttp.ClientSession) -> SecuritySpyClient:
    """Build a client for the "Live" account using its API key as the password.

    Skips when the key is not configured. Story 1.21's spike: SecuritySpy
    6.22b9+ per-account API keys authenticate identically to the password when
    placed in the same `Authorization: Basic` slot, with the username ignored.
    This uses the account's real username (see `.env.example`); the key value
    itself is never asserted on or logged.
    """
    host = live_env.get("SECURITYSPY_HOST")
    if host is None:
        pytest.skip("SECURITYSPY_HOST is not set; see aiosecurityspy/.env.example")
    account = live_env.credentials("LIVE")
    key = live_env.get("SECURITYSPY_LIVE_KEY")
    if account is None or key is None:
        pytest.skip("SECURITYSPY_LIVE_USER/_PASS/_KEY are not all set")
    username, _password = account
    return SecuritySpyClient(
        session,
        host,
        live_env.get_int("SECURITYSPY_PORT") or 8001,
        username=username,
        password=key,
        use_https=live_env.flag("SECURITYSPY_USE_HTTPS"),
        verify_ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
        timeout=15.0,
    )


# --- API keys as Basic-auth passwords (Story 1.21) ----------------------------


@pytest.mark.asyncio
async def test_live_server_info_accepts_key_as_password(
    session: aiohttp.ClientSession,
) -> None:
    """`++systemInfo` accepts the "Live" account's API key as the Basic password.

    Regression check for the spike's headline finding: a key placed in the
    password slot of `Authorization: Basic base64(username:KEY)` authenticates
    exactly like the password, with the real username. See
    `_bmad-output/planning-artifacts/research/securityspy-api-keys-6.22.md`.
    """
    client = _client_with_key_as_password(session)
    info = await client.async_get_server_info()
    assert info.cameras, "the key-authenticated account saw no cameras at all"


@pytest.mark.asyncio
async def test_live_camera_image_accepts_key_as_password(
    session: aiohttp.ClientSession,
) -> None:
    """`++image` accepts the "Live" account's API key as the Basic password.

    Companion to `test_live_server_info_accepts_key_as_password`: confirms the
    key also authenticates the media path, not only `++systemInfo`.
    """
    client = _client_with_key_as_password(session)
    info = await client.async_get_server_info()
    camera = _test_camera()
    if camera not in info.cameras:
        pytest.skip("SECURITYSPY_TEST_CAMERA is not visible to the LIVE account")
    image = await client.async_get_camera_image(info, camera)
    assert image.content_type.startswith("image/")
    assert image.data


def _base_url() -> str:
    """Build the server's base URL from `.env`, skipping when unconfigured.

    The library never constructs an `auth=` query parameter itself (AD-13
    confines that form to the relay's own upstream connection), so exercising
    it needs a raw request outside `SecuritySpyClient`.
    """
    host = live_env.get("SECURITYSPY_HOST")
    if host is None:
        pytest.skip("SECURITYSPY_HOST is not set; see aiosecurityspy/.env.example")
    port = live_env.get_int("SECURITYSPY_PORT") or 8001
    scheme = "https" if live_env.flag("SECURITYSPY_USE_HTTPS") else "http"
    return f"{scheme}://{host}:{port}"


@pytest.mark.asyncio
async def test_live_raw_key_in_auth_query_param_is_rejected(
    session: aiohttp.ClientSession,
) -> None:
    """A raw key in `?auth=` is refused, contrary to SecuritySpy's own help text.

    The "API Key" section of Settings > Web account management describes
    adding `auth=<key>` to any URL. Live testing found the server rejects that
    literal form with 401 on every endpoint tried, while wrapping it the way
    Basic auth wraps a password (`auth=` + base64 of `username:key`) succeeds.
    Regression check for that vendor discrepancy, not a library bug -- the
    library never builds the raw form itself.
    """
    key = live_env.get("SECURITYSPY_LIVE_KEY")
    if key is None:
        pytest.skip("SECURITYSPY_LIVE_KEY is not set; see aiosecurityspy/.env.example")
    async with session.get(
        f"{_base_url()}/++systemInfo",
        params={"auth": key},
        ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
    ) as response:
        await response.read()  # drain fully so the connection closes cleanly
        assert response.status == HTTPStatus.UNAUTHORIZED


@pytest.mark.asyncio
async def test_live_base64_wrapped_key_in_auth_query_param_is_accepted(
    session: aiohttp.ClientSession,
) -> None:
    """`?auth=` accepts a key wrapped the same way Basic auth wraps a password.

    Companion to `test_live_raw_key_in_auth_query_param_is_rejected`: proves
    the query-string form isn't rejected outright, only the raw-key spelling
    the vendor's help text describes. The username is arbitrary and ignored,
    matching the Basic-auth-header behavior -- confirmed with a made-up
    username, not the account's real one, so this cannot be mistaken for an
    ordinary authenticated request.
    """
    key = live_env.get("SECURITYSPY_LIVE_KEY")
    if key is None:
        pytest.skip("SECURITYSPY_LIVE_KEY is not set; see aiosecurityspy/.env.example")
    wrapped = base64.b64encode(f"not-a-real-account:{key}".encode()).decode()
    async with session.get(
        f"{_base_url()}/++systemInfo",
        params={"auth": wrapped},
        ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
    ) as response:
        await response.read()  # drain fully so the connection closes cleanly
        assert response.status == HTTPStatus.OK


def _samekey_password() -> str:
    """Return the SAMEKEY account's password, or skip when it is not configured.

    `SECURITYSPY_SAMEKEY_KEY` is deliberately not read here: it was miscaptured
    (one character short, missing the `API_` prefix) when this fixture was set
    up, and the account's password -- set equal to the real key at creation --
    is what actually carries the key value. `.env.example` documents this.
    """
    account = live_env.credentials("SAMEKEY")
    if account is None:
        pytest.skip("SECURITYSPY_SAMEKEY_USER/_PASS are not set")
    _username, password = account
    return password


@pytest.mark.asyncio
async def test_live_samekey_password_authenticates_api_endpoints_under_any_username(
    session: aiohttp.ClientSession,
) -> None:
    """An account whose password equals its own key authenticates like a key.

    Regression check for the password-equals-key lock-out finding: once an
    account's password is set to a key-shaped value, SecuritySpy treats it as
    key-authenticated on the API surface -- any username works, including one
    that is not the account's own -- exactly as a real key does.
    """
    password = _samekey_password()
    async with session.get(
        f"{_base_url()}/++systemInfo",
        headers={"Authorization": aiohttp.encode_basic_auth("not-a-real-account", password)},
        ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
    ) as response:
        await response.read()  # drain fully so the connection closes cleanly
        assert response.status == HTTPStatus.OK


@pytest.mark.asyncio
async def test_live_samekey_password_is_refused_at_web_login(
    session: aiohttp.ClientSession,
) -> None:
    """The same account is locked out of its own web UI login by its password.

    Companion to the API-side test above: with the account's real username,
    the identical password/key value is refused (403) at the web interface,
    the same lock-out a real API key produces. This is SecuritySpy's own
    behavior, not something the library can detect or prevent -- documented
    here as a known edge case, not addressed with a library change.
    """
    account = live_env.credentials("SAMEKEY")
    if account is None:
        pytest.skip("SECURITYSPY_SAMEKEY_USER/_PASS are not set")
    username, password = account
    async with session.get(
        f"{_base_url()}/",
        headers={"Authorization": aiohttp.encode_basic_auth(username, password)},
        ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
    ) as response:
        await response.read()  # drain fully so the connection closes cleanly
        assert response.status == HTTPStatus.FORBIDDEN


# --- Story 1.22: closing 1.21's unmet sub-ACs ---------------------------------


@pytest.mark.asyncio
async def test_live_partial_key_shaped_password_authenticates_normally(
    session: aiohttp.ClientSession,
) -> None:
    """A password starting `API_` but not full key-shaped authenticates as itself.

    Closes the sub-AC Story 1.21 left untested: does a password that merely
    begins with the key prefix get mistaken for a key (and so authenticate
    under any username, like the SAMEKEY case), or does it behave as an
    ordinary password? Only the account's own username is tried here.
    """
    account = live_env.credentials("PARTIALKEY")
    if account is None:
        pytest.skip("SECURITYSPY_PARTIALKEY_USER/_PASS are not set")
    username, password = account
    full_key_length = len("API_") + 32
    assert password.startswith("API_"), "SECURITYSPY_PARTIALKEY_PASS must start with 'API_'"
    assert len(password) != full_key_length, (
        "SECURITYSPY_PARTIALKEY_PASS must NOT match the full key shape (API_ + "
        "32 base62 chars), or this test silently validates an ordinary password "
        "instead of the partial-key-shape case it exists to cover -- see "
        ".env.example"
    )
    async with session.get(
        f"{_base_url()}/++systemInfo",
        headers={"Authorization": aiohttp.encode_basic_auth(username, password)},
        ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
    ) as response:
        await response.read()  # drain fully so the connection closes cleanly
        assert response.status == HTTPStatus.OK


@pytest.mark.asyncio
async def test_live_percam_key_on_unpermitted_camera_is_denied(
    session: aiohttp.ClientSession,
) -> None:
    """A PERCAM key sees exactly the same cameras as the PERCAM password.

    Closes the other sub-AC Story 1.21 left untested: does a key carry exactly
    the account's camera-visibility permissions? A local-only check (does
    `async_get_camera_image` refuse a camera absent from the key-authenticated
    inventory) would prove nothing, since that guard fires before any request
    reaches the server regardless of which credential fetched the inventory --
    see `client.py::async_get_camera_image`. The real question is whether the
    *server* scopes a key-authenticated `++systemInfo` the same as a
    password-authenticated one, so this compares both inventories for the same
    account and then, only as a secondary check, confirms the local guard still
    denies a camera outside that shared scope.
    """
    host = live_env.get("SECURITYSPY_HOST")
    if host is None:
        pytest.skip("SECURITYSPY_HOST is not set; see aiosecurityspy/.env.example")
    key = live_env.get("SECURITYSPY_PERCAM_KEY")
    if key is None:
        pytest.skip("SECURITYSPY_PERCAM_KEY is not set")
    password_client = _client(session, "PERCAM")
    password_info = await password_client.async_get_server_info()

    account = live_env.credentials("PERCAM")
    assert account is not None  # `_client` above already skipped if this were unset
    username, _password = account
    key_client = SecuritySpyClient(
        session,
        host,
        live_env.get_int("SECURITYSPY_PORT") or 8001,
        username=username,
        password=key,
        use_https=live_env.flag("SECURITYSPY_USE_HTTPS"),
        verify_ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
        timeout=15.0,
    )
    key_info = await key_client.async_get_server_info()

    assert set(key_info.cameras) == set(password_info.cameras), (
        "the key-authenticated account sees a different camera set than the "
        "password-authenticated one; the key does not carry exactly the "
        "account's camera-visibility permissions"
    )

    all_camera_numbers = range(max(password_info.cameras, default=-1) + 2)
    unpermitted = next((n for n in all_camera_numbers if n not in key_info.cameras), None)
    if unpermitted is None:
        pytest.skip("the PERCAM account can see every camera number the server has")

    with pytest.raises(SecuritySpyPermissionError):
        await key_client.async_get_camera_image(key_info, unpermitted)


# --- what each account can see ------------------------------------------------


@pytest.mark.parametrize("role", ["LIVE", "CAPTURES", "CONTROL", "ADMIN", "PERCAM"])
@pytest.mark.asyncio
async def test_live_permission_masks_decode_and_are_reported(
    session: aiohttp.ClientSession, role: str
) -> None:
    """Record the real per-camera mask for each rung of the permission ladder.

    This is the observation the offline fixtures were guessed from. It asserts
    only what must be true for the library to function -- that an account which
    can authenticate sees at least one camera and that every camera it sees
    grants live video -- and reports the rest, because the point is to learn the
    masks rather than to encode today's server into an assertion.
    """
    info = await _client(session, role).async_get_server_info()

    assert info.cameras, f"{role}: an authenticated account saw no cameras at all"
    for camera in info.cameras.values():
        names = sorted(camera.permission_names)
        _report(f"  {role} camera {camera.number}: mask={camera.permissions} -> {names}")
        # Live video is the visibility predicate, not merely a common grant --
        # see `test_live_inventory_is_scoped_to_live_video` for the measurement
        # and DW-5 for the decision that the library reports this rather than
        # working around it.
        assert camera.has_permission("live_video"), (
            f"{role} camera {camera.number} is in the inventory without live_video"
        )


@pytest.mark.asyncio
async def test_live_unnamed_bit_1_is_still_set_on_live_cameras(
    session: aiohttp.ClientSession,
) -> None:
    """Bit 1 (value 2) is set on live cameras and named in no published table.

    Recorded rather than asserted as required: if a future server stops setting
    it, that is information, not a regression. Decoding already ignores unknown
    bits, so nothing breaks either way.
    """
    info = await _client(session, "ADMIN").async_get_server_info()

    with_bit = [n for n, c in info.cameras.items() if c.permissions & UNNAMED_BIT_1]
    _report(f"  bit 1 set on {len(with_bit)}/{len(info.cameras)} cameras: {with_bit}")
    assert info.cameras


@pytest.mark.asyncio
async def test_live_inventory_is_scoped_to_live_video(
    session: aiohttp.ClientSession,
) -> None:
    """`++systemInfo` admits a camera only when the account holds live video on it.

    Measured on 6.21 with a per-camera-custom-permissions account holding a
    different single permission on each of eleven cameras: only the three
    granted "Get live video and images" appeared. Cameras granted PTZ control,
    trigger, set-camera-settings, capture download, capture deletion, PTZ
    presets or two-way audio were absent despite holding permissions the API
    honours.

    The project's decision (DW-5) is that this is the server's rule and the
    library reports it: live video is the prerequisite permission for a camera
    to be manageable at all, and NFR-9's least-privileged account must include
    it on every camera it is expected to cover. This test is what keeps that
    decision honest -- if a future server admits a camera without live video,
    the premise every consumer builds on has changed and this fails.
    """
    info = await _client(session, "PERCAM").async_get_server_info()
    if not info.cameras:
        pytest.skip("the per-camera account sees no cameras")

    without = [n for n, c in info.cameras.items() if not c.has_permission("live_video")]
    _report(
        f"  inventory admitted {len(info.cameras)} camera(s): {sorted(info.cameras)}; "
        f"{len(without)} lack live_video"
    )
    assert not without, (
        f"cameras {without} are in the inventory without live_video; the visibility "
        "predicate has changed and DW-5's decision needs revisiting"
    )


@pytest.mark.asyncio
async def test_live_permissions_vary_per_camera_within_one_account(
    session: aiohttp.ClientSession,
) -> None:
    """The library models permissions per camera, never collapsed to one account set.

    If the two named cameras come back with identical masks, the per-camera
    model is carrying weight it does not need -- which is a finding worth having
    before the integration builds entity gating on top of it.
    """
    full = live_env.get_int("SECURITYSPY_PERCAM_FULL_CAMERA")
    limited = live_env.get_int("SECURITYSPY_PERCAM_LIMITED_CAMERA")
    if full is None or limited is None:
        pytest.skip("SECURITYSPY_PERCAM_FULL_CAMERA/_LIMITED_CAMERA are not set")

    info = await _client(session, "PERCAM").async_get_server_info()
    masks = {number: camera.permissions for number, camera in info.cameras.items()}
    _report(f"  per-camera masks for the custom account: {masks}")

    assert full in masks, f"camera {full} is not visible to the per-camera account"
    assert masks[full] != masks.get(limited), (
        "the per-camera account reports identical masks for the camera configured with "
        "full rights and the one configured live-only; permissions may not in fact vary "
        "per camera, and the library's per-camera model should be revisited"
    )


@pytest.mark.asyncio
async def test_live_control_tier_reveals_whether_control_implies_schedule(
    session: aiohttp.ClientSession,
) -> None:
    """Report whether the "Live, Captures, Control" tier grants PERM_SCHED.

    The library treats camera control (64, PTZ and trigger) and schedule (128,
    arm and disarm) as independent permissions. If this tier grants one it must
    grant the other for that independence to be observable; if it bundles them,
    a consumer cannot offer PTZ without also offering arming, which changes what
    FR-28 entity gating can promise. Reported, not asserted either way.
    """
    info = await _client(session, "CONTROL").async_get_server_info()

    for camera in info.cameras.values():
        control = bool(camera.permissions & PERM_CAMCONTROL)
        schedule = bool(camera.permissions & PERM_SCHED)
        settings = bool(camera.permissions & PERM_SETTINGS)
        _report(
            f"  camera {camera.number}: camera_control={control} "
            f"schedule={schedule} settings={settings}"
        )
    assert info.cameras


# --- what a refused write actually returns (DW 1.6a) --------------------------


@pytest.mark.asyncio
async def test_live_arming_write_from_a_live_only_account_is_refused(
    session: aiohttp.ClientSession,
) -> None:
    """An effective arming write from an account without `schedule` must be refused.

    Verified against 6.21: the server answers such a write with **401**, not 403
    (research 5.9), and the disambiguating probe reclassifies it as a permission
    denial -- so a consumer does not open a reauth flow at a user whose password
    is fine. This is story 1.11 and 1.14 working end to end on a real server.
    """
    camera = _test_camera()
    client = _client(session, "LIVE")

    info = await client.async_get_server_info()
    visible = dict(info.cameras)
    if camera not in visible:
        pytest.skip(f"camera {camera} is not visible to the live-only account")
    assert not visible[camera].has_permission("schedule"), (
        "the account named by SECURITYSPY_LIVE_USER holds the schedule permission; "
        "it must be a 'Live' account for this test to mean anything"
    )

    # An *arming* override, never a disarming one: if enforcement were broken,
    # the camera would end up more armed rather than less.
    with pytest.raises(SecuritySpyPermissionError) as err:
        await client.async_set_camera_arming(
            camera, CaptureModes(motion=True), override=ARM_OVERRIDE_ARMED_1_HOUR
        )
    assert err.value.permission == "schedule"


@pytest.mark.asyncio
async def test_live_unchanged_override_is_a_no_op_the_server_accepts(
    session: aiohttp.ClientSession,
) -> None:
    """`override=ARM_OVERRIDE_UNCHANGED` succeeds even without the schedule permission.

    Not a permission bypass: -1 means "leave the existing override alone", and
    `mode` is a target selector rather than state to assign (story 1.16), so the
    call applies nothing and the server has nothing to authorize. It answers
    `200 OK` where the same call with a real override answers 401.

    Recorded because the asymmetry is surprising -- the same method, account and
    camera raises for one override and not another -- and because
    `async_set_camera_arming` already refuses the *other* way of producing an
    undetectable no-op (an empty mode set) with the reasoning "would return 200
    OK having done nothing". That guard has no twin for this case, so a caller
    can read success here as evidence of a permission it does not hold.
    """
    camera = _test_camera()
    client = _client(session, "LIVE")

    info = await client.async_get_server_info()
    if camera not in info.cameras:
        pytest.skip(f"camera {camera} is not visible to the live-only account")

    await client.async_set_camera_arming(
        camera, CaptureModes(motion=True), override=ARM_OVERRIDE_UNCHANGED
    )
    _report(f"  camera {camera}: override=UNCHANGED accepted without the schedule permission")


@pytest.mark.asyncio
async def test_live_settings_write_from_a_live_only_account_is_refused(
    session: aiohttp.ClientSession,
) -> None:
    """Same claim for the settings plane, which uses a different endpoint and verb."""
    camera = _test_camera()
    client = _client(session, "LIVE")

    with pytest.raises(SecuritySpyPermissionError) as err:
        await client.async_set_camera_settings(camera, CameraSettingsPatch(overlay_text="probe"))
    assert err.value.permission == "settings"


@pytest.mark.asyncio
async def test_live_media_fetch_from_a_live_only_account_is_a_permission_error(
    session: aiohttp.ClientSession,
) -> None:
    """Story 1.14's case, against the server that motivated it.

    A media 401 from an account without the Captures right must surface as a
    permission error, not an auth error -- otherwise a consumer opens a reauth
    dialog at a user whose password is perfectly fine.
    """
    client = _client(session, "LIVE")
    info = await client.async_get_server_info()
    if not info.cameras:
        pytest.skip("the live-only account sees no cameras")

    if info.utc_offset is None:
        pytest.skip("the server published no usable seconds-from-gmt offset")
    # An offset is not a timezone (story 1.13); this is the documented caller
    # pattern for turning the one the server publishes into the other.
    server_timezone = timezone(info.utc_offset)
    today = datetime.now(tz=server_timezone).date()
    captures = await client.async_get_captures(
        [next(iter(info.cameras))],
        start_date=today - timedelta(days=CAPTURE_LOOKBACK_DAYS),
        end_date=today,
        server_timezone=server_timezone,
    )
    if not captures:
        pytest.skip("no captures available to fetch")

    try:
        await client.async_get_capture_preview(captures[0])
    except SecuritySpyPermissionError:
        pass
    except SecuritySpyAuthError:
        pytest.fail(
            "a media denial for an account lacking the files permission surfaced as an "
            "authentication failure; a consumer would open a reauth flow at a user whose "
            "credentials are correct (story 1.14)"
        )


@pytest.mark.asyncio
async def test_live_camera_image_is_a_jpeg(
    session: aiohttp.ClientSession,
) -> None:
    """Story 1.20: ``++image`` answers a visible camera with a decodable JPEG."""
    camera = _test_camera()
    client = _client(session, "ADMIN")
    info = await client.async_get_server_info()
    if camera not in info.cameras:
        pytest.skip(f"camera {camera} is not visible to the admin account")

    image = await client.async_get_camera_image(info, camera)
    assert image.content_type.startswith("image/jpeg")
    assert image.data.startswith(b"\xff\xd8")
    _report(f"  camera {camera}: ++image returned {len(image.data)} bytes of {image.content_type}")


# --- writes that actually change the server (opt-in) --------------------------


@pytest.mark.asyncio
async def test_live_admin_arming_accepts_the_default_override(
    session: aiohttp.ClientSession,
) -> None:
    """Settle T10 -- whether ``override=-1`` is accepted on the wire.

    ``ARM_OVERRIDE_UNCHANGED`` (-1) is annotated in research §5.2 as a *client*
    sentinel, yet it is the default for ``async_set_camera_arming`` and is
    transmitted on every arming call that does not name an override. If the
    server rejects it, the most common arming call in the library depends on
    undocumented tolerance.

    ⚠️ **This test changes the server and does not promise to change it back.**
    An arming write's ``mode`` is a *target selector*, not the armed state being
    assigned (story 1.16), so re-sending the mode set that was read back does
    not restore anything -- and what a given ``override`` did is precisely what
    is not yet known. Rather than claim a restore it cannot make, this test
    reports the camera's capture modes before and after and leaves the operator
    to reset ``SECURITYSPY_TEST_CAMERA``. Point that variable at a camera whose
    arming state you do not mind perturbing.
    """
    if not live_env.flag("SECURITYSPY_ALLOW_WRITES"):
        pytest.skip("SECURITYSPY_ALLOW_WRITES is not set; this test arms a real camera")

    camera_number = _test_camera()
    client = _client(session, "ADMIN")

    before = _capture_modes_of(await client.async_get_server_info(), camera_number)
    if before is None:
        pytest.skip(f"camera {camera_number} is not visible to the admin account")

    # No `override=` argument: this is the defaulted call the ledger questions.
    await client.async_set_camera_arming(
        camera_number, CaptureModes(motion=True), override=ARM_OVERRIDE_UNCHANGED
    )

    after = _capture_modes_of(await client.async_get_server_info(), camera_number)
    _report(f"camera {camera_number}: capture modes before={before} after={after}")
    assert after is not None, "the camera vanished from the inventory after an arming write"


def _capture_modes_of(info: ServerInfo, number: int) -> CaptureModes | None:
    """Return the camera's decoded capture modes, or ``None`` when it is not visible."""
    for camera in info.cameras.values():
        if camera.number == number:
            return camera.capture_modes
    return None


# --- the RTSP relay -----------------------------------------------------------

#: Upper bound on one ffprobe run against the relay.
FFPROBE_SECONDS = 60


@pytest.mark.asyncio
async def test_live_relay_stream_decodes_through_ffprobe(session: aiohttp.ClientSession) -> None:
    """A relay ``stream_url`` opened by ffprobe on this host over TCP decodes video.

    The URL is never reported: it carries a relay identifier, which is access
    to the camera. Only the decoded stream types are.
    """
    ffprobe = shutil.which("ffprobe")
    if ffprobe is None:
        pytest.skip("ffprobe is not installed")
    client = _client(session, "LIVE")
    camera = _test_camera()
    info = await client.async_get_server_info()
    if info.rtsp_port is None:
        pytest.skip("the server is not serving RTSP")
    if camera not in info.cameras:
        pytest.skip("SECURITYSPY_TEST_CAMERA is not visible to the LIVE account")
    async with client.create_rtsp_relay(info) as relay:
        # `trace` makes ffprobe print every RTSP response it received, which is
        # what must carry no trace of SecuritySpy. The trace is asserted on,
        # never reported: it contains the relay identifier.
        process = await asyncio.create_subprocess_exec(
            ffprobe,
            "-loglevel",
            "trace",
            "-rtsp_transport",
            "tcp",
            "-show_entries",
            "stream=codec_name,codec_type",
            "-of",
            "csv=p=0",
            relay.stream_url(camera),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), FFPROBE_SECONDS)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
    streams = [line.split(",") for line in stdout.decode(errors="replace").split()]
    _report(f"relay streams: {streams}")
    assert process.returncode == 0
    assert any(len(fields) == 2 and fields[1] == "video" for fields in streams), streams  # noqa: PLR2004 - codec_name,codec_type
    trace = stderr.decode(errors="replace")
    assert client.host not in trace, "SecuritySpy's host reached the consumer"
    assert "auth=" not in trace
    assert "WWW-Authenticate" not in trace
