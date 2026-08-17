"""Settings, arming and permission decoding (story 1.6).

Self-contained by house rule: there is no ``conftest.py``, so the stub session
lives here. It records ``post`` as well as ``get``, because the settings write
is the library's first non-GET request and its *body* is the contract.
"""

from __future__ import annotations

import dataclasses
import json
from typing import TYPE_CHECKING, Any, Self, cast
from urllib.parse import unquote

import pytest

from aiosecurityspy import (
    ARM_OVERRIDE_ARMED_2_HOURS,
    ARM_OVERRIDE_ARMED_UNTIL_NEXT,
    ARM_OVERRIDE_NONE,
    ARM_OVERRIDE_UNCHANGED,
    ARM_OVERRIDES,
    PERM_AUDIORCV,
    PERM_AUDIOSND,
    PERM_CAMCONTROL,
    PERM_FILEDEL,
    PERM_FILES,
    PERM_LIVEVIDEO,
    PERM_PTZSET,
    PERM_SCHED,
    PERM_TRIGGER,
    ArmOverride,
    Camera,
    CameraSettings,
    CameraSettingsPatch,
    CaptureModes,
    SecuritySpyAuthError,
    SecuritySpyClient,
    SecuritySpyConnectError,
    SecuritySpyPermissionError,
    ServerInfo,
    arm_override,
    decode_permissions,
    decode_trigger_reasons,
    require_permission,
)

# Internal, deliberately: the parity test's whole point is that the two tables
# the public surface is generated *from* cannot drift apart.
from aiosecurityspy.models import (
    _PATCH_FIELD_ORDER,
    _SETTINGS_BOOL_KEYS,
    _SETTINGS_STR_FIELDS,
    SETTINGS_PAGE_KEYS,
)

if TYPE_CHECKING:
    from types import TracebackType

    import aiohttp

HOST = "nvr.example.com"
PORT = 8001
USERNAME = "sentinel-user-9d3f"
PASSWORD = "sentinel-pass-4a71"  # noqa: S105 - leak-detection sentinel, not a real credential

#: A settings payload shaped like the real one: curated keys the library models,
#: plus the plaintext device credentials research §8.3 warns about.
DEVICE_USERNAME = "device-user-77f1"
DEVICE_PASSWORD = "device-pass-22b9"  # noqa: S105 - leak-detection sentinel, not a real credential

#: Named so assertions do not trip PLR2004 on bare wire values.
CAMERA = 3
BRIGHTNESS = 50
OTHER_CAMERA = 4
MOTION_SENSITIVITY = 55
MOTION_SCHEDULE_ID = 2
MODE_COMBINATION_COUNT = 8
UNDOCUMENTED_OVERRIDE = 15
SECONDS_PER_HOUR = 3600
#: The per-camera permissions value research §9 records off a real server.
OBSERVED_PERMISSION_MASK = 10207


def settings_payload(**overrides: object) -> dict[str, object]:
    """Build a ``++settings-cameras`` body, credentials included."""
    payload: dict[str, object] = {
        "name": "Driveway",
        "overlayText": "Front Gate",
        "presenceRect": "10,20,30,40",
        "mcTriggerMotion": True,
        "mcTriggerMotionH": True,
        "mcTriggerMotionV": False,
        "mcTriggerMotionA": False,
        "mcTriggerAudio": False,
        "aTriggerMotion": True,
        "aTriggerMotionH": False,
        "aTriggerMotionV": False,
        "aTriggerMotionA": False,
        "ccMovie": False,
        "ccImage": False,
        "motionSensitivity": 55,
        "humanSensitivity": 60,
        "vehicleSensitivity": 65,
        "animalSensitivity": 70,
        "audioSensitivity": 40,
        "mcMoviePre": 5,
        "mcMoviePost": 30,
        "brightness": 128,
        "contrast": 100,
        # Never modelled, never retained:
        "username": DEVICE_USERNAME,
        "password": DEVICE_PASSWORD,
        "permissiveSsl": True,
        "aScript": "do-not-model.scpt",
        "aShellCommand": "/bin/echo do-not-model",
    }
    payload.update(overrides)
    return payload


class FakeContent:
    """Stand-in for ``response.content``, deliberately fragmented."""

    CHUNK = 64

    def __init__(self, raw: bytes) -> None:
        """Store the canned bytes."""
        self._raw = raw
        self._pos = 0

    async def read(self, limit: int = -1) -> bytes:
        """Return at most ``limit`` bytes from the current position."""
        take = len(self._raw) - self._pos if limit < 0 else min(limit, self.CHUNK)
        chunk = self._raw[self._pos : self._pos + take]
        self._pos += len(chunk)
        return chunk


class FakeResponse:
    """Minimal stand-in for an aiohttp response."""

    def __init__(self, status: int, body: str) -> None:
        """Store the canned status and body."""
        self.status = status
        self._raw = body.encode("utf-8")
        self.content = FakeContent(self._raw)

    @property
    def content_length(self) -> int | None:
        """The declared body length."""
        return len(self._raw)

    def get_encoding(self) -> str:
        """Return the charset the response declares."""
        return "utf-8"

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


class FakeSession:
    """Records every call, including the verb, and never closes itself."""

    def __init__(self, status: int = 200, body: str = "{}") -> None:
        """Configure the canned response every request receives."""
        self.status = status
        self.body = body
        self.closed = False
        #: ``(method, url, kwargs)`` per request, in order.
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Record a GET and return an async context manager."""
        return self._record("GET", url, kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401 - mirrors aiohttp's own signature
        """Record a POST and return an async context manager."""
        return self._record("POST", url, kwargs)

    #: Overridden by tests exercising a write receipt the declared encoding
    #: cannot decode. A *write* must not be reported as failed because its
    #: receipt -- whose content the library discards -- was malformed.
    response_factory: type[FakeResponse] = FakeResponse

    def _record(self, method: str, url: str, kwargs: dict[str, Any]) -> FakeResponse:
        """Append the call and build the canned response."""
        self.calls.append((method, url, kwargs))
        return self.response_factory(self.status, self.body)

    async def close(self) -> None:  # pragma: no cover - must never be called
        """Mark the session closed; the library must never reach this."""
        self.closed = True


class SettingsServer(FakeSession):
    """A stateful fake that applies **only** the keys a write actually posts.

    This is what makes the partial-write claim testable: a server that
    re-derived the whole page from the body would pass a read-modify-write
    implementation just as happily.
    """

    def __init__(self, state: dict[str, object]) -> None:
        """Start holding the given settings page."""
        super().__init__()
        self.state = dict(state)

    def _record(self, method: str, url: str, kwargs: dict[str, Any]) -> FakeResponse:
        """Serve a read from state, or apply a write to it."""
        self.calls.append((method, url, kwargs))
        if method == "POST":
            for key, value in decode_form_body(cast("bytes", kwargs["data"]).decode()).items():
                if key != "cameraNum":
                    self.state[key] = value
            return FakeResponse(200, json.dumps({"camUpdate": {"num": "3"}}))
        return FakeResponse(200, json.dumps(self.state))


def decode_form_body(body: str) -> dict[str, str]:
    """Split a posted body into fields, asserting the sentinel came first.

    Values are decoded with :func:`~urllib.parse.unquote`, not ``unquote_plus``:
    the library percent-encodes like ``encodeURIComponent`` (research §8.0), so
    a ``+`` in a decoded value is a *literal* plus that was sent as ``%2B``, not
    an encoded space.
    """
    parts = body.split("&")
    assert parts[0] == "formData", "the body must open with the literal sentinel"
    return {key: unquote(value) for key, _, value in (part.partition("=") for part in parts[1:])}


def make_client(session: FakeSession) -> SecuritySpyClient:
    return SecuritySpyClient(
        cast("aiohttp.ClientSession", session),
        HOST,
        PORT,
        username=USERNAME,
        password=PASSWORD,
    )


def camera(number: int = 3, permissions: int = 0) -> Camera:
    return Camera(number=number, name="Gate", connected=True, enabled=True, permissions=permissions)


# --- reading settings --------------------------------------------------------


@pytest.mark.asyncio
async def test_read_settings_issues_the_documented_request_and_types_the_result() -> None:
    session = FakeSession(body=json.dumps(settings_payload()))
    settings = await make_client(session).async_get_camera_settings(3)

    method, url, kwargs = session.calls[0]
    assert method == "GET"
    assert url == f"http://{HOST}:{PORT}/++settings-cameras"
    assert kwargs["params"] == {"cameraNum": "3", "format": "json"}
    assert isinstance(settings, CameraSettings)
    assert settings.camera_number == CAMERA
    assert settings.name == "Driveway"
    assert settings.overlay_text == "Front Gate"
    assert settings.motion_sensitivity == MOTION_SENSITIVITY
    assert settings.presence_rect == "10,20,30,40"


@pytest.mark.asyncio
async def test_boolean_read_encoding_decodes_json_true_and_false() -> None:
    session = FakeSession(body=json.dumps(settings_payload(mcTriggerMotionH=True, ccMovie=False)))
    settings = await make_client(session).async_get_camera_settings(3)

    assert settings.motion_capture_triggers_human is True
    assert settings.continuous_capture_movie is False


@pytest.mark.asyncio
async def test_unrecognised_boolean_token_uses_the_default_without_raising() -> None:
    session = FakeSession(body=json.dumps(settings_payload(mcTriggerMotionH=["nonsense"])))
    settings = await make_client(session).async_get_camera_settings(3)

    assert settings.motion_capture_triggers_human is False


@pytest.mark.asyncio
async def test_settings_never_retain_or_print_device_credentials() -> None:
    session = FakeSession(body=json.dumps(settings_payload()))
    settings = await make_client(session).async_get_camera_settings(3)

    haystack = " ".join(
        [repr(settings), str(settings), *[repr(getattr(settings, name)) for name in dir(settings)]]
    )
    for secret in (DEVICE_USERNAME, DEVICE_PASSWORD, "do-not-model.scpt", "/bin/echo do-not-model"):
        assert secret not in haystack
    assert not hasattr(settings, "username")
    assert not hasattr(settings, "password")
    assert not hasattr(settings, "raw")


@pytest.mark.asyncio
async def test_non_object_settings_body_is_a_typed_connect_error() -> None:
    session = FakeSession(body=json.dumps([1, 2, 3]))
    with pytest.raises(SecuritySpyConnectError, match="not a settings object"):
        await make_client(session).async_get_camera_settings(3)


@pytest.mark.asyncio
async def test_non_json_settings_body_is_a_typed_connect_error() -> None:
    session = FakeSession(body="<html>not securityspy</html>")
    with pytest.raises(SecuritySpyConnectError, match="not valid JSON"):
        await make_client(session).async_get_camera_settings(3)


# --- writing settings --------------------------------------------------------


@pytest.mark.asyncio
async def test_write_one_field_sends_the_byte_exact_sentinel_body() -> None:
    session = FakeSession()
    await make_client(session).async_set_camera_settings(
        3, CameraSettingsPatch(overlay_text="Front Gate")
    )

    method, url, kwargs = session.calls[0]
    assert method == "POST"
    assert url == f"http://{HOST}:{PORT}/++settings-cameras"
    assert kwargs["params"] == {}, "the query form of this endpoint returns 404"
    assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert kwargs["data"] == b"formData&cameraNum=3&overlayText=Front%20Gate", (
        "research §8.0's observed body percent-encodes the space; `+` would be quote_plus"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        ("Front Gate", "Front%20Gate"),
        ("a&b", "a%26b"),
        ("a=b", "a%3Db"),
        ("a+b", "a%2Bb"),
        ("100%", "100%25"),
        ("Grüße", "Gr%C3%BC%C3%9Fe"),
        ("front/back", "front%2Fback"),
        ("a b&c=d+e%f", "a%20b%26c%3Dd%2Be%25f"),
    ],
)
async def test_reserved_characters_are_percent_encoded_like_encodeuricomponent(
    value: str, encoded: str
) -> None:
    """Every reserved byte is escaped, and a literal ``+`` survives as ``%2B``.

    ``quote_plus`` would send ``Front+Gate``; research §8.0's observed body is
    ``Front%20Gate``. It also matters for safety: an unescaped ``&`` or ``=`` in
    a camera name would forge a field separator and write a key the caller never
    asked for.
    """
    session = FakeSession()
    await make_client(session).async_set_camera_settings(3, CameraSettingsPatch(overlay_text=value))

    body = cast("bytes", session.calls[0][2]["data"]).decode()
    assert body == f"formData&cameraNum=3&overlayText={encoded}"
    assert body.isascii(), "a non-ASCII byte must never reach the wire unencoded"
    # The body still splits into exactly the two fields that were meant.
    assert decode_form_body(body) == {"cameraNum": "3", "overlayText": value}


@pytest.mark.asyncio
async def test_write_body_starts_with_the_sentinel_and_then_the_camera_number() -> None:
    session = FakeSession()
    await make_client(session).async_set_camera_settings(7, CameraSettingsPatch(brightness=200))

    body = cast("bytes", session.calls[0][2]["data"]).decode()
    assert body.startswith("formData&cameraNum=7&")


@pytest.mark.asyncio
async def test_boolean_write_encoding_renders_one_and_zero() -> None:
    session = FakeSession()
    await make_client(session).async_set_camera_settings(
        3,
        CameraSettingsPatch(
            motion_capture_triggers_human=True, motion_capture_triggers_vehicle=False
        ),
    )

    body = cast("bytes", session.calls[0][2]["data"]).decode()
    assert body == "formData&cameraNum=3&mcTriggerMotionH=1&mcTriggerMotionV=0"


def test_patch_form_fields_is_the_only_place_that_knows_one_and_zero() -> None:
    fields = CameraSettingsPatch(
        continuous_capture_movie=True, continuous_capture_image=False
    ).form_fields()
    assert fields == {"ccMovie": "1", "ccImage": "0"}


def test_empty_patch_raises_before_anything_is_rendered() -> None:
    with pytest.raises(ValueError, match="patch is empty"):
        CameraSettingsPatch().form_fields()


@pytest.mark.asyncio
async def test_empty_patch_issues_no_request() -> None:
    session = FakeSession()
    with pytest.raises(ValueError, match="patch is empty"):
        await make_client(session).async_set_camera_settings(3, CameraSettingsPatch())
    assert session.calls == []


@pytest.mark.asyncio
async def test_partial_write_leaves_every_other_field_identical() -> None:
    session = SettingsServer(settings_payload())
    client = make_client(session)

    before = await client.async_get_camera_settings(3)
    await client.async_set_camera_settings(3, CameraSettingsPatch(overlay_text="Back Gate"))
    after = await client.async_get_camera_settings(3)

    assert before.overlay_text == "Front Gate"
    assert after.overlay_text == "Back Gate"
    changed = {
        name
        for name in vars(CameraSettings)["__dataclass_fields__"]
        if getattr(before, name) != getattr(after, name)
    }
    assert changed == {"overlay_text"}
    # The untouched credentials are still on the server, and still never modelled.
    assert session.state["username"] == DEVICE_USERNAME


@pytest.mark.asyncio
async def test_write_posts_only_the_changed_keys() -> None:
    session = SettingsServer(settings_payload())
    await make_client(session).async_set_camera_settings(
        3, CameraSettingsPatch(motion_sensitivity=80)
    )

    posted = decode_form_body(cast("bytes", session.calls[0][2]["data"]).decode())
    assert posted == {"cameraNum": "3", "motionSensitivity": "80"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected"),
    [(401, SecuritySpyAuthError), (403, SecuritySpyAuthError), (500, SecuritySpyConnectError)],
)
async def test_rejected_write_maps_to_a_typed_error_without_echoing_the_body(
    status: int, expected: type[Exception]
) -> None:
    session = FakeSession(status=status, body=json.dumps({"secret": DEVICE_PASSWORD}))
    with pytest.raises(expected) as err:
        await make_client(session).async_set_camera_settings(
            3, CameraSettingsPatch(overlay_text="x")
        )
    assert DEVICE_PASSWORD not in str(err.value)


@pytest.mark.asyncio
async def test_rejected_read_maps_to_a_typed_error_without_echoing_the_body() -> None:
    session = FakeSession(status=401, body=json.dumps({"password": DEVICE_PASSWORD}))
    with pytest.raises(SecuritySpyAuthError) as err:
        await make_client(session).async_get_camera_settings(3)
    assert DEVICE_PASSWORD not in str(err.value)


@pytest.mark.asyncio
async def test_settings_payload_is_never_logged_at_any_level(
    caplog: pytest.LogCaptureFixture,
) -> None:
    session = SettingsServer(settings_payload())
    with caplog.at_level(0, logger="aiosecurityspy"):
        client = make_client(session)
        await client.async_get_camera_settings(3)
        await client.async_set_camera_settings(3, CameraSettingsPatch(overlay_text="Front Gate"))

    text = caplog.text
    for secret in (DEVICE_USERNAME, DEVICE_PASSWORD, "Driveway", "Front Gate"):
        assert secret not in text


# --- arming ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_arming_all_three_modes_sends_cma() -> None:
    session = FakeSession(body="OK")
    await make_client(session).async_set_camera_arming(
        3, CaptureModes(continuous=True, motion=True, actions=True)
    )

    method, url, kwargs = session.calls[0]
    assert method == "GET"
    assert url == f"http://{HOST}:{PORT}/++ssSetSchedule"
    assert kwargs["params"]["mode"] == "CMA"


@pytest.mark.asyncio
async def test_arming_none_sends_an_empty_but_present_mode() -> None:
    session = FakeSession(body="OK")
    await make_client(session).async_set_camera_arming(
        3,
        CaptureModes(False, False, False),  # noqa: FBT003 - the positional all-false form must stay expressible
    )

    params = session.calls[0][2]["params"]
    assert "mode" in params
    assert params["mode"] == ""


@pytest.mark.parametrize(
    ("continuous", "motion", "actions", "expected"),
    [
        (False, False, False, ""),
        (False, False, True, "A"),
        (False, True, False, "M"),
        (False, True, True, "MA"),
        (True, False, False, "C"),
        (True, False, True, "CA"),
        (True, True, False, "CM"),
        (True, True, True, "CMA"),
    ],
)
def test_all_eight_mode_combinations_are_distinct_and_ordered(
    *, continuous: bool, motion: bool, actions: bool, expected: str
) -> None:
    modes = CaptureModes(continuous=continuous, motion=motion, actions=actions)
    assert modes.mode_string == expected


def test_the_eight_mode_strings_are_all_different() -> None:
    strings = {
        CaptureModes(continuous=c, motion=m, actions=a).mode_string
        for c in (False, True)
        for m in (False, True)
        for a in (False, True)
    }
    assert len(strings) == MODE_COMBINATION_COUNT


@pytest.mark.asyncio
async def test_arming_never_sends_a_schedule_parameter() -> None:
    session = FakeSession(body="OK")
    client = make_client(session)
    await client.async_set_camera_arming(3, CaptureModes(motion=True))
    await client.async_set_camera_arming(
        4, CaptureModes(continuous=True), override=ARM_OVERRIDE_ARMED_2_HOURS
    )

    for _, url, kwargs in session.calls:
        assert set(kwargs["params"]) == {"cameraNum", "mode", "override"}
        assert "schedule" not in url
        assert "schedule" not in kwargs["params"]


@pytest.mark.asyncio
async def test_arming_defaults_to_the_unchanged_override() -> None:
    session = FakeSession(body="OK")
    await make_client(session).async_set_camera_arming(3, CaptureModes(motion=True))
    assert session.calls[0][2]["params"]["override"] == "-1"


@pytest.mark.asyncio
async def test_arming_accepts_a_typed_override_record() -> None:
    session = FakeSession(body="OK")
    await make_client(session).async_set_camera_arming(
        3, CaptureModes(motion=True), override=arm_override(ARM_OVERRIDE_ARMED_2_HOURS)
    )
    assert session.calls[0][2]["params"]["override"] == "6"


@pytest.mark.asyncio
async def test_undocumented_override_is_refused_before_any_request() -> None:
    session = FakeSession(body="OK")
    with pytest.raises(ValueError, match="ARM_OVERRIDE"):
        await make_client(session).async_set_camera_arming(3, CaptureModes(), override=15)
    assert session.calls == []


# --- the override table ------------------------------------------------------


def test_bounded_override_carries_its_duration_and_label() -> None:
    record = arm_override(6)
    assert isinstance(record, ArmOverride)
    assert record.armed is True
    assert record.duration is not None
    assert record.duration.total_seconds() == 2 * SECONDS_PER_HOUR
    assert record.label == "Armed For 2 Hours"
    assert record.until_next_scheduled is False


def test_until_next_scheduled_override_has_no_duration() -> None:
    record = arm_override(ARM_OVERRIDE_ARMED_UNTIL_NEXT)
    assert record.armed is True
    assert record.duration is None
    assert record.until_next_scheduled is True


@pytest.mark.parametrize("value", [ARM_OVERRIDE_UNCHANGED, ARM_OVERRIDE_NONE])
def test_non_arming_overrides_report_no_arm_state_and_no_duration(value: int) -> None:
    record = arm_override(value)
    assert record.armed is None
    assert record.duration is None
    assert record.until_next_scheduled is False


def test_the_override_table_is_exactly_the_published_range() -> None:
    assert set(ARM_OVERRIDES) == set(range(-1, 15))
    assert UNDOCUMENTED_OVERRIDE not in ARM_OVERRIDES, "15 is undocumented; do not invent it"


@pytest.mark.parametrize("value", [15, -2, 99, True, "6", 2.0, None])
def test_unknown_override_values_raise_value_error(value: object) -> None:
    with pytest.raises(ValueError, match="ARM_OVERRIDE"):
        arm_override(cast("int", value))


# --- arm state read off ++systemInfo ----------------------------------------


def test_camera_decodes_capture_modes_and_schedules() -> None:
    info = ServerInfo.from_api(
        {
            "system": {
                "server": {"uuid": "u", "version": "6.20", "camera-count": "1"},
                "cameralist": {
                    "camera": [
                        {
                            "number": "3",
                            "name": "Gate",
                            "mc-mode": "armed",
                            "cc-mode": "disarmed",
                            "a-mode": 1,
                            "cc-schedule-id": "0",
                            "mc-schedule-id": "2",
                            "mc-schedule-override": "6",
                        }
                    ]
                },
            }
        }
    )
    decoded = info.cameras[3]

    assert decoded.capture_modes == CaptureModes(continuous=False, motion=True, actions=True)
    assert decoded.capture_modes.mode_string == "MA"
    assert decoded.schedules.continuous_schedule_id == 0
    assert decoded.schedules.motion_schedule_id == MOTION_SCHEDULE_ID
    assert decoded.schedules.motion_override == ARM_OVERRIDE_ARMED_2_HOURS
    # Absent fields are defaults, never zero standing in for "unset".
    assert decoded.schedules.actions_schedule_id is None
    assert decoded.schedules.continuous_override is None


def test_camera_without_arm_fields_defaults_to_disarmed_and_none() -> None:
    decoded = Camera.from_api({"number": "1"})
    assert decoded is not None
    assert decoded.capture_modes == CaptureModes()
    assert decoded.capture_modes.mode_string == ""
    assert decoded.schedules.motion_schedule_id is None


# --- permissions and trigger reasons ----------------------------------------


def test_permission_decode_of_the_observed_mask() -> None:
    """Research §9's observed mask, decoded bit by bit.

    Note the reference's prose gloss of 10207 lists AUDIOSND, but bit 11
    (2048) is *not* set in 10207 while bit 8 (PTZSET) is. The bits are the
    contract; the prose is not, so this asserts the arithmetic.
    """
    assert decode_permissions(OBSERVED_PERMISSION_MASK) == frozenset(
        {
            "live_video",
            "files",
            "file_delete",
            "camera_control",
            "schedule",
            "ptz_preset_set",
            "audio_receive",
            "trigger",
        }
    )
    observed = (
        PERM_LIVEVIDEO
        | PERM_FILES
        | PERM_FILEDEL
        | PERM_CAMCONTROL
        | PERM_SCHED
        | PERM_PTZSET
        | PERM_AUDIORCV
        | PERM_TRIGGER
    )
    assert decode_permissions(OBSERVED_PERMISSION_MASK) == decode_permissions(observed)
    assert not decode_permissions(OBSERVED_PERMISSION_MASK) & {"audio_send"}
    assert PERM_AUDIOSND & OBSERVED_PERMISSION_MASK == 0


@pytest.mark.parametrize("mask", [0, -1, -OBSERVED_PERMISSION_MASK, "10207", None, True, 2.5])
def test_absent_negative_or_non_int_permissions_decode_to_nothing(mask: object) -> None:
    assert decode_permissions(cast("int", mask)) == frozenset()


def test_undocumented_permission_bits_are_ignored_rather_than_rejected() -> None:
    # Bits 1, 4, 5 and 12+ are undecoded; they must simply not appear.
    assert decode_permissions(1 | 2 | 16 | 32 | (1 << 20)) == frozenset({"live_video"})


def test_trigger_reasons_on_a_default_install() -> None:
    assert decode_trigger_reasons(1) == frozenset({"video_motion"})


def test_disabled_trigger_reason_bits_are_simply_absent() -> None:
    # Bits 7-16 only fire when the mcTriggerMotionH/V/A settings are enabled.
    reasons = decode_trigger_reasons(1)
    assert "human_movement" not in reasons
    assert "vehicle_movement" not in reasons


def test_require_permission_raises_naming_the_permission_and_camera() -> None:
    without = camera(number=OTHER_CAMERA, permissions=PERM_LIVEVIDEO)
    with pytest.raises(SecuritySpyPermissionError) as err:
        require_permission(without, "schedule")
    assert err.value.permission == "schedule"
    assert err.value.camera_number == OTHER_CAMERA
    assert "schedule" in str(err.value)
    assert f"camera {OTHER_CAMERA}" in str(err.value)


def test_require_permission_is_silent_when_the_bit_is_granted() -> None:
    require_permission(camera(permissions=PERM_SCHED), "schedule")


def test_require_permission_leaks_no_credential() -> None:
    with pytest.raises(SecuritySpyPermissionError) as err:
        require_permission(camera(permissions=0), "schedule")
    assert PASSWORD not in str(err.value)
    assert PASSWORD not in repr(err.value)


# --- caller mistakes ---------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("number", [-1, True, "3", 2.0, None])
async def test_bad_camera_number_is_refused_by_every_new_method(number: object) -> None:
    session = FakeSession()
    client = make_client(session)
    bad = cast("int", number)

    with pytest.raises(ValueError, match="camera numbers must be non-negative"):
        await client.async_get_camera_settings(bad)
    with pytest.raises(ValueError, match="camera numbers must be non-negative"):
        await client.async_set_camera_settings(bad, CameraSettingsPatch(brightness=1))
    with pytest.raises(ValueError, match="camera numbers must be non-negative"):
        await client.async_set_camera_arming(bad, CaptureModes())

    assert session.calls == []


def test_camera_zero_is_a_legal_camera_number() -> None:
    assert CameraSettings.from_api({}, camera_number=0).camera_number == 0


# --- reprs -------------------------------------------------------------------


def test_new_model_reprs_are_informative_and_credential_free() -> None:
    assert "CaptureModes(continuous=True" in repr(CaptureModes(continuous=True))
    assert "CameraScheduleAssignment(" in repr(Camera.from_api({"number": "1"}).schedules)  # type: ignore[union-attr]
    assert repr(arm_override(6)).startswith("ArmOverride(value=6")
    assert repr(CameraSettings(camera_number=3)) == "CameraSettings(camera_number=3)"
    patch = CameraSettingsPatch(overlay_text="Front Gate", brightness=10)
    assert "Front Gate" not in repr(patch)
    assert "overlay_text" in repr(patch)
    assert "brightness" in repr(patch)


# --- review regressions (spec 1.6 review pass) --------------------------------


@pytest.mark.asyncio
async def test_a_hand_built_override_record_is_validated_like_a_bare_int() -> None:
    """A forged `ArmOverride` must not reach the wire.

    `ArmOverride` is public and freely constructible, so the typed door needs
    the same lock as the int one: `arm_override(15)` raises, and so must an
    `ArmOverride(value=15, ...)` handed straight to the client.
    """
    session = FakeSession()
    client = make_client(session)
    forged = ArmOverride(
        value=UNDOCUMENTED_OVERRIDE,
        label="invented",
        armed=True,
        duration=None,
        until_next_scheduled=False,
    )
    with pytest.raises(ValueError, match="override"):
        await client.async_set_camera_arming(CAMERA, CaptureModes(motion=True), override=forged)
    assert session.calls == []


@pytest.mark.asyncio
async def test_a_valid_override_record_still_passes_through_unchanged() -> None:
    """Validating the typed branch must not close it."""
    session = FakeSession()
    client = make_client(session)
    await client.async_set_camera_arming(
        CAMERA, CaptureModes(motion=True), override=arm_override(ARM_OVERRIDE_ARMED_2_HOURS)
    )
    assert session.calls[0][2]["params"]["override"] == str(ARM_OVERRIDE_ARMED_2_HOURS)


def test_a_bool_in_a_string_field_is_not_rendered_as_one_or_zero() -> None:
    """The write encoding follows the field's declaration, not the value.

    `bool` is a subclass of `int` and reads as one to every runtime check, so a
    type-check-first renderer silently renames the camera to "1".
    """
    misdeclared: Any = True
    assert CameraSettingsPatch(name=misdeclared).form_fields() == {"name": "True"}
    assert CameraSettingsPatch(motion_capture_triggers_human=True).form_fields() == {
        "mcTriggerMotionH": "1"
    }


@pytest.mark.asyncio
async def test_a_json_object_that_is_not_a_settings_page_is_refused() -> None:
    """An empty or unrelated object is not a settings page.

    It would otherwise decode to an all-default `CameraSettings` that reads
    exactly like a genuinely configured camera.
    """
    for body in ("{}", json.dumps({"error": "nope"})):
        session = FakeSession(body=body)
        client = make_client(session)
        with pytest.raises(SecuritySpyConnectError, match="not a settings object"):
            await client.async_get_camera_settings(CAMERA)


@pytest.mark.asyncio
async def test_no_frame_local_holds_the_settings_payload_when_the_decode_fails() -> None:
    """The raw page carries the device password in plaintext.

    Dropping it from the returned model is not enough: a traceback renderer
    such as Sentry or ``pytest --showlocals`` prints frame locals verbatim.
    """
    session = FakeSession(body=json.dumps({"password": DEVICE_PASSWORD}))
    client = make_client(session)
    with pytest.raises(SecuritySpyConnectError) as caught:
        await client.async_get_camera_settings(CAMERA)
    frames: list[dict[str, object]] = []
    traceback = caught.value.__traceback__
    while traceback is not None:
        frames.append(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert DEVICE_PASSWORD not in repr(frames)


def test_an_unknown_permission_name_is_a_caller_error_not_a_denial() -> None:
    """A misspelling can never be granted by any camera.

    Treating it as a permission failure would mask a caller bug as a server one.
    """
    camera = Camera(number=1, name="c", connected=True, enabled=True, permissions=0xFFFF)
    with pytest.raises(ValueError, match="unknown permission name"):
        require_permission(camera, "schedul")
    require_permission(camera, "schedule")


def test_an_unrecognised_arm_mode_token_is_reported(caplog: pytest.LogCaptureFixture) -> None:
    """An unrecorded arm-mode spelling must be discoverable.

    Guessing "disarmed" silently is the wrong way to be wrong on a security
    product, and research §10 does not record the field's wire spelling.
    """
    with caplog.at_level("DEBUG", logger="aiosecurityspy.models"):
        camera = Camera.from_api({"number": "1", "mc-mode": "enabled"})
    assert camera is not None
    assert camera.capture_modes.motion is False
    assert "enabled" in caplog.text


def test_a_cleared_string_setting_stays_distinct_from_an_absent_one() -> None:
    """Cleared and absent are different states, and only the first is writable."""
    cleared = CameraSettings.from_api({"name": "cam", "overlayText": ""}, camera_number=CAMERA)
    absent = CameraSettings.from_api({"name": "cam"}, camera_number=CAMERA)
    assert cleared.overlay_text == ""
    assert absent.overlay_text is None


def test_the_read_allowlist_and_the_write_field_tables_agree() -> None:
    """The credential-safety argument rests on one allowlist.

    Two hand-kept lists that no test compares will drift the first time a field
    is added to one of them.
    """
    decoded = {
        field.name for field in dataclasses.fields(CameraSettings) if field.name != "camera_number"
    }
    writable = {field.name for field in dataclasses.fields(CameraSettingsPatch)}
    assert decoded == writable
    assert {key for _, key in _PATCH_FIELD_ORDER} == SETTINGS_PAGE_KEYS
    assert {attribute for attribute, _ in _PATCH_FIELD_ORDER} == writable


def test_from_api_reads_each_field_from_the_wire_key_the_tables_declare() -> None:
    """`from_api` restates the attribute-to-wire-key pairing by hand.

    The set-equality parity test above cannot see a *swap*: exchanging
    ``humanSensitivity`` and ``vehicleSensitivity`` inside `from_api` keeps both
    sets identical while `human_sensitivity` silently reports the vehicle
    threshold -- and a consumer who round-trips read-then-patch writes the
    wrong value back to the camera. Giving every key a distinct sentinel value
    pins the pairing itself, not just the vocabulary.
    """
    payload: dict[str, object] = {}
    expected: dict[str, object] = {}
    for index, (attribute, key) in enumerate(_PATCH_FIELD_ORDER):
        if key in _SETTINGS_BOOL_KEYS:
            # Booleans cannot be made distinct, so alternate them: a swap
            # between two bool fields still shows up as a mismatch.
            value: object = index % 2 == 0
        elif any(attribute == name for name, _ in _SETTINGS_STR_FIELDS):
            value = f"sentinel-{index}"
        else:
            value = index + 1
        payload[key] = value
        expected[attribute] = value

    settings = CameraSettings.from_api(payload, camera_number=CAMERA)
    for attribute, value in expected.items():
        assert getattr(settings, attribute) == value, attribute


@pytest.mark.asyncio
async def test_a_body_sharing_one_ordinary_key_is_not_a_settings_page() -> None:
    """One overlapping key is not evidence.

    ``name``, ``brightness`` and ``contrast`` are ordinary words, so a
    reverse-proxy error page or a wrong-endpoint body clears a one-key test and
    decodes to a camera reporting every trigger `False` and every sensitivity
    `None` -- indistinguishable from a camera whose detection is genuinely all
    switched off.
    """
    for body in (
        {"name": "some other API", "error": "camera not found"},
        {"brightness": 50},
        {"name": "x", "contrast": 10},  # two keys: still short of the quorum
    ):
        session = FakeSession(body=json.dumps(body))
        client = make_client(session)
        with pytest.raises(SecuritySpyConnectError, match="not a settings object"):
            await client.async_get_camera_settings(CAMERA)


@pytest.mark.asyncio
async def test_a_body_meeting_the_key_quorum_is_accepted() -> None:
    """The quorum must not reject a page that is genuinely a settings page."""
    session = FakeSession(
        body=json.dumps({"name": "Front Gate", "brightness": BRIGHTNESS, "contrast": 10})
    )
    client = make_client(session)
    settings = await client.async_get_camera_settings(CAMERA)
    assert settings.name == "Front Gate"
    assert settings.brightness == BRIGHTNESS


@pytest.mark.asyncio
async def test_no_frame_local_holds_the_payload_when_the_decode_itself_raises() -> None:
    """The scrub must hold on *every* exit, not the branches we expect.

    A raise from inside `from_api` leaves a frame whose locals still bind the
    plaintext device password, which is exactly what the refusal branch's
    `del` was written to prevent on the other path.
    """
    # Built inline: this test's own frame is in the traceback too, so a local
    # holding the page would fail the assertion for the wrong reason.
    session = FakeSession(
        body=json.dumps(
            {key: DEVICE_PASSWORD for _, key in _PATCH_FIELD_ORDER} | {"password": DEVICE_PASSWORD}
        )
    )
    client = make_client(session)

    boom = RuntimeError("decode exploded")

    def explode(*_args: object, **_kwargs: object) -> CameraSettings:
        raise boom

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(CameraSettings, "from_api", explode)
        with pytest.raises(RuntimeError, match="decode exploded") as caught:
            await client.async_get_camera_settings(CAMERA)

    # Only the library's own frames are the subject: the injected `explode`
    # receives the page as an argument, so its frame holds it by construction --
    # that is the test double, not the code under test.
    traceback = caught.value.__traceback__
    checked = 0
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_globals.get("__name__", "").startswith("aiosecurityspy."):
            assert DEVICE_PASSWORD not in repr(frame.f_locals), frame.f_code.co_name
            checked += 1
        traceback = traceback.tb_next
    assert checked, "the client's own frame was never inspected"


class _BogusCharsetResponse(FakeResponse):
    """A receipt declaring a charset Python does not know."""

    def get_encoding(self) -> str:
        """Declare an unknown charset, as a misconfigured server would."""
        return "definitely-not-a-charset"


class _UndecodableResponse(FakeResponse):
    """A receipt whose bytes are not valid under its declared charset."""

    def __init__(self, status: int, body: str) -> None:
        """Replace the encoded body with bytes UTF-8 cannot decode."""
        super().__init__(status, body)
        self._raw = b"\xff\xfe not utf-8"
        self.content = FakeContent(self._raw)


@pytest.mark.parametrize(
    "factory",
    [_BogusCharsetResponse, _UndecodableResponse],
    ids=["unknown-charset", "undecodable-bytes"],
)
@pytest.mark.asyncio
async def test_a_malformed_write_receipt_does_not_fail_the_write(
    factory: type[FakeResponse],
) -> None:
    """A write that the server accepted must not be reported as a failure.

    Reads decode strictly, because a body the library is about to parse has to
    be trustworthy. A *write receipt* is discarded, so an unknown charset or
    undecodable bytes on the way back say nothing about whether the write
    landed -- and raising there would turn a successful write into a spurious
    error, which is the more damaging way to be wrong.
    """
    session = FakeSession(body='{"camUpdate": {"num": "3"}}')
    session.response_factory = factory
    client = make_client(session)

    await client.async_set_camera_settings(CAMERA, CameraSettingsPatch(overlay_text="Front Gate"))
    await client.async_set_camera_arming(CAMERA, CaptureModes(motion=True))

    assert [method for method, _, _ in session.calls] == ["POST", "GET"]


class _MidStreamFailureResponse(FakeResponse):
    """A receipt whose body drops the connection partway through the read."""

    def __init__(self, status: int, body: str) -> None:
        """Serve one credential-bearing chunk, then fail."""
        super().__init__(status, body)
        self.content = _FailingContent(body.encode())


class _FailingContent(FakeContent):
    """Yields the payload once, then raises as a dropped socket would."""

    def __init__(self, raw: bytes) -> None:
        """Track whether the first chunk has been served."""
        super().__init__(raw)
        self._served = False

    async def read(self, limit: int = -1) -> bytes:  # noqa: ARG002 - mirrors FakeContent.read
        """Return the whole payload once, then raise."""
        if self._served:
            message = "connection reset while reading the body"
            raise ConnectionResetError(message)
        self._served = True
        return self._raw


@pytest.mark.asyncio
async def test_the_transport_frame_holds_no_payload_when_the_read_itself_fails() -> None:
    """The scrub has to reach the frame that actually holds the bytes.

    `async_get_camera_settings` scrubs its own locals, but it is a frame away
    from `_request`, which is where `chunks` and `raw` bind the whole settings
    page -- credentials included -- and where a mid-read transport failure
    raises from. Without the `finally` in `_request` those locals survive into
    the traceback, and the caller-level scrub cannot see them.
    """
    session = FakeSession(body=json.dumps(settings_payload()))
    session.response_factory = _MidStreamFailureResponse
    client = make_client(session)

    with pytest.raises(SecuritySpyConnectError) as caught:
        await client.async_get_camera_settings(CAMERA)

    traceback = caught.value.__traceback__
    checked = 0
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_globals.get("__name__", "").startswith("aiosecurityspy."):
            assert DEVICE_PASSWORD not in repr(frame.f_locals), frame.f_code.co_name
            checked += 1
        traceback = traceback.tb_next
    assert checked, "the client's own frame was never inspected"
