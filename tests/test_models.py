"""Pure decoding coverage: models and constants, with no network anywhere."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from aiosecurityspy import (
    PERM_AUDIORCV,
    PERM_AUDIOSND,
    PERM_CAMCONTROL,
    PERM_FILEDEL,
    PERM_FILES,
    PERM_LIVEVIDEO,
    PERM_PTZSET,
    PERM_SCHED,
    PERM_TRIGGER,
    Camera,
    SecuritySpyUnsupportedVersionError,
    ServerInfo,
    class_slug,
    decode_permissions,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load_system_info() -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((FIXTURES / "system_info.json").read_text())
    return payload


def wrap(server: dict[str, Any], cameras: object) -> dict[str, Any]:
    return {"system": {"server": server, "cameralist": {"camera": cameras}}}


SERVER = {"version": "6.20", "uuid": "abc", "camera-count": "1"}
FIXTURE_CAMERA_COUNT = 3
FIXTURE_FULL_PERMISSIONS = 10207
TWO_CAMERAS = 2


# --- happy path -------------------------------------------------------------


def test_fixture_decodes_to_server_info() -> None:
    info = ServerInfo.from_api(load_system_info())
    assert info.uuid == "1D3A5C7E-9B21-4F60-8A44-0C2E6F1B7D93"
    assert info.version == "6.20"
    assert info.version_info == (6, 20)
    assert info.camera_count == FIXTURE_CAMERA_COUNT
    assert set(info.cameras) == {0, 1, 7}
    assert all(isinstance(number, int) for number in info.cameras)


def test_camera_fields_decode() -> None:
    info = ServerInfo.from_api(load_system_info())
    front = info.cameras[0]
    assert front.name == "Front Door"
    assert front.connected is True
    assert front.enabled is True
    assert front.permissions == FIXTURE_FULL_PERMISSIONS

    back = info.cameras[7]
    assert back.connected is False
    assert back.enabled is False
    assert back.permissions == PERM_LIVEVIDEO


def test_observed_bitmask_decodes_bit_by_bit() -> None:
    """Decode the observed 10207 mask from research §9, bit by bit.

    Research §9's *prose* summarises 10207 as
    ``LIVEVIDEO+FILES+FILEDEL+CAMCONTROL+SCHED+AUDIORCV+TRIGGER+AUDIOSND``, but
    that decomposition does not hold arithmetically: 10207 has bit 8 (PTZSET,
    256) set and bit 11 (AUDIOSND, 2048) clear. The bit *table* in §9 is
    authoritative, and this test pins the arithmetic rather than the prose.
    """
    expected = (
        PERM_LIVEVIDEO
        | PERM_FILES
        | PERM_FILEDEL
        | PERM_CAMCONTROL
        | PERM_SCHED
        | PERM_PTZSET
        | PERM_AUDIORCV
        | PERM_TRIGGER
    )
    assert FIXTURE_FULL_PERMISSIONS & expected == expected
    assert not FIXTURE_FULL_PERMISSIONS & PERM_AUDIOSND
    assert decode_permissions(FIXTURE_FULL_PERMISSIONS) == {
        "live_video",
        "files",
        "file_delete",
        "camera_control",
        "schedule",
        "ptz_preset_set",
        "audio_receive",
        "trigger",
    }


def test_partial_bitmask_and_helper() -> None:
    info = ServerInfo.from_api(load_system_info())
    driveway = info.cameras[1]
    assert driveway.permission_names == {"live_video", "files"}
    assert driveway.has_permission("live_video")
    assert not driveway.has_permission("file_delete")


def test_unknown_permission_bits_are_ignored_not_rejected() -> None:
    assert decode_permissions(1 | 1 << 20) == {"live_video"}
    assert decode_permissions(0) == frozenset()


def test_camera_inventory_is_not_mutable_through_the_model() -> None:
    """`ServerInfo` is frozen, so its inventory must not be mutable in place."""
    info = ServerInfo.from_api(load_system_info())
    with pytest.raises(TypeError):
        info.cameras[99] = info.cameras[1]  # type: ignore[index]


def test_permission_names_cannot_disagree_with_the_mask() -> None:
    """`permission_names` is derived, so no constructor can put them out of step."""
    camera = Camera(number=1, name="x", connected=True, enabled=True, permissions=PERM_FILES)
    assert camera.permission_names == {"files"}


def test_negative_permission_mask_grants_nothing() -> None:
    """Python ints are infinite-width, so `-1 & bit` would grant everything."""
    assert decode_permissions(-1) == frozenset()
    assert Camera.from_api({"number": 1, "permissions": "-1"}).permissions == 0  # type: ignore[union-attr]


@pytest.mark.parametrize("mask", ["5", None, 1.5, True])
def test_non_integer_permission_mask_grants_nothing(mask: object) -> None:
    """An exported helper degrades like class_slug() rather than raising TypeError."""
    assert decode_permissions(cast("int", mask)) == frozenset()


def test_bare_major_version_is_supported() -> None:
    """A server reporting "6" must not sort below the (6, 0) floor on length."""
    info = ServerInfo.from_api(wrap({**SERVER, "version": "6"}, []))
    assert info.version_info == (6, 0)


def test_non_finite_numbers_do_not_escape_as_value_errors() -> None:
    """`json.loads` accepts NaN/Infinity; `int()` raises on both."""
    assert Camera.from_api({"number": float("nan")}) is None
    assert Camera.from_api({"number": float("inf")}) is None


def test_duplicate_camera_numbers_keep_the_first_entry() -> None:
    info = ServerInfo.from_api(
        wrap(SERVER, [{"number": "1", "name": "First"}, {"number": "1", "name": "Second"}])
    )
    assert list(info.cameras) == [1]
    assert info.cameras[1].name == "First"


# --- camera-list shape edge cases -------------------------------------------


def test_single_camera_dict_rather_than_list() -> None:
    info = ServerInfo.from_api(wrap(SERVER, {"number": "2", "name": "Solo"}))
    assert list(info.cameras) == [2]
    assert info.cameras[2].name == "Solo"


def test_empty_camera_list_is_empty_dict() -> None:
    info = ServerInfo.from_api(wrap(SERVER, []))
    assert info.cameras == {}


def test_absent_camera_list_is_empty_dict() -> None:
    info = ServerInfo.from_api({"system": {"server": SERVER}})
    assert info.cameras == {}


def test_non_numeric_camera_number_is_skipped_and_rest_decode() -> None:
    info = ServerInfo.from_api(
        wrap(SERVER, [{"number": "x", "name": "Bad"}, {"number": "3", "name": "Good"}])
    )
    assert list(info.cameras) == [3]


def test_non_object_camera_entry_is_skipped() -> None:
    info = ServerInfo.from_api(wrap(SERVER, ["nonsense", {"number": 4, "name": "Good"}]))
    assert list(info.cameras) == [4]


def test_bare_envelope_without_system_wrapper() -> None:
    info = ServerInfo.from_api({"server": SERVER, "cameralist": {"camera": []}})
    assert info.version == "6.20"


def test_camera_count_falls_back_to_decoded_count() -> None:
    server = {"version": "6.20", "uuid": "abc"}
    info = ServerInfo.from_api(wrap(server, [{"number": 1}, {"number": 2}]))
    assert info.camera_count == TWO_CAMERAS


def test_camera_defaults_when_fields_absent() -> None:
    camera = Camera.from_api({"number": 9})
    assert camera is not None
    assert camera.name == "Camera 9"
    assert camera.connected is False
    assert camera.enabled is True
    assert camera.permissions == 0


def test_camera_from_api_returns_none_without_number() -> None:
    assert Camera.from_api({"name": "Nameless"}) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("yes", True), ("no", False), (1, True), (0, False), (True, True), ("TRUE", True)],
)
def test_boolean_coercion_variants(raw: object, expected: bool) -> None:  # noqa: FBT001 - table-driven expected value
    camera = Camera.from_api({"number": 1, "connected": raw})
    assert camera is not None
    assert camera.connected is expected


# --- version handling -------------------------------------------------------


def test_version_compares_numerically_not_lexically() -> None:
    info = ServerInfo.from_api(wrap({"version": "6.9", "uuid": "a"}, []))
    assert info.version_info == (6, 9)
    assert ServerInfo.from_api(wrap({"version": "6.20", "uuid": "a"}, [])).version_info > (6, 9)


def test_version_with_build_suffix_parses() -> None:
    info = ServerInfo.from_api(wrap({"version": "6.20b3", "uuid": "a"}, []))
    assert info.version_info == (6, 20)


@pytest.mark.parametrize("version", ["5.9", "4.0.1"])
def test_old_server_raises_unsupported_version(version: str) -> None:
    with pytest.raises(SecuritySpyUnsupportedVersionError) as err:
        ServerInfo.from_api(wrap({"version": version, "uuid": "a"}, []))
    assert version in str(err.value)
    assert "6.0" in str(err.value)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"system": {}},
        {"system": {"server": {"uuid": "a"}}},
        {"system": {"server": {"version": "not-a-version", "uuid": "a"}}},
        [],
        "nonsense",
        None,
    ],
)
def test_unlocatable_payload_raises_unsupported_version(payload: object) -> None:
    with pytest.raises(SecuritySpyUnsupportedVersionError):
        ServerInfo.from_api(payload)


# --- repr and slug ----------------------------------------------------------


def test_reprs_are_informative_and_short() -> None:
    info = ServerInfo.from_api(load_system_info())
    assert "ServerInfo(" in repr(info)
    assert "cameras=3" in repr(info)
    assert "Camera(number=0" in repr(info.cameras[0])


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Human", "human"),
        ("  VEHICLE ", "vehicle"),
        ("delivery van", "delivery_van"),
        ("Dog/Cat", "dog_cat"),
        ("a--b", "a_b"),
        ("__weird__", "weird"),
        ("!!!", "unknown"),
        ("", "unknown"),
        ("custom-model-42", "custom_model_42"),
    ],
)
def test_class_slug(raw: str, expected: str) -> None:
    slug = class_slug(raw)
    assert slug == expected
    # The AD-9 contract: the result may contain only [a-z0-9_] and is never empty,
    # because it is the only path a class name takes into a permanent key.
    assert slug
    assert all(char in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in slug)


def test_class_slug_degrades_on_a_non_string() -> None:
    """The vocabulary is open and comes off the wire; a public helper must not raise."""
    assert class_slug(cast("str", None)) == "unknown"
    assert class_slug(cast("str", 42)) == "unknown"


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("json-true", True),
        ("json-false", False),
        ("underscored-literal", "1_0"),
        ("non-ascii-digit", "²"),
        ("fractional-float", 2.9),
        ("whitespace-only", "   "),
        ("empty", ""),
        ("plus-only", "+"),
    ],
)
def test_camera_entries_with_unusable_numbers_are_skipped(label: str, raw: object) -> None:
    """The camera number is a stable key: no aliasing, no truncation, no Python literals."""
    del label
    assert Camera.from_api({"number": raw}) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("7", 7), (" 7 ", 7), ("+7", 7), ("-7", -7), (7, 7), (7.0, 7)],
)
def test_camera_numbers_that_do_parse(raw: object, expected: int) -> None:
    camera = Camera.from_api({"number": raw})
    assert camera is not None
    assert camera.number == expected


def test_underscored_camera_number_does_not_alias_a_real_camera() -> None:
    """`int("1_0")` is 10 in Python; that must not collide with a real camera 10."""
    info = ServerInfo.from_api(
        {
            "server": {"version": "6.20"},
            "cameralist": {"camera": [{"number": "1_0"}, {"number": "10", "name": "Real"}]},
        }
    )
    assert set(info.cameras) == {10}
    assert info.cameras[10].name == "Real"


@pytest.mark.parametrize("version", ["6.²", "².0", "6.0.²"])
def test_non_ascii_digit_version_raises_the_typed_error_not_value_error(version: str) -> None:
    """`"²".isdigit()` is True but `int("²")` raises; a bare ValueError must not escape."""
    with pytest.raises(SecuritySpyUnsupportedVersionError):
        ServerInfo.from_api({"server": {"version": version}})


def test_negative_camera_count_falls_back_to_the_decoded_count() -> None:
    """A negative inventory size is nonsense and must not reach a consumer."""
    info = ServerInfo.from_api(
        {
            "server": {"version": "6.20", "camera-count": "-3"},
            "cameralist": {"camera": [{"number": "1"}]},
        }
    )
    assert info.camera_count == 1
