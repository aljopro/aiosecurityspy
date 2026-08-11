"""Pure decoding coverage: models and constants, with no network anywhere."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from zoneinfo import ZoneInfo

import pytest

from aiosecurityspy import (
    CAPTURE_FILTER_ANIMAL,
    CAPTURE_FILTER_HUMAN,
    CAPTURE_FILTER_VEHICLE,
    CAPTURE_TYPE_IMAGE,
    CAPTURE_TYPE_MOVIE,
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
    Capture,
    SecuritySpyUnsupportedVersionError,
    ServerInfo,
    capture_filter_for_class,
    class_slug,
    decode_object_classes,
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


# --- capture history: decoding (spec 1.4) -----------------------------------

CHICAGO = ZoneInfo("America/Chicago")

#: Research §4.1's worked example: 63319 seconds since local midnight -> 17:35:19.
SECONDS_1735 = 63319
FIXTURE_MOVIE_SIZE = 10485760
FIXTURE_DURATION_SECONDS = 42
FIXTURE_TAG_ID = 2
UNKNOWN_CAPTURE_TYPE = 7
SECONDS_PER_DAY = 86400


def load_caplist() -> list[Any]:
    entries: list[Any] = json.loads((FIXTURES / "caplist.json").read_text())
    return entries


def fixture_entry(index: int) -> dict[str, Any]:
    return cast("dict[str, Any]", load_caplist()[index])


def decode(payload: dict[str, Any], tz: Any = UTC) -> Capture:  # noqa: ANN401 - a tzinfo, kept loose so tests can pass anything
    capture = Capture.from_api(payload, server_timezone=tz)
    assert capture is not None
    return capture


def base_entry(**overrides: Any) -> dict[str, Any]:  # noqa: ANN401 - synthetic wire values are deliberately untyped
    entry: dict[str, Any] = {
        "c": 3,
        "t": 1,
        "s": SECONDS_1735,
        "d": 10,
        "f": "2026-08-09",
        "n": "capture.m4v",
        "o": 0,
    }
    entry.update(overrides)
    return entry


# --- absolute time reconstruction -------------------------------------------


def test_start_reconstructs_from_folder_date_and_seconds() -> None:
    capture = decode(base_entry())
    assert capture.start == datetime(2026, 8, 9, 17, 35, 19, tzinfo=UTC)
    assert capture.start is not None
    assert capture.start.tzinfo is not None


def test_start_is_interpreted_in_the_server_timezone_and_returned_as_utc() -> None:
    capture = decode(base_entry(), CHICAGO)
    # 2026-08-09 is CDT (UTC-5), so 17:35:19 local is 22:35:19 UTC.
    assert capture.start == datetime(2026, 8, 9, 22, 35, 19, tzinfo=UTC)
    assert capture.start.utcoffset() == timedelta(0)


def test_seconds_past_midnight_roll_into_the_next_day() -> None:
    capture = decode(base_entry(s=SECONDS_PER_DAY + 1))
    assert capture.start == datetime(2026, 8, 10, 0, 0, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "overrides",
    [
        {"f": None},
        {"f": ""},
        {"f": "2026/08/09"},
        {"f": "not-a-date"},
        {"f": "2026-13-45"},
        {"f": "٢٠٢٦-٠٨-٠٩"},
        {"s": None},
        {"s": "later"},
        {"s": -1},
        {"s": 1.5},
        {"s": True},
    ],
)
def test_unusable_time_fields_yield_none_but_keep_the_capture(overrides: dict[str, Any]) -> None:
    capture = decode(base_entry(**overrides))
    assert capture.start is None
    assert capture.camera == base_entry()["c"]


def test_missing_time_fields_entirely_yield_none() -> None:
    capture = decode({"c": 3})
    assert capture.start is None
    assert capture.folder_date == ""
    assert capture.filename == ""
    assert capture.path == ""


def test_fixture_entry_with_no_folder_date_has_no_start() -> None:
    capture = decode(fixture_entry(4))
    assert capture.start is None
    assert capture.camera == 4  # noqa: PLR2004 - the fixture's camera number


# --- classification bitmask -------------------------------------------------


def test_classification_bitmask_decodes_to_class_names() -> None:
    assert decode(base_entry(o=5)).object_classes == frozenset({"human", "animal"})


@pytest.mark.parametrize("overrides", [{"o": 0}, {"o": None}, {}])
def test_empty_classification_is_an_empty_frozenset(overrides: dict[str, Any]) -> None:
    entry = base_entry(**overrides)
    if not overrides:
        del entry["o"]
    classes = decode(entry).object_classes
    assert classes == frozenset()
    assert isinstance(classes, frozenset)


def test_unknown_classification_bit_is_ignored() -> None:
    # Bit 3 (value 8) has no meaning; the human bit still decodes.
    assert decode(base_entry(o=9)).object_classes == frozenset({"human"})


@pytest.mark.parametrize("mask", [0, -1, -5])
def test_decode_object_classes_degrades_like_decode_permissions(mask: int) -> None:
    assert decode_object_classes(mask) == frozenset()


@pytest.mark.parametrize("value", ["5", None, 1.5, True])
def test_decode_object_classes_rejects_non_integers(value: object) -> None:
    assert decode_object_classes(cast("int", value)) == frozenset()


def test_decode_object_classes_covers_every_declared_bit() -> None:
    assert decode_object_classes(7) == frozenset({"human", "vehicle", "animal"})


def test_has_class() -> None:
    capture = decode(base_entry(o=2))
    assert capture.has_class("vehicle")
    assert not capture.has_class("human")


# --- capture type -----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected_name", "expected_movie"),
    [
        (CAPTURE_TYPE_MOVIE, "movie", True),
        (CAPTURE_TYPE_IMAGE, "image", False),
        (UNKNOWN_CAPTURE_TYPE, None, False),
    ],
)
def test_capture_type_decodes_and_carries_unknown_values(
    raw: int,
    expected_name: str | None,
    expected_movie: bool,  # noqa: FBT001 - parametrized expectation
) -> None:
    capture = decode(base_entry(t=raw))
    assert capture.capture_type == raw
    assert capture.capture_type_name == expected_name
    assert capture.is_movie is expected_movie


def test_absent_capture_type_is_none() -> None:
    capture = decode({"c": 3})
    assert capture.capture_type is None
    assert capture.capture_type_name is None
    assert capture.is_movie is False


def test_capture_type_values_do_not_collide_with_clip_movie_type() -> None:
    """Research §4b.3: `caplist.t` and `clip.movieType` must not share a mapping.

    Continuous Capture is `clip.movieType == 1`, which is `caplist.t == 1`
    (movie). Asserting the caplist meaning here is what would fail loudly if a
    later story reused this table for clips.
    """
    assert CAPTURE_TYPE_MOVIE == 1
    assert CAPTURE_TYPE_IMAGE == 2  # noqa: PLR2004 - the wire value under test


# --- remaining fields -------------------------------------------------------


def test_fixture_movie_entry_decodes_every_field() -> None:
    capture = decode(fixture_entry(0))
    assert capture.camera == 1
    assert capture.start == datetime(2026, 8, 9, 17, 35, 19, tzinfo=UTC)
    assert capture.duration == timedelta(seconds=FIXTURE_DURATION_SECONDS)
    assert capture.capture_type == CAPTURE_TYPE_MOVIE
    assert capture.object_classes == frozenset({"human", "animal"})
    assert capture.filename == "09-08-2026 17-35-19 M Front Door.m4v"
    assert capture.folder_date == "2026-08-09"
    assert capture.file_size == FIXTURE_MOVIE_SIZE
    assert capture.tag_id == 0
    assert capture.archived is False
    assert capture.unread is True
    assert capture.path == "1/2026-08-09/09-08-2026 17-35-19 M Front Door.m4v"


def test_fixture_image_entry_decodes() -> None:
    capture = decode(fixture_entry(1))
    assert capture.capture_type == CAPTURE_TYPE_IMAGE
    assert capture.capture_type_name == "image"
    assert capture.is_movie is False
    assert capture.archived is True
    assert capture.tag_id == FIXTURE_TAG_ID
    assert capture.object_classes == frozenset({"human"})


@pytest.mark.parametrize("overrides", [{"d": -1}, {"d": "soon"}, {}])
def test_unusable_duration_is_none(overrides: dict[str, Any]) -> None:
    entry = base_entry(**overrides)
    if not overrides:
        del entry["d"]
    assert decode(entry).duration is None


@pytest.mark.parametrize("value", [-1, "big", None])
def test_unusable_file_size_is_none(value: object) -> None:
    assert decode(base_entry(m=value)).file_size is None


def test_entry_with_no_usable_camera_is_skipped() -> None:
    assert Capture.from_api(fixture_entry(6), server_timezone=UTC) is None
    assert Capture.from_api({"c": "front"}, server_timezone=UTC) is None
    assert Capture.from_api({"c": True}, server_timezone=UTC) is None


def test_capture_is_frozen_and_hashable() -> None:
    capture = decode(base_entry())
    with pytest.raises(AttributeError):
        capture.camera = 9  # type: ignore[misc]
    assert hash(capture) == hash(decode(base_entry()))


def test_capture_repr_carries_no_credential_bearing_material() -> None:
    text = repr(decode(base_entry(o=5)))
    assert text.startswith("Capture(camera=3")
    assert "human" in text
    assert "password" not in text.lower()


# --- capture_filter_for_class -----------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("human", CAPTURE_FILTER_HUMAN),
        ("vehicle", CAPTURE_FILTER_VEHICLE),
        ("animal", CAPTURE_FILTER_ANIMAL),
        ("Human", CAPTURE_FILTER_HUMAN),
        ("  ANIMAL  ", CAPTURE_FILTER_ANIMAL),
    ],
)
def test_capture_filter_for_class(name: str, expected: int) -> None:
    assert capture_filter_for_class(name) == expected


@pytest.mark.parametrize("name", ["delivery_van", "", "package", "unknown"])
def test_capture_filter_for_class_rejects_unfilterable_classes(name: str) -> None:
    """The error names the three filterable classes and never quotes the caller's."""
    with pytest.raises(ValueError, match="animal, human, vehicle") as excinfo:
        capture_filter_for_class(name)
    assert "delivery_van" not in str(excinfo.value)


# --- review regressions (spec 1.4 review pass) ------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "../../../etc/passwd",
        "a/b.m4v",
        "a\\b.m4v",
        "..",
    ],
)
def test_a_filename_that_could_escape_its_directory_yields_no_path(filename: str) -> None:
    """`path` is the triple a consumer concatenates into a media URL.

    The filename encodes the camera's user-set name, so it is influenced from
    outside; a separator or a `..` segment in it would address something other
    than the capture it describes. The capture is still returned -- it simply
    has no addressable file.
    """
    capture = Capture.from_api(
        {"c": 1, "f": "2026-08-09", "n": filename, "s": 10}, server_timezone=UTC
    )
    assert capture is not None
    assert capture.path == ""
    assert capture.filename == filename


def test_a_folder_date_with_a_separator_yields_no_path() -> None:
    capture = Capture.from_api(
        {"c": 1, "f": "2026-08-09/../..", "n": "x.m4v", "s": 10}, server_timezone=UTC
    )
    assert capture is not None
    assert capture.path == ""


CHICAGO = ZoneInfo("America/Chicago")


def test_seconds_since_midnight_are_wall_clock_across_a_dst_boundary() -> None:
    """`s` is a wall-clock second-of-day, so 17:35:19 local stays 17:35:19 local.

    The day before a fall-back and the day after must both reconstruct to the
    same local wall time, which is what absolute-seconds arithmetic would get
    wrong by an hour.
    """
    before = Capture.from_api(
        {"c": 1, "f": "2026-10-31", "s": 63319, "n": "a.m4v"}, server_timezone=CHICAGO
    )
    after = Capture.from_api(
        {"c": 1, "f": "2026-11-02", "s": 63319, "n": "b.m4v"}, server_timezone=CHICAGO
    )
    assert before is not None
    assert after is not None
    assert before.start is not None
    assert after.start is not None
    assert before.start.astimezone(CHICAGO).time() == after.start.astimezone(CHICAGO).time()


def test_an_ambiguous_local_hour_resolves_to_the_earlier_instant() -> None:
    """[ASSUMPTION] `s` carries no fold bit, so fold=0 -- the pre-transition instant.

    Documented rather than fixed: nothing in `caplist` can express which side of
    the fall-back a capture fell on.
    """
    capture = Capture.from_api(
        {"c": 1, "f": "2026-11-01", "s": 3600, "n": "a.m4v"}, server_timezone=CHICAGO
    )
    assert capture is not None
    assert capture.start == datetime(2026, 11, 1, 6, 0, tzinfo=UTC)


def test_an_out_of_range_second_of_day_rolls_over_rather_than_raising() -> None:
    """The field's meaning does not permit it, but a misbehaving server can send it."""
    capture = Capture.from_api(
        {"c": 1, "f": "2026-08-09", "s": 86400 + 61, "n": "a.m4v"}, server_timezone=UTC
    )
    assert capture is not None
    assert capture.start == datetime(2026, 8, 10, 0, 1, 1, tzinfo=UTC)
