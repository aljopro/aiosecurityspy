"""Pure decoding coverage for the event-stream record parser (research §3).

Every row of the story's edge-case matrix that concerns decoding is asserted
here, with no socket involved: the parser is deliberately pure so the protocol's
traps can be pinned down without a server. The recorded-shape fixture backs the
framing claims; synthetic lines cover the cases a well-behaved server never
sends.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Final
from zoneinfo import ZoneInfo

import pytest

from aiosecurityspy import (
    ClassificationPayload,
    ErrorPayload,
    FilePayload,
    MotionPayload,
    TriggerPayload,
    decode_trigger_reasons,
    events,
    parse_event_line,
)

if TYPE_CHECKING:
    from aiosecurityspy import StreamEvent

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "event_stream.bin"

#: Records in the fixture, one of which is deliberately malformed.
FIXTURE_RECORDS: Final = 15
FIXTURE_EVENTS: Final = 14

#: The camera number the fixture's camera-specific records carry.
FIXTURE_CAMERA: Final = 7


def fixture_bytes() -> bytes:
    return FIXTURE.read_bytes()


def fixture_events() -> list[StreamEvent]:
    """Frame the fixture exactly the way the stream reader does: split on CR only."""
    records = fixture_bytes().split(b"\r")
    parsed: list[StreamEvent] = []
    for record in records:
        if not record:
            continue
        event = parse_event_line(record.decode("utf-8"), server_timezone=UTC)
        if event is not None:
            parsed.append(event)
    return parsed


def find(event_type: str) -> StreamEvent:
    for event in fixture_events():
        if event.event_type == event_type:
            return event
    pytest.fail(f"fixture contains no {event_type} record")


def test_fixture_contains_no_line_feed_bytes() -> None:
    """The framing claim of research §3.1, asserted rather than assumed.

    If an LF ever appears in this fixture, the fixture has stopped representing
    the wire format and every framing test built on it proves nothing.
    """
    raw = fixture_bytes()
    assert b"\n" not in raw
    assert raw.count(b"\r") == FIXTURE_RECORDS
    assert raw.endswith(b"\r")


def test_fixture_decodes_every_well_formed_record() -> None:
    events = fixture_events()
    # 15 records, one of which is deliberately malformed and must be skipped.
    assert len(events) == FIXTURE_EVENTS
    assert [event.event_number for event in events] == list(range(FIXTURE_EVENTS))


def test_fixture_event_types_cover_the_protocol_table() -> None:
    types = {event.event_type for event in fixture_events()}
    assert types == {
        "MOTION",
        "MOTION_END",
        "CLASSIFY",
        "TRIGGER_M",
        "TRIGGER_A",
        "FILE",
        "ARM_C",
        "ONLINE",
        "ERROR",
        "CONFIGCHANGE",
        "NULL",
    }


def test_motion_decodes_a_bounding_box() -> None:
    event = parse_event_line("20260809175335 0 7 MOTION 10 20 30 40", server_timezone=UTC)
    assert event is not None
    assert event.camera == FIXTURE_CAMERA
    assert event.event_type == "MOTION"
    assert event.payload == MotionPayload(x=10, y=20, width=30, height=40)
    assert event.raw == "20260809175335 0 7 MOTION 10 20 30 40"


def test_motion_with_an_unparseable_box_still_delivers_the_event() -> None:
    """A payload that will not decode must never cost the event itself."""
    event = parse_event_line("20260809175335 0 7 MOTION 10 20 wide 40", server_timezone=UTC)
    assert event is not None
    assert event.event_type == "MOTION"
    assert event.payload is None
    assert event.info == "10 20 wide 40"


@pytest.mark.parametrize("info", ["10 20 30", "10 20 30 40 50", ""])
def test_motion_with_the_wrong_field_count_yields_no_payload(info: str) -> None:
    event = parse_event_line(f"20260809175335 0 7 MOTION {info}".rstrip(), server_timezone=UTC)
    assert event is not None
    assert event.payload is None


def test_classify_decodes_built_in_classes() -> None:
    event = parse_event_line("20260809175335 1 7 CLASSIFY HUMAN 88 VEHICLE 3", server_timezone=UTC)
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"HUMAN": 88.0, "VEHICLE": 3.0}


def test_classify_carries_an_unknown_custom_model_class_unchanged() -> None:
    """AD-9: the vocabulary is open. Nothing may reject a label (research §11)."""
    event = parse_event_line("20260809175337 6 10 CLASSIFY DELIVERY_VAN 61", server_timezone=UTC)
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"DELIVERY_VAN": 61.0}


def test_classify_built_in_handling_is_unaffected_by_an_unknown_class() -> None:
    event = parse_event_line(
        "20260809175335 1 7 CLASSIFY HUMAN 88 DELIVERY_VAN 61", server_timezone=UTC
    )
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"HUMAN": 88.0, "DELIVERY_VAN": 61.0}


def test_classify_skips_an_unpaired_or_unparseable_confidence() -> None:
    event = parse_event_line(
        "20260809175335 1 7 CLASSIFY HUMAN 88 VEHICLE nope ANIMAL", server_timezone=UTC
    )
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"HUMAN": 88.0}


def test_classify_with_no_usable_pair_yields_no_payload() -> None:
    event = parse_event_line("20260809175335 1 7 CLASSIFY HUMAN", server_timezone=UTC)
    assert event is not None
    assert event.payload is None


def test_classification_slugged_normalizes_and_keeps_the_stronger_signal() -> None:
    payload = ClassificationPayload(classes={"Delivery Van": 12.0, "DELIVERY_VAN": 61.0})
    assert dict(payload.slugged()) == {"delivery_van": 61.0}


def test_classification_slugged_is_read_only() -> None:
    payload = ClassificationPayload(classes={"HUMAN": 88.0})
    slugged = payload.slugged()
    assert dict(slugged) == {"human": 88.0}
    with pytest.raises(TypeError):
        slugged["human"] = 1.0  # type: ignore[index]  # proving the view is read-only


def test_trigger_decodes_the_reason_bitmask() -> None:
    event = parse_event_line("20260809175335 2 7 TRIGGER_M 129", server_timezone=UTC)
    assert event is not None
    assert event.payload == TriggerPayload(
        mask=129, reasons=frozenset({"video_motion", "human_movement"})
    )


def test_trigger_a_uses_the_same_bitmask() -> None:
    event = parse_event_line("20260809175336 3 7 TRIGGER_A 1", server_timezone=UTC)
    assert event is not None
    assert isinstance(event.payload, TriggerPayload)
    assert event.payload.reasons == frozenset({"video_motion"})


def test_trigger_with_a_non_numeric_mask_yields_no_payload() -> None:
    event = parse_event_line("20260809175335 2 7 TRIGGER_M motion", server_timezone=UTC)
    assert event is not None
    assert event.event_type == "TRIGGER_M"
    assert event.payload is None


@pytest.mark.parametrize(
    ("mask", "expected"),
    [
        (0, frozenset()),
        (1, frozenset({"video_motion"})),
        (1 << 9, frozenset({"homekit_event"})),
        (1 << 16, frozenset({"animal_departure"})),
        # Bit 17 is not in the §3.4 table: an unknown bit is ignored, not fatal.
        (1 << 17 | 1, frozenset({"video_motion"})),
    ],
)
def test_decode_trigger_reasons_covers_the_bit_table(mask: int, expected: frozenset[str]) -> None:
    assert decode_trigger_reasons(mask) == expected


def test_decode_trigger_reasons_degrades_like_decode_permissions() -> None:
    """A negative mask must not grant every reason: Python ints have no width."""
    assert decode_trigger_reasons(-1) == frozenset()
    assert decode_trigger_reasons(True) == frozenset()  # noqa: FBT003 - proving bool is not mask 1
    assert decode_trigger_reasons("129") == frozenset()  # type: ignore[arg-type]  # runtime degradation


def test_file_keeps_the_whole_remainder_including_spaces() -> None:
    event = find("FILE")
    assert event.payload == FilePayload(path="/Volumes/Cam/2026-08-09/Front Door 01.m4v")


def test_error_splits_a_leading_numeric_code() -> None:
    event = find("ERROR")
    assert event.payload == ErrorPayload(code=42, description="Camera connection timed out")


def test_error_without_a_numeric_code_keeps_the_whole_description() -> None:
    event = parse_event_line("20260809175339 10 7 ERROR camera unreachable", server_timezone=UTC)
    assert event is not None
    assert event.payload == ErrorPayload(code=None, description="camera unreachable")


def test_non_camera_specific_records_are_delivered_with_no_camera() -> None:
    """`X` means "not camera-specific", never "invalid" (research §3.2)."""
    event = parse_event_line("20260809175336 3 X NULL", server_timezone=UTC)
    assert event is not None
    assert event.camera is None
    assert event.event_type == "NULL"
    assert event.payload is None


def test_a_non_numeric_camera_field_is_also_not_camera_specific() -> None:
    event = parse_event_line("20260809175336 3 ?? NULL", server_timezone=UTC)
    assert event is not None
    assert event.camera is None


def test_unknown_event_type_is_delivered_with_its_info_verbatim() -> None:
    event = parse_event_line("20260809175336 3 7 SOMETHING_NEW 1 2", server_timezone=UTC)
    assert event is not None
    assert event.event_type == "SOMETHING_NEW"
    assert event.payload is None
    assert event.info == "1 2"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "MALFORMED RECORD",
        "20260809175336 3 7",
        "2026080917 3 7 NULL",  # timestamp is not 14 characters
        "202608091753350 3 7 NULL",  # 15 characters
        "20260809175336 X 7 NULL",  # non-numeric event number
    ],
)
def test_malformed_records_are_skipped_rather_than_raised(line: str) -> None:
    assert parse_event_line(line, server_timezone=UTC) is None


def test_a_14_character_but_impossible_timestamp_still_delivers_the_event() -> None:
    """Structure is intact, so the event is real; only the instant is unknown."""
    event = parse_event_line("20269909175336 3 7 NULL", server_timezone=UTC)
    assert event is not None
    assert event.timestamp is None
    assert event.raw_timestamp == "20269909175336"


def test_timestamps_are_converted_to_timezone_aware_utc() -> None:
    """AD-15: timestamps are tz-aware UTC, and the raw string survives."""
    server_zone = timezone(timedelta(hours=-7), "server")
    event = parse_event_line("20260809175335 0 7 MOTION_END", server_timezone=server_zone)
    assert event is not None
    assert event.timestamp == datetime(2026, 8, 10, 0, 53, 35, tzinfo=UTC)
    assert event.timestamp.tzinfo is UTC
    assert event.raw_timestamp == "20260809175335"


def test_an_explicit_utc_timezone_decodes_the_wall_clock_verbatim() -> None:
    """`server_timezone` is now required -- this pins the explicit-UTC case."""
    event = parse_event_line("20260809175335 0 7 MOTION_END", server_timezone=UTC)
    assert event is not None
    assert event.timestamp == datetime(2026, 8, 9, 17, 53, 35, tzinfo=UTC)


def test_the_live_heartbeat_decodes_correctly_under_the_servers_published_offset() -> None:
    """Research §5.7: the live heartbeat `20260829062049` with the server's UTC-5 offset."""
    server_offset = timezone(timedelta(seconds=-18000), "server")
    event = parse_event_line("20260829062049 3 X NULL", server_timezone=server_offset)
    assert event is not None
    assert event.timestamp == datetime(2026, 8, 29, 11, 20, 49, tzinfo=UTC)


def test_a_real_zoneinfo_produces_the_same_instant_as_the_matching_fixed_offset() -> None:
    """The caller's zone wins, and for the same reading it agrees with the fixed offset."""
    server_offset = timezone(timedelta(seconds=-18000), "server")
    fixed = parse_event_line("20260829062049 3 X NULL", server_timezone=server_offset)
    zoned = parse_event_line("20260829062049 3 X NULL", server_timezone=ZoneInfo("America/Chicago"))
    assert fixed is not None
    assert zoned is not None
    assert fixed.timestamp == zoned.timestamp == datetime(2026, 8, 29, 11, 20, 49, tzinfo=UTC)


def test_a_fixed_offset_disagrees_with_a_real_zone_across_a_dst_boundary() -> None:
    """An offset is not a timezone: a January record under a fixed UTC-5 is wrong by an hour.

    `research §5.7`: `20260829062049` (August, CDT) matches a fixed UTC-5, but
    `20260115062049` (January, CST) does not -- the fixed offset silently keeps
    assuming daylight time it is not in.
    """
    fixed_offset = timezone(timedelta(seconds=-18000), "server")
    real_zone = ZoneInfo("America/Chicago")

    august_fixed = parse_event_line("20260829062049 0 X NULL", server_timezone=fixed_offset)
    august_real = parse_event_line("20260829062049 0 X NULL", server_timezone=real_zone)
    assert august_fixed is not None
    assert august_real is not None
    assert august_fixed.timestamp == august_real.timestamp

    january_fixed = parse_event_line("20260115062049 0 X NULL", server_timezone=fixed_offset)
    january_real = parse_event_line("20260115062049 0 X NULL", server_timezone=real_zone)
    assert january_fixed is not None
    assert january_real is not None
    assert january_fixed.timestamp is not None
    assert january_real.timestamp is not None
    assert january_fixed.timestamp != january_real.timestamp
    assert abs(january_fixed.timestamp - january_real.timestamp) == timedelta(hours=1)


def test_server_timezone_is_a_required_keyword_argument() -> None:
    """No default exists: omitting it is a `mypy --strict` failure at every call site.

    Because it is a required keyword-only parameter with no default, it is
    also a runtime `TypeError`, not merely a discouraged pattern.
    """
    with pytest.raises(TypeError):
        parse_event_line("20260809175335 0 7 MOTION_END")  # type: ignore[call-arg]


def test_a_stray_line_feed_around_a_record_does_not_corrupt_it() -> None:
    """Defensive: a future server build emitting CRLF must not break decoding."""
    event = parse_event_line("\n20260809175335 0 7 MOTION 10 20 30 40\n", server_timezone=UTC)
    assert event is not None
    assert event.payload == MotionPayload(x=10, y=20, width=30, height=40)


def test_event_number_is_recorded_but_is_not_an_identifier() -> None:
    """It restarts at 0 on every reconnect, so it is data, not a key."""
    first = parse_event_line("20260809175335 0 7 MOTION_END", server_timezone=UTC)
    assert first is not None
    assert first.event_number == 0


def test_stream_events_are_frozen() -> None:
    event = parse_event_line("20260809175335 0 7 MOTION_END", server_timezone=UTC)
    assert event is not None
    with pytest.raises(AttributeError):
        event.camera = 9  # type: ignore[misc]  # proving the model is frozen


# --- Review regressions ----------------------------------------------------
# Each test below pins a defect the original implementation shipped with.


@pytest.mark.parametrize(
    "confidence",
    [
        "nan",
        "NaN",
        "inf",
        "-inf",
        "infinity",
        "1e999",  # overflows to infinity rather than raising
        "1_0",  # Python's underscore literal is not a wire format
        "\uff18\uff18",  # fullwidth digits parse in Python, never on the wire
    ],
)
def test_classify_rejects_values_the_wire_format_cannot_mean(confidence: str) -> None:
    """Bare `float()` accepts all of these; `_parse_int`'s sibling must not.

    A NaN is the dangerous one: it compares False against everything, so it
    silently wins comparisons it should lose.
    """
    event = parse_event_line(f"20260809175335 1 7 CLASSIFY HUMAN {confidence}", server_timezone=UTC)
    assert event is not None
    assert event.payload is None


def test_classify_keeps_the_good_pairs_beside_a_rejected_one() -> None:
    event = parse_event_line(
        "20260809175335 1 7 CLASSIFY HUMAN nan VEHICLE 50", server_timezone=UTC
    )
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"VEHICLE": 50.0}


def test_slugged_never_lets_a_non_finite_confidence_evict_a_real_one() -> None:
    """`confidence > previous` is False for NaN, so a bare `>` got this backwards."""
    payload = ClassificationPayload(classes={"Human": 50.0, "HUMAN": float("nan")})
    assert dict(payload.slugged()) == {"human": 50.0}

    reversed_order = ClassificationPayload(classes={"HUMAN": float("nan"), "Human": 50.0})
    assert dict(reversed_order.slugged()) == {"human": 50.0}


def test_slugged_keeps_a_non_finite_value_only_when_nothing_else_exists() -> None:
    payload = ClassificationPayload(classes={"HUMAN": float("nan")})
    assert list(payload.slugged()) == ["human"]


def test_an_absurdly_long_integer_field_skips_the_record_rather_than_raising() -> None:
    """CPython raises ValueError past its own digit limit for `int()`.

    One mis-framed or hostile record must not tear down a live connection.
    """
    huge = "9" * 5000
    assert parse_event_line(f"20260809175335 {huge} 7 MOTION_END", server_timezone=UTC) is None
    event = parse_event_line(f"20260809175335 0 {huge} MOTION_END", server_timezone=UTC)
    assert event is not None
    assert event.camera is None  # unparseable camera field: not camera-specific


def test_an_absurdly_long_motion_field_yields_no_payload_rather_than_raising() -> None:
    event = parse_event_line(
        f"20260809175335 0 7 MOTION {'9' * 5000} 20 30 40", server_timezone=UTC
    )
    assert event is not None
    assert event.payload is None


def test_a_timestamp_at_the_edge_of_the_calendar_does_not_raise() -> None:
    """`astimezone` can overflow out of the representable range near year 9999."""
    ahead = timezone(timedelta(hours=-14), "far-west")
    event = parse_event_line("99991231235959 0 7 MOTION_END", server_timezone=ahead)
    assert event is not None
    assert event.timestamp is None
    assert event.raw_timestamp == "99991231235959"

    behind = timezone(timedelta(hours=14), "far-east")
    early = parse_event_line("00010101000000 0 7 MOTION_END", server_timezone=behind)
    assert early is not None
    assert early.timestamp is None


def test_parsing_holds_no_process_global_state() -> None:
    """The parser is pure: log damping belongs to the stream that owns the socket.

    A module-global damping set made two streams interfere -- the second
    server's unknown types were silently never reported because the first had
    already seen them -- and made this suite order-dependent.
    """
    assert not [name for name in vars(events) if name.startswith("_REPORTED")]
    for index in range(256):
        event = parse_event_line(f"20260809175335 0 7 SYNTHETIC_TYPE_{index}", server_timezone=UTC)
        assert event is not None
        assert event.event_type == f"SYNTHETIC_TYPE_{index}"


# -- review follow-up: camera decoding, stride re-sync, whitespace ------------


@pytest.mark.parametrize("field", ["-1", "+3", "abc", "7.0", "\N{ARABIC-INDIC DIGIT SEVEN}"])
def test_a_camera_field_that_is_not_an_unsigned_number_carries_no_camera(field: str) -> None:
    """`-1` is not a camera, and `+3` must not alias onto camera 3.

    `_parse_int` accepts a leading sign, so these arrived as real camera IDs and
    a consumer keying entities by camera number built one that cannot exist.
    """
    event = parse_event_line(f"20260809175335 0 {field} MOTION 1 2 3 4", server_timezone=UTC)
    assert event is not None
    assert event.camera is None
    assert event.raw_camera == field


def test_raw_camera_tells_not_camera_specific_apart_from_unparseable() -> None:
    """`camera is None` alone conflated a heartbeat with a mis-framed record."""
    heartbeat = parse_event_line("20260809175335 3 X NULL", server_timezone=UTC)
    garbled = parse_event_line("20260809175335 3 ?? NULL", server_timezone=UTC)
    assert heartbeat is not None
    assert garbled is not None
    assert heartbeat.camera is garbled.camera is None
    assert heartbeat.raw_camera == "X"
    assert garbled.raw_camera == "??"


def test_classification_resyncs_after_an_unparseable_confidence() -> None:
    """A fixed stride of two shifted every later pair, silently losing them."""
    event = parse_event_line(
        "20260809175335 0 7 CLASSIFY HUMAN 88 VEHICLE bad ANIMAL 70", server_timezone=UTC
    )
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"HUMAN": 88.0, "ANIMAL": 70.0}


def test_an_error_description_is_stripped_with_or_without_a_code() -> None:
    """Whitespace must not depend on whether the server led with a code."""
    with_code = parse_event_line("20260809175335 0 7 ERROR 42 disk full  ", server_timezone=UTC)
    without = parse_event_line("20260809175335 0 7 ERROR disk full  ", server_timezone=UTC)
    assert with_code is not None
    assert without is not None
    assert isinstance(with_code.payload, ErrorPayload)
    assert isinstance(without.payload, ErrorPayload)
    assert with_code.payload.description == "disk full"
    assert without.payload.description == "disk full"


def test_a_file_path_keeps_its_interior_spaces_but_not_its_tail() -> None:
    """A padded record yielded a path nothing could stat."""
    event = parse_event_line(
        "20260809175335 0 7 FILE /Volumes/Cam A/2026-08-09/x.m4v   ", server_timezone=UTC
    )
    assert event is not None
    assert isinstance(event.payload, FilePayload)
    assert event.payload.path == "/Volumes/Cam A/2026-08-09/x.m4v"


def test_a_directly_constructed_classification_payload_is_read_only() -> None:
    """The `Mapping` annotation did not stop a caller keeping a live dict."""
    source = {"HUMAN": 90.0}
    payload = ClassificationPayload(classes=source)
    source["HUMAN"] = 1.0
    assert payload.classes["HUMAN"] == 90.0  # noqa: PLR2004 - the value it was constructed with
    with pytest.raises(TypeError):
        payload.classes["VEHICLE"] = 5.0  # type: ignore[index]
