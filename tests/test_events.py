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

import pytest

from aiosecurityspy import (
    ClassificationPayload,
    ErrorPayload,
    FilePayload,
    MotionPayload,
    TriggerPayload,
    decode_trigger_reasons,
    parse_event_line,
)

# The log damper's bound is only assertable from inside the module that owns it.
from aiosecurityspy.events import _MAX_REPORTED_TYPES, _REPORTED_UNKNOWN_TYPES

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
        event = parse_event_line(record.decode("utf-8"))
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
    event = parse_event_line("20260809175335 0 7 MOTION 10 20 30 40")
    assert event is not None
    assert event.camera == FIXTURE_CAMERA
    assert event.event_type == "MOTION"
    assert event.payload == MotionPayload(x=10, y=20, width=30, height=40)
    assert event.raw == "20260809175335 0 7 MOTION 10 20 30 40"


def test_motion_with_an_unparseable_box_still_delivers_the_event() -> None:
    """A payload that will not decode must never cost the event itself."""
    event = parse_event_line("20260809175335 0 7 MOTION 10 20 wide 40")
    assert event is not None
    assert event.event_type == "MOTION"
    assert event.payload is None
    assert event.info == "10 20 wide 40"


@pytest.mark.parametrize("info", ["10 20 30", "10 20 30 40 50", ""])
def test_motion_with_the_wrong_field_count_yields_no_payload(info: str) -> None:
    event = parse_event_line(f"20260809175335 0 7 MOTION {info}".rstrip())
    assert event is not None
    assert event.payload is None


def test_classify_decodes_built_in_classes() -> None:
    event = parse_event_line("20260809175335 1 7 CLASSIFY HUMAN 88 VEHICLE 3")
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"HUMAN": 88.0, "VEHICLE": 3.0}


def test_classify_carries_an_unknown_custom_model_class_unchanged() -> None:
    """AD-9: the vocabulary is open. Nothing may reject a label (research §11)."""
    event = parse_event_line("20260809175337 6 10 CLASSIFY DELIVERY_VAN 61")
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"DELIVERY_VAN": 61.0}


def test_classify_built_in_handling_is_unaffected_by_an_unknown_class() -> None:
    event = parse_event_line("20260809175335 1 7 CLASSIFY HUMAN 88 DELIVERY_VAN 61")
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"HUMAN": 88.0, "DELIVERY_VAN": 61.0}


def test_classify_skips_an_unpaired_or_unparseable_confidence() -> None:
    event = parse_event_line("20260809175335 1 7 CLASSIFY HUMAN 88 VEHICLE nope ANIMAL")
    assert event is not None
    assert isinstance(event.payload, ClassificationPayload)
    assert dict(event.payload.classes) == {"HUMAN": 88.0}


def test_classify_with_no_usable_pair_yields_no_payload() -> None:
    event = parse_event_line("20260809175335 1 7 CLASSIFY HUMAN")
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
    event = parse_event_line("20260809175335 2 7 TRIGGER_M 129")
    assert event is not None
    assert event.payload == TriggerPayload(
        mask=129, reasons=frozenset({"video_motion", "human_movement"})
    )


def test_trigger_a_uses_the_same_bitmask() -> None:
    event = parse_event_line("20260809175336 3 7 TRIGGER_A 1")
    assert event is not None
    assert isinstance(event.payload, TriggerPayload)
    assert event.payload.reasons == frozenset({"video_motion"})


def test_trigger_with_a_non_numeric_mask_yields_no_payload() -> None:
    event = parse_event_line("20260809175335 2 7 TRIGGER_M motion")
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
    event = parse_event_line("20260809175339 10 7 ERROR camera unreachable")
    assert event is not None
    assert event.payload == ErrorPayload(code=None, description="camera unreachable")


def test_non_camera_specific_records_are_delivered_with_no_camera() -> None:
    """`X` means "not camera-specific", never "invalid" (research §3.2)."""
    event = parse_event_line("20260809175336 3 X NULL")
    assert event is not None
    assert event.camera is None
    assert event.event_type == "NULL"
    assert event.payload is None


def test_a_non_numeric_camera_field_is_also_not_camera_specific() -> None:
    event = parse_event_line("20260809175336 3 ?? NULL")
    assert event is not None
    assert event.camera is None


def test_unknown_event_type_is_delivered_with_its_info_verbatim() -> None:
    event = parse_event_line("20260809175336 3 7 SOMETHING_NEW 1 2")
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
    assert parse_event_line(line) is None


def test_a_14_character_but_impossible_timestamp_still_delivers_the_event() -> None:
    """Structure is intact, so the event is real; only the instant is unknown."""
    event = parse_event_line("20269909175336 3 7 NULL")
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


def test_the_default_timezone_assumption_is_utc() -> None:
    event = parse_event_line("20260809175335 0 7 MOTION_END")
    assert event is not None
    assert event.timestamp == datetime(2026, 8, 9, 17, 53, 35, tzinfo=UTC)


def test_a_stray_line_feed_around_a_record_does_not_corrupt_it() -> None:
    """Defensive: a future server build emitting CRLF must not break decoding."""
    event = parse_event_line("\n20260809175335 0 7 MOTION 10 20 30 40\n")
    assert event is not None
    assert event.payload == MotionPayload(x=10, y=20, width=30, height=40)


def test_event_number_is_recorded_but_is_not_an_identifier() -> None:
    """It restarts at 0 on every reconnect, so it is data, not a key."""
    first = parse_event_line("20260809175335 0 7 MOTION_END")
    assert first is not None
    assert first.event_number == 0


def test_stream_events_are_frozen() -> None:
    event = parse_event_line("20260809175335 0 7 MOTION_END")
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
    event = parse_event_line(f"20260809175335 1 7 CLASSIFY HUMAN {confidence}")
    assert event is not None
    assert event.payload is None


def test_classify_keeps_the_good_pairs_beside_a_rejected_one() -> None:
    event = parse_event_line("20260809175335 1 7 CLASSIFY HUMAN nan VEHICLE 50")
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
    assert parse_event_line(f"20260809175335 {huge} 7 MOTION_END") is None
    event = parse_event_line(f"20260809175335 0 {huge} MOTION_END")
    assert event is not None
    assert event.camera is None  # unparseable camera field: not camera-specific


def test_an_absurdly_long_motion_field_yields_no_payload_rather_than_raising() -> None:
    event = parse_event_line(f"20260809175335 0 7 MOTION {'9' * 5000} 20 30 40")
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


def test_the_unknown_type_log_damper_is_bounded() -> None:
    """A process-global set fed from the wire must not grow without bound."""
    for index in range(_MAX_REPORTED_TYPES * 4):
        event = parse_event_line(f"20260809175335 0 7 SYNTHETIC_TYPE_{index}")
        assert event is not None
    assert len(_REPORTED_UNKNOWN_TYPES) <= _MAX_REPORTED_TYPES
