"""Frozen event models and the pure event-stream record parser (research §3.2).

Decoding lives here rather than in :mod:`aiosecurityspy.stream` so every row of
the protocol's edge-case matrix is testable without a socket. Nothing in this
module performs I/O.

Raw lines never cross the public boundary as strings to be re-parsed (AD-15):
every record becomes a :class:`StreamEvent` with a typed, per-event-type
payload. The original line is kept on :attr:`StreamEvent.raw` for diagnosis,
which is safe because the event stream carries no credentials.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from .const import (
    EVENT_CLASSIFY,
    EVENT_ERROR,
    EVENT_FILE,
    EVENT_MOTION,
    EVENT_TRIGGER_A,
    EVENT_TRIGGER_M,
    class_slug,
    decode_trigger_reasons,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import tzinfo

__all__ = [
    "ClassificationPayload",
    "ErrorPayload",
    "EventPayload",
    "FilePayload",
    "MotionPayload",
    "StreamEvent",
    "TriggerPayload",
    "parse_event_line",
]

_LOGGER: Final = logging.getLogger(__name__)

#: Longest integer field this parser will convert. Comfortably above any real
#: value (camera numbers, event counters and bitmasks are all small) and well
#: under CPython's own 4300-digit conversion limit.
_MAX_INT_DIGITS: Final = 64

#: Length of the ``YYYYMMDDHHMMSS`` timestamp field (research §3.2).
_TIMESTAMP_LENGTH: Final = 14
_TIMESTAMP_FORMAT: Final = "%Y%m%d%H%M%S"

#: Minimum field count of a well-formed record: time, number, camera, event.
_MIN_FIELDS: Final = 4

#: A ``MOTION`` box is exactly four integers: X, Y, W, H.
_MOTION_FIELDS: Final = 4

#: Camera field value meaning "this event is not about one camera" (§3.2).
_CAMERA_NOT_SPECIFIC: Final = "X"

#: Event types whose payload is a trigger reason bitmask (§3.4).
_TRIGGER_EVENTS: Final = frozenset({EVENT_TRIGGER_M, EVENT_TRIGGER_A})

#: Ceiling on :data:`_REPORTED_UNKNOWN_TYPES`. The event vocabulary of §3.3 is
#: a couple of dozen entries, so anything approaching this is a mis-framed or
#: hostile stream inventing type names -- which must not be able to grow a
#: process-global set without bound.
_MAX_REPORTED_TYPES: Final = 64

#: Event types already reported as having no decodable payload, so the debug
#: log fires once per type rather than once per record. `CLASSIFY` alone can be
#: 191 records in 95 s (§3.5); logging every one would be a flood. Bounded, and
#: cleared wholesale when full: this is log damping, not a correctness record,
#: so re-reporting a type after a reset is harmless.
_REPORTED_UNKNOWN_TYPES: set[str] = set()


def _should_report(event_type: str) -> bool:
    """Return whether this type's missing payload has yet to be logged."""
    if event_type in _REPORTED_UNKNOWN_TYPES:
        return False
    if len(_REPORTED_UNKNOWN_TYPES) >= _MAX_REPORTED_TYPES:
        _REPORTED_UNKNOWN_TYPES.clear()
    _REPORTED_UNKNOWN_TYPES.add(event_type)
    return True


@dataclass(frozen=True, slots=True)
class MotionPayload:
    """A ``MOTION`` bounding box, in the camera's own pixel coordinates.

    The origin is the **top-left** corner (research §3.3), not the bottom-left
    that image-processing conventions might suggest.
    """

    x: int
    y: int
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class ClassificationPayload:
    """One ``CLASSIFY`` inference: object-class labels with their confidences.

    The vocabulary is **open** (AD-9): keys are exactly the labels the server
    sent, including labels from a user-supplied CoreML custom model (research
    §11). Nothing here validates a label against a known set.

    ``CLASSIFY`` is a per-frame inference stream rather than a detection event
    (§3.5), so a single confidence value means very little on its own; reducing
    a sequence of them into an episode is Story 1.5's job, not this module's.
    """

    #: Confidences as percentages, 0-100, keyed by the raw label. A read-only
    #: view: this model is frozen and its contents are not mutable through it.
    classes: Mapping[str, float]

    def slugged(self) -> Mapping[str, float]:
        """Return the confidences keyed by :func:`~aiosecurityspy.class_slug`.

        Use this, and only this, when a class name has to become a permanent
        key such as a unique ID (AD-9). Two raw labels can normalize to the
        same slug (``"Delivery Van"`` and ``"DELIVERY_VAN"``), in which case
        the higher confidence wins -- dropping the stronger signal to a
        formatting difference would be the worse failure. A non-finite value
        (which this library's own parser never produces, but a directly
        constructed payload can carry) always loses to a finite one.

        Returns:
            A read-only mapping of slug to confidence.

        """
        merged: dict[str, float] = {}
        for label, confidence in self.classes.items():
            slug = class_slug(label)
            previous = merged.get(slug)
            if previous is None or _prefers(confidence, previous):
                merged[slug] = confidence
        return MappingProxyType(merged)


@dataclass(frozen=True, slots=True)
class TriggerPayload:
    """A ``TRIGGER_M`` / ``TRIGGER_A`` reason bitmask and its decoded names.

    Both the raw mask and the decoded names are kept: unknown bits carry no
    name, and a consumer diagnosing a new server build needs the number.
    """

    mask: int
    reasons: frozenset[str]


@dataclass(frozen=True, slots=True)
class FilePayload:
    """A ``FILE`` event's completed-recording path, as the server spelled it.

    The path is server-local and lags the episode by roughly 96 s (§3.5), so it
    is a reconciliation signal rather than a low-latency trigger.
    """

    path: str


@dataclass(frozen=True, slots=True)
class ErrorPayload:
    """An ``ERROR`` event's code and human-readable description.

    ``code`` is ``None`` when the server did not lead with a numeric code; the
    whole ``INFO`` field is then the description.
    """

    code: int | None
    description: str


#: Every payload a decoded event can carry. `None` on a `StreamEvent` means the
#: event type has no payload, or its payload did not decode -- the event is
#: delivered either way.
type EventPayload = (
    MotionPayload | ClassificationPayload | TriggerPayload | FilePayload | ErrorPayload
)


@dataclass(frozen=True, slots=True)
class StreamEvent:
    """One decoded record from the SecuritySpy event stream (research §3.2)."""

    #: The record's timestamp, converted to timezone-aware UTC (AD-15), or
    #: ``None`` when the 14-character field did not name a real instant.
    timestamp: datetime | None
    #: The timestamp exactly as it arrived, so a consumer that later learns the
    #: server's real timezone can re-interpret it.
    raw_timestamp: str
    #: Per-connection counter starting at 0. **Not** a persistent identifier:
    #: it restarts on every reconnect, so nothing may be keyed off it.
    event_number: int
    #: The camera this event concerns, or ``None`` when the record's camera
    #: field was ``X`` -- meaning "not camera-specific", never "invalid".
    camera: int | None
    #: The raw event type, e.g. ``"MOTION"``. An open vocabulary: a type this
    #: library has never seen arrives here unchanged.
    event_type: str
    #: The unparsed ``INFO`` remainder, always present (empty when absent).
    info: str
    #: The decoded payload, or ``None`` for an event type with no payload or
    #: one whose payload did not decode.
    payload: EventPayload | None
    #: The full record as received, minus its terminator.
    raw: str


def _parse_int(text: str) -> int | None:
    """Parse an optionally-signed ASCII decimal integer, or return ``None``.

    ASCII-only and underscore-free on purpose: ``int("1_0")`` is 10 and
    ``"²".isdigit()`` is True, and neither is something the wire format means.
    """
    digits = text[1:] if text[:1] in {"+", "-"} else text
    if not digits or not digits.isascii() or not digits.isdigit():
        return None
    if len(digits) > _MAX_INT_DIGITS:
        # CPython refuses to convert an integer string past its own digit limit
        # and raises ValueError. Every field this parses is a small number, so
        # a value this long is mis-framed or hostile -- and it must skip the
        # record rather than raise out of the parser and end a live stream.
        return None
    return int(text)


def _parse_float(text: str) -> float | None:
    """Parse a confidence percentage, or return ``None``.

    As strict as :func:`_parse_int`, and for the same reason: bare ``float()``
    accepts ``"nan"``, ``"inf"``, ``"1e999"`` (which becomes infinity) and
    ``"1_0"``, none of which the wire format means. A NaN is the worst of them
    -- it compares False against everything, so it would silently win a
    confidence comparison it should lose.
    """
    if not text.isascii() or "_" in text:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    if not math.isfinite(value):
        return None
    return value


def _prefers(candidate: float, incumbent: float) -> bool:
    """Return whether `candidate` should replace `incumbent` as a confidence.

    A finite value always beats a non-finite one. Nothing beats a finite value
    except a larger finite value -- in particular, a NaN never wins, which a
    bare ``>`` comparison would get wrong in the opposite direction.
    """
    if not math.isfinite(candidate):
        return False
    if not math.isfinite(incumbent):
        return True
    return candidate > incumbent


def _parse_timestamp(raw: str, server_timezone: tzinfo) -> datetime | None:
    """Interpret a ``YYYYMMDDHHMMSS`` field as a timezone-aware UTC instant."""
    try:
        naive = datetime.strptime(raw, _TIMESTAMP_FORMAT)  # noqa: DTZ007 - naive by design; the zone is applied below
    except ValueError:
        # 14 ASCII digits that are not a real instant, e.g. month 99.
        return None
    try:
        return naive.replace(tzinfo=server_timezone).astimezone(UTC)
    except OverflowError, ValueError:
        # Converting an instant near year 0001 or 9999 out of a non-UTC zone
        # can run off the end of the representable range. An unusable timestamp
        # is a `None`, never an exception out of a parser the reader depends on.
        return None


def _decode_motion(info: str) -> MotionPayload | None:
    """Decode ``X Y W H``; return ``None`` if it is not four integers."""
    fields = info.split()
    if len(fields) != _MOTION_FIELDS:
        return None
    values: list[int] = []
    for field in fields:
        value = _parse_int(field)
        if value is None:
            return None
        values.append(value)
    return MotionPayload(x=values[0], y=values[1], width=values[2], height=values[3])


def _decode_classification(info: str) -> ClassificationPayload | None:
    """Decode ``LABEL n LABEL n ...`` into label-to-confidence pairs.

    Labels are carried through verbatim (AD-9). A trailing label with no
    number, or a number that will not parse, is skipped rather than discarding
    the pairs that did decode.
    """
    fields = info.split()
    classes: dict[str, float] = {}
    for index in range(0, len(fields) - 1, 2):
        label = fields[index]
        confidence = _parse_float(fields[index + 1])
        if confidence is None:
            continue
        classes[label] = confidence
    if not classes:
        return None
    return ClassificationPayload(classes=MappingProxyType(classes))


def _decode_trigger(info: str) -> TriggerPayload | None:
    """Decode a reason bitmask; return ``None`` if it is not an integer."""
    mask = _parse_int(info.strip())
    if mask is None:
        return None
    return TriggerPayload(mask=mask, reasons=decode_trigger_reasons(mask))


def _decode_error(info: str) -> ErrorPayload | None:
    """Decode ``code description``, tolerating a missing numeric code."""
    if not info:
        return None
    head, _, tail = info.partition(" ")
    code = _parse_int(head)
    if code is None:
        return ErrorPayload(code=None, description=info)
    return ErrorPayload(code=code, description=tail.strip())


def _decode_payload(event_type: str, info: str) -> EventPayload | None:
    """Dispatch to the decoder for one event type.

    An unrecognised type is not an error: it decodes to no payload and keeps
    its ``INFO`` verbatim, which is what makes a future server build additive
    rather than breaking.
    """
    if event_type == EVENT_MOTION:
        return _decode_motion(info)
    if event_type == EVENT_CLASSIFY:
        return _decode_classification(info)
    if event_type in _TRIGGER_EVENTS:
        return _decode_trigger(info)
    if event_type == EVENT_FILE:
        # The full remainder, spaces and all: capture paths contain them.
        return FilePayload(path=info) if info else None
    if event_type == EVENT_ERROR:
        return _decode_error(info)
    return None


def parse_event_line(line: str, *, server_timezone: tzinfo = UTC) -> StreamEvent | None:
    """Decode one event-stream record.

    Args:
        line: A single record with its CR terminator already removed.
        server_timezone: The timezone the server's wall-clock timestamps are
            expressed in. **[ASSUMPTION]** No SecuritySpy endpoint in the
            protocol research exposes the server's timezone, so this defaults
            to UTC and a consumer that knows better must say so.
            :attr:`StreamEvent.raw_timestamp` preserves the original string
            either way.

    Returns:
        The decoded event, or ``None`` when the record is blank or malformed.
        A malformed record is skipped, never raised: one bad line must not end
        a long-lived stream.

    """
    record = line.strip("\r\n")
    if not record.strip():
        return None
    fields = record.split(maxsplit=_MIN_FIELDS)
    if len(fields) < _MIN_FIELDS:
        _LOGGER.debug("Skipping event record with %d fields", len(fields))
        return None
    raw_timestamp, raw_number, raw_camera, event_type = fields[:_MIN_FIELDS]
    info = fields[_MIN_FIELDS] if len(fields) > _MIN_FIELDS else ""

    if len(raw_timestamp) != _TIMESTAMP_LENGTH:
        # The record contents are deliberately not logged: this is the one
        # place a mis-framed body would be echoed, and it may be anything.
        _LOGGER.debug("Skipping event record with a %d-character timestamp", len(raw_timestamp))
        return None
    event_number = _parse_int(raw_number)
    if event_number is None:
        _LOGGER.debug("Skipping event record with a non-numeric event number")
        return None

    # `X` -- or anything else non-numeric -- means "not camera-specific"
    # (§3.2). Such a record is delivered with `camera=None`, never dropped and
    # never attributed to a camera: `NULL` heartbeats arrive this way.
    camera = None if raw_camera == _CAMERA_NOT_SPECIFIC else _parse_int(raw_camera)

    payload = _decode_payload(event_type, info)
    if payload is None and _should_report(event_type):
        _LOGGER.debug("Event type %s carries no decoded payload", event_type)

    return StreamEvent(
        timestamp=_parse_timestamp(raw_timestamp, server_timezone),
        raw_timestamp=raw_timestamp,
        event_number=event_number,
        camera=camera,
        event_type=event_type,
        info=info,
        payload=payload,
        raw=record,
    )
