"""SecuritySpy protocol vocabulary: endpoints, permission bits and class names.

This module is the single home for anything that only exists because the
SecuritySpy wire protocol says so. It imports nothing from the rest of the
library so every other module can depend on it.
"""

from __future__ import annotations

import re
from datetime import timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "BACKOFF_INITIAL",
    "BACKOFF_JITTER",
    "BACKOFF_MAX",
    "BACKOFF_MULTIPLIER",
    "CAPTURE_FILTERS",
    "CAPTURE_FILTER_ALL",
    "CAPTURE_FILTER_ANIMAL",
    "CAPTURE_FILTER_CONTINUOUS",
    "CAPTURE_FILTER_HUMAN",
    "CAPTURE_FILTER_IMAGES",
    "CAPTURE_FILTER_MOTION",
    "CAPTURE_FILTER_MOVIES",
    "CAPTURE_FILTER_VEHICLE",
    "CAPTURE_TYPE_IMAGE",
    "CAPTURE_TYPE_MOVIE",
    "CAPTURE_TYPE_NAMES",
    "CLASS_ANIMAL",
    "CLASS_HUMAN",
    "CLASS_VEHICLE",
    "DEFAULT_DETECTION_DEBOUNCE",
    "DEFAULT_DETECTION_GAP",
    "DEFAULT_DETECTION_THRESHOLD",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "ENDPOINT_CAPTURE_LIST",
    "ENDPOINT_EVENT_STREAM",
    "ENDPOINT_PREFIX",
    "ENDPOINT_SYSTEM_INFO",
    "EVENT_ARM_A",
    "EVENT_ARM_C",
    "EVENT_ARM_M",
    "EVENT_CLASSIFY",
    "EVENT_CONFIGCHANGE",
    "EVENT_DISARM_A",
    "EVENT_DISARM_C",
    "EVENT_DISARM_M",
    "EVENT_ERROR",
    "EVENT_FILE",
    "EVENT_MOTION",
    "EVENT_MOTION_END",
    "EVENT_NULL",
    "EVENT_OFFLINE",
    "EVENT_ONLINE",
    "EVENT_STREAM_VERSION",
    "EVENT_TRIGGER_A",
    "EVENT_TRIGGER_M",
    "HEARTBEAT_INTERVAL",
    "HEARTBEAT_MISSES_BEFORE_LOSS",
    "MIN_SERVER_VERSION",
    "MIN_SERVER_VERSION_TEXT",
    "OBJECT_CLASS_BITS",
    "PERMISSION_NAMES",
    "PERM_AUDIORCV",
    "PERM_AUDIOSND",
    "PERM_CAMCONTROL",
    "PERM_FILEDEL",
    "PERM_FILES",
    "PERM_LIVEVIDEO",
    "PERM_PTZSET",
    "PERM_SCHED",
    "PERM_TRIGGER",
    "STREAM_MAX_RECORD_BYTES",
    "TRIGGER_REASON_NAMES",
    "capture_filter_for_class",
    "class_slug",
    "decode_object_classes",
    "decode_permissions",
    "decode_trigger_reasons",
]

#: SecuritySpy's default plain-HTTP web-server port.
DEFAULT_PORT: Final = 8000

#: Default total request timeout, in seconds. Every request carries one so a
#: wrong-host TLS handshake fails rather than hanging.
DEFAULT_TIMEOUT: Final = 30.0

#: All endpoints are prefixed ``++`` in external URLs (research §1). The web
#: client omits the prefix only because the server adds it for same-origin
#: requests; an external consumer must always send it.
ENDPOINT_PREFIX: Final = "++"

#: Server and camera inventory endpoint (research §10).
ENDPOINT_SYSTEM_INFO: Final = f"{ENDPOINT_PREFIX}systemInfo"

#: Long-lived event-stream endpoint (research §3). The response never ends.
ENDPOINT_EVENT_STREAM: Final = f"{ENDPOINT_PREFIX}eventStream"

#: Capture-history endpoint (research §4). One request covers many cameras.
ENDPOINT_CAPTURE_LIST: Final = f"{ENDPOINT_PREFIX}caplist"

#: The event-stream protocol version this library speaks. Sent as the
#: ``version`` query parameter; version 3 is the record format of research §3.2.
EVENT_STREAM_VERSION: Final = "3"

# [ASSUMPTION] PRD Open Q8: the architecture has not pinned the earliest
# sufficient 6.x release. 6.0 is the conservative floor -- the whole reference
# in `research/securityspy-api-reference.md` is "SecuritySpy 6.x". Narrow this
# once a specific minimum is confirmed.
#: Minimum supported server version, as an ordered numeric tuple.
MIN_SERVER_VERSION: Final[tuple[int, ...]] = (6, 0)

#: Human-readable form of :data:`MIN_SERVER_VERSION`, for error messages.
MIN_SERVER_VERSION_TEXT: Final = ".".join(str(part) for part in MIN_SERVER_VERSION)

# Per-camera permission bitmask (research §9, from the web client's js/script.js).
# The bits are non-contiguous, so they are transcribed rather than computed.
PERM_LIVEVIDEO: Final = 1  # bit 0  -- view live video
PERM_FILES: Final = 4  # bit 2  -- access captured files
PERM_FILEDEL: Final = 8  # bit 3  -- delete files
PERM_CAMCONTROL: Final = 64  # bit 6  -- camera control (incl. PTZ movement)
PERM_SCHED: Final = 128  # bit 7  -- arm/disarm, set schedules
PERM_PTZSET: Final = 256  # bit 8  -- save PTZ presets
PERM_AUDIORCV: Final = 512  # bit 9  -- receive audio
PERM_TRIGGER: Final = 1024  # bit 10 -- manually trigger
PERM_AUDIOSND: Final = 2048  # bit 11 -- send audio (two-way talk)

#: Mapping of permission bit value to a stable, snake_case permission name.
#: Exposed as a read-only view so a consumer cannot corrupt decoding globally.
PERMISSION_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        PERM_LIVEVIDEO: "live_video",
        PERM_FILES: "files",
        PERM_FILEDEL: "file_delete",
        PERM_CAMCONTROL: "camera_control",
        PERM_SCHED: "schedule",
        PERM_PTZSET: "ptz_preset_set",
        PERM_AUDIORCV: "audio_receive",
        PERM_TRIGGER: "trigger",
        PERM_AUDIOSND: "audio_send",
    }
)

# Event-stream event types (research §3.3). These are constants for convenience,
# never an enumeration: an event type this library has never seen must carry
# through to the consumer as an ordinary string rather than being rejected.
EVENT_MOTION: Final = "MOTION"
EVENT_MOTION_END: Final = "MOTION_END"  # unreliable; see research §3.5
EVENT_CLASSIFY: Final = "CLASSIFY"
EVENT_TRIGGER_M: Final = "TRIGGER_M"
EVENT_TRIGGER_A: Final = "TRIGGER_A"
EVENT_FILE: Final = "FILE"
EVENT_ARM_C: Final = "ARM_C"
EVENT_DISARM_C: Final = "DISARM_C"
EVENT_ARM_M: Final = "ARM_M"
EVENT_DISARM_M: Final = "DISARM_M"
EVENT_ARM_A: Final = "ARM_A"
EVENT_DISARM_A: Final = "DISARM_A"
EVENT_ONLINE: Final = "ONLINE"
EVENT_OFFLINE: Final = "OFFLINE"
EVENT_ERROR: Final = "ERROR"
EVENT_CONFIGCHANGE: Final = "CONFIGCHANGE"
EVENT_NULL: Final = "NULL"  # heartbeat, every 10 s exactly, on camera `X`

# Trigger reason bitmask (research §3.4). Bits 0-16 are transcribed rather than
# computed: the meanings are not contiguous families, and bits 7-16 only ever
# appear when the corresponding `mcTriggerMotionH/V/A` settings are enabled, so
# on a default install only bit 0 is ever seen.
#: Mapping of trigger-reason bit value to a stable, snake_case reason name.
#: Exposed as a read-only view so a consumer cannot corrupt decoding globally.
TRIGGER_REASON_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        1 << 0: "video_motion",
        1 << 1: "audio_detection",
        1 << 2: "applescript",
        1 << 3: "camera_event",
        1 << 4: "web_server_event",
        1 << 5: "other_camera",
        1 << 6: "manual_trigger",
        1 << 7: "human_movement",
        1 << 8: "vehicle_movement",
        1 << 9: "homekit_event",
        1 << 10: "animal_movement",
        1 << 11: "human_arrival",
        1 << 12: "human_departure",
        1 << 13: "vehicle_arrival",
        1 << 14: "vehicle_departure",
        1 << 15: "animal_arrival",
        1 << 16: "animal_departure",
    }
)

#: Nominal interval between ``NULL`` heartbeats, in seconds (research §3.3).
HEARTBEAT_INTERVAL: Final = 10.0

#: Missed heartbeats tolerated before the connection is declared lost (AD-11).
#: The watchdog measures socket silence rather than counting ``NULL`` records,
#: because real traffic proves liveness just as well and a busy camera must not
#: false-positive.
HEARTBEAT_MISSES_BEFORE_LOSS: Final = 3

#: First reconnect delay, in seconds.
BACKOFF_INITIAL: Final = 1.0

#: Ceiling on the reconnect delay, in seconds. Reconnection is indefinite
#: (AD-11), so the delay is capped rather than the attempt count.
BACKOFF_MAX: Final = 300.0

#: Growth factor applied to the reconnect delay after each failed attempt.
BACKOFF_MULTIPLIER: Final = 2.0

#: Fraction of the reconnect delay removed at random, so a server restart does
#: not bring every client back in lockstep.
BACKOFF_JITTER: Final = 0.25

#: Cap on a single unterminated event-stream record, in bytes. A record is a
#: short line; anything larger means the CR framing is gone (a wrong endpoint,
#: an error page) and the buffer must be dropped rather than grown without
#: bound inside a long-running process.
STREAM_MAX_RECORD_BYTES: Final = 64 * 1024

# Built-in object classes. The classification vocabulary is deliberately OPEN
# (AD-9): these are constants for convenience, never an enumeration, and an
# unknown class carries through unchanged.
CLASS_HUMAN: Final = "human"
CLASS_VEHICLE: Final = "vehicle"
CLASS_ANIMAL: Final = "animal"

# Detection-episode reduction defaults (research §3.5). `CLASSIFY` is a
# per-frame inference stream -- 191 records on one camera in 95 s, 0-2 s apart,
# with confidence swinging 8 -> 97 between adjacent frames for a single subject
# -- so a consumer has to reduce it before it means anything. These three values
# are the tuning vocabulary that reduction is driven by; they live here with the
# rest of the protocol vocabulary rather than inside the reducer, because the
# reducer takes every one of them as an injected, per-camera-per-class value
# (AD-3, FR-8) and bakes none of them in.
#
# [ASSUMPTION] All three are provisional (PRD Open Q5). No measurement in the
# protocol research establishes them; they are starting points chosen to be
# defensible, not values verified against a real installation. Treat a consumer
# that needs different behaviour as expected, not as a misconfiguration.

#: Minimum confidence percentage a `CLASSIFY` signal must carry to count
#: towards opening an episode. **[ASSUMPTION]**, see above.
DEFAULT_DETECTION_THRESHOLD: Final = 70.0

#: Consecutive at-or-above-threshold signals required before an episode opens.
#: Guards against the single stray high-confidence frame that §3.5's sequence
#: shows is routine. **[ASSUMPTION]**, see above.
DEFAULT_DETECTION_DEBOUNCE: Final = 3

#: Silence after the last qualifying signal before an episode is considered
#: ended. Inactivity is the only usable end signal: `MOTION_END` is unreliable
#: (467 `MOTION` records and 0 ends on camera 10, §3.5). A `timedelta` rather
#: than a bare number of seconds, so that passing this constant straight into
#: the field it is the default for is the thing that works, not the thing that
#: raises. **[ASSUMPTION]**, see above.
DEFAULT_DETECTION_GAP: Final = timedelta(seconds=30)

# `++caplist?filter=` values (research §4.2, from the web client's `capFilter`
# control). The server does the class filtering itself, so "when was a human
# last seen" is one request with `filter=5` -- never a `filter=0` fetch of the
# whole day's history followed by a local bitmask scan.
CAPTURE_FILTER_ALL: Final = 0  # all files
CAPTURE_FILTER_IMAGES: Final = 1  # all images
CAPTURE_FILTER_MOVIES: Final = 2  # all movies
CAPTURE_FILTER_CONTINUOUS: Final = 3  # continuous-capture movies
CAPTURE_FILTER_MOTION: Final = 4  # motion-capture movies
CAPTURE_FILTER_HUMAN: Final = 5  # human motion-capture movies
CAPTURE_FILTER_VEHICLE: Final = 6  # vehicle motion-capture movies
CAPTURE_FILTER_ANIMAL: Final = 7  # animal motion-capture movies

#: Every ``filter`` value SecuritySpy defines. The server is not documented to
#: validate the parameter, and a value it ignores returns the whole history
#: while looking like a narrow query, so an unknown value is rejected here.
CAPTURE_FILTERS: Final[frozenset[int]] = frozenset(
    {
        CAPTURE_FILTER_ALL,
        CAPTURE_FILTER_IMAGES,
        CAPTURE_FILTER_MOVIES,
        CAPTURE_FILTER_CONTINUOUS,
        CAPTURE_FILTER_MOTION,
        CAPTURE_FILTER_HUMAN,
        CAPTURE_FILTER_VEHICLE,
        CAPTURE_FILTER_ANIMAL,
    }
)

# `caplist.t` -- the capture's media type (research §4.1).
#
# ⚠️ These must NEVER be shared with `clip.movieType` / `cliplist.t`, where the
# same letter means Motion Capture (0) vs Continuous Capture (1) (research
# §4b.3). Same letter, different meaning: no enumeration, mapping or constant
# name may be reused across the two, which is also why `Capture.capture_type`
# stays a bare `int` rather than becoming an enum a later story could reach for.
CAPTURE_TYPE_MOVIE: Final = 1
CAPTURE_TYPE_IMAGE: Final = 2

#: Mapping of ``caplist.t`` value to a stable, snake_case media-type name.
#: Exposed as a read-only view so a consumer cannot corrupt decoding globally.
#: An unrecognised value has no name and is carried through as the raw integer.
CAPTURE_TYPE_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        CAPTURE_TYPE_MOVIE: "movie",
        CAPTURE_TYPE_IMAGE: "image",
    }
)

#: Mapping of ``caplist.o`` classification bit value to an object-class name
#: (research §4.1). The persisted counterpart of the transient stream signal.
#: Exposed as a read-only view so a consumer cannot corrupt decoding globally.
OBJECT_CLASS_BITS: Final[Mapping[int, str]] = MappingProxyType(
    {
        1: CLASS_HUMAN,
        2: CLASS_VEHICLE,
        4: CLASS_ANIMAL,
    }
)

# The server offers a `filter` value for exactly these three classes. The open
# vocabulary rule (AD-9) governs labels arriving *from* the server; it cannot
# conjure a server-side scan that does not exist, so an unfilterable class is a
# caller mistake rather than something to emulate locally.
_CLASS_CAPTURE_FILTERS: Final[Mapping[str, int]] = MappingProxyType(
    {
        CLASS_HUMAN: CAPTURE_FILTER_HUMAN,
        CLASS_VEHICLE: CAPTURE_FILTER_VEHICLE,
        CLASS_ANIMAL: CAPTURE_FILTER_ANIMAL,
    }
)

_SLUG_INVALID = re.compile(r"[^a-z0-9]+")


def decode_permissions(mask: int) -> frozenset[str]:
    """Decode a per-camera ``permissions`` bitmask into permission names.

    Unknown bits are ignored rather than rejected: the server may grow new ones.
    A negative mask is treated as "no permissions": Python's ints are of
    infinite width, so ``-1 & bit`` would otherwise grant every permission. A
    non-integer likewise decodes to no permissions rather than raising.

    Args:
        mask: The raw ``permissions`` integer from the API.

    Returns:
        The set of granted permission names.

    """
    # Exported helper: degrade like class_slug() rather than raising a bare
    # TypeError out of the public surface. The cast widens the static type so
    # the runtime check is not eliminated as dead. `bool` is excluded because
    # True would otherwise decode as mask 1.
    if not isinstance(cast("object", mask), int) or isinstance(mask, bool):
        return frozenset()
    if mask < 0:
        return frozenset()
    return frozenset(name for bit, name in PERMISSION_NAMES.items() if mask & bit)


def decode_trigger_reasons(mask: int) -> frozenset[str]:
    """Decode a ``TRIGGER_M`` / ``TRIGGER_A`` reason bitmask into reason names.

    Degrades exactly like :func:`decode_permissions`: unknown bits are ignored
    because the server may grow new ones, a negative mask decodes to nothing
    (Python ints are of infinite width, so ``-1 & bit`` would otherwise report
    every reason), and a non-integer decodes to nothing rather than raising.

    Args:
        mask: The raw reason bitmask from the event's ``INFO`` field.

    Returns:
        The set of reason names the server signalled.

    """
    # Exported helper: degrade rather than raising a bare TypeError out of the
    # public surface. The cast widens the static type so the runtime check is
    # not eliminated as dead. `bool` is excluded because True would otherwise
    # decode as mask 1.
    if not isinstance(cast("object", mask), int) or isinstance(mask, bool):
        return frozenset()
    if mask < 0:
        return frozenset()
    return frozenset(name for bit, name in TRIGGER_REASON_NAMES.items() if mask & bit)


def decode_object_classes(mask: int) -> frozenset[str]:
    """Decode a persisted ``caplist.o`` classification bitmask into class names.

    Degrades exactly like :func:`decode_permissions`: unknown bits are ignored
    because the server may grow new ones, a negative mask decodes to nothing
    (Python ints are of infinite width, so ``-1 & bit`` would otherwise report
    every class), and a non-integer decodes to nothing rather than raising.

    A mask of ``0`` -- and an absent or null ``o`` field, which the caller
    passes through as ``0`` -- yields an empty frozenset, never ``None``.

    Args:
        mask: The raw ``o`` bitmask from a capture entry.

    Returns:
        The set of object classes the server recorded against the capture.

    """
    # Exported helper: degrade rather than raising a bare TypeError out of the
    # public surface. The cast widens the static type so the runtime check is
    # not eliminated as dead. `bool` is excluded because True would otherwise
    # decode as mask 1.
    if not isinstance(cast("object", mask), int) or isinstance(mask, bool):
        return frozenset()
    if mask < 0:
        return frozenset()
    return frozenset(name for bit, name in OBJECT_CLASS_BITS.items() if mask & bit)


def capture_filter_for_class(name: str) -> int:
    """Return the ``++caplist?filter=`` value that selects one object class.

    Args:
        name: An object-class name. It is normalized with :func:`class_slug`,
            so ``"Human"`` and ``"human"`` are the same request.

    Raises:
        ValueError: The server has no server-side filter for that class. The
            message names the three classes it does have, because there is no
            correct local fallback: fetching everything and filtering on the
            ``o`` bitmask is exactly the transfer cost this endpoint exists to
            avoid.

    Returns:
        The ``filter`` value to send.

    """
    filter_value = _CLASS_CAPTURE_FILTERS.get(class_slug(name))
    if filter_value is None:
        supported = ", ".join(sorted(_CLASS_CAPTURE_FILTERS))
        message = (
            f"SecuritySpy has no capture filter for that object class; use one of: {supported}"
        )
        raise ValueError(message)
    return filter_value


def class_slug(name: str) -> str:
    """Normalize an object-class name into a stable key (AD-9).

    This is the only path a class name may take into a permanent key such as a
    unique ID or a storage key. The result contains only ``[a-z0-9_]``.

    Args:
        name: An arbitrary object-class name as it came off the wire.

    Returns:
        The normalized slug, or ``"unknown"`` when nothing usable remains.

    """
    # The classification vocabulary is open and comes off the wire, so a
    # non-string must degrade rather than raise out of a public helper. The cast
    # widens the static type so the runtime check is not eliminated as dead.
    if not isinstance(cast("object", name), str):
        return "unknown"
    slug = _SLUG_INVALID.sub("_", name.strip().lower()).strip("_")
    return slug or "unknown"
