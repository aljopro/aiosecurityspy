"""SecuritySpy protocol vocabulary: endpoints, permission bits and class names.

This module is the single home for anything that only exists because the
SecuritySpy wire protocol says so. It imports nothing from the rest of the
library so every other module can depend on it.
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "BACKOFF_INITIAL",
    "BACKOFF_JITTER",
    "BACKOFF_MAX",
    "BACKOFF_MULTIPLIER",
    "CLASS_ANIMAL",
    "CLASS_HUMAN",
    "CLASS_VEHICLE",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
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
    "class_slug",
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
