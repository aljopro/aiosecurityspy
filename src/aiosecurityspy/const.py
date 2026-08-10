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
    "CLASS_ANIMAL",
    "CLASS_HUMAN",
    "CLASS_VEHICLE",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "ENDPOINT_PREFIX",
    "ENDPOINT_SYSTEM_INFO",
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
    "class_slug",
    "decode_permissions",
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
