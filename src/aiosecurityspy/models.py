"""Frozen, fully-typed data models decoded from SecuritySpy payloads (AD-15).

Raw dictionaries never cross the library boundary: every public method returns
one of these models. Decoding lives here, not in the client, so a payload can be
decoded in a test with no network involved at all.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

from .const import (
    ARM_OVERRIDE_ARMED_1_HOUR,
    ARM_OVERRIDE_ARMED_2_HOURS,
    ARM_OVERRIDE_ARMED_3_HOURS,
    ARM_OVERRIDE_ARMED_4_HOURS,
    ARM_OVERRIDE_ARMED_5_HOURS,
    ARM_OVERRIDE_ARMED_6_HOURS,
    ARM_OVERRIDE_ARMED_UNTIL_NEXT,
    ARM_OVERRIDE_DISARMED_1_HOUR,
    ARM_OVERRIDE_DISARMED_2_HOURS,
    ARM_OVERRIDE_DISARMED_3_HOURS,
    ARM_OVERRIDE_DISARMED_4_HOURS,
    ARM_OVERRIDE_DISARMED_5_HOURS,
    ARM_OVERRIDE_DISARMED_6_HOURS,
    ARM_OVERRIDE_DISARMED_UNTIL_NEXT,
    ARM_OVERRIDE_NONE,
    ARM_OVERRIDE_UNCHANGED,
    CAPTURE_TYPE_MOVIE,
    CAPTURE_TYPE_NAMES,
    MIN_SERVER_VERSION,
    MIN_SERVER_VERSION_TEXT,
    MODE_ACTIONS,
    MODE_CONTINUOUS,
    MODE_MOTION,
    PERMISSION_NAMES,
    decode_object_classes,
    decode_permissions,
)
from .exceptions import SecuritySpyPermissionError, SecuritySpyUnsupportedVersionError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import tzinfo

__all__ = [
    "ARM_OVERRIDES",
    "ArmOverride",
    "Camera",
    "CameraScheduleAssignment",
    "CameraSettings",
    "CameraSettingsPatch",
    "Capture",
    "CaptureModes",
    "ServerInfo",
    "arm_override",
    "require_permission",
]

_LOGGER: Final = logging.getLogger(__name__)

_TRUE_TOKENS: Final = frozenset({"1", "true", "yes", "on", "y"})
_FALSE_TOKENS: Final = frozenset({"0", "false", "no", "off", "n", ""})


def _as_str(value: object) -> str | None:
    """Coerce an API value to a non-empty string, or ``None``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, int | float):
        return str(value)
    return None


def _as_int(value: object) -> int | None:
    """Coerce an API value to an ``int``, or ``None`` when it will not parse.

    Deliberately strict, because the result becomes a stable key: a JSON
    ``true`` must not alias camera 1, ``2.9`` must not silently become camera 2,
    and Python's underscore and non-ASCII digit literals (``"1_0"`` -> 10,
    ``"²"``) must not be honoured for wire data.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # `json.loads` accepts NaN/Infinity literals; `int()` raises on both.
        return int(value) if math.isfinite(value) and value.is_integer() else None
    if isinstance(value, str):
        return _parse_ascii_int(value.strip())
    return None


def _parse_ascii_int(text: str) -> int | None:
    """Parse an optionally-signed ASCII decimal integer, or return ``None``."""
    digits = text[1:] if text[:1] in {"+", "-"} else text
    if not digits or not digits.isascii() or not digits.isdigit():
        return None
    return int(text)


def _as_bool(value: object, *, default: bool = False) -> bool:
    """Coerce an API value to a ``bool``.

    SecuritySpy is inconsistent: the same concept arrives as JSON ``true``, the
    string ``"yes"``, or the integer ``1`` depending on the endpoint.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE_TOKENS:
            return True
        if token in _FALSE_TOKENS:
            return False
    if value is not None:
        # Every other decode failure in this module is logged; a camera silently
        # reported as disconnected because of an unrecognised token is exactly
        # the bug that costs hours to find. The value itself is not logged.
        _LOGGER.debug(
            "Unrecognised boolean token of type %s; using the default", type(value).__name__
        )
    return default


def _parse_version(text: str) -> tuple[int, ...] | None:
    """Parse a dotted version string into an ordered numeric tuple.

    Comparison must be numeric component-by-component so that ``6.20`` sorts
    above ``6.9``; a lexical comparison would get that backwards.
    """
    parts: list[int] = []
    for raw in text.strip().split("."):
        # Tolerate a trailing build suffix such as "6.20b3".
        digits = ""
        for char in raw:
            # ASCII-only: `"²".isdigit()` is True but `int("²")` raises, which
            # would let a bare ValueError escape a public method.
            if not (char.isascii() and char.isdigit()):
                break
            digits += char
        if not digits:
            return None
        parts.append(int(digits))
    if not parts:
        return None
    # Pad so a server reporting a bare major version ("6") compares as (6, 0)
    # rather than sorting below the floor on length alone.
    while len(parts) < len(MIN_SERVER_VERSION):
        parts.append(0)
    return tuple(parts)


#: ``caplist.f`` is a folder date, always ``YYYY-MM-DD`` (research §4.1).
_FOLDER_DATE_FORMAT: Final = "%Y-%m-%d"


def _parse_capture_start(
    folder_date: str, seconds: object, server_timezone: tzinfo
) -> datetime | None:
    """Reconstruct a capture's absolute start instant, or return ``None``.

    ``caplist`` never sends an absolute time: it sends the folder date ``f``
    and ``s``, seconds since *local* midnight (research §4.1, ``63319`` ->
    17:35:19). Absent or undecodable means ``None`` -- never epoch, never zero
    (AD-15).

    ``s`` is a *wall-clock* second-of-day, so the offset is added to a
    zone-aware local midnight: adding a ``timedelta`` to an aware ``datetime``
    is wall-clock arithmetic in Python, which is exactly the semantics ``s``
    has. It is added rather than divided into hour/minute/second so that a
    value at or beyond ``86400`` -- which the field's meaning does not permit,
    but a misbehaving server could still send -- rolls into the next day
    instead of raising out of a ``datetime(hour=s // 3600, ...)``.

    **[ASSUMPTION]** A wall-clock second-of-day cannot express which side of a
    DST fall-back a capture fell on, and names an instant that does not exist
    on a spring-forward day. ``fold=0`` is used, so on the one ambiguous local
    hour per year the earlier (pre-transition) instant is chosen, and on the
    skipped hour two distinct captures can reconstruct to the same UTC instant.
    Nothing in ``caplist`` carries the missing bit; recovering it would need an
    absolute time the endpoint does not send. This is recorded in the ledger
    alongside the unresolved server timezone.
    """
    if not folder_date.isascii():
        # `strptime`'s `\d` is Unicode-aware and `int()` accepts non-ASCII
        # digits, so "٢٠٢٦-٠٨-٠٩" would otherwise parse as a real date.
        return None
    try:
        folder = datetime.strptime(folder_date, _FOLDER_DATE_FORMAT).date()  # noqa: DTZ007 - a bare date; the zone is applied below
    except ValueError:
        return None
    offset = _as_int(seconds)
    if offset is None or offset < 0:
        return None
    try:
        naive = datetime.combine(folder, time(), tzinfo=server_timezone)
        return (naive + timedelta(seconds=offset)).astimezone(UTC)
    except OverflowError, ValueError, OSError:
        # Converting an instant near year 0001 or 9999 out of a non-UTC zone can
        # run off the end of the representable range. An unusable time is a
        # `None`, never an exception out of a public method.
        return None


def _capture_path(camera: int, folder_date: str, filename: str) -> str:
    """Build the ``<camera>/<folderDate>/<filename>`` media triple, or ``""``.

    The components come off the wire and a filename is user-influenced (it
    encodes the camera's name), so a value carrying a separator or a ``..``
    segment would let a consumer that concatenates this into a media URL address
    something outside the capture it describes. Such an entry gets an empty path
    rather than a plausible-looking one: the capture is still returned, but it
    has no addressable file. The result is *not* URL-encoded -- real filenames
    contain spaces -- so a consumer must quote it before use.
    """
    if not folder_date or not filename:
        return ""
    if any(
        separator in component for component in (folder_date, filename) for separator in ("/", "\\")
    ) or ".." in (folder_date, filename):
        _LOGGER.debug("Capture on camera %s has an unusable file path; omitting it", camera)
        return ""
    return f"{camera}/{folder_date}/{filename}"


def _as_mapping(value: object) -> dict[str, object] | None:
    """Return ``value`` as a string-keyed mapping, or ``None``."""
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}  # pyright: ignore[reportUnknownVariableType]
    return None


def _as_arm_mode(value: object) -> bool:
    """Coerce a ``++systemInfo`` ``*-mode`` field to "this mode is armed".

    Research §10 records the field's *meaning* ("armed/disarmed per mode") but
    not its wire spelling, which has been seen as a boolean and as an integer.
    The two obvious word forms are decoded here rather than added to
    :func:`_as_bool`'s global token sets, where ``"armed"`` would mean nothing
    and ``"disarmed"`` would be an unexplained falsy token for every other
    field in the library.
    """
    if isinstance(value, str):
        word = value.strip().lower()
        if word == "armed":
            return True
        if word == "disarmed":
            return False
        if word not in _TRUE_TOKENS and word not in _FALSE_TOKENS:
            # Falling through to `_as_bool` yields False -- "disarmed" -- for
            # any spelling neither function knows, and guessing "disarmed" for
            # an arm-state field is the wrong way to be wrong. The token is
            # logged so an unrecorded spelling is discoverable rather than
            # silent; `*-mode` comes from `++systemInfo`, which carries no
            # credential, so the value itself is safe to log (research §10).
            _LOGGER.debug("Unrecognised arm-mode token %r; treating it as disarmed", value)
    return _as_bool(value)


@dataclass(frozen=True, slots=True)
class CaptureModes:
    """The three independent capture modes of one camera (research §5.1).

    Continuous capture, motion capture and actions are **independent
    booleans**, not a single armed/disarmed state: all eight combinations are
    legal, including all-false. That is precisely why arming is expressed as a
    concatenated letter string rather than as one enumerated state.
    """

    continuous: bool = False
    motion: bool = False
    actions: bool = False

    @property
    def mode_string(self) -> str:
        """The ``++ssSetSchedule?mode=`` value for these three booleans.

        Letters are always emitted in ``C``, ``M``, ``A`` order so the request
        is a function of the *set* of modes rather than of construction order.
        All three false yields ``""`` -- an empty ``mode`` is the instruction
        "disarm all three", not a missing value.
        """
        return (
            (MODE_CONTINUOUS if self.continuous else "")
            + (MODE_MOTION if self.motion else "")
            + (MODE_ACTIONS if self.actions else "")
        )

    @classmethod
    def from_api(cls, payload: dict[str, object]) -> CaptureModes:
        """Decode the ``cc-mode`` / ``mc-mode`` / ``a-mode`` fields of a camera.

        Args:
            payload: A single ``camera`` object from ``++systemInfo``.

        Returns:
            The decoded modes. An absent field decodes to ``False``: a camera
            that does not report a mode is not armed for it.

        """
        return cls(
            continuous=_as_arm_mode(payload.get("cc-mode")),
            motion=_as_arm_mode(payload.get("mc-mode")),
            actions=_as_arm_mode(payload.get("a-mode")),
        )

    # No hand-written `__repr__`: every field is a `bool`, so the dataclass's
    # own repr cannot carry a credential and a hand-written copy of it would
    # only be one more thing to keep in sync. The custom reprs elsewhere in
    # this module exist because they *suppress* something.


@dataclass(frozen=True, slots=True)
class CameraScheduleAssignment:
    """A camera's current schedule ids and schedule overrides (research §10).

    Read-only data (AD-7). Schedules are user-definable and this library has no
    method that reassigns one: ``schedule=`` is never sent to
    ``++ssSetSchedule``. Only the transient, bounded *override* is writable.
    """

    continuous_schedule_id: int | None = None
    motion_schedule_id: int | None = None
    actions_schedule_id: int | None = None
    continuous_override: int | None = None
    motion_override: int | None = None
    actions_override: int | None = None

    @classmethod
    def from_api(cls, payload: dict[str, object]) -> CameraScheduleAssignment:
        """Decode the ``*-schedule-id`` and ``*-schedule-override`` fields.

        Args:
            payload: A single ``camera`` object from ``++systemInfo``.

        Returns:
            The decoded assignment. An absent or unparseable field is ``None``,
            never ``0`` -- schedule ``0`` is a real, built-in schedule.

        """
        return cls(
            continuous_schedule_id=_as_int(payload.get("cc-schedule-id")),
            motion_schedule_id=_as_int(payload.get("mc-schedule-id")),
            actions_schedule_id=_as_int(payload.get("a-schedule-id")),
            continuous_override=_as_int(payload.get("cc-schedule-override")),
            motion_override=_as_int(payload.get("mc-schedule-override")),
            actions_override=_as_int(payload.get("a-schedule-override")),
        )

    # No hand-written `__repr__`: every field is an `int | None`, so the
    # dataclass's own repr cannot carry a credential. See `CaptureModes`.


@dataclass(frozen=True, slots=True)
class ArmOverride:
    """One ``++ssSetSchedule?override=`` value and what it actually does.

    An override is **transient and bounded**: it suspends the camera's schedule
    for a stated duration and then the schedule resumes. It is not a permanent
    arm/disarm, which is why the duration is typed data here rather than a
    number a call site has to know.
    """

    value: int
    label: str
    #: Whether the override arms or disarms, or ``None`` when it does neither
    #: (``-1`` "unchanged" and ``0`` "none" are not arm instructions).
    armed: bool | None
    #: How long the override lasts, or ``None`` when it is unbounded in clock
    #: time -- either because it runs until the next scheduled event or because
    #: it is not an override at all.
    duration: timedelta | None
    #: Whether the override ends at the camera's next scheduled event.
    until_next_scheduled: bool = False

    def __repr__(self) -> str:
        """Return a representation that cannot carry credentials."""
        return (
            f"ArmOverride(value={self.value}, label={self.label!r}, armed={self.armed}, "
            f"duration={self.duration!r}, until_next_scheduled={self.until_next_scheduled})"
        )


def _bounded(value: int, label: str, *, armed: bool, hours: int) -> ArmOverride:
    """Build one duration-bounded :class:`ArmOverride`."""
    return ArmOverride(value=value, label=label, armed=armed, duration=timedelta(hours=hours))


#: Every ``override`` value SecuritySpy publishes (research §5.2), keyed by the
#: integer sent on the wire. The table stops at ``14``: there is no documented
#: value ``15``, so this library does not define one and
#: :func:`arm_override` rejects it rather than guessing.
#: Exposed as a read-only view so a consumer cannot corrupt the table globally.
ARM_OVERRIDES: Final[Mapping[int, ArmOverride]] = MappingProxyType(
    {
        ARM_OVERRIDE_UNCHANGED: ArmOverride(
            value=ARM_OVERRIDE_UNCHANGED, label="Unchanged", armed=None, duration=None
        ),
        ARM_OVERRIDE_NONE: ArmOverride(
            value=ARM_OVERRIDE_NONE, label="None", armed=None, duration=None
        ),
        ARM_OVERRIDE_DISARMED_UNTIL_NEXT: ArmOverride(
            value=ARM_OVERRIDE_DISARMED_UNTIL_NEXT,
            label="Disarmed Until Next Scheduled Event",
            armed=False,
            duration=None,
            until_next_scheduled=True,
        ),
        ARM_OVERRIDE_ARMED_UNTIL_NEXT: ArmOverride(
            value=ARM_OVERRIDE_ARMED_UNTIL_NEXT,
            label="Armed Until Next Scheduled Event",
            armed=True,
            duration=None,
            until_next_scheduled=True,
        ),
        ARM_OVERRIDE_DISARMED_1_HOUR: _bounded(
            ARM_OVERRIDE_DISARMED_1_HOUR, "Disarmed For 1 Hour", armed=False, hours=1
        ),
        ARM_OVERRIDE_ARMED_1_HOUR: _bounded(
            ARM_OVERRIDE_ARMED_1_HOUR, "Armed For 1 Hour", armed=True, hours=1
        ),
        ARM_OVERRIDE_DISARMED_2_HOURS: _bounded(
            ARM_OVERRIDE_DISARMED_2_HOURS, "Disarmed For 2 Hours", armed=False, hours=2
        ),
        ARM_OVERRIDE_ARMED_2_HOURS: _bounded(
            ARM_OVERRIDE_ARMED_2_HOURS, "Armed For 2 Hours", armed=True, hours=2
        ),
        ARM_OVERRIDE_DISARMED_3_HOURS: _bounded(
            ARM_OVERRIDE_DISARMED_3_HOURS, "Disarmed For 3 Hours", armed=False, hours=3
        ),
        ARM_OVERRIDE_ARMED_3_HOURS: _bounded(
            ARM_OVERRIDE_ARMED_3_HOURS, "Armed For 3 Hours", armed=True, hours=3
        ),
        ARM_OVERRIDE_DISARMED_4_HOURS: _bounded(
            ARM_OVERRIDE_DISARMED_4_HOURS, "Disarmed For 4 Hours", armed=False, hours=4
        ),
        ARM_OVERRIDE_ARMED_4_HOURS: _bounded(
            ARM_OVERRIDE_ARMED_4_HOURS, "Armed For 4 Hours", armed=True, hours=4
        ),
        ARM_OVERRIDE_DISARMED_5_HOURS: _bounded(
            ARM_OVERRIDE_DISARMED_5_HOURS, "Disarmed For 5 Hours", armed=False, hours=5
        ),
        ARM_OVERRIDE_ARMED_5_HOURS: _bounded(
            ARM_OVERRIDE_ARMED_5_HOURS, "Armed For 5 Hours", armed=True, hours=5
        ),
        ARM_OVERRIDE_DISARMED_6_HOURS: _bounded(
            ARM_OVERRIDE_DISARMED_6_HOURS, "Disarmed For 6 Hours", armed=False, hours=6
        ),
        ARM_OVERRIDE_ARMED_6_HOURS: _bounded(
            ARM_OVERRIDE_ARMED_6_HOURS, "Armed For 6 Hours", armed=True, hours=6
        ),
    }
)


def arm_override(value: int) -> ArmOverride:
    """Look up the typed record for one ``override`` value.

    Args:
        value: An ``override`` id. Use the ``ARM_OVERRIDE_*`` constants.

    Raises:
        ValueError: The value is not one research §5.2 publishes. Sending an
            undocumented override would be guessing at server behaviour on a
            write, so it is refused here rather than on the wire. The message
            names the supported range and does not quote the offending value.

    Returns:
        The typed override record, including its bounded duration.

    """
    # A public entry point: the static type says `int`, but a `bool` would
    # otherwise look up override 1 ("disarmed until next scheduled event") for
    # `True`. The cast widens the static type so the runtime check is not
    # eliminated as dead.
    if isinstance(cast("object", value), int) and not isinstance(value, bool):
        record = ARM_OVERRIDES.get(value)
        if record is not None:
            return record
    message = (
        "override must be one of the ARM_OVERRIDE_* values "
        f"({ARM_OVERRIDE_UNCHANGED} to {ARM_OVERRIDE_ARMED_6_HOURS})"
    )
    raise ValueError(message)


#: The permission names `require_permission` accepts, derived from the single
#: source in `const.py` so the two can never drift apart.
_PERMISSION_NAME_SET: Final = frozenset(PERMISSION_NAMES.values())
_PERMISSION_NAME_LIST: Final = ", ".join(sorted(_PERMISSION_NAME_SET))


def require_permission(camera: Camera, permission: str) -> None:
    """Raise unless ``camera`` grants ``permission``.

    A pure, synchronous guard, so a consumer can refuse an arming or settings
    call without a round trip. The client methods deliberately do **not** call
    it themselves: this library holds no camera inventory and must not fetch
    one to serve a write.

    Args:
        camera: The camera the request targets.
        permission: A permission name from
            :data:`~aiosecurityspy.PERMISSION_NAMES`, such as ``"schedule"``.

    Raises:
        ValueError: ``permission`` is not a name this library decodes. A
            misspelling would otherwise deny every camera unconditionally,
            since no camera can grant a name that no bit maps to -- a caller
            bug wearing a permission failure's clothes.
        SecuritySpyPermissionError: The camera does not grant the permission.
            The error carries the permission name and the camera number.

    """
    if permission not in _PERMISSION_NAME_SET:
        message = f"unknown permission name {permission!r}; expected one of {_PERMISSION_NAME_LIST}"
        raise ValueError(message)
    if not camera.has_permission(permission):
        raise SecuritySpyPermissionError(permission, camera.number)


@dataclass(frozen=True, slots=True)
class Camera:
    """A single camera as reported by ``++systemInfo``.

    The camera ``number`` is the stable key; names are user-editable.
    ``connected``, ``enabled`` and ``online`` are three distinct states in
    SecuritySpy and are not interchangeable.
    """

    number: int
    name: str
    connected: bool
    enabled: bool
    permissions: int
    #: The three independent capture modes (research §5.1, §10). Defaulted so
    #: a camera entry that reports no ``*-mode`` field is simply unarmed.
    capture_modes: CaptureModes = field(default_factory=CaptureModes)
    #: Read-only schedule ids and overrides (research §10, AD-7).
    schedules: CameraScheduleAssignment = field(default_factory=CameraScheduleAssignment)

    @classmethod
    def from_api(cls, payload: dict[str, object]) -> Camera | None:
        """Decode one camera entry.

        Args:
            payload: A single ``camera`` object from the API.

        Returns:
            The decoded camera, or ``None`` when the entry has no usable
            camera number and must be skipped.

        """
        number = _as_int(payload.get("number"))
        if number is None:
            _LOGGER.debug("Skipping camera entry with a non-numeric camera number")
            return None
        return cls(
            number=number,
            name=_as_str(payload.get("name")) or f"Camera {number}",
            connected=_as_bool(payload.get("connected")),
            enabled=_as_bool(payload.get("enabled"), default=True),
            permissions=max(_as_int(payload.get("permissions")) or 0, 0),
            capture_modes=CaptureModes.from_api(payload),
            schedules=CameraScheduleAssignment.from_api(payload),
        )

    @property
    def permission_names(self) -> frozenset[str]:
        """The granted permission names, derived from :attr:`permissions`.

        Derived rather than stored so the two can never be constructed out of
        step with one another.
        """
        return decode_permissions(self.permissions)

    def has_permission(self, permission: str) -> bool:
        """Return whether this camera grants the named permission."""
        return permission in self.permission_names

    def __repr__(self) -> str:
        """Return a representation that cannot carry credentials."""
        return (
            f"Camera(number={self.number}, name={self.name!r}, "
            f"connected={self.connected}, enabled={self.enabled}, "
            f"permissions={self.permissions}, "
            f"capture_modes={self.capture_modes.mode_string!r}, "
            f"schedules={self.schedules!r})"
        )


@dataclass(frozen=True, slots=True)
class ServerInfo:
    """The SecuritySpy server and its camera inventory.

    ``uuid`` is the stable hub identifier; never key off hostname or IP.
    """

    uuid: str
    version: str
    version_info: tuple[int, ...]
    camera_count: int
    #: Read-only view; ``ServerInfo`` is frozen and its inventory is not
    #: mutable through this attribute.
    cameras: Mapping[int, Camera] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_api(cls, payload: object) -> ServerInfo:
        """Decode a ``++systemInfo?format=json`` body.

        The envelope is not recorded in the protocol research, so this accepts
        both the wrapped form (``{"system": {"server": ...}}``) and a bare
        ``{"server": ...}``, and accepts ``cameralist.camera`` as either a list
        or a single object.

        Args:
            payload: The parsed JSON body.

        Raises:
            SecuritySpyUnsupportedVersionError: When no server block is
                locatable, when the version is missing or unparseable, or when
                the server is older than the supported minimum.

        Returns:
            The decoded server info.

        """
        root = _as_mapping(payload)
        if root is None:
            raise SecuritySpyUnsupportedVersionError(None, MIN_SERVER_VERSION_TEXT)
        system = _as_mapping(root.get("system")) or root
        server = _as_mapping(system.get("server"))
        if server is None:
            raise SecuritySpyUnsupportedVersionError(None, MIN_SERVER_VERSION_TEXT)

        version = _as_str(server.get("version"))
        version_info = _parse_version(version) if version is not None else None
        if version is None or version_info is None:
            raise SecuritySpyUnsupportedVersionError(version, MIN_SERVER_VERSION_TEXT)
        if version_info < MIN_SERVER_VERSION:
            raise SecuritySpyUnsupportedVersionError(version, MIN_SERVER_VERSION_TEXT)

        cameras = cls._decode_cameras(system)
        camera_count = _as_int(server.get("camera-count"))
        if camera_count is not None and camera_count < 0:
            # A negative inventory size is nonsense; fall back to what decoded.
            _LOGGER.debug("Server reported a negative camera count; using the decoded count")
            camera_count = None
        if camera_count is not None and camera_count != len(cameras):
            _LOGGER.debug("Server reports %s cameras but %s decoded", camera_count, len(cameras))
        return cls(
            uuid=_as_str(server.get("uuid")) or "",
            version=version,
            version_info=version_info,
            camera_count=camera_count if camera_count is not None else len(cameras),
            cameras=MappingProxyType(cameras),
        )

    @staticmethod
    def _decode_cameras(system: dict[str, object]) -> dict[int, Camera]:
        """Decode the camera list, tolerating absent, single-object and list forms."""
        cameralist = _as_mapping(system.get("cameralist"))
        raw = system.get("camera") if cameralist is None else cameralist.get("camera")
        entries: list[object]
        if raw is None:
            entries = []
        elif isinstance(raw, list):
            entries = list(raw)  # pyright: ignore[reportUnknownArgumentType]
        else:
            entries = [raw]

        cameras: dict[int, Camera] = {}
        for entry in entries:
            mapping = _as_mapping(entry)
            if mapping is None:
                _LOGGER.debug("Skipping non-object camera entry")
                continue
            camera = Camera.from_api(mapping)
            if camera is None:
                continue
            if camera.number in cameras:
                _LOGGER.debug("Duplicate camera number %s; keeping the first", camera.number)
                continue
            cameras[camera.number] = camera
        return cameras

    def __repr__(self) -> str:
        """Return a representation that cannot carry credentials."""
        return (
            f"ServerInfo(uuid={self.uuid!r}, version={self.version!r}, "
            f"camera_count={self.camera_count}, cameras={len(self.cameras)})"
        )


@dataclass(frozen=True, slots=True)
class Capture:
    """One entry from ``++caplist``: a recorded movie or JPG (research §4.1).

    This is SecuritySpy's *persisted* record of what happened, and the only
    source of truth that survives a restart -- the event stream is transient and
    starts again at zero. ``object_classes`` is the stored counterpart of a
    transient ``CLASSIFY`` signal, which is what makes poll-derived state
    correct after a restart.

    ``capture_type`` is deliberately a bare ``int`` rather than an enumeration:
    ``caplist.t`` and ``clip.movieType`` share a letter and mean different
    things (research §4b.3), and an unknown future value must carry through
    rather than be rejected.
    """

    camera: int
    start: datetime | None
    duration: timedelta | None
    capture_type: int | None
    object_classes: frozenset[str]
    filename: str
    folder_date: str
    file_size: int | None
    tag_id: int | None
    archived: bool
    unread: bool
    path: str

    @classmethod
    def from_api(cls, payload: dict[str, object], *, server_timezone: tzinfo) -> Capture | None:
        """Decode one ``++caplist`` entry.

        Args:
            payload: A single capture object from the API.
            server_timezone: Timezone of the server's wall-clock times. ``s``
                is seconds since *local* midnight, so this is what makes the
                returned UTC instant correct. **[ASSUMPTION]** No SecuritySpy
                endpoint exposes it, so callers default it to UTC.

        Returns:
            The decoded capture, or ``None`` when the entry has no usable
            camera number and must be skipped.

        """
        camera = _as_int(payload.get("c"))
        if camera is None:
            _LOGGER.debug("Skipping capture entry with a non-numeric camera number")
            return None

        folder_date = _as_str(payload.get("f")) or ""
        filename = _as_str(payload.get("n")) or ""
        start = _parse_capture_start(folder_date, payload.get("s"), server_timezone)
        if start is None:
            # The capture is still returned: a missing time makes it unorderable,
            # not unreal. The payload is never logged (research §8.3).
            _LOGGER.debug("Capture on camera %s has no reconstructable start time", camera)

        duration_seconds = _as_int(payload.get("d"))
        file_size = _as_int(payload.get("m"))
        return cls(
            camera=camera,
            start=start,
            duration=(
                timedelta(seconds=duration_seconds)
                if duration_seconds is not None and duration_seconds >= 0
                else None
            ),
            capture_type=_as_int(payload.get("t")),
            # An absent, null or zero `o` is an empty set, never `None`.
            object_classes=decode_object_classes(_as_int(payload.get("o")) or 0),
            filename=filename,
            folder_date=folder_date,
            file_size=file_size if file_size is not None and file_size >= 0 else None,
            tag_id=_as_int(payload.get("g")),
            archived=_as_bool(payload.get("a")),
            unread=_as_bool(payload.get("u")),
            path=_capture_path(camera, folder_date, filename),
        )

    @property
    def is_movie(self) -> bool:
        """Whether this capture is a movie rather than a JPG image."""
        return self.capture_type == CAPTURE_TYPE_MOVIE

    @property
    def capture_type_name(self) -> str | None:
        """The media-type name, or ``None`` for a value this library has not seen.

        Derived rather than stored so the two can never be constructed out of
        step with one another.
        """
        return CAPTURE_TYPE_NAMES.get(self.capture_type) if self.capture_type is not None else None

    def has_class(self, name: str) -> bool:
        """Return whether the server recorded the named object class here."""
        return name in self.object_classes

    def __repr__(self) -> str:
        """Return a representation that cannot carry credentials."""
        return (
            f"Capture(camera={self.camera}, start={self.start!r}, "
            f"capture_type={self.capture_type}, "
            f"object_classes={sorted(self.object_classes)}, "
            f"filename={self.filename!r})"
        )


# The curated ``++settings-cameras`` fields this library models, as
# ``(attribute, wire key)`` pairs grouped by how the value is written.
#
# ⚠️ This list is an allowlist, and that is the whole point. The settings
# payload also carries the camera's `username` and `password` in plaintext
# (research §8.3); a model that kept a raw dict would carry live device
# credentials into every consumer's diagnostics. Unknown keys are dropped at
# decode and never retained, so the leak is one a curated decode simply never
# creates. Adding a field costs a code change here -- that is the right trade.
#
# `aScript` and `aShellCommand` are deliberately absent: the artifacts do not
# say whether writing them falls under AD-2's remote-execution exclusion, so
# they stay out of the writable surface entirely.
_SETTINGS_BOOL_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("motion_capture_triggers_motion", "mcTriggerMotion"),
    ("motion_capture_triggers_human", "mcTriggerMotionH"),
    ("motion_capture_triggers_vehicle", "mcTriggerMotionV"),
    ("motion_capture_triggers_animal", "mcTriggerMotionA"),
    ("motion_capture_triggers_audio", "mcTriggerAudio"),
    ("actions_trigger_motion", "aTriggerMotion"),
    ("actions_trigger_human", "aTriggerMotionH"),
    ("actions_trigger_vehicle", "aTriggerMotionV"),
    ("actions_trigger_animal", "aTriggerMotionA"),
    ("continuous_capture_movie", "ccMovie"),
    ("continuous_capture_image", "ccImage"),
)

_SETTINGS_INT_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("motion_sensitivity", "motionSensitivity"),
    ("human_sensitivity", "humanSensitivity"),
    ("vehicle_sensitivity", "vehicleSensitivity"),
    ("animal_sensitivity", "animalSensitivity"),
    ("audio_sensitivity", "audioSensitivity"),
    ("motion_capture_pre_seconds", "mcMoviePre"),
    ("motion_capture_post_seconds", "mcMoviePost"),
    ("brightness", "brightness"),
    ("contrast", "contrast"),
)

_SETTINGS_STR_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("name", "name"),
    ("overlay_text", "overlayText"),
    ("presence_rect", "presenceRect"),
)

#: The wire keys written as `1`/`0`. Declaration, not runtime type, decides the
#: write encoding -- see `CameraSettingsPatch.form_fields`.
_SETTINGS_BOOL_KEYS: Final[frozenset[str]] = frozenset(key for _, key in _SETTINGS_BOOL_FIELDS)

#: Every curated wire key, used by the client to tell a real ~120-key settings
#: page from an unrelated JSON object that merely happens to be a dict. An
#: empty body would otherwise decode to an all-default `CameraSettings` that
#: reads as a genuinely configured camera.
SETTINGS_PAGE_KEYS: Final[frozenset[str]] = frozenset(
    key for _, key in (*_SETTINGS_STR_FIELDS, *_SETTINGS_BOOL_FIELDS, *_SETTINGS_INT_FIELDS)
)

#: How many curated keys a body must carry before it is accepted as a settings
#: page. A single overlap is not evidence: `name`, `brightness` and `contrast`
#: are ordinary words, so a reverse-proxy error page or a wrong-endpoint body
#: like `{"name": "...", "error": "..."}` would clear a one-key test and decode
#: to a camera reporting every trigger `False` and every sensitivity `None` --
#: indistinguishable from a camera whose detection is genuinely all switched
#: off, which on a security product is the wrong way to be wrong. A real page
#: carries every key in `SETTINGS_PAGE_KEYS`, so the bar costs nothing.
#:
#: The bar is a *quorum*, not a proof: a body carrying exactly these three
#: overlapping words alongside an `error` key still clears it. It is set where
#: it is because the failure it exists to prevent is a one-word coincidence, and
#: because raising it further would start rejecting real pages from any
#: SecuritySpy version whose settings form carries fewer keys than the one
#: research §8.1 was read off -- a trade that cannot be settled without a second
#: server version to read. Raise it if one becomes available.
SETTINGS_PAGE_KEY_QUORUM: Final = 3


def _as_settings_str(payload: Mapping[str, object], key: str) -> str | None:
    """Coerce a settings string field, keeping ``""`` distinct from absent.

    `_as_str` folds the empty string to ``None``, which is right for the rest
    of the library but wrong here: a camera whose overlay text the user has
    *cleared* is a different state from one whose page does not carry the key
    at all, and only the first is something a consumer can write back.
    """
    if key not in payload:
        return None
    value = payload[key]
    if isinstance(value, str):
        return value
    return _as_str(value)


#: Rendering order for a settings write. Fixed, so a body is a function of the
#: *set* of changed fields rather than of attribute-assignment order.
_PATCH_FIELD_ORDER: Final[tuple[tuple[str, str], ...]] = (
    *_SETTINGS_STR_FIELDS,
    *_SETTINGS_BOOL_FIELDS,
    *_SETTINGS_INT_FIELDS,
)


@dataclass(frozen=True, slots=True)
class CameraSettings:
    """A curated, credential-free view of ``++settings-cameras`` (research §8.1).

    Only the declared fields above are retained. The raw payload -- which
    contains the camera's device ``username`` and ``password`` in plaintext
    (research §8.3) -- is dropped at decode and is never stored, never logged
    at any level including debug, and never reachable from this object.

    Booleans read back as JSON ``true``/``false`` here but must be *written* as
    ``1``/``0``; that asymmetry lives entirely in
    :meth:`CameraSettingsPatch.form_fields`, so no call site ever sees it.
    """

    camera_number: int
    name: str | None = None
    overlay_text: str | None = None
    presence_rect: str | None = None
    motion_capture_triggers_motion: bool = False
    motion_capture_triggers_human: bool = False
    motion_capture_triggers_vehicle: bool = False
    motion_capture_triggers_animal: bool = False
    motion_capture_triggers_audio: bool = False
    actions_trigger_motion: bool = False
    actions_trigger_human: bool = False
    actions_trigger_vehicle: bool = False
    actions_trigger_animal: bool = False
    continuous_capture_movie: bool = False
    continuous_capture_image: bool = False
    motion_sensitivity: int | None = None
    human_sensitivity: int | None = None
    vehicle_sensitivity: int | None = None
    animal_sensitivity: int | None = None
    audio_sensitivity: int | None = None
    motion_capture_pre_seconds: int | None = None
    motion_capture_post_seconds: int | None = None
    brightness: int | None = None
    contrast: int | None = None

    @classmethod
    def from_api(cls, payload: dict[str, object], *, camera_number: int) -> CameraSettings:
        """Decode one ``++settings-cameras?format=json`` body.

        Args:
            payload: The parsed settings object. Every key outside the curated
                allowlist -- including ``username`` and ``password`` -- is
                discarded rather than retained.
            camera_number: The camera the settings were read for. The payload
                is not trusted for it: it is the caller's own request
                parameter, and it is the model's stable key.

        Returns:
            The decoded settings.

        """
        return cls(
            camera_number=camera_number,
            name=_as_settings_str(payload, "name"),
            overlay_text=_as_settings_str(payload, "overlayText"),
            presence_rect=_as_settings_str(payload, "presenceRect"),
            motion_capture_triggers_motion=_as_bool(payload.get("mcTriggerMotion")),
            motion_capture_triggers_human=_as_bool(payload.get("mcTriggerMotionH")),
            motion_capture_triggers_vehicle=_as_bool(payload.get("mcTriggerMotionV")),
            motion_capture_triggers_animal=_as_bool(payload.get("mcTriggerMotionA")),
            motion_capture_triggers_audio=_as_bool(payload.get("mcTriggerAudio")),
            actions_trigger_motion=_as_bool(payload.get("aTriggerMotion")),
            actions_trigger_human=_as_bool(payload.get("aTriggerMotionH")),
            actions_trigger_vehicle=_as_bool(payload.get("aTriggerMotionV")),
            actions_trigger_animal=_as_bool(payload.get("aTriggerMotionA")),
            continuous_capture_movie=_as_bool(payload.get("ccMovie")),
            continuous_capture_image=_as_bool(payload.get("ccImage")),
            motion_sensitivity=_as_int(payload.get("motionSensitivity")),
            human_sensitivity=_as_int(payload.get("humanSensitivity")),
            vehicle_sensitivity=_as_int(payload.get("vehicleSensitivity")),
            animal_sensitivity=_as_int(payload.get("animalSensitivity")),
            audio_sensitivity=_as_int(payload.get("audioSensitivity")),
            motion_capture_pre_seconds=_as_int(payload.get("mcMoviePre")),
            motion_capture_post_seconds=_as_int(payload.get("mcMoviePost")),
            brightness=_as_int(payload.get("brightness")),
            contrast=_as_int(payload.get("contrast")),
        )

    def __repr__(self) -> str:
        """Return a representation that cannot carry credentials.

        Deliberately minimal: the settings page is the one payload in this
        library that is known to carry device credentials, so its ``repr`` is
        an identity, not a dump. It is what a consumer's diagnostics and a
        traceback frame will print.
        """
        return f"CameraSettings(camera_number={self.camera_number})"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class CameraSettingsPatch:
    """The set of settings fields a caller wants to change, and nothing else.

    Writes are **partial** (research §8.0, verified): only the fields set here
    are posted, and every untouched key on the ~120-key page keeps its value.
    There is deliberately no read-modify-write, which removes a whole class of
    race condition.

    ``None`` means "leave alone". A field set to ``False`` is a real change and
    is written as ``0``.
    """

    name: str | None = None
    overlay_text: str | None = None
    presence_rect: str | None = None
    motion_capture_triggers_motion: bool | None = None
    motion_capture_triggers_human: bool | None = None
    motion_capture_triggers_vehicle: bool | None = None
    motion_capture_triggers_animal: bool | None = None
    motion_capture_triggers_audio: bool | None = None
    actions_trigger_motion: bool | None = None
    actions_trigger_human: bool | None = None
    actions_trigger_vehicle: bool | None = None
    actions_trigger_animal: bool | None = None
    continuous_capture_movie: bool | None = None
    continuous_capture_image: bool | None = None
    motion_sensitivity: int | None = None
    human_sensitivity: int | None = None
    vehicle_sensitivity: int | None = None
    animal_sensitivity: int | None = None
    audio_sensitivity: int | None = None
    motion_capture_pre_seconds: int | None = None
    motion_capture_post_seconds: int | None = None
    brightness: int | None = None
    contrast: int | None = None

    def form_fields(self) -> dict[str, str]:
        """Render the changed fields as ordered ``wire key -> string value``.

        This is the single home of the read/write boolean asymmetry: SecuritySpy
        reads booleans back as JSON ``true``/``false`` but requires ``1``/``0``
        on a write (research §8.0 rule 3). No call site ever sees ``1``/``0``.

        The result is ordered and its order is fixed by declaration, so the body
        the client builds from it is byte-identical across calls.

        Raises:
            ValueError: No field was set. An empty patch would post a body of
                nothing but the sentinel and the camera number, which is a
                request the caller did not mean to make.

        Returns:
            The changed fields, already stringified. Values are **not** URL
            encoded: quoting belongs to the body builder, which is the only
            place that knows the body is form-urlencoded.

        """
        rendered: dict[str, str] = {}
        for attribute, key in _PATCH_FIELD_ORDER:
            value: object = getattr(self, attribute)
            if value is None:
                continue
            # Keyed off the field's *declared* group, never off the runtime type
            # of the value. `isinstance(value, bool)` first would rename a camera
            # to "1" for `CameraSettingsPatch(name=True)`: a `bool` is an `int`
            # and reads as one to every runtime check, so only the declaration
            # can say which encoding a field takes.
            if key in _SETTINGS_BOOL_KEYS:
                rendered[key] = "1" if value else "0"
            else:
                rendered[key] = str(value)
        if not rendered:
            message = "patch is empty; set at least one field to change"
            raise ValueError(message)
        return rendered

    def __repr__(self) -> str:
        """Return a representation that names only the fields that are set.

        The values are omitted: a patch can carry a camera name and an overlay
        string, and this object is the one a caller is most likely to log.
        """
        changed = [
            attribute for attribute, _ in _PATCH_FIELD_ORDER if getattr(self, attribute) is not None
        ]
        return f"CameraSettingsPatch(changed={changed})"

    __str__ = __repr__
