"""Frozen, fully-typed data models decoded from SecuritySpy payloads (AD-15).

Raw dictionaries never cross the library boundary: every public method returns
one of these models. Decoding lives here, not in the client, so a payload can be
decoded in a test with no network involved at all.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from .const import MIN_SERVER_VERSION, MIN_SERVER_VERSION_TEXT, decode_permissions
from .exceptions import SecuritySpyUnsupportedVersionError

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ["Camera", "ServerInfo"]

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


def _as_mapping(value: object) -> dict[str, object] | None:
    """Return ``value`` as a string-keyed mapping, or ``None``."""
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}  # pyright: ignore[reportUnknownVariableType]
    return None


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
            f"permissions={self.permissions})"
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
