"""Async, fully-typed client library for the Ben Software SecuritySpy API.

The library owns all SecuritySpy protocol knowledge and imports nothing from
Home Assistant. It never creates an HTTP session: callers inject their own.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _metadata_version

from .client import SecuritySpyClient
from .const import (
    CLASS_ANIMAL,
    CLASS_HUMAN,
    CLASS_VEHICLE,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    ENDPOINT_PREFIX,
    ENDPOINT_SYSTEM_INFO,
    MIN_SERVER_VERSION,
    MIN_SERVER_VERSION_TEXT,
    PERM_AUDIORCV,
    PERM_AUDIOSND,
    PERM_CAMCONTROL,
    PERM_FILEDEL,
    PERM_FILES,
    PERM_LIVEVIDEO,
    PERM_PTZSET,
    PERM_SCHED,
    PERM_TRIGGER,
    PERMISSION_NAMES,
    class_slug,
    decode_permissions,
)
from .exceptions import (
    SecuritySpyAuthError,
    SecuritySpyConnectError,
    SecuritySpyError,
    SecuritySpyPermissionError,
    SecuritySpyUnsupportedVersionError,
)
from .models import Camera, ServerInfo

try:
    __version__ = _metadata_version("aiosecurityspy")
except PackageNotFoundError:  # pragma: no cover - source tree without install
    __version__ = "0.0.0.dev0"

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
    "Camera",
    "SecuritySpyAuthError",
    "SecuritySpyClient",
    "SecuritySpyConnectError",
    "SecuritySpyError",
    "SecuritySpyPermissionError",
    "SecuritySpyUnsupportedVersionError",
    "ServerInfo",
    "__version__",
    "class_slug",
    "decode_permissions",
]
