"""Async, fully-typed client library for the Ben Software SecuritySpy API.

The library owns all SecuritySpy protocol knowledge and imports nothing from
Home Assistant. It never creates an HTTP session: callers inject their own.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _metadata_version

try:
    __version__ = _metadata_version("aiosecurityspy")
except PackageNotFoundError:  # pragma: no cover - source tree without install
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
