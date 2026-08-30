"""Load ``aiosecurityspy/.env`` for the live-server tests.

Deliberately dependency-free: the live tests are an opt-in developer tool, and
adding a runtime or dev dependency to read six lines of ``KEY=value`` would put
a package on every contributor's machine to serve a path most of them never
take. Nothing here is imported by the library itself.

Credential handling rule for this whole module and its callers: values are
passed to the client and never returned in a repr, asserted on, written to a
fixture, or included in an assertion message. A failing live test must be
debuggable from status codes and shapes alone.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

#: `.env` sits beside `pyproject.toml`, one level up from `tests/`.
ENV_FILE: Final = Path(__file__).resolve().parent.parent / ".env"


def _load_env_file() -> dict[str, str]:
    """Parse ``.env`` into a mapping, or return empty when it is absent.

    Absent is the normal case -- a clone with no server runs the offline suite
    and every live test skips -- so a missing file is not an error.
    """
    if not ENV_FILE.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


#: Process environment wins over the file, so CI or a shell export can override
#: a checked-out `.env` without editing it.
_VALUES: Final[dict[str, str]] = {**_load_env_file(), **os.environ}


def get(name: str) -> str | None:
    """Return the configured value for ``name``, or ``None`` when unset or blank."""
    value = _VALUES.get(name)
    return value or None


def get_int(name: str) -> int | None:
    """Return ``name`` as an int, or ``None`` when unset or not an integer."""
    value = get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def flag(name: str) -> bool:
    """Return whether ``name`` is set to a truthy value."""
    value = get(name)
    return value is not None and value.lower() in {"1", "true", "yes", "on"}


def credentials(role: str) -> tuple[str, str] | None:
    """Return ``(username, password)`` for a role, or ``None`` when not configured.

    ``role`` is the middle word of the pair, e.g. ``"LIVE"`` for
    ``SECURITYSPY_LIVE_USER``/``SECURITYSPY_LIVE_PASS``.
    """
    username = get(f"SECURITYSPY_{role}_USER")
    password = get(f"SECURITYSPY_{role}_PASS")
    if username is None or password is None:
        return None
    return username, password


def server_configured() -> bool:
    """Return whether a host is configured at all."""
    return get("SECURITYSPY_HOST") is not None
