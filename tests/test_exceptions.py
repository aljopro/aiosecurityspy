"""Unit tests for the typed exception hierarchy in :mod:`aiosecurityspy.exceptions`.

Covers the `API_`-prefix diagnostic hint on `SecuritySpyAuthError` (deferred
from Story 1.21/1.22): flag off must reproduce today's message byte-for-byte,
flag on must append one generic, credential-free sentence.
"""

from __future__ import annotations

from aiosecurityspy.exceptions import SecuritySpyAuthError

HOST = "nvr.example.com"
PORT = 8001
STATUS = 401


def test_auth_error_message_unchanged_when_flag_is_false() -> None:
    """Default (and explicit `False`) flag reproduces today's exact message."""
    default = SecuritySpyAuthError(HOST, PORT, STATUS)
    explicit = SecuritySpyAuthError(HOST, PORT, STATUS, password_has_api_key_prefix=False)
    expected = f"SecuritySpy at {HOST}:{PORT} rejected the supplied credentials (HTTP {STATUS})"
    assert str(default) == expected
    assert str(explicit) == expected


def test_auth_error_message_gains_hint_when_flag_is_true() -> None:
    """Flag on appends one extra sentence, on top of today's unchanged message."""
    base = f"SecuritySpy at {HOST}:{PORT} rejected the supplied credentials (HTTP {STATUS})"
    hinted = SecuritySpyAuthError(HOST, PORT, STATUS, password_has_api_key_prefix=True)
    message = str(hinted)
    assert message.startswith(base)
    assert message != base
    assert "API_" in message


def test_auth_error_hint_never_references_a_password_value() -> None:
    """The hint is generic: it names the prefix, never a password's actual content."""
    sentinel_password = "API_9f3a7c1e5b2d4f608a1c3e5f7b9d1c3e"  # noqa: S105 - leak-detection sentinel
    hinted = SecuritySpyAuthError(HOST, PORT, STATUS, password_has_api_key_prefix=True)
    assert sentinel_password not in str(hinted)
    assert repr(hinted).count("API_") == str(hinted).count("API_")


def test_auth_error_hint_is_phrased_as_observed_not_guaranteed() -> None:
    """The hint must not claim certainty about *why* the server rejected the password."""
    hinted = SecuritySpyAuthError(HOST, PORT, STATUS, password_has_api_key_prefix=True)
    message = str(hinted).lower()
    assert "observed" in message
