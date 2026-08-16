"""Skeleton-level tests: the package imports and its version is single-sourced."""

from __future__ import annotations

import importlib
import importlib.util
import pathlib
import re
from importlib.metadata import version as metadata_version

import aiosecurityspy

# PEP 440 version regex (canonical form from the PEP 440 appendix), including the
# optional local-version segment so an editable or CI-built install still matches.
PEP440 = re.compile(
    r"^([1-9][0-9]*!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*"
    r"((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))?"
    r"(\.dev(0|[1-9][0-9]*))?"
    r"(\+[a-z0-9]+([.-][a-z0-9]+)*)?$"
)


def test_import_succeeds() -> None:
    assert importlib.import_module("aiosecurityspy") is aiosecurityspy


def test_version_is_non_empty_pep440() -> None:
    assert aiosecurityspy.__version__
    assert PEP440.match(aiosecurityspy.__version__) is not None


def test_version_matches_distribution_metadata() -> None:
    assert aiosecurityspy.__version__ == metadata_version("aiosecurityspy")


def test_public_surface() -> None:
    assert "__version__" in aiosecurityspy.__all__


def test_home_assistant_is_not_installed() -> None:
    """The library must be usable with no Home Assistant anywhere on the system."""
    assert importlib.util.find_spec("homeassistant") is None


#: Endpoints and settings keys AD-2 excludes from this library entirely:
#: capture deletion and remote execution. They are absent, not wrapped and not
#: private-but-present, so absence is an enumerable property -- enumerate it.
EXCLUDED_TOKENS = (
    "doShell",
    "doShortcut",
    "deleteclip",
    "++delete",
    "aScript",
    "aShellCommand",
    "setTags",
)

#: Substrings that would betray a deletion or execution method on the public API.
EXCLUDED_NAME_FRAGMENTS = ("delete", "remove", "shell", "shortcut", "applescript", "exec")

SOURCE_ROOT = pathlib.Path(aiosecurityspy.__file__).parent


def test_public_api_has_no_deletion_or_execution_name() -> None:
    for name in aiosecurityspy.__all__:
        assert not any(fragment in name.lower() for fragment in EXCLUDED_NAME_FRAGMENTS), name


def test_client_exposes_no_deletion_or_execution_method() -> None:
    for name in dir(aiosecurityspy.SecuritySpyClient):
        # Private-but-present counts as present (AD-2), so dunders are the only
        # exemption and `file_delete` -- a *permission name*, not a method -- is
        # not on this object at all.
        if name.startswith("__"):
            continue
        assert not any(fragment in name.lower() for fragment in EXCLUDED_NAME_FRAGMENTS), name


def test_no_source_file_names_an_excluded_endpoint_or_key() -> None:
    offenders: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                # A comment recording the exclusion is explicitly allowed.
                continue
            offenders.extend(
                f"{path.name}:{number}: {token}" for token in EXCLUDED_TOKENS if token in line
            )
    assert offenders == []
