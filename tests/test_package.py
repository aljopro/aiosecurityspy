"""Skeleton-level tests: the package imports and its version is single-sourced."""

from __future__ import annotations

import importlib
import importlib.util
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
