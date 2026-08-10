# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-10

### Added

- Initial publishable package skeleton: `src/` layout, hatchling build backend, and all
  configuration in `pyproject.toml`.
- `aiosecurityspy.__version__`, single-sourced from package metadata.
- `py.typed` marker so type information ships to consumers.
- ruff (lint + format) and `mypy --strict` gates, plus a pytest suite.
- GitHub Actions CI and a PyPI trusted-publisher (OIDC) release workflow.

[Unreleased]: https://github.com/aljopro/aiosecurityspy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aljopro/aiosecurityspy/releases/tag/v0.1.0
