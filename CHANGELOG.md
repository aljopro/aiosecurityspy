# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SecuritySpyClient`: an async REST client over a caller-injected `aiohttp.ClientSession`.
  The library never creates, reconfigures, or closes a session, so the client has no
  `close()` and no async-context-manager protocol. Credentials are sent only as
  `aiohttp.BasicAuth` and never appear in a URL, log line, exception message, `repr`, or
  traceback. Certificate verification is a constructor flag applied per request, and every
  request carries an explicit total timeout (30 s by default).
- `SecuritySpyClient.async_get_server_info()`, reading `++systemInfo?format=json`.
- Frozen, fully-typed models `ServerInfo` and `Camera` with `from_api()` constructors.
  Camera number is `int` everywhere, and `ServerInfo.cameras` is a read-only mapping.
- Typed exception hierarchy: `SecuritySpyError` and its `SecuritySpyConnectError`,
  `SecuritySpyAuthError`, `SecuritySpyPermissionError`, and
  `SecuritySpyUnsupportedVersionError` subclasses. No `aiohttp` exception, `TimeoutError`,
  `OSError`, `LookupError`, `RuntimeError`, or `ValueError` (including `JSONDecodeError` and
  `UnicodeDecodeError`) escapes a request or a decode. The constructor is the deliberate
  exception: it validates its arguments and raises `ValueError`, or `TypeError` for a
  non-integer port, for a caller mistake.
- Constructor validation: the host is checked against an allowlist (bare hostname, IPv4, or
  IPv6 literal, which is bracketed when built into the URL), and credentials that HTTP Basic
  auth cannot carry — a `':'` in the username, or a non-latin-1 username or password — are
  rejected up front. aiohttp would otherwise raise `UnicodeEncodeError` at request time with
  the password in its `args`. No validation message quotes the offending value.
- A response-body size cap (8 MiB), enforced while accumulating the stream rather than by
  trusting `Content-Length`, so a chunked hostile body cannot be buffered into a Home
  Assistant process while a legitimate multi-chunk body still reads in full. The request
  timeout bounds duration, not bytes.
- Redirects are reported, not followed. A different port is a different origin, so aiohttp
  strips the `Authorization` header across SecuritySpy's HTTP-to-HTTPS redirect; following it
  would turn a wrong-scheme mistake into a 401 that blames the user's password. A 3xx now
  raises `SecuritySpyConnectError` naming the status and suggesting `use_https=True`.
- Protocol constants in `const.py`: `DEFAULT_PORT`, `DEFAULT_TIMEOUT`, the `++` endpoint
  prefix and `++systemInfo` path, `MIN_SERVER_VERSION`, the `PERM_*` permission bitmask
  values with `decode_permissions()`, the built-in object-class constants, and
  `class_slug()` as the single class-name normalizer.
- A hand-authored `++systemInfo` protocol fixture built from the field names in
  `research/securityspy-api-reference.md` §10 — not captured from a live server — plus
  model-level tests, stubbed-session transport tests, and transport tests against a real
  in-process `aiohttp` server.

### Changed

- Narrowed the `aiohttp` dependency to `>=3.12,<4`, matching the architecture's declared
  stack now that `aiohttp` is actually imported.

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
