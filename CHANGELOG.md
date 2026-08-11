# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SecuritySpyClient.async_get_captures(...)`: batched capture-history queries against
  `++caplist`. One request covers every requested camera — the `cams` parameter is the
  sorted, de-duplicated camera list with the trailing comma the server's own client sends
  — and object-class filtering is done **by the server** via `filter=`, so the cost is one
  request rather than one per camera or cameras × classes. There is deliberately no
  fetch-everything-and-filter-locally fallback. The date range is required and is never
  widened or defaulted: the lookback window is the consumer's policy. Argument mistakes
  (a negative or non-integer camera number, a `datetime` where a `date` is required,
  `start_date` after `end_date`, an object class the server has no filter for, a
  `capture_filter` SecuritySpy does not define, or both `object_class` and
  `capture_filter` at once) raise `ValueError` before any request is issued, and no
  message quotes the offending value. The class filters select motion-capture *movies* of
  that class, so a JPG or continuous capture carrying the same class is not returned by
  them. A body wrapping the array is accepted only under a named key, so an error
  envelope cannot be mistaken for an empty day.
  An empty camera list short-circuits to `()` with no request at all. Results come back
  newest first, deterministically, regardless of the server's ordering.
- Frozen `Capture` model with `from_api()`. `start` is a timezone-aware UTC instant
  reconstructed from the folder date plus seconds-since-midnight (research §4.1's `63319`
  → 17:35:19). The field is a wall-clock second-of-day, so it is added to a zone-aware
  local midnight; it carries no fold bit, which makes one local hour per DST fall-back
  ambiguous (the earlier instant is chosen) and the skipped spring-forward hour
  non-injective. An absent or undecodable time is `None`, never
  epoch and never zero, and those captures still come back — sorted last. `object_classes`
  decodes the persisted `o` bitmask into a `frozenset[str]` and is empty rather than `None`
  when nothing was classified. An entry that is not an object, or that carries no usable
  camera number, is skipped and the rest decode; nothing about the payload is ever logged.
- Protocol constants: `ENDPOINT_CAPTURE_LIST`, the `CAPTURE_FILTER_*` values of research
  §4.2, `CAPTURE_TYPE_MOVIE`/`CAPTURE_TYPE_IMAGE` with `CAPTURE_TYPE_NAMES`,
  `OBJECT_CLASS_BITS`, `decode_object_classes()` (which degrades exactly like
  `decode_permissions()`), and `capture_filter_for_class()`, which raises `ValueError`
  naming the three filterable classes rather than inventing a filter the server lacks.
  `caplist`'s type field and `clip.movieType` share a letter and mean different things
  (research §4b.3), so they share no name, mapping, or enumeration — `Capture.capture_type`
  stays a bare `int` and an unrecognised value carries through with a `None` name.
- A recorded-shape `++caplist` fixture (`tests/fixtures/caplist.json`) covering a movie and
  a JPG, `o` values of 0/1/5/9, a missing folder date, a non-object entry, and an entry with
  no usable camera number, plus decode and request-shape tests for every row of the story's
  edge-case matrix.
- `SecuritySpyEventStream` and `SecuritySpyClient.event_stream(...)`: a reader for
  `++eventStream?version=3` that owns its whole lifecycle. Records are framed on CR
  (`0x0D`) **only** — the stream contains zero LF bytes, so nothing in the library waits
  on a line feed — and a record split across TCP chunk boundaries reassembles. A record
  left unterminated when the stream ends is discarded rather than half-decoded, and one
  that exceeds the 64 KiB cap with no separator in sight is dropped rather than buffered
  without bound — and the reader then stays out of sync until the next separator, so the
  tail of a dropped record is never emitted as though it were a whole one.
- Stream lifecycle: a heartbeat watchdog that declares loss after three missed ~10 s
  heartbeats (measured as socket silence, so a busy camera cannot false-positive),
  indefinite exponential backoff with jitter and a capped ceiling (the delay returns to
  its initial value after every successful connection, so a server that drops the stream
  periodically does not creep up to the ceiling and stay there), and explicit
  `on_connected` / `on_disconnected` / `on_reconnected` / `on_auth_failed` callbacks.
  `connected` fires only on the first-ever successful connect; every later one is a
  `reconnected`. On 401/403 the stream fires `on_auth_failed` and **pauses** reconnection
  until the consumer calls `resume()` — the library never re-authenticates and never
  counts auth failures. The pause has exactly one door out of it: `connect()` declines
  while paused, and the pause survives `disconnect()`, so a rejected credential cannot be
  retried through the ordinary entry point. `connect()` and `disconnect()` are idempotent
  and serialized against each other, callbacks may be sync or async, and a callback that
  raises is logged and swallowed. `disconnect()` is safe to call from inside a callback,
  which runs on the reader task: the cancellation unwinds as the callback returns rather
  than the reader awaiting itself. No exception escapes the stream, and the stream request
  carries no total timeout (it is long-lived by design) but does carry a bounded connect
  timeout.
- Frozen event models in `events.py`: `StreamEvent` plus `MotionPayload`,
  `ClassificationPayload` (with `slugged()`), `TriggerPayload`, `FilePayload`, and
  `ErrorPayload`, and the pure `parse_event_line()` decoder. A camera field of `X` decodes
  to `camera=None`, meaning "not camera-specific" rather than invalid; a malformed record
  is skipped and the stream continues; an unknown event type is delivered with its `INFO`
  verbatim. Numeric fields are parsed strictly — no underscore literals, no non-ASCII
  digits, no `nan`/`inf`, and no integer long enough to trip CPython's conversion limit —
  because every one of those would otherwise decode to something the wire format never
  meant, or raise out of the parser and end a live connection. The classification vocabulary stays open, so a label from a user-supplied
  CoreML model carries through unchanged. Timestamps become timezone-aware UTC, with the
  original 14-character string preserved on `raw_timestamp` and the server's timezone an
  injectable assumption defaulting to UTC.
- Protocol constants: `ENDPOINT_EVENT_STREAM`, `EVENT_STREAM_VERSION`, the `EVENT_*` type
  names of research §3.3, the §3.4 trigger-reason bit table as `TRIGGER_REASON_NAMES` with
  `decode_trigger_reasons()`, and the heartbeat and backoff defaults.
- A recorded-shape event-stream fixture (`tests/fixtures/event_stream.bin`, CR-terminated
  with zero LF bytes), pure decoding tests, stubbed lifecycle tests, and stream tests
  against a real in-process `aiohttp` server that chunks mid-record.
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

- Host, port, timeout and credential validation, URL construction, and the `BasicAuth`
  credential moved out of `client.py` into an internal `connection.py`, so the client and
  the event stream share exactly one definition of validated transport state and one place
  a URL is built. `SecuritySpyClient`'s observable behaviour is unchanged.
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
