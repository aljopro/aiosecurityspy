# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Added

- **Credential-safe diagnostics.** `anonymize()` returns a credential-free copy of any
  structure — a raw settings payload, a library model, an `aiohttp.BasicAuth`, a config
  mapping, a list of URLs — so a consumer can point its diagnostics dump at one function
  instead of scrubbing by hand. Structure survives: mappings stay mappings, keys stay
  keys, lists and tuples keep their order and container type, and every non-credential
  value is returned unchanged, because a dump that redaction flattened would be safe and
  useless. A URL embedded in an ordinary free-text message is redacted where it sits —
  including a protocol-relative `//user:pass@host/…` one — and a timestamp, duration,
  `Decimal`, `UUID`, `PurePath` or `Enum` is rendered rather than flattened to a type
  marker, so a capture dump keeps the times it is read for. An exception is walked
  argument by argument rather than rendered through `str()`, which on a multi-argument
  exception is the `repr` of its arguments and would publish a credential-bearing one.
  A number a caller declares in `secrets=` is matched on its rendered form, so a numeric
  passcode is caught as readily as a string one; booleans and `None` are exempt from that
  match, so declaring a config's values wholesale cannot destroy every flag in the dump.
- `redact_url()`: replaces a URL's userinfo — including on a protocol-relative
  `//user:pass@host/…` reference, and without inventing a password on a `//user@host/…`
  one that never carried a second field — and every credential-shaped parameter in the
  query, the fragment and an RFC 3986 `;`-delimited path segment alike, whether the query
  is separated by `&` or the legacy `;`. A URL nested inside another one — in a parameter
  value, percent-encoded or not, or in the path of a redirect or proxy endpoint — is
  redacted too. The scheme in its original case, the host, port, path and every other
  parameter come back byte for byte.
  This is what a consumer **must** call before a credential-bearing stream URL reaches a
  log line or a subprocess argument — an external tool has been observed echoing an
  `rtsp://user:pass@host/…` URL back verbatim.
- `CREDENTIAL_KEYS` and `is_credential_key()`: one declared vocabulary and one predicate
  that every redaction decision routes through. Matching is on the key lowercased with
  non-alphanumerics stripped, tested for **exact** membership — so `authToken`,
  `auth_token` and `AUTH-TOKEN` all match while `passwordProtected` is preserved.
  `aiosecurityspy.const.CREDENTIAL_KEYS` is the single place to extend when a future
  SecuritySpy version grows a credential-shaped key; both redactors read that module
  attribute at call time, so adding a name there is the whole change.
- `REDACTED`, the marker every redaction substitutes.
- The anonymizer is fail-closed on shapes: a `NamedTuple` is walked by `_fields` rather
  than positionally (`aiohttp.BasicAuth("bob", "s3cret")` as a sequence would be
  `["bob", "s3cret"]`, with no key left to match the password on), bytes become a length
  marker, cycles and runaway nesting stop at `<recursive>`/`<truncated>`, and an
  unrecognised object becomes its bare type name — never its `repr`. It never raises: a
  container that refuses to be walked, or a member whose getter throws, degrades to
  `<unwalkable TypeName>`, so `anonymize()` is safe to call from an exception handler.
- `anonymize(..., secrets=[...])` substitutes literal secrets the *caller* knows inside
  every string it produces, which is the only thing that catches a credential embedded in
  a free-text field where no key names it. Blank secrets are ignored rather than honoured.
- `aiosecurityspy.diagnostics` is pure: it imports the standard library and the protocol
  vocabulary and nothing else — no `aiohttp`, no network, no I/O, no logger. There is
  deliberately **no** diagnostics-dump builder and no `async_get_diagnostics()`: the
  library supplies the anonymizer, the consumer supplies the dump.
- Your credential never appears in a URL the library builds or sends, and neither it nor a
  camera's device credential nor any settings-payload value ever reaches a log line, an
  exception message or a traceback — on any request path, at any log level. Both claims are
  now enforced by the test suite rather than stated in prose.

### Added

- `SecuritySpyCertificateError`, raised **only** when the server's TLS certificate fails
  verification (`aiohttp.ClientConnectorCertificateError` or
  `ssl.SSLCertVerificationError`): an expired certificate, an unknown issuer, or a name
  that does not match the address used. It is a **subclass** of
  `SecuritySpyConnectError`, so every existing consumer that catches connect errors keeps
  catching it unchanged; a consumer that wants to name the certificate specifically opts
  in by testing the subclass **first**. The message says verification can be disabled,
  which is a real remedy for this class of failure and only for this class.
- Every *other* TLS failure now reports as a `SecuritySpyConnectError` naming the
  OpenSSL reason and the likeliest cause. Speaking TLS to a plain-HTTP listener raises
  `WRONG_VERSION_NUMBER` with verification on and off alike, so it must not be reported
  as a certificate problem.
- Both clauses precede `_request()`'s `TimeoutError`/`ClientError`/`OSError` handling,
  which would otherwise swallow a TLS failure whole: `ClientSSLError` subclasses
  `ClientError` *and* `OSError`, and `ssl.SSLError` subclasses `OSError`.

### Changed

- **Breaking (positional construction):** `ServerInfo.name` is inserted as the second
  field, shifting `version`, `version_info` and `camera_count` one position right. Code
  building a `ServerInfo` positionally must be updated; keyword construction and every
  attribute read are unaffected, as is `ServerInfo.from_api()`, which is how the model is
  meant to be built.

### Added

- `ServerInfo.name`: the server's display name, decoded from the `server` block's
  `bonjour-name` with a trailing `.local` stripped and falling back to `"SecuritySpy"`
  when the server publishes nothing usable. `++systemInfo` carries no dedicated
  server-name field, so this is the only human-chosen identifier available; the
  suffix-stripping lives here because it is a wire-format fact and no consumer may
  hold one (AD-2).
- **Settings, arming and permission decoding.** `async_get_camera_settings()` reads a
  camera's settings page into a curated, credential-free `CameraSettings`;
  `async_set_camera_settings()` writes a `CameraSettingsPatch` as a *partial* form POST;
  `async_set_camera_arming()` sets the three independent capture modes plus a transient
  override.
- The settings write's three traps live in the library, not at a call site: the POST goes
  to the **bare** `++settings-cameras` path (the query form 404s), `cameraNum` travels in
  the **body**, and the body is assembled as an ordered string opening with the literal
  `formData` sentinel. Booleans read back as JSON `true`/`false` but are written as
  `1`/`0`; `CameraSettingsPatch.form_fields()` is the single home of that asymmetry.
- Writes are partial and verified as such: only the fields you set are posted, and every
  other key on the ~120-key page keeps its value. There is no read-modify-write.
- `CameraSettings` retains only a declared allowlist of non-credential fields. The raw
  payload — which carries the camera's device `username` and `password` in plaintext —
  is dropped at decode, never stored, and never logged at any level including debug. Its
  `repr` is just the camera number.
- `CaptureModes` (three independent booleans with a `C`/`M`/`A`-ordered `mode_string`),
  `CameraScheduleAssignment` (read-only schedule ids and overrides), `ArmOverride` with
  the `ARM_OVERRIDES` table and `arm_override()` lookup, and `require_permission()` — the
  first caller of the previously-unused `SecuritySpyPermissionError`.
- `Camera` now decodes its arm state: `capture_modes` and `schedules` come off
  `++systemInfo`'s `*-mode`, `*-schedule-id` and `*-schedule-override` fields.
- The arming override is **transient and bounded** and its duration is typed data;
  the undocumented override value `15` is rejected rather than invented. **Schedules are
  read-only**: `schedule=` is never sent, and a test asserts its absence rather than
  leaving it as a convention.
- One transport seam serves GET-JSON, GET-text and POST-form: URL building, BasicAuth, the
  SSL flag, the timeout, redirect handling, status mapping, the 8 MiB body cap and the
  never-echo-the-body rule have exactly one implementation.

- `EpisodeReducer`: the detection-episode reducer, turning the per-frame `CLASSIFY`
  inference stream into `EpisodeOpened` / `EpisodeClosed` emissions. Research §3.5's
  reference burst — 191 signals on one camera in 95 s with confidence swinging 8 → 97
  between adjacent frames — reduces to exactly one episode with a peak confidence of 99,
  which is asserted rather than assumed: the ~190:1 ratio is a correctness requirement.
  The component is **pure**: no I/O, no network, no `asyncio`, no timer, and no clock read
  anywhere. Every instant comes from the caller, so the whole edge-case matrix is
  exercisable from synthetic signals with no session, no server, and no event loop.
- Threshold, debounce and inactivity gap are injected **per camera per object class** via
  `ReducerConfig` and an overrides mapping resolving `(camera, class)` → `(camera, None)`
  → `(None, class)` → the default; nothing in the reduction reads a module constant.
  `config_for()` exposes the resolution.
- **The three defaults are provisional.** `DEFAULT_DETECTION_THRESHOLD` (70 %),
  `DEFAULT_DETECTION_DEBOUNCE` (3 consecutive signals) and `DEFAULT_DETECTION_GAP` (30 s)
  are marked `[ASSUMPTION]` in `const.py`: no measurement in the protocol research
  establishes them, and a consumer needing different values is expected, not misconfigured.
- Episode semantics: an episode opens only after `debounce` *consecutive* at-or-above-
  threshold signals, and closes only on **inactivity** — never on `MOTION_END` (467
  `MOTION` records and 0 ends on camera 10) and never on a run of below-threshold frames,
  which are mid-episode rather than the end of one. `peak_confidence` spans the whole
  episode, including the debounce signals that opened it and any below-threshold frame
  inside it, so it is never the value at the threshold crossing. Exactly one open and one
  close per episode; signals in between are absorbed silently.
- The caller owns the clock: `tick(now)` closes what has lapsed, and `add()` runs the same
  inactivity check against the incoming signal's timestamp through the same helper, so a
  boundary computed by a tick and one computed by an arrival are the same instant. `end`
  is `last_signal + gap` — when the episode actually lapsed — so a late tick does not
  stretch it. `close_all(now)` ends everything open at a disconnect; `reset()` discards
  state and deliberately emits nothing, because resetting is not a claim that anything
  ended.
- `feed(stream_event)` fans a `StreamEvent` into one signal per object class at the
  event's timestamp. A non-`CLASSIFY` event, a missing or wrong payload, a missing
  timestamp or camera, a blank label, and a non-finite confidence are all ignored rather
  than raised on: one record must not kill a live stream. Two raw labels that slug the
  same are one episode (the higher confidence wins, as `ClassificationPayload.slugged()`
  already resolves them) and both raw labels are recorded. An out-of-order signal is
  counted and can raise the peak, but never rewinds the inactivity deadline; a backwards
  `tick` closes nothing. The class vocabulary stays open — no enumeration, no validation.
- An override **replaces** the matched configuration outright rather than merging into the
  `default`, which `config_for()` and the README both now state explicitly, since a
  partially-specified override otherwise appears to inherit and does not. Two override
  keys that normalize to the same `(camera, class)` pair are a `ValueError` rather than a
  silent last-one-wins.
- `add()` applies its inactivity check to the incoming signal's own camera and class only.
  A signal's timestamp is evidence about the camera that produced it, and camera clocks
  disagree; sweeping every track from it would let one fast camera close every other
  camera's live episode at an `end` in their future. `tick(now)` still sweeps everything,
  because there `now` is the caller's single authoritative clock.
- Caller mistakes are `ValueError` at construction, naming the field and quoting no value:
  a threshold outside 0–100 or non-finite, a debounce below 1, a non-positive gap, a
  `default` or override value that is not a `ReducerConfig`, a non-integer camera, an empty
  object class, a naive timestamp, or an override key that is not a `(camera, class)` pair
  — including `(None, None)`, which would silently never be consulted.
- `DEFAULT_DETECTION_GAP` is a `timedelta`, so passing the public constant into the field
  it is the default for works rather than raising.
- Degradation hardening: an episode's `start` moves back to accommodate an out-of-order
  signal older than the span, so `start <= last_signal` always holds; `close_all(now)`
  raises `end` to the episode's own last signal when `now` predates it, so no episode ends
  before it started; a deadline that would overflow near `datetime.max` leaves the track
  open instead of raising out of `tick()`; and a hand-built `ClassificationPayload`
  carrying a non-numeric confidence is skipped rather than raising out of `feed()`. A
  multi-class frame emits in slug order, matching every other method here.
- Labels containing no `[a-z0-9_]` characters at all — a class named only in a non-Latin
  script — all slug to `"unknown"` and therefore share one episode per camera. This is the
  accepted cost of having a single normalizer on the path to a permanent key; the raw
  labels remain distinguishable in `DetectionEpisode.raw_labels`. Documented on the model
  and pinned by a test.
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

## [0.1.0] - 2026-08-28

### Added

- Initial publishable package skeleton: `src/` layout, hatchling build backend, and all
  configuration in `pyproject.toml`.
- `aiosecurityspy.__version__`, single-sourced from package metadata.
- `py.typed` marker so type information ships to consumers.
- ruff (lint + format) and `mypy --strict` gates, plus a pytest suite.
- GitHub Actions CI and a PyPI trusted-publisher (OIDC) release workflow.

[0.1.0]: https://github.com/aljopro/aiosecurityspy/releases/tag/v0.1.0
