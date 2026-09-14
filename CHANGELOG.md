# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-09-13

### Added

- `client.async_get_camera_image(server_info, camera_number, *, width=None, quality=None)`:
  a camera's current still image from `++image`, returned as a `CameraImage`
  (`data: bytes`, `content_type: str`; its `repr` hides the bytes). The credential
  travels in the `Authorization` header only. A camera absent from
  `server_info.cameras` raises `SecuritySpyPermissionError` without a request; a bad
  camera number, a `width` below 1 or a `quality` outside 0-100 raises `ValueError`; a
  response that is not an image raises `SecuritySpyConnectError`.
- `ENDPOINT_IMAGE` constant.

## [0.3.0] - 2026-09-13

### Added

- `RtspRelay`, created with `client.create_rtsp_relay(server_info)`: a local asyncio
  RTSP relay that hands a consumer (ffmpeg, go2rtc, VLC, Frigate) a URL of the form
  `rtsp://127.0.0.1:<port>/<id>` carrying no credential. `<id>` is an unguessable
  per-camera token, fixed for the relay's life. The relay authenticates upstream with
  an `Authorization: Basic` header only, rewrites every SecuritySpy URL in responses
  (including the malformed single-slash `rtsp:/host:port/…` form) to its own address,
  drops `WWW-Authenticate`, `SS-UUID` and `Server`, and copies interleaved RTP
  untouched. TCP interleaved transport only. The upstream leg is cleartext RTSP on the
  LAN, as SecuritySpy offers no RTSPS. `max_connections` (default 16) caps the consumer
  connections served at once; more are answered `503`.
- `client.unsecured_stream_url(server_info, camera_number)`: SecuritySpy's own RTSP
  URL for a camera, with no credential in it.
- `ServerInfo.rtsp_port`: the web server's `http-port` when `http-enabled` is truthy,
  otherwise `None`. SecuritySpy serves RTSP on that listener.

## [0.2.0] - 2026-09-12

Breaking, pre-1.0. Two public-surface changes in this release that a 0.1.0
consumer must adapt to (the full list of breaking changes is under ### Changed
below):

- `server_timezone` is now a **required** keyword on `client.event_stream()`,
  `client.async_get_captures()`, `parse_event_line()` and `Capture.from_api()`.
  It previously defaulted to UTC, which silently shifted every event and capture
  time on a server in any other zone (story 1.13). SecuritySpy publishes an
  *offset*, not a timezone; build one with `timezone(info.utc_offset)`.
- `Capture.file_size` is renamed **`Capture.file_size_mb`** and decodes as
  fractional megabytes rather than an integer byte count, which is what
  `caplist`'s `m` field actually carries (story 1.15).

### Changed

- The event stream delivers events on a task of its own, fed by a bounded queue,
  rather than awaiting `on_event` inside the read loop. A handler that blocked
  forever used to park the reader inside it: the heartbeat watchdog wraps the
  socket read, so it never got another chance to fire and the stream was
  silently dead with no `disconnected` and no reconnection. Lifecycle callbacks
  share the queue, so they stay ordered against the events around them. A
  consumer that falls far enough behind now loses the oldest queued events, with
  a warning, rather than stalling the socket.
- `StreamEvent` carries `raw_camera`, the camera field exactly as it arrived.
  `camera is None` alone could not distinguish "not camera-specific" — a `NULL`
  heartbeat — from a mis-framed record, so a consumer applied garbage
  server-wide. Symmetric with the existing `timestamp` / `raw_timestamp` pair.
- `SecuritySpyClient.event_stream()` forwards the stream's tuning parameters.
  They were validated by the constructor but unreachable through the
  construction path the docs point at, so tuning a slow link meant reaching into
  internal state.
- Reconnect backoff resets only after a connection that actually delivered a
  record. Headers alone set `connected`, so a server answering `200` and closing
  the body reset the delay on every cycle and was retried roughly once a second,
  indefinitely.

### Fixed

- `connect()` is no longer a silent no-op after a `disconnect()` issued from
  inside a consumer callback. That path cannot await the task it cancels, so the
  following `connect()` saw a still-running reader and started nothing — leaving
  a permanently dead stream that had reported success. Intent is now tracked
  explicitly and the restart is deferred to the outgoing reader's completion.
- `resume()` no longer restarts a stream the consumer explicitly disconnected.
  An authentication pause survives `disconnect()` by design, so auth-fail →
  `disconnect()` → `resume()` opened a live socket against an object the
  consumer believed was dead.
- A camera field that is not an unsigned decimal no longer becomes a camera
  number. `-1` arrived as camera `-1` and `+3` aliased onto camera 3, so a
  consumer keying entities by camera number built one that cannot exist.
- `CLASSIFY` decoding re-syncs after an unparseable confidence instead of
  stepping by a fixed two. One bad number shifted the label/number phase for the
  rest of the record, silently dropping every later pair and letting a number be
  captured as a label.
- The read buffer is now bounded by `max_record_bytes` rather than reaching
  roughly twice it. The drop check runs after the chunk is appended, and a flat
  64 KiB read against the 64 KiB default meant peak occupancy of ~128 KiB.
- A non-2xx event-stream response is logged at warning level, with the REST
  path's own "construct the client with `use_https=True`" hint on a redirect. A
  wrong scheme was an infinite retry loop with nothing above debug to explain it.
- Unknown-event-type log damping is per stream instead of process-global. Two
  streams against two servers shared one set, so the second silently never
  reported a type the first had logged.
- Tuning that would have failed deep in the transport is rejected at
  construction: `heartbeat_misses` and `max_record_bytes` must be integers (a
  float reached `content.read(0.5)` and was swallowed into a forever-failing
  retry loop), `backoff_multiplier` must be at least 1 (below 1 shrank the delay
  into a busy-loop), and `backoff_initial` must not exceed `backoff_max`.
- `validate_host` raises `TypeError` for a non-string host instead of
  `AttributeError` from `.strip()`, and a non-numeric `timeout` raises `TypeError`
  naming the parameter instead of one from inside `math`. Both slipped past
  callers catching `(ValueError, TypeError)`.
- `ClassificationPayload` wraps a directly-supplied mapping, so the read-only
  view its annotation promises holds for a hand-built payload too. A value that
  is not a mapping is left untouched, since the reducer's contract is to
  tolerate one rather than raise.
- An `ERROR` description is stripped whether or not the server led with a
  numeric code, and a `FILE` path no longer keeps trailing whitespace — interior
  spaces are still preserved.

- `EpisodeReducer` no longer keeps an episode open for the duration of a forward
  clock skew, nor closes a still-active one early because of ordinary,
  sustained drift between the signal source's clock and the caller's. A record
  stamped ahead of the caller's clock used to pin the inactivity deadline to
  that future instant, so a signal an hour ahead held the episode open for an
  hour. `tick(now)` now bounds such a track to a `skew_ceiling` of one gap past
  the tick that first noticed the anchor was ahead of `now`, without ever
  touching the track's own `start`/`last_any`/`last_qualifying`: an emitted
  episode always reports the true, unmutated timestamps, even when they were
  poisoned by a bad future-stamped signal. That ceiling re-extends itself
  whenever the anchor has genuinely advanced since it was set (fresh
  qualifying signals kept arriving) and only holds fixed once the anchor
  stalls (real silence), so a continuously-active track under a small,
  sustained clock disagreement between the two clocks — ordinary in a
  deployment with no NTP guarantee between them, not just an hour-scale
  anomaly — is never closed early merely because polling happened to catch it
  mid-drift. The ceiling applies only to `tick`'s own evaluation, never to
  `add`'s "close by arrival" check: an arrival's own timestamp is exactly the
  value under suspicion, so bounding it against a ceiling some earlier tick
  set could otherwise close, and split in two, a track that kept receiving
  genuine signals the whole time. `deadline()` falls back to the ceiling when
  the true deadline's own arithmetic overflows (an extreme, near-`datetime.max`
  anchor), since the ceiling is computed from `now + gap` and cannot itself
  overflow — and setting the ceiling is itself guarded against `now` being
  within one gap of `datetime.max`. `tick`'s `now` is the only authority for
  all of this — a signal's own timestamp is the value a skew corrupts — so
  this is the one place where the tick and arrival paths deliberately differ;
  they still agree instant for instant on unskewed input.
- `SecuritySpyClient.async_get_captures()` (`++caplist`) now names the
  `'files'` permission on a denied request instead of `"unknown"`. `++caplist`
  is the same 'files'-gated capture-access surface as `++getpreview` and
  `++getfile` (research §5, "Get captured footage" -> `PERM_FILES`), but its
  request never passed a `permission=` context, so `SecuritySpyPermissionError`
  fell back to its unknown-permission sentinel for this one call site while its
  sibling media methods correctly named `'files'` for the identical bit.
- `EpisodeReducer.add()` now runs the inactivity check for a signal whose
  confidence is non-finite. The confidence is still ignored, but the timestamp
  is usable evidence that time has passed, so a lapsed episode no longer stays
  open just because the only later signals were NaN.
- `EpisodeReducer.feed()` no longer raises on a hand-built record: a naive
  timestamp, a bool camera, and a `ClassificationPayload` whose `classes` is not
  a mapping are all skipped rather than escaping as `ValueError`/`AttributeError`.
  The library's own parser cannot produce any of them, but `feed()` promises not
  to die on one record, and the loop was already hardened for hand-built labels
  and confidences.
- `EpisodeReducer.config_for()` rejects a bool camera instead of silently
  resolving camera 1's override (`True` hashes equal to `1`).
- A non-mapping `overrides` argument is the documented `ValueError` rather than
  an `AttributeError` from inside the constructor.

### Documentation

- `DetectionEpisode.start` and `.peak_confidence` now record that two episodes
  for one camera and class **can overlap**: a delayed signal stamped inside an
  already-closed episode is absorbed by its successor, moving that episode's
  `start` back before its predecessor's `end` and possibly setting its peak from
  a signal that belonged to the predecessor.
- The claim that episodes close "never on low confidence" is corrected
  throughout: closure is the absence of a *qualifying* signal for longer than the
  gap, so a dense below-threshold run lasting longer than the gap does close an
  episode.

### Added

- **`SecuritySpyClient.async_get_visible_cameras()`** answers "which cameras
  may this account see, and how are they right now?" in one call. It composes
  `async_get_server_info()` -- the only permission-scoped inventory surface
  (research gap G8) -- with `async_get_camera_status()`, which returns every
  camera on the server to any authenticated account regardless of permission,
  and intersects them via the new `visible_camera_views()` so a camera absent
  from `++systemInfo` can never reach the result. A disabled camera and a
  de-permissioned camera are indistinguishable here, by design (FR-16a): both
  are simply absent.
- **`SecuritySpyClient.async_refresh_camera_status(server_info)`** is the
  cheap-poll counterpart: given a `ServerInfo` the caller already holds, it
  issues only `++camStatus` -- no re-read of `++systemInfo` -- so a
  coordinator polling on a cycle is not forced to pay for a 27 KB read every
  tick.
- **`aiosecurityspy.visible_camera_views(server_info, statuses)`** is the pure
  intersection behind both of the above: `CameraStatus` rows for cameras
  outside `server_info.cameras` are discarded at the point of receipt, never
  returned and never logged by number -- only a discard count may be logged.
  Returns a tuple of the new `CameraView(camera, status)` pairs, one per
  member camera, in `server_info.cameras` order.
- **`Camera.can_receive_audio` / `Camera.can_send_audio`** are pure
  properties that separate permission from liveness for the two audio bits
  that SecuritySpy clears while a camera is disconnected and restores on
  reconnect (research §5.11). Each returns `None` while the camera is
  disconnected -- never `False` -- so "the camera is unplugged" can never be
  read as "you are not allowed".
- **`ServerInfo.utc_offset`** decodes the server's own UTC offset from
  `seconds-from-gmt` on `++systemInfo` (research §5.7), exposed as a `timedelta`.
  `None` when the field is absent, non-integral, or beyond +/-24h -- never coerced
  to zero, which is a legitimate real offset (the server is on UTC) and must stay
  distinguishable from "unknown". This is the value the four entry points below
  now require you to supply.
- **`aiosecurityspy.IDENTIFYING_KEYS`** is the declared vocabulary of
  identifying-network-detail keys (`wan-address`, `ddns-name`, `deviceList`,
  normalized the same way `CREDENTIAL_KEYS` is) a consumer can extend when a
  future SecuritySpy endpoint exposes a new identifying field. A new
  `aiosecurityspy.is_identifying_key()` predicate mirrors
  `is_credential_key()`: same exact-membership semantics, same
  normalization, same fail-closed behaviour on a non-string.

### Changed

- **AD-13 widened.** `is_credential_key()` now recognises SecuritySpy's
  `*Pass` camelCase convention (`setPass`, `fsPass`, `quitPass` -- research
  §5.18.3) on the original, pre-normalization key, where the `Pass` is a
  distinct word at the end of the name. `videoPassthrough` is not a credential
  because its `Pass` is embedded in `Passthrough`, not at the end. The bare
  normalised spelling `pass` is still in `CREDENTIAL_KEYS`, so a key with the
  exact name `pass` was already a credential. The rule is the convention, not a
  substring of the normalised form. A diagnostics dump that previously
  published `setPass`/`fsPass`/`quitPass` in cleartext no longer does.
- **`anonymize()` now redacts identifying network detail as a separate
  disclosure class.** `server.wan-address` (a personal `*.viewcam.me` hostname
  visible to Administrator accounts, research §5.11), `ddns-name`, and
  `deviceList` (ONVIF discovery: camera LAN IPs and UUIDs, §5.17.2) are now
  replaced with `REDACTED` at every level of the walk -- including when the
  field is nested under a `server` block. The predicate is
  `is_identifying_key()`; the vocabulary is `IDENTIFYING_KEYS`; the
  extensibility contract mirrors `CREDENTIAL_KEYS`. A new identifying field
  a future endpoint exposes is one declaration in `const.py` away from being
  redacted.
- **The `auth=` query parameter is redacted in both its forms.** The base64
  form (`auth=Ym9iOnMzY3JldA`, which is the account's `username:password`
  encoded) was already caught by the parameter-name predicate; the
  `!`-prefixed scoped stream token form (`auth=!abc123-…`, research §5.16.1)
  is now covered with a regression test pinning both its standalone-URL and
  free-text-embedded shapes. Neither token value ever survives in a shareable
  artifact.
- The `_LOGGER.debug` calls in `client.py`, `events.py`, `models.py`, and
  `stream.py` were audited against the widened AD-13. None of them log a
  credential-, secret- or PII-bearing value: every call either logs a type
  name, a count, a fixed string, or a value explicitly verified as
  non-sensitive in the surrounding comment. The two `_LOGGER.exception`
  calls in `stream.py` log a callback's traceback -- a callback is consumer
  code, not library code, and its exception arguments are out of the
  library's control; the traceback logging is the consumer's responsibility
  to keep safe.

- **BREAKING: `async_set_camera_arming`'s `override` argument is now required
  and has no default.** It previously defaulted to `ARM_OVERRIDE_UNCHANGED`
  (`-1`), which research §5.15.5 confirms on the wire is the server's "leave
  as-is" sentinel. Because `schedule=` is never sent (AD-7), `override` is the
  only value this method ever applies -- so a defaulted call sent
  `mode=<target>&override=-1`, targeted capture modes, applied nothing, and
  returned `200 OK` having done nothing. That is exactly the undetectable no-op
  the previous release refused an empty *target* for, left in place as an empty
  *value*. Passing `ARM_OVERRIDE_UNCHANGED` explicitly is still legal; it is now
  an instruction the caller states rather than one the signature supplies.
  Callers relying on the default get a `TypeError` at the call site rather than
  a silent no-op at runtime.

- **BREAKING: `Capture.file_size` is renamed `Capture.file_size_mb` and is now
  decoded as a fractional count of megabytes (a `float`), exactly as the wire
  sends it.** `caplist.m` is a float in megabytes — verified live across 10,476
  captures in the observed range 0.04–9129.763 (research §5.6), with
  SecuritySpy's own client naming the parameter `mb`. The old `int | None`
  decode ran the deliberately strict `_as_int` over it, so 10,468 of 10,476
  captures silently decoded to `None` — the 8 that survived were megabyte counts
  under a name that read as bytes. Values still decode to `None` exactly as
  before when the key is absent, negative, non-finite, or malformed. No
  conversion to bytes is applied: the field carries the decimal megabytes as
  transmitted, so a consumer that needs bytes must choose its multiplier
  deliberately rather than inherit a guessed one. `_tiebreak` still orders on
  the size, with `-1` staying unreachable by a real value, so capture ordering
  is unchanged.
- **BREAKING: `server_timezone` is now a required keyword argument, with no
  default, on `parse_event_line()`, `SecuritySpyEventStream.__init__()`,
  `SecuritySpyClient.event_stream()` and `SecuritySpyClient.async_get_captures()`.**
  All four previously defaulted to `UTC`, which silently produced the wrong
  instant on any server that is not actually on UTC -- verified live: the
  6.21 heartbeat `20260829062049` decoded as `06:20:49Z` when the server's own
  published offset (`seconds-from-gmt: -18000`, UTC-5) makes the true instant
  `11:20:49Z`, five hours off (research §5.7). `Capture.from_api()` already
  required this argument; the outer layers now agree with the layer they wrap.
  Every call site must pass a zone explicitly -- decode `ServerInfo.utc_offset`
  and wrap it in `datetime.timezone(...)`, or pass a `zoneinfo.ZoneInfo` if you
  know the server's real IANA zone (recommended for DST-correct historical
  decoding of `caplist` windows that can span a transition -- an offset alone
  cannot express that). See the README's "Timezones" section for both patterns.
  The library still never fetches `++systemInfo` on your behalf to fill this in;
  that would be hidden state with an ordering dependency.
- **BREAKING: HTTP `403` no longer raises `SecuritySpyAuthError` -- it raises
  `SecuritySpyPermissionError`.** Verified against a live 6.21 server (research
  §4.1, §5.2, §7.1), `403` means the credentials were *accepted* and the account
  merely lacks a permission bit; `401` alone means the credentials were rejected.
  Any consumer that previously caught `SecuritySpyAuthError` to handle both status
  codes -- for example to trigger a credential re-prompt -- now needs to catch
  `SecuritySpyPermissionError` too, since re-authentication cannot fix a missing
  permission. `SecuritySpyPermissionError` already existed and already carries a
  `permission` name and an optional `camera_number`; `async_get_camera_settings()`,
  `async_set_camera_settings()` and `async_set_camera_arming()` now name the
  `"settings"`/`"schedule"` permission and the camera on a `403`. Every other
  endpoint still raises `SecuritySpyPermissionError` on `403`, without a name it
  cannot honestly supply. `401` behaviour, message and type are unchanged.
- **BREAKING: `async_set_camera_arming` now treats its capture modes as the set
  the write *targets* and applies `override` to exactly those modes.** Verified
  live (research §5.14), `mode` on `++ssSetSchedule` selects *which* of the
  three capture modes a write applies to — it is not their armed state — and
  `override` is the value applied to the selected modes. An all-false mode set
  now raises `ValueError` before any request, instead of sending a silent no-op
  `mode=` that the server answered with `200 OK` having done nothing; a consumer
  relying on the old all-false call was relying on a no-op. `200 OK` now
  documents as *accepted*, not *applied*: the server returns it even when
  nothing changed, and the library performs no read-back to confirm an effect.
  `schedule=` is still never sent (AD-7).

### Fixed

- **`PERM_SETTINGS` (bit 4), `PERM_NODOWNLOAD` (bit 12) and `PERM_PUSH_STREAMS`
  (bit 13) are now recognised.** The permission bitmask was missing the very bit
  that gates settings writes: `PERMISSION_NAMES` now decodes `"settings"` and
  `"push_streams"` in addition to the existing seven names. `PERM_NODOWNLOAD` is
  exported as a constant for a consumer that wants to test it directly, but
  deliberately excluded from `PERMISSION_NAMES`: it is an inverted, deny-shaped
  bit ("hide download options"), and that mapping feeds `has_permission()`, which
  reads as *grants*.
- **`ServerInfo._decode_cameras` now recognises a top-level `camera-list` key** -- the
  shape a real SecuritySpy 6.21 server actually sends -- in addition to the existing
  `cameralist.camera` (list or single object) and bare `camera` forms, all of which keep
  working unchanged. Previously, a live server's `camera-list` array fell through the
  lookup silently and `async_get_server_info()` reported an inventory of **zero cameras**
  against a server reporting eleven, with no error, only a debug log -- blocking every
  camera-scoped feature.
- **An unlocatable camera inventory now raises `SecuritySpyUnsupportedVersionError`**
  where it previously returned an empty `{}` silently. The two cases are
  indistinguishable to a consumer but mean opposite things: a genuinely empty, located
  list (`camera-count: 0`) still decodes to a success with no cameras, but no recognised
  camera-list key at all, or a located list that decodes to nothing while the server
  reports a positive `camera-count`, is now a typed decode failure instead of a
  plausible-looking empty result. A partial mismatch (some cameras decode, the count
  doesn't match) is unaffected and stays a debug log.

### Added

- **OpenAPI description of the SecuritySpy HTTP API** at `docs/securityspy-openapi.yaml`,
  shipped in the sdist and schema-validated in CI. Each operation records whether it was
  verified against a live server, read from the shipped web client, or taken from research
  only. The parts OpenAPI cannot express — `++getpreview`'s double-`?` URL, the `formData`
  body sentinel, id-keyed checkbox fields — are annotated rather than normalised.

- **Capture media fetch.** `async_get_capture_preview()` returns a capture's JPEG thumbnail
  as raw bytes + content type; `async_get_capture_file()` returns a `CaptureFileStream` --
  an async-iterable that yields the file body in bounded chunks without ever buffering the
  full recording. Both derive their URL entirely from a `Capture` (no caller-supplied path,
  folder date, or raw query parameter). The `archive` flag defaults to
  `capture.archived`; an explicit override is available on the file fetch. Bandwidth
  selection (`CAPTURE_FILE_BANDWIDTH_STANDARD`, `_HIGH`, `_LOW`) picks one of three
  distinct endpoint paths (`++getfile`, `++getfilehb`, `++getfilelb`);
  `CaptureFileStream.content_type` reports the content type the server actually sent.
  The stream supports `async with` and `aclose()` so a consumer that does not drain it can
  still release the connection. Transport errors during streaming (connection drop,
  timeout, OS error) are wrapped into `SecuritySpyConnectError`.
- `CapturePreview` frozen dataclass (`data: bytes`, `content_type: str`) for the preview
  return value.
- `CaptureFileBandwidth` frozen dataclass with a `capture_file_bandwidth()` lookup
  function, mirroring the `ArmOverride`/`arm_override()` pattern.
- `CaptureFileStream` exported from the package root, so the return type of
  `async_get_capture_file()` is nameable from the public surface.
- `ENDPOINT_GET_PREVIEW`, `ENDPOINT_GET_FILE`, `ENDPOINT_GET_FILE_HIGH_BANDWIDTH`,
  `ENDPOINT_GET_FILE_LOW_BANDWIDTH` protocol constants for the media endpoints.
- `CAPTURE_FILE_BANDWIDTH_STANDARD`, `CAPTURE_FILE_BANDWIDTH_HIGH`,
  `CAPTURE_FILE_BANDWIDTH_LOW` client-side bandwidth selectors.
- **Server and camera health decoding.** `ServerInfo` gains `cpu_usage`, `memory_pressure`,
  `cert_expiry_days` and `update_version`; `Camera` gains `current_fps`, `data_rate`,
  `last_error` and `last_error_description` — all decoded from `++systemInfo` (research
  §10) via a new `_as_float` helper alongside the existing `_as_str`/`_as_int`/`_as_bool`
  tolerant-optional coercions. Every new field is `None` when the server omits it, sends a
  non-numeric value, or — for the fields where only a non-negative reading is meaningful
  (CPU usage, memory pressure, frame rate, data rate) — sends a negative one; the
  surrounding `ServerInfo`/`Camera` decode still succeeds. `cert_expiry_days` is
  deliberately **not** clamped on a negative value: a negative day count is what an
  already-expired certificate reports, and that is exactly the diagnosable state the field
  exists to carry. `update_version` folds `new-version`'s empty string to `None` like every
  other `_as_str` field, and is never compared against `version` — an empty `new-version`
  is the only "no update" signal the API documents.
- `CameraStatus` and `SecuritySpyClient.async_get_camera_status()`: a typed accessor for
  the cheap `++camStatus` poll (794 B for 11 cameras vs `++systemInfo`'s 27 KB), for a consumer that only
  needs to notice a camera going offline, closing, or erroring on every cycle.
  `enabled`/`online`/`open` are three independent booleans, never collapsed, matching the
  precedent `CaptureModes` already set for the three capture modes. `error`/
  `error_description` decode the wire's `err`/`errDesc` keys, named to match
  `Camera.last_error`/`last_error_description`. Zero, not just the empty string, is this
  surface's "no error" sentinel — the one live capture sends `"err":0` on a healthy camera
  — so both spellings decode to `None` and only a non-zero code is carried through. The
  description is decoded with its code rather than independently, so it is `None` whenever
  the code is and can never outlive the fault it describes. `Camera.last_error`/
  `last_error_description` follow both rules, since research §10 lists the two as one
  error surface. An array entry with no usable camera number is skipped — the same
  precedent `Camera.from_api` follows — and the rest of the response still decodes.
- `ENDPOINT_CAM_STATUS` protocol constant for `++camStatus`.
- **Schedule names and the camera enable write.** `ServerInfo` gains `schedules`, a
  read-only id-to-name mapping decoded from `++systemInfo`'s `schedule-list` (research §5.4),
  and `CameraScheduleAssignment.resolve_names()` resolves a camera's three schedule ids to
  names against it — pure and synchronous, with an id absent from the mapping (or already
  `None`) resolving to `None` rather than raising. Schedules remain **read-only**: this
  library still has no method that reassigns one (AD-7), and `schedule=` is never sent to
  `++ssSetSchedule`. New `SecuritySpyClient.async_set_camera_enabled(camera_number, *,
  enabled=)` takes a camera in or out of service (FR-16, research §5.5), writing the single
  `enabled` checkbox key through the same verified partial-write path as
  `async_set_camera_settings()` — `enabled` is read as a JSON bool but written as `1`/`0`,
  an asymmetry that lives entirely in `CameraSettingsPatch.form_fields()` like every other
  boolean. `CameraSettings` and `CameraSettingsPatch` both gain the `enabled` field so the
  read allowlist and the write field tables stay in lock-step.

## [0.1.0] - 2026-08-28

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
  raises `end` to the most recent signal absorbed into the episode when `now` predates it,
  so no episode ends before it started — that clamp is against the last signal of any kind,
  so a span whose trailing frames were below threshold can report an `end` later than its
  own `last_signal`, which is the last *qualifying* one; a deadline that would overflow near `datetime.max` leaves the track
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
- Initial publishable package skeleton: `src/` layout, hatchling build backend, and all
  configuration in `pyproject.toml`.
- `aiosecurityspy.__version__`, single-sourced from package metadata.
- `py.typed` marker so type information ships to consumers.
- ruff (lint + format) and `mypy --strict` gates, plus a pytest suite.
- GitHub Actions CI and a PyPI trusted-publisher (OIDC) release workflow.

[0.4.0]: https://github.com/aljopro/aiosecurityspy/releases/tag/v0.4.0
[0.3.0]: https://github.com/aljopro/aiosecurityspy/releases/tag/v0.3.0
[0.2.0]: https://github.com/aljopro/aiosecurityspy/releases/tag/v0.2.0
[0.1.0]: https://github.com/aljopro/aiosecurityspy/releases/tag/v0.1.0
