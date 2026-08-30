# aiosecurityspy

Async, fully-typed Python client library for the [Ben Software SecuritySpy](https://www.bensoftware.com/securityspy/) HTTP and event API.

## Install

```bash
pip install aiosecurityspy
```

Requires Python 3.14 or newer.

## What this is

`aiosecurityspy` owns all SecuritySpy protocol knowledge — endpoint URLs, event-stream
framing, capture-field and bitmask decoding, the detection-episode reducer, and
credential-safe diagnostics — as an ordinary PyPI package usable from any script.

- **No Home Assistant.** The library imports nothing from Home Assistant and carries no
  Home Assistant test tooling. It works in a bare virtual environment.
- **Session-injected.** `aiohttp` is a declared dependency, but the library never creates
  an HTTP session. The caller owns session lifetime and passes one in.
- **Typed.** A `py.typed` marker ships with the wheel; the source passes `mypy --strict`.

## The API this wraps

SecuritySpy's HTTP API is undocumented by the vendor. This library's description of it lives
in [`docs/securityspy-openapi.yaml`](docs/securityspy-openapi.yaml) — an OpenAPI 3.1 file
that ships in the sdist and is schema-validated in CI.

Read its header before generating anything from it. OpenAPI cannot express several things
this server does, and the file marks them rather than normalising them away: `++getpreview`'s
URL carries a literal `?` inside the path and a second one before `archive`; every settings
POST body must begin with a bare `formData` token that is not a key=value pair; checkbox
fields are keyed by HTML element id and their order matters. A generated client that ignores
those annotations will be broken in ways the description looks like it endorses.

Every operation carries an `x-verification` marker — `live-6.21`, `client-source` or
`research-only` — so you can tell which parts were observed from a running server and which
are still inherited belief. CI fails if an operation lacks one.

## Usage

The caller creates and owns the `aiohttp` session. `aiosecurityspy` never creates,
reconfigures, or closes one — `SecuritySpyClient` deliberately has no `close()`.

```python
import asyncio

import aiohttp

from aiosecurityspy import SecuritySpyAuthError, SecuritySpyClient, SecuritySpyError


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        client = SecuritySpyClient(
            session,
            "nvr.example.com",
            8001,
            username="ha-readonly",
            password="...",
            use_https=True,
        )
        try:
            info = await client.async_get_server_info()
        except SecuritySpyAuthError:
            print("credentials rejected")
            return
        except SecuritySpyError as err:
            print(f"could not read server info: {err}")
            return

        print(f"SecuritySpy {info.version} ({info.uuid}) — {info.camera_count} cameras")
        for number, camera in sorted(info.cameras.items()):
            state = "connected" if camera.connected else "offline"
            print(f"  {number}: {camera.name} [{state}] {sorted(camera.permission_names)}")


asyncio.run(main())
```

### Read the live event stream

`event_stream()` returns a reader that owns its own lifecycle: CR-only record framing,
a heartbeat watchdog (loss after three missed ~10 s heartbeats), indefinite exponential
backoff, and explicit lifecycle callbacks. Callbacks may be sync or async, and one that
raises is logged and swallowed rather than killing the stream.

```python
import asyncio
from datetime import UTC, timezone

import aiohttp

from aiosecurityspy import ClassificationPayload, SecuritySpyClient, StreamEvent


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        client = SecuritySpyClient(
            session,
            "nvr.example.com",
            8001,
            username="ha-readonly",
            password="...",
            use_https=True,
        )

        # server_timezone is required: SecuritySpy's event-stream records carry a
        # bare local wall clock with no offset, so the library will not guess.
        # Decode it from the server's own published offset (see "Timezones" below).
        info = await client.async_get_server_info()
        server_timezone = timezone(info.utc_offset) if info.utc_offset is not None else UTC

        def on_event(event: StreamEvent) -> None:
            if isinstance(event.payload, ClassificationPayload):
                print(f"camera {event.camera}: {dict(event.payload.classes)}")

        stream = client.event_stream(
            on_event=on_event,
            on_connected=lambda: print("stream live"),
            on_disconnected=lambda: print("stream lost; reconnecting"),
            on_reconnected=lambda: print("stream back; reconcile state"),
            on_auth_failed=lambda: print("credentials rejected; call resume() to retry"),
            server_timezone=server_timezone,
        )
        await stream.connect()
        try:
            await asyncio.sleep(60)
        finally:
            await stream.disconnect()


asyncio.run(main())
```

A few things the protocol makes non-obvious:

- **`connected` fires once**, on the first successful connect of the stream's life. Every
  later successful connect fires `reconnected` — including after your own
  `disconnect()`/`connect()` pair, because any gap means state must be reconciled.
- **On 401/403 the stream pauses** rather than retrying. `on_auth_failed` fires once, and
  nothing else happens until you call `await stream.resume()` — `connect()` declines while
  paused, and the pause survives `disconnect()`, so the rejected credential has exactly one
  door out of it. The library never re-authenticates and never counts auth failures.
- **`event.camera is None`** means the record was not camera-specific (the wire format
  sends `X`), not that it was invalid. `NULL` heartbeats arrive this way.
- **`event.event_number` restarts at 0 on every reconnect.** Record it; never key off it.
- **The classification vocabulary is open.** A label from a custom CoreML model arrives in
  `ClassificationPayload.classes` unchanged. Use `slugged()` only when you need a
  permanent key.
- **`MOTION_END` is unreliable** and is not an inactivity signal; implement your own
  timeout if you need one.

- **Backoff resets after every successful connection**, so a server that drops the stream
  periodically retries promptly instead of creeping up to the five-minute ceiling.

`disconnect()` is idempotent, is safe to call from inside a callback, and leaves no task,
timer, or socket behind. Your session is untouched either way.

### Timezones

Every decode entry point that turns a SecuritySpy wall clock into a `datetime` --
`event_stream()`, `async_get_captures()`, and the lower-level `parse_event_line()` and
`SecuritySpyEventStream()` -- takes a **required** `server_timezone` keyword argument.
There is no default, and passing none is a `mypy --strict` failure as well as a runtime
`TypeError`: the wire format sends a bare local wall clock (`YYYYMMDDHHMMSS`, or a folder
date plus seconds-since-midnight) with no offset, and the library will not silently guess
UTC.

`ServerInfo.utc_offset` decodes the server's own answer, `seconds-from-gmt` off
`++systemInfo`, as a `timedelta`:

```python
from datetime import UTC, timezone

info = await client.async_get_server_info()
server_timezone = timezone(info.utc_offset) if info.utc_offset is not None else UTC
```

`utc_offset` is `None` — never coerced to zero — when the server did not publish a usable
value; zero itself is a legitimate real offset (the server is on UTC) and stays
distinguishable from "unknown". The library never fetches `++systemInfo` on your behalf to
fill this in: caching or auto-fetching a timezone behind your back would be hidden state
with an ordering dependency, so it is you who reads `ServerInfo.utc_offset` and passes it
along.

**An offset is not a timezone.** `seconds-from-gmt` is only the offset in force when it
was read — it does not encode daylight-saving rules, and SecuritySpy never publishes an
IANA zone name. A fixed offset built from it is exact for events decoded around the same
time, but a `caplist` window spanning weeks or months can cross a DST transition, and a
fixed offset silently keeps assuming whichever side of the transition it started on. If
you know the server's real IANA zone — Home Assistant callers usually do, via
`hass.config.time_zone` — pass a `zoneinfo.ZoneInfo` instead of a fixed offset for
DST-correct historical decoding:

```python
from zoneinfo import ZoneInfo

server_timezone = ZoneInfo("America/Chicago")
```

**Breaking change:** prior releases defaulted `server_timezone` to `UTC` on these four
entry points, which silently produced the wrong instant on any server that is not
actually on UTC. Every call site must now state a zone explicitly.

### Reduce `CLASSIFY` frames into detection episodes

`CLASSIFY` is a per-frame inference stream, not a detection event: 191 records on one
camera in 95 s, 0–2 s apart, with confidence swinging 8 → 97 between adjacent frames for a
single subject. `EpisodeReducer` turns that into one "a human was here, peak confidence
99". It is a pure component — no I/O, no timers, no `asyncio` — so it is equally usable
against a recording or a list of synthetic signals.

**You own the clock.** A pure reducer cannot notice that *nothing* has happened, so you
must call `tick(now)` periodically or an episode whose camera went quiet stays open
forever. This is the one obligation that fails silently if you skip it.

```python
import asyncio
from datetime import UTC, datetime, timedelta, timezone

import aiohttp

from aiosecurityspy import (
    EpisodeClosed,
    EpisodeOpened,
    EpisodeReducer,
    ReducerConfig,
    SecuritySpyClient,
)


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        client = SecuritySpyClient(
            session,
            "nvr.example.com",
            8001,
            username="ha-readonly",
            password="...",
            use_https=True,
        )

        # An override REPLACES the default outright — it is not merged into it —
        # so each one restates all three values rather than inheriting two.
        reducer = EpisodeReducer(
            default=ReducerConfig(threshold=70.0, debounce=3, gap=timedelta(seconds=30)),
            overrides={
                # A dim doorway camera: lower bar, everything else as above.
                (4, None): ReducerConfig(threshold=50.0, debounce=3, gap=timedelta(seconds=30)),
                # Vehicles are slower and larger: more evidence, longer memory.
                (None, "vehicle"): ReducerConfig(
                    threshold=70.0, debounce=5, gap=timedelta(seconds=60)
                ),
            },
        )

        def report(events: tuple[EpisodeOpened | EpisodeClosed, ...]) -> None:
            for event in events:
                episode = event.episode
                verb = "started" if isinstance(event, EpisodeOpened) else "ended"
                print(
                    f"camera {episode.camera}: {episode.object_class} {verb} "
                    f"peak={episode.peak_confidence:.0f} signals={episode.signal_count}"
                )

        info = await client.async_get_server_info()
        server_timezone = timezone(info.utc_offset) if info.utc_offset is not None else UTC
        stream = client.event_stream(
            on_event=lambda event: report(reducer.feed(event)), server_timezone=server_timezone
        )
        await stream.connect()
        try:
            while True:
                # The tick obligation. Anything comfortably shorter than your gap works.
                await asyncio.sleep(5)
                report(reducer.tick(datetime.now(UTC)))
        finally:
            await stream.disconnect()
            # The stream is gone, so no further signal can arrive: end what is open
            # rather than stranding it.
            report(reducer.close_all(datetime.now(UTC)))


asyncio.run(main())
```

Worth knowing:

- **The three defaults are provisional.** `DEFAULT_DETECTION_THRESHOLD` (70 %),
  `DEFAULT_DETECTION_DEBOUNCE` (3 signals) and `DEFAULT_DETECTION_GAP` (30 s) are starting
  points, not values verified against a real installation. Expect to tune them.
- **Threshold, debounce and gap are per camera per object class.** Overrides resolve
  `(camera, class)` → `(camera, None)` → `(None, class)` → the default, and **the first
  match wins whole**. An override is a replacement, not a merge: any field it leaves out
  falls back to the provisional module default, *not* to the `default=` config you passed.
  Two override keys that normalize to the same pair (`"Delivery Van"` and
  `"DELIVERY_VAN"`) are a `ValueError` rather than a silent last-one-wins.
- **Episodes close on inactivity, never on low confidence.** A run of below-threshold
  frames is mid-episode, not the end of one — and `MOTION_END` is far too unreliable to
  close anything with.
- **`peak_confidence` covers the whole span**, including the debounce signals that opened
  the episode and any below-threshold frame inside it. It is never the value at the
  threshold crossing.
- **`end` is the instant the episode lapsed** (`last_signal + gap`), not the `now` that
  noticed. A late tick does not stretch an episode, and a signal arriving after the gap
  has already elapsed closes the stale episode before starting a fresh debounce run — so
  tick and arrival always agree about where the boundary was.
- **`add()` only expires its own camera and class.** A signal's timestamp is evidence
  about the camera that sent it; one camera with a fast clock must not end another
  camera's live episode. Sweeping everything is `tick(now)`'s job, with your clock.
- **`reset()` emits nothing** on purpose: it means you stopped tracking, not that anything
  ended. Use `close_all(now)` when you do want to claim the boundaries. `close_all` stamps
  `end=now`, raised to the episode's own last signal if your `now` predates it.
- **Two raw labels that slug the same are one episode.** Both are kept in `raw_labels`.
  Note that `class_slug()` keeps only `[a-z0-9_]` and falls back to `"unknown"`, so labels
  written entirely in a non-Latin script all reduce under a single `"unknown"` episode per
  camera; `raw_labels` is where they stay distinguishable.

### Ask when a human was last seen

The event stream is transient and restarts at zero. `++caplist` is SecuritySpy's
*persisted* record, so an answer derived from it is still correct after a restart.
`async_get_captures()` batches every camera into **one** request and lets the server do
the class filtering, so the cost is one request — not one per camera, and not
cameras × classes.

```python
import asyncio
from datetime import UTC, datetime, timedelta, timezone

import aiohttp

from aiosecurityspy import SecuritySpyClient, SecuritySpyError


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        client = SecuritySpyClient(
            session,
            "nvr.example.com",
            8001,
            username="ha-readonly",
            password="...",
            use_https=True,
        )

        # server_timezone is required: `caplist` folder dates plus seconds-since-
        # midnight are a local wall clock, so the library will not guess the offset.
        # For DST-correct historical decoding, pass the server's real IANA zone
        # (e.g. `ZoneInfo("America/Chicago")`) if you know it -- a fixed offset is
        # only exact for the instant it was read at.
        info = await client.async_get_server_info()
        server_timezone = timezone(info.utc_offset) if info.utc_offset is not None else UTC

        today = datetime.now(UTC).date()
        try:
            captures = await client.async_get_captures(
                [1, 2, 3],
                start_date=today - timedelta(days=1),
                end_date=today,
                object_class="human",
                server_timezone=server_timezone,
            )
        except SecuritySpyError as err:
            print(f"could not read capture history: {err}")
            return

        if not captures:
            print("no human captures in the window")
            return

        newest = captures[0]  # results come back newest first
        print(f"camera {newest.camera}: human at {newest.start} ({newest.filename})")
        print(f"  classes={sorted(newest.object_classes)} type={newest.capture_type_name}")


asyncio.run(main())
```

Worth knowing:

- **The date range is required and is never widened.** How far back to look is your
  policy, not the library's.
- **`object_class` is filtered by the server**, and SecuritySpy offers a filter for
  `human`, `vehicle` and `animal` only. Anything else raises `ValueError` before a
  request is issued rather than silently degrading into a fetch-everything scan. For the
  non-class filters (movies only, continuous capture only) pass `capture_filter=` with a
  `CAPTURE_FILTER_*` constant instead; passing both is a `ValueError`. Note that these
  three filters select *motion-capture movies* of that class: a JPG capture or a
  continuous recording that carries the same class in its `o` bitmask is not returned by
  them.
- **Both date bounds are `date` objects, not `datetime`s.** A `datetime` is rejected: the
  server matches folder dates, and an ISO instant is a query it cannot satisfy.
- **The whole response is read into memory** and capped, and `caplist` offers no paging.
  A wide window over many cameras with no filter can exceed the cap and fail; narrowing
  the window or the filter is the fix.
- **`Capture.start` is a timezone-aware UTC instant** reconstructed from the folder date
  plus seconds-since-midnight, because the wire format carries no absolute time.
  `server_timezone=` is required (see "Timezones" below). An unreconstructable time is
  `None` — never epoch, never zero — and those captures sort last. The wire format sends
  a wall-clock second-of-day with no fold bit, so on the one ambiguous local hour of a
  DST fall-back the earlier instant is chosen, and on a spring-forward day two captures
  in the skipped hour can reconstruct to the same instant.
- **`Capture.path` is a `<camera>/<folderDate>/<filename>` triple, not a URL.** It is not
  percent-encoded — real filenames contain spaces — so quote it before use. An entry
  whose filename or folder date carries a path separator gets an empty `path` rather than
  one that could address a different file.
- **`Capture.object_classes` is the persisted classification**, empty rather than `None`
  when the server recorded none.
- **`Capture.capture_type` is a bare `int`** on purpose. `caplist`'s type field and
  `clip`'s `movieType` share a letter and mean different things, so there is no shared
  enumeration; use `is_movie` or `capture_type_name`, and an unknown future value carries
  through rather than being rejected.

### Read and change camera settings, and arm a camera

```python
import asyncio

import aiohttp

from aiosecurityspy import (
    ARM_OVERRIDE_ARMED_2_HOURS,
    CameraSettingsPatch,
    CaptureModes,
    SecuritySpyClient,
    SecuritySpyPermissionError,
    arm_override,
    require_permission,
)


async def main() -> None:
    async with aiohttp.ClientSession() as session:
        client = SecuritySpyClient(session, "nvr.example.com", username="viewer", password="secret")

        # `require_permission` is a pure guard: it costs no round trip, so run
        # it before touching a plane, and guard each call with the permission
        # that call actually needs. `"settings"` covers the settings page --
        # both reading it and writing it; `"schedule"` covers arming. They are
        # separate grants, so holding one says nothing about the other. A
        # server that answers a settings or arming call with 403 raises this
        # same `SecuritySpyPermissionError` even if you skip the guard --
        # `require_permission` just avoids the round trip.
        info = await client.async_get_server_info()
        camera = info.cameras.get(3)
        if camera is None:
            print("camera 3 is not on this server")
            return
        try:
            require_permission(camera, "settings")
        except SecuritySpyPermissionError as err:
            print(err)
            return

        # Read: the returned model carries only curated, credential-free fields.
        settings = await client.async_get_camera_settings(3)
        print(settings.name, settings.overlay_text, settings.motion_sensitivity)
        print(settings.motion_capture_triggers_human)  # a real bool, not 1/0

        # Write: partial. Only the fields you set are sent; everything else on
        # the ~120-key settings page keeps its value. No read-modify-write.
        await client.async_set_camera_settings(
            3,
            CameraSettingsPatch(
                overlay_text="Front Gate",
                motion_capture_triggers_human=True,
                motion_capture_triggers_vehicle=False,
            ),
        )

        # Arming: the three booleans select which capture modes the write
        # targets; an all-false set is refused before any request.
        try:
            require_permission(camera, "schedule")
        except SecuritySpyPermissionError as err:
            print(err)
            return

        override = arm_override(ARM_OVERRIDE_ARMED_2_HOURS)
        print(override.label, override.duration)  # Armed For 2 Hours 2:00:00
        await client.async_set_camera_arming(
            3,
            CaptureModes(continuous=False, motion=True, actions=True),
            override=ARM_OVERRIDE_ARMED_2_HOURS,
        )

        # The camera's arm state comes back off ++systemInfo. `Camera` is
        # frozen, so re-read it: the object fetched above still holds the
        # pre-write state.
        info = await client.async_get_server_info()
        camera = info.cameras[3]
        print(camera.capture_modes.mode_string, camera.schedules.motion_schedule_id)


asyncio.run(main())
```

Three things about this surface are worth stating plainly:

- **The override is transient and bounded.** It suspends the camera's schedule for the
  stated duration and then the schedule resumes; it is not a permanent arm or disarm.
  `override` is **required and has no default**: it is the only value this library ever
  applies, so a defaulted call would target modes, apply nothing, and return `200 OK`
  having done nothing. `ARM_OVERRIDE_UNCHANGED` leaves any existing override alone,
  `ARM_OVERRIDE_NONE` clears it, and the "until next scheduled event" values report
  `duration is None` with `until_next_scheduled` true. `arm_override()` rejects any value
  outside the published `-1`..`14` table rather than guessing.
- **Schedules are read-only.** `Camera.schedules` reports the ids SecuritySpy assigned,
  and no method in this library reassigns one: the arming request sends `cameraNum`,
  `mode` and `override`, and never `schedule=`. The ids resolve to human-readable names
  without a second request: `ServerInfo.schedules` is a read-only id-to-name map decoded
  from the server's `schedule-list`, and `camera.schedules.resolve_names(info.schedules)`
  returns the three names in `(continuous, motion, actions)` order. Schedules are
  user-editable, so an id missing from the map resolves to `None` rather than raising.
- **A camera can be taken in or out of service.** `async_set_camera_enabled(3,
  enabled=False)` writes the settings page's `enabled` checkbox, through the same verified
  partial-write path as `async_set_camera_settings` — only the one field is sent, and the
  read-as-bool/write-as-`1`/`0` asymmetry is absorbed by the library.
- **A settings payload contains the camera's device credentials in plaintext.**
  `CameraSettings` therefore keeps only a declared, curated set of non-credential fields —
  the raw payload is dropped at decode, never retained, and never logged at any level
  including debug. Its `repr` is deliberately just the camera number.

Booleans read back from SecuritySpy as JSON `true`/`false` but must be *written* as
`1`/`0`. That asymmetry is absorbed inside the library, so a call site only ever sees
`bool`.

### Check server and camera health

`ServerInfo` and `Camera` (from `async_get_server_info()`) carry a handful of health
fields alongside the identity and permission ones: server `cpu_usage`, `memory_pressure`,
`cert_expiry_days` and `update_version`, and per-camera `current_fps`, `data_rate`,
`last_error` and `last_error_description`. Every one of them is `None` when the server
omits it, sends something unparseable, or — for the fields where only a non-negative
number means anything (CPU usage, memory pressure, frame rate, data rate) — sends a
negative one; decoding never raises over a missing or malformed health reading.
`cert_expiry_days` is the one exception to the non-negative rule: a *negative* count is
exactly what an already-expired certificate reports, so it is passed through rather than
clamped to `None`. `update_version` is `None` both when `new-version` is absent and when
it is the empty string SecuritySpy sends to mean "no update offered" — it is never
compared against `version`, since an empty `new-version` is the only "no update" signal
the API documents.

For a cheap health poll on every cycle, `async_get_camera_status()` reads `++camStatus` —
794 B for 11 cameras versus `++systemInfo`'s 27 KB — and returns one typed `CameraStatus` per camera the
server reports:

```python
statuses = await client.async_get_camera_status()
for status in statuses:
    state = "online" if status.online else "offline"
    print(f"camera {status.number}: {state}, enabled={status.enabled}, open={status.open}")
    if status.error is not None:
        print(f"  error: {status.error} ({status.error_description})")
```

`enabled`, `online` and `open` are three independent booleans, never collapsed into one
state. `CameraStatus.error`/`error_description` decode the wire's `err`/`errDesc` keys and
mirror `Camera.last_error`/`last_error_description` in naming. A healthy camera reports
*zero* on this surface, not an empty string — the one live capture of `++camStatus` sends
`"err":0` — so both an empty and a zero error code decode to `None`, and the
`if status.error is not None` test above means "this camera is actually reporting an
error". A non-zero code is carried through as the server's own string. The description is
decoded with its code, never independently: when the code folds to `None`, so does
`error_description`, so a description can never outlive the fault it describes.
`Camera.last_error`/`last_error_description` follow both rules, since research §10 lists
the two as one error surface. An entry with no usable camera number is skipped, the same precedent
`Camera.from_api` follows, and the rest of the response still decodes.

### Fetch capture previews and recordings

`async_get_capture_preview()` returns the JPEG thumbnail for a capture as raw bytes, and
`async_get_capture_file()` returns a streaming handle to the recorded file. Both derive
their URL entirely from a `Capture` -- no caller-supplied path, folder date, or raw query
parameter.

```python
# Get the thumbnail for a capture
preview = await client.async_get_capture_preview(capture)
# preview.data is the JPEG bytes, preview.content_type is "image/jpeg"

# Stream the recorded file (never fully buffered)
async with await client.async_get_capture_file(capture) as stream:
    async for chunk in stream:
        process(chunk)  # each chunk is a bounded slice of the file body
```

A few things the protocol makes non-obvious:

- **The `archive` flag is derived from `Capture.archived` by default.** Both calls work
  from the `Capture` alone. An explicit `archive=True` or `archive=False` on the file fetch
  overrides it.
- **`getpreview`'s `archive` flag travels inside the path string.** The URL is
  `++getpreview?/{camera}/{folderDate}/{filename}?archive={0|1}` -- a literal second `?`,
  not `&`. The library assembles this correctly so you never have to think about it.
- **Bandwidth selects one of three endpoint paths.** `CaptureFileBandwidth.STANDARD` (the
  default) uses `++getfile`, `HIGH` uses `++getfilehb`, and `LOW` uses `++getfilelb`. Pass
  a `CAPTURE_FILE_BANDWIDTH_*` constant or a `CaptureFileBandwidth` record.
- **`stream.content_type` is what the server sent.** The variants usually differ
  (`++getfilelb` typically serves `video/mp4`, the others QuickTime), but the library
  reports the response's own content type rather than asserting one from the bandwidth you
  asked for, so it cannot drift from what is actually on the wire.
- **The file stream never buffers the full body.** Bytes are read and yielded in bounded
  chunks, so even a multi-gigabyte recording stays at one chunk in memory at a time. There
  is no total deadline, so a large transfer is not cut short, but the per-read socket
  timeout is bounded: a server that sends headers and then stalls fails instead of hanging.
- **Release the stream if you do not drain it.** Iterating to the end releases the response
  for you. If you stop early, or never iterate at all, use `async with` (as above) or call
  `await stream.aclose()` -- otherwise the connection stays checked out of your session's
  pool. Re-iterating a stream raises `RuntimeError`: the body is consumed as it is read, so
  a second pass could only yield a truncated remainder.
- **Transport errors during streaming are wrapped.** A connection drop mid-iteration raises
  `SecuritySpyConnectError`, not a bare `aiohttp.ClientError` or `TimeoutError`.

### Anonymize a diagnostics dump before you publish it

The library keeps credentials out of its own models, logs, URLs and exceptions. What it
cannot do is see the object *you* are about to write to a diagnostics file, a bug report
or a log line. `anonymize()` is that tool, and `redact_url()` is the one you need before a
credential-bearing stream URL reaches a log or a subprocess argument — that exact leak has
been observed in the wild, where an external tool echoed an `rtsp://user:pass@host/…` URL
back verbatim.

```python
from aiosecurityspy import CREDENTIAL_KEYS, anonymize, redact_url

# A raw ++settings-cameras page carries the camera's device credentials in
# plaintext. Structure survives; only the credential-shaped values go.
raw = {
    "name": "Driveway",
    "overlayText": "Front Gate",
    "motionSensitivity": 55,
    "passwordProtected": True,  # not a credential — a fact worth keeping
    "username": "camera-admin",
    "password": "hunter2",
}
print(anonymize(raw))
# {'name': 'Driveway', 'overlayText': 'Front Gate', 'motionSensitivity': 55,
#  'passwordProtected': True, 'username': '**REDACTED**', 'password': '**REDACTED**'}

# Anything at all: a library model, an aiohttp.BasicAuth, a config mapping, a
# list of URLs. Pass your own known secrets when you have them — key matching
# cannot see a password embedded in a free-text field, but you know yours.
print(anonymize({"note": "login failed for hunter2"}, secrets=["hunter2"]))
# {'note': 'login failed for **REDACTED**'}

# A URL embedded in an ordinary message is redacted where it sits.
print(anonymize({"note": "connecting to rtsp://bob:hunter2@nvr.example.com/x"}))
# {'note': 'connecting to rtsp://**REDACTED**:**REDACTED**@nvr.example.com/x'}

# Before a URL is logged, printed, or handed to ffmpeg as an argument:
print(redact_url("rtsp://bob:hunter2@nvr.example.com:8000/++stream?auth=Ym9i&cameraNum=3"))
# rtsp://**REDACTED**:**REDACTED**@nvr.example.com:8000/++stream?auth=**REDACTED**&cameraNum=3

# One declared vocabulary, and it is the only place to extend.
print(sorted(CREDENTIAL_KEYS))
# ['apikey', 'auth', 'authorization', 'authtoken', 'bearer', 'cookie',
#  'credentials', 'pass', 'passphrase', 'passwd', 'password', 'privatekey',
#  'secret', 'sessionid', 'setcookie', 'token', 'username', 'xapikey']
```

Three things worth knowing about it:

- **`aiosecurityspy.const.CREDENTIAL_KEYS` is the single place to extend.** Every redaction
  decision — in `anonymize()` and in `redact_url()` alike — routes through
  `is_credential_key()`, which tests the key lowercased with non-alphanumerics stripped for
  *exact* membership in that one set. So `authToken`, `auth_token` and `AUTH-TOKEN` all
  match, while `passwordProtected` does not: it is a boolean telling you whether the camera
  uses authentication at all, and a substring test would have thrown it away. If a future
  SecuritySpy version grows a credential-shaped key, add it to
  `aiosecurityspy.const.CREDENTIAL_KEYS` and both redactors pick it up — they read that
  module attribute at call time, so the addition needs no other change.
- **It is fail-closed on shapes and fail-open on structure.** Mappings, `NamedTuple`s (by
  field name — `aiohttp.BasicAuth` walked positionally would yield `["bob", "hunter2"]`
  with no key to match on), dataclasses, lists, tuples, sets, strings and scalars are
  walked and preserved (a sequence that is neither a list nor a tuple, such as a `deque`,
  is not — like any other unrecognised shape it becomes its bare type name); a timestamp,
  duration, `Decimal`, `UUID`, `PurePath` or `Enum` renders through `str()` so a capture
  dump keeps its times, and an exception is walked argument by argument rather than
  through `str()`, which on a multi-argument exception is the `repr` of its arguments and
  would publish a credential-bearing one; bytes become `<bytes: 27>`;
  anything else becomes its bare type name such as `<ClientSession>`, never its `repr`.
  Cycles and runaway nesting stop at `<recursive>`/`<truncated>`, a container that refuses
  to be walked becomes `<unwalkable TypeName>`, and `anonymize()` never raises.
- **There is no diagnostics-dump builder here, deliberately.** The library supplies the
  anonymizer; you decide what belongs in your own diagnostics. `anonymize()` is pure — no
  network, no I/O, no logging, no Home Assistant — so it can never be the thing that fails.

### Use a least-privileged SecuritySpy account

Create a dedicated SecuritySpy user for this library rather than reusing an administrator
account, and grant it only the per-camera permissions you actually need — typically
**view live video** and **access captured files**. Withhold **delete files**, **camera
control**, and **arm/disarm** unless a feature you use requires them. Each camera's
granted permissions are decoded for you into `Camera.permission_names`, so you can check
capability before attempting an operation.

A least-privileged account that lacks a permission a call needs gets `SecuritySpyPermissionError`,
not `SecuritySpyAuthError` — the server answers with a `403`, and a `403` means the
credentials were *accepted*, not that they were wrong. Catch `SecuritySpyAuthError` to
detect a bad username or password (`401`) and `SecuritySpyPermissionError` to detect a
missing grant; re-prompting for credentials on the latter will not fix anything.

### Prefer HTTPS

Credentials are sent as HTTP Basic auth, which is only base64-encoded — over plain HTTP
anyone on the path can read them. Enable SecuritySpy's HTTPS listener and pass
`use_https=True`. SecuritySpy's certificate is issued for its DDNS hostname, so connecting
by LAN IP will fail verification; prefer configuring the hostname, and reach for
`verify_ssl=False` only when that is genuinely impossible.

Credentials never appear in a URL, a log line, an exception message, a `repr`, or a
traceback.

## Status

Early development. The client, typed models, protocol constants, exception hierarchy, the
event stream, capture history, the detection-episode reducer, the settings, arming and
permission surface, and the credential anonymizer are all in place. The public API is not
yet stable, and the reducer's three defaults are explicitly provisional.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src tests
uv run pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
