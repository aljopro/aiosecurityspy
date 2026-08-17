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

        def on_event(event: StreamEvent) -> None:
            if isinstance(event.payload, ClassificationPayload):
                print(f"camera {event.camera}: {dict(event.payload.classes)}")

        stream = client.event_stream(
            on_event=on_event,
            on_connected=lambda: print("stream live"),
            on_disconnected=lambda: print("stream lost; reconnecting"),
            on_reconnected=lambda: print("stream back; reconcile state"),
            on_auth_failed=lambda: print("credentials rejected; call resume() to retry"),
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
from datetime import UTC, datetime, timedelta

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

        stream = client.event_stream(on_event=lambda event: report(reducer.feed(event)))
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
from datetime import UTC, datetime, timedelta

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

        today = datetime.now(UTC).date()
        try:
            captures = await client.async_get_captures(
                [1, 2, 3],
                start_date=today - timedelta(days=1),
                end_date=today,
                object_class="human",
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
  plus seconds-since-midnight, because the wire format carries no absolute time. Pass
  `server_timezone=` if your server does not run in UTC. An unreconstructable time is
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
        # that call actually needs. `"camera_control"` covers the settings page
        # -- both reading it and writing it; `"schedule"` covers arming. They
        # are separate grants, so holding one says nothing about the other.
        info = await client.async_get_server_info()
        camera = info.cameras.get(3)
        if camera is None:
            print("camera 3 is not on this server")
            return
        try:
            require_permission(camera, "camera_control")
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

        # Arming: three independent booleans, so all eight combinations are
        # expressible -- including all-false, which disarms all three.
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
  `ARM_OVERRIDE_UNCHANGED` (the default) leaves any existing override alone,
  `ARM_OVERRIDE_NONE` clears it, and the "until next scheduled event" values report
  `duration is None` with `until_next_scheduled` true. `arm_override()` rejects any value
  outside the published `-1`..`14` table rather than guessing.
- **Schedules are read-only.** `Camera.schedules` reports the ids SecuritySpy assigned,
  and no method in this library reassigns one: the arming request sends `cameraNum`,
  `mode` and `override`, and never `schedule=`.
- **A settings payload contains the camera's device credentials in plaintext.**
  `CameraSettings` therefore keeps only a declared, curated set of non-credential fields —
  the raw payload is dropped at decode, never retained, and never logged at any level
  including debug. Its `repr` is deliberately just the camera number.

Booleans read back from SecuritySpy as JSON `true`/`false` but must be *written* as
`1`/`0`. That asymmetry is absorbed inside the library, so a call site only ever sees
`bool`.

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
