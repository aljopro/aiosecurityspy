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
event stream, and capture history are in place; the detection-episode reducer, settings
writes, and the anonymizer land in subsequent releases. The public API is not yet stable.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src tests
uv run pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
