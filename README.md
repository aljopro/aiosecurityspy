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

Early development. The client, typed models, protocol constants, and exception hierarchy
are in place; the event stream, capture history, detection-episode reducer, settings
writes, and anonymizer land in subsequent releases. The public API is not yet stable.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src tests
uv run pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
