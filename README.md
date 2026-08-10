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

## Status

Early development (`0.1.0`). This release is the packaging skeleton only: it installs,
imports, and exposes `__version__`. The client, event stream, models, reducer, and
anonymizer land in subsequent releases. The public API is not yet stable.

```python
import aiosecurityspy

print(aiosecurityspy.__version__)
```

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src tests
uv run pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
