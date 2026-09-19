# AGENTS.md

This file provides guidance to AI coding agents (Claude Code and others) when working with code in this repository.

## What this is

`aiosecurityspy` — an async, fully-typed Python client library for the Ben Software SecuritySpy HTTP and event API. It owns *all* SecuritySpy protocol knowledge (endpoint URLs, event-stream framing, capture-field/bitmask decoding, the detection-episode reducer, credential-safe diagnostics) as an ordinary PyPI package usable from any script — no Home Assistant import anywhere in it.

This is its own repository (`aljopro/aiosecurityspy`), published to PyPI through the trusted-publisher workflow. The `ha-securityspy` Home Assistant integration consumes it as an exactly-pinned PyPI dependency; it is no longer a subtree of that repo, and changes here reach the integration only through a release and a pin bump there.

Design constraints that shape everything here:
- **Session-injected**: `aiohttp` is a dependency, but the library never creates, reconfigures, or closes a session. The caller owns it. `SecuritySpyClient` deliberately has no `close()`.
- **Fully typed**: ships a `py.typed` marker; source passes `mypy --strict`.
- **No Home Assistant**: no HA imports, no HA test tooling — must work in a bare venv.

## Commands

```bash
uv sync                                    # install deps (dev group includes mypy, ruff, pytest, openapi-spec-validator)

uv run pytest -q                           # full suite
uv run pytest tests/test_stream.py -q      # single file
uv run pytest tests/test_stream.py::test_name -q   # single test

uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests

uv build                                   # sdist + wheel
```

This library's own pytest config (`asyncio_mode = "strict"`, `filterwarnings = ["error"]` — a bare deprecation warning fails the run) applies when pytest starts from inside this repository, so run every command from here.

### CI does more than the four commands above

`.github/workflows/*.yml` also: validates `docs/securityspy-openapi.yaml` against the OpenAPI 3.1 spec and asserts every operation has a valid `x-verification` marker (`live-6.21` / `client-source` / `research-only`); builds sdist/wheel and greps them for `docs/securityspy-openapi.yaml` and `py.typed` respectively; and imports the built wheel from a bare venv with no Home Assistant present. A change that breaks any of these won't necessarily fail `pytest`/`mypy`/`ruff` locally — check before assuming CI will pass.

## The protocol reference

SecuritySpy's HTTP API is undocumented by the vendor. This library's description of it is the authority:
- **[docs/securityspy-openapi.yaml](docs/securityspy-openapi.yaml)** — OpenAPI 3.1, schema-validated in CI. Read its header before generating anything from it: `++getpreview`'s URL has a literal `?` inside the path and a second one before `archive`; settings POST bodies must start with a bare `formData` token (not `key=value`); checkbox fields are keyed by HTML element id and their order matters. A generated client that ignores these annotations will be broken in ways the description looks like it endorses.
- The `ha-securityspy` repo's `_bmad-output/planning-artifacts/research/securityspy-api-reference.md` is the deeper reverse-engineering writeup this OpenAPI file is distilled from, and supersedes the vendor's own docs where they disagree.

## Protocol gotchas — each has caused a real bug

- **Event-stream lines are CR-terminated only.** A standard `readline()` hangs indefinitely. The single most likely bug in any SecuritySpy client.
- **`server_timezone` is a required keyword arg, with no default**, on `parse_event_line()`, `SecuritySpyEventStream.__init__()`, `SecuritySpyClient.event_stream()`, and `SecuritySpyClient.async_get_captures()`. The wire format sends a bare local wall clock with no offset — the library will not guess UTC. Decode `ServerInfo.utc_offset` (from `++systemInfo`'s `seconds-from-gmt`) and build a `timezone`/`ZoneInfo` from it; `None` means the server didn't publish a usable value and must stay distinguishable from a legitimate zero offset. An offset alone is not DST-correct across a long window — prefer a `zoneinfo.ZoneInfo` (e.g. HA's `hass.config.time_zone`) over a fixed offset when decoding a `caplist` spanning weeks.
- **Settings write bodies must begin with the literal sentinel `formData`**, not a `key=value` pair, and use `1`/`0` where JSON reads return `true`/`false`.
- **The `t` field means different things in `caplist` vs. `clip`** — don't share enums between them.
- **A 401 on the media endpoint can mean permission-denied, not bad credentials** — don't collapse it into `SecuritySpyAuthError`.
- **`event.camera is None`** means the record wasn't camera-specific (wire sends `X`), not that it's invalid — `NULL` heartbeats arrive this way.
- **`event.event_number` restarts at 0 on every reconnect.** Record it, never key off it.
- **`MOTION_END` is unreliable** and is not an inactivity signal — implement your own timeout.
- **On 401/403 the event stream pauses rather than retrying.** `on_auth_failed` fires once; nothing resumes until `stream.resume()` is called explicitly. `connect()` declines while paused, and the pause survives `disconnect()`.
- **`connected` fires once, ever; every later successful connect fires `reconnected`** — including after your own `disconnect()`/`connect()`, since any gap means state must be reconciled.
- **Backoff resets after every successful connection** — a stream that drops periodically retries promptly rather than creeping to the ceiling.
- **The classification vocabulary is open** — a label from a custom CoreML model arrives in `ClassificationPayload.classes` unchanged; use `slugged()` only when a permanent key is needed.
- **`CLASSIFY` is a per-frame inference stream, not a detection event** (191 records/95s on one camera is typical) — `EpisodeReducer` turns a run of frames into one bounded episode with peak confidence. It's a pure component (no I/O, no timers): **you must call `tick(now)` periodically yourself**, or an episode whose camera went quiet stays open forever — this is the one obligation that fails silently.

## Code layout (`src/aiosecurityspy/`)

- `client.py` — `SecuritySpyClient`, the HTTP surface.
- `connection.py` — low-level HTTP transport/auth shared by client and stream.
- `stream.py` — event-stream reader: CR framing, heartbeat watchdog (loss after three missed ~10s heartbeats), exponential backoff, lifecycle callbacks.
- `events.py` — decoded event/payload types (`StreamEvent`, `ClassificationPayload`, etc.).
- `episodes.py` — `EpisodeReducer` / `ReducerConfig` / `EpisodeOpened` / `EpisodeClosed`.
- `models.py` — `ServerInfo`, camera info, `Capture`, etc.
- `diagnostics.py` — credential-safe redaction helpers.
- `exceptions.py` — typed error hierarchy: `SecuritySpyAuthError`, `SecuritySpyPermissionError`, `SecuritySpyConnectError`, `SecuritySpyCertificateError`, `SecuritySpyUnsupportedVersionError`, `SecuritySpyServerIdentityError` (the `++systemInfo` payload has no server UUID; permanent, not retryable), `SecuritySpyError`.
- `const.py` — protocol constants (e.g. `DEFAULT_PORT`).

## Release process

PyPI publishing is trusted-publisher (OIDC) via `.github/workflows/publish.yml`, triggered on a GitHub release — no API tokens/secrets involved. See the `aiosecurityspy-release-setup` memory: the trusted publisher and `pypi` environment are already configured; releases are cut from GitHub releases (the CHANGELOG lists what has shipped), but check PyPI before assuming a given version is published.

Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [SemVer](https://semver.org/spec/v2.0.0.html) in `CHANGELOG.md` — a breaking API change (like the `server_timezone` requirement) gets an explicit "BREAKING" callout under `### Changed`, not just a terse bullet.
