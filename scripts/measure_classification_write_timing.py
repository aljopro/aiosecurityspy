# ruff: noqa: INP001 - standalone script in a flat scripts/ dir, not a package
"""Measure when SecuritySpy writes classification to a capture (Story 4.1 spike).

The spike's open fact (PRD Open Q3, risk R-001, test-design gate
``4.1-LIVE-076``): does SecuritySpy write a capture's object classification
(``o`` in ``++caplist``) at capture close, or some time afterwards? This probe
is the instrument behind Story 4.1's acceptance criterion. It fires the test
camera's manual trigger, polls capture history through the library's public
client on a short cadence, and records, per trigger: the wall-clock appearance
time of the new capture, its recording-close time (``start + duration``), the
first poll at which its object-class set became non-empty, and the two deltas.

The manual-trigger request is the one piece of wire knowledge in this file --
it deliberately lives here, in the library repo, never in the integration
(AD-2). Everything else goes through the library's public surface
(:class:`~aiosecurityspy.SecuritySpyClient`, ``async_get_captures``,
``async_get_server_info``).

Configuration is read through ``tests/live_env.py`` (``.env`` beside
``pyproject.toml``; process environment overrides the file). Required: host /
port / https settings, a trigger-capable account (``ADMIN`` or ``CONTROL``),
``SECURITYSPY_TEST_CAMERA``, and ``SECURITYSPY_ALLOW_WRITES`` truthy. When any
of those is missing the probe prints a short reason and exits 0 without doing
anything. No credential value is ever printed, logged, or asserted on (AD-13;
see the ``live_env.py`` docstring).

Usage::

    uv run python scripts/measure_classification_write_timing.py --triggers 3
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Final

import aiohttp

if TYPE_CHECKING:
    from collections.abc import Sequence

    from aiosecurityspy.models import Capture

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

import live_env
from aiosecurityspy import (
    CAPTURE_FILTER_ALL,
    CAPTURE_TYPE_MOVIE,
    SecuritySpyAuthError,
    SecuritySpyClient,
)

_DEFAULT_PORT: Final = 8001
_MANUAL_TRIGGER_ENDPOINT: Final = "++triggermd"
_CLIENT_TIMEOUT_SECONDS: Final = 15.0
_HTTP_OK_MIN: Final = 200
_HTTP_OK_MAX: Final = 300

#: How far before the trigger instant a matching capture's ``start`` may lie.
#: Motion recordings carry a pre-roll (``mcMoviePre``), so the capture can
#: begin a few seconds before the trigger fires; this is that headroom. ``0``
#: excludes any capture whose ``start`` predates the trigger.
_DEFAULT_MATCH_EPSILON_SECONDS: Final = 15.0

#: The capture's ``start`` must also not lie after the trigger by more than
#: this margin; a future-dated start (unrelated motion, clock skew) is not the
#: triggered capture.
_MAX_POST_TRIGGER_START_SECONDS: Final = 10.0

#: Date-window padding on either side of "today": the trigger can straddle the
#: server's local midnight, in which case the capture lands in the adjacent
#: folder date and would otherwise never be fetched.
_FOLDER_DATE_PADDING_DAYS: Final = 1

_NO_CAPTURE_NOTE: Final = (
    "no new capture matched the trigger window; the camera may not be armed for motion recording"
)


def _out(message: str) -> None:
    """Write one line to stdout (avoids flake8-print, matching ``_report``)."""
    sys.stdout.write(f"{message}\n")


@dataclass(frozen=True)
class ProbeConfig:
    """Resolved probe configuration, including the trigger-capable account.

    ``username``/``password`` are carried here only to build the client and the
    manual-trigger ``Authorization`` header; the repr deliberately omits them
    (AD-13).
    """

    host: str
    port: int
    use_https: bool
    verify_ssl: bool
    username: str
    password: str
    camera: int

    def __repr__(self) -> str:
        """Return a representation that cannot leak the credential."""
        return (
            f"ProbeConfig(host={self.host!r}, port={self.port}, "
            f"use_https={self.use_https}, verify_ssl={self.verify_ssl}, "
            f"camera={self.camera})"
        )


@dataclass(frozen=True)
class ProbeOptions:
    """Tuning knobs for one probe run, all taken from the CLI."""

    interval: float
    timeout: float
    pause: float
    epsilon: float


@dataclass(frozen=True)
class TriggerMeasurement:
    """One trigger's measured wall-clock times and deltas, in UTC."""

    trigger_wall: datetime
    appeared: datetime | None
    close: datetime | None
    classified: datetime | None
    delta_classified_minus_close: timedelta | None
    delta_classified_minus_appeared: timedelta | None
    object_classes: frozenset[str] | None
    note: str


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the CLI options into an argparse namespace."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--triggers",
        type=int,
        default=3,
        help="number of manual triggers to measure (default 3)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="poll interval in seconds (default 3)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="poll deadline per trigger in seconds (default 180)",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=5.0,
        help="pause between triggers in seconds (default 5)",
    )
    parser.add_argument(
        "--epsilon",
        type=float,
        default=_DEFAULT_MATCH_EPSILON_SECONDS,
        help="capture start may precede the trigger by up to this many seconds (default 15)",
    )
    return parser.parse_args(argv)


def _resolve_config() -> ProbeConfig | None:
    """Return the resolved configuration, or ``None`` when the probe cannot run.

    Prints the specific reason on stdout. This is a skip, not an error: the
    probe is a developer instrument and should do nothing at all when the
    environment is not configured for writes.
    """
    if not live_env.server_configured():
        _out("SECURITYSPY_HOST is not set; see aiosecurityspy/.env.example")
        return None
    if not live_env.flag("SECURITYSPY_ALLOW_WRITES"):
        _out("SECURITYSPY_ALLOW_WRITES is not set; refusing to trigger a real camera (exit 0)")
        return None
    account = live_env.credentials("ADMIN") or live_env.credentials("CONTROL")
    if account is None:
        _out(
            "neither SECURITYSPY_ADMIN_USER/_PASS nor SECURITYSPY_CONTROL_USER/_PASS "
            "are set; a trigger-capable account is required"
        )
        return None
    camera = live_env.get_int("SECURITYSPY_TEST_CAMERA")
    if camera is None:
        _out("SECURITYSPY_TEST_CAMERA is not set")
        return None
    host = live_env.get("SECURITYSPY_HOST")
    if host is None:
        _out("SECURITYSPY_HOST is not set; see aiosecurityspy/.env.example")
        return None
    username, password = account
    return ProbeConfig(
        host=host,
        port=live_env.get_int("SECURITYSPY_PORT") or _DEFAULT_PORT,
        use_https=live_env.flag("SECURITYSPY_USE_HTTPS"),
        verify_ssl=live_env.flag("SECURITYSPY_VERIFY_SSL"),
        username=username,
        password=password,
        camera=camera,
    )


async def _fire_trigger(session: aiohttp.ClientSession, config: ProbeConfig) -> None:
    """Fire the manual-trigger endpoint for the test camera.

    A raw request: the trigger is not part of the library's public surface.
    Raises :class:`RuntimeError` (with a credential-free message) when the
    server does not answer 2xx.
    """
    scheme = "https" if config.use_https else "http"
    host = (
        f"[{config.host}]"
        if ":" in config.host and not config.host.startswith("[")
        else config.host
    )
    url = f"{scheme}://{host}:{config.port}/{_MANUAL_TRIGGER_ENDPOINT}"
    headers = {"Authorization": aiohttp.encode_basic_auth(config.username, config.password)}
    async with session.get(
        url,
        params={"cameraNum": config.camera},
        headers=headers,
        ssl=config.verify_ssl,
    ) as response:
        body = await response.read()  # drain fully so the connection closes cleanly
        if not _HTTP_OK_MIN <= response.status < _HTTP_OK_MAX:
            message = f"manual trigger returned HTTP {response.status} (body {len(body)} bytes)"
            raise RuntimeError(message)


async def _fetch_captures(
    client: SecuritySpyClient,
    config: ProbeConfig,
    server_timezone: timezone,
) -> tuple[Capture, ...]:
    """Return captures for the test camera across the folder-date window.

    The window is widened by ``_FOLDER_DATE_PADDING_DAYS`` on both sides so a
    trigger that straddles the server's local midnight still finds its capture
    in the adjacent folder. The ``start``-based match window keeps unrelated
    older captures out of the result.
    """
    today = datetime.now(tz=server_timezone).date()
    return await client.async_get_captures(
        [config.camera],
        start_date=today - timedelta(days=_FOLDER_DATE_PADDING_DAYS),
        end_date=today + timedelta(days=_FOLDER_DATE_PADDING_DAYS),
        capture_filter=CAPTURE_FILTER_ALL,
        server_timezone=server_timezone,
    )


def _select_match(  # noqa: PLR0913, PLR0917 - one bounded-match helper with all six inputs explicit
    captures: tuple[Capture, ...],
    seen: set[str],
    camera: int,
    earliest: datetime,
    latest: datetime,
    trigger_wall: datetime,
) -> Capture | None:
    """Return the best new capture for ``camera`` in ``[earliest, latest]``.

    Only captures whose ``start`` is bounded by the trigger window qualify.
    Among them, prefer a motion movie, then the one whose ``start`` lies
    closest to the trigger instant, so an unrelated same-camera capture that
    happens to fall inside the window is not misattributed. ``seen`` records
    every new filename so a capture is never selected twice, but a capture
    that fails the window check is left alone for a later poll to re-judge
    (its fields may not be final on the first sighting).
    """
    candidates: list[Capture] = []
    for capture in captures:
        if capture.filename in seen:
            continue
        seen.add(capture.filename)
        if capture.camera != camera or capture.start is None:
            continue
        if not earliest <= capture.start <= latest:
            continue
        candidates.append(capture)
    if not candidates:
        return None

    def _rank(capture: Capture) -> tuple[int, timedelta]:
        is_movie = capture.capture_type == CAPTURE_TYPE_MOVIE
        distance = abs(capture.start - trigger_wall) if capture.start is not None else timedelta.max
        return (0 if is_movie else 1, distance)

    return min(candidates, key=_rank)


def _refresh_target(captures: tuple[Capture, ...], filename: str) -> Capture | None:
    """Return the freshest copy of the named capture, or ``None`` when absent."""
    for capture in captures:
        if capture.filename == filename:
            return capture
    return None


def _close_of(capture: Capture) -> datetime | None:
    """Return the capture's recording-close instant, or ``None`` when unknown."""
    if capture.start is None or capture.duration is None:
        return None
    return capture.start + capture.duration


def _duration_of(capture: Capture) -> timedelta | None:
    """Return the capture's duration, or ``None`` when unknown."""
    return capture.duration


def _build_measurement(
    trigger_wall: datetime,
    appeared: datetime | None,
    target: Capture | None,
    classified: datetime | None,
    note: str,
) -> TriggerMeasurement:
    """Assemble a measurement from the observed times and the target capture."""
    close: datetime | None = None
    if target is not None and target.start is not None and target.duration is not None:
        close = target.start + target.duration
    delta_close: timedelta | None = None
    if classified is not None and close is not None:
        delta_close = classified - close
    delta_appeared: timedelta | None = None
    if classified is not None and appeared is not None:
        delta_appeared = classified - appeared
    return TriggerMeasurement(
        trigger_wall=trigger_wall,
        appeared=appeared,
        close=close,
        classified=classified,
        delta_classified_minus_close=delta_close,
        delta_classified_minus_appeared=delta_appeared,
        object_classes=target.object_classes if target is not None else None,
        note=note,
    )


async def _measure_one_trigger(  # noqa: PLR0912, PLR0915 - the poll loop's branches are the measurement's edge cases
    session: aiohttp.ClientSession,
    client: SecuritySpyClient,
    config: ProbeConfig,
    server_timezone: timezone,
    options: ProbeOptions,
) -> TriggerMeasurement:
    """Trigger the camera once and measure the resulting capture's class lag.

    Takes a baseline poll before firing so a capture that is already fully
    written -- and possibly already classified -- at its first post-trigger
    observation is still detected as new. Then polls on ``options.interval``
    until the class set has settled AND the recording has closed with a stable
    duration, or the deadline elapses.

    The close-time measurement is only trustworthy once the recording has
    actually finished: ``duration`` is still growing while the movie is being
    written, so a delta computed against a mid-recording ``close`` would be
    wrong precisely in the classified branches this spike exists to
    characterize. We therefore keep polling after the first classified sighting
    until ``close <= now`` and two consecutive polls report the same duration.
    """
    baseline = await _fetch_captures(client, config, server_timezone)
    seen = {capture.filename for capture in baseline}

    trigger_wall = datetime.now(UTC)
    await _fire_trigger(session, config)

    deadline = asyncio.get_running_loop().time() + options.timeout
    earliest = trigger_wall - timedelta(seconds=options.epsilon)
    latest = trigger_wall + timedelta(seconds=_MAX_POST_TRIGGER_START_SECONDS)
    target_filename: str | None = None
    target: Capture | None = None
    appeared: datetime | None = None
    classified: datetime | None = None
    disappeared = False
    settled_polls = 0
    settled_duration: timedelta | None = None

    while asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(options.interval)
        poll_wall = datetime.now(UTC)
        captures = await _fetch_captures(client, config, server_timezone)
        if target_filename is None:
            selected = _select_match(
                captures,
                seen,
                config.camera,
                earliest,
                latest,
                trigger_wall,
            )
            if selected is not None:
                target_filename = selected.filename
                target = selected
                appeared = poll_wall
        else:
            refreshed = _refresh_target(captures, target_filename)
            if refreshed is None:
                disappeared = True
                break
            target = refreshed

        if target is not None and target.object_classes and classified is None:
            classified = poll_wall

        if classified is not None:
            close = _close_of(target)
            if close is not None and poll_wall >= close:
                duration = _duration_of(target)
                if duration == settled_duration:
                    settled_polls += 1
                else:
                    settled_polls = 0
                settled_duration = duration
                if settled_polls >= 2:  # noqa: PLR2004 - two stable polls confirm the close
                    break
            else:
                settled_polls = 0
                settled_duration = None

    if disappeared:
        return _build_measurement(
            trigger_wall,
            appeared,
            None,
            classified,
            "matched capture disappeared from caplist mid-poll (deleted or rotated)",
        )
    if target is None:
        return _build_measurement(trigger_wall, None, None, None, _NO_CAPTURE_NOTE)
    if classified is None:
        return _build_measurement(
            trigger_wall,
            appeared,
            target,
            None,
            "unclassified within the poll window",
        )
    note = (
        "classified at first sight"
        if classified == appeared
        else f"classified {classified - appeared} after appearance"
    )
    if not (settled_polls >= 2):  # noqa: PLR2004 - same settle threshold as the loop above
        note += "; recording close not confirmed before deadline"
    return _build_measurement(trigger_wall, appeared, target, classified, note)


def _fmt_instant(instant: datetime | None) -> str:
    """Format an instant as a compact UTC string, or ``-`` when absent."""
    if instant is None:
        return "-"
    return instant.astimezone(UTC).strftime("%H:%M:%S")


def _fmt_delta(delta: timedelta | None) -> str:
    """Format a delta in seconds with one decimal, or ``-`` when absent."""
    if delta is None:
        return "-"
    return f"{delta.total_seconds():+.1f}s"


def _print_row(index: int, measurement: TriggerMeasurement) -> None:
    """Print one per-trigger measurement row."""
    classes = ",".join(sorted(measurement.object_classes)) if measurement.object_classes else ""
    _out(
        f"  trigger {index}: "
        f"trigger={_fmt_instant(measurement.trigger_wall)} "
        f"appeared={_fmt_instant(measurement.appeared)} "
        f"close={_fmt_instant(measurement.close)} "
        f"classified={_fmt_instant(measurement.classified)} "
        f"classified-close={_fmt_delta(measurement.delta_classified_minus_close)} "
        f"classified-appeared={_fmt_delta(measurement.delta_classified_minus_appeared)} "
        f"classes={{{classes}}} "
        f"({measurement.note})"
    )


async def _run() -> int:  # noqa: PLR0911 - each return is one distinct skip/validation outcome
    """Drive the probe: resolve config, run the triggers, print the table.

    CLI options are parsed and validated before environment/config resolution
    so ``--help`` and an invalid invocation behave normally even on a machine
    without a configured ``.env``.
    """
    args = _parse_args()
    if args.triggers < 1:
        _out("--triggers must be at least 1")
        return 1
    if args.interval <= 0 or args.timeout <= 0 or args.pause < 0 or args.epsilon < 0:
        _out("--interval/--timeout must be positive and --pause/--epsilon non-negative")
        return 1
    if args.timeout <= args.interval:
        _out("--timeout must be greater than --interval (otherwise only one poll can run)")
        return 1
    options = ProbeOptions(
        interval=args.interval,
        timeout=args.timeout,
        pause=args.pause,
        epsilon=args.epsilon,
    )

    config = _resolve_config()
    if config is None:
        return 0

    async with aiohttp.ClientSession() as session:
        client = SecuritySpyClient(
            session,
            config.host,
            config.port,
            username=config.username,
            password=config.password,
            use_https=config.use_https,
            verify_ssl=config.verify_ssl,
            timeout=_CLIENT_TIMEOUT_SECONDS,
        )
        info = await client.async_get_server_info()
        if info.utc_offset is None:
            _out("the server published no usable seconds-from-gmt offset; aborting")
            return 1
        if config.camera not in info.cameras:
            _out(f"camera {config.camera} is not visible to the configured account; aborting")
            return 1
        server_timezone = timezone(info.utc_offset)

        _out(
            f"server version={info.version} camera={config.camera} "
            f"triggers={args.triggers} interval={options.interval}s "
            f"timeout={options.timeout}s (times are UTC; classified-close is "
            "positive when classification lags recording close)"
        )
        for index in range(args.triggers):
            if index:
                await asyncio.sleep(options.pause)
            measurement = await _measure_one_trigger(
                session,
                client,
                config,
                server_timezone,
                options,
            )
            _print_row(index + 1, measurement)
    return 0


def main() -> int:
    """Entry point: run the probe, translating transport failures to exit 1."""
    try:
        return asyncio.run(_run())
    except SecuritySpyAuthError:
        # The library's auth-error mapping may carry a credential-derived
        # fact (the API_-prefix diagnostic from story 1.22); never print it.
        _out("probe failed: authentication was refused (check .env credentials)")
        return 1
    except Exception as err:  # noqa: BLE001 - the probe is a top-level script
        _out(f"probe failed: {type(err).__name__}: {err}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
