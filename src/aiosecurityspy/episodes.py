"""Reduce the per-frame ``CLASSIFY`` signal stream into detection episodes.

``CLASSIFY`` is an inference stream, not a detection event: research §3.5
measured 191 of them on one camera in 95 s, 0-2 s apart, with confidence
swinging 8 -> 97 between adjacent frames for a single subject. "A human was
here, peak confidence 99" is a *reduction* of that stream, and PRD §11.1 calls
the roughly 190:1 ratio a correctness requirement rather than an optimization.
This module is where that reduction lives, so no consumer re-derives it.

The reducer is a **pure component** (AD-3). It performs no I/O, starts no task,
owns no timer, and never reads a clock: every instant it works with arrives from
the caller, either as a signal's own timestamp or as the ``now`` passed to
:meth:`EpisodeReducer.tick`. That makes the whole edge-case matrix exercisable
from synthetic signals with no server, no session, and no event loop.

Threshold, debounce and inactivity gap are injected per camera per object class
(AD-3, FR-8); nothing in the reduction reads a module-level tuning constant. The
defaults in :mod:`aiosecurityspy.const` are provisional (PRD Open Q5) and are
marked as such there.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Final

from .const import (
    DEFAULT_DETECTION_DEBOUNCE,
    DEFAULT_DETECTION_GAP,
    DEFAULT_DETECTION_THRESHOLD,
    EVENT_CLASSIFY,
    class_slug,
)

# `_prefers` is private to `events`, and imported anyway rather than
# reimplemented: it encodes a subtle rule (a NaN compares False against
# everything, so a bare `>` lets it win a comparison it must lose) that a second
# copy could silently drift away from. One definition, one place to fix it.
from .events import ClassificationPayload, _prefers

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from .events import StreamEvent

__all__ = [
    "ClassificationSignal",
    "DetectionEpisode",
    "EpisodeClosed",
    "EpisodeEvent",
    "EpisodeOpened",
    "EpisodeReducer",
    "OverrideKey",
    "ReducerConfig",
]

#: Confidence bounds, as percentages. The wire format reports 0-100 (§3.3).
_MIN_CONFIDENCE: Final = 0.0
_MAX_CONFIDENCE: Final = 100.0

#: The smallest debounce that is still a debounce: one signal opens instantly.
_MIN_DEBOUNCE: Final = 1

#: An override key selecting a camera (or any camera) and a class slug (or any
#: class). ``(None, None)`` is deliberately not a legal key: that is the default
#: config, and accepting it as an override would silently do nothing.
type OverrideKey = tuple[int | None, str | None]


# The `_is_*` predicates take `object` on purpose. Every caller passes an
# already-annotated value, so the parameter widens the static type and keeps the
# runtime check from being eliminated as unreachable -- and keeping the
# `isinstance` out of the raising branch's own condition is what lets these
# report a caller mistake as the `ValueError` the contract specifies, rather
# than the `TypeError` a bare type guard would be expected to raise. Every one
# of these is a mistake in the caller's own code, not something off the wire:
# wire data degrades, caller arguments are rejected loudly.


def _is_int(value: object) -> bool:
    """Return whether `value` is a real ``int``.

    ``bool`` is excluded because ``True`` would otherwise pass as camera 1.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    """Return whether `value` is a real ``int`` or ``float``."""
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_nonempty_str(value: object) -> bool:
    """Return whether `value` is a string with something in it."""
    return isinstance(value, str) and bool(value.strip())


def _is_timedelta(value: object) -> bool:
    """Return whether `value` is a ``timedelta``."""
    return isinstance(value, timedelta)


def _is_pair(value: object) -> bool:
    """Return whether `value` is a two-element tuple."""
    pair_length = 2
    return isinstance(value, tuple) and len(value) == pair_length


def _is_config(value: object) -> bool:
    """Return whether `value` is a :class:`ReducerConfig`.

    Resolved at call time, so it may name a class defined further down.
    """
    return isinstance(value, ReducerConfig)


def _is_aware_datetime(value: object) -> bool:
    """Return whether `value` is a timezone-aware ``datetime``."""
    if not isinstance(value, datetime):
        return False
    return value.tzinfo is not None and value.tzinfo.utcoffset(value) is not None


def _require_int(value: int, name: str) -> int:
    """Return `value`, or raise a ``ValueError`` naming the field."""
    if not _is_int(value):
        message = f"{name} must be an int"
        raise ValueError(message)
    return value


def _require_finite(value: float, name: str) -> float:
    """Return `value` as a finite float, or raise naming the field."""
    if not _is_number(value):
        message = f"{name} must be a number"
        raise ValueError(message)
    if not math.isfinite(value):
        message = f"{name} must be finite"
        raise ValueError(message)
    return float(value)


def _require_config(value: ReducerConfig, name: str) -> ReducerConfig:
    """Return `value`, or raise unless it is a :class:`ReducerConfig`.

    Without this, a mapping or a bare number passed as a config survives
    construction and dies much later as an ``AttributeError`` from inside the
    reduction, pointing at this module rather than at the call site that got it
    wrong -- which is exactly the failure this module's other argument checks
    exist to prevent.
    """
    if not _is_config(value):
        message = f"{name} must be a ReducerConfig"
        raise ValueError(message)
    return value


def _require_aware(value: datetime, name: str) -> datetime:
    """Return `value`, or raise unless it is a timezone-aware ``datetime``.

    Timestamps are timezone-aware UTC everywhere in this library (AD-15). A
    naive one cannot even be compared against an aware one, so accepting it
    would turn a caller's mistake into a ``TypeError`` from deep inside the
    reduction rather than a ``ValueError`` at the point of the mistake.
    """
    if not _is_aware_datetime(value):
        message = f"{name} must be a timezone-aware datetime"
        raise ValueError(message)
    return value


@dataclass(frozen=True, slots=True)
class ClassificationSignal:
    """One ``CLASSIFY`` inference about one object class on one camera.

    This is the reducer's only input unit. It is deliberately constructible by
    hand: the whole point of a pure reducer is that its behaviour can be pinned
    down from synthetic signals, with no stream and no server.

    Raises:
        ValueError: A field the caller got wrong -- a non-integer camera, an
            empty object class, or a naive timestamp. A non-finite confidence
            is **not** an error here: it is carried and then ignored by the
            reducer, because it arrives from the wire rather than from the
            caller's own code.

    """

    #: The camera the inference is about. ``int`` everywhere (AD-15).
    camera: int
    #: The object class exactly as the server labelled it. The vocabulary is
    #: open (AD-9): this is never validated against a known set, and it becomes
    #: an episode key only through :func:`~aiosecurityspy.class_slug`.
    object_class: str
    #: Confidence as a percentage, 0-100. A non-finite value is ignored by the
    #: reducer: it can neither open an episode nor set a peak.
    confidence: float
    #: When the inference happened, as a timezone-aware instant.
    timestamp: datetime

    def __post_init__(self) -> None:
        """Validate the caller-supplied fields."""
        _require_int(self.camera, "camera")
        if not _is_nonempty_str(self.object_class):
            message = "object_class must be a non-empty string"
            raise ValueError(message)
        if not _is_number(self.confidence):
            message = "confidence must be a number"
            raise ValueError(message)
        _require_aware(self.timestamp, "timestamp")

    @property
    def slug(self) -> str:
        """Return the normalized class key this signal reduces under (AD-9)."""
        return class_slug(self.object_class)

    @property
    def is_usable(self) -> bool:
        """Return whether the confidence is a number the reducer can use."""
        return math.isfinite(self.confidence)


@dataclass(frozen=True, slots=True)
class ReducerConfig:
    """The three values that decide where one episode begins and ends.

    Injected per camera per object class (AD-3, FR-8); the reduction reads
    nothing else. The defaults are the provisional ones from
    :mod:`aiosecurityspy.const` and are **[ASSUMPTION]** values (PRD Open Q5).

    Raises:
        ValueError: A threshold outside 0-100 or non-finite, a debounce below
            1, or a gap that is not a positive ``timedelta``.
            The message names the field, never a credential-adjacent value.

    """

    #: Minimum confidence a signal must carry to count towards opening.
    threshold: float = DEFAULT_DETECTION_THRESHOLD
    #: Consecutive qualifying signals required before an episode opens.
    debounce: int = DEFAULT_DETECTION_DEBOUNCE
    #: Silence after the last qualifying signal before the episode has ended.
    gap: timedelta = DEFAULT_DETECTION_GAP

    def __post_init__(self) -> None:
        """Validate the configuration at construction, not at first signal."""
        threshold = _require_finite(self.threshold, "threshold")
        if not _MIN_CONFIDENCE <= threshold <= _MAX_CONFIDENCE:
            message = "threshold must be between 0 and 100"
            raise ValueError(message)
        if _require_int(self.debounce, "debounce") < _MIN_DEBOUNCE:
            message = "debounce must be at least 1"
            raise ValueError(message)
        if not _is_timedelta(self.gap):
            message = "gap must be a timedelta"
            raise ValueError(message)
        if self.gap <= timedelta(0):
            message = "gap must be positive"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class DetectionEpisode:
    """One reduced detection: a class was present on a camera for a span.

    A single episode stands in for the whole burst of ``CLASSIFY`` signals that
    produced it -- 191 of them in the §3.5 reference case -- which is the
    reduction PRD §11.1 requires.
    """

    #: The camera the episode happened on.
    camera: int
    #: The normalized class key (AD-9). Two raw labels that slug the same are
    #: one episode, not two.
    #:
    #: :func:`~aiosecurityspy.class_slug` keeps only ``[a-z0-9_]`` and falls
    #: back to ``"unknown"`` when nothing survives, so a label written entirely
    #: in a non-Latin script -- ``"人"``, ``"车辆"``, ``"🐋"`` -- reduces under
    #: ``"unknown"``, and several such labels on one camera merge into a single
    #: ``(camera, "unknown")`` episode with a shared peak and mingled
    #: :attr:`raw_labels`. That is the accepted cost of having exactly one
    #: normalizer on the path to a permanent key; :attr:`raw_labels` is where
    #: the distinction survives.
    object_class: str
    #: Every raw label seen inside the span, before slugging.
    raw_labels: frozenset[str]
    #: The first signal of the span -- including the below-threshold signals
    #: that preceded the debounce run, because they are part of the same
    #: presence. Always ``<= last_signal``: an out-of-order arrival older than
    #: the span moves this back rather than leaving the episode starting after
    #: one of its own signals.
    start: datetime
    #: When the episode lapsed, or ``None`` while it is still open. Normally
    #: ``last_signal + gap`` -- the instant it actually went quiet, never the
    #: ``now`` that happened to notice, so a late tick cannot stretch it. The
    #: one exception is :meth:`EpisodeReducer.close_all`, where observation
    #: stopped rather than the episode lapsing.
    end: datetime | None
    #: The most recent **qualifying** signal. Never moves backward, so an
    #: out-of-order arrival cannot rewind the inactivity deadline.
    last_signal: datetime
    #: The highest confidence anywhere in the span (FR-6) -- including the
    #: debounce signals that opened it and any below-threshold signal inside
    #: it. Never the value at the threshold crossing.
    peak_confidence: float
    #: Every signal absorbed into the span, qualifying or not. Divide by one to
    #: get the reduction ratio this episode achieved.
    signal_count: int

    @property
    def is_open(self) -> bool:
        """Return whether the episode is still accumulating signals."""
        return self.end is None


@dataclass(frozen=True, slots=True)
class EpisodeOpened:
    """Emitted once, when an episode's debounce run has been satisfied."""

    episode: DetectionEpisode


@dataclass(frozen=True, slots=True)
class EpisodeClosed:
    """Emitted once, when an episode has gone quiet for longer than its gap."""

    episode: DetectionEpisode


#: Everything the reducer emits. Exactly one `EpisodeOpened` and at most one
#: `EpisodeClosed` per episode: signals absorbed in between emit nothing at all.
type EpisodeEvent = EpisodeOpened | EpisodeClosed


@dataclass(slots=True)
class _Track:
    """Mutable accumulation for one ``(camera, class slug)`` key.

    Private and never handed out: every value that leaves the reducer leaves as
    a frozen :class:`DetectionEpisode`.
    """

    start: datetime
    last_any: datetime
    peak_confidence: float
    signal_count: int
    raw_labels: set[str] = field(default_factory=set)
    last_qualifying: datetime | None = None
    run: int = 0
    opened: bool = False

    def deadline(self, gap: timedelta) -> datetime | None:
        """Return the instant this track lapses, or ``None`` if it cannot.

        Inactivity is the *only* thing that ends an episode here. The obvious
        alternative, the stream's own MOTION_END event, is unusable: research
        §3.5 recorded 467 motion signals and **zero** ends on camera 10, and 1
        end against 383 signals on camera 7. Closing on a run of below-threshold
        signals is equally wrong -- §3.5's sequence has `88, 8, 54` in
        consecutive frames for one subject, so a low run is mid-episode, not the
        end of one. Only silence reliably means "gone".

        An open episode therefore measures from its last **qualifying** signal.
        A track that never opened measures from its last signal of any kind: it
        is only being kept so a later debounce run can report the presence's
        real start, and after a gap of silence that context is stale.

        Returns:
            The lapse instant, or ``None`` when adding the gap would run off the
            end of the representable range. Such a track is reported as
            not-yet-lapsed rather than raising ``OverflowError`` out of a public
            method -- the same choice :func:`~aiosecurityspy.parse_event_line`
            makes about an unrepresentable instant.

        """
        anchor = self.last_qualifying if self.opened and self.last_qualifying is not None else None
        if anchor is None:
            anchor = self.last_any
        try:
            return anchor + gap
        except OverflowError:
            return None

    def snapshot(self, camera: int, object_class: str, *, end: datetime | None) -> DetectionEpisode:
        """Freeze the current accumulation into a public episode."""
        # An opened track always has a qualifying signal; `start` is only a
        # fallback so this stays total rather than asserting.
        last_signal = self.last_qualifying if self.last_qualifying is not None else self.start
        return DetectionEpisode(
            camera=camera,
            object_class=object_class,
            raw_labels=frozenset(self.raw_labels),
            start=self.start,
            end=end,
            last_signal=last_signal,
            peak_confidence=self.peak_confidence,
            signal_count=self.signal_count,
        )


class EpisodeReducer:
    """Turn a ``CLASSIFY`` signal stream into open/close episode emissions.

    The consumer owns the clock. A pure reducer cannot notice that *nothing*
    has happened, so :meth:`tick` must be called periodically or an episode
    that has gone quiet stays open. :meth:`add` performs the same inactivity
    check against the incoming signal's timestamp before absorbing it, through
    the same helper, so a boundary computed by a tick and one computed by an
    arrival are the same instant -- the two paths cannot disagree.

    Nothing here subscribes to a stream, spawns a task, or reads a clock.
    """

    __slots__ = ("_default", "_overrides", "_tracks")

    def __init__(
        self,
        *,
        default: ReducerConfig | None = None,
        overrides: Mapping[OverrideKey, ReducerConfig] | None = None,
    ) -> None:
        """Create a reducer.

        Args:
            default: The configuration used when no override matches.
            overrides: Per-camera and per-class configuration, keyed by
                ``(camera, object_class)`` where either element may be ``None``
                meaning "any". Class names are normalized with
                :func:`~aiosecurityspy.class_slug`, so an override written as
                ``"Delivery Van"`` matches the episodes it looks like it should.
                Each value **replaces** the default outright; see
                :meth:`config_for`.

        Raises:
            ValueError: A `default` or an override value that is not a
                :class:`ReducerConfig`; an override key that is not a
                ``(camera, class)`` pair of the right types; the key
                ``(None, None)``, which would silently never be consulted
                because that is what `default` is; or two keys that normalize to
                the same pair, where one would silently win over the other.

        """
        self._default = _require_config(
            default if default is not None else ReducerConfig(), "default"
        )
        self._overrides: dict[OverrideKey, ReducerConfig] = {}
        for key, config in (overrides or {}).items():
            normalized = _normalize_override_key(key)
            if normalized in self._overrides:
                # `("Delivery Van", ...)` and `("delivery_van", ...)` are the
                # same key after slugging. Letting the last one silently win
                # would hide a real disagreement in the caller's own config.
                message = "two override keys normalize to the same (camera, object_class) pair"
                raise ValueError(message)
            self._overrides[normalized] = _require_config(config, "override config")
        self._tracks: dict[tuple[int, str], _Track] = {}

    @property
    def open_episodes(self) -> tuple[DetectionEpisode, ...]:
        """Return every currently open episode, ordered by camera then class.

        Tracks that have not yet satisfied their debounce are not episodes and
        do not appear here.
        """
        return tuple(
            track.snapshot(camera, object_class, end=None)
            for (camera, object_class), track in sorted(self._tracks.items())
            if track.opened
        )

    def config_for(self, camera: int, object_class: str) -> ReducerConfig:
        """Resolve the configuration governing one camera and one class.

        Resolution order is ``(camera, class)`` -> ``(camera, None)`` ->
        ``(None, class)`` -> the default, which is exactly FR-8's "a per-camera
        value overrides the global".

        **The first match wins whole.** An override is a replacement, not a
        merge: the matched :class:`ReducerConfig` supplies all three values, and
        the ones it did not spell out are that class's own defaults -- the
        provisional module constants -- not the values on the `default` config
        passed to the constructor. So an override meaning "same as my default
        but debounce 5" has to restate the threshold and the gap. Nothing here
        combines two configs, because a half-inherited tuning is far harder to
        reason about than a repeated one.

        Args:
            camera: The camera number.
            object_class: A raw or already-slugged class name.

        Returns:
            The most specific matching configuration.

        """
        slug = class_slug(object_class)
        for key in ((camera, slug), (camera, None), (None, slug)):
            config = self._overrides.get(key)
            if config is not None:
                return config
        return self._default

    def add(self, signal: ClassificationSignal) -> tuple[EpisodeEvent, ...]:
        """Absorb one signal and return whatever it caused to be emitted.

        The inactivity check runs first, against the signal's own timestamp, so
        a signal arriving after the gap has already elapsed closes the stale
        episode before starting a fresh debounce run -- a lazy consumer that
        never ticks still gets correct boundaries, just late ones.

        That check covers **only this signal's own camera and class**. A
        signal's timestamp is evidence about its own camera's clock and nothing
        else, and camera clocks disagree: one camera running an hour fast would
        otherwise close every other camera's live episode, at an `end` an hour
        in their future. Sweeping every track is :meth:`tick`'s job, where `now`
        is the caller's single authoritative clock.

        Args:
            signal: The inference to absorb. A non-finite confidence is ignored
                entirely rather than raising: it comes off the wire, and it must
                neither open an episode nor win a peak comparison.

        Returns:
            The emissions, in order. Usually empty: an already-open episode
            absorbs further signals silently.

        """
        if not signal.is_usable:
            return ()
        emitted = list(self._expire(signal.timestamp, keys=((signal.camera, signal.slug),)))
        emitted.extend(self._absorb(signal))
        return tuple(emitted)

    def feed(self, event: StreamEvent) -> tuple[EpisodeEvent, ...]:
        """Absorb one stream event, fanned into one signal per object class.

        Anything unusable is ignored rather than raised on: a live stream must
        not die because one record was not a classification, carried no
        payload, or named no camera.

        Args:
            event: A record from :class:`~aiosecurityspy.SecuritySpyEventStream`.

        Returns:
            The emissions caused by every class in the payload, in slug order.
            A frame naming several classes must not have its emission order
            decided by the order the server happened to list them in, because
            every other method here emits in sorted order.

        """
        signals = self._signals_from(event)
        emitted: list[EpisodeEvent] = []
        for signal in signals:
            emitted.extend(self.add(signal))
        return tuple(emitted)

    def tick(self, now: datetime) -> tuple[EpisodeEvent, ...]:
        """Close every episode that has been quiet for longer than its gap.

        This is the caller's obligation: without it, an episode whose camera
        simply stopped seeing anything stays open forever.

        Args:
            now: The current instant, timezone-aware. A `now` earlier than an
                episode's last signal closes nothing rather than raising -- a
                clock that stepped backwards is not a reason to end a detection.

        Returns:
            One :class:`EpisodeClosed` per lapsed episode, camera order.

        Raises:
            ValueError: `now` is not a timezone-aware ``datetime``.

        """
        _require_aware(now, "now")
        return self._expire(now, keys=sorted(self._tracks))

    def close_all(self, now: datetime) -> tuple[EpisodeEvent, ...]:
        """Close every open episode at `now` and discard all state.

        For a disconnect: the stream has stopped, so no further signal can
        arrive, and leaving episodes open would strand them. Unlike
        :meth:`tick`, the end is `now` itself -- nothing lapsed, the observation
        stopped.

        Args:
            now: The instant every open episode is declared to have ended at.
                A `now` that predates an episode's own last signal is raised to
                that signal instead, so no episode can be emitted ending before
                it started. :meth:`tick` is hardened against a clock that
                stepped backwards; this must be too.

        Returns:
            One :class:`EpisodeClosed` per open episode, camera order. A
            following :meth:`tick` emits nothing.

        Raises:
            ValueError: `now` is not a timezone-aware ``datetime``.

        """
        _require_aware(now, "now")
        emitted = [
            EpisodeClosed(track.snapshot(camera, object_class, end=max(now, track.last_any)))
            for (camera, object_class), track in sorted(self._tracks.items())
            if track.opened
        ]
        self._tracks.clear()
        return tuple(emitted)

    def reset(self) -> None:
        """Discard all state, emitting nothing.

        Deliberately silent, and deliberately distinct from :meth:`close_all`.
        Resetting means the caller has stopped tracking, not that anything
        ended; emitting closes would be claiming episode boundaries nobody
        observed. Use :meth:`close_all` when you do want to claim them.
        """
        self._tracks.clear()

    # -- internals ---------------------------------------------------------

    def _signals_from(self, event: StreamEvent) -> tuple[ClassificationSignal, ...]:
        """Fan one stream event out into one signal per object class.

        Two raw labels in a single payload that slug the same are merged the way
        :meth:`ClassificationPayload.slugged` merges them -- the higher
        confidence wins -- so one frame contributes one signal per class and
        cannot advance a debounce run twice.

        This is **stricter** than ``slugged()``, which merges every pair it is
        given: a blank label and a confidence that is not a finite number are
        dropped here rather than merged, because each would otherwise raise out
        of a method a live stream calls once per record. The result is returned
        in slug order.
        """
        if event.event_type != EVENT_CLASSIFY:
            return ()
        payload = event.payload
        if not isinstance(payload, ClassificationPayload):
            return ()
        timestamp = event.timestamp
        camera = event.camera
        if timestamp is None or camera is None:
            return ()
        best: dict[str, tuple[str, float]] = {}
        for label, confidence in payload.classes.items():
            # Everything here came off the wire, including -- for a payload a
            # consumer built by hand -- a value that is not a number at all, on
            # which `math.isfinite` would raise. Nothing in this loop may raise:
            # one bad record must not end a live stream.
            if not _is_nonempty_str(label) or not _is_number(confidence):
                continue
            if not math.isfinite(confidence):
                continue
            slug = class_slug(label)
            previous = best.get(slug)
            if previous is None or _prefers(confidence, previous[1]):
                best[slug] = (label, confidence)
        return tuple(
            ClassificationSignal(
                camera=camera,
                object_class=label,
                confidence=confidence,
                timestamp=timestamp,
            )
            for _slug, (label, confidence) in sorted(best.items())
        )

    def _expire(
        self, now: datetime, *, keys: Iterable[tuple[int, str]]
    ) -> tuple[EpisodeEvent, ...]:
        """Close, or silently forget, whichever of `keys` have gone quiet.

        The single inactivity path. :meth:`add` and :meth:`tick` both come
        through here, which is what makes an arrival-computed boundary and a
        tick-computed boundary the same instant; they differ only in how much
        of the state they are entitled to judge with the clock they hold.
        """
        emitted: list[EpisodeEvent] = []
        for key in keys:
            track = self._tracks.get(key)
            if track is None:
                continue
            camera, object_class = key
            config = self.config_for(camera, object_class)
            deadline = track.deadline(config.gap)
            if deadline is None or now <= deadline:
                continue
            if track.opened:
                emitted.append(EpisodeClosed(track.snapshot(camera, object_class, end=deadline)))
            del self._tracks[key]
        return tuple(emitted)

    def _absorb(self, signal: ClassificationSignal) -> tuple[EpisodeEvent, ...]:
        """Fold one usable signal into its track, opening an episode if due."""
        slug = signal.slug
        key = (signal.camera, slug)
        config = self.config_for(signal.camera, slug)
        track = self._tracks.get(key)
        if track is None:
            track = _Track(
                start=signal.timestamp,
                last_any=signal.timestamp,
                peak_confidence=signal.confidence,
                signal_count=0,
            )
            self._tracks[key] = track

        track.signal_count += 1
        track.raw_labels.add(signal.object_class)
        if _prefers(signal.confidence, track.peak_confidence):
            track.peak_confidence = signal.confidence
        # An out-of-order signal is counted and can raise the peak, but it must
        # never rewind an inactivity deadline -- so the "last" marks only move
        # forward. `start` moves the other way for the same reason: an episode
        # whose start was later than one of its own signals would break the
        # `start <= last_signal` invariant the model documents.
        track.start = min(track.start, signal.timestamp)
        track.last_any = max(track.last_any, signal.timestamp)

        if signal.confidence < config.threshold:
            # A below-threshold signal breaks the debounce run but never ends an
            # open episode -- see `_Track.deadline`.
            track.run = 0
            return ()

        track.run += 1
        track.last_qualifying = (
            signal.timestamp
            if track.last_qualifying is None
            else max(track.last_qualifying, signal.timestamp)
        )
        if track.opened or track.run < config.debounce:
            return ()
        track.opened = True
        return (EpisodeOpened(track.snapshot(signal.camera, slug, end=None)),)


def _normalize_override_key(key: OverrideKey) -> OverrideKey:
    """Validate one override key and slug its class name.

    Raises:
        ValueError: The key is not a ``(camera, class)`` pair of the right
            types, or is ``(None, None)``.

    """
    if not _is_pair(key):
        message = "override keys must be (camera, object_class) pairs"
        raise ValueError(message)
    camera, object_class = key
    if camera is not None:
        _require_int(camera, "override camera")
    if object_class is not None:
        if not _is_nonempty_str(object_class):
            message = "override object_class must be a non-empty string or None"
            raise ValueError(message)
        object_class = class_slug(object_class)
    if camera is None and object_class is None:
        message = "the (None, None) override is the default config; pass it as `default`"
        raise ValueError(message)
    return (camera, object_class)
