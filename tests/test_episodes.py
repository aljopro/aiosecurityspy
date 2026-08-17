"""Reduction coverage for the detection-episode reducer (research §3.5).

Every row of the story's edge-case matrix is asserted here from synthetic
signals: no session, no server, no event loop and no clock. That is the whole
claim of a pure reducer (AD-3), so the test module proves it by never importing
`asyncio` or `aiohttp` either.

The reference case is built programmatically from the confidence sequence
research §3.5 published for a single subject, because the ~190:1 reduction is a
correctness requirement (PRD §11.1) rather than an optimization, and a
correctness requirement has to be asserted.
"""

from __future__ import annotations

import ast
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

import pytest

import aiosecurityspy
from aiosecurityspy import (
    DEFAULT_DETECTION_DEBOUNCE,
    DEFAULT_DETECTION_GAP,
    DEFAULT_DETECTION_THRESHOLD,
    ClassificationPayload,
    ClassificationSignal,
    DetectionEpisode,
    EpisodeClosed,
    EpisodeOpened,
    EpisodeReducer,
    MotionPayload,
    ReducerConfig,
    StreamEvent,
)

if TYPE_CHECKING:
    from aiosecurityspy import EpisodeEvent

#: The confidence sequence research §3.5 published for one subject on one
#: camera. Transcribed verbatim; the reference case cycles it.
SEQUENCE: Final = (
    20.0,
    69.0,
    19.0,
    77.0,
    88.0,
    8.0,
    54.0,
    25.0,
    5.0,
    18.0,
    18.0,
    49.0,
    13.0,
    17.0,
    16.0,
    97.0,
    96.0,
    99.0,
    99.0,
    28.0,
    51.0,
    71.0,
    64.0,
    91.0,
    97.0,
)

#: 191 `CLASSIFY` records on one camera in 95 s (§3.5).
REFERENCE_SIGNALS: Final = 191

#: Sequence index at which the first run of three at-or-above-70 values
#: completes, so the index of the signal the reference episode opens on.
REFERENCE_OPEN_INDEX: Final = 17

#: PRD §11.1 calls the ~190:1 collapse a correctness requirement. Stated as a
#: floor: the burst must produce an open and a close and nothing else, so any
#: extra emission -- a spurious close mid-burst, a re-open -- drops below it.
MIN_REDUCTION_RATIO: Final = 90.0
REFERENCE_SPAN: Final = timedelta(seconds=95)
REFERENCE_PEAK: Final = 99.0

#: The camera the reference case runs on.
CAMERA: Final = 10
OTHER_CAMERA: Final = 7

T0: Final = datetime(2026, 8, 10, 12, 0, 0, tzinfo=UTC)
GAP: Final = DEFAULT_DETECTION_GAP

# Named so the assertions read as claims rather than as bare numbers.
HIGHEST: Final = 100.0
SPAN_OF_FOUR: Final = 4
SPAN_OF_TWO: Final = 2


def signal(
    confidence: float,
    *,
    at: datetime,
    camera: int = CAMERA,
    object_class: str = "human",
) -> ClassificationSignal:
    return ClassificationSignal(
        camera=camera,
        object_class=object_class,
        confidence=confidence,
        timestamp=at,
    )


def opened(emitted: tuple[EpisodeEvent, ...]) -> list[DetectionEpisode]:
    return [event.episode for event in emitted if isinstance(event, EpisodeOpened)]


def closed(emitted: tuple[EpisodeEvent, ...]) -> list[DetectionEpisode]:
    return [event.episode for event in emitted if isinstance(event, EpisodeClosed)]


def classify_event(
    classes: dict[str, float],
    *,
    at: datetime | None = T0,
    camera: int | None = CAMERA,
    event_type: str = "CLASSIFY",
    payload_override: object = ...,
) -> StreamEvent:
    """Build a `CLASSIFY` stream event without going near a socket."""
    payload = (
        ClassificationPayload(classes=MappingProxyType(dict(classes)))
        if payload_override is ...
        else payload_override
    )
    return StreamEvent(
        timestamp=at,
        raw_timestamp="20260810120000",
        event_number=0,
        camera=camera,
        event_type=event_type,
        info="",
        payload=payload,  # type: ignore[arg-type]
        raw="",
    )


# -- the reference reduction -------------------------------------------------


def reference_signals() -> list[ClassificationSignal]:
    """191 signals over 95 s, cycling §3.5's published confidence sequence."""
    step = REFERENCE_SPAN / (REFERENCE_SIGNALS - 1)
    return [
        signal(SEQUENCE[index % len(SEQUENCE)], at=T0 + step * index)
        for index in range(REFERENCE_SIGNALS)
    ]


def test_the_reference_burst_reduces_to_exactly_one_episode() -> None:
    """191 signals in, one episode out -- PRD §11.1's ratio, asserted.

    The ratio is measured between what was *fed in* and what came *out*, not
    between two numbers the reducer already agreed on: an assertion that divides
    an episode's own `signal_count` by its own emission count cannot fail
    independently of the assertions above it, which makes it decoration rather
    than a check on the requirement.
    """
    reducer = EpisodeReducer()
    signals = reference_signals()
    emitted: list[EpisodeEvent] = []
    signals_fed = 0
    for item in signals:
        signals_fed += 1
        emitted.extend(reducer.add(item))
    emitted.extend(reducer.tick(signals[-1].timestamp + GAP + timedelta(seconds=1)))

    assert signals_fed == REFERENCE_SIGNALS
    assert signals_fed / len(emitted) >= MIN_REDUCTION_RATIO

    assert len(opened(tuple(emitted))) == 1
    assert len(closed(tuple(emitted))) == 1

    episode = closed(tuple(emitted))[0]
    assert episode.camera == CAMERA
    assert episode.object_class == "human"
    assert episode.peak_confidence == REFERENCE_PEAK
    assert episode.signal_count == REFERENCE_SIGNALS
    assert episode.start == T0
    assert not episode.is_open


def first_debounce_completion(
    sequence: tuple[float, ...], *, threshold: float, debounce: int
) -> int:
    """Return the index at which `sequence` first completes a debounce run.

    The debounce rule restated independently of the reducer, so the expected
    open index is derived rather than being a literal that happens to coincide
    with the position of some value in the sequence.
    """
    run = 0
    for index, confidence in enumerate(sequence):
        run = run + 1 if confidence >= threshold else 0
        if run == debounce:
            return index
    pytest.fail("the sequence never completes a debounce run")


def test_the_reference_burst_opens_only_after_three_consecutive_qualifying() -> None:
    """The 77, 88 pair early in the sequence must not be enough to open."""
    expected = first_debounce_completion(
        SEQUENCE,
        threshold=DEFAULT_DETECTION_THRESHOLD,
        debounce=DEFAULT_DETECTION_DEBOUNCE,
    )
    # Positions 15-17 are 97, 96, 99: the first run of three. Positions 3-4 are
    # 77, 88 -- only two, and broken by the 8 that follows.
    assert expected == REFERENCE_OPEN_INDEX
    assert SEQUENCE[REFERENCE_OPEN_INDEX - 2 : REFERENCE_OPEN_INDEX + 1] == (97.0, 96.0, 99.0)

    reducer = EpisodeReducer()
    for index, item in enumerate(reference_signals()):
        if opened(reducer.add(item)):
            assert index == expected
            break
    else:  # pragma: no cover - the reference case always opens
        pytest.fail("the reference burst never opened an episode")


def test_a_mid_episode_low_confidence_run_does_not_close_it() -> None:
    """§3.5's 88, 8, 54 in consecutive frames is one presence, not three."""
    reducer = EpisodeReducer()
    emitted: list[EpisodeEvent] = []
    for index, confidence in enumerate([95.0, 95.0, 95.0, 8.0, 5.0, 18.0, 13.0, 96.0]):
        emitted.extend(reducer.add(signal(confidence, at=T0 + timedelta(seconds=index))))
    assert len(opened(tuple(emitted))) == 1
    assert closed(tuple(emitted)) == []
    assert len(reducer.open_episodes) == 1


# -- debounce and threshold --------------------------------------------------


def test_isolated_qualifying_signals_never_open_an_episode() -> None:
    reducer = EpisodeReducer()
    emitted: list[EpisodeEvent] = []
    pattern = (99.0, 99.0, 20.0)
    for index in range(20):
        # Two qualifying signals, then a low one -- never three in a row.
        emitted.extend(
            reducer.add(signal(pattern[index % len(pattern)], at=T0 + timedelta(seconds=index)))
        )
    assert emitted == []
    assert reducer.open_episodes == ()


def test_five_hundred_below_threshold_signals_emit_nothing() -> None:
    reducer = EpisodeReducer()
    emitted: list[EpisodeEvent] = []
    for index in range(500):
        emitted.extend(reducer.add(signal(69.0, at=T0 + timedelta(seconds=index))))
    assert emitted == []
    assert reducer.open_episodes == ()


def test_a_signal_exactly_at_the_threshold_qualifies() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    emitted = reducer.add(signal(70.0, at=T0))
    assert len(opened(emitted)) == 1


def test_peak_spans_the_signals_that_preceded_the_opening_crossing() -> None:
    """FR-6: the peak is the whole span's, never the value at the crossing."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=90.0, debounce=2))
    confidences = (95.0, 20.0, 95.0, 96.0)
    emitted: list[EpisodeEvent] = []
    for index, confidence in enumerate(confidences):
        emitted.extend(reducer.add(signal(confidence, at=T0 + timedelta(seconds=index))))

    episodes = opened(tuple(emitted))
    assert len(episodes) == 1
    episode = episodes[0]
    # Opened on the second consecutive 95+, i.e. the 96 at index 3.
    assert episode.peak_confidence == max(confidences)
    # The pre-open 95 at index 0 is inside the span.
    assert episode.start == T0
    assert episode.signal_count == SPAN_OF_FOUR


# -- closure -----------------------------------------------------------------


def open_one(reducer: EpisodeReducer, *, at: datetime = T0) -> datetime:
    """Open an episode with the default debounce; return the last signal's time."""
    last = at
    for index in range(DEFAULT_DETECTION_DEBOUNCE):
        last = at + timedelta(seconds=index)
        reducer.add(signal(99.0, at=last))
    return last


def test_a_tick_past_the_gap_closes_the_episode_exactly_once() -> None:
    reducer = EpisodeReducer()
    last = open_one(reducer)

    assert reducer.tick(last + GAP) == ()
    emitted = reducer.tick(last + GAP + timedelta(seconds=1))
    episodes = closed(emitted)
    assert len(episodes) == 1
    # The instant it lapsed, not the `now` that noticed it.
    assert episodes[0].end == last + GAP
    assert reducer.tick(last + GAP + timedelta(minutes=5)) == ()
    assert reducer.open_episodes == ()


def test_a_late_signal_closes_the_stale_episode_then_starts_a_fresh_run() -> None:
    reducer = EpisodeReducer()
    last = open_one(reducer)

    emitted = reducer.add(signal(99.0, at=last + GAP + timedelta(seconds=5)))
    assert len(closed(emitted)) == 1
    assert closed(emitted)[0].end == last + GAP
    assert opened(emitted) == []
    # One qualifying signal into a fresh debounce run, so still nothing open.
    assert reducer.open_episodes == ()


def test_tick_and_arrival_compute_the_same_boundary() -> None:
    """The two paths share one `_expire`, so they cannot disagree."""
    by_tick = EpisodeReducer()
    last = open_one(by_tick)
    tick_end = closed(by_tick.tick(last + GAP + timedelta(seconds=5)))[0].end

    by_arrival = EpisodeReducer()
    open_one(by_arrival)
    arrival_end = closed(by_arrival.add(signal(99.0, at=last + GAP + timedelta(seconds=5))))[0].end

    assert tick_end == arrival_end == last + GAP


def test_below_threshold_signals_do_not_extend_the_inactivity_deadline() -> None:
    reducer = EpisodeReducer()
    last = open_one(reducer)
    reducer.add(signal(10.0, at=last + timedelta(seconds=10)))
    emitted = reducer.tick(last + GAP + timedelta(seconds=1))
    assert closed(emitted)[0].end == last + GAP


def test_a_pending_run_is_forgotten_after_a_gap_of_silence() -> None:
    """A stale below-threshold signal must not become a later episode's start."""
    reducer = EpisodeReducer()
    reducer.add(signal(10.0, at=T0))
    assert reducer.tick(T0 + GAP + timedelta(seconds=1)) == ()

    later = T0 + timedelta(hours=1)
    emitted: list[EpisodeEvent] = []
    for index in range(DEFAULT_DETECTION_DEBOUNCE):
        emitted.extend(reducer.add(signal(99.0, at=later + timedelta(seconds=index))))
    assert opened(tuple(emitted))[0].start == later


def test_one_cameras_skewed_clock_cannot_close_another_cameras_episode() -> None:
    """A signal's timestamp is evidence about its own camera and nothing else.

    Camera clocks disagree, sometimes by hours. Expiring every track against an
    arriving signal's timestamp would let the fastest camera on the system end
    every other camera's live episode, at an `end` in their future.
    """
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    reducer.add(signal(99.0, at=T0, camera=OTHER_CAMERA))
    assert len(reducer.open_episodes) == 1

    # A camera whose clock runs an hour fast, well past the 30 s gap.
    emitted = reducer.add(signal(99.0, at=T0 + timedelta(hours=1), camera=CAMERA))
    assert closed(emitted) == []
    assert sorted(episode.camera for episode in reducer.open_episodes) == [OTHER_CAMERA, CAMERA]

    # The caller's own clock is still authoritative over everything.
    swept = reducer.tick(T0 + timedelta(hours=2))
    assert sorted(episode.camera for episode in closed(swept)) == [OTHER_CAMERA, CAMERA]


def test_an_inactivity_close_is_reachable_through_feed_alone() -> None:
    """The stream-facing path the README example depends on, end to end."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=2))
    first = classify_event({"human": 99.0})
    second = classify_event({"human": 98.0}, at=T0 + timedelta(seconds=1))
    assert reducer.feed(first) == ()
    assert len(opened(reducer.feed(second))) == 1

    late = classify_event(
        {"human": 97.0}, at=T0 + timedelta(seconds=1) + GAP + timedelta(seconds=5)
    )
    emitted = reducer.feed(late)
    assert len(closed(emitted)) == 1
    assert closed(emitted)[0].end == T0 + timedelta(seconds=1) + GAP


def test_open_episodes_are_ordered_by_camera_then_class() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    for camera in (OTHER_CAMERA + 2, OTHER_CAMERA, CAMERA):
        for object_class in ("vehicle", "animal"):
            reducer.add(signal(99.0, at=T0, camera=camera, object_class=object_class))

    assert [(episode.camera, episode.object_class) for episode in reducer.open_episodes] == [
        (OTHER_CAMERA, "animal"),
        (OTHER_CAMERA, "vehicle"),
        (OTHER_CAMERA + 2, "animal"),
        (OTHER_CAMERA + 2, "vehicle"),
        (CAMERA, "animal"),
        (CAMERA, "vehicle"),
    ]


def test_a_never_opened_track_is_forgotten_silently() -> None:
    """Expiring a pending run emits nothing and leaves nothing behind.

    Distinct from the `start` assertion elsewhere: this pins that the discarded
    run contributes neither an emission nor its accumulated peak and count to
    whatever comes next.
    """
    debounce = 3
    fresh_peak = 71.0
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=debounce))
    # One qualifying signal, so the track carries a real peak -- but not enough
    # of them to open anything.
    reducer.add(signal(99.0, at=T0))
    assert reducer.tick(T0 + GAP + timedelta(seconds=1)) == ()
    assert reducer.open_episodes == ()

    later = T0 + timedelta(hours=1)
    emitted: list[EpisodeEvent] = []
    for index in range(debounce):
        emitted.extend(reducer.add(signal(fresh_peak, at=later + timedelta(seconds=index))))

    episodes = opened(tuple(emitted))
    assert len(episodes) == 1
    # The discarded run contributed neither its count nor its peak of 99.
    assert episodes[0].signal_count == debounce
    assert episodes[0].peak_confidence == fresh_peak


# -- configuration resolution ------------------------------------------------


def test_a_per_camera_override_beats_the_global_threshold() -> None:
    reducer = EpisodeReducer(
        default=ReducerConfig(threshold=70.0, debounce=3),
        overrides={(4, None): ReducerConfig(threshold=50.0, debounce=3)},
    )
    emitted: list[EpisodeEvent] = []
    for index in range(3):
        at = T0 + timedelta(seconds=index)
        emitted.extend(reducer.add(signal(60.0, at=at, camera=4)))
        emitted.extend(reducer.add(signal(60.0, at=at, camera=OTHER_CAMERA)))

    episodes = opened(tuple(emitted))
    assert [episode.camera for episode in episodes] == [4]


def test_a_per_class_override_beats_the_global_debounce() -> None:
    reducer = EpisodeReducer(
        default=ReducerConfig(threshold=70.0, debounce=3),
        overrides={(None, "vehicle"): ReducerConfig(threshold=70.0, debounce=5)},
    )
    emitted: list[EpisodeEvent] = []
    for index in range(4):
        at = T0 + timedelta(seconds=index)
        emitted.extend(reducer.add(signal(99.0, at=at, object_class="human")))
        emitted.extend(reducer.add(signal(99.0, at=at, object_class="vehicle")))

    assert [episode.object_class for episode in opened(tuple(emitted))] == ["human"]

    emitted = list(reducer.add(signal(99.0, at=T0 + timedelta(seconds=4), object_class="vehicle")))
    assert [episode.object_class for episode in opened(tuple(emitted))] == ["vehicle"]


def test_config_resolution_prefers_the_most_specific_key() -> None:
    exact = ReducerConfig(threshold=10.0)
    by_camera = ReducerConfig(threshold=20.0)
    by_class = ReducerConfig(threshold=30.0)
    default = ReducerConfig(threshold=40.0)
    reducer = EpisodeReducer(
        default=default,
        overrides={
            (CAMERA, "human"): exact,
            (CAMERA, None): by_camera,
            (None, "human"): by_class,
        },
    )
    assert reducer.config_for(CAMERA, "human") == exact
    assert reducer.config_for(CAMERA, "vehicle") == by_camera
    assert reducer.config_for(OTHER_CAMERA, "human") == by_class
    assert reducer.config_for(OTHER_CAMERA, "vehicle") == default


def test_override_class_names_are_slugged_like_everything_else() -> None:
    config = ReducerConfig(threshold=1.0)
    reducer = EpisodeReducer(overrides={(None, "Delivery Van"): config})
    assert reducer.config_for(CAMERA, "DELIVERY_VAN") == config


def test_an_override_replaces_the_default_outright_rather_than_merging() -> None:
    """Documented behaviour, pinned so it cannot drift into a silent merge."""
    vehicle_debounce = 5
    reducer = EpisodeReducer(
        default=ReducerConfig(threshold=20.0, debounce=2, gap=timedelta(seconds=5)),
        overrides={(None, "vehicle"): ReducerConfig(debounce=vehicle_debounce)},
    )
    vehicle = reducer.config_for(CAMERA, "vehicle")
    assert vehicle.debounce == vehicle_debounce
    # Not 20.0 and not 5 s: the unspecified fields fall back to the module
    # defaults, not to the `default` config passed above.
    assert vehicle.threshold == DEFAULT_DETECTION_THRESHOLD
    assert vehicle.gap == DEFAULT_DETECTION_GAP


def test_two_override_keys_that_normalize_alike_are_rejected() -> None:
    with pytest.raises(ValueError, match="normalize"):
        EpisodeReducer(
            overrides={
                (None, "Delivery Van"): ReducerConfig(threshold=10.0),
                (None, "delivery_van"): ReducerConfig(threshold=90.0),
            }
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        pytest.param({"default": "strict"}, "default", id="default-not-a-config"),
        pytest.param({"default": {"threshold": 70.0}}, "default", id="default-is-a-mapping"),
        pytest.param({"overrides": {(4, None): 70.0}}, "override config", id="value-not-a-config"),
        pytest.param(
            {
                "overrides": {
                    (4, None): ReducerConfig,
                }
            },
            "override config",
            id="value-is-the-class",
        ),
    ],
)
def test_a_config_that_is_not_a_reducer_config_is_rejected_at_construction(
    kwargs: dict[str, object], match: str
) -> None:
    """Otherwise it survives here and dies as an `AttributeError` mid-reduction."""
    with pytest.raises(ValueError, match=match):
        EpisodeReducer(**kwargs)  # type: ignore[arg-type]


def test_the_defaults_are_the_provisional_constants() -> None:
    config = ReducerConfig()
    assert config.threshold == DEFAULT_DETECTION_THRESHOLD
    assert config.debounce == DEFAULT_DETECTION_DEBOUNCE
    assert config.gap == DEFAULT_DETECTION_GAP
    # The public constant must be usable as the field it is the default for.
    assert ReducerConfig(gap=DEFAULT_DETECTION_GAP).gap == DEFAULT_DETECTION_GAP


# -- keys: slugging and independence -----------------------------------------


def test_two_raw_labels_that_slug_the_same_are_one_episode() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=2))
    weaker, stronger = 80.0, 90.0
    emitted: list[EpisodeEvent] = []
    emitted.extend(reducer.add(signal(weaker, at=T0, object_class="Delivery Van")))
    emitted.extend(
        reducer.add(signal(stronger, at=T0 + timedelta(seconds=1), object_class="DELIVERY_VAN"))
    )

    episodes = opened(tuple(emitted))
    assert len(episodes) == 1
    episode = episodes[0]
    assert episode.object_class == "delivery_van"
    assert episode.peak_confidence == stronger
    assert episode.raw_labels == frozenset({"Delivery Van", "DELIVERY_VAN"})


def test_two_classes_on_one_camera_reduce_independently() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=2))
    emitted: list[EpisodeEvent] = []
    peaks = {"human": 99.0, "vehicle": 72.0}
    for index, (human, vehicle) in enumerate([(99.0, 10.0), (98.0, 71.0), (10.0, 72.0)]):
        at = T0 + timedelta(seconds=index)
        emitted.extend(reducer.add(signal(human, at=at, object_class="human")))
        emitted.extend(reducer.add(signal(vehicle, at=at, object_class="vehicle")))

    episodes = {episode.object_class: episode for episode in opened(tuple(emitted))}
    assert set(episodes) == {"human", "vehicle"}
    assert episodes["human"].peak_confidence == peaks["human"]
    assert episodes["vehicle"].peak_confidence == peaks["vehicle"]
    assert [episode.object_class for episode in reducer.open_episodes] == ["human", "vehicle"]


def test_the_class_vocabulary_is_open() -> None:
    """AD-9: an unknown class is reduced, never rejected."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=1.0, debounce=1))
    emitted = reducer.add(signal(42.0, at=T0, object_class="Épaulard 🐋"))
    assert len(opened(emitted)) == 1
    assert opened(emitted)[0].object_class == "paulard"


def test_labels_with_no_ascii_alphanumerics_all_collapse_into_unknown() -> None:
    """Accepted, documented, and pinned -- not discovered later in production.

    `class_slug` keeps only `[a-z0-9_]` and falls back to "unknown", so several
    non-Latin labels on one camera become one episode. `raw_labels` is where the
    distinction survives.
    """
    reducer = EpisodeReducer(default=ReducerConfig(threshold=1.0, debounce=1))
    labels = ("人", "车辆", "🐋")
    emitted: list[EpisodeEvent] = []
    for index, label in enumerate(labels):
        emitted.extend(
            reducer.add(
                signal(10.0 * (index + 1), at=T0 + timedelta(seconds=index), object_class=label)
            )
        )

    episodes = opened(tuple(emitted))
    assert len(episodes) == 1
    assert episodes[0].object_class == "unknown"
    assert reducer.open_episodes[0].raw_labels == frozenset(labels)
    assert reducer.open_episodes[0].peak_confidence == 10.0 * len(labels)


# -- feeding stream events ---------------------------------------------------


def test_a_classify_event_fans_out_into_one_signal_per_class() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    emitted = reducer.feed(classify_event({"human": 91.0, "vehicle": 88.0}))
    assert sorted(episode.object_class for episode in opened(emitted)) == ["human", "vehicle"]
    assert all(episode.start == T0 for episode in opened(emitted))


def test_one_event_advances_a_debounce_run_by_exactly_one() -> None:
    """Two raw labels that slug the same in one frame are still one signal."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=2))
    stronger = 95.0
    emitted = reducer.feed(classify_event({"Delivery Van": 80.0, "DELIVERY_VAN": stronger}))
    assert emitted == ()
    emitted = reducer.feed(
        classify_event({"delivery_van": 71.0}, at=T0 + timedelta(seconds=1)),
    )
    episodes = opened(emitted)
    assert len(episodes) == 1
    assert episodes[0].signal_count == SPAN_OF_TWO
    # The stronger of the two colliding labels won, exactly as `slugged()` does.
    assert episodes[0].peak_confidence == stronger


def test_a_multi_class_frame_emits_in_slug_order() -> None:
    """Every other method here emits sorted; the server's key order must not win."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    emitted = reducer.feed(classify_event({"vehicle": 99.0, "human": 98.0, "animal": 97.0}))
    assert [episode.object_class for episode in opened(emitted)] == ["animal", "human", "vehicle"]


def test_a_payload_carrying_a_non_numeric_confidence_does_not_kill_the_stream() -> None:
    """`math.isfinite` raises on a string; `feed()` may not raise on any record."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=1.0, debounce=1))
    payload = ClassificationPayload(classes=MappingProxyType({"human": "very"}))  # type: ignore[dict-item]
    assert reducer.feed(classify_event({}, payload_override=payload)) == ()

    # A usable class alongside the unusable one still reduces.
    mixed = ClassificationPayload(classes=MappingProxyType({"human": "very", "vehicle": 80.0}))  # type: ignore[dict-item]
    emitted = reducer.feed(classify_event({}, payload_override=mixed))
    assert [episode.object_class for episode in opened(emitted)] == ["vehicle"]


@pytest.mark.parametrize(
    "event",
    [
        pytest.param(classify_event({"human": 99.0}, event_type="MOTION"), id="not-classify"),
        pytest.param(classify_event({}, payload_override=None), id="no-payload"),
        pytest.param(
            classify_event({}, payload_override=MotionPayload(x=1, y=2, width=3, height=4)),
            id="wrong-payload",
        ),
        pytest.param(classify_event({"human": 99.0}, at=None), id="no-timestamp"),
        pytest.param(classify_event({"human": 99.0}, camera=None), id="no-camera"),
        pytest.param(classify_event({"human": math.nan}), id="non-finite"),
        pytest.param(classify_event({"human": math.inf}), id="infinite"),
        pytest.param(classify_event({"   ": 99.0}), id="blank-label"),
    ],
)
def test_an_unusable_stream_event_is_ignored_rather_than_raised_on(event: StreamEvent) -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=1.0, debounce=1))
    assert reducer.feed(event) == ()
    assert reducer.open_episodes == ()


# -- degradation and out-of-order --------------------------------------------


@pytest.mark.parametrize("confidence", [math.nan, math.inf, -math.inf])
def test_a_non_finite_confidence_is_ignored_and_never_wins_a_peak(confidence: float) -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=2))
    emitted: list[EpisodeEvent] = []
    peak = 96.0
    emitted.extend(reducer.add(signal(95.0, at=T0)))
    emitted.extend(reducer.add(signal(confidence, at=T0 + timedelta(seconds=1))))
    emitted.extend(reducer.add(signal(peak, at=T0 + timedelta(seconds=2))))

    episodes = opened(tuple(emitted))
    assert len(episodes) == 1
    assert episodes[0].peak_confidence == peak
    # Ignored entirely: it did not even count towards the span.
    assert episodes[0].signal_count == SPAN_OF_TWO


def test_an_out_of_order_signal_counts_and_can_raise_the_peak_but_never_rewinds() -> None:
    reducer = EpisodeReducer()
    last = open_one(reducer)
    reducer.add(signal(HIGHEST, at=last - timedelta(seconds=10)))

    emitted = reducer.tick(last + GAP + timedelta(seconds=1))
    episode = closed(emitted)[0]
    assert episode.peak_confidence == HIGHEST
    assert episode.signal_count == DEFAULT_DETECTION_DEBOUNCE + 1
    assert episode.last_signal == last
    assert episode.end == last + GAP
    # The span has to contain its own signals: `start` moves back to the
    # earliest one rather than leaving the episode starting after it.
    assert episode.start == last - timedelta(seconds=10)
    assert episode.start <= episode.last_signal


def test_a_backwards_clock_closes_nothing() -> None:
    reducer = EpisodeReducer()
    last = open_one(reducer)
    assert reducer.tick(last - timedelta(hours=1)) == ()
    assert len(reducer.open_episodes) == 1


# -- lifecycle ---------------------------------------------------------------


def test_close_all_ends_every_open_episode_at_now() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    reducer.add(signal(99.0, at=T0, object_class="human"))
    reducer.add(signal(99.0, at=T0, object_class="vehicle"))

    now = T0 + timedelta(seconds=5)
    emitted = reducer.close_all(now)
    episodes = closed(emitted)
    assert [episode.object_class for episode in episodes] == ["human", "vehicle"]
    assert all(episode.end == now for episode in episodes)
    assert reducer.tick(now + timedelta(hours=1)) == ()
    assert reducer.open_episodes == ()


def test_close_all_never_emits_an_episode_ending_before_it_started() -> None:
    """`tick` is hardened against a backwards clock; `close_all` must be too."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    reducer.add(signal(99.0, at=T0))

    episode = closed(reducer.close_all(T0 - timedelta(hours=1)))[0]
    assert episode.end == T0
    assert episode.end >= episode.start


def test_a_track_near_the_end_of_time_does_not_raise_out_of_tick() -> None:
    """`last_signal + gap` can overflow; an unrepresentable deadline is not an error."""
    reducer = EpisodeReducer(default=ReducerConfig(threshold=1.0, debounce=1))
    end_of_time = datetime.max.replace(tzinfo=UTC)
    reducer.add(signal(99.0, at=end_of_time))

    assert reducer.tick(end_of_time) == ()
    assert len(reducer.open_episodes) == 1


def test_reset_discards_state_and_emits_nothing() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    reducer.add(signal(99.0, at=T0))
    before = reducer.open_episodes
    assert len(before) == 1

    reducer.reset()
    assert not reducer.open_episodes
    assert reducer.tick(T0 + timedelta(hours=1)) == ()


def test_an_open_episode_absorbs_further_signals_silently() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    assert len(opened(reducer.add(signal(99.0, at=T0)))) == 1
    for index in range(1, 20):
        assert reducer.add(signal(99.0, at=T0 + timedelta(seconds=index))) == ()


# -- caller mistakes ---------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "field_name"),
    [
        ({"threshold": -1.0}, "threshold"),
        ({"threshold": 101.0}, "threshold"),
        ({"threshold": math.nan}, "threshold"),
        ({"threshold": math.inf}, "threshold"),
        ({"threshold": "70"}, "threshold"),
        ({"debounce": 0}, "debounce"),
        ({"debounce": -3}, "debounce"),
        ({"debounce": 2.5}, "debounce"),
        ({"debounce": True}, "debounce"),
        ({"gap": timedelta(0)}, "gap"),
        ({"gap": timedelta(seconds=-1)}, "gap"),
        ({"gap": 30.0}, "gap"),
    ],
)
def test_a_bad_config_raises_naming_the_field(kwargs: dict[str, object], field_name: str) -> None:
    with pytest.raises(ValueError, match=field_name):
        ReducerConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "field_name"),
    [
        ({"camera": "10"}, "camera"),
        ({"camera": 10.0}, "camera"),
        ({"camera": True}, "camera"),
        ({"object_class": ""}, "object_class"),
        ({"object_class": "   "}, "object_class"),
        ({"object_class": None}, "object_class"),
        ({"confidence": "99"}, "confidence"),
        ({"timestamp": datetime(2026, 8, 10, 12, 0, 0)}, "timestamp"),  # noqa: DTZ001 - naive on purpose
        ({"timestamp": "2026-08-10"}, "timestamp"),
    ],
)
def test_a_bad_signal_raises_at_construction(kwargs: dict[str, object], field_name: str) -> None:
    fields: dict[str, object] = {
        "camera": CAMERA,
        "object_class": "human",
        "confidence": 99.0,
        "timestamp": T0,
    }
    fields.update(kwargs)
    with pytest.raises(ValueError, match=field_name):
        ClassificationSignal(**fields)  # type: ignore[arg-type]


def test_a_non_finite_confidence_is_constructible_but_unusable() -> None:
    """It comes off the wire, so it degrades rather than raising."""
    item = signal(math.nan, at=T0)
    assert not item.is_usable
    assert EpisodeReducer(default=ReducerConfig(threshold=0.0, debounce=1)).add(item) == ()


@pytest.mark.parametrize(
    "key",
    [
        pytest.param((None, None), id="the-default-in-disguise"),
        pytest.param(("10", "human"), id="stringly-camera"),
        pytest.param((10, ""), id="empty-class"),
        pytest.param((10,), id="not-a-pair"),
    ],
)
def test_a_bad_override_key_raises_at_construction(key: object) -> None:
    with pytest.raises(ValueError, match=r"override|default"):
        EpisodeReducer(overrides={key: ReducerConfig()})  # type: ignore[dict-item]


@pytest.mark.parametrize("now", [datetime(2026, 8, 10, 12, 0, 0), "now"])  # noqa: DTZ001 - naive on purpose
def test_a_naive_or_non_datetime_now_is_rejected(now: object) -> None:
    reducer = EpisodeReducer()
    with pytest.raises(ValueError, match="now"):
        reducer.tick(now)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="now"):
        reducer.close_all(now)  # type: ignore[arg-type]


# -- purity ------------------------------------------------------------------


#: Module roots the reducer may not import: I/O, networking, concurrency,
#: Home Assistant, and any source of "what time is it now".
FORBIDDEN_IMPORTS: Final = frozenset(
    {"asyncio", "aiohttp", "homeassistant", "time", "socket", "os", "subprocess", "threading"}
)

#: Attribute names that read a clock. Checked as attribute *access* rather than
#: as text, so that `getattr(datetime, "now")()` is caught too and so that
#: prose is free to name them.
CLOCK_ATTRIBUTES: Final = frozenset(
    {"now", "utcnow", "today", "fromtimestamp", "utcfromtimestamp", "monotonic", "perf_counter"}
)


def episodes_ast() -> ast.Module:
    module = Path(__file__).parent.parent / "src" / "aiosecurityspy" / "episodes.py"
    return ast.parse(module.read_text(encoding="utf-8"))


def test_the_reducer_imports_nothing_impure() -> None:
    """AD-3, asserted against the parsed module rather than trusted."""
    roots: set[str] = set()
    for node in ast.walk(episodes_ast()):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    assert roots & FORBIDDEN_IMPORTS == set()


def test_the_reducer_never_reads_a_clock() -> None:
    """The single most consequential purity claim, checked structurally.

    A substring grep over the source would be satisfied by
    ``getattr(datetime, "now")()`` and would, worse, forbid the module from ever
    explaining in prose why it does not do that. Walking the AST checks the
    behaviour and leaves the comments alone.
    """
    offenders: list[str] = []
    for node in ast.walk(episodes_ast()):
        if isinstance(node, ast.Attribute) and node.attr in CLOCK_ATTRIBUTES:
            offenders.append(node.attr)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) > 1
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in CLOCK_ATTRIBUTES
        ):
            offenders.append(str(node.args[1].value))
    assert offenders == []


def test_the_reducer_explains_why_motion_end_is_unusable() -> None:
    """The decision the module most needs to record, and can now record.

    Closure is inactivity-only. The reason is empirical (§3.5: 467 motion
    signals and zero ends on camera 10) and is exactly the kind of thing a
    maintainer re-derives at 2 a.m. unless it is written down next to the code.
    """
    module = Path(__file__).parent.parent / "src" / "aiosecurityspy" / "episodes.py"
    source = module.read_text(encoding="utf-8")
    assert "MOTION_END" in source
    assert "467" in source


def test_the_public_surface_is_exported() -> None:
    for name in (
        "ClassificationSignal",
        "DetectionEpisode",
        "EpisodeClosed",
        "EpisodeEvent",
        "EpisodeOpened",
        "EpisodeReducer",
        "OverrideKey",
        "ReducerConfig",
        "DEFAULT_DETECTION_DEBOUNCE",
        "DEFAULT_DETECTION_GAP",
        "DEFAULT_DETECTION_THRESHOLD",
    ):
        assert name in aiosecurityspy.__all__
        assert hasattr(aiosecurityspy, name)


def test_episodes_are_frozen() -> None:
    reducer = EpisodeReducer(default=ReducerConfig(threshold=70.0, debounce=1))
    episode = opened(reducer.add(signal(99.0, at=T0)))[0]
    with pytest.raises(AttributeError):
        episode.peak_confidence = 1.0  # type: ignore[misc]
