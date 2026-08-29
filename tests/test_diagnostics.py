"""The anonymizer: what it redacts, what it preserves, and what it refuses to guess.

Self-contained by house rule: there is no ``conftest.py``, so the sample payload
lives here. The sentinels are distinct strings rather than realistic passwords so
a failure names the row of the story's I/O matrix that broke.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Final, NamedTuple, cast
from urllib.parse import quote, unquote
from uuid import UUID

import pytest

from aiosecurityspy import (
    CREDENTIAL_KEYS,
    REDACTED,
    Camera,
    CameraSettings,
    CaptureModes,
    anonymize,
    is_credential_key,
    redact_url,
)
from aiosecurityspy import const as const_module

if TYPE_CHECKING:
    from collections.abc import Iterator

DEVICE_USERNAME: Final = "device-user-77f1"
DEVICE_PASSWORD: Final = "device-pass-22b9"  # noqa: S105 - leak-detection sentinel, not a real credential
NESTED_SENTINEL: Final = "nested-value-6b2c"

#: Named so assertions do not trip PLR2004 on bare numbers.
BYTES_LENGTH: Final = 27
USER_COUNT: Final = 3
BRIGHTNESS: Final = 128
CAMERA_NUMBER: Final = 3
PAST_THE_DEPTH_CAP: Final = 40
CAST_VIEW_BYTES: Final = 8

#: The ceiling for a 200 KB walk. Generous: the linear form takes ~0.02s, the
#: quadratic one it replaced took roughly a minute.
LINEAR_WALK_SECONDS: Final = 5.0

#: Raised by the hostile shapes below. A named constant because ruff will not
#: take a string literal straight into an exception constructor.
EXPLOSION: Final = "this member explodes"


class ExplodingMapping(Mapping[str, object]):
    """A mapping whose iteration explodes: a lazy proxy that lost its backend."""

    def __getitem__(self, key: str) -> object:
        """Explode rather than answer."""
        raise RuntimeError(EXPLOSION)

    def __iter__(self) -> Iterator[str]:
        """Explode rather than iterate, which is what ``items()`` walks."""
        raise RuntimeError(EXPLOSION)

    def __len__(self) -> int:
        """Claim one entry, so nothing short-circuits on emptiness."""
        return 1


@dataclasses.dataclass
class ExplodingDataclass:
    """A dataclass whose second field reads like a property that failed."""

    fine: str
    boom: str

    def __getattribute__(self, name: str) -> object:
        """Explode on ``boom`` only, leaving the rest of the instance walkable."""
        if name == "boom":
            raise RuntimeError(EXPLOSION)
        return super().__getattribute__(name)


class Colour(Enum):
    """A plain ``Enum``, which is neither a scalar nor a container."""

    AMBER = "amber"


def settings_payload() -> dict[str, object]:
    """Build a ``++settings-cameras`` body, plaintext device credentials included."""
    return {
        "name": "Driveway",
        "overlayText": "Front Gate",
        "motionSensitivity": 55,
        "mcTriggerMotionH": True,
        "brightness": BRIGHTNESS,
        # research §8.3: the server really does send these in the clear.
        "username": DEVICE_USERNAME,
        "password": DEVICE_PASSWORD,
        # A lookalike that is not a credential and must stay readable.
        "passwordProtected": True,
    }


# --- is_credential_key -------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["username", "Password", "PASSWORD", "authToken", "auth_token", "AUTH-TOKEN", "api key"],
)
def test_credential_keys_match_however_they_are_spelled(key: str) -> None:
    """Matching is on the key lowercased with non-alphanumerics stripped."""
    assert is_credential_key(key)


@pytest.mark.parametrize("key", ["passwordProtected", "userCount", "name", "", "authorised"])
def test_lookalike_keys_are_not_credentials(key: str) -> None:
    """Membership is exact over the normalized key, never a substring test.

    ``passwordProtected`` tells a maintainer whether the camera is using
    authentication at all, which is the sort of thing a diagnostics dump exists
    to answer.
    """
    assert not is_credential_key(key)


@pytest.mark.parametrize("key", [None, 3, True, b"password", ("password",)])
def test_a_non_string_key_degrades_rather_than_raising(key: object) -> None:
    assert not is_credential_key(cast("str", key))


def test_every_declared_key_is_already_normalized() -> None:
    """The set is the normalized vocabulary, so a key in it must match itself.

    An entry such as ``"auth_token"`` would be dead data: nothing normalizes to
    it, so it could never match anything.
    """
    for key in CREDENTIAL_KEYS:
        assert is_credential_key(key), key


# --- redact_url --------------------------------------------------------------


def test_a_credential_bearing_stream_url_keeps_everything_but_the_credential() -> None:
    """Research §7's hazard: an RTSP URL echoed verbatim by an external tool."""
    redacted = redact_url("rtsp://ad min:s3cret@host.example:8000/++stream?auth=Ym9i&cameraNum=3")

    assert "s3cret" not in redacted
    assert "ad min" not in redacted
    assert "Ym9i" not in redacted
    assert redacted.startswith("rtsp://")
    assert "@host.example:8000/++stream" in redacted
    assert "cameraNum=3" in redacted
    assert redacted.count(REDACTED) == 3  # noqa: PLR2004 - userinfo is two of them, the auth param the third


@pytest.mark.parametrize(
    "text", ["Front Gate", "a:b", "", "10,20,30,40", "not a url://at all", "mailto:x@y"]
)
def test_a_string_that_is_not_a_url_is_returned_unchanged(text: str) -> None:
    assert redact_url(text) == text


def test_a_url_without_a_credential_survives_byte_for_byte() -> None:
    url = "http://nvr.example.com:8000/++settings-cameras?cameraNum=3&format=json"
    assert redact_url(url) == url


def test_an_unparseable_url_fails_closed() -> None:
    """It opens with a scheme, so it is a URL that failed to parse, not text.

    Returning it unchanged would publish whatever the parser could not make
    sense of -- which is exactly the string that might be carrying a credential.
    """
    assert redact_url("http://[::1") == REDACTED


def test_a_non_string_fails_closed() -> None:
    assert redact_url(cast("str", {"password": DEVICE_PASSWORD})) == REDACTED


def test_a_percent_encoded_parameter_name_cannot_slip_past_the_predicate() -> None:
    redacted = redact_url("http://host/x?%61uth=Ym9i")
    assert "Ym9i" not in redacted


def test_a_protocol_relative_reference_still_loses_its_userinfo() -> None:
    """``//user:pass@host/x`` carries a credential exactly like ``rtsp://`` does."""
    assert redact_url("//bob:s3cret@host/x") == f"//{REDACTED}:{REDACTED}@host/x"
    assert redact_url("//host/x?auth=Ym9i") == f"//host/x?auth={REDACTED}"


@pytest.mark.parametrize(
    "text",
    [
        "// see a@b.com for details",
        "// no credentials here",
        "//",
        "// a@b c@d",
    ],
)
def test_prose_opening_with_a_double_slash_is_not_a_reference(text: str) -> None:
    """A `//` authority cannot contain whitespace, so a comment stays a comment.

    Widening `redact_url` to cover protocol-relative references risks the reverse
    error -- redacting an email address out of an ordinary line of text, which is
    the "safe and useless" outcome the module exists to avoid.
    """
    assert redact_url(text) == text
    assert anonymize(text) == text


def test_a_credential_in_the_fragment_is_redacted_like_one_in_the_query() -> None:
    """A fragment is a place a token gets parked, not a safe harbour."""
    assert redact_url("http://h/x#auth=s3cret") == f"http://h/x#auth={REDACTED}"
    # A fragment that names nothing credential-shaped is still preserved.
    assert redact_url("http://h/x#section-2") == "http://h/x#section-2"
    assert redact_url("http://h/x?a=1#token=s3cret") == f"http://h/x?a=1#token={REDACTED}"


def test_the_legacy_semicolon_query_separator_does_not_bypass_redaction() -> None:
    """``?cameraNum=3;auth=Ym9i`` is a real shape, and ``&`` alone misses it."""
    redacted = redact_url("http://h/x?cameraNum=3;auth=Ym9i")

    assert redacted == f"http://h/x?cameraNum=3;auth={REDACTED}"
    # The original separator comes back out, not a normalized `&`.
    assert ";" in redacted


def test_an_empty_userinfo_does_not_fabricate_a_credential() -> None:
    """``http://@host/x`` had no credential; saying it did is a false fact."""
    assert redact_url("http://@host/x") == "http://@host/x"
    assert REDACTED not in redact_url("http://@host/x")


def test_the_scheme_survives_in_its_original_case() -> None:
    """The "byte for byte" claim has to include the bytes of the scheme."""
    assert redact_url("HTTP://HOST/Path?Format=JSON") == "HTTP://HOST/Path?Format=JSON"
    assert redact_url("RTSP://bob:s3cret@HOST/Path") == f"RTSP://{REDACTED}:{REDACTED}@HOST/Path"


# --- anonymize: the settings payload -----------------------------------------


def test_a_settings_payload_loses_its_credentials_and_keeps_everything_else() -> None:
    anonymized = anonymize(settings_payload())

    assert anonymized == {
        "name": "Driveway",
        "overlayText": "Front Gate",
        "motionSensitivity": 55,
        "mcTriggerMotionH": True,
        "brightness": BRIGHTNESS,
        "username": REDACTED,
        "password": REDACTED,
        "passwordProtected": True,
    }


def test_the_input_is_not_mutated() -> None:
    payload = settings_payload()
    anonymize(payload)
    assert payload["password"] == DEVICE_PASSWORD


def test_a_lookalike_value_survives_alongside_a_real_credential() -> None:
    anonymized = anonymize({"passwordProtected": True, "userCount": USER_COUNT, "pass": "x"})
    assert anonymized == {"passwordProtected": True, "userCount": USER_COUNT, "pass": REDACTED}


@pytest.mark.parametrize(
    "value", [None, 0, False, "", {"inner": NESTED_SENTINEL}, [NESTED_SENTINEL], b"bytes"]
)
def test_a_credential_key_is_redacted_whatever_its_value_is(value: object) -> None:
    """The value's type does not matter and its subtree is never walked."""
    anonymized = anonymize({"password": value})
    assert anonymized == {"password": REDACTED}
    assert NESTED_SENTINEL not in repr(anonymized)


def test_a_url_value_under_an_ordinary_key_is_still_redacted() -> None:
    anonymized = anonymize({"streamUrl": "rtsp://bob:s3cret@host/++stream"})
    assert "s3cret" not in repr(anonymized)


def test_a_url_embedded_in_free_text_is_redacted_where_it_sits() -> None:
    """Free text is the canonical diagnostics content, and it is where URLs live.

    ``redact_url`` stays anchored -- the matrix rows for a non-URL string and for
    an unparseable one depend on it -- so the embedded pass is additional rather
    than a loosening.
    """
    anonymized = anonymize({"note": "connecting to rtsp://bob:s3cret@host/x now"})

    assert anonymized == {"note": f"connecting to rtsp://{REDACTED}:{REDACTED}@host/x now"}


def test_an_unparseable_url_embedded_in_free_text_fails_closed() -> None:
    anonymized = cast("dict[str, str]", anonymize({"note": "tried http://[::1 and gave up"}))
    assert anonymized["note"] == f"tried {REDACTED} and gave up"


@pytest.mark.parametrize("text", ["Front Gate", "a:b", "", "not a url://at all", "mailto:x@y"])
def test_the_embedded_pass_leaves_ordinary_text_alone(text: str) -> None:
    """The matrix's non-URL row must keep holding once free text is scanned."""
    assert anonymize({"name": text}) == {"name": text}


def test_a_bytes_key_naming_a_credential_still_redacts_its_value() -> None:
    """The key is normalized to a string *before* the predicate runs.

    A key that arrived as ``bytes`` used to render as ``<bytes>``, which matches
    nothing -- so the value beside it was published.
    """
    assert anonymize({b"password": "LEAK"}) == {"password": REDACTED}
    assert anonymize({b"name": "Driveway"}) == {"name": "Driveway"}


def test_a_secret_used_as_a_mapping_key_is_scrubbed_like_any_other_string() -> None:
    """The promise is "every string the walk produces", keys included."""
    assert anonymize({"hunter2": "x"}, secrets=["hunter2"]) == {REDACTED: "x"}


def test_a_bare_string_secret_is_one_secret_not_a_bag_of_characters() -> None:
    """A ``str`` is a valid ``Iterable[str]``, so this is an easy mistake."""
    assert anonymize({"name": "Front Gate"}, secrets="ab") == {"name": "Front Gate"}
    assert anonymize({"name": "Front Gate"}, secrets="Gate") == {"name": f"Front {REDACTED}"}


def test_keys_that_render_the_same_are_disambiguated_rather_than_dropped() -> None:
    """One entry used to vanish with no marker at all."""
    assert anonymize({1: "a", "1": "b"}) == {"1": "a", "1 (2)": "b"}


# --- anonymize: shapes -------------------------------------------------------


class _LegacyBasicAuth(NamedTuple):
    """Same shape as ``aiohttp.BasicAuth``, which this test predates and outlives.

    ``aiohttp.BasicAuth`` is itself deprecated ahead of removal in aiohttp 4.0,
    but the shape it exemplifies -- a credential-bearing ``NamedTuple`` -- is
    what motivates the field-name walk this test protects, and a consumer's own
    older code may still hand ``anonymize()`` one for years yet.
    """

    login: str
    password: str
    encoding: str = "latin1"


def test_a_named_tuple_is_walked_by_field_name_not_positionally() -> None:
    """``BasicAuth`` walked as a sequence would yield ``["bob", "s3cret"]``.

    There would be no key left for the predicate to match the password on,
    which is why ``_fields`` is checked before the sequence branch.
    """
    anonymized = anonymize(_LegacyBasicAuth("bob", "s3cret"))

    assert anonymized == {"login": "bob", "password": REDACTED, "encoding": "latin1"}
    assert "s3cret" not in repr(anonymized)


def test_a_library_model_anonymizes_into_a_readable_mapping() -> None:
    camera = Camera(
        number=CAMERA_NUMBER,
        name="Driveway",
        connected=True,
        enabled=True,
        permissions=5,
        capture_modes=CaptureModes(motion=True),
    )
    anonymized = cast("dict[str, Any]", anonymize(camera))

    assert anonymized["number"] == CAMERA_NUMBER
    assert anonymized["name"] == "Driveway"
    assert anonymized["capture_modes"] == {"continuous": False, "motion": True, "actions": False}


def test_a_camera_settings_model_round_trips_into_a_diagnosable_dict() -> None:
    settings = CameraSettings.from_api(settings_payload(), camera_number=CAMERA_NUMBER)
    anonymized = cast("dict[str, Any]", anonymize(settings))

    # The model never held the credentials in the first place; the anonymizer
    # must not flatten what it *did* keep into an identity `repr` either.
    assert anonymized["camera_number"] == CAMERA_NUMBER
    assert anonymized["name"] == "Driveway"
    assert anonymized["brightness"] == BRIGHTNESS
    assert anonymized["motion_capture_triggers_human"] is True
    assert DEVICE_PASSWORD not in repr(anonymized)


def test_an_opaque_object_becomes_its_type_name_never_its_repr() -> None:
    class Loud:
        def __repr__(self) -> str:
            return f"Loud(password={DEVICE_PASSWORD!r})"

    assert anonymize(Loud()) == "<Loud>"
    assert anonymize(lambda: None) == "<function>"
    assert DEVICE_PASSWORD not in repr(anonymize({"session": Loud()}))


def test_bytes_become_a_length_marker() -> None:
    assert anonymize(b"x" * BYTES_LENGTH) == f"<bytes: {BYTES_LENGTH}>"
    assert anonymize(bytearray(BYTES_LENGTH)) == f"<bytes: {BYTES_LENGTH}>"


def test_a_cast_memoryview_reports_bytes_rather_than_elements() -> None:
    """``len()`` counts elements once a view has been cast."""
    view = memoryview(b"abcdefgh").cast("I")

    assert anonymize(view) == f"<bytes: {CAST_VIEW_BYTES}>"


def test_a_timestamp_a_duration_and_an_error_stay_diagnosable() -> None:
    """``Capture.start`` and ``Capture.duration`` are exactly these types.

    Flattening them to ``<datetime>`` and ``<timedelta>`` makes a capture dump
    safe and useless, which is the pair the module docstring exists to avoid.
    """
    anonymized = anonymize(
        {
            "start": datetime(2026, 8, 9, 17, 53, 35, tzinfo=UTC),
            "duration": timedelta(seconds=30),
            "error": ValueError("connect timed out"),
            "uuid": UUID("12345678-1234-5678-1234-567812345678"),
            "path": PurePosixPath("/Volumes/Captures"),
            "amount": Decimal("1.5"),
            "colour": Colour.AMBER,
        }
    )

    assert anonymized == {
        "start": "2026-08-09 17:53:35+00:00",
        "duration": "0:00:30",
        "error": "ValueError: connect timed out",
        "uuid": "12345678-1234-5678-1234-567812345678",
        "path": "/Volumes/Captures",
        "amount": "1.5",
        "colour": str(Colour.AMBER),
    }


def test_a_rendered_value_goes_through_the_same_string_pipeline() -> None:
    """Rendering must not be a hole in the redaction it bypassed the walk for."""
    anonymized = anonymize(
        {"error": ValueError("failed on rtsp://bob:s3cret@host/x for device-user-77f1")},
        secrets=[DEVICE_USERNAME],
    )

    rendered = repr(anonymized)
    assert "s3cret" not in rendered
    assert DEVICE_USERNAME not in rendered


def test_an_unrecognised_object_still_fails_closed_to_its_type_name() -> None:
    """The rendered set is a closed list; everything outside it keeps the old rule."""

    class Loud:
        def __str__(self) -> str:
            return f"Loud(password={DEVICE_PASSWORD})"

    assert anonymize(Loud()) == "<Loud>"


# --- anonymize: it never raises ----------------------------------------------


def test_a_mapping_that_refuses_to_be_walked_degrades_rather_than_raising() -> None:
    """The spec's Always constraint is fail closed, *no raise*."""
    assert anonymize(ExplodingMapping()) == "<unwalkable ExplodingMapping>"
    assert anonymize({"payload": ExplodingMapping()}) == {
        "payload": "<unwalkable ExplodingMapping>"
    }


def test_a_member_whose_getter_explodes_degrades_rather_than_raising() -> None:
    """A dataclass field can be shadowed by arbitrary code; the walk survives it."""
    assert anonymize(ExplodingDataclass("ok", "x")) == {
        "fine": "ok",
        "boom": "<unwalkable ExplodingDataclass>",
    }


def test_a_container_of_hostile_members_still_returns_a_value() -> None:
    """Whatever else happens, an anonymizer a consumer cannot trust is no anonymizer."""
    payload = {
        "mapping": ExplodingMapping(),
        "model": ExplodingDataclass("ok", "x"),
        "list": [ExplodingMapping()],
        "password": ExplodingDataclass("ok", "x"),
    }

    anonymized = cast("dict[str, Any]", anonymize(payload))

    assert anonymized["password"] == REDACTED
    assert anonymized["list"] == ["<unwalkable ExplodingMapping>"]


def test_containers_and_their_types_survive() -> None:
    anonymized = anonymize({"list": [1, "a"], "tuple": (1, 2), "set": frozenset({1})})

    assert anonymized == {"list": [1, "a"], "tuple": (1, 2), "set": frozenset({1})}


def test_a_set_of_mappings_degrades_to_a_list_rather_than_losing_its_contents() -> None:
    """Redaction can produce unhashable members; the contents matter more.

    A frozen dataclass is hashable, so it is a legal set member -- and it walks
    into a `dict`, which is not.
    """
    anonymized = anonymize({CaptureModes(motion=True)})
    assert anonymized == [{"continuous": False, "motion": True, "actions": False}]


def test_a_non_string_mapping_key_is_rendered_rather_than_dropped() -> None:
    anonymized = anonymize({1: "a", None: "b", (2, 3): "c"})
    assert anonymized == {"1": "a", "None": "b", "<tuple>": "c"}


# --- anonymize: cycles and depth ---------------------------------------------


def test_a_self_referential_structure_terminates() -> None:
    payload: dict[str, object] = {"name": "Driveway"}
    payload["self"] = payload
    payload["nested"] = [payload]

    assert anonymize(payload) == {
        "name": "Driveway",
        "self": "<recursive>",
        "nested": ["<recursive>"],
    }


def test_the_same_object_twice_in_two_branches_is_not_a_cycle() -> None:
    """The guard is path-based: sharing is ordinary, containment is not."""
    shared = {"name": "Driveway"}
    assert anonymize({"a": shared, "b": shared}) == {
        "a": {"name": "Driveway"},
        "b": {"name": "Driveway"},
    }


def test_nesting_past_the_depth_cap_is_marked_rather_than_raising() -> None:
    payload: dict[str, object] = {"password": DEVICE_PASSWORD}
    for _ in range(PAST_THE_DEPTH_CAP):
        payload = {"nested": payload}

    rendered = repr(anonymize(payload))
    assert "<truncated>" in rendered
    assert DEVICE_PASSWORD not in rendered


# --- anonymize: known literal secrets ----------------------------------------


def test_a_known_secret_is_replaced_wherever_it_appears() -> None:
    """Key matching cannot see a value out of context; the consumer can."""
    anonymized = anonymize(
        {"note": f"login failed for {DEVICE_PASSWORD}", "list": [DEVICE_PASSWORD]},
        secrets=[DEVICE_PASSWORD],
    )

    assert DEVICE_PASSWORD not in repr(anonymized)
    assert anonymized == {"note": f"login failed for {REDACTED}", "list": [REDACTED]}


@pytest.mark.parametrize("secret", ["", "   ", None])
def test_a_blank_secret_is_ignored_rather_than_shredding_every_string(secret: str | None) -> None:
    """``str.replace("", ...)`` would rewrite every string it touched."""
    assert anonymize({"name": "Driveway"}, secrets=[secret]) == {"name": "Driveway"}


def test_secrets_may_be_any_iterable_including_a_generator() -> None:
    def known() -> Iterator[str]:
        yield DEVICE_PASSWORD

    assert anonymize({"note": DEVICE_PASSWORD}, secrets=known()) == {"note": REDACTED}


# --- the one declared vocabulary ---------------------------------------------


def test_extending_the_declared_set_extends_both_redactors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC5: adding a key to `CREDENTIAL_KEYS` is the whole change.

    The set is extended at its *declared home*, `aiosecurityspy.const`,
    rather than at the private binding `diagnostics` used to hold -- because a
    `from .const import CREDENTIAL_KEYS` made an addition there invisible, which
    is precisely the extensibility this criterion claims.
    """
    before = anonymize({"pin": "1234"})
    assert before == {"pin": "1234"}
    assert redact_url("http://host/x?pin=1234") == "http://host/x?pin=1234"

    monkeypatch.setattr(const_module, "CREDENTIAL_KEYS", CREDENTIAL_KEYS | {"pin"})

    assert is_credential_key("P-I-N")
    assert anonymize({"pin": "1234", "P-I-N": "1234"}) == {"pin": REDACTED, "P-I-N": REDACTED}
    assert redact_url("http://host/x?pin=1234") == f"http://host/x?pin={REDACTED}"
    assert redact_url("http://host/x#pin=1234") == f"http://host/x#pin={REDACTED}"


# --- the second review pass: shapes that still published a credential ---------


class Numbered(Enum):
    """An ``IntEnum``, which is an ``int`` before it is anything else."""

    ONE = 1


def test_an_exception_argument_is_walked_rather_than_repr_ed() -> None:
    """`str(exc)` on a multi-argument exception is the `repr` of its args.

    `ValueError(BasicAuth(...))` rendered as
    `ValueError: BasicAuth(login='bob', password='s3cret')` -- the module's one
    forbidden call, reached through the back door. Each argument is walked now.
    """
    walked = cast(
        "dict[str, Any]",
        anonymize({"error": ValueError(_LegacyBasicAuth(DEVICE_USERNAME, DEVICE_PASSWORD))}),
    )
    assert DEVICE_PASSWORD not in str(walked)
    assert walked["error"] == {
        "type": "ValueError",
        "args": [{"login": DEVICE_USERNAME, "password": REDACTED, "encoding": "latin1"}],
    }
    # The single-string shape, which is every exception the library itself
    # raises, still renders as the readable one-liner it did before.
    assert anonymize(ValueError("boom")) == "ValueError: boom"
    assert anonymize(ValueError()) == "ValueError"


def test_an_embedded_protocol_relative_reference_is_redacted() -> None:
    """The whole-string redactor accepted `//user:pw@host`; the embedded one did not."""
    assert anonymize({"note": f"see //bob:{DEVICE_PASSWORD}@host/x now"}) == {
        "note": f"see //{REDACTED}:{REDACTED}@host/x now"
    }
    # And the false positive that widening invites stays a false positive.
    for prose in ("// see a@b.com", "// plain comment", "a//b"):
        assert anonymize({"note": prose}) == {"note": prose}


def test_a_url_nested_in_another_urls_parameter_keeps_no_userinfo() -> None:
    """`_redact_query` inspected parameter names only, and the outer match ate the inner URL."""
    redacted = redact_url(f"http://h/x?auth=Ym9i&next=see%20http://u:{DEVICE_PASSWORD}@z/")
    assert DEVICE_PASSWORD not in redacted
    assert redacted == f"http://h/x?auth={REDACTED}&next=see%20http://{REDACTED}:{REDACTED}@z/"


def test_a_path_matrix_parameter_is_redacted_like_a_query_one() -> None:
    """RFC 3986 lets a parameter sit in the path: `/x;auth=s3cret`."""
    assert redact_url(f"http://h/x;auth={DEVICE_PASSWORD};cam=3") == (
        f"http://h/x;auth={REDACTED};cam=3"
    )
    # A `;` in an ordinary path segment names no parameter and is left alone.
    assert redact_url("http://h/a;b/c") == "http://h/a;b/c"


def test_a_username_only_userinfo_does_not_fabricate_a_password() -> None:
    """The same argument the empty-userinfo branch already makes, applied one case over."""
    assert redact_url("http://bob@host/x") == f"http://{REDACTED}@host/x"
    assert redact_url("http://bob:pw@host/x") == f"http://{REDACTED}:{REDACTED}@host/x"


def test_an_int_enum_member_does_not_escape_the_walk_as_a_live_object() -> None:
    """An `IntEnum` is an `int`, so the scalar branch returned it untouched."""
    walked = cast("dict[str, Any]", anonymize({"mode": Numbered.ONE}))
    assert isinstance(walked["mode"], str)
    assert walked["mode"] == str(Numbered.ONE)


def test_a_declared_secret_is_caught_in_a_numeric_value() -> None:
    """Substring replacement only ever sees strings; a PIN arrives as an `int`."""
    assert anonymize({"pin": 1234, "port": 8000}, secrets=["1234"]) == {
        "pin": REDACTED,
        "port": 8000,
    }


def test_the_header_names_the_docstring_advertises_are_in_the_set() -> None:
    """A header mapping is one of the two dump shapes `CREDENTIAL_KEYS` is read for."""
    headers = {
        "Authorization": "Bearer x",
        "Cookie": "session=x",
        "Set-Cookie": "session=x",
        "X-Api-Key": "x",
        "sessionId": "x",
        "passphrase": "x",
        "private_key": "x",
    }
    assert anonymize(headers) == dict.fromkeys(headers, REDACTED)
    # And the lookalikes still survive, because membership is exact.
    assert anonymize({"cookieCount": 3, "authorized": True}) == {
        "cookieCount": 3,
        "authorized": True,
    }


# --- the third review pass: shapes that still published a credential ----------


class CallerCodeError(RuntimeError):
    """What a caller's own generator raising looks like from inside the walk."""


def test_a_url_nested_in_the_path_keeps_no_userinfo() -> None:
    """A redirect or a proxy endpoint carries its target in the path, not the query.

    The query branch already redacted a nested URL. Leaving the path out applied
    half a defence: the outer match consumes the nested URL, so no later pass
    ever looks at it.
    """
    assert redact_url("http://h/proxy/http://bob:s3cret@z/") == (
        f"http://h/proxy/http://{REDACTED}:{REDACTED}@z/"
    )
    assert redact_url("http://h/x;next=http://bob:s3cret@z/") == (
        f"http://h/x;next=http://{REDACTED}:{REDACTED}@z/"
    )
    assert "s3cret" not in repr(anonymize({"u": "http://h/proxy/http://bob:s3cret@z/"}))
    # An ordinary path is still returned byte for byte.
    assert redact_url("http://h/++image?cameraNum=3") == "http://h/++image?cameraNum=3"


def test_a_percent_encoded_nested_url_is_decoded_before_it_is_trusted() -> None:
    """Percent-encoding is the normal way to nest a URL inside a parameter.

    A single ``unquote`` recovers the credential, so scanning only the raw text
    published it to anyone who bothered to decode.
    """
    nested = quote("http://bob:s3cret@z/", safe="")
    redacted = redact_url(f"http://h/x?next={nested}")

    assert "s3cret" not in unquote(redacted)
    assert REDACTED in unquote(redacted)
    # A parameter with no nested credential is not re-encoded: `+` stays `+`.
    assert redact_url("http://h/x?q=a%20b&plain=1+2") == "http://h/x?q=a%20b&plain=1+2"


def test_an_embedded_protocol_relative_reference_matches_the_anchored_rule() -> None:
    """The two passes must agree about what a URL is, or free text is the leaking side.

    The embedded pattern used to require an ``@`` in the authority, so a
    credential carried as a *parameter* of a protocol-relative reference
    survived a walk that the anchored redactor would have caught.
    """
    assert anonymize({"n": "see //host/x?auth=Ym9i now"}) == {
        "n": f"see //host/x?auth={REDACTED} now"
    }


@pytest.mark.parametrize("text", ["// see a@b.com", "a//b and 1//2", "read // then stop"])
def test_widening_the_embedded_pattern_still_leaves_prose_alone(text: str) -> None:
    """The word boundary and the whitespace-free authority are what keep prose prose."""
    assert anonymize({"n": text}) == {"n": text}


def test_a_long_string_is_walked_in_linear_time() -> None:
    """An unbounded scheme made the pattern quadratic, and a dump holds long strings.

    A base64 image or a captured HTML body is an ordinary thing to anonymize; at
    100 KB the walk took twelve seconds, which is an anonymizer failing at the
    one job its module docstring claims it can never fail at.
    """
    started = time.perf_counter()
    anonymize({"blob": "A" * 200_000})

    assert time.perf_counter() - started < LINEAR_WALK_SECONDS


def test_a_declared_secret_never_destroys_a_boolean() -> None:
    """``str(True)`` is ``"True"``, and no credential is the word ``True``.

    A caller that hands its whole config's values over as ``secrets=`` -- a
    plausible reading of the documented usage -- would otherwise silently
    destroy every matching flag in its own dump.
    """
    assert anonymize({"armed": True, "count": 0}, secrets=["True", "None"]) == {
        "armed": True,
        "count": 0,
    }
    # A genuinely numeric secret is still caught.
    assert anonymize({"pin": 1234}, secrets=["1234"]) == {"pin": REDACTED}


def test_a_secrets_generator_that_raises_keeps_what_it_already_yielded() -> None:
    """``secrets=`` is the only thing that catches a credential no key names.

    Failing open here fails open on the last line of defence, so the secrets
    that arrived before the caller's generator exploded must still apply.
    """

    def exploding() -> Iterator[str]:
        yield "hunter2"
        raise CallerCodeError

    assert anonymize({"note": "login failed for hunter2"}, secrets=exploding()) == {
        "note": f"login failed for {REDACTED}"
    }


def test_one_unwalkable_leaf_costs_its_own_entry_and_no_sibling() -> None:
    """A released ``memoryview`` used to collapse the whole dump to one marker."""
    buffer = bytearray(b"abc")
    view = memoryview(buffer)
    view.release()

    assert anonymize({"name": "Driveway", "buf": view}) == {
        "name": "Driveway",
        "buf": "<bytes: unknown>",
    }
