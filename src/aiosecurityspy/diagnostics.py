"""Credential-safe anonymization for a consumer's diagnostics dump.

SecuritySpy hands out credentials in two shapes this library cannot control.
``++settings-cameras`` returns each camera's device ``username`` and
``password`` in plaintext (research §8.3), and a stream URL can carry a
credential in its userinfo -- ``rtsp://user:pass@host/...`` -- which research §7
records being echoed verbatim by an external tool. The library keeps both out of
its own models, logs and URLs; what it cannot do is see the object a consumer is
about to publish as a diagnostics dump. That is what this module is for.

Everything here is pure: no network, no I/O, no logger, no state. It imports the
standard library and :mod:`aiosecurityspy.const` and nothing else -- deliberately
not even ``aiohttp``, so an anonymizer can never be the thing that fails.

There is no dump *builder* here on purpose. The library supplies the anonymizer;
the consumer decides what belongs in its own diagnostics.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Final, cast
from urllib.parse import quote, unquote, urlsplit
from uuid import UUID

from . import const
from .const import REDACTED

__all__ = ["anonymize", "is_credential_key", "redact_url"]

#: How deep :func:`anonymize` walks before it stops and says so. Deep enough for
#: any real payload -- ``++systemInfo`` nests four levels -- and shallow enough
#: that a pathological structure cannot exhaust the interpreter's stack.
_MAX_DEPTH: Final = 12

#: Emitted where the depth cap stops the walk.
_TRUNCATED: Final = "<truncated>"

#: Emitted where an object is already on the path being walked, which is what a
#: structure containing itself looks like from inside the recursion.
_RECURSIVE: Final = "<recursive>"

#: A string is only treated *as a whole* as a URL when it opens with a real
#: scheme followed by ``://``, or with the ``//`` of a protocol-relative
#: reference -- which carries userinfo exactly like an absolute one does. The
#: ``//`` form additionally requires a whitespace-free authority, because a line
#: of prose or a C-style comment opening ``// see a@b.com`` is not a reference
#: and must not be mangled into one. Anchored, so ``"a:b"`` and a camera named
#: ``"Front Gate"`` are left exactly as they are.
_SCHEME_RE: Final = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|//(?=[^\s/?#]*[/?#]|[^\s/?#]+$))")

#: A URL *embedded* in free text, which is the canonical diagnostics shape:
#: ``"connecting to rtsp://bob:s3cret@host/x"``. Runs to the first whitespace or
#: quoting character, because a URL cannot contain one unescaped.
#:
#: The protocol-relative ``//`` form is admitted on exactly the terms
#: :data:`_SCHEME_RE` admits it -- at a word boundary, with a whitespace-free
#: authority -- rather than on the narrower "authority holds an ``@``" rule this
#: pattern used to apply. That narrower rule made the two passes disagree about
#: what a URL is, and free text was the leaking side: ``"see //host/x?auth=Ym9i"``
#: kept its credential because the parameter sat in the query rather than in the
#: userinfo. The word boundary and the whitespace-free authority are what keep a
#: line of prose or a C-style comment opening ``// see a@b.com`` a comment.
#:
#: The scheme is length-bounded. Unbounded, ``[A-Za-z0-9+.-]*`` scans to
#: end-of-string at every starting position before failing to find ``://``,
#: which is quadratic: a 100 KB base64 blob or captured HTML body in a dump --
#: an ordinary thing to anonymize -- took twelve seconds to walk. No registered
#: scheme approaches this length.
_EMBEDDED_URL_RE: Final = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s\"'<>]*"
    r"|(?<!\S)//(?:[^\s/?#\"'<>]*[/?#][^\s\"'<>]*|[^\s/?#\"'<>]+)"
)

#: Query-pair separators, captured so the original text comes back out. ``;`` is
#: the legacy separator; a redactor that only knew ``&`` would hand
#: ``?cameraNum=3;auth=Ym9i`` back with the credential in the clear.
_QUERY_SEPARATOR_RE: Final = re.compile(r"([&;])")


def is_credential_key(key: str) -> bool:
    """Return whether a key names something credential-shaped.

    Every redaction decision in this library routes through this one predicate
    over the one declared set in :data:`aiosecurityspy.const.CREDENTIAL_KEYS`,
    read at call time, so a name added there lands everywhere at once.

    The key is normalized to lowercase with every non-alphanumeric character
    removed and then tested for **exact** membership. Normalizing catches
    ``authToken``, ``auth_token`` and ``AUTH-TOKEN`` without inventing matches;
    exact membership is what keeps ``passwordProtected`` -- a boolean saying
    whether the camera uses authentication at all -- readable.

    Args:
        key: A mapping key, field name or query-parameter name.

    Returns:
        Whether the key is one whose value must be redacted.

    """
    # A public helper over data that comes off the wire, so a non-string degrades
    # rather than raising, exactly like `class_slug`. The cast widens the static
    # type so the runtime check is not eliminated as dead.
    if not isinstance(cast("object", key), str):
        return False
    normalized = "".join(character for character in key.lower() if character.isalnum())
    # Read through the module rather than binding the set at import time: the
    # vocabulary module is the declared place to extend, and a `from ... import`
    # would make an addition there invisible here.
    return normalized in const.CREDENTIAL_KEYS


def redact_url(url: str) -> str:
    """Return ``url`` with its userinfo and credential-shaped parameters removed.

    This is what a consumer must call before a credential-bearing URL reaches a
    log line, a diagnostics dump or a subprocess argument. Research §7 records
    exactly that leak happening: an ``rtsp://user:pass@host/...`` URL echoed
    verbatim by an external tool.

    Everything that makes the URL diagnosable survives: the scheme -- in its
    original case -- the host, port, path and every non-credential query or
    fragment parameter are returned untouched, byte for byte. The URL is taken
    apart by string surgery rather than round-tripped through
    :func:`~urllib.parse.urlunsplit`, which is what makes that claim true.

    A credential-shaped parameter is redacted in the fragment as well as the
    query: ``#auth=s3cret`` is a credential wherever it sits.

    Args:
        url: A URL, or any string. A string that does not open with a scheme
            and ``://``, or with a protocol-relative ``//``, is not a URL and is
            returned unchanged.

    Returns:
        The redacted URL, the original string when it is not a URL, or
        :data:`~aiosecurityspy.REDACTED` when it claims to be a URL but cannot
        be parsed -- an unparseable credential-bearing string is exactly the one
        that must not be published on a guess.

    """
    # Fail closed on a non-string: something handed a URL redactor a value that
    # is not a URL, and returning it unchanged would publish whatever it is.
    if not isinstance(cast("object", url), str):
        return REDACTED
    opening = _SCHEME_RE.match(url)
    if opening is None:
        return url
    try:
        urlsplit(url)
    except ValueError:
        # A malformed IPv6 literal, an unparseable port. It opens with a scheme,
        # so it is a URL that failed to parse rather than ordinary text.
        return REDACTED
    start = opening.end()
    authority, remainder = _split_authority(url[start:])
    # The fragment is whatever follows the first `#`, query delimiters included;
    # the query is whatever follows the first `?` before it.
    before_fragment, hash_mark, fragment = remainder.partition("#")
    path, question_mark, query = before_fragment.partition("?")
    return "".join(
        (
            url[:start],
            _redact_userinfo(authority),
            _redact_path(path),
            f"{question_mark}{_redact_query(query)}" if question_mark else "",
            f"{hash_mark}{_redact_query(fragment)}" if hash_mark else "",
        )
    )


def _split_authority(rest: str) -> tuple[str, str]:
    """Split the text after ``scheme://`` into its authority and everything else."""
    end = len(rest)
    for delimiter in "/?#":
        found = rest.find(delimiter)
        if found != -1:
            end = min(end, found)
    return rest[:end], rest[end:]


def _redact_userinfo(authority: str) -> str:
    """Replace a non-empty userinfo, leaving the host and port exactly as they are."""
    # `rpartition`, not `partition`: the userinfo itself may contain an `@`, and
    # the last one is the delimiter RFC 3986 recognises.
    userinfo, separator, host = authority.rpartition("@")
    if not separator or not userinfo:
        # `http://@host/` carries no credential. Redacting it would tell the
        # reader one had been there, which is a fabricated fact.
        return authority
    # Same argument one line down: `http://bob@host/` carries a username and no
    # password, so emitting `**REDACTED**:**REDACTED**` would invent a password
    # that was never in the string. The colon is replayed only if it arrived.
    _, colon, _ = userinfo.partition(":")
    return f"{REDACTED}{f':{REDACTED}' if colon else ''}@{host}"


def _redact_query(query: str) -> str:
    """Replace the value of every credential-shaped query or fragment parameter.

    The pairs are split by hand rather than round-tripped through
    :func:`~urllib.parse.parse_qsl` and :func:`~urllib.parse.urlencode`, so an
    untouched parameter comes back exactly as it went in: a re-encode would
    rewrite ``+`` as ``%20`` and turn a valueless flag into ``flag=``, which is a
    changed URL reported as an unchanged one. The separators are captured and
    replayed for the same reason.
    """
    if not query:
        return query
    pieces = _QUERY_SEPARATOR_RE.split(query)
    for index, piece in enumerate(pieces):
        if index % 2:
            # A captured separator, replayed as it arrived.
            continue
        key, separator, _ = piece.partition("=")
        # The name is unquoted before the test but the original text is what goes
        # back out, so `auth%54oken=x` cannot slip past the predicate.
        if separator and is_credential_key(unquote(key)):
            pieces[index] = f"{key}={REDACTED}"
        else:
            pieces[index] = _redact_parameter_value(piece)
    return "".join(pieces)


def _redact_nested_urls(text: str) -> str:
    """Redact every URL *embedded* in a longer string, leaving the rest alone."""
    return _EMBEDDED_URL_RE.sub(lambda found: redact_url(found.group()), text)


def _redact_parameter_value(pair: str) -> str:
    """Redact a URL nested inside a non-credential parameter's value.

    A callback or a ``next=`` target carries its own userinfo, and the outer pass
    consumed this whole string as one match, so nothing else will look at it.
    Only the parameter *name* is tested by the caller; the value needs its own
    look.

    The value is also examined percent-decoded, because percent-encoding is the
    normal way to nest a URL inside a parameter and a single ``unquote`` recovers
    the credential from it. Re-encoding happens only when the decoded form
    actually held one, so a parameter this function did not change comes back
    byte for byte as it went in.
    """
    redacted = _redact_nested_urls(pair)
    if redacted != pair:
        return redacted
    key, separator, value = pair.partition("=")
    if not separator or "%" not in value:
        return pair
    decoded = unquote(value)
    decoded_redacted = _redact_nested_urls(decoded)
    if decoded_redacted == decoded:
        return pair
    return f"{key}={quote(decoded_redacted, safe='')}"


def _redact_path(path: str) -> str:
    """Replace the value of every credential-shaped RFC 3986 path matrix parameter.

    ``http://host/x;auth=s3cret`` parks a credential in the path rather than the
    query. The first segment is the path proper; each ``;`` segment after it is a
    parameter and goes through the same redactor the query does, so there is one
    answer to "what is a credential-shaped parameter".

    A whole URL nested in the path -- ``http://host/proxy/http://u:pw@z/``, the
    shape a redirect or a proxy endpoint takes -- is redacted here too. The query
    branch already did this; leaving the path out applied half a defence, since
    the outer match consumes the nested URL and no later pass sees it.
    """
    if ";" not in path:
        return _redact_nested_urls(path)
    segments = path.split(";")
    segments[0] = _redact_nested_urls(segments[0])
    for index, segment in enumerate(segments[1:], start=1):
        key, separator, _ = segment.partition("=")
        if separator and is_credential_key(unquote(key)):
            segments[index] = f"{key}={REDACTED}"
        else:
            segments[index] = _redact_parameter_value(segment)
    return ";".join(segments)


def anonymize(value: object, *, secrets: str | Iterable[str | None] = ()) -> object:
    """Return a credential-free copy of an arbitrary structure.

    Point this at anything a consumer is about to publish -- a settings dict, a
    config entry, a library model, a list of URLs. The structure survives:
    mappings stay mappings, keys stay keys, lists and tuples keep their order and
    their container type, and every non-credential value is returned unchanged,
    because a dump that redaction flattened would be safe and useless. A sequence
    that is neither a list nor a tuple -- a :class:`~collections.deque`, a
    :class:`range` -- is not walked; like any other unrecognised shape it fails
    closed to its bare type name.

    What is credential-shaped is decided by :func:`is_credential_key` alone. The
    walk is fail-closed on shapes it does not recognise: an object that is not a
    mapping, a :class:`~typing.NamedTuple`, a dataclass, a sequence, a string, a
    bytes-like, a scalar or one of the small set of renderable standard-library
    values becomes its bare type name, never its ``repr`` -- which is the whole
    reason ``aiohttp.BasicAuth`` is walked by ``_fields`` rather than as the
    two-element tuple it also is.

    A timestamp, duration, :class:`~decimal.Decimal`, :class:`~uuid.UUID`,
    :class:`~pathlib.PurePath`, :class:`~enum.Enum` or exception renders through
    ``str()`` and then through the same redaction the walk applies to any other
    string, because ``<datetime>`` in place of a capture's start time is safe and
    useless in equal measure.

    It never raises. A container that refuses to be walked, or a member whose
    getter explodes, degrades to ``<unwalkable TypeName>`` -- an anonymizer that
    can fail is one a consumer cannot put in an exception handler.

    Args:
        value: Anything at all.
        secrets: Literal secret strings the caller already knows -- its own
            configured password, for instance. Every occurrence of each is
            replaced inside every string the walk produces, keys included, which
            is the only thing that catches a credential embedded in a free-text
            field where no key names it. A bare :class:`str` is taken as one
            secret rather than as the iterable of characters it also is. Blank
            and non-string entries are ignored: ``str.replace("", ...)`` would
            shred every string it touched.

    Returns:
        A new structure of plain containers, strings, scalars and markers. The
        input is never mutated.

    """
    try:
        return _walk(value, _usable_secrets(secrets), 0, frozenset())
    except Exception:  # noqa: BLE001 - the walk guards every branch already; this is the backstop that makes "never raises" true rather than nearly true
        return _unwalkable(value)


def _usable_secrets(secrets: str | Iterable[str | None]) -> tuple[str, ...]:
    """Drop the blank and non-string entries a caller's config may hand over."""
    # A `str` satisfies `Iterable[str]`, so `secrets="ab"` would otherwise be two
    # one-character secrets and shred every string the walk produced.
    candidates: Iterable[str | None] = (
        (cast("str", secrets),) if isinstance(cast("object", secrets), str) else secrets
    )
    # Collected as they arrive rather than in one comprehension: a caller's
    # generator that yields two secrets and then raises must not cost the walk
    # the two it already handed over. `secrets=` is the only mechanism that
    # catches a credential no key names, so failing open here fails open on the
    # last line of defence.
    usable: list[str] = []
    try:
        for secret in candidates:
            if isinstance(secret, str) and secret.strip():
                usable.append(secret)  # noqa: PERF401 - the loop is the point: `extend` over a generator loses everything yielded before it raises
    except Exception:  # noqa: BLE001 - a caller's generator is caller code; it must not take the anonymizer down, and there is no logger here to log it to
        return tuple(usable)
    return tuple(usable)


def _scrub(text: str, secrets: tuple[str, ...]) -> str:
    """Replace every known literal secret inside one produced string."""
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


def _string(text: str, secrets: tuple[str, ...]) -> str:
    """Push one produced string through the whole redaction pipeline.

    Every string the walk emits -- a value, a mapping key, a rendered timestamp
    or exception -- goes through here, so there is one answer to "what happens to
    a string" rather than one per site.
    """
    # `redact_url` first, anchored, so a string that *is* a URL keeps its
    # whole-string behaviour including the unparseable-fails-closed rule; then
    # every embedded occurrence, because free text is where the leak lives.
    return _scrub(_redact_nested_urls(redact_url(text)), secrets)


def _unwalkable(value: object) -> str:
    """Name the shape that refused to be walked, without touching its ``repr``."""
    return f"<unwalkable {type(value).__name__}>"


def _key(key: object) -> str:
    """Render a mapping key, which is not always a string on the wire.

    The rendering happens *before* the credential test, so a ``bytes`` key
    naming a credential still redacts its value instead of publishing it under
    a ``<bytes>`` marker.
    """
    if isinstance(key, str):
        return key
    if isinstance(key, bytes | bytearray | memoryview):
        try:
            return bytes(key).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - a released buffer or an exotic memoryview; the type name is still true
            return f"<{type(key).__name__}>"
    if key is None or isinstance(key, bool | int | float):
        return str(key)
    # Same rule as a value: a type name, never a repr.
    return f"<{type(key).__name__}>"


def _unique(name: str, taken: Mapping[str, object]) -> str:
    """Disambiguate a rendered key that has already been used.

    ``{1: "a", "1": "b"}`` renders both keys as ``"1"``; a plain assignment would
    drop one entry with no marker at all. A ``CIMultiDict`` makes a repeated key
    an ordinary shape rather than a curiosity.
    """
    if name not in taken:
        return name
    ordinal = 2
    while f"{name} ({ordinal})" in taken:
        ordinal += 1
    return f"{name} ({ordinal})"


def _named_tuple_fields(value: object) -> tuple[str, ...] | None:
    """Return a ``NamedTuple``'s field names, or ``None`` if it is not one.

    Checked *before* the sequence branch, and that ordering is the point:
    ``aiohttp.BasicAuth("bob", "s3cret")`` walked as a sequence yields
    ``["bob", "s3cret"]`` with no key left to match the password on.
    """
    if not isinstance(value, tuple):
        return None
    try:
        fields = getattr(value, "_fields", None)
    except Exception:  # noqa: BLE001 - `_fields` may be a property on a hostile subclass
        return None
    if isinstance(fields, tuple) and all(isinstance(name, str) for name in fields):
        return cast("tuple[str, ...]", fields)
    return None


def _rendered_scalar(value: object) -> str | None:
    """Render the standard-library values worth keeping, or ``None`` for anything else.

    ``Capture.start`` is a :class:`~datetime.datetime` and ``Capture.duration`` a
    :class:`~datetime.timedelta`, so flattening these to ``<datetime>`` would
    cost a capture dump the very timestamps it is read for. The result still goes
    through the string pipeline, so a URL or a known secret inside one of them is
    redacted like any other string.
    """
    if isinstance(value, datetime | date | time | timedelta | Decimal | UUID | PurePath | Enum):
        try:
            text = str(value)
        except Exception:  # noqa: BLE001 - ditto; fall back to the bare type name
            return None
        return text
    return None


def _walk(  # noqa: PLR0911, PLR0912 - one branch per recognised shape, in an order the Enum, NamedTuple and scalar cases each depend on; merging any two would hide it
    value: object, secrets: tuple[str, ...], depth: int, seen: frozenset[int]
) -> object:
    """Anonymize one node, then its children."""
    if depth > _MAX_DEPTH:
        return _TRUNCATED
    # Before the scalar branch, not after it: an `IntEnum` member *is* an `int`,
    # so testing scalars first returned the live enum object rather than a
    # rendered string -- handing the consumer's serializer exactly the arbitrary
    # `__str__` this walk exists to avoid calling.
    if isinstance(value, Enum):
        return _string(_rendered_scalar(value) or f"<{type(value).__name__}>", secrets)
    if isinstance(value, BaseException):
        return _walk_exception(value, secrets, depth, seen)
    # Scalars: the common case, and they cannot hold a child.
    if value is None or isinstance(value, bool | int | float | complex):
        # A secret the caller declared may have arrived as a number -- a PIN, a
        # numeric passcode. Matching the rendered form is the only way to catch
        # it, since substring replacement only ever sees strings.
        #
        # `bool` and `None` are excluded: `str(True)` is `"True"`, and a caller
        # that hands its whole config's values over as `secrets=` -- a plausible
        # reading of the documented usage -- would otherwise silently destroy
        # every matching flag in the dump. No credential is the word `True`.
        if secrets and not isinstance(value, bool) and value is not None:
            return REDACTED if _renders_to_a_secret(value, secrets) else value
        return value
    if isinstance(value, str):
        return _string(value, secrets)
    if isinstance(value, bytes | bytearray | memoryview):
        # Length only. The bytes could be anything, including a credential, and
        # nothing about a diagnostics dump is improved by decoding them. `nbytes`
        # where it exists: `len()` on a cast memoryview counts elements, so
        # `memoryview(b"abcdefgh").cast("I")` would otherwise report two bytes.
        try:
            size = getattr(value, "nbytes", None)
            return f"<bytes: {size if isinstance(size, int) else len(value)}>"
        except Exception:  # noqa: BLE001 - `len()` on a released memoryview raises; a length is not worth a lost dump
            return "<bytes: unknown>"
    # Identity-based and path-based: the same object appearing twice in two
    # sibling branches is fine and is walked twice; an object that contains
    # itself is what this stops.
    if id(value) in seen:
        return _RECURSIVE
    seen = seen | {id(value)}
    fields = _named_tuple_fields(value)
    if fields is not None:
        return {name: _member(value, name, secrets, depth, seen) for name in fields}
    if isinstance(value, Mapping):
        return _walk_mapping(value, secrets, depth, seen)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _walk_dataclass(value, secrets, depth, seen)
    if isinstance(value, list | tuple):
        return _walk_sequence(value, secrets, depth, seen)
    if isinstance(value, set | frozenset):
        return _walk_set(value, secrets, depth, seen)
    rendered = _rendered_scalar(value)
    if rendered is not None:
        return _string(rendered, secrets)
    # Fail closed. A `repr` here is one `BasicAuth` away from printing a
    # password, and this branch is precisely the shape nothing understands.
    return f"<{type(value).__name__}>"


def _renders_to_a_secret(value: object, secrets: tuple[str, ...]) -> bool:
    """Return whether a non-string scalar renders to exactly a declared secret."""
    try:
        return str(value) in secrets
    except Exception:  # noqa: BLE001 - `__str__` on a scalar subclass is still arbitrary code
        return False


def _walk_exception(
    value: BaseException, secrets: tuple[str, ...], depth: int, seen: frozenset[int]
) -> object:
    """Render an exception without letting ``str()`` reach its arguments' ``repr``.

    ``str(exc)`` on a single-argument exception *is* that argument, but on any
    other shape it is the ``repr`` of the argument tuple -- so
    ``ValueError(BasicAuth("bob", "s3cret"))`` rendered as
    ``ValueError: BasicAuth(login='bob', password='s3cret')``, publishing the
    password through the one call the rest of this module refuses to make. Each
    argument is walked instead, so a credential-bearing argument is redacted by
    the same rules that would have applied to it anywhere else.
    """
    try:
        arguments = tuple(value.args)
    except Exception:  # noqa: BLE001 - `args` may be overridden with anything
        return f"<unwalkable {type(value).__name__}>"
    walked = [_walk(argument, secrets, depth + 1, seen) for argument in arguments]
    if len(walked) == 1 and isinstance(walked[0], str):
        # The overwhelmingly common shape, and the one whose `str()` is exact.
        return _string(f"{type(value).__name__}: {walked[0]}", secrets)
    if not walked:
        return f"{type(value).__name__}"
    return {"type": type(value).__name__, "args": walked}


def _walk_mapping(
    value: Mapping[object, object], secrets: tuple[str, ...], depth: int, seen: frozenset[int]
) -> object:
    """Anonymize a mapping, key by key."""
    try:
        items = list(value.items())
    except Exception:  # noqa: BLE001 - a lazy or proxying mapping may refuse; the type name is still diagnostic
        return _unwalkable(value)
    walked: dict[str, object] = {}
    for key, item in items:
        # Render first, test second: `b"password"` names a credential just as
        # much as `"password"` does.
        name = _key(key)
        try:
            entry = (
                REDACTED
                if is_credential_key(name)
                # The subtree under a credential key is deliberately not walked:
                # whatever shape the value has, all of it is the credential.
                else _walk(item, secrets, depth + 1, seen)
            )
        except Exception:  # noqa: BLE001 - one hostile leaf must cost its own entry, not every sibling key in the dump
            entry = _unwalkable(item)
        walked[_unique(_string(name, secrets), walked)] = entry
    return walked


def _walk_dataclass(
    value: object, secrets: tuple[str, ...], depth: int, seen: frozenset[int]
) -> object:
    """Anonymize a dataclass instance by field name."""
    try:
        fields = dataclasses.fields(value)  # type: ignore[arg-type]  # guarded by `is_dataclass` at the call site
    except Exception:  # noqa: BLE001 - a rewritten `__dataclass_fields__` is arbitrary data
        return _unwalkable(value)
    return {field.name: _member(value, field.name, secrets, depth, seen) for field in fields}


def _walk_sequence(
    value: list[object] | tuple[object, ...],
    secrets: tuple[str, ...],
    depth: int,
    seen: frozenset[int],
) -> object:
    """Anonymize a list or tuple, keeping its order and its container type."""
    try:
        items = [_walk(item, secrets, depth + 1, seen) for item in value]
    except Exception:  # noqa: BLE001 - a subclass may override `__iter__` with anything
        return _unwalkable(value)
    return tuple(items) if isinstance(value, tuple) else items


def _walk_set(
    value: set[object] | frozenset[object],
    secrets: tuple[str, ...],
    depth: int,
    seen: frozenset[int],
) -> object:
    """Anonymize a set, degrading to a list when redaction makes it unhashable."""
    try:
        items = [_walk(item, secrets, depth + 1, seen) for item in value]
    except Exception:  # noqa: BLE001 - a member whose `__hash__` explodes must not take the walk down
        return _unwalkable(value)
    try:
        return frozenset(items) if isinstance(value, frozenset) else set(items)
    except Exception:  # noqa: BLE001 - unhashable after redaction, most often; a list keeps the contents either way
        # Redacting a set of mappings produces unhashable members. A list
        # keeps the contents; insisting on the container type would lose them.
        return items


def _member(
    owner: object, name: str, secrets: tuple[str, ...], depth: int, seen: frozenset[int]
) -> object:
    """Anonymize one named member of a ``NamedTuple`` or dataclass."""
    if is_credential_key(name):
        # The attribute is not even read: a property could compute anything.
        return REDACTED
    try:
        member = getattr(owner, name, None)
    except Exception:  # noqa: BLE001 - a property getter is arbitrary code and this walk must survive it
        return _unwalkable(owner)
    return _walk(member, secrets, depth + 1, seen)
