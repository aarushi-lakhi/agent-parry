"""Unicode and encoding normalization applied before pattern matching.

Detection regexes run on raw input today, so ``ignore all previous instructions``
is bypassed by a zero-width space, a fullwidth spelling, a Cyrillic homoglyph, or
any of base64 / hex / percent encoding. This module produces normalized *views* of
a string. Each view carries an offset map back to the original so a finding can
still quote and redact real input.

Views are cheap when nothing needs normalizing: every transform has an identity
fast path, and :meth:`Normalizer.views` drops views whose text is byte-identical
to a higher-priority view, so clean ASCII input yields exactly one view and one
regex pass per pattern.

No gzip, zlib, or deflate decoding lives here. Decompression is where ratio bombs
live and it needs its own expansion-ratio guard, so it is deliberately out of
scope; a compressed payload simply never becomes a view.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

MAX_INPUT_CHARS = 1_000_000
MAX_DECODE_DEPTH = 3
MAX_FRAGMENTS_PER_STRING = 32
MAX_DECODED_BYTES_PER_FRAGMENT = 16_000
MAX_DECODED_BYTES_TOTAL = 64_000

MIN_BASE64_FRAGMENT = 16
MIN_HEX_FRAGMENT = 32
MIN_OPAQUE_BLOB = 40

VIEW_ORIGINAL = "original"
VIEW_CANONICAL = "canonical"

_VIEW_PRIORITY = {VIEW_ORIGINAL: 0, VIEW_CANONICAL: 1}


def view_priority(name: str) -> int:
    """Rank a view name for dedupe: original beats canonical beats decoded."""
    return _VIEW_PRIORITY.get(name, 2)


_INVISIBLE_CLASS = (
    "\u00ad"  # SOFT HYPHEN
    "\u034f"  # COMBINING GRAPHEME JOINER
    "\u0600-\u0605"  # ARABIC NUMBER SIGN .. ARABIC NUMBER MARK ABOVE
    "\u061c"  # ARABIC LETTER MARK
    "\u06dd"  # ARABIC END OF AYAH
    "\u070f"  # SYRIAC ABBREVIATION MARK
    "\u0890-\u0891"  # ARABIC POUND MARK ABOVE .. ARABIC PIASTRE MARK ABOVE
    "\u08e2"  # ARABIC DISPUTED END OF AYAH
    "\u180e"  # MONGOLIAN VOWEL SEPARATOR
    "\u200b-\u200f"  # ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
    "\u202a-\u202e"  # LEFT-TO-RIGHT EMBEDDING .. RIGHT-TO-LEFT OVERRIDE
    "\u2060-\u2064"  # WORD JOINER .. INVISIBLE PLUS
    "\u2066-\u206f"  # LEFT-TO-RIGHT ISOLATE .. NOMINAL DIGIT SHAPES
    "\ufeff"  # ZERO WIDTH NO-BREAK SPACE
    "\ufff9-\ufffb"  # INTERLINEAR ANNOTATION ANCHOR .. INTERLINEAR ANNOTATION TERMINATOR
    "\U000110bd"  # KAITHI NUMBER SIGN
    "\U000110cd"  # KAITHI NUMBER SIGN ABOVE
    "\U00013430-\U00013438"  # EGYPTIAN HIEROGLYPH VERTICAL JOINER .. EGYPTIAN HIEROGLYPH END SEGMENT
    "\U0001bca0-\U0001bca3"  # SHORTHAND FORMAT LETTER OVERLAP .. SHORTHAND FORMAT UP STEP
    "\U0001d173-\U0001d17a"  # MUSICAL SYMBOL BEGIN BEAM .. MUSICAL SYMBOL END PHRASE
    "\U000e0001"  # LANGUAGE TAG
    "\U000e0020-\U000e007f"  # TAG SPACE .. CANCEL TAG
)
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE_CLASS}]")

_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # CYRILLIC SMALL LETTER A
    "\u0435": "e",  # CYRILLIC SMALL LETTER IE
    "\u043e": "o",  # CYRILLIC SMALL LETTER O
    "\u0440": "p",  # CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # CYRILLIC SMALL LETTER ES
    "\u0443": "y",  # CYRILLIC SMALL LETTER U
    "\u0445": "x",  # CYRILLIC SMALL LETTER HA
    "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0458": "j",  # CYRILLIC SMALL LETTER JE
    "\u0455": "s",  # CYRILLIC SMALL LETTER DZE
    "\u051b": "q",  # CYRILLIC SMALL LETTER QA
    "\u04bb": "h",  # CYRILLIC SMALL LETTER SHHA
    "\u0501": "d",  # CYRILLIC SMALL LETTER KOMI DE
    "\u051d": "w",  # CYRILLIC SMALL LETTER WE
    "\u04cf": "l",  # CYRILLIC SMALL LETTER PALOCHKA
    "\u043d": "h",  # CYRILLIC SMALL LETTER EN
    "\u0442": "t",  # CYRILLIC SMALL LETTER TE
    "\u043a": "k",  # CYRILLIC SMALL LETTER KA
    "\u043c": "m",  # CYRILLIC SMALL LETTER EM
    "\u0432": "b",  # CYRILLIC SMALL LETTER VE
    # Cyrillic uppercase
    "\u0410": "A",  # CYRILLIC CAPITAL LETTER A
    "\u0412": "B",  # CYRILLIC CAPITAL LETTER VE
    "\u0415": "E",  # CYRILLIC CAPITAL LETTER IE
    "\u041a": "K",  # CYRILLIC CAPITAL LETTER KA
    "\u041c": "M",  # CYRILLIC CAPITAL LETTER EM
    "\u041d": "H",  # CYRILLIC CAPITAL LETTER EN
    "\u041e": "O",  # CYRILLIC CAPITAL LETTER O
    "\u0420": "P",  # CYRILLIC CAPITAL LETTER ER
    "\u0421": "C",  # CYRILLIC CAPITAL LETTER ES
    "\u0422": "T",  # CYRILLIC CAPITAL LETTER TE
    "\u0425": "X",  # CYRILLIC CAPITAL LETTER HA
    "\u0423": "Y",  # CYRILLIC CAPITAL LETTER U
    "\u0405": "S",  # CYRILLIC CAPITAL LETTER DZE
    "\u0406": "I",  # CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0408": "J",  # CYRILLIC CAPITAL LETTER JE
    "\u051a": "Q",  # CYRILLIC CAPITAL LETTER QA
    "\u051c": "W",  # CYRILLIC CAPITAL LETTER WE
    # Greek lowercase
    "\u03b1": "a",  # GREEK SMALL LETTER ALPHA
    "\u03b5": "e",  # GREEK SMALL LETTER EPSILON
    "\u03b9": "i",  # GREEK SMALL LETTER IOTA
    "\u03ba": "k",  # GREEK SMALL LETTER KAPPA
    "\u03bd": "v",  # GREEK SMALL LETTER NU
    "\u03bf": "o",  # GREEK SMALL LETTER OMICRON
    "\u03c1": "p",  # GREEK SMALL LETTER RHO
    "\u03c4": "t",  # GREEK SMALL LETTER TAU
    "\u03c5": "u",  # GREEK SMALL LETTER UPSILON
    "\u03c7": "x",  # GREEK SMALL LETTER CHI
    # Greek uppercase
    "\u0391": "A",  # GREEK CAPITAL LETTER ALPHA
    "\u0392": "B",  # GREEK CAPITAL LETTER BETA
    "\u0395": "E",  # GREEK CAPITAL LETTER EPSILON
    "\u0396": "Z",  # GREEK CAPITAL LETTER ZETA
    "\u0397": "H",  # GREEK CAPITAL LETTER ETA
    "\u0399": "I",  # GREEK CAPITAL LETTER IOTA
    "\u039a": "K",  # GREEK CAPITAL LETTER KAPPA
    "\u039c": "M",  # GREEK CAPITAL LETTER MU
    "\u039d": "N",  # GREEK CAPITAL LETTER NU
    "\u039f": "O",  # GREEK CAPITAL LETTER OMICRON
    "\u03a1": "P",  # GREEK CAPITAL LETTER RHO
    "\u03a4": "T",  # GREEK CAPITAL LETTER TAU
    "\u03a5": "Y",  # GREEK CAPITAL LETTER UPSILON
    "\u03a7": "X",  # GREEK CAPITAL LETTER CHI
    # Armenian
    "\u0585": "o",  # ARMENIAN SMALL LETTER OH
    "\u0578": "n",  # ARMENIAN SMALL LETTER VO
    "\u057d": "s",  # ARMENIAN SMALL LETTER SEH
    "\u0561": "w",  # ARMENIAN SMALL LETTER AYB
    "\u0566": "q",  # ARMENIAN SMALL LETTER ZA
    "\u0570": "h",  # ARMENIAN SMALL LETTER HO
    "\u0563": "g",  # ARMENIAN SMALL LETTER GIM
    "\u0584": "p",  # ARMENIAN SMALL LETTER KEH
    # Latin forms NFKC leaves alone
    "\u0131": "i",  # LATIN SMALL LETTER DOTLESS I
    "\u0269": "i",  # LATIN SMALL LETTER IOTA
    "\u0251": "a",  # LATIN SMALL LETTER ALPHA
    "\u0261": "g",  # LATIN SMALL LETTER SCRIPT G
    "\u0237": "j",  # LATIN SMALL LETTER DOTLESS J
}

_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)
_CONFUSABLE_CLASS = "".join(re.escape(char) for char in sorted(_CONFUSABLES))
_CONFUSABLE_CHAR_RE = re.compile(f"[{_CONFUSABLE_CLASS}]")
_MIXED_TOKEN_RE = re.compile(rf"\b(?=\w*[{_CONFUSABLE_CLASS}])(?=\w*[A-Za-z])\w+")

_HORIZONTAL_WS_RE = re.compile(r"[^\S\n\r]+")

_NON_SPACE_HWS: tuple[str, ...] = (
    "\t",
    "\v",
    "\f",
    "\u00a0",  # NO-BREAK SPACE
    "\u1680",  # OGHAM SPACE MARK
    "\u202f",  # NARROW NO-BREAK SPACE
    "\u205f",  # MEDIUM MATHEMATICAL SPACE
    "\u3000",  # IDEOGRAPHIC SPACE
    *(chr(code) for code in range(0x2000, 0x200B)),  # EN QUAD .. HAIR SPACE
)

_ASCII_LETTER_RE = re.compile(r"[A-Za-z]")

_BASE64_RUN_RE = re.compile(
    rf"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{{{MIN_BASE64_FRAGMENT},}}={{0,2}}(?![A-Za-z0-9+/=])"
)
_HEX_RUN_RE = re.compile(rf"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{{2}}){{{MIN_HEX_FRAGMENT // 2},}}(?![0-9A-Za-z])")
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_ONLY_RE = re.compile(r"\A[0-9A-Fa-f]+\Z")


class _LostOffsets(list):  # type: ignore[type-arg]
    """Sentinel offsets meaning the span map was dropped for this transform."""


_LOST = _LostOffsets()

Offsets = list[int] | None
"""Per-character map from view index to index in the transform input.

``None`` means the identity map, so an unchanged transform costs nothing.
"""


@dataclass(frozen=True, slots=True)
class TextView:
    """One normalized view of a string plus the map back to the original."""

    name: str
    text: str
    offsets: tuple[int, ...] | None = None
    source_span: tuple[int, int] | None = None
    depth: int = 0
    original_length: int = 0
    mappable: bool = True

    def map_span(self, start: int, end: int) -> tuple[int, int] | None:
        """Translate a half-open span in this view to a span in the original.

        Returns ``None`` when no span can be reported, which callers must treat
        as "redact the whole value" rather than "redact nothing".

        Decoded views map to the whole encoded fragment, because a byte offset
        inside decoded plaintext has no meaningful character offset inside the
        base64 that carried it.
        """
        if self.source_span is not None:
            return self.source_span
        if not self.mappable:
            return None
        if start < 0 or end <= start:
            return None
        if self.offsets is None:
            return (start, end)
        if end > len(self.offsets):
            return None
        origin_start = self.offsets[start]
        origin_end = self.offsets[end] if end < len(self.offsets) else self.original_length
        return (origin_start, max(origin_end, origin_start + 1))


class NormalizerSettings(BaseModel):
    """Which normalized views to build and the budgets that bound the work."""

    canonical: bool = True
    decoded: bool = False
    strip_invisible: bool = True
    nfkc: bool = True
    fold_homoglyphs: bool = True
    collapse_whitespace: bool = True
    max_input_chars: int = Field(default=MAX_INPUT_CHARS, gt=0)
    max_decode_depth: int = Field(default=MAX_DECODE_DEPTH, ge=0)
    max_fragments: int = Field(default=MAX_FRAGMENTS_PER_STRING, ge=0)
    max_decoded_bytes_per_fragment: int = Field(default=MAX_DECODED_BYTES_PER_FRAGMENT, gt=0)
    max_decoded_bytes_total: int = Field(default=MAX_DECODED_BYTES_TOTAL, ge=0)


def strip_invisible(text: str) -> tuple[str, Offsets]:
    """Drop format characters and the combining grapheme joiner.

    Mandatory and separate from NFKC: NFKC preserves U+200B, U+200C, U+200D,
    U+2060, U+FEFF, U+00AD and U+202E, so a zero-width space between letters
    survives NFKC and defeats every word-based pattern.
    """
    if text.isascii():
        return text, None
    matches = list(_INVISIBLE_RE.finditer(text))
    if not matches:
        return text, None

    parts: list[str] = []
    offsets: list[int] = []
    position = 0
    for match in matches:
        parts.append(text[position : match.start()])
        offsets.extend(range(position, match.start()))
        position = match.end()
    parts.append(text[position:])
    offsets.extend(range(position, len(text)))
    return "".join(parts), offsets


def nfkc_fold(text: str) -> tuple[str, Offsets]:
    """Apply NFKC compatibility folding, mapping fullwidth and ligature forms.

    The whole-string result is always the text that gets matched. The offset map
    is built by normalizing one combining cluster at a time, because a per-
    character map disagrees with whole-string NFKC for any decomposed accent:
    NFKC of ``e`` then ``U+0301`` separately is two characters, while NFKC of the
    pair is the single character ``e-acute``.

    Composition can still cross a cluster boundary, conjoining Hangul jamo being
    the case that matters. When the reconstructed text disagrees with whole-string
    NFKC the map is dropped rather than trusted, so span reporting degrades to the
    whole value while matching is unaffected.
    """
    if unicodedata.is_normalized("NFKC", text):
        return text, None

    folded = unicodedata.normalize("NFKC", text)
    parts: list[str] = []
    offsets: list[int] = []
    for start, cluster in _combining_clusters(text):
        piece = unicodedata.normalize("NFKC", cluster)
        parts.append(piece)
        offsets.extend([start] * len(piece))
    if "".join(parts) != folded:
        logger.debug("NFKC cluster map disagreed with whole-string NFKC; dropping span map")
        return folded, _LOST
    return folded, offsets


def _combining_clusters(text: str) -> list[tuple[int, str]]:
    """Split text into (start index, base character plus its combining marks)."""
    clusters: list[tuple[int, str]] = []
    start = 0
    for index in range(1, len(text)):
        if unicodedata.combining(text[index]) == 0:
            clusters.append((start, text[start:index]))
            start = index
    if text:
        clusters.append((start, text[start:]))
    return clusters


def fold_homoglyphs(text: str) -> tuple[str, Offsets]:
    """Fold confusables to ASCII inside mixed-script word tokens only.

    Scoped deliberately. Folding every confusable everywhere would turn Cyrillic
    or Greek prose into Latin gibberish and flood detection with nonsense; a
    token that mixes an ASCII letter with a Cyrillic lookalike is the spoofing
    signal worth acting on.
    """
    if text.isascii():
        return text, None
    if not _CONFUSABLE_CHAR_RE.search(text) or not _ASCII_LETTER_RE.search(text):
        return text, None
    if not _MIXED_TOKEN_RE.search(text):
        return text, None
    folded = _MIXED_TOKEN_RE.sub(lambda match: match.group(0).translate(_CONFUSABLE_TABLE), text)
    # Every mapping is 1:1, so length and character positions are preserved.
    return folded, None


def _needs_collapse(text: str) -> bool:
    """Cheap gate for collapse_whitespace.

    ``str.__contains__`` uses a fast substring search, so a handful of these
    beats one regex pass over the same string by roughly 20x. Ordinary prose
    with single spaces never reaches the regex at all.
    """
    if "  " in text:
        return True
    return any(char in text for char in _NON_SPACE_HWS)


def collapse_whitespace(text: str) -> tuple[str, Offsets]:
    """Collapse runs of horizontal whitespace to a single space, keeping newlines."""
    if not _needs_collapse(text):
        return text, None
    matches = [match for match in _HORIZONTAL_WS_RE.finditer(text) if match.group(0) != " "]
    if not matches:
        return text, None

    parts: list[str] = []
    offsets: list[int] = []
    position = 0
    for match in matches:
        parts.append(text[position : match.start()])
        offsets.extend(range(position, match.start()))
        parts.append(" ")
        offsets.append(match.start())
        position = match.end()
    parts.append(text[position:])
    offsets.extend(range(position, len(text)))
    return "".join(parts), offsets


def _compose(outer: Offsets, inner: Offsets) -> Offsets:
    """Chain a view->intermediate map with an intermediate->original map."""
    if outer is _LOST or inner is _LOST:
        return _LOST
    if outer is None:
        return inner
    if inner is None:
        return outer
    return [inner[index] for index in outer]


def iter_base64_runs(text: str, min_length: int = MIN_BASE64_FRAGMENT) -> list[re.Match[str]]:
    """Return base64-alphabet runs of at least ``min_length`` characters."""
    return [match for match in _BASE64_RUN_RE.finditer(text) if len(match.group(0)) >= min_length]


def decode_base64_fragment(fragment: str, max_bytes: int = MAX_DECODED_BYTES_PER_FRAGMENT) -> str | None:
    """Decode one base64 run to text, or None when it is not printable UTF-8.

    Missing padding is tolerated because unpadded base64 is the norm in the wild
    (JWT segments, for one) and an attacker would otherwise just drop the ``=``.
    A remainder of 1 cannot come from any byte string, so it is rejected.
    """
    if len(fragment) > max_bytes * 2:
        return None
    padded = fragment
    remainder = len(padded) % 4
    if remainder == 1:
        return None
    if remainder:
        padded += "=" * (4 - remainder)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable_text(raw, max_bytes)


def is_opaque_blob(fragment: str) -> bool:
    """Report whether a run looks like encoded bytes that carry no readable text.

    Requires mixed case plus a digit or base64 punctuation, which is what base64
    of random bytes looks like in practice. Pure-hex and single-case runs are
    excluded so a sha1 digest, a sha256 digest, a git SHA, or a camelCase
    identifier does not become a finding; a hex-shaped payload that really does
    carry text is caught by the hex decoder and the primary signal instead.
    """
    if len(fragment) < MIN_OPAQUE_BLOB:
        return False
    if _HEX_ONLY_RE.match(fragment):
        return False
    body = fragment.rstrip("=")
    has_lower = any(char.islower() for char in body)
    has_upper = any(char.isupper() for char in body)
    has_other = any(char.isdigit() or char in "+/" for char in body)
    if not (has_lower and has_upper and has_other):
        return False
    return decode_base64_fragment(fragment) is None


def _printable_text(raw: bytes, max_bytes: int) -> str | None:
    if not raw or len(raw) > max_bytes:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for char in decoded if char.isprintable() or char in "\t\n\r")
    if printable != len(decoded):
        return None
    return decoded


@dataclass(slots=True)
class _DecodeBudget:
    """Mutable per-string budget shared across every depth of the decode tree."""

    fragments_left: int
    bytes_left: int

    def take(self, size: int) -> bool:
        if self.fragments_left <= 0 or size > self.bytes_left:
            return False
        self.fragments_left -= 1
        self.bytes_left -= size
        return True


class Normalizer:
    """Builds normalized views of a string for pattern matching."""

    def __init__(self, settings: NormalizerSettings | None = None) -> None:
        self._settings = settings or NormalizerSettings()

    @property
    def settings(self) -> NormalizerSettings:
        """Return the settings this normalizer was built with."""
        return self._settings

    def views(self, text: str) -> list[TextView]:
        """Return the original view plus every enabled normalized view.

        Views whose text is identical to a higher-priority view are dropped, so
        already-canonical input costs one regex pass per pattern rather than
        several.
        """
        original = TextView(name=VIEW_ORIGINAL, text=text, original_length=len(text))
        if len(text) > self._settings.max_input_chars:
            logger.warning(
                "Input exceeds normalization budget, using original view only chars=%s limit=%s",
                len(text),
                self._settings.max_input_chars,
            )
            return [original]

        candidates = [original]
        if self._settings.canonical:
            candidates.append(self.canonical(text))
        candidates.extend(self.decoded_views(text))

        seen: set[str] = set()
        deduped: list[TextView] = []
        for view in candidates:
            if view.text in seen:
                continue
            seen.add(view.text)
            deduped.append(view)
        return deduped

    def canonical(self, text: str) -> TextView:
        """Return the canonical view: invisibles stripped, NFKC folded, homoglyphs folded."""
        current = text
        offsets: Offsets = None
        for enabled, transform in (
            (self._settings.strip_invisible, strip_invisible),
            (self._settings.nfkc, nfkc_fold),
            (self._settings.fold_homoglyphs, fold_homoglyphs),
            (self._settings.collapse_whitespace, collapse_whitespace),
        ):
            if not enabled:
                continue
            current, step_offsets = transform(current)
            offsets = _compose(step_offsets, offsets)

        if offsets is _LOST:
            return TextView(
                name=VIEW_CANONICAL,
                text=current,
                original_length=len(text),
                mappable=False,
            )
        return TextView(
            name=VIEW_CANONICAL,
            text=current,
            offsets=None if offsets is None else tuple(offsets),
            original_length=len(text),
        )

    def decoded_views(self, text: str) -> list[TextView]:
        """Return views for base64, hex, and percent-encoded fragments that decode to text."""
        if not self._settings.decoded or self._settings.max_decode_depth < 1:
            return []
        budget = _DecodeBudget(
            fragments_left=self._settings.max_fragments,
            bytes_left=self._settings.max_decoded_bytes_total,
        )
        views: list[TextView] = []
        self._decode_level(text, depth=1, source_span=None, budget=budget, views=views)
        return views

    def _decode_level(
        self,
        text: str,
        *,
        depth: int,
        source_span: tuple[int, int] | None,
        budget: _DecodeBudget,
        views: list[TextView],
    ) -> None:
        if depth > self._settings.max_decode_depth:
            return
        for span, kind, decoded in self._decode_fragments(text, budget):
            outer_span = source_span if source_span is not None else span
            views.append(
                TextView(
                    name=f"decoded:{kind}",
                    text=decoded,
                    source_span=outer_span,
                    depth=depth,
                )
            )
            self._decode_level(decoded, depth=depth + 1, source_span=outer_span, budget=budget, views=views)

    def _decode_fragments(
        self,
        text: str,
        budget: _DecodeBudget,
    ) -> list[tuple[tuple[int, int], str, str]]:
        found: list[tuple[tuple[int, int], str, str]] = []
        per_fragment = self._settings.max_decoded_bytes_per_fragment

        for match in iter_base64_runs(text):
            decoded = decode_base64_fragment(match.group(0), per_fragment)
            if decoded is None or not budget.take(len(decoded.encode("utf-8"))):
                continue
            found.append((match.span(), "base64", decoded))

        for match in _HEX_RUN_RE.finditer(text):
            try:
                raw = bytes.fromhex(match.group(0))
            except ValueError:
                continue
            decoded = _printable_text(raw, per_fragment)
            if decoded is None or not budget.take(len(raw)):
                continue
            found.append((match.span(), "hex", decoded))

        if _PERCENT_RE.search(text):
            try:
                decoded = unquote(text, errors="strict")
            except UnicodeDecodeError:
                decoded = text
            if decoded != text and budget.take(len(decoded.encode("utf-8"))):
                found.append(((0, len(text)), "percent", decoded))

        return found


def detection_normalizer() -> Normalizer:
    """Normalizer for detect-only callers: canonical and decoded views both on.

    Right default for the inspectors, which report findings and never decide on
    their own to block, so surfacing an injection hidden inside base64 costs
    nothing but a few extra regex passes.
    """
    return Normalizer(NormalizerSettings(canonical=True, decoded=True))


def raw_only_normalizer() -> Normalizer:
    """Normalizer that produces the original view and nothing else."""
    return Normalizer(NormalizerSettings(canonical=False, decoded=False))


__all__ = [
    "MAX_DECODED_BYTES_PER_FRAGMENT",
    "MAX_DECODED_BYTES_TOTAL",
    "MAX_DECODE_DEPTH",
    "MAX_FRAGMENTS_PER_STRING",
    "MAX_INPUT_CHARS",
    "MIN_BASE64_FRAGMENT",
    "MIN_HEX_FRAGMENT",
    "MIN_OPAQUE_BLOB",
    "VIEW_CANONICAL",
    "VIEW_ORIGINAL",
    "Normalizer",
    "NormalizerSettings",
    "TextView",
    "collapse_whitespace",
    "decode_base64_fragment",
    "detection_normalizer",
    "fold_homoglyphs",
    "is_opaque_blob",
    "iter_base64_runs",
    "nfkc_fold",
    "raw_only_normalizer",
    "strip_invisible",
    "view_priority",
]
