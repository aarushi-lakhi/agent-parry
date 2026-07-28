"""Cross-call taint tracking: remember sensitive values seen in tool results.

Every other detector in this codebase judges one message in isolation, so none
can see a two-call exfiltration: read a secret with ``file_read``, send it with
``email_send``. Neither call is suspicious on its own and the signal is only in
the relationship between them.

:class:`TaintTracker` keeps the small amount of cross-call state that makes the
flow visible. It stores keyed digests of sensitive-looking values found in tool
results and screens later tool arguments against them. Plaintext is never
retained; the hash key is per process and never written to disk.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import math
import os
import re
import secrets
import time
import unicodedata
from collections import Counter, OrderedDict
from collections.abc import Iterator
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.inspector import AGENTPARRY_KEY
from src.models import Finding
from src.normalize import fold_homoglyphs

logger = logging.getLogger(__name__)

SHINGLE_LEN = 12
MIN_NORMALIZED_LEN = 8
MIN_HEURISTIC_LEN = 16
MIN_ENTROPY_BITS = 3.0
MIN_CHARSET_CLASSES = 3
MIN_SHINGLE_HITS = 3

MAX_CANDIDATES_PER_SESSION = 256
MAX_SHINGLES_PER_CANDIDATE = 32
MAX_CLIENT_ORIGIN_PER_SESSION = 256
MAX_SESSIONS = 16
CANDIDATE_TTL_SECONDS = 3600.0
MAX_SCAN_CHARS = 65536

DIGEST_BYTES = 16
REDACTION_MARKER = "[REDACTED-TAINT]"
DEFAULT_SESSION_KEY = "-"

TAINT_BLOCK_MESSAGE = "Blocked: a value from an earlier tool result reached this argument"

EGRESS_TOOL_HINTS = (
    "send",
    "email",
    "mail",
    "post",
    "http",
    "fetch",
    "request",
    "upload",
    "publish",
    "webhook",
    "slack",
    "message",
    "tweet",
    "shell",
    "exec",
    "commit",
    "push",
    "dns",
    "curl",
)

_SEED_PATTERNS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), True),
    ("credit_card", re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), True),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    (
        "api_key",
        re.compile(r"(?:sk-|pk_|sk_live_|sk_test_|ghp_|github_pat_|xox[baprs]-)[A-Za-z0-9_-]{6,}"),
        True,
    ),
    ("url_credentials", re.compile(r"://[^:/\s]+:([^@/\s]{8,})@"), True),
    (
        "secret_assignment",
        re.compile(
            r"(?:api[_-]?key|secret[_\w]*|token|access[_-]?key|private[_-]?key|password|passwd|pwd)"
            r"\s*[=:]\s*[\"']?([^\s\"',;]{8,})",
            re.IGNORECASE,
        ),
        False,
    ),
    ("high_entropy_token", re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b"), False),
)

_STRUCTURED = frozenset(kind for kind, _pattern, structured in _SEED_PATTERNS if structured)


class TaintMode(str, Enum):
    """What the proxy does when a tainted value reaches a tool argument."""

    OFF = "off"
    FLAG = "flag"
    REDACT = "redact"
    BLOCK = "block"


class TaintSettings(BaseModel):
    """The ``settings.taint_tracking`` block of a policy file."""

    enabled: bool = False
    action: Literal["off", "flag", "redact", "block"] = "flag"
    exempt_tools: list[str] = Field(default_factory=list)
    max_candidates: int = Field(default=MAX_CANDIDATES_PER_SESSION, gt=0)
    max_sessions: int = Field(default=MAX_SESSIONS, gt=0)
    ttl_seconds: float = Field(default=CANDIDATE_TTL_SECONDS, gt=0)

    @property
    def mode(self) -> TaintMode:
        """The effective mode, folding ``enabled: false`` into ``off``."""
        return TaintMode(self.action) if self.enabled else TaintMode.OFF


def env_mode_override(raw: str | None = None) -> TaintMode | None:
    """Read ``AGENTPARRY_TAINT``, returning None when it is unset or unparseable."""
    source = os.environ.get("AGENTPARRY_TAINT", "") if raw is None else raw
    cleaned = source.strip().lower()
    if not cleaned:
        return None
    try:
        return TaintMode(cleaned)
    except ValueError:
        logger.warning("Ignoring unrecognized AGENTPARRY_TAINT value %r", source)
        return None


class TaintMatch(BaseModel):
    """One tainted value found in an outgoing tool argument."""

    model_config = ConfigDict(extra="forbid")

    field: str
    kind: str
    confidence: Literal["exact", "partial"]
    source_tool: str
    shingle_hits: int = 0
    span: tuple[int, int] | None = None


class TaintCheck(BaseModel):
    """Result of screening one tool call's arguments against the taint set."""

    model_config = ConfigDict(extra="forbid")

    arguments: dict[str, Any] = Field(default_factory=dict)
    matches: list[TaintMatch] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    action: Literal["none", "flag", "redact", "block"] = "none"
    blocked: bool = False
    redacted: bool = False
    block_message: str = TAINT_BLOCK_MESSAGE

    @property
    def hit(self) -> bool:
        """True when at least one tainted value reached these arguments."""
        return bool(self.matches)

    @property
    def detail(self) -> str:
        """One-line description of the hit that quotes no value."""
        if not self.matches:
            return ""
        kinds = sorted({match.kind for match in self.matches})
        sources = sorted({match.source_tool for match in self.matches})
        confidences = sorted({match.confidence for match in self.matches})
        return (
            f"{self.action}: {len(self.matches)} tainted value(s) "
            f"kinds={','.join(kinds)} from={','.join(sources)} match={','.join(confidences)}"
        )


def normalize(text: str) -> str:
    """Fold a value to its comparison form: NFKC, homoglyphs, casefold, alphanumerics.

    Space insertion, quoting, line wrapping, case flips, dash/underscore swaps
    and confusable substitution all collapse to the same string, so evading an
    exact match has to change the value itself.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded, _offsets = fold_homoglyphs(folded)
    return re.sub(r"[^0-9a-z]", "", folded.casefold())


def entropy_bits_per_char(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    total = len(text)
    counts = Counter(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def charset_classes(text: str) -> int:
    """How many of lowercase, uppercase and digit appear in the raw value."""
    return sum(
        (
            any(c.islower() for c in text),
            any(c.isupper() for c in text),
            any(c.isdigit() for c in text),
        )
    )


def is_egress_tool(tool_name: str) -> bool:
    """Heuristic: does this tool name look like it moves data off the machine?"""
    lowered = tool_name.casefold()
    return any(hint in lowered for hint in EGRESS_TOOL_HINTS)


def extract_candidates(text: str) -> list[tuple[str, str, int, int]]:
    """Return ``(kind, value, start, end)`` for every sensitive-looking span."""
    found: list[tuple[str, str, int, int]] = []
    for kind, pattern, _structured in _SEED_PATTERNS:
        for match in pattern.finditer(text):
            group = 1 if pattern.groups else 0
            value = match.group(group)
            if not value:
                continue
            start, end = match.span(group)
            found.append((kind, value, start, end))
    return found


def seedable_candidates(text: str) -> list[tuple[str, str, int, int]]:
    """Return the seedable candidates in ``text``, dropping enclosing spans.

    ``high_entropy_token`` matches ``API_KEY=sk-...`` as one run, which is the
    same secret plus its label. Keeping both would store two digests for one
    value, and the wider one defeats client-origin suppression: the narrow
    digest is exempt while the wide one still shingle-matches it.
    """
    found = [
        (kind, value, start, end)
        for kind, value, start, end in extract_candidates(text)
        if _seedable(kind, value, normalize(value))
    ]
    spans = [(start, end) for _kind, _value, start, end in found]
    return [
        candidate
        for candidate, (start, end) in zip(found, spans, strict=True)
        if not any(
            inner_start >= start and inner_end <= end and (inner_end - inner_start) < (end - start)
            for inner_start, inner_end in spans
        )
    ]


def iter_strings(value: Any, path: str = "arguments") -> Iterator[tuple[str, str]]:
    """Yield ``(field_path, string)`` for every nested string in a JSON-like value."""
    if isinstance(value, dict):
        for key, nested in value.items():
            yield from iter_strings(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, nested in enumerate(value):
            yield from iter_strings(nested, f"{path}[{idx}]")
    elif isinstance(value, str):
        yield path, value


def _seedable(kind: str, raw: str, normalized: str) -> bool:
    if len(normalized) < MIN_NORMALIZED_LEN:
        return False
    if kind in _STRUCTURED:
        return True
    if len(normalized) < MIN_HEURISTIC_LEN or entropy_bits_per_char(normalized) < MIN_ENTROPY_BITS:
        return False
    return charset_classes(raw) >= MIN_CHARSET_CLASSES


def _shingleable(normalized: str) -> bool:
    return len(normalized) >= SHINGLE_LEN and entropy_bits_per_char(normalized) >= MIN_ENTROPY_BITS


def _shingles(normalized: str) -> list[str]:
    if len(normalized) < SHINGLE_LEN:
        return []
    return [normalized[i : i + SHINGLE_LEN] for i in range(len(normalized) - SHINGLE_LEN + 1)]


def _stride_sample(items: list[str], limit: int) -> list[str]:
    if len(items) <= limit:
        return items
    step = len(items) / limit
    return [items[int(i * step)] for i in range(limit)]


def _redact_string(text: str, spans: list[tuple[int, int]]) -> str:
    out = text
    for start, end in sorted(spans, reverse=True):
        out = out[:start] + REDACTION_MARKER + out[end:]
    return out


def _apply_redactions(value: Any, spans: dict[str, list[tuple[int, int]]], path: str = "arguments") -> Any:
    if isinstance(value, dict):
        return {key: _apply_redactions(nested, spans, f"{path}.{key}") for key, nested in value.items()}
    if isinstance(value, list):
        return [_apply_redactions(nested, spans, f"{path}[{idx}]") for idx, nested in enumerate(value)]
    if isinstance(value, str) and path in spans:
        return _redact_string(value, spans[path])
    return value


def annotate_result(result: dict[str, Any], check: TaintCheck) -> dict[str, Any]:
    """Record on the result what taint tracking did to the outgoing arguments.

    The scanner reads this marker the same way it reads the result-injection and
    terminal-escape ones. Only an action the client can feel is annotated, so a
    ``flag`` hit leaves the payload byte-identical.
    """
    if not check.redacted:
        return result
    payload = copy.deepcopy(result)
    existing = payload.get(AGENTPARRY_KEY)
    meta = dict(existing) if isinstance(existing, dict) else {}
    meta["taint"] = {
        "action": check.action,
        "matches": len(check.matches),
        "kinds": sorted({match.kind for match in check.matches}),
    }
    payload[AGENTPARRY_KEY] = meta
    return payload


class _Candidate:
    """One remembered sensitive value, stored only as keyed digests."""

    __slots__ = ("kind", "shingles", "source_tool", "stored_at")

    def __init__(
        self, *, kind: str, source_tool: str, shingles: frozenset[str], stored_at: float
    ) -> None:
        self.kind = kind
        self.source_tool = source_tool
        self.shingles = shingles
        self.stored_at = stored_at


class _Session:
    """Per-session taint state: what was seen in results, and what the client already had."""

    def __init__(self) -> None:
        self.candidates: OrderedDict[str, _Candidate] = OrderedDict()
        self.client_origin: OrderedDict[str, float] = OrderedDict()


class TaintTracker:
    """Remember digests of sensitive values from tool results, screen later arguments.

    Values are keyed-hashed with a per-process random key, so the tracker cannot
    answer "what secrets have you seen" and its digests are useless in any other
    process. That protects a crash dump or a leaked stats endpoint, not an
    attacker who can read this process's memory.
    """

    def __init__(self, settings: TaintSettings | None = None) -> None:
        self._key = secrets.token_bytes(32)
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._settings = settings or TaintSettings()
        self._exempt = set(self._settings.exempt_tools)

    @classmethod
    def from_policy_settings(cls, settings: Any, **kwargs: Any) -> TaintTracker:
        """Build from the ``settings.taint_tracking`` block of a policy file."""
        return cls(settings=parse_settings(settings), **kwargs)

    @property
    def settings(self) -> TaintSettings:
        """Return the settings this tracker is running with."""
        return self._settings

    @property
    def mode(self) -> TaintMode:
        """Effective mode, with ``AGENTPARRY_TAINT`` overriding the policy file."""
        override = env_mode_override()
        return override if override is not None else self._settings.mode

    def reconfigure(self, settings: TaintSettings) -> None:
        """Adopt new settings without dropping state or rotating the hash key.

        A policy reload must not silently empty the taint set: a detector that
        quietly stops detecting is worse than one that is plainly off.
        """
        self._settings = settings
        self._exempt = set(settings.exempt_tools)

    def digest(self, text: str) -> str:
        """Keyed digest of an already-normalized string."""
        return hashlib.blake2b(text.encode("utf-8"), key=self._key, digest_size=DIGEST_BYTES).hexdigest()

    def reset(self) -> None:
        """Drop all state and rotate the hashing key."""
        self._key = secrets.token_bytes(32)
        self._sessions.clear()

    def candidate_count(self, session_id: str | None = None) -> int:
        """Number of remembered candidates in one session."""
        session = self._sessions.get(self._key_for(session_id))
        return 0 if session is None else len(session.candidates)

    def session_count(self) -> int:
        """Number of live sessions."""
        return len(self._sessions)

    @staticmethod
    def _key_for(session_id: str | None) -> str:
        return session_id or DEFAULT_SESSION_KEY

    def _session(self, session_id: str | None) -> _Session:
        key = self._key_for(session_id)
        session = self._sessions.get(key)
        if session is None:
            session = _Session()
            self._sessions[key] = session
            while len(self._sessions) > self._settings.max_sessions:
                self._sessions.popitem(last=False)
        else:
            self._sessions.move_to_end(key)
        return session

    def _expire(self, session: _Session, now: float) -> None:
        ttl = self._settings.ttl_seconds
        for digest, candidate in list(session.candidates.items()):
            if now - candidate.stored_at > ttl:
                del session.candidates[digest]
        for digest, stored_at in list(session.client_origin.items()):
            if now - stored_at > ttl:
                del session.client_origin[digest]

    def observe_result(
        self,
        tool_name: str,
        result: Any,
        *,
        session_id: str | None = None,
        request_arguments: Any = None,
    ) -> int:
        """Seed taint from a tool result, returning how many new candidates were stored.

        Call this with the pre-redaction result. A value the client provably
        never saw is exactly the one worth remembering: its later appearance in
        an argument means it arrived through a channel the proxy does not
        mediate.
        """
        if self.mode is TaintMode.OFF:
            return 0
        now = time.monotonic()
        session = self._session(session_id)
        self._expire(session, now)
        if request_arguments is not None:
            self._mark_client_origin(session, request_arguments, now)

        stored = 0
        for _field, text in iter_strings(result, path="result"):
            for kind, value, _start, _end in seedable_candidates(text[:MAX_SCAN_CHARS]):
                normalized = normalize(value)
                digest = self.digest(normalized)
                if digest in session.client_origin:
                    continue
                if digest in session.candidates:
                    session.candidates.move_to_end(digest)
                    continue
                session.candidates[digest] = _Candidate(
                    kind=kind,
                    source_tool=tool_name,
                    shingles=self._shingle_set(normalized),
                    stored_at=now,
                )
                stored += 1
                while len(session.candidates) > self._settings.max_candidates:
                    session.candidates.popitem(last=False)
        return stored

    def _shingle_set(self, normalized: str) -> frozenset[str]:
        if not _shingleable(normalized):
            return frozenset()
        sampled = _stride_sample(_shingles(normalized), MAX_SHINGLES_PER_CANDIDATE)
        return frozenset(self.digest(piece) for piece in sampled)

    def _remember_client_origin(self, session: _Session, digest: str, now: float) -> None:
        session.client_origin[digest] = now
        while len(session.client_origin) > MAX_CLIENT_ORIGIN_PER_SESSION:
            session.client_origin.popitem(last=False)

    def _mark_client_origin(self, session: _Session, arguments: Any, now: float) -> None:
        for _field, text in iter_strings(arguments):
            for _kind, value, _start, _end in seedable_candidates(text[:MAX_SCAN_CHARS]):
                digest = self.digest(normalize(value))
                if digest in session.candidates:
                    continue
                self._remember_client_origin(session, digest, now)

    def check_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        session_id: str | None = None,
    ) -> TaintCheck:
        """Screen outgoing arguments against remembered results.

        Any sensitive-looking argument value that is *not* already tainted is
        recorded as client-originated and can never seed later, which is the one
        mechanism that suppresses both the echo and the pre-possession false
        positive.
        """
        mode = self.mode
        if mode is TaintMode.OFF or tool_name in self._exempt:
            return TaintCheck(arguments=arguments)

        now = time.monotonic()
        session = self._session(session_id)
        self._expire(session, now)

        matches: list[TaintMatch] = []
        spans: dict[str, list[tuple[int, int]]] = {}
        for field, text in iter_strings(arguments):
            clipped = text[:MAX_SCAN_CHARS]
            for _kind, value, start, end in seedable_candidates(clipped):
                digest = self.digest(normalize(value))
                candidate = session.candidates.get(digest)
                if candidate is None:
                    self._remember_client_origin(session, digest, now)
                    continue
                matches.append(
                    TaintMatch(
                        field=field,
                        kind=candidate.kind,
                        confidence="exact",
                        source_tool=candidate.source_tool,
                        span=(start, end),
                    )
                )
                spans.setdefault(field, []).append((start, end))
            matches.extend(self._partial_matches(session, field, clipped, exact_fields=spans))

        if not matches:
            return TaintCheck(arguments=arguments)
        return self._decide(tool_name, arguments, matches, spans, mode)

    def _decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        matches: list[TaintMatch],
        spans: dict[str, list[tuple[int, int]]],
        mode: TaintMode,
    ) -> TaintCheck:
        findings = [self._finding(tool_name, match) for match in matches]
        if mode is TaintMode.BLOCK:
            return TaintCheck(
                arguments=arguments,
                matches=matches,
                findings=findings,
                action="block",
                blocked=True,
            )
        if mode is TaintMode.REDACT and spans:
            return TaintCheck(
                arguments=_apply_redactions(arguments, spans),
                matches=matches,
                findings=findings,
                action="redact",
                redacted=True,
            )
        return TaintCheck(arguments=arguments, matches=matches, findings=findings, action="flag")

    def _partial_matches(
        self,
        session: _Session,
        field: str,
        text: str,
        *,
        exact_fields: dict[str, list[tuple[int, int]]],
    ) -> list[TaintMatch]:
        if field in exact_fields:
            return []
        observed = {self.digest(piece) for piece in _shingles(normalize(text))}
        if not observed:
            return []
        found: list[TaintMatch] = []
        for candidate in session.candidates.values():
            if not candidate.shingles:
                continue
            hits = len(candidate.shingles & observed)
            if hits >= min(MIN_SHINGLE_HITS, len(candidate.shingles)):
                found.append(
                    TaintMatch(
                        field=field,
                        kind=candidate.kind,
                        confidence="partial",
                        source_tool=candidate.source_tool,
                        shingle_hits=hits,
                    )
                )
        return found

    @staticmethod
    def _finding(tool_name: str, match: TaintMatch) -> Finding:
        egress = is_egress_tool(tool_name)
        if match.confidence == "exact":
            severity = "high" if egress else "medium"
        else:
            severity = "medium" if egress else "low"
        shape = "verbatim" if match.confidence == "exact" else f"reformatted, {match.shingle_hits} shingles"
        return Finding(
            severity=severity,  # type: ignore[arg-type]
            description=(
                f"Tainted {match.kind} from {match.source_tool} result "
                f"reached {tool_name} argument ({shape})"
            ),
            field=match.field,
            matched_pattern=f"taint:{match.kind}",
        )


def taint_requested(settings: Any) -> bool:
    """True when policy or environment asks for taint tracking to be on.

    The stdio proxy uses this to say plainly that it does not implement the
    feature, rather than leaving an operator who enabled it to conclude from
    silence that nothing suspicious happened.
    """
    override = env_mode_override()
    if override is not None:
        return override is not TaintMode.OFF
    return parse_settings(settings).mode is not TaintMode.OFF


def parse_settings(settings: Any) -> TaintSettings:
    """Read the ``settings.taint_tracking`` block, falling back to defaults."""
    raw = settings.get("taint_tracking") if isinstance(settings, dict) else None
    if not isinstance(raw, dict):
        return TaintSettings()
    overrides = {key: value for key, value in raw.items() if key in TaintSettings.model_fields}
    try:
        return TaintSettings(**overrides)
    except ValidationError:
        logger.exception("Invalid settings.taint_tracking block, using defaults")
        return TaintSettings()


__all__ = [
    "CANDIDATE_TTL_SECONDS",
    "MAX_CANDIDATES_PER_SESSION",
    "MAX_CLIENT_ORIGIN_PER_SESSION",
    "MAX_SESSIONS",
    "MAX_SHINGLES_PER_CANDIDATE",
    "MIN_CHARSET_CLASSES",
    "MIN_SHINGLE_HITS",
    "REDACTION_MARKER",
    "SHINGLE_LEN",
    "TAINT_BLOCK_MESSAGE",
    "TaintCheck",
    "TaintMatch",
    "TaintMode",
    "TaintSettings",
    "TaintTracker",
    "annotate_result",
    "charset_classes",
    "entropy_bits_per_char",
    "env_mode_override",
    "extract_candidates",
    "is_egress_tool",
    "iter_strings",
    "normalize",
    "parse_settings",
    "seedable_candidates",
    "taint_requested",
]
