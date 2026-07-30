"""Over-block analysis for policy files: static regex checks plus empirical evaluation.

Two independent halves, both offline.

Static analysis walks each rule pattern's parse tree (`re._parser`, a private
stdlib API, used because a hand-rolled regex tokenizer would be more code and
less accurate) and reports structural shapes that over-block: unanchored short
literals, generic character classes with a low repetition floor, patterns that
match the empty string, long `.*` bridges, patterns that cannot match the
payload they were generated from, and ReDoS-shaped nesting.

Empirical analysis evaluates every rule, one rule at a time, through a real
`PolicyEngine`, against the benign payloads in the payload file, and reports the
matched span of every benign block. A corpus-free fallback mutates each pattern
into plausible-benign strings (an ordinary reference number, a keyword embedded
in a longer word, a keyword quoted inside prose) so the empirical half still
says something when a payload file carries no benign entries.

Both halves run under the policy's own ``settings.normalization`` block and its
per-rule ``normalize:`` overrides, so a rule that only matches in the canonical
or decoded view is reported with that view rather than read as unmatched.
"""

from __future__ import annotations

import re
import re._parser as regex_parser
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from src.models import Finding, PolicyAction
from src.normalize import VIEW_CANONICAL, VIEW_ORIGINAL
from src.policy import PolicyEngine, ViewFlags

SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
_SEV_ORDER = {SEV_HIGH: 0, SEV_MEDIUM: 1, SEV_LOW: 2}

MAXREPEAT = regex_parser.MAXREPEAT

VIEW_DECODED = "decoded"
_INHERITED_VIEWS: ViewFlags = (True, False)

SCOPE_RULE = "rule"
SCOPE_SETTINGS = "settings"

_METADATA_SEVERITY_ORDER = ("medium", "high", "critical")
_MUTATING_METADATA_ACTIONS = frozenset({"redact", "drop", "block"})

_LARGE_CLASS = 36
_FLOOR_MIN = 8
_FLOOR_MAX = 64
_FLOOR_HIGH = 48
_SHORT_LITERAL = 4
_BRIDGE_WORD = 4
_ALT_CAP = 8
_DEPTH_CAP = 6
_PROBES_PER_PATTERN = 2

_CATEGORY_SIZES = {
    "CATEGORY_DIGIT": 10,
    "CATEGORY_NOT_DIGIT": 118,
    "CATEGORY_SPACE": 6,
    "CATEGORY_NOT_SPACE": 122,
    "CATEGORY_WORD": 63,
    "CATEGORY_NOT_WORD": 65,
}

_COMMAND_FIELD_NAMES = frozenset(
    {"command", "cmd", "shell", "script", "path", "filepath", "filename", "file", "url"}
)

_ID_SOURCE = "8f3b1c9d4e7a2b6c5d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a"
_DIGITS = "1234567890"
_BRIDGE_FILLER = " the old onboarding "

_ORDINARY_WORDS = (
    "forms",
    "format",
    "platform",
    "transform",
    "confirm",
    "performance",
    "dashboard",
    "washington",
    "sync",
    "increment",
    "function",
    "finance",
    "cancel",
    "license",
    "purchase",
    "brochure",
    "schedule",
    "warehouse",
    "checkout",
    "backup",
    "changelog",
    "catalog",
    "template",
    "attachment",
    "onboarding",
    "shipment",
    "assets",
    "release",
    "readme",
    "invoice",
)

_NEUTRAL_STRINGS = (
    "Here is the weekly status report. No blockers.",
    "ls -la /tmp",
    "git status --short",
    "/home/user/README.md",
    "teammate@company.com",
    "Invoice attached, due Friday.",
    "cat /var/log/app.log | grep -c ERROR",
    "Meeting moved to 3pm, room 4.",
    "npm run build",
    "Thanks, that works for me.",
)

_PROBE_WRAPPERS: dict[str, tuple[str, ...]] = {
    "command": (
        "echo 'note: {ex} is unsafe' >> notes.txt",
        "ls -la /var/log/{ex}",
    ),
    "text": (
        "Please review the attached note: {ex} (no action needed).",
        "Order reference: {ex}",
    ),
}


class LintFinding(BaseModel):
    """One actionable observation about a single rule or settings block.

    ``scope`` is ``settings`` for findings about an inspection block rather than a
    rule. Those stay out of every per-rule rate: counting a settings finding as a
    flagged rule would inflate the flag rate and the unconfirmed rate against a
    rule count it does not belong to.
    """

    rule: str
    check: str
    severity: str
    message: str
    scope: str = SCOPE_RULE
    pattern: str | None = None
    field: str | None = None
    example: str | None = None
    kind: str | None = None


class BenignOutcome(BaseModel):
    """A benign payload that a rule did not allow, with the span that caused it."""

    payload_id: str
    tool: str
    rule: str
    action: str
    field: str | None = None
    pattern: str | None = None
    matched_text: str | None = None
    span: tuple[int, int] | None = None
    view: str = VIEW_ORIGINAL
    reason: str = ""


class LintReport(BaseModel):
    """Result of linting one policy file."""

    policy_path: str
    payloads_path: str | None = None
    rule_count: int = 0
    pattern_count: int = 0
    benign_total: int = 0
    views: list[str] = Field(default_factory=lambda: [VIEW_ORIGINAL])
    findings: list[LintFinding] = Field(default_factory=list)
    blocks: list[BenignOutcome] = Field(default_factory=list)
    approvals: list[BenignOutcome] = Field(default_factory=list)
    flagged_rules: list[str] = Field(default_factory=list)
    high_rules: list[str] = Field(default_factory=list)
    corpus_confirmed_rules: list[str] = Field(default_factory=list)
    probe_only_rules: list[str] = Field(default_factory=list)
    unconfirmed_rules: list[str] = Field(default_factory=list)
    over_block_rate: float | None = None
    flag_rate: float | None = None
    unconfirmed_rate: float | None = None
    high_unconfirmed_rate: float | None = None

    def count(self, severity: str) -> int:
        """Number of findings at one severity."""
        return sum(1 for f in self.findings if f.severity == severity)


@dataclass(frozen=True)
class _Probe:
    kind: str
    text: str


def _rate(numerator: int, denominator: int) -> float | None:
    """Ratio as a percentage, or None on an empty denominator."""
    if denominator <= 0:
        return None
    return round(100.0 * numerator / denominator, 1)


def _expand(seq: Any, depth: int = 0) -> list[list[tuple[str, Any]]]:
    """Flatten a parsed pattern into alternative token sequences, inlining groups."""
    if depth > _DEPTH_CAP:
        return [[("OPAQUE", None)]]
    alts: list[list[tuple[str, Any]]] = [[]]
    for op, arg in seq:
        name = op.name
        if name == "BRANCH":
            branches: list[list[tuple[str, Any]]] = []
            for branch in arg[1]:
                branches.extend(_expand(branch, depth + 1))
            alts = [a + b for a in alts for b in branches][:_ALT_CAP]
        elif name in ("SUBPATTERN", "ATOMIC_GROUP"):
            sub = arg[3] if name == "SUBPATTERN" else arg
            sub_alts = _expand(sub, depth + 1)
            alts = [a + b for a in alts for b in sub_alts][:_ALT_CAP]
        else:
            for a in alts:
                a.append((name, arg))
    return alts


def _parse_alternatives(pattern: str) -> list[list[tuple[str, Any]]]:
    """Parse a pattern into alternative token sequences, or [] when unparseable."""
    try:
        return _expand(regex_parser.parse(pattern, flags=re.IGNORECASE))
    except (re.error, RecursionError, IndexError, TypeError):
        return []


def _class_size(items: Any) -> int:
    """Approximate the number of characters a character class accepts."""
    negate = False
    size = 0
    for op, arg in items:
        name = op.name
        if name == "NEGATE":
            negate = True
        elif name == "LITERAL":
            size += 1
        elif name == "RANGE":
            size += arg[1] - arg[0] + 1
        elif name == "CATEGORY":
            size += _CATEGORY_SIZES.get(arg.name, 64)
    return max(1, 128 - size) if negate else size


def _token_class_size(token: tuple[str, Any]) -> int | None:
    """Class size for a single-character token, or None when it is not one."""
    name, arg = token
    if name == "ANY":
        return 128
    if name == "IN":
        return _class_size(arg)
    return None


def _repeat_parts(token: tuple[str, Any]) -> tuple[int, int, Any] | None:
    """(min, max, subpattern) when the token is a repeat, else None."""
    name, arg = token
    if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
        return int(arg[0]), arg[1], arg[2]
    return None


def _single_token(sub: Any) -> tuple[str, Any] | None:
    """The one token a subpattern contains, or None when it holds several."""
    alts = _expand(sub, _DEPTH_CAP - 1)
    if len(alts) == 1 and len(alts[0]) == 1:
        return alts[0][0]
    return None


def _class_member(token: tuple[str, Any], index: int) -> str:
    """A representative character a single-character token accepts."""
    name, arg = token
    if name == "ANY":
        return "x"
    if name != "IN":
        return "x"
    for op, item in arg:
        if op.name == "CATEGORY":
            category = item.name
            if category == "CATEGORY_SPACE":
                return " "
            if category == "CATEGORY_DIGIT":
                return _DIGITS[index % len(_DIGITS)]
            if category == "CATEGORY_WORD":
                return "x"
        elif op.name == "RANGE":
            lo, hi = item
            if lo <= ord("a") <= hi:
                return "x"
            if lo <= ord("0") <= hi:
                return _DIGITS[index % len(_DIGITS)]
            return chr(lo)
        elif op.name == "LITERAL":
            return chr(item)
    return "x"


def _id_slice(length: int) -> str:
    """An ordinary-looking reference number of the requested length."""
    repeats = (length // len(_ID_SOURCE)) + 1
    return (_ID_SOURCE * repeats)[:length]


def _literal_runs(alt: list[tuple[str, Any]]) -> list[tuple[int, str]]:
    """Maximal runs of consecutive literals, as (token index of run start, text)."""
    runs: list[tuple[int, str]] = []
    start: int | None = None
    chars: list[str] = []
    for index, (name, arg) in enumerate(alt):
        if name == "LITERAL":
            if start is None:
                start = index
            chars.append(chr(arg))
            continue
        if start is not None:
            runs.append((start, "".join(chars)))
            start, chars = None, []
    if start is not None:
        runs.append((start, "".join(chars)))
    return runs


def _is_space_repeat(token: tuple[str, Any]) -> bool:
    """True for a repeat over whitespace only, which cannot occur inside a word."""
    parts = _repeat_parts(token)
    if parts is None:
        return False
    inner = _single_token(parts[2])
    if inner is None or inner[0] != "IN":
        return False
    return all(
        op.name == "CATEGORY" and item.name == "CATEGORY_SPACE" for op, item in inner[1]
    )


def _is_anchored_before(alt: list[tuple[str, Any]], index: int) -> bool:
    """True when an anchor or word boundary precedes `index`, across whitespace only."""
    for position in range(index - 1, -1, -1):
        token = alt[position]
        if token[0] == "AT":
            return True
        if not _is_space_repeat(token):
            return False
    return False


def _unbounded_gap(token: tuple[str, Any]) -> bool:
    """True when the token is an unbounded repeat over a very permissive class."""
    parts = _repeat_parts(token)
    if parts is None:
        return False
    _, high, sub = parts
    if high != MAXREPEAT:
        return False
    inner = _single_token(sub)
    size = _token_class_size(inner) if inner else None
    return size is not None and size >= 64


def _minimal_example(alt: list[tuple[str, Any]], *, gap: str) -> tuple[str, bool] | None:
    """Build a shortest-ish string the alternative matches, plus whether an id filled a run.

    `gap` is inserted for every unbounded permissive repeat, so a caller can turn
    `disregard.*rules` into prose instead of `disregardrules`.
    """
    out: list[str] = []
    used_id = False
    counter = 0
    for token in alt:
        name, _arg = token
        if name in ("AT", "OPAQUE"):
            continue
        parts = _repeat_parts(token)
        if parts is not None:
            low, high, sub = parts
            inner = _single_token(sub)
            size = _token_class_size(inner) if inner else None
            if size is not None and size >= _LARGE_CLASS and low >= _FLOOR_MIN:
                out.append(_id_slice(low))
                used_id = True
                continue
            if low == 0:
                if high == MAXREPEAT and size is not None and size >= 64:
                    out.append(gap)
                continue
            if inner is not None:
                out.append("".join(_class_member(inner, counter + i) for i in range(low)))
                counter += low
                continue
            piece = _minimal_example(_expand(sub, _DEPTH_CAP - 1)[0], gap=gap)
            if piece is None:
                return None
            out.append(piece[0] * low)
            continue
        if name == "LITERAL":
            out.append(chr(_arg))
            continue
        if name in ("IN", "ANY"):
            out.append(_class_member(token, counter))
            counter += 1
            continue
        return None
    return "".join(out), used_id


def _field_kind(field: str | None) -> str:
    """Which probe wrapper family suits an argument name."""
    return "command" if (field or "").lower() in _COMMAND_FIELD_NAMES else "text"


def _word_embeddings(literal: str) -> list[str]:
    """Ordinary words that contain `literal` somewhere other than their start."""
    lowered = literal.lower()
    out: list[str] = []
    for word in _ORDINARY_WORDS:
        index = word.find(lowered)
        if index > 0:
            out.append(word)
    return out


def _bridge_pairs(alt: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    """Literal runs on either side of an unbounded gap, in token order."""
    pairs: list[tuple[str, str]] = []
    runs = _literal_runs(alt)
    for index, token in enumerate(alt):
        if not _unbounded_gap(token):
            continue
        before = [text for start, text in runs if start < index]
        after = [text for start, text in runs if start > index]
        if before and after:
            pairs.append((before[-1], after[0]))
    return pairs


def _generate_probes(pattern: str, field: str | None) -> list[_Probe]:
    """Plausible-benign strings this pattern matches, derived only from the pattern."""
    alts = _parse_alternatives(pattern)
    if not alts:
        return []
    try:
        compiled = re.compile(pattern, flags=re.IGNORECASE)
    except re.error:
        return []

    cores: list[_Probe] = []
    for alt in alts[:4]:
        base = _minimal_example(alt, gap="")
        if base is None:
            continue
        text, used_id = base
        if text:
            cores.append(_Probe("ordinary_id" if used_id else "mention", text))
        for pattern_a, pattern_b in _bridge_pairs(alt):
            if _is_prose_word(pattern_a) and _is_prose_word(pattern_b):
                bridged = _minimal_example(alt, gap=_BRIDGE_FILLER)
                if bridged is not None and bridged[0] != text:
                    cores.append(_Probe("bridge_prose", bridged[0]))
        for start, run in _literal_runs(alt):
            if not run.isalnum() or len(run) > _SHORT_LITERAL or _is_anchored_before(alt, start):
                continue
            for word in _word_embeddings(run):
                index = word.lower().find(run.lower())
                for candidate in (word[: index + len(run)], word):
                    cores.append(_Probe("word_embedded", text.replace(run, candidate, 1)))

    wrappers = _PROBE_WRAPPERS[_field_kind(field)]
    probes: list[_Probe] = []
    kinds: set[str] = set()
    for core in sorted(cores, key=lambda p: _PROBE_ORDER.index(p.kind)):
        if core.kind in kinds:
            continue
        for text in _dedupe([core.text.strip(), core.text]):
            candidate = next((w.format(ex=text) for w in wrappers if compiled.search(w.format(ex=text))), None)
            if candidate is None:
                continue
            kinds.add(core.kind)
            probes.append(_Probe(core.kind, candidate))
            break
        if len(probes) >= _PROBES_PER_PATTERN:
            break
    return probes


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving deduplication of non-empty strings."""
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


_PROBE_ORDER = ("ordinary_id", "bridge_prose", "word_embedded", "mention")


def _is_prose_word(text: str) -> bool:
    """True for an alphabetic run long enough to be an ordinary English word."""
    return text.isalpha() and len(text) >= _BRIDGE_WORD


def _pattern_conditions(rule: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    """Every pattern_match condition of a raw rule, with its index in the rule."""
    conditions = rule.get("conditions") or []
    if not isinstance(conditions, list):
        return []
    return [
        (index, c)
        for index, c in enumerate(conditions)
        if isinstance(c, dict) and c.get("type") == "pattern_match" and isinstance(c.get("patterns"), list)
    ]


def _resolved_views(policy_path: Path) -> dict[tuple[str, int], ViewFlags]:
    """Per-condition view flags, resolved by PolicyEngine rather than re-derived.

    Keyed by rule name and condition index, which is the raw index too: a rule
    whose conditions do not all parse is dropped whole, so surviving conditions
    keep their positions.
    """
    engine = PolicyEngine(policy_path=str(policy_path))
    return {
        (rule.name, index): condition.normalize
        for rule in engine.compiled_rules()
        for index, condition in enumerate(rule.conditions)
    }


def _view_labels(flags: list[ViewFlags]) -> list[str]:
    """Which normalized views any condition of the policy is matched against."""
    labels = [VIEW_ORIGINAL]
    if any(canonical for canonical, _ in flags):
        labels.append(VIEW_CANONICAL)
    if any(decoded for _, decoded in flags):
        labels.append(VIEW_DECODED)
    return labels


def _decoded_view_findings(
    rule_name: str,
    pattern: str,
    field: str | None,
    views: ViewFlags,
) -> list[LintFinding]:
    """Conditions matched against decoded plaintext, where the raw pattern understates reach."""
    if not views[1]:
        return []
    return [
        LintFinding(
            rule=rule_name,
            check="decoded_view_widens_match",
            severity=SEV_MEDIUM,
            pattern=pattern,
            field=field,
            message=(
                f"this condition also runs against base64 and percent-encoded fragments of `{field}` "
                "decoded to plaintext, so it reaches text a reader of the raw pattern cannot see, and "
                "every static check below reads the raw pattern only. PolicyEngine keeps decoded views "
                "off by default for exactly this reason"
            ),
        )
    ]


def _allowlist_findings(rule_name: str, rule: dict[str, Any]) -> list[LintFinding]:
    """domain_allowlist conditions that flag every value, per PolicyEngine's fail-safe."""
    findings: list[LintFinding] = []
    for condition in rule.get("conditions") or []:
        if not isinstance(condition, dict) or condition.get("type") != "domain_allowlist":
            continue
        domains = condition.get("allowed_domains")
        if isinstance(domains, list) and any(str(d).strip() for d in domains):
            continue
        findings.append(
            LintFinding(
                rule=rule_name,
                check="empty_domain_allowlist",
                severity=SEV_HIGH,
                field=condition.get("field") if isinstance(condition.get("field"), str) else None,
                message=(
                    "the allowlist is empty, and PolicyEngine deliberately flags every value when it is, "
                    "so this rule fires on all traffic to the tool. List the domains you accept"
                ),
            )
        )
    return findings


def _settings_findings(settings: dict[str, Any]) -> list[LintFinding]:
    """Inspection blocks configured to act destructively on a false positive.

    Static only, and it stays that way until there is a benign corpus of tool
    results and tool metadata. Both inspectors run a fixed pattern set over
    response text rather than rule regexes, so there is nothing here for the
    static regex checks to read and nothing for the benign payload corpus, which
    carries request arguments only, to exercise.
    """
    findings: list[LintFinding] = []
    result = settings.get("result_inspection")
    if isinstance(result, dict) and result.get("enabled", True) and result.get("action") == "block":
        findings.append(
            LintFinding(
                rule="settings.result_inspection",
                check="result_inspection_blocks",
                severity=SEV_MEDIUM,
                scope=SCOPE_SETTINGS,
                message=(
                    "action: block fails the whole tool call when an injection pattern fires on the "
                    "result, and these patterns cannot tell text that instructs the model from text "
                    "that quotes it. neutralize costs a fence on a false positive instead of the task"
                ),
            )
        )

    metadata = settings.get("metadata_inspection")
    if not isinstance(metadata, dict) or not metadata.get("enabled", True):
        return findings
    action = str(metadata.get("action") or "redact")
    if action in ("drop", "block"):
        findings.append(
            LintFinding(
                rule="settings.metadata_inspection",
                check="metadata_inspection_discards_tools",
                severity=SEV_MEDIUM,
                scope=SCOPE_SETTINGS,
                message=(
                    f"action: {action} removes a tool from discovery on a false positive, and "
                    "legitimate tool descriptions are imperative prose. redact or annotate leave the "
                    "tool callable"
                ),
            )
        )
    threshold = str(metadata.get("severity_threshold") or "critical")
    if action in _MUTATING_METADATA_ACTIONS and threshold in ("medium", "high"):
        findings.append(
            LintFinding(
                rule="settings.metadata_inspection",
                check="metadata_inspection_low_threshold",
                severity=SEV_MEDIUM,
                scope=SCOPE_SETTINGS,
                message=(
                    f"severity_threshold: {threshold} with action: {action} rewrites tool metadata on "
                    f"{len(_METADATA_SEVERITY_ORDER) - _METADATA_SEVERITY_ORDER.index(threshold)} of "
                    f"{len(_METADATA_SEVERITY_ORDER)} severity tiers, so ordinary imperative "
                    "descriptions are degraded. critical-only is the default for that reason"
                ),
            )
        )
    return findings


def _always_findings(rule_name: str, pattern: str, field: str | None) -> list[LintFinding]:
    """Patterns that match the empty string or nearly every ordinary string."""
    try:
        compiled = re.compile(pattern, flags=re.IGNORECASE)
    except re.error:
        return [
            LintFinding(
                rule=rule_name,
                check="uncompilable_pattern",
                severity=SEV_HIGH,
                pattern=pattern,
                field=field,
                message="pattern does not compile, so PolicyEngine drops the whole rule and it protects nothing",
            )
        ]
    if compiled.search("") is not None:
        return [
            LintFinding(
                rule=rule_name,
                check="matches_empty_string",
                severity=SEV_HIGH,
                pattern=pattern,
                field=field,
                message=(
                    "matches the empty string, so every call to this tool is blocked; "
                    "a payload with a blank argument makes the generator emit re.escape(\"\")"
                ),
            )
        ]
    hits = [s for s in _NEUTRAL_STRINGS if compiled.search(s)]
    if len(hits) >= len(_NEUTRAL_STRINGS) - 2:
        return [
            LintFinding(
                rule=rule_name,
                check="matches_everything",
                severity=SEV_HIGH,
                pattern=pattern,
                field=field,
                example=hits[0],
                message=(
                    f"matches {len(hits)} of {len(_NEUTRAL_STRINGS)} unrelated ordinary strings, "
                    "so it is close to a blanket block on this tool"
                ),
            )
        ]
    return []


def _class_floor_findings(rule_name: str, pattern: str, field: str | None) -> list[LintFinding]:
    """Generic character classes whose repetition floor is low enough to hit ordinary ids."""
    findings: list[LintFinding] = []
    for alt in _parse_alternatives(pattern):
        for token in alt:
            parts = _repeat_parts(token)
            if parts is None:
                continue
            low, high, sub = parts
            inner = _single_token(sub)
            size = _token_class_size(inner) if inner else None
            if size is None or size < _LARGE_CLASS:
                continue
            if not (_FLOOR_MIN <= low <= _FLOOR_MAX) or (high != MAXREPEAT and high < low * 2):
                continue
            findings.append(
                LintFinding(
                    rule=rule_name,
                    check="low_floor_generic_class",
                    severity=SEV_HIGH if low <= _FLOOR_HIGH else SEV_MEDIUM,
                    pattern=pattern,
                    field=field,
                    example=_id_slice(low),
                    message=(
                        f"{{{low},}} over a {size}-character class matches any {low}-character run of "
                        f"ordinary text: order references, git SHAs, UUIDs. Require structure "
                        f"(a prefix, a decode check) or raise the floor above {_FLOOR_MAX}"
                    ),
                )
            )
    return findings


def _bridge_findings(rule_name: str, pattern: str, field: str | None) -> list[LintFinding]:
    """Unbounded `.*` gaps that let unrelated words co-occur.

    One finding per alternative, on its widest-consequence pair, because every
    gap in one alternative has the same fix and repeating it buries the report.
    """
    findings: list[LintFinding] = []
    seen: set[tuple[str, str]] = set()
    for alt in _parse_alternatives(pattern):
        pairs = _bridge_pairs(alt)
        prose_pairs = [p for p in pairs if _is_prose_word(p[0]) and _is_prose_word(p[1])]
        for left, right in (prose_pairs or pairs)[:1]:
            if (left, right) in seen:
                continue
            seen.add((left, right))
            prose = _is_prose_word(left) and _is_prose_word(right)
            findings.append(
                LintFinding(
                    rule=rule_name,
                    check="wide_bridge",
                    severity=SEV_HIGH if prose else SEV_MEDIUM,
                    pattern=pattern,
                    field=field,
                    example=f"{left}{_BRIDGE_FILLER}{right}" if prose else None,
                    message=(
                        f"`{left}` and `{right}` are bridged by an unbounded gap, so they match whenever both "
                        f"appear anywhere in `{field}`, however unrelated. Bound the gap (`.{{0,20}}`) or "
                        "require adjacency"
                    ),
                )
            )
    return findings


def _short_literal_findings(rule_name: str, pattern: str, field: str | None) -> list[LintFinding]:
    """Short unanchored literals that also occur inside ordinary words."""
    try:
        compiled = re.compile(pattern, flags=re.IGNORECASE)
    except re.error:
        return []
    findings: list[LintFinding] = []
    seen: set[str] = set()
    for alt in _parse_alternatives(pattern):
        base = _minimal_example(alt, gap="")
        for start, run in _literal_runs(alt):
            if run in seen or not run.isalnum() or len(run) > _SHORT_LITERAL:
                continue
            if _is_anchored_before(alt, start):
                continue
            words = _word_embeddings(run)
            if not words:
                continue
            seen.add(run)
            confirmed: str | None = None
            if base is not None:
                for word in words:
                    index = word.lower().find(run.lower())
                    candidate = base[0].replace(run, word[: index + len(run)], 1)
                    if compiled.search(candidate):
                        confirmed = word
                        break
            findings.append(
                LintFinding(
                    rule=rule_name,
                    check="unanchored_short_literal",
                    severity=SEV_MEDIUM if confirmed else SEV_LOW,
                    pattern=pattern,
                    field=field,
                    example=confirmed,
                    message=(
                        f"`{run}` is unanchored and occurs inside ordinary words ({', '.join(words[:3])}), so it "
                        + (
                            f"matches inside `{confirmed}`. Anchor it with \\b or require a command position"
                            if confirmed
                            else "may match mid-word; the rest of the pattern prevented every word tried here"
                        )
                    ),
                )
            )
    return findings


def _redos_findings(rule_name: str, pattern: str, field: str | None) -> list[LintFinding]:
    """Nested quantifiers, with a measured growth estimate rather than a proof."""
    nested = False
    inner_token: tuple[str, Any] | None = None
    for alt in _parse_alternatives(pattern):
        for token in alt:
            parts = _repeat_parts(token)
            if parts is None:
                continue
            for sub_alt in _expand(parts[2], _DEPTH_CAP - 1):
                for sub_token in sub_alt:
                    sub_parts = _repeat_parts(sub_token)
                    if sub_parts is not None and (parts[1] == MAXREPEAT or sub_parts[1] == MAXREPEAT):
                        nested = True
                        inner = _single_token(sub_parts[2])
                        inner_token = inner_token or inner
    if not nested:
        return []

    filler = _class_member(inner_token, 0) if inner_token else "a"
    estimate, severity = _growth_estimate(pattern, filler)
    return [
        LintFinding(
            rule=rule_name,
            check="redos_shape",
            severity=severity,
            pattern=pattern,
            field=field,
            message=(
                f"nested quantifiers can backtrack catastrophically; {estimate}. "
                "Rewrite the inner repeat away or bound both quantifiers"
            ),
        )
    ]


def _growth_estimate(pattern: str, filler: str) -> tuple[str, str]:
    """Time matching adversarial inputs of growing length and classify the growth."""
    try:
        compiled = re.compile(pattern, flags=re.IGNORECASE)
    except re.error:
        return "pattern does not compile", SEV_MEDIUM
    timings: dict[int, float] = {}
    for length in (12, 16, 20):
        probe = filler * length + "!"
        start = time.perf_counter()
        compiled.search(probe)
        elapsed = time.perf_counter() - start
        timings[length] = elapsed
        if elapsed > 0.25:
            break
    lengths = sorted(timings)
    if len(lengths) < 2:
        return f"matching {lengths[0]} filler characters already took {timings[lengths[0]] * 1000:.0f}ms", SEV_HIGH
    first, last = lengths[0], lengths[-1]
    ratio = timings[last] / max(timings[first], 1e-9)
    detail = (
        f"{first} filler characters took {timings[first] * 1000:.2f}ms, {last} took "
        f"{timings[last] * 1000:.2f}ms (x{ratio:.0f} over {last - first} more characters)"
    )
    if ratio >= 8:
        return f"complexity estimate exponential: {detail}", SEV_HIGH
    return f"complexity estimate not measurably superlinear here: {detail}", SEV_MEDIUM


def _dead_pattern_findings(
    rule_name: str,
    rule: dict[str, Any],
    payloads: dict[str, dict[str, Any]],
) -> list[LintFinding]:
    """Autogen rules whose patterns cannot match the payload they came from."""
    if not rule_name.startswith("autogen_"):
        return []
    payload = payloads.get(rule_name[len("autogen_") :])
    if payload is None:
        return []
    arguments = payload.get("arguments") or {}
    findings: list[LintFinding] = []
    for _index, condition in _pattern_conditions(rule):
        field = condition.get("field")
        value = arguments.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        patterns = [str(p) for p in condition["patterns"]]
        if any(_safe_search(p, value) for p in patterns):
            continue
        findings.append(
            LintFinding(
                rule=rule_name,
                check="dead_pattern",
                severity=SEV_HIGH,
                pattern=patterns[0] if patterns else None,
                field=field,
                message=(
                    f"no pattern matches the `{field}` of payload {payload.get('id')} that generated this rule, "
                    "so the rule can never fire and the gap it claims to close is still open"
                ),
            )
        )
    return findings


def _safe_search(pattern: str, value: str) -> bool:
    """`re.search` with IGNORECASE, treating an invalid pattern as no match."""
    try:
        return re.search(pattern, value, flags=re.IGNORECASE) is not None
    except re.error:
        return False


def _probe_findings(rule_name: str, rule: dict[str, Any]) -> list[LintFinding]:
    """Corpus-free over-block evidence: plausible-benign strings each pattern matches.

    A `mention` probe only quotes the rule's own keyword inside ordinary prose, so
    it fires on almost every keyword rule. It stays medium and is reported once per
    rule; `_summarize` does not treat it as confirmation of the other findings.
    """
    action = str(rule.get("action") or "").strip().upper()
    findings: list[LintFinding] = []
    mentioned = False
    for _index, condition in _pattern_conditions(rule):
        field = condition.get("field")
        for pattern in (str(p) for p in condition["patterns"]):
            for probe in _generate_probes(pattern, field if isinstance(field, str) else None):
                if probe.kind == "mention":
                    if mentioned:
                        continue
                    mentioned = True
                strong = probe.kind != "mention" and action == PolicyAction.BLOCK.value
                findings.append(
                    LintFinding(
                        rule=rule_name,
                        check="probe_over_block",
                        severity=SEV_HIGH if strong else SEV_MEDIUM,
                        pattern=pattern,
                        field=field if isinstance(field, str) else None,
                        example=probe.text,
                        kind=probe.kind,
                        message=(
                            f"generated benign string ({probe.kind}) is {action or 'matched'}ed by this rule: "
                            f"{probe.text!r}"
                        ),
                    )
                )
    return findings


def _load_payloads(payloads_path: str | Path | None) -> list[dict[str, Any]]:
    """Payload dicts from a payload YAML file, or [] when there is none."""
    if payloads_path is None:
        return []
    path = Path(payloads_path)
    if not path.is_file():
        raise FileNotFoundError(f"payload file not found: {path}")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    payloads = loaded.get("payloads") or []
    return [p for p in payloads if isinstance(p, dict)]


def _is_benign(payload: dict[str, Any]) -> bool:
    """True for a payload the policy is supposed to allow."""
    expected = str(payload.get("expected_behavior") or "").strip().lower()
    return expected == "allow" or payload.get("category") == "benign"


def _evaluate_benign(
    rules: list[dict[str, Any]],
    benign: list[dict[str, Any]],
    settings: dict[str, Any],
) -> tuple[list[BenignOutcome], list[BenignOutcome]]:
    """Run every rule alone against every benign payload through a real PolicyEngine.

    Each one-rule policy carries the real ``settings`` block, so normalization is
    resolved exactly as the deployed policy resolves it. With ``settings: {}`` a
    policy that turned normalization off would still be linted with the canonical
    view on, and the lint would report blocks enforcement does not make.
    """
    blocks: list[BenignOutcome] = []
    approvals: list[BenignOutcome] = []
    with tempfile.TemporaryDirectory(prefix="agentparry-lint-") as tmp:
        for index, rule in enumerate(rules):
            path = Path(tmp) / f"rule_{index}.yaml"
            path.write_text(yaml.safe_dump({"rules": [rule], "settings": settings}), encoding="utf-8")
            engine = PolicyEngine(policy_path=str(path))
            for payload in benign:
                decision = engine.evaluate(str(payload.get("tool") or ""), payload.get("arguments") or {})
                if decision.action == PolicyAction.ALLOW:
                    continue
                outcome = _outcome(rule, payload, decision.action.value, decision.findings)
                if decision.action == PolicyAction.BLOCK:
                    blocks.append(outcome)
                else:
                    approvals.append(outcome)
    return blocks, approvals


def _outcome(
    rule: dict[str, Any],
    payload: dict[str, Any],
    action: str,
    findings: list[Finding],
) -> BenignOutcome:
    """Describe why a rule did not allow a benign payload, from the engine's own findings.

    The span and view come from ``PolicyDecision``, so a match found only in a
    normalized view is reported with that view and a span back in the original
    argument, instead of being reported as a non-pattern condition.
    """
    base = {
        "payload_id": str(payload.get("id") or ""),
        "tool": str(payload.get("tool") or ""),
        "rule": str(rule.get("name") or ""),
        "action": action,
    }
    matched = next((f for f in findings if f.matched_pattern is not None), None)
    if matched is not None:
        return BenignOutcome(
            **base,
            field=matched.field,
            pattern=matched.matched_pattern,
            matched_text=matched.matched_text,
            span=matched.span,
            view=matched.view,
            reason=f"pattern matched in `{matched.field}`",
        )
    reason = findings[0].description if findings else "condition matched (see rule conditions)"
    return BenignOutcome(**base, reason=reason)


def lint_policy(
    policy_path: str | Path = "config/default_policy.yaml",
    payloads_path: str | Path | None = "attacks/payloads.yaml",
    *,
    probes: bool = True,
) -> LintReport:
    """Analyze a policy file statically and empirically for over-blocking."""
    path = Path(policy_path)
    if not path.is_file():
        raise FileNotFoundError(f"policy file not found: {path}")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = [r for r in (loaded.get("rules") or []) if isinstance(r, dict)]
    settings = loaded.get("settings") if isinstance(loaded.get("settings"), dict) else {}

    all_payloads = _load_payloads(payloads_path)
    by_id = {str(p.get("id")): p for p in all_payloads}
    benign = [p for p in all_payloads if _is_benign(p)]
    resolved_views = _resolved_views(path)

    findings: list[LintFinding] = _settings_findings(settings)
    pattern_count = 0
    for rule in rules:
        name = str(rule.get("name") or "")
        findings.extend(_dead_pattern_findings(name, rule, by_id))
        findings.extend(_allowlist_findings(name, rule))
        for index, condition in _pattern_conditions(rule):
            field = condition.get("field")
            field_name = field if isinstance(field, str) else None
            views = resolved_views.get((name, index), _INHERITED_VIEWS)
            for pattern in (str(p) for p in condition["patterns"]):
                pattern_count += 1
                findings.extend(_always_findings(name, pattern, field_name))
                findings.extend(_class_floor_findings(name, pattern, field_name))
                findings.extend(_bridge_findings(name, pattern, field_name))
                findings.extend(_short_literal_findings(name, pattern, field_name))
                findings.extend(_redos_findings(name, pattern, field_name))
                findings.extend(_decoded_view_findings(name, pattern, field_name, views))
        if probes:
            findings.extend(_probe_findings(name, rule))

    blocks, approvals = _evaluate_benign(rules, benign, settings)
    findings.extend(
        LintFinding(
            rule=block.rule,
            check="benign_corpus_block",
            severity=SEV_HIGH,
            pattern=block.pattern,
            field=block.field,
            example=block.matched_text,
            message=(
                f"blocks benign payload {block.payload_id} on `{block.field}` span {block.span} "
                f"in the {block.view} view: {block.matched_text!r}"
            ),
        )
        for block in blocks
    )
    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.rule, f.check))

    return _summarize(
        LintReport(
            policy_path=str(path),
            payloads_path=str(payloads_path) if payloads_path else None,
            rule_count=len(rules),
            pattern_count=pattern_count,
            benign_total=len(benign),
            views=_view_labels(list(resolved_views.values())),
            findings=findings,
            blocks=blocks,
            approvals=approvals,
        )
    )


def _summarize(report: LintReport) -> LintReport:
    """Fill in the aggregate rates, including the linter's own unconfirmed rate.

    Confirmation means a concrete blocked string: a benign corpus payload, or a
    probe that mutated the pattern rather than merely quoting its keyword.
    """
    rule_findings = [f for f in report.findings if f.scope == SCOPE_RULE]
    flagged = _ordered({f.rule for f in rule_findings})
    high = _ordered({f.rule for f in rule_findings if f.severity == SEV_HIGH})
    corpus = _ordered({b.rule for b in report.blocks})
    confirming = {
        f.rule for f in rule_findings if f.check == "probe_over_block" and f.kind != "mention"
    }
    probe_only = [r for r in flagged if r not in corpus and r in confirming]
    unconfirmed = [r for r in flagged if r not in corpus and r not in probe_only]

    report.flagged_rules = flagged
    report.high_rules = high
    report.corpus_confirmed_rules = corpus
    report.probe_only_rules = probe_only
    report.unconfirmed_rules = unconfirmed
    blocked_payloads = {b.payload_id for b in report.blocks}
    report.over_block_rate = _rate(len(blocked_payloads), report.benign_total)
    report.flag_rate = _rate(len(flagged), report.rule_count)
    report.unconfirmed_rate = _rate(len(unconfirmed), len(flagged))
    report.high_unconfirmed_rate = _rate(len([r for r in high if r not in corpus and r not in probe_only]), len(high))
    return report


def _ordered(names: set[str]) -> list[str]:
    """Deterministic ordering for a set of rule names."""
    return sorted(names)


def _pct(value: float | None) -> str:
    """Percentage for display, or n/a on an empty denominator."""
    return "n/a" if value is None else f"{value}%"


def render_findings(findings: list[LintFinding]) -> list[str]:
    """Render findings as two indented lines each: the header, then the message."""
    lines: list[str] = []
    for finding in findings:
        head = f"  [{finding.severity}] {finding.rule}  {finding.check}"
        lines.append(head if finding.pattern is None else f"{head}  `{finding.pattern}` on `{finding.field}`")
        lines.append(f"         {finding.message}")
    return lines


def render_report(report: LintReport) -> str:
    """Render a lint report as plain text."""
    corpus_note = ""
    if report.benign_total:
        corpus_note = f", benign corpus {report.benign_total} payloads from {report.payloads_path}"
    lines: list[str] = [
        f"Policy lint: {report.policy_path}",
        f"{report.rule_count} rules, {report.pattern_count} patterns{corpus_note}",
        f"matched views: {', '.join(report.views)}",
        "",
        "EMPIRICAL: benign corpus",
    ]
    if not report.benign_total:
        lines.append("  no benign payloads in the payload file; corpus half skipped")
    elif not report.blocks:
        lines.append("  no benign payload is blocked")
    for block in report.blocks:
        lines.append(f"  BLOCK  {block.payload_id}  {block.tool}  {block.rule}")
        detail = (
            f"pattern `{block.pattern}` on `{block.field}` span {block.span} "
            f"matched {block.matched_text!r} in the {block.view} view"
        )
        lines.append(f"         {detail if block.pattern else block.reason}")
    for approval in report.approvals:
        lines.append(f"  {approval.action}  {approval.payload_id}  {approval.tool}  {approval.rule}")
        lines.append(f"         {approval.reason} (friction, not a block)")
    blocked = len({b.payload_id for b in report.blocks})
    lines.append(f"  over-block rate: {blocked}/{report.benign_total} = {_pct(report.over_block_rate)}")

    lines.extend(["", "STATIC AND PROBE FINDINGS"])
    static = [
        f
        for f in report.findings
        if f.scope == SCOPE_RULE and f.check != "benign_corpus_block"
    ]
    lines.extend(render_findings(static) or ["  none"])

    settings_findings = [f for f in report.findings if f.scope == SCOPE_SETTINGS]
    if settings_findings:
        lines.extend(
            [
                "",
                "INSPECTION SETTINGS (static only: there is no benign corpus of tool results or metadata)",
                *render_findings(settings_findings),
            ]
        )

    counts = f"{report.count(SEV_HIGH)} high, {report.count(SEV_MEDIUM)} medium, {report.count(SEV_LOW)} low"
    high_names = f" -> {', '.join(report.high_rules)}" if report.high_rules else ""
    lines.extend(
        [
            "",
            "SUMMARY",
            f"  findings: {counts}",
            f"  rules flagged: {len(report.flagged_rules)}/{report.rule_count} ({_pct(report.flag_rate)})",
            f"  high-severity rules: {len(report.high_rules)}/{report.rule_count}{high_names}",
            f"  corpus-confirmed: {len(report.corpus_confirmed_rules)}"
            f"  probe-only: {len(report.probe_only_rules)}"
            f"  unconfirmed: {len(report.unconfirmed_rules)}",
            f"  linter unconfirmed rate: {_pct(report.unconfirmed_rate)}"
            f"  (high severity: {_pct(report.high_unconfirmed_rate)})",
        ]
    )
    return "\n".join(lines)
