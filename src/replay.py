"""Read a recorded audit log back and re-evaluate its decisions against a policy.

The audit log is write-only today. This module is the reader: it parses JSONL
back into `AuditRecord`s, aggregates what actually happened, and replays each
recorded policy decision against a candidate policy file.

A default record carries a keyed HMAC of the arguments, never the arguments, so
a replay cannot re-run a regex it has no input for. Every rule evaluation here
is three-valued: `MATCH`, `NO_MATCH` or `UNKNOWN`, derived only from what the
record actually holds (tool name, top-level argument key names, argument byte
count, and raw arguments when the log was recorded with `args_mode=full`). A
decision whose outcome depends on an `UNKNOWN` rule is reported as
indeterminate, never guessed.

Reading is defensive. A JSONL log can have a torn final line, unknown future
fields and mixed schema versions; unparseable lines are counted, not fatal.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from src.audit import MAX_ARG_KEYS
from src.models import (
    AuditAction,
    AuditDirection,
    AuditRecord,
    AuditTransport,
    PolicyAction,
)
from src.policy import Condition, PolicyEngine, Rule

MATCH = "match"
NO_MATCH = "no_match"
UNKNOWN = "unknown"

VERDICT_UNCHANGED = "unchanged"
VERDICT_NEWLY_BLOCKED = "newly_blocked"
VERDICT_NO_LONGER_BLOCKED = "no_longer_blocked"
VERDICT_ACTION_CHANGED = "action_changed"
VERDICT_INDETERMINATE = "indeterminate"

VERDICT_ORDER = (
    VERDICT_UNCHANGED,
    VERDICT_NEWLY_BLOCKED,
    VERDICT_NO_LONGER_BLOCKED,
    VERDICT_ACTION_CHANGED,
    VERDICT_INDETERMINATE,
)

POLICY_SCOPE_ACTIONS = frozenset(
    {AuditAction.ALLOW, AuditAction.BLOCK_POLICY, AuditAction.REQUIRE_APPROVAL}
)

STOPPING_ACTIONS = frozenset({PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL})

BUCKET_WIDTHS = {"day": 10, "hour": 13, "minute": 16}
DEFAULT_BUCKET = "hour"

MAX_SAMPLES = 20
DEFAULT_TOP = 10
EMPTY_ARGS_BYTES = 2
UNKNOWN_BUCKET = "unknown"

_KNOWN_FIELDS = frozenset(AuditRecord.model_fields)


class SkipStats(BaseModel):
    """What a read pass could not turn into an `AuditRecord`."""

    lines: int = 0
    blank: int = 0
    bad_json: int = 0
    not_object: int = 0
    rejected: int = 0
    torn_tail: bool = False
    unknown_field_records: int = 0
    unknown_field_names: list[str] = Field(default_factory=list)

    @property
    def skipped(self) -> int:
        """Non-blank lines that produced no record."""
        return self.bad_json + self.not_object + self.rejected


class AuditLog(BaseModel):
    """Records recovered from one or more audit files, plus what was skipped."""

    records: list[AuditRecord] = Field(default_factory=list)
    stats: SkipStats = Field(default_factory=SkipStats)
    sources: list[str] = Field(default_factory=list)


class RuleUsage(BaseModel):
    """How often one rule fired, and on which tools."""

    rule: str
    count: int
    tools: dict[str, int] = Field(default_factory=dict)


class TimeBucket(BaseModel):
    """Decision counts inside one time bucket."""

    bucket: str
    total: int = 0
    blocks: int = 0
    approvals: int = 0
    fail_open: int = 0


class LogSummary(BaseModel):
    """Everything answerable from a log without any policy file."""

    sources: list[str] = Field(default_factory=list)
    records: int = 0
    stats: SkipStats = Field(default_factory=SkipStats)
    runs: int = 0
    first_ts: str | None = None
    last_ts: str | None = None
    schema_versions: dict[str, int] = Field(default_factory=dict)
    args_modes: dict[str, int] = Field(default_factory=dict)
    key_ids: dict[str, int] = Field(default_factory=dict)
    actions: dict[str, int] = Field(default_factory=dict)
    transports: dict[str, int] = Field(default_factory=dict)
    tools: dict[str, int] = Field(default_factory=dict)
    rules: list[RuleUsage] = Field(default_factory=list)
    fail_open: int = 0
    fail_open_samples: list[str] = Field(default_factory=list)
    stdio_require_approval: int = 0
    stdio_require_approval_tools: dict[str, int] = Field(default_factory=dict)
    buckets: list[TimeBucket] = Field(default_factory=list)
    policy_decisions: int = 0
    with_arguments: int = 0


class DecisionChange(BaseModel):
    """One recorded decision re-evaluated against a candidate policy."""

    seq: int = 0
    ts: str = ""
    tool: str | None = None
    recorded_action: str = ""
    recorded_rule: str | None = None
    new_action: str | None = None
    new_rule: str | None = None
    verdict: str = VERDICT_UNCHANGED
    reason: str = ""


class PolicyDiff(BaseModel):
    """Result of replaying a log against one candidate policy."""

    policy: str = ""
    baseline_policy: str | None = None
    rules: int = 0
    considered: int = 0
    out_of_scope: int = 0
    counts: dict[str, int] = Field(default_factory=dict)
    samples: list[DecisionChange] = Field(default_factory=list)
    blocking_rules: dict[str, int] = Field(default_factory=dict)
    unreplayable_rules: dict[str, int] = Field(default_factory=dict)
    never_fired_in_log: list[str] = Field(default_factory=list)
    constrained_by_recorded_outcome: int = 0
    shared_conditions: int = 0

    @property
    def newly_blocked(self) -> int:
        """Recorded allows the candidate policy would stop."""
        return self.counts.get(VERDICT_NEWLY_BLOCKED, 0)

    @property
    def indeterminate(self) -> int:
        """Decisions the candidate policy cannot settle from recorded metadata."""
        return self.counts.get(VERDICT_INDETERMINATE, 0)


class ReplayReport(BaseModel):
    """Full replay output: the log summary, dead rules, and any policy diff."""

    summary: LogSummary
    baseline_policy: str | None = None
    dead_rules: list[str] = Field(default_factory=list)
    unmatched_fired_rules: list[str] = Field(default_factory=list)
    diff: PolicyDiff | None = None


def parse_record(raw: str) -> tuple[AuditRecord | None, str, list[str]]:
    """Parse one JSONL line into a record.

    Unknown top-level fields are dropped before validation because
    `AuditRecord` forbids extras, so a log written by a newer AgentParry still
    reads here.

    Args:
        raw: One line of the audit log, without the trailing newline.

    Returns:
        `(record, reason, unknown_fields)`. `reason` is empty on success and
        one of `bad_json`, `not_object` or `rejected` otherwise.
    """
    try:
        obj = json.loads(raw)
    except ValueError:
        return None, "bad_json", []
    if not isinstance(obj, dict):
        return None, "not_object", []
    unknown = sorted(str(k) for k in obj if k not in _KNOWN_FIELDS)
    known = {k: v for k, v in obj.items() if k in _KNOWN_FIELDS}
    try:
        record = AuditRecord.model_validate(known)
    except ValidationError:
        return None, "rejected", unknown
    return record, "", unknown


def read_log(path: Path | str, *, include_rotated: bool = False) -> AuditLog:
    """Read an audit log, skipping and counting anything unparseable.

    Args:
        path: Path to the JSONL audit log.
        include_rotated: Also read the single-generation `.1` sibling first, so
            the returned records are in age order.

    Returns:
        An `AuditLog` with every recovered record and the skip counters.
    """
    target = Path(path)
    log = AuditLog()
    candidates: list[Path] = []
    if include_rotated:
        rotated = target.with_name(target.name + ".1")
        if rotated.is_file():
            candidates.append(rotated)
    candidates.append(target)
    for candidate in candidates:
        _read_one(candidate, log)
    return log


def _read_one(path: Path, log: AuditLog) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    log.sources.append(str(path))
    if not text:
        return
    ends_clean = text.endswith("\n")
    lines = text.splitlines()
    unknown_names: set[str] = set(log.stats.unknown_field_names)
    for index, raw in enumerate(lines):
        log.stats.lines += 1
        if not raw.strip():
            log.stats.blank += 1
            continue
        record, reason, unknown = parse_record(raw)
        if unknown:
            unknown_names.update(unknown)
        if record is None:
            if index == len(lines) - 1 and not ends_clean:
                log.stats.torn_tail = True
            if reason == "bad_json":
                log.stats.bad_json += 1
            elif reason == "not_object":
                log.stats.not_object += 1
            else:
                log.stats.rejected += 1
            continue
        if unknown:
            log.stats.unknown_field_records += 1
        log.records.append(record)
    log.stats.unknown_field_names = sorted(unknown_names)


def bucket_key(ts: str, width: str) -> str:
    """Truncate an ISO timestamp to a bucket label."""
    size = BUCKET_WIDTHS.get(width, BUCKET_WIDTHS[DEFAULT_BUCKET])
    if len(ts) < size:
        return UNKNOWN_BUCKET
    return ts[:size]


def is_policy_decision(record: AuditRecord) -> bool:
    """True for a client-to-server decision the policy engine actually produced.

    Injection blocks, invalid params, unknown methods, passthroughs and
    fail-open records never reached a policy rule, and output-side records are
    the `OutputInspector`, so none of them can be replayed against a policy.
    """
    return (
        record.direction is AuditDirection.CLIENT_TO_SERVER
        and record.action in POLICY_SCOPE_ACTIONS
        and record.tool is not None
    )


def fired_rules(log: AuditLog) -> set[str]:
    """Names of every rule observed firing anywhere in the log."""
    return {r.rule for r in log.records if r.rule}


def summarize(log: AuditLog, *, bucket: str = DEFAULT_BUCKET, top: int = DEFAULT_TOP) -> LogSummary:
    """Aggregate a log into the questions answerable without any policy file."""
    actions: Counter[str] = Counter()
    transports: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    rule_tools: dict[str, Counter[str]] = {}
    schema_versions: Counter[str] = Counter()
    args_modes: Counter[str] = Counter()
    key_ids: Counter[str] = Counter()
    approval_tools: Counter[str] = Counter()
    buckets: dict[str, TimeBucket] = {}
    runs: set[str] = set()
    fail_open_samples: list[str] = []
    fail_open = 0
    stdio_approvals = 0
    policy_decisions = 0
    with_arguments = 0
    timestamps: list[str] = []

    for record in log.records:
        actions[record.action.value] += 1
        transports[record.transport.value] += 1
        schema_versions[str(record.schema_version)] += 1
        args_modes[record.args_mode.value] += 1
        if record.arg_hash_key_id:
            key_ids[record.arg_hash_key_id] += 1
        if record.tool:
            tools[record.tool] += 1
        if record.rule:
            rule_counts[record.rule] += 1
            rule_tools.setdefault(record.rule, Counter())[record.tool or "-"] += 1
        runs.add(record.run_id)
        if record.ts:
            timestamps.append(record.ts)
        if record.arguments is not None:
            with_arguments += 1
        if is_policy_decision(record):
            policy_decisions += 1
        if record.action is AuditAction.FAIL_OPEN:
            fail_open += 1
            if len(fail_open_samples) < MAX_SAMPLES:
                fail_open_samples.append(
                    f"seq={record.seq} tool={record.tool or '-'} {record.detail or 'no detail'}"
                )
        if (
            record.action is AuditAction.REQUIRE_APPROVAL
            and record.transport is AuditTransport.STDIO
        ):
            stdio_approvals += 1
            approval_tools[record.tool or "-"] += 1

        slot = buckets.setdefault(bucket_key(record.ts, bucket), TimeBucket(bucket=bucket_key(record.ts, bucket)))
        slot.total += 1
        if record.action in (AuditAction.BLOCK_POLICY, AuditAction.BLOCK_INJECTION):
            slot.blocks += 1
        if record.action is AuditAction.REQUIRE_APPROVAL:
            slot.approvals += 1
        if record.action is AuditAction.FAIL_OPEN:
            slot.fail_open += 1

    usage = [
        RuleUsage(rule=name, count=count, tools=dict(rule_tools.get(name, Counter()).most_common()))
        for name, count in rule_counts.most_common(top)
    ]

    return LogSummary(
        sources=list(log.sources),
        records=len(log.records),
        stats=log.stats,
        runs=len(runs),
        first_ts=min(timestamps) if timestamps else None,
        last_ts=max(timestamps) if timestamps else None,
        schema_versions=dict(sorted(schema_versions.items())),
        args_modes=dict(sorted(args_modes.items())),
        key_ids=dict(sorted(key_ids.items())),
        actions=dict(actions.most_common()),
        transports=dict(sorted(transports.items())),
        tools=dict(tools.most_common(top)),
        rules=usage,
        fail_open=fail_open,
        fail_open_samples=fail_open_samples,
        stdio_require_approval=stdio_approvals,
        stdio_require_approval_tools=dict(approval_tools.most_common()),
        buckets=[buckets[key] for key in sorted(buckets)],
        policy_decisions=policy_decisions,
        with_arguments=with_arguments,
    )


def load_rules(policy_path: Path | str) -> tuple[PolicyEngine, list[Rule]]:
    """Load a policy file and return its engine plus compiled rules in order."""
    engine = PolicyEngine(str(policy_path))
    return engine, engine.compiled_rules


def dead_rules(policy_path: Path | str, fired: set[str]) -> list[str]:
    """Rules present in a policy that never fired anywhere in the log.

    A rule can be silent because nothing triggered it, because an earlier rule
    shadows it, or because the log predates it. This reports absence of
    evidence, and cannot distinguish those causes.
    """
    _engine, rules = load_rules(policy_path)
    return [rule.name for rule in rules if rule.name not in fired]


def _keys_known(record: AuditRecord) -> bool:
    """True when the record's `arg_keys` is a complete top-level key list.

    `arg_bytes` is the marker that arguments were stamped at all, and a list at
    `MAX_ARG_KEYS` may have been truncated, so absence proves nothing there.
    """
    return record.arg_bytes is not None and len(record.arg_keys) < MAX_ARG_KEYS


def _field_absent(record: AuditRecord, field: str) -> bool:
    return _keys_known(record) and field not in record.arg_keys


def _args_empty(record: AuditRecord) -> bool:
    return record.arg_bytes == EMPTY_ARGS_BYTES and not record.arg_keys


def condition_signature(condition: Condition) -> str:
    """Identity of a condition, so the same condition in two policies compares equal.

    Pattern order is normalized because it does not change whether the
    condition matches, only which pattern is reported in a finding.
    """
    parts = [condition.type, condition.field or ""]
    parts.extend(sorted(condition.patterns))
    parts.extend(sorted(condition.allowed_domains))
    return "\x00".join(parts)


def condition_facts(baseline: list[Rule], record: AuditRecord) -> dict[str, bool]:
    """Facts about this call's arguments implied by the decision already recorded.

    The recorded decision is an oracle over the policy that produced it. The rule
    that fired had every one of its conditions match, and first-match-wins means
    every earlier rule for that tool did not match. A non-match only pins one
    condition when the rule has exactly one, since otherwise any of them could
    have been the one that failed.

    Args:
        baseline: Compiled rules of the policy that was in force for this log.
        record: A recorded policy decision.

    Returns:
        Condition signature to match/no-match. Empty when nothing is implied.
    """
    applicable = [r for r in baseline if r.tool == "*" or r.tool == record.tool]
    fired_index: int | None = None
    if record.rule:
        for index, rule in enumerate(applicable):
            if rule.name == record.rule:
                fired_index = index
                break
        if fired_index is None:
            return {}
        preceding = applicable[:fired_index]
    else:
        preceding = applicable

    facts: dict[str, bool] = {}
    for rule in preceding:
        if len(rule.conditions) == 1:
            facts.setdefault(condition_signature(rule.conditions[0]), False)
    if fired_index is not None:
        for condition in applicable[fired_index].conditions:
            facts[condition_signature(condition)] = True
    return facts


def condition_verdict(
    condition: Condition, record: AuditRecord, facts: dict[str, bool] | None = None
) -> str:
    """Three-valued evaluation of one condition against recorded metadata only.

    `facts` from `condition_facts` decide first, because an identical condition
    in the recorded policy already has its answer for this exact call.

    The remaining determinate cases are the ones that need no value: `always`
    always matches, an absent field makes `pattern_match` reduce to matching
    the empty string, an absent field or an empty allowlist makes
    `domain_allowlist` flag, and empty arguments give `pii_detection` nothing to
    scan. Everything else is `UNKNOWN`.
    """
    if facts:
        known = facts.get(condition_signature(condition))
        if known is not None:
            return MATCH if known else NO_MATCH
    if condition.type == "always":
        return MATCH
    field = condition.field or ""
    if condition.type == "pattern_match":
        if _field_absent(record, field):
            return MATCH if any(p.search("") for p in condition.compiled_patterns) else NO_MATCH
        return UNKNOWN
    if condition.type == "domain_allowlist":
        if not condition.allowed_domains:
            return MATCH
        if _field_absent(record, field):
            return MATCH
        return UNKNOWN
    if condition.type == "pii_detection":
        if _args_empty(record):
            return NO_MATCH
        return UNKNOWN
    return UNKNOWN


def rule_verdict(rule: Rule, record: AuditRecord, facts: dict[str, bool] | None = None) -> str:
    """Three-valued evaluation of one rule, mirroring the engine's `all()`."""
    if rule.tool != "*" and rule.tool != record.tool:
        return NO_MATCH
    unknown = False
    for condition in rule.conditions:
        verdict = condition_verdict(condition, record, facts)
        if verdict == NO_MATCH:
            return NO_MATCH
        if verdict == UNKNOWN:
            unknown = True
    return UNKNOWN if unknown else MATCH


def replay_record(
    engine: PolicyEngine,
    rules: list[Rule],
    record: AuditRecord,
    facts: dict[str, bool] | None = None,
) -> tuple[PolicyAction | None, str | None, str]:
    """Re-evaluate one recorded decision. A None action means indeterminate.

    Args:
        engine: Engine built from the candidate policy.
        rules: `engine.compiled_rules`, hoisted so a whole log shares one list.
        record: The recorded decision.
        facts: Condition facts from `condition_facts`, if a baseline policy is
            available.

    Returns:
        `(action, rule_name, reason)`. On an indeterminate result the rule name
        is the first rule that could not be settled.
    """
    if record.arguments is not None:
        decision = engine.evaluate(record.tool or "", record.arguments)
        return decision.action, decision.rule_name, "replayed against recorded arguments"
    for rule in rules:
        verdict = rule_verdict(rule, record, facts)
        if verdict == MATCH:
            return rule.action, rule.name, "settled without argument values"
        if verdict == UNKNOWN:
            return None, rule.name, f"{rule.name} needs argument values this log does not carry"
    return PolicyAction.ALLOW, None, "every rule ruled out without argument values"


def _equivalent(recorded: AuditAction, new: PolicyAction) -> bool:
    if recorded is AuditAction.ALLOW:
        return new in (PolicyAction.ALLOW, PolicyAction.REDACT_OUTPUT)
    if recorded is AuditAction.BLOCK_POLICY:
        return new is PolicyAction.BLOCK
    return new is PolicyAction.REQUIRE_APPROVAL


def classify(recorded: AuditAction, new: PolicyAction | None) -> str:
    """Label how a candidate policy's action differs from what was recorded."""
    if new is None:
        return VERDICT_INDETERMINATE
    if _equivalent(recorded, new):
        return VERDICT_UNCHANGED
    if recorded is AuditAction.ALLOW and new in STOPPING_ACTIONS:
        return VERDICT_NEWLY_BLOCKED
    if recorded is not AuditAction.ALLOW and new not in STOPPING_ACTIONS:
        return VERDICT_NO_LONGER_BLOCKED
    return VERDICT_ACTION_CHANGED


def replay_policy(
    log: AuditLog,
    policy_path: Path | str,
    *,
    baseline_path: Path | str | None = None,
    max_samples: int = MAX_SAMPLES,
) -> PolicyDiff:
    """Replay every recorded policy decision against a candidate policy.

    Args:
        log: Records read by `read_log`.
        policy_path: Candidate policy to evaluate against.
        baseline_path: Policy that was in force when the log was recorded. With
            it, every recorded decision becomes an oracle over the conditions
            the two policies share, which is what makes most decisions
            determinate at all.
        max_samples: Cap on the changed-decision sample list.
    """
    engine, rules = load_rules(policy_path)
    baseline: list[Rule] = []
    if baseline_path is not None:
        _baseline_engine, baseline = load_rules(baseline_path)
    candidate_signatures = {
        condition_signature(condition) for rule in rules for condition in rule.conditions
    }
    baseline_signatures = {
        condition_signature(condition) for rule in baseline for condition in rule.conditions
    }

    counts: Counter[str] = Counter()
    blocking: Counter[str] = Counter()
    unreplayable: Counter[str] = Counter()
    samples: list[DecisionChange] = []
    considered = 0
    out_of_scope = 0
    from_oracle = 0

    for record in log.records:
        if not is_policy_decision(record):
            out_of_scope += 1
            continue
        considered += 1
        facts = condition_facts(baseline, record) if baseline else {}
        if facts and any(sig in candidate_signatures for sig in facts):
            from_oracle += 1
        action, rule_name, reason = replay_record(engine, rules, record, facts)
        verdict = classify(record.action, action)
        counts[verdict] += 1
        if verdict == VERDICT_INDETERMINATE and rule_name:
            unreplayable[rule_name] += 1
        if action in STOPPING_ACTIONS and rule_name:
            blocking[rule_name] += 1
        if verdict != VERDICT_UNCHANGED and len(samples) < max_samples:
            samples.append(
                DecisionChange(
                    seq=record.seq,
                    ts=record.ts,
                    tool=record.tool,
                    recorded_action=record.action.value,
                    recorded_rule=record.rule,
                    new_action=None if action is None else action.value,
                    new_rule=rule_name,
                    verdict=verdict,
                    reason=reason,
                )
            )

    fired = fired_rules(log)
    return PolicyDiff(
        policy=str(policy_path),
        baseline_policy=None if baseline_path is None else str(baseline_path),
        rules=len(rules),
        considered=considered,
        out_of_scope=out_of_scope,
        counts={name: counts.get(name, 0) for name in VERDICT_ORDER},
        samples=samples,
        blocking_rules=dict(blocking.most_common()),
        unreplayable_rules=dict(unreplayable.most_common()),
        never_fired_in_log=[rule.name for rule in rules if rule.name not in fired],
        constrained_by_recorded_outcome=from_oracle,
        shared_conditions=len(candidate_signatures & baseline_signatures),
    )


def build_report(
    log: AuditLog,
    *,
    bucket: str = DEFAULT_BUCKET,
    top: int = DEFAULT_TOP,
    baseline_policy: Path | str | None = None,
    candidate_policy: Path | str | None = None,
) -> ReplayReport:
    """Summarize a log, plus dead-rule and candidate-policy analysis if asked."""
    summary = summarize(log, bucket=bucket, top=top)
    fired = fired_rules(log)
    report = ReplayReport(summary=summary)
    if baseline_policy is not None:
        _engine, rules = load_rules(baseline_policy)
        known = {rule.name for rule in rules}
        report.baseline_policy = str(baseline_policy)
        report.dead_rules = [rule.name for rule in rules if rule.name not in fired]
        report.unmatched_fired_rules = sorted(fired - known)
    if candidate_policy is not None:
        report.diff = replay_policy(log, candidate_policy, baseline_path=baseline_policy)
    return report


def _counter_line(counts: dict[str, int], limit: int = DEFAULT_TOP) -> str:
    items = list(counts.items())[:limit]
    return ", ".join(f"{name} {count}" for name, count in items) or "none"


def render_text(report: ReplayReport) -> str:
    """Render a replay report as the plain-text console output."""
    summary = report.summary
    stats = summary.stats
    out: list[str] = []
    out.append(f"Audit replay: {', '.join(summary.sources) or '(none)'}")
    out.append(
        f"Lines: {stats.lines} read, {summary.records} records, "
        f"{stats.skipped} unparseable, {stats.blank} blank"
    )
    if stats.torn_tail:
        out.append("  final line was torn (no trailing newline); skipped")
    if stats.rejected:
        out.append(f"  {stats.rejected} line(s) parsed as JSON but did not validate as a record")
    if stats.unknown_field_records:
        out.append(
            f"  {stats.unknown_field_records} record(s) carried unknown fields "
            f"({', '.join(stats.unknown_field_names)}); dropped, record kept"
        )
    if not summary.records:
        out.append("No records; nothing to replay.")
        return "\n".join(out)

    out.append(f"Window: {summary.first_ts} -> {summary.last_ts} across {summary.runs} run(s)")
    out.append(f"Schema versions: {_counter_line(summary.schema_versions)}")
    out.append(f"Args modes: {_counter_line(summary.args_modes)}")
    out.append(f"Transports: {_counter_line(summary.transports)}")
    if len(summary.key_ids) > 1:
        out.append(f"HMAC key ids: {_counter_line(summary.key_ids)} (a rotated key breaks arg_hash correlation)")
    out.append("")

    out.append("Decisions by action:")
    for action, count in summary.actions.items():
        out.append(f"  {action:<18} {count}")
    out.append("")

    out.append(f"FAIL_OPEN (a rule crashed and traffic was allowed unchecked): {summary.fail_open}")
    for sample in summary.fail_open_samples:
        out.append(f"  {sample}")
    out.append(
        f"REQUIRE_APPROVAL over stdio (logged, allowed, never prompted): {summary.stdio_require_approval}"
    )
    if summary.stdio_require_approval_tools:
        out.append(f"  {_counter_line(summary.stdio_require_approval_tools)}")
    out.append("")

    out.append("Rules that fired:")
    if not summary.rules:
        out.append("  none")
    for usage in summary.rules:
        out.append(f"  {usage.rule:<28} {usage.count:>5}  ({_counter_line(usage.tools)})")
    out.append(f"Tools called: {_counter_line(summary.tools)}")
    out.append("")

    out.append("Decisions over time:")
    for slot in summary.buckets:
        out.append(
            f"  {slot.bucket:<18} {slot.total:>5} total  {slot.blocks:>4} block  "
            f"{slot.approvals:>4} approval  {slot.fail_open:>3} fail-open"
        )
    out.append("")

    if report.baseline_policy is not None:
        out.append(f"Dead rules in {report.baseline_policy} (never fired in this log): {len(report.dead_rules)}")
        for name in report.dead_rules:
            out.append(f"  {name}")
        if report.unmatched_fired_rules:
            out.append(
                "Rules that fired but are not in that policy "
                f"(renamed, removed, or a different policy was live): {', '.join(report.unmatched_fired_rules)}"
            )
        out.append("")

    if report.diff is not None:
        out.extend(_render_diff(report.diff))
    return "\n".join(out)


def _render_diff(diff: PolicyDiff) -> list[str]:
    out: list[str] = []
    out.append(f"Replay against {diff.policy} ({diff.rules} rules)")
    out.append(
        f"  {diff.considered} policy decisions replayed, {diff.out_of_scope} records out of scope "
        "(injection blocks, passthrough, invalid params, fail-open, output-side)"
    )
    if diff.baseline_policy is None:
        out.append(
            "  no --policy baseline given, so nothing is known about the arguments and almost "
            "every pattern rule is unsettleable. Pass the policy the log was recorded under."
        )
    else:
        out.append(
            f"  {diff.shared_conditions} condition(s) shared with the baseline policy; the recorded "
            f"outcome constrains a candidate condition on {diff.constrained_by_recorded_outcome} decision(s)"
        )
    for name in VERDICT_ORDER:
        out.append(f"  {name:<20} {diff.counts.get(name, 0)}")
    if diff.indeterminate:
        out.append(
            "  indeterminate means the deciding rule needs argument values this log does not "
            "carry. It is not a pass."
        )
        out.append(f"  rules that could not be settled: {_counter_line(diff.unreplayable_rules)}")
    if diff.never_fired_in_log:
        out.append(f"  candidate rules never seen firing in this log: {', '.join(diff.never_fired_in_log)}")
    if diff.samples:
        out.append("  changed decisions (sample):")
        for change in diff.samples:
            out.append(
                f"    seq={change.seq} {change.tool or '-'}: {change.recorded_action}"
                f"({change.recorded_rule or '-'}) -> {change.new_action or 'indeterminate'}"
                f"({change.new_rule or '-'}) [{change.verdict}] {change.reason}"
            )
    return out


__all__ = [
    "MATCH",
    "MAX_SAMPLES",
    "NO_MATCH",
    "UNKNOWN",
    "VERDICT_ACTION_CHANGED",
    "VERDICT_INDETERMINATE",
    "VERDICT_NEWLY_BLOCKED",
    "VERDICT_NO_LONGER_BLOCKED",
    "VERDICT_ORDER",
    "VERDICT_UNCHANGED",
    "AuditLog",
    "DecisionChange",
    "LogSummary",
    "PolicyDiff",
    "ReplayReport",
    "RuleUsage",
    "SkipStats",
    "TimeBucket",
    "bucket_key",
    "build_report",
    "classify",
    "condition_facts",
    "condition_signature",
    "condition_verdict",
    "dead_rules",
    "fired_rules",
    "is_policy_decision",
    "load_rules",
    "parse_record",
    "read_log",
    "render_text",
    "replay_policy",
    "replay_record",
    "rule_verdict",
    "summarize",
]
