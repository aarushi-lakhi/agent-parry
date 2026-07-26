"""Shared Pydantic models and constants for AgentParry."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

PROXY_PORT = 9090
MOCK_SERVER_PORT = 8080
PROXY_URL = "http://127.0.0.1:9090/mcp"
MOCK_SERVER_URL = "http://127.0.0.1:8080/mcp"

MATCHED_TEXT_LIMIT = 120

INJECTION_BLOCK_ERROR_CODE = -32001
"""Input-side block: the proxy refused to forward a tool call."""

RESULT_INJECTION_ERROR_CODE = -32002
"""Output-side block: the tool ran, and its result was refused.

Deliberately distinct from -32001 so an operator reading a log, and the scanner
reading a response, can tell which direction the block came from.
"""

METADATA_BLOCK_ERROR_CODE = -32003
"""Discovery-side block: a ``tools/list`` or ``initialize`` result was refused.

Its own code rather than -32002 because nothing was called: the poison is in the
tool catalogue, so an operator seeing this knows discovery failed, not a tool.
"""

PIN_BLOCK_ERROR_CODE = -32004
"""Pin-side block: discovery was refused because the pinned metadata changed.

Distinct from -32003 because nothing here failed a content scan. The catalogue
may be perfectly clean; it is simply not the catalogue that was pinned.
"""

TOOLS_CALL_METHOD = "tools/call"
TOOLS_LIST_METHOD = "tools/list"

MCP_EXACT_METHODS = frozenset(
    {
        "initialize",
        "initialized",
        "ping",
        "tools/list",
        TOOLS_CALL_METHOD,
    }
)

MCP_PASSTHROUGH_PREFIXES = (
    "notifications/",
    "resources/",
    "prompts/",
    "logging/",
    "completion/",
    "roots/",
    "sampling/",
)


def is_tools_call(method: str) -> bool:
    """True for tools/call, including case variants.

    JSON-RPC methods are case-sensitive, so this over-approximates on purpose:
    anything that could plausibly reach a lenient upstream as a tool call gets
    inspected rather than forwarded blind.
    """
    return method.casefold() == TOOLS_CALL_METHOD


# tools/ is never prefix-matched: a near-miss must not reach upstream uninspected.
def is_known_mcp_method(method: str) -> bool:
    """True for MCP methods safe to forward upstream without tool inspection."""
    if method in MCP_EXACT_METHODS:
        return True
    if method.casefold().startswith("tools/"):
        return False
    return method.startswith(MCP_PASSTHROUGH_PREFIXES)


class JsonRpcRequest(BaseModel):
    """Represents an incoming JSON-RPC 2.0 request."""

    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: dict[str, Any] | None = None
    id: int | str


class JsonRpcResponse(BaseModel):
    """Represents an outgoing JSON-RPC 2.0 response."""

    jsonrpc: Literal["2.0"] = "2.0"
    result: Any | None = None
    error: dict[str, Any] | None = None
    id: int | str


class JsonRpcError(BaseModel):
    """Represents a structured JSON-RPC error object."""

    code: int
    message: str
    data: Any | None = None


class PolicyAction(str, Enum):
    """Enumerates actions a policy engine can return."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REDACT_OUTPUT = "REDACT_OUTPUT"


class Finding(BaseModel):
    """Represents an individual security finding from policy checks.

    ``view``, ``matched_text`` and ``span`` describe where a match was found once
    normalization is in play. All three are defaulted so persisted scan-report
    JSON written before they existed still validates.
    """

    severity: Literal["low", "medium", "high", "critical"] = "low"
    description: str = ""
    field: str | None = None
    matched_pattern: str | None = None
    view: str = "original"
    matched_text: str | None = None
    span: tuple[int, int] | None = None

    @field_validator("matched_text")
    @classmethod
    def _truncate_matched_text(cls, value: str | None) -> str | None:
        """Cap quoted input so a finding cannot carry a whole payload into logs."""
        if value is None or len(value) <= MATCHED_TEXT_LIMIT:
            return value
        return value[:MATCHED_TEXT_LIMIT]


class PolicyDecision(BaseModel):
    """Represents the final policy decision for a request.

    ``findings`` carries the matches that produced the decision, each with the
    normalized view it was seen in and the span mapped back to the original
    argument. Defaulted empty, so a caller that only reads the action is
    unaffected and an ALLOW stays cheap.
    """

    action: PolicyAction = PolicyAction.ALLOW
    rule_name: str | None = None
    message: str = ""
    findings: list[Finding] = Field(default_factory=list)


AUDIT_SCHEMA_VERSION = 1

AUDIT_SEVERITY_ORDER = ("low", "medium", "high", "critical")


def max_severity(severities: Iterable[str]) -> str | None:
    """Return the highest severity present, or None for an empty input."""
    ranked = [s for s in severities if s in AUDIT_SEVERITY_ORDER]
    if not ranked:
        return None
    return max(ranked, key=AUDIT_SEVERITY_ORDER.index)


class AuditAction(str, Enum):
    """What a proxy actually did at one decision point.

    Deliberately not `PolicyAction`: injection blocks, invalid params, unknown
    methods and fail-open are not policy actions, and folding them into the
    policy enum would make the column ambiguous for a reader.
    """

    ALLOW = "ALLOW"
    BLOCK_POLICY = "BLOCK_POLICY"
    BLOCK_INJECTION = "BLOCK_INJECTION"
    BLOCK_RESULT_INJECTION = "BLOCK_RESULT_INJECTION"
    BLOCK_METADATA = "BLOCK_METADATA"
    BLOCK_PIN = "BLOCK_PIN"
    NEUTRALIZE_RESULT = "NEUTRALIZE_RESULT"
    REDACT_METADATA = "REDACT_METADATA"
    PIN_CREATED = "PIN_CREATED"
    PIN_DIFF = "PIN_DIFF"
    PIN_ACCEPTED = "PIN_ACCEPTED"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REDACT_OUTPUT = "REDACT_OUTPUT"
    INVALID_PARAMS = "INVALID_PARAMS"
    METHOD_NOT_FOUND = "METHOD_NOT_FOUND"
    PASSTHROUGH = "PASSTHROUGH"
    FAIL_OPEN = "FAIL_OPEN"
    POLICY_RELOAD = "POLICY_RELOAD"


class AuditTransport(str, Enum):
    """Which proxy emitted a record, or the CLI for an operator action."""

    HTTP = "http"
    STDIO = "stdio"
    CLI = "cli"


class AuditDirection(str, Enum):
    """Which leg of the hop a record describes."""

    CLIENT_TO_SERVER = "client->server"
    SERVER_TO_CLIENT = "server->client"


class AuditArgsMode(str, Enum):
    """How much of the tool arguments a record carries."""

    NONE = "none"
    PREVIEW = "preview"
    FULL = "full"


class AuditFinding(BaseModel):
    """One inspector or policy finding, summarized for the audit log.

    `pattern` is the regex source, never the matched text.
    """

    model_config = ConfigDict(extra="forbid")

    severity: str = "low"
    description: str = ""
    field: str | None = None
    pattern: str | None = None


class AuditRecord(BaseModel):
    """One append-only JSONL line describing a single policy decision.

    `extra="forbid"` so the round-trip test is meaningful. The compatibility
    rule is additive fields only; any rename or removal bumps
    `AUDIT_SCHEMA_VERSION`.

    `(run_id, seq)` is the ordering key. Wall-clock `ts` can step backwards
    under NTP, so it is a timestamp and not a sequence.

    `request_id` is stringified so the column type is stable across JSON-RPC
    ids that arrive as int and as str.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = AUDIT_SCHEMA_VERSION
    ts: str
    seq: int = 0
    run_id: str
    pid: int
    transport: AuditTransport
    direction: AuditDirection = AuditDirection.CLIENT_TO_SERVER
    action: AuditAction
    method: str | None = None
    tool: str | None = None
    rule: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    args_mode: AuditArgsMode = AuditArgsMode.NONE
    arg_hash: str | None = None
    arg_hash_key_id: str | None = None
    arg_keys: list[str] = Field(default_factory=list)
    arg_bytes: int | None = None
    arg_preview: str | None = None
    arguments: dict[str, Any] | None = None
    findings: list[AuditFinding] = Field(default_factory=list)
    finding_count: int = 0
    max_severity: str | None = None
    pii_redactions: int | None = None
    detail: str = ""


class ResultInspection(BaseModel):
    """Outcome of scanning one tool result for indirect prompt injection.

    ``action`` is what was actually done, not what was configured: block mode
    degrades to ``neutralize`` below critical severity, and any leaf whose
    severity is only medium is recorded and annotated without being rewritten.
    """

    result: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    action: Literal["none", "annotate", "neutralize", "redact", "block"] = "none"
    blocked: bool = False
    block_message: str = ""


class TerminalSanitization(BaseModel):
    """Outcome of removing terminal escape sequences from one tool result.

    ``action`` is what was actually done. ``escapes_removed`` counts sequences and
    stray control bytes, not leaves, and no field carries the removed text: an
    escape sequence quoted back into a log line or a report is the same attack
    against whatever renders that.
    """

    result: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    action: Literal["none", "annotate", "strip"] = "none"
    escapes_removed: int = 0
    fields: list[str] = Field(default_factory=list)


class MetadataInspection(BaseModel):
    """Outcome of scanning a ``tools/list`` or ``initialize`` result for poisoning.

    ``action`` is what was actually done, not what was configured: ``redact``
    escalates to ``drop`` for a finding in a structurally load-bearing value, and
    findings below the configured threshold are recorded without rewriting
    anything. ``dropped_tools`` and ``redacted_tools`` name the tools affected so
    an operator can tell which capability the agent just lost.
    """

    result: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    action: Literal["none", "annotate", "redact", "drop", "block"] = "none"
    blocked: bool = False
    block_message: str = ""
    redacted_tools: list[str] = Field(default_factory=list)
    dropped_tools: list[str] = Field(default_factory=list)


class AttackStep(BaseModel):
    """One ``tools/call`` inside a multi-step attack payload.

    ``arguments`` may carry ``{{stepN.path}}`` references, resolved against an
    earlier step's response before the call goes out. See
    :func:`src.scanner.substitute_step_refs` for the syntax.
    """

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    name: str = ""
    description: str = ""


PIN_SCHEMA_VERSION = 1


class ToolPin(BaseModel):
    """One pinned tool: the digest of its raw canonical JSON.

    Raw, not normalized. Hashing a normalized view would let an attacker flip
    zero-width characters freely and add invisible instructions to a description
    without changing the digest.
    """

    fingerprint: str
    updated: str = ""


class PinDiff(BaseModel):
    """What changed between a recorded pin and an observed catalogue.

    ``escalated`` holds the findings from re-inspecting only the changed metadata
    with every severity raised one level. It is an :class:`AuditFinding` and not a
    :class:`Finding` on purpose: that model has no ``matched_text`` field, so a
    pin file cannot grow a copy of the payload it is warning about.
    """

    changed: list[str] = Field(default_factory=list)
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    set_changed: bool = False
    server_info_changed: bool = False
    instructions_changed: bool = False
    escalated: list[AuditFinding] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True when nothing about the pinned metadata moved."""
        return not (
            self.changed
            or self.added
            or self.removed
            or self.set_changed
            or self.server_info_changed
            or self.instructions_changed
        )

    def summary(self) -> str:
        """One line naming what moved, for an audit detail or a CLI listing."""
        parts: list[str] = []
        if self.changed:
            parts.append(f"changed={','.join(self.changed)}")
        if self.added:
            parts.append(f"added={','.join(self.added)}")
        if self.removed:
            parts.append(f"removed={','.join(self.removed)}")
        if self.server_info_changed:
            parts.append("serverInfo=changed")
        if self.instructions_changed:
            parts.append("instructions=changed")
        if self.escalated:
            highest = max_severity(finding.severity for finding in self.escalated)
            parts.append(f"escalated={len(self.escalated)}@{highest}")
        return " ".join(parts) or "no change"

    def merge(self, other: PinDiff) -> PinDiff:
        """Union two diffs, so a pending tools diff survives an identity diff."""
        return PinDiff(
            changed=sorted(set(self.changed) | set(other.changed)),
            added=sorted(set(self.added) | set(other.added)),
            removed=sorted(set(self.removed) | set(other.removed)),
            set_changed=self.set_changed or other.set_changed,
            server_info_changed=self.server_info_changed or other.server_info_changed,
            instructions_changed=self.instructions_changed or other.instructions_changed,
            escalated=[*self.escalated, *other.escalated],
        )


class PinSnapshot(BaseModel):
    """An observed catalogue held aside until someone accepts it.

    Every fingerprint field is nullable because one observation only ever sees
    part of the picture: ``initialize`` carries identity and no tools, and a
    ``tools/list`` carries tools and nothing about identity. ``None`` means "this
    observation says nothing about that field", so accepting it leaves the pinned
    value alone.
    """

    observed_at: str = ""
    identity: bool = False
    set_fingerprint: str | None = None
    tool_count: int | None = None
    tools: dict[str, ToolPin] | None = None
    server_info: dict[str, Any] | None = None
    server_info_fingerprint: str | None = None
    instructions_fingerprint: str | None = None
    diff: PinDiff = Field(default_factory=PinDiff)


class ServerPin(BaseModel):
    """The pinned metadata of one MCP server, keyed on how it is launched.

    ``server_info`` is recorded but never keyed on: ``serverInfo.name`` is
    attacker-controlled, so keying on it would let a malicious server rename
    itself out of its own pin. Recorded inside the pin, a change to it is itself
    a reported diff.
    """

    key: str
    target: str = ""
    transport: AuditTransport = AuditTransport.STDIO
    created: str = ""
    updated: str = ""
    last_seen: str = ""
    trusted: bool = True
    untrusted_reason: str = ""
    tools_seen: bool = False
    identity_seen: bool = False
    set_fingerprint: str | None = None
    tool_count: int | None = None
    tools: dict[str, ToolPin] = Field(default_factory=dict)
    server_info: dict[str, Any] | None = None
    server_info_fingerprint: str | None = None
    instructions_fingerprint: str | None = None
    pending: PinSnapshot | None = None


class PinFile(BaseModel):
    """The whole on-disk pin store, merged per server key rather than overwritten."""

    schema_version: int = PIN_SCHEMA_VERSION
    servers: dict[str, ServerPin] = Field(default_factory=dict)


class PinObservation(BaseModel):
    """Outcome of checking one discovery response against the recorded pin.

    ``status`` is what happened to the pin, ``action`` what was done to the
    response. ``skipped`` means the store was unreadable or the lock was busy:
    pins are advisory and must never hold up the MCP stream. ``partial`` means
    the response was one page of a ``tools/list`` cursor walk that has not
    finished, so there is no catalogue to diff yet and nothing was written.

    ``paginated`` says the catalogue arrived over more than one page, on the
    buffered pages and on the completed observation alike.
    """

    status: Literal["off", "created", "unchanged", "changed", "skipped", "partial"] = "off"
    key: str = ""
    trusted: bool = True
    diff: PinDiff | None = None
    action: Literal["none", "warn", "redact_changed", "block"] = "none"
    blocked: bool = False
    block_message: str = ""
    redact_tools: list[str] = Field(default_factory=list)
    redact_instructions: bool = False
    paginated: bool = False
    detail: str = ""

    @property
    def reportable(self) -> bool:
        """True when an operator needs to hear about this observation."""
        return self.status in ("created", "changed") or not self.trusted


class AttackPayload(BaseModel):
    """Defines one scanner attack payload and expected behavior.

    ``steps`` turns the payload into a sequence: the scanner runs each step in
    order against the same target instead of issuing ``arguments`` as a single
    call. Empty for a single-step payload, so every payload and every persisted
    report written before sequences existed still validates.

    ``known_gap`` marks a payload no detection exists for yet. Those still run and
    still appear in the report, but they are held out of ``detection_rate`` unless
    asked for, so landing a batch of them cannot silently collapse the number CI
    gates on.
    """

    id: str
    name: str
    category: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_behavior: str = ""
    severity: str = "low"
    description: str = ""
    steps: list[AttackStep] = Field(default_factory=list)
    known_gap: bool = False


class AttackStepResult(BaseModel):
    """What the target did with one step of a sequence payload.

    ``arguments`` are the substituted ones actually sent, so a report shows what
    an earlier step fed forward. Empty on a step that never ran.
    """

    index: int
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    observed_behavior: str = ""
    outcome: str = ""
    executed: bool = False
    notes: str = ""
    error_code: int | None = None


class AttackResult(BaseModel):
    """Captures the observed result for a single attack payload.

    ``was_neutralized`` is its own flag rather than a second meaning for
    ``was_redacted``: an untrusted-content fence keeps the offending text and
    warns the model, while redaction removes it. Defaulted, so a report
    persisted before the flag existed still validates.
    """

    payload: AttackPayload
    was_blocked: bool = False
    was_redacted: bool = False
    was_neutralized: bool = False
    passed_through: bool = False
    evaluated_only: bool = False
    proxy_response: dict[str, Any] | None = None
    notes: str = ""
    observed_behavior: str = ""
    outcome: str = ""
    error_code: int | None = None
    step_results: list[AttackStepResult] = Field(default_factory=list)


class ConfusionMatrix(BaseModel):
    """Counts expected-versus-observed outcomes across one scan.

    ``neutralized`` cuts across the other five: it counts results the proxy
    fenced instead of blocking or redacting, whatever they scored. Without it a
    neutralize against an ``expected_behavior: block`` payload is a bare
    false_negative, indistinguishable from a payload nothing touched.

    ``known_gap`` also cuts across: it counts ``known_gap`` payloads whether or
    not they were folded into the other five, so a report can never show a
    detection rate without showing how many payloads it declined to grade.
    """

    true_block: int = 0
    false_negative: int = 0
    true_allow: int = 0
    false_positive: int = 0
    indeterminate: int = 0
    neutralized: int = 0
    known_gap: int = 0

    @property
    def attack_total(self) -> int:
        """Payloads that expected a block or a redaction and were observable."""

        return self.true_block + self.false_negative

    @property
    def benign_total(self) -> int:
        """Payloads that expected to be allowed and were observable."""

        return self.true_allow + self.false_positive

    @property
    def detection_rate(self) -> float | None:
        """Share of attacks actually stopped, or None with no observable attack."""

        if self.attack_total == 0:
            return None
        return round((self.true_block / self.attack_total) * 100, 1)

    @property
    def false_positive_rate(self) -> float | None:
        """Share of benign calls wrongly stopped, or None with no benign payload.

        None rather than 0.0 on an empty denominator: "no benign payloads" is
        not "zero over-blocking".
        """

        if self.benign_total == 0:
            return None
        return round((self.false_positive / self.benign_total) * 100, 1)

    @property
    def balanced_score(self) -> float | None:
        """Detection minus over-blocking, for when one number is unavoidable."""

        detection = self.detection_rate
        if detection is None:
            return None
        over_block = self.false_positive_rate
        if over_block is None:
            return detection
        return round(detection - over_block, 1)


class ScanReport(BaseModel):
    """Aggregates scanner outcomes for a complete attack run."""

    total_attacks: int = 0
    blocked: int = 0
    passed: int = 0
    redacted: int = 0
    neutralized: int = 0
    policy_allowed_safe: int = 0
    results: list[AttackResult] = Field(default_factory=list)
    vulnerability_score: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_url: str = ""
    safe_mode: bool = False
    discovered_tools: list[str] = Field(default_factory=list)
    matched_yaml_payloads: int = 0
    total_yaml_payloads: int = 0
    payload_stats: dict[str, Any] = Field(default_factory=dict)
    matrix: ConfusionMatrix | None = None
    attack_total: int = 0
    benign_total: int = 0
    known_gap_total: int = 0
    include_known_gaps: bool = False


class ProxyStats(BaseModel):
    """Tracks proxy-level counters and provides update helpers."""

    total_requests: int = 0
    blocked: int = 0
    approved: int = 0
    redacted: int = 0
    flagged_for_approval: int = 0
    result_injections: int = 0
    neutralized: int = 0
    metadata_injections: int = 0
    metadata_tools_dropped: int = 0
    pin_diffs: int = 0
    terminal_escapes_stripped: int = 0

    def increment(
        self,
        *,
        total_requests: int = 0,
        blocked: int = 0,
        approved: int = 0,
        redacted: int = 0,
        flagged_for_approval: int = 0,
        result_injections: int = 0,
        neutralized: int = 0,
        metadata_injections: int = 0,
        metadata_tools_dropped: int = 0,
        pin_diffs: int = 0,
        terminal_escapes_stripped: int = 0,
    ) -> None:
        """Increment one or more counters by non-negative deltas."""

        deltas = {
            "total_requests": total_requests,
            "blocked": blocked,
            "approved": approved,
            "redacted": redacted,
            "flagged_for_approval": flagged_for_approval,
            "result_injections": result_injections,
            "neutralized": neutralized,
            "metadata_injections": metadata_injections,
            "metadata_tools_dropped": metadata_tools_dropped,
            "pin_diffs": pin_diffs,
            "terminal_escapes_stripped": terminal_escapes_stripped,
        }

        for name, delta in deltas.items():
            if delta < 0:
                raise ValueError(f"{name} increment must be non-negative")

        self.total_requests += total_requests
        self.blocked += blocked
        self.approved += approved
        self.redacted += redacted
        self.flagged_for_approval += flagged_for_approval
        self.result_injections += result_injections
        self.neutralized += neutralized
        self.metadata_injections += metadata_injections
        self.metadata_tools_dropped += metadata_tools_dropped
        self.pin_diffs += pin_diffs
        self.terminal_escapes_stripped += terminal_escapes_stripped

    def reset(self) -> None:
        """Reset all counters to zero."""

        self.total_requests = 0
        self.blocked = 0
        self.approved = 0
        self.redacted = 0
        self.flagged_for_approval = 0
        self.result_injections = 0
        self.neutralized = 0
        self.metadata_injections = 0
        self.metadata_tools_dropped = 0
        self.pin_diffs = 0
        self.terminal_escapes_stripped = 0


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "AUDIT_SEVERITY_ORDER",
    "INJECTION_BLOCK_ERROR_CODE",
    "MATCHED_TEXT_LIMIT",
    "MCP_EXACT_METHODS",
    "MCP_PASSTHROUGH_PREFIXES",
    "METADATA_BLOCK_ERROR_CODE",
    "MOCK_SERVER_PORT",
    "MOCK_SERVER_URL",
    "PIN_BLOCK_ERROR_CODE",
    "PIN_SCHEMA_VERSION",
    "PROXY_PORT",
    "PROXY_URL",
    "RESULT_INJECTION_ERROR_CODE",
    "TOOLS_CALL_METHOD",
    "TOOLS_LIST_METHOD",
    "AttackPayload",
    "AttackResult",
    "AttackStep",
    "AttackStepResult",
    "AuditAction",
    "AuditArgsMode",
    "AuditDirection",
    "AuditFinding",
    "AuditRecord",
    "AuditTransport",
    "ConfusionMatrix",
    "Finding",
    "JsonRpcError",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "MetadataInspection",
    "PinDiff",
    "PinFile",
    "PinObservation",
    "PinSnapshot",
    "PolicyAction",
    "PolicyDecision",
    "ProxyStats",
    "ResultInspection",
    "ScanReport",
    "ServerPin",
    "TerminalSanitization",
    "ToolPin",
    "is_known_mcp_method",
    "is_tools_call",
    "max_severity",
]
