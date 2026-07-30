"""Shared Pydantic models and constants for AgentParry."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

PROXY_PORT = 9090
MOCK_SERVER_PORT = 8080
PROXY_URL = "http://127.0.0.1:9090/mcp"
MOCK_SERVER_URL = "http://127.0.0.1:8080/mcp"

TOOLS_CALL_METHOD = "tools/call"

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


class PolicyDecision(BaseModel):
    """Represents the final policy decision for a request."""

    action: PolicyAction = PolicyAction.ALLOW
    rule_name: str | None = None
    message: str = ""


class Finding(BaseModel):
    """Represents an individual security finding from policy checks."""

    severity: Literal["low", "medium", "high", "critical"] = "low"
    description: str = ""
    field: str | None = None
    matched_pattern: str | None = None


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
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REDACT_OUTPUT = "REDACT_OUTPUT"
    INVALID_PARAMS = "INVALID_PARAMS"
    METHOD_NOT_FOUND = "METHOD_NOT_FOUND"
    PASSTHROUGH = "PASSTHROUGH"
    FAIL_OPEN = "FAIL_OPEN"


class AuditTransport(str, Enum):
    """Which proxy emitted a record."""

    HTTP = "http"
    STDIO = "stdio"


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


class AttackPayload(BaseModel):
    """Defines one scanner attack payload and expected behavior."""

    id: str
    name: str
    category: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_behavior: str = ""
    severity: str = "low"
    description: str = ""


class AttackResult(BaseModel):
    """Captures the observed result for a single attack payload."""

    payload: AttackPayload
    was_blocked: bool = False
    was_redacted: bool = False
    passed_through: bool = False
    evaluated_only: bool = False
    proxy_response: dict[str, Any] | None = None
    notes: str = ""


class ScanReport(BaseModel):
    """Aggregates scanner outcomes for a complete attack run."""

    total_attacks: int = 0
    blocked: int = 0
    passed: int = 0
    redacted: int = 0
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


class ProxyStats(BaseModel):
    """Tracks proxy-level counters and provides update helpers."""

    total_requests: int = 0
    blocked: int = 0
    approved: int = 0
    redacted: int = 0
    flagged_for_approval: int = 0

    def increment(
        self,
        *,
        total_requests: int = 0,
        blocked: int = 0,
        approved: int = 0,
        redacted: int = 0,
        flagged_for_approval: int = 0,
    ) -> None:
        """Increment one or more counters by non-negative deltas."""

        deltas = {
            "total_requests": total_requests,
            "blocked": blocked,
            "approved": approved,
            "redacted": redacted,
            "flagged_for_approval": flagged_for_approval,
        }

        for name, delta in deltas.items():
            if delta < 0:
                raise ValueError(f"{name} increment must be non-negative")

        self.total_requests += total_requests
        self.blocked += blocked
        self.approved += approved
        self.redacted += redacted
        self.flagged_for_approval += flagged_for_approval

    def reset(self) -> None:
        """Reset all counters to zero."""

        self.total_requests = 0
        self.blocked = 0
        self.approved = 0
        self.redacted = 0
        self.flagged_for_approval = 0


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "AUDIT_SEVERITY_ORDER",
    "MCP_EXACT_METHODS",
    "MCP_PASSTHROUGH_PREFIXES",
    "MOCK_SERVER_PORT",
    "MOCK_SERVER_URL",
    "PROXY_PORT",
    "PROXY_URL",
    "TOOLS_CALL_METHOD",
    "AttackPayload",
    "AttackResult",
    "AuditAction",
    "AuditArgsMode",
    "AuditDirection",
    "AuditFinding",
    "AuditRecord",
    "AuditTransport",
    "Finding",
    "JsonRpcError",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "PolicyAction",
    "PolicyDecision",
    "ProxyStats",
    "ScanReport",
    "is_known_mcp_method",
    "is_tools_call",
    "max_severity",
]
