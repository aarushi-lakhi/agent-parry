"""Shared Pydantic models and constants for AgentParry."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

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
    result_injections: int = 0
    neutralized: int = 0
    metadata_injections: int = 0
    metadata_tools_dropped: int = 0

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


__all__ = [
    "INJECTION_BLOCK_ERROR_CODE",
    "MATCHED_TEXT_LIMIT",
    "METADATA_BLOCK_ERROR_CODE",
    "MOCK_SERVER_PORT",
    "MOCK_SERVER_URL",
    "PROXY_PORT",
    "PROXY_URL",
    "RESULT_INJECTION_ERROR_CODE",
    "AttackPayload",
    "AttackResult",
    "Finding",
    "JsonRpcError",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "MetadataInspection",
    "PolicyAction",
    "PolicyDecision",
    "ProxyStats",
    "ResultInspection",
    "ScanReport",
]
