"""Shared Pydantic models and constants for AgentParry."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


PROXY_PORT = 9090
MOCK_SERVER_PORT = 8080
PROXY_URL = "http://localhost:9090/mcp"
MOCK_SERVER_URL = "http://localhost:8080/mcp"


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


class AttackPayload(BaseModel):
    """Defines one scanner attack payload and expected behavior."""

    id: str
    name: str
    category: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_behavior: str = ""
    severity: str = "low"


class AttackResult(BaseModel):
    """Captures the observed result for a single attack payload."""

    payload: AttackPayload
    was_blocked: bool = False
    was_redacted: bool = False
    passed_through: bool = False
    proxy_response: dict[str, Any] | None = None
    notes: str = ""


class ScanReport(BaseModel):
    """Aggregates scanner outcomes for a complete attack run."""

    total_attacks: int = 0
    blocked: int = 0
    passed: int = 0
    redacted: int = 0
    results: list[AttackResult] = Field(default_factory=list)
    vulnerability_score: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


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
    "PROXY_PORT",
    "MOCK_SERVER_PORT",
    "PROXY_URL",
    "MOCK_SERVER_URL",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "JsonRpcError",
    "PolicyAction",
    "PolicyDecision",
    "Finding",
    "AttackPayload",
    "AttackResult",
    "ScanReport",
    "ProxyStats",
]
