"""Security proxy that intercepts and inspects agent-to-tool traffic."""

from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import FastAPI
from rich.console import Console

from src.inspector import InputInspector, OutputInspector
from src.models import MOCK_SERVER_URL, JsonRpcRequest, JsonRpcResponse, PolicyAction, ProxyStats
from src.policy import PolicyEngine

app = FastAPI(title="AgentParry Proxy", version="1.0")
console = Console()
policy_engine = PolicyEngine()
input_inspector = InputInspector()
output_inspector = OutputInspector()
stats = ProxyStats()


def _jsonrpc_error(*, request_id: int | str, code: int, message: str, data: Any | None = None) -> JsonRpcResponse:
    return JsonRpcResponse(
        id=request_id,
        error={
            "code": code,
            "message": message,
            "data": data,
        },
    )


def _compact_args(arguments: dict[str, Any]) -> str:
    return json.dumps(arguments, separators=(", ", ": "), ensure_ascii=True)


def _print_log_line(line: str) -> None:
    try:
        console.print(line)
    except UnicodeEncodeError:
        fallback = line.encode("ascii", errors="replace").decode("ascii")
        console.file.write(f"{fallback}\n")


def _log_allow(tool_name: str, arguments: dict[str, Any]) -> None:
    _print_log_line(f"[ALLOW]   {tool_name:<10} {_compact_args(arguments)}")


def _log_block(tool_name: str, arguments: dict[str, Any], reason: str) -> None:
    _print_log_line(f"[BLOCK]   {tool_name:<10} {_compact_args(arguments)}  <- {reason}")


def _log_approve(tool_name: str, arguments: dict[str, Any], reason: str) -> None:
    _print_log_line(f"[APPROVE] {tool_name:<10} {_compact_args(arguments)}  <- {reason}")


def _log_redact(tool_name: str, count: int) -> None:
    _print_log_line(f"[REDACT]  {tool_name:<10} ({count} PII items redacted)")


def _log_inject(tool_name: str) -> None:
    _print_log_line(f"[INJECT]  {tool_name:<10} prompt injection detected (critical)")


def _get_tool_payload(request: JsonRpcRequest) -> tuple[str | None, dict[str, Any] | None]:
    params = request.params or {}
    tool_name = params.get("name")
    arguments = params.get("arguments")
    if not isinstance(tool_name, str):
        return None, None
    if not isinstance(arguments, dict):
        return tool_name, None
    return tool_name, arguments


def _forward_to_upstream(payload: dict[str, Any]) -> dict[str, Any]:
    with httpx.Client(timeout=20.0) as client:
        response = client.post(MOCK_SERVER_URL, json=payload)
        response.raise_for_status()
        return response.json()


@app.get("/health")
def health() -> dict[str, str]:
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get(MOCK_SERVER_URL.replace("/mcp", "/health"))
            response.raise_for_status()
        upstream = "connected"
    except Exception:
        upstream = "disconnected"
    return {"status": "ok", "upstream": upstream}


@app.get("/stats")
def get_stats() -> dict[str, int]:
    return stats.model_dump()


@app.post("/policy/reload")
def reload_policy() -> dict[str, Any]:
    policy_engine.reload()
    return {"status": "ok", "rules_loaded": len(policy_engine.get_rules())}


@app.get("/policy/rules")
def list_rules() -> dict[str, Any]:
    return {"rules": policy_engine.get_rules()}


@app.post("/mcp")
def mcp(request: JsonRpcRequest) -> JsonRpcResponse:
    if request.method in {"initialize", "tools/list"}:
        upstream_payload = _forward_to_upstream(request.model_dump())
        return JsonRpcResponse.model_validate(upstream_payload)

    if request.method != "tools/call":
        return _jsonrpc_error(
            request_id=request.id,
            code=-32601,
            message=f"Method not found: {request.method}",
        )

    stats.increment(total_requests=1)
    tool_name, arguments = _get_tool_payload(request)
    if tool_name is None:
        return _jsonrpc_error(
            request_id=request.id,
            code=-32602,
            message="Invalid params: 'name' must be a string.",
        )
    if arguments is None:
        return _jsonrpc_error(
            request_id=request.id,
            code=-32602,
            message="Invalid params: 'arguments' must be an object.",
        )

    injection_findings = input_inspector.inspect(tool_name, arguments)
    if any(finding.severity == "critical" for finding in injection_findings):
        stats.increment(blocked=1)
        _log_inject(tool_name)
        return _jsonrpc_error(
            request_id=request.id,
            code=-32001,
            message="Blocked: critical prompt injection pattern detected",
        )

    decision = policy_engine.evaluate(tool_name, arguments)
    if decision.action == PolicyAction.BLOCK:
        stats.increment(blocked=1)
        _log_block(tool_name, arguments, decision.rule_name or "policy_block")
        return _jsonrpc_error(
            request_id=request.id,
            code=-32001,
            message=decision.message or "Blocked by policy",
        )

    if decision.action == PolicyAction.REQUIRE_APPROVAL:
        stats.increment(flagged_for_approval=1, approved=1)
        _log_approve(tool_name, arguments, decision.rule_name or "requires_approval")
    else:
        _log_allow(tool_name, arguments)

    upstream_payload = _forward_to_upstream(request.model_dump())
    result_payload = upstream_payload.get("result")
    if not isinstance(result_payload, dict):
        return JsonRpcResponse.model_validate(upstream_payload)

    sanitized_result, pii_findings = output_inspector.inspect(tool_name, result_payload)
    if pii_findings:
        stats.increment(redacted=1)
        _log_redact(tool_name, len(pii_findings))
        upstream_payload["result"] = sanitized_result

    return JsonRpcResponse.model_validate(upstream_payload)
