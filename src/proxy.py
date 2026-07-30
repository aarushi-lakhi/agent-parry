"""Security proxy that intercepts and inspects agent-to-tool traffic."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shlex
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError
from rich.console import Console
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware

from src import audit
from src.inspector import InputInspector, OutputInspector, ResultInspector
from src.models import (
    INJECTION_BLOCK_ERROR_CODE,
    MOCK_SERVER_URL,
    RESULT_INJECTION_ERROR_CODE,
    AuditAction,
    AuditDirection,
    AuditRecord,
    Finding,
    JsonRpcRequest,
    JsonRpcResponse,
    PolicyAction,
    ProxyStats,
    is_known_mcp_method,
    is_tools_call,
)
from src.policy import PolicyEngine

DEFAULT_POLICY_PATH = "config/default_policy.yaml"


def _policy_path() -> str:
    """Resolve the policy file, matching the stdio proxy's precedence."""
    return os.environ.get("AGENTPARRY_POLICY", "").strip() or DEFAULT_POLICY_PATH


app = FastAPI(title="AgentParry Proxy", version="1.0")
console = Console()
policy_engine = PolicyEngine(policy_path=_policy_path())
input_inspector = InputInspector()
output_inspector = OutputInspector()
result_inspector = ResultInspector.from_policy_settings(policy_engine.get_settings())
stats = ProxyStats()

_stdio_server: subprocess.Popen[bytes] | None = None
_stdio_lock = threading.Lock()


class UpstreamConfigurationError(Exception):
    """Raised when AGENTPARRY_UPSTREAM_CMD and AGENTPARRY_UPSTREAM_URL are both set."""


def _upstream_cmd() -> str:
    return os.environ.get("AGENTPARRY_UPSTREAM_CMD", "").strip()


def _upstream_url_env() -> str:
    return os.environ.get("AGENTPARRY_UPSTREAM_URL", "").strip()


def _upstream_config_conflict_message() -> str | None:
    if _upstream_cmd() and _upstream_url_env():
        return "Set only one of AGENTPARRY_UPSTREAM_CMD or AGENTPARRY_UPSTREAM_URL"
    return None


def _effective_http_mcp_url() -> str:
    return _upstream_url_env() or MOCK_SERVER_URL


def _health_probe_url(mcp_url: str) -> str | None:
    if "/mcp" in mcp_url:
        return mcp_url.replace("/mcp", "/health", 1)
    parts = urlsplit(mcp_url)
    if parts.scheme and parts.netloc:
        return urlunsplit((parts.scheme, parts.netloc, "/health", "", ""))
    return None


def _drain_stderr(proc: subprocess.Popen[bytes]) -> None:
    if proc.stderr is None:
        return
    try:
        while proc.stderr.readline():
            pass
    except Exception:
        pass


def _ensure_stdio_server() -> subprocess.Popen[bytes]:
    global _stdio_server
    if _stdio_server is not None and _stdio_server.poll() is None:
        return _stdio_server
    _stdio_server = None
    raw = os.environ["AGENTPARRY_UPSTREAM_CMD"].strip()
    argv = shlex.split(raw, posix=(os.name != "nt"))
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    threading.Thread(target=_drain_stderr, args=(proc,), daemon=True).start()
    _stdio_server = proc
    return proc


def _forward_via_stdio(payload: dict[str, Any]) -> dict[str, Any]:
    line = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    if "\n" in line or "\r" in line:
        raise ValueError("JSON-RPC payload must not contain embedded newlines for stdio transport")
    req_id = payload.get("id")
    with _stdio_lock:
        proc = _ensure_stdio_server()
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("MCP stdio subprocess missing stdin/stdout")
        proc.stdin.write(line.encode("utf-8") + b"\n")
        proc.stdin.flush()
        while True:
            out = proc.stdout.readline()
            if not out:
                raise RuntimeError("EOF from MCP stdio server")
            try:
                msg: Any = json.loads(out.decode("utf-8"))
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            if "id" not in msg:
                continue
            if msg.get("id") == req_id:
                return msg


def _cors_origins(raw: str | None = None) -> list[str]:
    """Parse AGENTPARRY_CORS_ORIGINS into an explicit origin allowlist."""
    source = os.environ.get("AGENTPARRY_CORS_ORIGINS", "") if raw is None else raw
    return [origin.strip() for origin in source.split(",") if origin.strip()]


def _admin_token() -> str:
    return os.environ.get("AGENTPARRY_ADMIN_TOKEN", "").strip()


def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth.removeprefix("Bearer ").strip()


def require_admin(request: Request) -> None:
    """Gate the /policy control plane. Fails closed when no admin token is set."""
    expected = _admin_token()
    if not expected:
        raise HTTPException(
            status_code=403,
            detail="AGENTPARRY_ADMIN_TOKEN is not set; the /policy control plane is disabled",
        )
    origin = request.headers.get("origin")
    if origin and origin not in _cors_origins():
        raise HTTPException(status_code=403, detail="Cross-origin policy request refused")
    presented = _bearer_token(request)
    if presented is None or not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


class _BearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        expected = os.environ.get("AGENTPARRY_AUTH_TOKEN", "").strip()
        if expected and request.method != "OPTIONS":
            presented = _bearer_token(request)
            if presented is None or not secrets.compare_digest(presented, expected):
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)


app.add_middleware(_BearerAuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Accept",
        "Mcp-Session-Id",
        "Authorization",
        "AgentParry-Safe-Scan",
    ],
)


def _jsonrpc_error(*, request_id: int | str, code: int, message: str, data: Any | None = None) -> JsonRpcResponse:
    return JsonRpcResponse(
        id=request_id,
        error={
            "code": code,
            "message": message,
            "data": data,
        },
    )


def _print_log_line(line: str) -> None:
    try:
        console.print(line, markup=False, highlight=False)
    except UnicodeEncodeError:
        fallback = line.encode("ascii", errors="replace").decode("ascii")
        console.file.write(f"{fallback}\n")


def _record(
    action: AuditAction,
    *,
    direction: AuditDirection = AuditDirection.CLIENT_TO_SERVER,
    method: str | None = None,
    tool: str | None = None,
    arguments: dict[str, Any] | None = None,
    rule: str | None = None,
    request_id: Any = None,
    session_id: str | None = None,
    findings: list[Finding] | None = None,
    pii_redactions: int | None = None,
    detail: str = "",
) -> AuditRecord:
    """Audit one already-computed decision and print the derived console line.

    The single logging path for this module. The five `_log_*` helpers it
    replaced were one of the two independent formatting paths whose divergence
    the audit log exists to fix; a third would recreate it.
    """
    writer = audit.get_writer()
    record = writer.build(
        action=action,
        direction=direction,
        method=method,
        tool=tool,
        rule=rule,
        request_id=request_id,
        session_id=session_id,
        arguments=arguments,
        findings=findings,
        pii_redactions=pii_redactions,
        detail=detail,
    )
    writer.write(record)
    line = audit.format_console_line(record, arguments=arguments)
    if line is not None:
        _print_log_line(line)
    return record


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
    conflict = _upstream_config_conflict_message()
    if conflict:
        raise UpstreamConfigurationError(conflict)
    if _upstream_cmd():
        return _forward_via_stdio(payload)
    url = _effective_http_mcp_url()
    with httpx.Client(timeout=20.0) as client:
        response = client.post(url, json=payload)
        response.raise_for_status()
        return response.json()


def _resolve_session_id(*, rpc_method: str, incoming_session: str | None) -> str | None:
    """Resolve the session id before dispatch so audit records can carry it.

    initialize mints its id here rather than in the response-header helper,
    which is the only way the record and the Mcp-Session-Id header can agree.
    """
    if rpc_method == "initialize":
        return str(uuid.uuid4())
    return incoming_session


def _mcp_session_response_headers(*, rpc_method: str, session_id: str | None) -> dict[str, str]:
    if rpc_method == "initialize":
        return {"Mcp-Session-Id": session_id or str(uuid.uuid4())}
    if session_id:
        return {"Mcp-Session-Id": session_id}
    return {}


def _safe_scan_truthy(value: str | None) -> bool:
    if value is None or not value.strip():
        return False
    return value.strip().lower() in ("1", "true", "yes", "on")


def _validated_response(request_id: int | str, upstream_payload: dict[str, Any]) -> JsonRpcResponse:
    """Validate an upstream response, surfacing a JSON-RPC error instead of a 500.

    JsonRpcResponse requires an id, so an upstream that answers without one
    would otherwise raise ValidationError out of the request handler.
    """
    try:
        return JsonRpcResponse.model_validate(upstream_payload)
    except ValidationError:
        return _jsonrpc_error(
            request_id=request_id,
            code=-32603,
            message="Malformed response from upstream MCP server",
        )


def _handle_mcp_rpc(
    request: JsonRpcRequest,
    *,
    safe_scan: bool = False,
    session_id: str | None = None,
) -> JsonRpcResponse:
    audit_ctx: dict[str, Any] = {
        "method": request.method,
        "request_id": request.id,
        "session_id": session_id,
    }
    if not is_tools_call(request.method):
        if not is_known_mcp_method(request.method):
            _record(AuditAction.METHOD_NOT_FOUND, detail="method not in the MCP allowlist", **audit_ctx)
            return _jsonrpc_error(
                request_id=request.id,
                code=-32601,
                message=f"Method not found: {request.method}",
            )
        _record(AuditAction.PASSTHROUGH, detail="known MCP method forwarded without tool inspection", **audit_ctx)
        upstream_payload = _forward_to_upstream(request.model_dump())
        return _validated_response(request.id, upstream_payload)

    stats.increment(total_requests=1)
    tool_name, arguments = _get_tool_payload(request)
    if tool_name is None:
        _record(AuditAction.INVALID_PARAMS, detail="'name' must be a string", **audit_ctx)
        return _jsonrpc_error(
            request_id=request.id,
            code=-32602,
            message="Invalid params: 'name' must be a string.",
        )
    if arguments is None:
        _record(AuditAction.INVALID_PARAMS, tool=tool_name, detail="'arguments' must be an object", **audit_ctx)
        return _jsonrpc_error(
            request_id=request.id,
            code=-32602,
            message="Invalid params: 'arguments' must be an object.",
        )

    injection_findings = input_inspector.inspect(tool_name, arguments)
    if any(finding.severity == "critical" for finding in injection_findings):
        stats.increment(blocked=1)
        _record(
            AuditAction.BLOCK_INJECTION,
            tool=tool_name,
            arguments=arguments,
            findings=injection_findings,
            detail="critical prompt injection pattern",
            **audit_ctx,
        )
        return _jsonrpc_error(
            request_id=request.id,
            code=INJECTION_BLOCK_ERROR_CODE,
            message="Blocked: critical prompt injection pattern detected",
        )

    decision = policy_engine.evaluate(tool_name, arguments)
    if decision.action == PolicyAction.BLOCK:
        stats.increment(blocked=1)
        _record(
            AuditAction.BLOCK_POLICY,
            tool=tool_name,
            arguments=arguments,
            rule=decision.rule_name or "policy_block",
            findings=injection_findings,
            detail=decision.message,
            **audit_ctx,
        )
        return _jsonrpc_error(
            request_id=request.id,
            code=INJECTION_BLOCK_ERROR_CODE,
            message=decision.message or "Blocked by policy",
        )

    forwarding = "policy evaluated only (safe scan)" if safe_scan else "forwarded upstream"
    if decision.action == PolicyAction.REQUIRE_APPROVAL:
        stats.increment(flagged_for_approval=1, approved=1)
        _record(
            AuditAction.REQUIRE_APPROVAL,
            tool=tool_name,
            arguments=arguments,
            rule=decision.rule_name or "requires_approval",
            findings=injection_findings,
            detail=f"policy asked REQUIRE_APPROVAL; auto-approved and {forwarding}",
            **audit_ctx,
        )
    else:
        _record(
            AuditAction.ALLOW,
            tool=tool_name,
            arguments=arguments,
            rule=decision.rule_name,
            findings=injection_findings,
            detail=f"policy {decision.action.value}; {forwarding}",
            **audit_ctx,
        )

    if safe_scan:
        return JsonRpcResponse(
            id=request.id,
            result={"_agentparry": {"safe_scan": True, "would_forward": True}},
        )

    upstream_payload = _forward_to_upstream(request.model_dump())
    result_payload = upstream_payload.get("result")
    if not isinstance(result_payload, dict):
        return _validated_response(request.id, upstream_payload)

    sanitized_result, pii_findings = output_inspector.inspect(tool_name, result_payload)
    if pii_findings:
        stats.increment(redacted=1)
        _record(
            AuditAction.REDACT_OUTPUT,
            direction=AuditDirection.SERVER_TO_CLIENT,
            tool=tool_name,
            findings=pii_findings,
            pii_redactions=len(pii_findings),
            detail="PII redacted from tool result",
            **audit_ctx,
        )

    # PII first, so the injection scan sees the text the model will actually see.
    inspection = result_inspector.inspect(tool_name, sanitized_result)
    if inspection.findings:
        stats.increment(result_injections=1)
        if inspection.action in ("neutralize", "redact"):
            stats.increment(neutralized=1)
        _record(
            AuditAction.BLOCK_RESULT_INJECTION if inspection.blocked else AuditAction.NEUTRALIZE_RESULT,
            direction=AuditDirection.SERVER_TO_CLIENT,
            tool=tool_name,
            findings=inspection.findings,
            detail=f"{inspection.action}: {len(inspection.findings)} injection finding(s) in tool result",
            **audit_ctx,
        )
    if inspection.blocked:
        stats.increment(blocked=1)
        return _jsonrpc_error(
            request_id=request.id,
            code=RESULT_INJECTION_ERROR_CODE,
            message=inspection.block_message,
        )

    upstream_payload["result"] = inspection.result
    return _validated_response(request.id, upstream_payload)


@app.get("/health")
def health() -> dict[str, str]:
    if _upstream_config_conflict_message():
        return {"status": "ok", "upstream": "misconfigured"}
    if _upstream_cmd():
        proc = _stdio_server
        if proc is not None and proc.poll() is None:
            return {"status": "ok", "upstream": "connected"}
        return {"status": "ok", "upstream": "disconnected"}
    mcp_url = _effective_http_mcp_url()
    probe = _health_probe_url(mcp_url)
    if probe is None:
        return {"status": "ok", "upstream": "unknown"}
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get(probe)
            response.raise_for_status()
        return {"status": "ok", "upstream": "connected"}
    except Exception:
        return {"status": "ok", "upstream": "disconnected"}


@app.get("/stats")
def get_stats() -> dict[str, int]:
    return stats.model_dump()


def _rebuild_inspectors() -> None:
    """Rebuild the settings-derived inspectors after a policy load."""
    global result_inspector
    result_inspector = ResultInspector.from_policy_settings(policy_engine.get_settings())


def set_policy_path(path: str) -> None:
    """Repoint the live policy engine and reload it.

    The engine is built at import time, so main() has to call this after
    parsing --policy; setting the env var alone would come too late.
    """
    os.environ["AGENTPARRY_POLICY"] = path
    policy_engine.policy_path = Path(path)
    policy_engine.reload()
    _rebuild_inspectors()


@app.post("/policy/reload", dependencies=[Depends(require_admin)])
def reload_policy() -> dict[str, Any]:
    policy_engine.reload()
    _rebuild_inspectors()
    return {"status": "ok", "rules_loaded": len(policy_engine.get_rules())}


@app.get("/policy/rules", dependencies=[Depends(require_admin)])
def list_rules() -> dict[str, Any]:
    return {"rules": policy_engine.get_rules()}


@app.get("/mcp")
async def mcp_get() -> StreamingResponse:
    async def keepalive() -> Any:
        yield ": open\n\n"
        while True:
            await asyncio.sleep(30)
            yield ": keepalive\n\n"

    return StreamingResponse(keepalive(), media_type="text/event-stream")


@app.delete("/mcp")
def mcp_delete() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/mcp")
async def mcp_post(request: Request) -> Response:
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"detail": "Invalid JSON body"}, status_code=400)
    except Exception:
        return JSONResponse({"detail": "Invalid JSON body"}, status_code=400)

    try:
        rpc_req = JsonRpcRequest.model_validate(body)
    except ValidationError as exc:
        return JSONResponse({"detail": exc.errors()}, status_code=422)

    safe_hdr = request.headers.get("agentparry-safe-scan") or request.headers.get("AgentParry-Safe-Scan")
    safe_scan = _safe_scan_truthy(safe_hdr)
    incoming = request.headers.get("mcp-session-id")
    session_id = _resolve_session_id(rpc_method=rpc_req.method, incoming_session=incoming)
    try:
        rpc_resp = _handle_mcp_rpc(rpc_req, safe_scan=safe_scan, session_id=session_id)
    except UpstreamConfigurationError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=503)
    rpc_dict = rpc_resp.model_dump(mode="json")
    extra_headers = _mcp_session_response_headers(rpc_method=rpc_req.method, session_id=session_id)
    accept = (request.headers.get("accept") or "").lower()
    wants_sse = "text/event-stream" in accept

    if wants_sse:
        line = json.dumps(rpc_dict, separators=(",", ":"), ensure_ascii=True)
        content = f"event: message\ndata: {line}\n\n"
        return Response(content=content, media_type="text/event-stream", headers=extra_headers)

    return JSONResponse(rpc_dict, headers=extra_headers)


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentParry MCP security proxy")
    parser.add_argument(
        "--upstream-url",
        default=None,
        metavar="URL",
        help="Forward JSON-RPC to this HTTP MCP endpoint (or set AGENTPARRY_UPSTREAM_URL)",
    )
    parser.add_argument(
        "--upstream-command",
        default=None,
        metavar="CMD",
        help="Run this command as stdio MCP server (or set AGENTPARRY_UPSTREAM_CMD)",
    )
    parser.add_argument(
        "--policy",
        default=None,
        metavar="PATH",
        help=f"Policy YAML (default: {DEFAULT_POLICY_PATH}, or AGENTPARRY_POLICY)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=9090, help="Bind port")
    parser.add_argument("--log-level", default="info", help="Uvicorn log level")
    args = parser.parse_args()
    if args.upstream_url is not None:
        os.environ["AGENTPARRY_UPSTREAM_URL"] = args.upstream_url.strip()
    if args.upstream_command is not None:
        os.environ["AGENTPARRY_UPSTREAM_CMD"] = args.upstream_command.strip()
    if _upstream_config_conflict_message():
        print(_upstream_config_conflict_message(), file=sys.stderr)
        sys.exit(1)
    if args.policy is not None:
        policy_file = Path(args.policy).expanduser()
        if not policy_file.exists():
            print(f"error: policy file not found: {policy_file}", file=sys.stderr)
            sys.exit(1)
        set_policy_path(str(policy_file))
    import uvicorn

    uvicorn.run("src.proxy:app", host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
