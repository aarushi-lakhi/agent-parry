"""Security proxy that intercepts and inspects agent-to-tool traffic."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import subprocess
import sys
import threading
import uuid
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError
from rich.console import Console
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware

from src.inspector import InputInspector, OutputInspector
from src.models import MOCK_SERVER_URL, JsonRpcRequest, JsonRpcResponse, PolicyAction, ProxyStats
from src.policy import PolicyEngine

app = FastAPI(title="AgentParry Proxy", version="1.0")
console = Console()
policy_engine = PolicyEngine()
input_inspector = InputInspector()
output_inspector = OutputInspector()
stats = ProxyStats()
_bypass_all: bool = False

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


class _BearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        expected = os.environ.get("AGENTPARRY_AUTH_TOKEN", "").strip()
        if expected and request.method != "OPTIONS":
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Bearer ") or auth.removeprefix("Bearer ").strip() != expected:
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)


app.add_middleware(_BearerAuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Mcp-Session-Id", "Authorization"],
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


def _mcp_session_response_headers(*, rpc_method: str, incoming_session: str | None) -> dict[str, str]:
    if rpc_method == "initialize":
        return {"Mcp-Session-Id": str(uuid.uuid4())}
    if incoming_session:
        return {"Mcp-Session-Id": incoming_session}
    return {}


def _handle_mcp_rpc(request: JsonRpcRequest) -> JsonRpcResponse:
    if request.method in {"initialize", "tools/list"}:
        upstream_payload = _forward_to_upstream(request.model_dump())
        return JsonRpcResponse.model_validate(upstream_payload)

    if request.method != "tools/call":
        return _jsonrpc_error(
            request_id=request.id,
            code=-32601,
            message=f"Method not found: {request.method}",
        )

    if _bypass_all:
        upstream_payload = _forward_to_upstream(request.model_dump())
        return JsonRpcResponse.model_validate(upstream_payload)

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


@app.post("/policy/disable")
def disable_policy() -> dict[str, str]:
    global _bypass_all
    _bypass_all = True
    return {"status": "ok", "policy": "disabled"}


@app.post("/policy/enable")
def enable_policy() -> dict[str, str]:
    global _bypass_all
    _bypass_all = False
    return {"status": "ok", "policy": "enabled"}


@app.post("/policy/reload")
def reload_policy() -> dict[str, Any]:
    policy_engine.reload()
    return {"status": "ok", "rules_loaded": len(policy_engine.get_rules())}


@app.get("/policy/rules")
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

    try:
        rpc_resp = _handle_mcp_rpc(rpc_req)
    except UpstreamConfigurationError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=503)
    rpc_dict = rpc_resp.model_dump(mode="json")
    incoming = request.headers.get("mcp-session-id")
    extra_headers = _mcp_session_response_headers(rpc_method=rpc_req.method, incoming_session=incoming)
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
    import uvicorn

    uvicorn.run("src.proxy:app", host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
