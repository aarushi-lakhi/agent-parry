"""Stdio MCP proxy: sits between a client (e.g. Claude) and a real MCP server.

Also hosts the policy hot reload: `PolicyFileWatcher` polls the policy file and
installs a validated `PolicyBundle` into the running proxy, so an edit takes
effect without restarting the MCP client.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import json
import logging
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

import yaml

from src.audit import AuditWriter
from src.inspector import (
    METADATA_METHODS,
    InputInspector,
    MetadataInspector,
    OutputInspector,
    ResultInspector,
)
from src.models import (
    INJECTION_BLOCK_ERROR_CODE,
    METADATA_BLOCK_ERROR_CODE,
    PIN_BLOCK_ERROR_CODE,
    RESULT_INJECTION_ERROR_CODE,
    TOOLS_CALL_METHOD,
    AuditAction,
    AuditDirection,
    AuditTransport,
    Finding,
    MetadataInspection,
    PinObservation,
    PolicyAction,
    is_known_mcp_method,
    is_tools_call,
)
from src.pins import ServerIdentity, ToolPinner, audit_findings_for
from src.policy import PolicyEngine
from src.resources import POLICY_DEFAULT_HELP, resolve_policy

_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"

_PROXY_STOP_STDIN = object()

DEFAULT_RELOAD_INTERVAL = 2.0
MIN_RELOAD_INTERVAL = 0.02


def _debug_exc_info() -> bool:
    return logging.getLogger().isEnabledFor(logging.DEBUG)


def _parse_wrap_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split argv into AgentParry flags and the wrapped command argv."""
    try:
        idx = argv.index("--wrap")
    except ValueError as exc:
        raise SystemExit("error: --wrap is required") from exc
    return argv[:idx], argv[idx + 1 :]


def _parse_child_command(wrap_argv: list[str]) -> tuple[str, list[str]]:
    if not wrap_argv:
        raise SystemExit("error: --wrap requires a command")
    cmd = wrap_argv[0]
    rest = wrap_argv[1:]
    if rest and rest[0] == "--":
        return cmd, rest[1:]
    return cmd, rest


def _resolve_policy_path(explicit: str | None) -> str:
    """Policy file for this session: flag, then env, then user copy, then packaged."""
    return str(resolve_policy(explicit).path)


def _default_log_path() -> Path:
    return Path.home() / ".agentparry" / "proxy.log"


def _configure_logging(log_path: Path, *, verbose: bool) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    root.addHandler(file_handler)

    if verbose:
        err_handler = logging.StreamHandler(sys.stderr)
        err_handler.setLevel(logging.DEBUG)
        err_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        root.addHandler(err_handler)


def _read_one_json_message_from_buffer(buffer: Any) -> dict[str, Any] | None:
    """Read one JSON-RPC message from a binary stdin-like buffer (NDJSON or Content-Length)."""
    logger = logging.getLogger(__name__)
    first = buffer.readline()
    if not first:
        return None
    stripped = first.lstrip()
    if stripped.lower().startswith(b"content-length:"):
        try:
            header_line = stripped.split(b"\n", 1)[0]
            n = int(header_line.split(b":", 1)[1].strip())
        except (ValueError, IndexError):
            logger.warning("Invalid Content-Length header; skipping message")
            return None
        while True:
            line = buffer.readline()
            if not line:
                return None
            if line in (b"\r\n", b"\n") or line.strip() == b"":
                break
        body = buffer.read(n)
        if len(body) != n:
            logger.warning("Short read on Content-Length body; skipping message")
            return None
        try:
            text = body.decode("utf-8")
            return json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.warning("Invalid JSON in Content-Length body; skipping message", exc_info=_debug_exc_info())
            return None
    try:
        text = first.decode("utf-8").strip()
        if not text:
            return _read_one_json_message_from_buffer(buffer)
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("Invalid JSON on stdin; skipping line", exc_info=_debug_exc_info())
        return None


async def _read_one_json_message_async(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    logger = logging.getLogger(__name__)
    first = await reader.readline()
    if not first:
        return None
    stripped = first.lstrip()
    if stripped.lower().startswith(b"content-length:"):
        try:
            header_line = stripped.split(b"\n", 1)[0]
            n = int(header_line.split(b":", 1)[1].strip())
        except (ValueError, IndexError):
            logger.warning("Invalid Content-Length from server; skipping message")
            return None
        while True:
            line = await reader.readline()
            if not line:
                return None
            if line in (b"\r\n", b"\n") or line.strip() == b"":
                break
        body = await reader.readexactly(n)
        try:
            text = body.decode("utf-8")
            return json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.warning("Invalid JSON in server Content-Length body; passing raw forward disabled")
            return None
    try:
        text = first.decode("utf-8").strip()
        if not text:
            return await _read_one_json_message_async(reader)
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("Invalid JSON from server; skipping message", exc_info=_debug_exc_info())
        return None


def _json_dumps_line(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _get_tool_payload(params: Any) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(params, dict):
        return None, None
    tool_name = params.get("name")
    arguments = params.get("arguments")
    if not isinstance(tool_name, str):
        return None, None
    if not isinstance(arguments, dict):
        return tool_name, None
    return tool_name, arguments


def _error_response(request_id: Any, *, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


class PolicyReloadError(RuntimeError):
    """A policy file did not yield a policy that still enforces something."""


def _policy_stamp(path: Path) -> tuple[int, int] | None:
    """Return (mtime_ns, size) for the policy file, or None when it cannot be stat'ed."""
    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_mtime_ns, stat.st_size)


def _load_policy_document(path: Path) -> dict[str, Any]:
    """Parse a policy file, rejecting any document that would weaken enforcement.

    Every rejection path raises. A hot reload has no safe empty state: swapping in
    zero rules is allow-everything, so a truncated write, a YAML syntax error and
    a rule list that vanished all have to leave the loaded policy alone.

    Args:
        path: Policy YAML path.

    Returns:
        The parsed policy mapping, with `rules` present and non-empty.

    Raises:
        PolicyReloadError: The file is unreadable, is not YAML, is not a mapping,
            or carries no usable rules.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyReloadError(f"policy file unreadable: {exc}") from exc
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyReloadError(f"policy YAML did not parse: {type(exc).__name__}") from exc
    if not isinstance(loaded, dict):
        raise PolicyReloadError("policy root is not a mapping")
    rules = loaded.get("rules")
    if not isinstance(rules, list):
        raise PolicyReloadError("policy has no 'rules' list")
    if not rules:
        raise PolicyReloadError("policy declares zero rules, which would disable enforcement")
    settings = loaded.get("settings")
    if settings is not None and not isinstance(settings, dict):
        raise PolicyReloadError("policy 'settings' is not a mapping")
    return loaded


@dataclass(frozen=True)
class PolicyBundle:
    """A policy engine plus everything else derived from the same settings block.

    The pinner belongs here and not beside it: it reads
    ``settings.tool_pinning`` and holds the metadata inspector it re-inspects
    changed tools with, so a bundle that swapped the engine and the inspectors
    but kept the old pinner would leave pinning enforcing the previous file.
    """

    engine: PolicyEngine
    result_inspector: ResultInspector
    metadata_inspector: MetadataInspector
    tool_pinner: ToolPinner

    @property
    def rule_count(self) -> int:
        """Number of rules the engine compiled, so the number that can match."""
        return self.engine.active_rule_count


def build_policy_bundle(
    policy_path: str | Path, *, identity: ServerIdentity | None = None
) -> PolicyBundle:
    """Load a policy file into an engine and everything derived from its settings.

    Args:
        policy_path: Policy YAML path.
        identity: Pin identity of the wrapped server, carried across a reload
            because it comes from the command line and not from the policy.

    Returns:
        A bundle ready to install, built entirely off to the side.

    Raises:
        PolicyReloadError: The document was rejected by `_load_policy_document`.
    """
    path = Path(policy_path)
    document = _load_policy_document(path)
    engine = PolicyEngine(policy_path=str(path), policy=document)
    if engine.active_rule_count == 0:
        raise PolicyReloadError(
            f"none of the {len(engine.get_rules())} rule(s) compiled, which would disable enforcement"
        )
    settings = engine.get_settings()
    metadata_inspector = MetadataInspector.from_policy_settings(settings)
    return PolicyBundle(
        engine=engine,
        result_inspector=ResultInspector.from_policy_settings(settings),
        metadata_inspector=metadata_inspector,
        tool_pinner=ToolPinner.from_policy_settings(
            settings, identity=identity, inspector=metadata_inspector
        ),
    )


class StdioMcpProxy:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        input_inspector: InputInspector,
        output_inspector: OutputInspector,
        stdout_lock: asyncio.Lock,
        audit: AuditWriter,
        result_inspector: ResultInspector | None = None,
        metadata_inspector: MetadataInspector | None = None,
        tool_pinner: ToolPinner | None = None,
    ) -> None:
        self._policy = policy_engine
        self._input_inspector = input_inspector
        self._output_inspector = output_inspector
        self._result_inspector = result_inspector or ResultInspector()
        self._metadata_inspector = metadata_inspector or MetadataInspector()
        self._tool_pinner = tool_pinner or ToolPinner()
        self._stdout_lock = stdout_lock
        self._audit = audit
        self._pending_forwarded: dict[Any, str] = {}
        self._pending_tools: dict[Any, str] = {}

    @property
    def rule_count(self) -> int:
        """Number of rules currently in force."""
        return self._policy.active_rule_count

    def swap_policy(self, bundle: PolicyBundle) -> None:
        """Install an already-built policy bundle, every settings consumer together.

        Synchronous and only ever called from the event loop, so it cannot land
        between a handler reading one of these attributes and the synchronous
        evaluation that uses it. Nothing in the outgoing bundle is mutated, so an
        inspection already running on a worker thread finishes against the objects
        it started with.

        Every attribute derived from the policy's settings has to move at once,
        the pinner included: leaving it behind would keep pinning on the previous
        settings and pointed at the previous metadata inspector.
        """
        self._policy = bundle.engine
        self._result_inspector = bundle.result_inspector
        self._metadata_inspector = bundle.metadata_inspector
        self._tool_pinner = bundle.tool_pinner

    def record_policy_reload(self, *, succeeded: bool, rules: int, reason: str = "") -> None:
        """Audit one reload attempt, successful or rejected."""
        if succeeded:
            detail = f"policy reload ok; rules_loaded={rules}"
        else:
            detail = f"policy reload rejected; rules_in_force={rules}; {reason}"
        self._record(AuditAction.POLICY_RELOAD, detail=detail)

    async def write_stdout(self, obj: dict[str, Any]) -> None:
        data = _json_dumps_line(obj)
        async with self._stdout_lock:

            def _write() -> None:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            await asyncio.to_thread(_write)

    def _record(
        self,
        action: AuditAction,
        *,
        direction: AuditDirection = AuditDirection.CLIENT_TO_SERVER,
        method: str | None = None,
        tool: str | None = None,
        arguments: dict[str, Any] | None = None,
        rule: str | None = None,
        request_id: Any = None,
        findings: list[Finding] | None = None,
        pii_redactions: int | None = None,
        detail: str = "",
    ) -> None:
        """Append one audit record for an already-computed decision.

        Synchronous on the event loop on purpose, unlike `write_stdout`: this is
        one small unsynced syscall, and going off-loop via asyncio.to_thread
        would reorder audit records relative to stdout writes for no gain.
        """
        record = self._audit.build(
            action=action,
            direction=direction,
            method=method,
            tool=tool,
            rule=rule,
            request_id=request_id,
            arguments=arguments,
            findings=findings,
            pii_redactions=pii_redactions,
            detail=detail,
        )
        self._audit.write(record)

    async def handle_client_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """
        Inspect client→server message. Returns dict to forward to child, or None if
        a response was already written to stdout.
        """
        logger = logging.getLogger(__name__)
        if not isinstance(msg, dict):
            return None
        if msg.get("jsonrpc") != "2.0":
            raw_method = msg.get("method")
            self._record(
                AuditAction.PASSTHROUGH,
                method=raw_method if isinstance(raw_method, str) else None,
                request_id=msg.get("id"),
                detail="jsonrpc field is not 2.0; forwarded uninspected",
            )
            return msg

        method = msg.get("method")
        req_id = msg.get("id")

        if not (isinstance(method, str) and is_tools_call(method)):
            if req_id is not None:
                m = method if isinstance(method, str) else "unknown"
                self._pending_forwarded[req_id] = m
            if isinstance(method, str) and not is_known_mcp_method(method):
                logger.warning("Forwarding unknown MCP method without inspection method=%s", method)
                self._record(
                    AuditAction.PASSTHROUGH,
                    method=method,
                    request_id=req_id,
                    detail="unknown MCP method forwarded without inspection",
                )
            else:
                self._record(
                    AuditAction.PASSTHROUGH,
                    method=method if isinstance(method, str) else None,
                    request_id=req_id,
                    detail="known MCP method forwarded without tool inspection",
                )
            return msg

        params = msg.get("params")
        tool_name, arguments = _get_tool_payload(params)

        if tool_name is None:
            if req_id is None:
                logger.warning("tools/call missing tool name (notification); forwarding")
                self._record(
                    AuditAction.FAIL_OPEN,
                    method=method,
                    detail="tools/call with invalid 'name' and no id; forwarded (fail-open)",
                )
                return msg
            await self.write_stdout(
                _error_response(
                    req_id,
                    code=-32602,
                    message="Invalid params: 'name' must be a string.",
                )
            )
            self._record(
                AuditAction.INVALID_PARAMS,
                method=method,
                request_id=req_id,
                detail="'name' must be a string",
            )
            return None

        if arguments is None:
            if req_id is None:
                logger.warning("tools/call missing arguments object (notification); forwarding")
                self._record(
                    AuditAction.FAIL_OPEN,
                    method=method,
                    tool=tool_name,
                    detail="tools/call with invalid 'arguments' and no id; forwarded (fail-open)",
                )
                return msg
            await self.write_stdout(
                _error_response(
                    req_id,
                    code=-32602,
                    message="Invalid params: 'arguments' must be an object.",
                )
            )
            self._record(
                AuditAction.INVALID_PARAMS,
                method=method,
                tool=tool_name,
                request_id=req_id,
                detail="'arguments' must be an object",
            )
            return None

        findings: list[Any] = []
        try:
            findings = self._input_inspector.inspect(tool_name, arguments)
        except Exception as exc:
            logger.exception("InputInspector failed for %s; allowing (fail-open)", tool_name)
            self._record(
                AuditAction.FAIL_OPEN,
                method=method,
                tool=tool_name,
                arguments=arguments,
                request_id=req_id,
                detail=f"InputInspector raised {type(exc).__name__}; injection check skipped and call allowed",
            )

        if any(getattr(f, "severity", None) == "critical" for f in findings):
            if req_id is None:
                logger.warning("Critical injection in tools/call notification; forwarding (fail-open)")
                self._record(
                    AuditAction.FAIL_OPEN,
                    method=method,
                    tool=tool_name,
                    arguments=arguments,
                    findings=findings,
                    detail="critical injection but notification has no id to answer; forwarded (fail-open)",
                )
                return msg
            await self.write_stdout(
                _error_response(
                    req_id,
                    code=INJECTION_BLOCK_ERROR_CODE,
                    message="Blocked: critical prompt injection pattern detected",
                )
            )
            self._record(
                AuditAction.BLOCK_INJECTION,
                method=method,
                tool=tool_name,
                arguments=arguments,
                request_id=req_id,
                findings=findings,
                detail="critical prompt injection pattern",
            )
            return None

        decision = None
        try:
            decision = self._policy.evaluate(tool_name, arguments)
        except Exception as exc:
            logger.exception("PolicyEngine.evaluate failed for %s; allowing (fail-open)", tool_name)
            self._record(
                AuditAction.FAIL_OPEN,
                method=method,
                tool=tool_name,
                arguments=arguments,
                request_id=req_id,
                findings=findings,
                detail=f"PolicyEngine.evaluate raised {type(exc).__name__}; no policy applied and call allowed",
            )

        if decision is not None:
            if decision.action == PolicyAction.BLOCK:
                if req_id is None:
                    logger.warning("Policy BLOCK for tools/call notification; forwarding (fail-open)")
                    self._record(
                        AuditAction.FAIL_OPEN,
                        method=method,
                        tool=tool_name,
                        arguments=arguments,
                        rule=decision.rule_name,
                        findings=findings,
                        detail="policy asked BLOCK but notification has no id to answer; forwarded (fail-open)",
                    )
                    return msg
                await self.write_stdout(
                    _error_response(
                        req_id,
                        code=INJECTION_BLOCK_ERROR_CODE,
                        message=decision.message or "Blocked by policy",
                    )
                )
                self._record(
                    AuditAction.BLOCK_POLICY,
                    method=method,
                    tool=tool_name,
                    arguments=arguments,
                    request_id=req_id,
                    rule=decision.rule_name or "policy",
                    findings=findings,
                    detail=decision.message,
                )
                return None
            if decision.action == PolicyAction.REQUIRE_APPROVAL:
                logger.warning(
                    "REQUIRE_APPROVAL for tool=%s rule=%s (stdio mode cannot prompt; allowing)",
                    tool_name,
                    decision.rule_name,
                )
                self._record(
                    AuditAction.REQUIRE_APPROVAL,
                    method=method,
                    tool=tool_name,
                    arguments=arguments,
                    request_id=req_id,
                    rule=decision.rule_name or "requires_approval",
                    findings=findings,
                    detail="policy asked REQUIRE_APPROVAL; stdio cannot prompt, so the call was allowed",
                )
            else:
                self._record(
                    AuditAction.ALLOW,
                    method=method,
                    tool=tool_name,
                    arguments=arguments,
                    request_id=req_id,
                    rule=decision.rule_name,
                    findings=findings,
                    detail=f"policy {decision.action.value}; forwarded upstream",
                )

        if req_id is not None:
            self._pending_forwarded[req_id] = "tools/call"
            self._pending_tools[req_id] = tool_name

        return msg

    async def handle_server_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Inspect server→client message; may sanitize tools/call results."""
        logger = logging.getLogger(__name__)
        if not isinstance(msg, dict):
            return msg

        rid = msg.get("id")
        is_request = isinstance(msg.get("method"), str)

        pending_method: str | None = None
        if rid is not None and not is_request:
            pending_method = self._pending_forwarded.pop(rid, None)

        if rid is not None and not is_request and rid in self._pending_tools:
            tool_name = self._pending_tools.pop(rid)
            inbound = {
                "direction": AuditDirection.SERVER_TO_CLIENT,
                "method": TOOLS_CALL_METHOD,
                "tool": tool_name,
                "request_id": rid,
            }
            if msg.get("error") is not None:
                self._record(AuditAction.ALLOW, detail="upstream returned a tool error", **inbound)
                return msg
            result = msg.get("result")
            if isinstance(result, dict):
                try:
                    sanitized, pii_findings = self._output_inspector.inspect(tool_name, result)
                except Exception as exc:
                    logger.exception("OutputInspector failed for %s; forwarding raw (fail-open)", tool_name)
                    self._record(
                        AuditAction.FAIL_OPEN,
                        detail=(
                            f"OutputInspector raised {type(exc).__name__}; "
                            "result forwarded unredacted (fail-open)"
                        ),
                        **inbound,
                    )
                    return msg

                if pii_findings:
                    self._record(
                        AuditAction.REDACT_OUTPUT,
                        findings=pii_findings,
                        pii_redactions=len(pii_findings),
                        detail="PII redacted from tool result",
                        **inbound,
                    )

                # PII first, so the injection scan sees what the model will see.
                try:
                    inspection = self._result_inspector.inspect(tool_name, sanitized)
                except Exception as exc:
                    logger.exception("ResultInspector failed for %s; forwarding raw (fail-open)", tool_name)
                    self._record(
                        AuditAction.FAIL_OPEN,
                        detail=(
                            f"ResultInspector raised {type(exc).__name__}; "
                            "result forwarded without an injection scan (fail-open)"
                        ),
                        **inbound,
                    )
                    if pii_findings:
                        msg = dict(msg)
                        msg["result"] = sanitized
                    return msg

                if inspection.findings:
                    self._record(
                        AuditAction.BLOCK_RESULT_INJECTION
                        if inspection.blocked
                        else AuditAction.NEUTRALIZE_RESULT,
                        findings=inspection.findings,
                        detail=(
                            f"{inspection.action}: {len(inspection.findings)} "
                            "injection finding(s) in tool result"
                        ),
                        **inbound,
                    )
                if inspection.blocked:
                    return {
                        "jsonrpc": msg.get("jsonrpc", "2.0"),
                        "id": rid,
                        "error": {
                            "code": RESULT_INJECTION_ERROR_CODE,
                            "message": inspection.block_message,
                        },
                    }
                if pii_findings or inspection.findings:
                    msg = dict(msg)
                    msg["result"] = inspection.result
                else:
                    self._record(AuditAction.ALLOW, detail="tool result inspected, no findings", **inbound)
            else:
                self._record(AuditAction.ALLOW, detail="tool result is not an object; not inspected", **inbound)
            return msg

        if pending_method in METADATA_METHODS and msg.get("error") is None:
            return await self._inspect_metadata(msg, rid, pending_method)

        if is_request:
            method = msg.get("method")
            self._record(
                AuditAction.PASSTHROUGH,
                direction=AuditDirection.SERVER_TO_CLIENT,
                method=method if isinstance(method, str) else None,
                request_id=rid,
                detail="server-initiated request forwarded uninspected",
            )
        elif "result" in msg or msg.get("error") is not None:
            self._record(
                AuditAction.PASSTHROUGH,
                direction=AuditDirection.SERVER_TO_CLIENT,
                request_id=rid,
                detail="response to an untracked request forwarded uninspected",
            )

        return msg

    async def _inspect_metadata(self, msg: dict[str, Any], rid: Any, method: str) -> dict[str, Any]:
        """Scan a discovery response for poisoned metadata, failing open on error.

        The scan runs on a worker thread: a deeply nested inputSchema walked on
        the event loop would stall the handshake this response is part of, and the
        handshake is exactly when a client is least tolerant of a delay.
        """
        logger = logging.getLogger(__name__)
        inbound: dict[str, Any] = {
            "direction": AuditDirection.SERVER_TO_CLIENT,
            "method": method,
            "request_id": rid,
        }
        result = msg.get("result")
        if not isinstance(result, dict):
            self._record(AuditAction.ALLOW, detail="discovery result is not an object; not inspected", **inbound)
            return msg

        inspection: MetadataInspection | None = None
        try:
            inspection = await asyncio.to_thread(self._metadata_inspector.inspect, method, result)
        except Exception as exc:
            logger.exception("Metadata inspection failed for %s; forwarding raw (fail-open)", method)
            self._record(
                AuditAction.FAIL_OPEN,
                detail=(
                    f"MetadataInspector raised {type(exc).__name__}; "
                    "discovery result forwarded uninspected (fail-open)"
                ),
                **inbound,
            )

        if inspection is None:
            findings: list[Finding] = []
        elif inspection.findings:
            affected = inspection.dropped_tools + inspection.redacted_tools
            detail = f"{inspection.action}: {len(inspection.findings)} poisoned metadata finding(s)"
            if affected:
                detail += f" tools={','.join(affected)}"
            self._record(
                AuditAction.BLOCK_METADATA if inspection.blocked else AuditAction.REDACT_METADATA,
                findings=inspection.findings,
                detail=detail,
                **inbound,
            )
            findings = inspection.findings
        else:
            self._record(AuditAction.ALLOW, detail="discovery metadata inspected, no findings", **inbound)
            findings = []

        observation = await self._observe_pin(method, result, findings, inbound)

        if inspection is not None and inspection.blocked:
            return {
                "jsonrpc": msg.get("jsonrpc", "2.0"),
                "id": rid,
                "error": {
                    "code": METADATA_BLOCK_ERROR_CODE,
                    "message": inspection.block_message,
                },
            }
        if observation.blocked:
            return {
                "jsonrpc": msg.get("jsonrpc", "2.0"),
                "id": rid,
                "error": {"code": PIN_BLOCK_ERROR_CODE, "message": observation.block_message},
            }

        payload = result if inspection is None else inspection.result
        payload = self._tool_pinner.apply(payload, observation)
        if payload is result and not (inspection is not None and inspection.findings):
            return msg
        updated = dict(msg)
        updated["result"] = payload
        return updated

    async def _observe_pin(
        self,
        method: str,
        result: dict[str, Any],
        findings: list[Finding],
        inbound: dict[str, Any],
    ) -> PinObservation:
        """Diff the raw discovery result against the pin on disk, failing open.

        The raw result, not the redacted one: pinning what metadata inspection
        rewrote would diff on every run, and would pin poison it had already
        removed as if it were clean. The check touches the filesystem, so it runs
        on a worker thread like the scan above it.
        """
        logger = logging.getLogger(__name__)
        try:
            observation = await asyncio.to_thread(self._tool_pinner.observe, method, result, findings)
        except Exception as exc:
            logger.exception("Tool-list pin check failed for %s; forwarding raw (fail-open)", method)
            self._record(
                AuditAction.FAIL_OPEN,
                detail=f"ToolPinner raised {type(exc).__name__}; pin not checked (fail-open)",
                **inbound,
            )
            return PinObservation()

        if not observation.reportable:
            return observation
        action = AuditAction.PIN_CREATED if observation.status == "created" else AuditAction.PIN_DIFF
        if observation.blocked:
            action = AuditAction.BLOCK_PIN
        self._record(
            action,
            findings=audit_findings_for(observation),
            detail=observation.detail,
            **inbound,
        )
        return observation


class PolicyFileWatcher:
    """Hot-reload the policy of a live proxy when its policy file changes on disk.

    Polls `(mtime_ns, size)` instead of taking a signal or exposing a control
    endpoint: the proxy runs as a child of an MCP client, so there is no pid a
    user can find, no port they can reach, and the inbound JSON-RPC stream is the
    untrusted path a control surface must not live on.
    """

    def __init__(
        self,
        proxy: StdioMcpProxy,
        policy_path: str | Path,
        *,
        interval: float = DEFAULT_RELOAD_INTERVAL,
        identity: ServerIdentity | None = None,
    ) -> None:
        self._proxy = proxy
        self._path = Path(policy_path)
        self._interval = max(float(interval), MIN_RELOAD_INTERVAL)
        self._identity = identity
        self._stamp = _policy_stamp(self._path)

    async def poll_once(self) -> bool:
        """Reload if the file changed, keeping the loaded policy on any failure.

        Returns:
            True when a new policy took effect.
        """
        logger = logging.getLogger(__name__)
        stamp = await asyncio.to_thread(_policy_stamp, self._path)
        if stamp is None or stamp == self._stamp:
            return False
        self._stamp = stamp
        try:
            bundle = await asyncio.to_thread(
                functools.partial(build_policy_bundle, self._path, identity=self._identity)
            )
        except Exception as exc:
            logger.warning(
                "Policy reload rejected path=%s reason=%s; keeping the %d rule(s) already in force",
                self._path,
                exc,
                self._proxy.rule_count,
                exc_info=_debug_exc_info(),
            )
            self._proxy.record_policy_reload(succeeded=False, rules=self._proxy.rule_count, reason=str(exc))
            return False
        self._proxy.swap_policy(bundle)
        logger.info("Policy reloaded path=%s rules=%d", self._path, bundle.rule_count)
        self._proxy.record_policy_reload(succeeded=True, rules=bundle.rule_count)
        return True

    async def run(self) -> None:
        """Poll until cancelled."""
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.getLogger(__name__).exception("Policy watch failed; keeping the loaded policy")


async def _drain_stderr(proc: asyncio.subprocess.Process, log_file: TextIO) -> None:
    logger = logging.getLogger(__name__)
    assert proc.stderr is not None
    while True:
        line = await proc.stderr.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        logger.warning("child stderr: %s", text)
        try:
            log_file.write(f"{text}\n")
            log_file.flush()
        except Exception:
            logger.exception("Failed writing child stderr to log file")


async def _terminate_child(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except TimeoutError:
        proc.kill()
        await proc.wait()


async def _run_proxy(argv: list[str]) -> int:
    if ("-h" in argv or "--help" in argv) and "--wrap" not in argv:
        help_parser = argparse.ArgumentParser(
            description="AgentParry stdio MCP proxy",
            epilog=(
                "Examples:\n"
                "  python -m src.stdio_proxy --wrap npx -- some-mcp-server\n"
                "  python -m src.stdio_proxy --policy my_policy.yaml --verbose --wrap uvx -- pkg\n"
                "\n"
                f"Default policy: {POLICY_DEFAULT_HELP}.\n"
                "Default log file: ~/.agentparry/proxy.log\n"
                "Default audit log: ~/.agentparry/audit.jsonl, overridden by AGENTPARRY_AUDIT_PATH.\n"
                "Policy edits are picked up while running; pass --no-reload-on-change to opt out.\n"
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        help_parser.add_argument(
            "--policy",
            metavar="PATH",
            help=f"Policy YAML (default: {POLICY_DEFAULT_HELP})",
        )
        help_parser.add_argument(
            "--log",
            dest="log_path",
            metavar="PATH",
            help="Log file (default: ~/.agentparry/proxy.log)",
        )
        help_parser.add_argument(
            "--audit",
            dest="audit_path",
            metavar="PATH",
            help="JSONL audit log (default: ~/.agentparry/audit.jsonl or AGENTPARRY_AUDIT_PATH)",
        )
        help_parser.add_argument(
            "--no-audit",
            dest="no_audit",
            action="store_true",
            help="Disable the JSONL audit log (same as AGENTPARRY_AUDIT=0)",
        )
        help_parser.add_argument(
            "--reload-on-change",
            dest="reload_on_change",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="Reload the policy file when it changes on disk (default: enabled)",
        )
        help_parser.add_argument(
            "--reload-interval",
            dest="reload_interval",
            type=float,
            metavar="SECONDS",
            default=DEFAULT_RELOAD_INTERVAL,
            help=f"Policy file poll interval in seconds (default: {DEFAULT_RELOAD_INTERVAL})",
        )
        help_parser.add_argument("--verbose", action="store_true", help="Verbose logging to stderr and log file")
        help_parser.add_argument(
            "--wrap",
            metavar="CMD",
            help="MCP server executable; use '--' before that server's arguments",
        )
        help_parser.print_help()
        return 0

    before, wrap_argv = _parse_wrap_argv(argv)
    parser = argparse.ArgumentParser(description="AgentParry stdio MCP proxy")
    parser.add_argument(
        "--policy",
        default=None,
        help=f"Policy YAML path (default: {POLICY_DEFAULT_HELP})",
    )
    parser.add_argument(
        "--log",
        dest="log_path",
        default=None,
        help="Log file path (default: ~/.agentparry/proxy.log)",
    )
    parser.add_argument(
        "--audit",
        dest="audit_path",
        default=None,
        help="JSONL audit log path (default: ~/.agentparry/audit.jsonl or AGENTPARRY_AUDIT_PATH)",
    )
    parser.add_argument(
        "--no-audit",
        dest="no_audit",
        action="store_true",
        help="Disable the JSONL audit log (same as AGENTPARRY_AUDIT=0)",
    )
    parser.add_argument(
        "--reload-on-change",
        dest="reload_on_change",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reload the policy file when it changes on disk (default: enabled)",
    )
    parser.add_argument(
        "--reload-interval",
        dest="reload_interval",
        type=float,
        metavar="SECONDS",
        default=DEFAULT_RELOAD_INTERVAL,
        help=f"Policy file poll interval in seconds (default: {DEFAULT_RELOAD_INTERVAL})",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging to stderr and log file")
    parsed = parser.parse_args(before)

    policy_path = _resolve_policy_path(parsed.policy)
    log_path = Path(parsed.log_path) if parsed.log_path else _default_log_path()
    _configure_logging(log_path, verbose=parsed.verbose)
    logger = logging.getLogger(__name__)

    cmd, child_args = _parse_child_command(wrap_argv)
    logger.info("Starting wrapped server command=%s args=%s policy=%s", cmd, child_args, policy_path)

    pin_identity = ServerIdentity.for_command([cmd, *child_args], transport=AuditTransport.STDIO)
    try:
        policy_engine = PolicyEngine(policy_path=str(policy_path))
        input_inspector = InputInspector()
        output_inspector = OutputInspector()
        result_inspector = ResultInspector.from_policy_settings(policy_engine.get_settings())
        metadata_inspector = MetadataInspector.from_policy_settings(policy_engine.get_settings())
        tool_pinner = ToolPinner.from_policy_settings(
            policy_engine.get_settings(),
            identity=pin_identity,
            inspector=metadata_inspector,
        )
    except Exception:
        logger.exception("Failed to initialize policy/inspectors; exiting")
        return 1
    logger.info(
        "Tool-list pin action=%s key=%s store=%s",
        tool_pinner.settings.action,
        tool_pinner.identity_key,
        tool_pinner.store.path,
    )

    proc = await asyncio.create_subprocess_exec(
        cmd,
        *child_args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )

    stderr_log_handle: TextIO
    try:
        stderr_log_handle = log_path.open("a", encoding="utf-8")
    except Exception:
        stderr_log_handle = open(os.devnull, "a", encoding="utf-8")  # noqa: SIM115
        logger.exception("Could not open log file for stderr mirror; discarding child stderr mirror")

    try:
        audit_writer = AuditWriter(
            transport=AuditTransport.STDIO,
            path=parsed.audit_path,
            enabled=False if parsed.no_audit else None,
        )
    except Exception:
        # A misconfigured audit path must not stop a client session.
        logger.exception("Could not construct the audit writer; auditing disabled for this run")
        audit_writer = AuditWriter(transport=AuditTransport.STDIO, enabled=False)
    logger.info(
        "Audit log enabled=%s path=%s args_mode=%s",
        audit_writer.enabled,
        audit_writer.path,
        audit_writer.args_mode.value,
    )

    stdout_lock = asyncio.Lock()
    proxy = StdioMcpProxy(
        policy_engine=policy_engine,
        input_inspector=input_inspector,
        output_inspector=output_inspector,
        result_inspector=result_inspector,
        metadata_inspector=metadata_inspector,
        tool_pinner=tool_pinner,
        stdout_lock=stdout_lock,
        audit=audit_writer,
    )

    watch_task: asyncio.Task[None] | None = None
    if parsed.reload_on_change:
        watcher = PolicyFileWatcher(
            proxy, policy_path, interval=parsed.reload_interval, identity=pin_identity
        )
        watch_task = asyncio.create_task(watcher.run())
        logger.info("Watching policy for changes path=%s interval=%ss", policy_path, parsed.reload_interval)

    loop = asyncio.get_running_loop()
    stdin_queue: asyncio.Queue[Any] = asyncio.Queue()

    def _stdin_reader_thread() -> None:
        try:
            while True:
                msg = _read_one_json_message_from_buffer(sys.stdin.buffer)
                try:
                    asyncio.run_coroutine_threadsafe(stdin_queue.put(msg), loop).result()
                except Exception:
                    logging.getLogger(__name__).exception("Failed to enqueue stdin message")
                    break
                if msg is None:
                    break
        except Exception:
            logging.getLogger(__name__).exception("stdin reader thread crashed")
            with contextlib.suppress(Exception):
                asyncio.run_coroutine_threadsafe(stdin_queue.put(None), loop).result()

    threading.Thread(target=_stdin_reader_thread, name="agentparry-stdin", daemon=True).start()

    async def client_to_server() -> None:
        assert proc.stdin is not None
        try:
            while True:
                msg = await stdin_queue.get()
                if msg is _PROXY_STOP_STDIN:
                    logger.warning("Stopping client→server loop (child stdout closed)")
                    break
                if msg is None:
                    logger.info("stdin closed by client; closing wrapped MCP server stdin (await clean exit)")
                    break
                if not isinstance(msg, dict):
                    logger.warning("Skipping non-object JSON message from client")
                    continue
                try:
                    to_forward = await proxy.handle_client_message(msg)
                except Exception:
                    logger.exception("handle_client_message crashed; forwarding raw (fail-open)")
                    to_forward = msg

                if to_forward is None:
                    continue
                try:
                    proc.stdin.write(_json_dumps_line(to_forward))
                    await proc.stdin.drain()
                except (BrokenPipeError, ConnectionResetError, RuntimeError) as exc:
                    logger.warning("Failed writing to child stdin: %s", exc)
                    break
                except Exception:
                    logger.exception("Unexpected error writing to child stdin")
                    break
        finally:
            with contextlib.suppress(Exception):
                proc.stdin.close()

    async def server_to_client() -> None:
        assert proc.stdout is not None
        try:
            while True:
                msg = await _read_one_json_message_async(proc.stdout)
                if msg is None:
                    break
                try:
                    out = await proxy.handle_server_message(msg)
                except Exception:
                    logger.exception("handle_server_message crashed; forwarding raw (fail-open)")
                    out = msg
                await proxy.write_stdout(out)
        finally:
            await stdin_queue.put(_PROXY_STOP_STDIN)

    stderr_task = asyncio.create_task(_drain_stderr(proc, stderr_log_handle))

    client_task = asyncio.create_task(client_to_server())
    server_task = asyncio.create_task(server_to_client())

    results = await asyncio.gather(client_task, server_task, return_exceptions=True)
    for item in results:
        if isinstance(item, BaseException):
            logger.error("Proxy task failed", exc_info=item)

    if watch_task is not None:
        watch_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await watch_task

    code = proc.returncode
    if code is None:
        await _terminate_child(proc)
        code = proc.returncode

    logger.warning("Child process ended returncode=%s", code)

    for pending_id in list(proxy._pending_forwarded.keys()):
        try:
            await proxy.write_stdout(
                _error_response(
                    pending_id,
                    code=-32000,
                    message="MCP server process exited before a response was produced",
                )
            )
        except Exception:
            logger.exception("Failed to write synthetic error for pending id=%s", pending_id)

    proxy._pending_forwarded.clear()
    proxy._pending_tools.clear()

    try:
        await asyncio.wait_for(stderr_task, timeout=2.0)
    except TimeoutError:
        stderr_task.cancel()
    with contextlib.suppress(Exception):
        stderr_log_handle.close()
    if audit_writer.drops:
        logger.warning("Audit log dropped %d record(s) this run", audit_writer.drops)
    audit_writer.close()

    return 0 if code in (0, None) else 1


def main_argv(argv: list[str] | None = None) -> int:
    """Run the stdio proxy with argv as from the shell (excluding program name)."""
    args = sys.argv[1:] if argv is None else argv
    return asyncio.run(_run_proxy(args))


def main() -> None:
    try:
        raise SystemExit(main_argv())
    except KeyboardInterrupt:
        raise SystemExit(130) from None


if __name__ == "__main__":
    main()
