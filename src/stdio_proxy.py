"""Stdio MCP proxy: sits between a client (e.g. Claude) and a real MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, TextIO

from src.inspector import InputInspector, OutputInspector
from src.models import PolicyAction
from src.policy import PolicyEngine

_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"

# Injected into the stdin asyncio queue when the child stdout closes first, so the
# client forwarding loop can exit without blocking forever on stdin.
_PROXY_STOP_STDIN = object()


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
    env_path = os.environ.get("AGENTPARRY_POLICY")
    if explicit:
        return explicit
    if env_path:
        return env_path
    return "config/default_policy.yaml"


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


class StdioMcpProxy:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        input_inspector: InputInspector,
        output_inspector: OutputInspector,
        stdout_lock: asyncio.Lock,
    ) -> None:
        self._policy = policy_engine
        self._input_inspector = input_inspector
        self._output_inspector = output_inspector
        self._stdout_lock = stdout_lock
        self._pending_forwarded: dict[Any, str] = {}
        self._pending_tools: dict[Any, str] = {}

    async def write_stdout(self, obj: dict[str, Any]) -> None:
        data = _json_dumps_line(obj)
        async with self._stdout_lock:

            def _write() -> None:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            await asyncio.to_thread(_write)

    def _log_line(
        self,
        direction: str,
        method: str | None,
        decision: str,
        details: str,
    ) -> None:
        logging.getLogger(__name__).info(
            "%s method=%s decision=%s %s",
            direction,
            method or "-",
            decision,
            details,
        )

    async def handle_client_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """
        Inspect client→server message. Returns dict to forward to child, or None if
        a response was already written to stdout.
        """
        logger = logging.getLogger(__name__)
        if not isinstance(msg, dict):
            return None
        if msg.get("jsonrpc") != "2.0":
            self._log_line("client→server", msg.get("method") if isinstance(msg.get("method"), str) else None, "passthrough", "non-2.0 jsonrpc")
            return msg

        method = msg.get("method")
        req_id = msg.get("id")

        if method != "tools/call":
            if req_id is not None:
                m = method if isinstance(method, str) else "unknown"
                self._pending_forwarded[req_id] = m
            self._log_line("client→server", method if isinstance(method, str) else None, "allow", "passthrough")
            return msg

        params = msg.get("params")
        tool_name, arguments = _get_tool_payload(params)

        if tool_name is None:
            if req_id is not None:
                await self.write_stdout(
                    _error_response(
                        req_id,
                        code=-32602,
                        message="Invalid params: 'name' must be a string.",
                    )
                )
            else:
                logger.warning("tools/call missing tool name (notification); forwarding")
                return msg
            self._log_line("client→server", "tools/call", "block", "invalid tool name")
            return None

        if arguments is None:
            if req_id is not None:
                await self.write_stdout(
                    _error_response(
                        req_id,
                        code=-32602,
                        message="Invalid params: 'arguments' must be an object.",
                    )
                )
            else:
                logger.warning("tools/call missing arguments object (notification); forwarding")
                return msg
            self._log_line("client→server", "tools/call", "block", "invalid arguments")
            return None

        findings: list[Any] = []
        try:
            findings = self._input_inspector.inspect(tool_name, arguments)
        except Exception:
            logger.exception("InputInspector failed for %s; allowing (fail-open)", tool_name)

        if any(getattr(f, "severity", None) == "critical" for f in findings):
            if req_id is not None:
                await self.write_stdout(
                    _error_response(
                        req_id,
                        code=-32001,
                        message="Blocked: critical prompt injection pattern detected",
                    )
                )
            else:
                logger.warning("Critical injection in tools/call notification; forwarding (fail-open)")
                return msg
            self._log_line("client→server", "tools/call", "block", "critical injection")
            return None

        decision = None
        try:
            decision = self._policy.evaluate(tool_name, arguments)
        except Exception:
            logger.exception("PolicyEngine.evaluate failed for %s; allowing (fail-open)", tool_name)

        if decision is not None:
            if decision.action == PolicyAction.BLOCK:
                if req_id is not None:
                    await self.write_stdout(
                        _error_response(
                            req_id,
                            code=-32001,
                            message=decision.message or "Blocked by policy",
                        )
                    )
                else:
                    logger.warning("Policy BLOCK for tools/call notification; forwarding (fail-open)")
                    return msg
                self._log_line("client→server", "tools/call", "block", decision.rule_name or "policy")
                return None
            if decision.action == PolicyAction.REQUIRE_APPROVAL:
                logger.warning(
                    "REQUIRE_APPROVAL for tool=%s rule=%s (stdio mode cannot prompt; allowing)",
                    tool_name,
                    decision.rule_name,
                )
                self._log_line("client→server", "tools/call", "allow", f"approval_required rule={decision.rule_name}")
            elif decision.action == PolicyAction.REDACT_OUTPUT:
                self._log_line("client→server", "tools/call", "allow", f"redact_output rule={decision.rule_name}")
            else:
                self._log_line("client→server", "tools/call", "allow", "policy_allow")

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

        if rid is not None and not is_request:
            self._pending_forwarded.pop(rid, None)

        if rid is not None and not is_request and rid in self._pending_tools:
            tool_name = self._pending_tools.pop(rid)
            if msg.get("error") is not None:
                self._log_line("server→client", "tools/call", "allow", f"tool error tool={tool_name}")
                return msg
            result = msg.get("result")
            if isinstance(result, dict):
                try:
                    sanitized, pii_findings = self._output_inspector.inspect(tool_name, result)
                    if pii_findings:
                        msg = dict(msg)
                        msg["result"] = sanitized
                        self._log_line(
                            "server→client",
                            "tools/call",
                            "redact",
                            f"{len(pii_findings)} finding(s) tool={tool_name}",
                        )
                    else:
                        self._log_line("server→client", "tools/call", "allow", f"tool={tool_name}")
                except Exception:
                    logger.exception("OutputInspector failed for %s; forwarding raw (fail-open)", tool_name)
                    self._log_line("server→client", "tools/call", "allow", "inspect_error_fail_open")
            else:
                self._log_line("server→client", "tools/call", "allow", "non-dict result")
            return msg

        if is_request:
            self._log_line("server→client", msg.get("method"), "passthrough", "server request")
        elif "result" in msg or msg.get("error") is not None:
            self._log_line("server→client", "-", "passthrough", "response")

        return msg


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
                "  python -m src.stdio_proxy --policy config/default_policy.yaml --verbose --wrap uvx -- pkg\n"
                "\n"
                "Default policy path: config/default_policy.yaml, overridden by AGENTPARRY_POLICY.\n"
                "Default log file: ~/.agentparry/proxy.log\n"
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        help_parser.add_argument(
            "--policy",
            metavar="PATH",
            help="Policy YAML (default: config/default_policy.yaml or AGENTPARRY_POLICY)",
        )
        help_parser.add_argument(
            "--log",
            dest="log_path",
            metavar="PATH",
            help="Log file (default: ~/.agentparry/proxy.log)",
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
        help="Policy YAML path (default: config/default_policy.yaml or AGENTPARRY_POLICY)",
    )
    parser.add_argument(
        "--log",
        dest="log_path",
        default=None,
        help="Log file path (default: ~/.agentparry/proxy.log)",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging to stderr and log file")
    parsed = parser.parse_args(before)

    policy_path = _resolve_policy_path(parsed.policy)
    log_path = Path(parsed.log_path) if parsed.log_path else _default_log_path()
    _configure_logging(log_path, verbose=parsed.verbose)
    logger = logging.getLogger(__name__)

    cmd, child_args = _parse_child_command(wrap_argv)
    logger.info("Starting wrapped server command=%s args=%s policy=%s", cmd, child_args, policy_path)

    try:
        policy_engine = PolicyEngine(policy_path=str(policy_path))
        input_inspector = InputInspector()
        output_inspector = OutputInspector()
    except Exception:
        logger.exception("Failed to initialize policy/inspectors; exiting")
        return 1

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

    stdout_lock = asyncio.Lock()
    proxy = StdioMcpProxy(
        policy_engine=policy_engine,
        input_inspector=input_inspector,
        output_inspector=output_inspector,
        stdout_lock=stdout_lock,
    )

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
            try:
                asyncio.run_coroutine_threadsafe(stdin_queue.put(None), loop).result()
            except Exception:
                pass

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
            try:
                proc.stdin.close()
            except Exception:
                pass

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
    try:
        stderr_log_handle.close()
    except Exception:
        pass

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
