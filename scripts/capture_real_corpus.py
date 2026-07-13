#!/usr/bin/env python
"""Capture real MCP server discovery payloads into a corpus fixture.

Boots the AgentParry HTTP proxy against a stdio MCP server, records the
``initialize`` and ``tools/list`` results the proxy saw, sanitizes machine
specific strings out of them and writes one JSON file per server.

Only discovery methods are sent. No ``tools/call`` ever leaves this script, so
pointing it at a real server cannot make that server act.

    python scripts/capture_real_corpus.py \
        --name filesystem \
        --command "npx -y @modelcontextprotocol/server-filesystem /private/tmp/scratch"
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "tests" / "fixtures" / "real_servers"
PROTOCOL_VERSION = "2025-06-18"

HOME_PLACEHOLDER = "/home/USER"
SCRATCH_PLACEHOLDER = "/tmp/mcp-scratch"
HOST_PLACEHOLDER = "HOST"
USER_PLACEHOLDER = "USER"

_SECRET_SHAPED = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{20,})"
)


class CaptureError(RuntimeError):
    """A server failed to install, boot or answer discovery."""


def free_port() -> int:
    """Return a port the OS says is free right now."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_replacements(scratch: str | None) -> list[tuple[str, str]]:
    """Return longest-first (needle, placeholder) pairs for sanitization."""
    pairs: list[tuple[str, str]] = []
    if scratch:
        pairs.append((str(Path(scratch).resolve()), SCRATCH_PLACEHOLDER))
        pairs.append((scratch, SCRATCH_PLACEHOLDER))
    home = os.path.expanduser("~")
    if home and home != "/":
        pairs.append((home, HOME_PLACEHOLDER))
    hostname = socket.gethostname()
    if hostname and len(hostname) > 3:
        pairs.append((hostname, HOST_PLACEHOLDER))
        short = hostname.split(".", 1)[0]
        if len(short) > 3:
            pairs.append((short, HOST_PLACEHOLDER))
    user = os.environ.get("USER") or ""
    if len(user) > 2:
        pairs.append((user, USER_PLACEHOLDER))
    deduped = {needle: placeholder for needle, placeholder in pairs if needle}
    return sorted(deduped.items(), key=lambda item: -len(item[0]))


def sanitize_text(text: str, replacements: list[tuple[str, str]]) -> str:
    """Replace machine-specific and credential-shaped substrings in one string."""
    out = text
    for needle, placeholder in replacements:
        out = out.replace(needle, placeholder)
    return _SECRET_SHAPED.sub("REDACTED_TOKEN", out)


def sanitize(value: Any, replacements: list[tuple[str, str]]) -> Any:
    """Recursively sanitize every string in a JSON-like value, keys included."""
    if isinstance(value, str):
        return sanitize_text(value, replacements)
    if isinstance(value, dict):
        return {
            sanitize_text(str(key), replacements): sanitize(nested, replacements)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [sanitize(nested, replacements) for nested in value]
    return value


def start_proxy(command: str, port: int, policy: Path) -> subprocess.Popen[bytes]:
    """Launch src.proxy in a subprocess wired to a stdio MCP server."""
    env = dict(os.environ)
    env["AGENTPARRY_UPSTREAM_CMD"] = command
    env.pop("AGENTPARRY_UPSTREAM_URL", None)
    env["AGENTPARRY_AUDIT_LOG"] = os.devnull
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "src.proxy",
            "--policy",
            str(policy),
            "--port",
            str(port),
            "--log-level",
            "error",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def wait_for_health(port: int, timeout: float) -> None:
    """Poll /health until the proxy answers, or raise."""
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"http://127.0.0.1:{port}/health", timeout=2.0)
            if resp.status_code == 200:
                return
        except Exception as exc:
            last = exc
        time.sleep(0.25)
    raise CaptureError(f"proxy on port {port} never became healthy: {last}")


def rpc(port: int, method: str, params: dict[str, Any], request_id: int, timeout: float) -> dict[str, Any]:
    """Send one JSON-RPC request through the proxy and return the whole envelope."""
    body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    resp = httpx.post(f"http://127.0.0.1:{port}/mcp", json=body, timeout=timeout)
    resp.raise_for_status()
    return dict(resp.json())


def collect_tool_pages(port: int, timeout: float) -> tuple[list[dict[str, Any]], int, bool]:
    """Walk tools/list cursors, returning (pages, tool count, paginated)."""
    pages: list[dict[str, Any]] = []
    cursor: str | None = None
    request_id = 10
    for _ in range(10):
        params: dict[str, Any] = {} if cursor is None else {"cursor": cursor}
        envelope = rpc(port, "tools/list", params, request_id, timeout)
        request_id += 1
        if envelope.get("error"):
            raise CaptureError(f"tools/list error: {envelope['error']}")
        result = envelope.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise CaptureError(f"tools/list returned no tools array: {envelope}")
        pages.append(result)
        cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
        if cursor is None:
            break
    total = sum(len(page["tools"]) for page in pages)
    return pages, total, len(pages) > 1


def capture(name: str, command: str, scratch: str | None, timeout: float, policy: Path) -> dict[str, Any]:
    """Boot one server behind the proxy and return its sanitized corpus entry."""
    port = free_port()
    proc = start_proxy(command, port, policy)
    try:
        wait_for_health(port, timeout=20.0)
        init_envelope = rpc(
            port,
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentparry-corpus", "version": "0"},
            },
            1,
            timeout,
        )
        if init_envelope.get("error"):
            raise CaptureError(f"initialize error: {init_envelope['error']}")
        initialize = init_envelope.get("result")
        if not isinstance(initialize, dict):
            raise CaptureError(f"initialize returned no result: {init_envelope}")
        pages, tool_count, paginated = collect_tool_pages(port, timeout)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    replacements = build_replacements(scratch)
    entry = {
        "server": name,
        "command": sanitize_text(command, replacements),
        "protocol_version": initialize.get("protocolVersion"),
        "paginated": paginated,
        "page_count": len(pages),
        "tool_count": tool_count,
        "initialize": sanitize(initialize, replacements),
        "tools_list": sanitize(pages[0], replacements),
        "extra_pages": [sanitize(page, replacements) for page in pages[1:]],
    }
    return entry


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="Corpus entry name, used as the filename stem")
    parser.add_argument("--command", required=True, help="stdio MCP server command line")
    parser.add_argument("--scratch", default=None, help="Throwaway directory passed to the server, sanitized out")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="Where to write the JSON entry")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-request timeout in seconds")
    parser.add_argument(
        "--policy",
        default=str(REPO_ROOT / "config" / "default_policy.yaml"),
        help="Policy file the proxy loads",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Capture one server and write its fixture, returning a shell exit code."""
    args = parse_args(argv)
    try:
        entry = capture(args.name, args.command, args.scratch, args.timeout, Path(args.policy))
    except Exception as exc:
        print(f"FAILED {args.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{args.name}.json"
    path.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"captured {args.name}: {entry['tool_count']} tools, paginated={entry['paginated']} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
