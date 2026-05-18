"""AgentParry CLI: wrap, scan, harden, verify, and install helpers."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import shlex
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import json5

from src.models import PROXY_URL, ScanReport
from src.scanner import (
    OUTCOME_FALSE_NEGATIVE,
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_TRUE_ALLOW,
    OUTCOME_TRUE_BLOCK,
    SAFE_SCAN_HEADER,
    Scanner,
    is_attack_payload,
    result_outcome,
    save_scan_outputs,
)
from src.stdio_proxy import main_argv as stdio_main_argv

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2  # argparse's own code for a bad command line
EXIT_VULNERABLE = 3
EXIT_ABORTED = 4
EXIT_INTERRUPTED = 130

STDIO_RESTART_NOTE = (
    "Note: the stdio proxy (agentparry wrap) builds its policy engine once at startup and has no "
    "reload path, so a running wrap session keeps the old rules. Restart your MCP client to pick "
    "up this policy."
)


def _split_command(command: str) -> tuple[str, list[str]]:
    parts = shlex.split(command, posix=os.name != "nt")
    if not parts:
        raise SystemExit("error: --command produced no tokens")
    return parts[0], parts[1:]


def _wrap_stdio_args(policy_abs: str, cmd: str, child_args: list[str]) -> list[str]:
    wrap_tail = ["--wrap", cmd]
    if child_args:
        wrap_tail.extend(["--", *child_args])
    return [
        "-m",
        "src.stdio_proxy",
        "--policy",
        policy_abs,
        *wrap_tail,
    ]


def cmd_wrap(args: argparse.Namespace) -> int:
    policy = args.policy
    parts = shlex.split(args.command, posix=os.name != "nt")
    if not parts:
        raise SystemExit("error: --command produced no tokens")

    proxy_argv: list[str] = ["--policy", policy]
    if args.log:
        proxy_argv.extend(["--log", args.log])
    if args.verbose:
        proxy_argv.append("--verbose")
    proxy_argv.append("--wrap")
    proxy_argv.extend(parts)

    try:
        return stdio_main_argv(proxy_argv)
    except KeyboardInterrupt:
        return 130


async def _cmd_scan_live(args: argparse.Namespace) -> int:
    scanner = Scanner(payloads_path=args.payloads)
    report = await scanner.run_scan(
        proxy_url=args.target,
        discover=args.discover,
        safe=args.safe,
    )
    scanner.print_report(report)
    paths = save_scan_outputs(scanner, report, args.output, args.format)
    for p in paths:
        print(f"Report saved: {p}", file=sys.stderr)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if args.report_only is not None and args.target is not None:
        raise SystemExit("error: use either --report-only or --target, not both")
    if args.report_only is not None:
        text = Path(args.report_only).read_text(encoding="utf-8")
        report = ScanReport.model_validate_json(text)
        Scanner(payloads_path=None).print_report(report)
        return 0
    if args.target is None:
        args.target = PROXY_URL
    try:
        return asyncio.run(_cmd_scan_live(args))
    except KeyboardInterrupt:
        return 130


def vulnerability_exit_code(remaining: int, max_vulns: int = 0, *, regression: bool = False) -> int:
    """Map a post-hardening result onto an exit code.

    `cmd_scan` still returns 0 whatever it finds, so its contract does not change
    under anyone's feet; the threshold lives here so it can adopt it later
    without a second implementation.
    """
    if regression or remaining > max_vulns:
        return EXIT_VULNERABLE
    return EXIT_OK


def _is_loopback_target(url: str) -> bool:
    """True when a scan target resolves to this machine.

    Anything unparseable reads as remote. Firing `rm -rf /` at a host because its
    URL did not parse is not a tolerable default.
    """
    host = urlparse(url).hostname
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _guard_live_target(target: str, *, safe: bool, allow_remote: bool) -> None:
    """Refuse to fire real payloads at a non-loopback target by accident.

    Outside `--safe` the proxy forwards the calls upstream, so the payload set
    genuinely runs `rm -rf /` and `curl ... | bash` against whatever is behind
    the target.
    """
    if safe or allow_remote or _is_loopback_target(target):
        return
    raise SystemExit(
        f"error: {target} is not a loopback address. Without --safe the payloads execute upstream "
        "(rm -rf /, curl-pipe-bash). Re-run with --safe, or --allow-remote if you mean it."
    )


def _stdin_is_tty() -> bool:
    return sys.stdin.isatty()


def _confirm(prompt: str) -> bool:
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


async def _probe_target(target: str, *, safe: bool) -> None:
    """Check the target answers at all before firing payloads at it.

    `Scanner._execute_payloads` records a connection error as `passed_through`,
    so an unreachable proxy reports every payload as a vulnerability and the
    generated rules are built from nothing. Any HTTP response counts as reachable
    here, including a JSON-RPC error.
    """
    headers = {SAFE_SCAN_HEADER: "1"} if safe else {}
    rpc = {"jsonrpc": "2.0", "method": "tools/list", "id": 0, "params": {}}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(target, json=rpc, headers=headers)
    except httpx.HTTPError as exc:
        raise SystemExit(f"error: target {target} is unreachable ({exc}); nothing was scanned") from exc


def _policy_reload_url(target: str) -> str:
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}/policy/reload"


async def _reload_policy(target: str) -> bool:
    """Ask the HTTP proxy at `target` to reload its policy. Never fatal.

    The control plane fails closed when `AGENTPARRY_ADMIN_TOKEN` is unset, and
    the target may not be an AgentParry HTTP proxy at all, so a failure is a
    warning: the policy file on disk is already updated either way.
    """
    url = _policy_reload_url(target)
    headers: dict[str, str] = {}
    token = os.environ.get("AGENTPARRY_ADMIN_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, headers=headers)
    except httpx.HTTPError as exc:
        print(f"warning: policy reload at {url} failed ({exc}); the proxy is still on the old rules", file=sys.stderr)
        return False
    if resp.status_code >= 400:
        hint = ""
        if resp.status_code in (401, 403):
            hint = " set AGENTPARRY_ADMIN_TOKEN to the proxy's admin token and retry, or reload it yourself."
        print(
            f"warning: policy reload at {url} returned HTTP {resp.status_code};"
            f" the proxy is still on the old rules.{hint}",
            file=sys.stderr,
        )
        return False
    print(f"Policy reloaded at {url}")
    return True


@dataclass(frozen=True)
class RescanAnalysis:
    """What changed between a before scan and the scan taken after hardening."""

    remaining: int
    fixed: int
    introduced_false_positives: int
    regressed_attacks: int
    unreplayed_correct: int

    @property
    def regression(self) -> bool:
        return self.regressed_attacks > 0 or self.introduced_false_positives > 0


def _analyze_rescan(before: ScanReport, after: ScanReport) -> RescanAnalysis:
    """Compare two reports by outcome rather than by flags.

    `false_negative` is the portable measure of "attack still gets through": in
    safe mode an allowed attack is `evaluated`, never `passed_through`, so
    counting the flag would report a clean sheet.
    """
    after_by_id = {r.payload.id: r for r in after.results}

    remaining = sum(
        1
        for r in after.results
        if result_outcome(r, safe=after.safe_mode) == OUTCOME_FALSE_NEGATIVE
    )

    fixed = 0
    regressed = 0
    introduced_fp = 0
    unreplayed = 0

    for r_before in before.results:
        outcome_before = result_outcome(r_before, safe=before.safe_mode)
        r_after = after_by_id.get(r_before.payload.id)
        if r_after is None:
            if outcome_before in (OUTCOME_TRUE_BLOCK, OUTCOME_TRUE_ALLOW):
                unreplayed += 1
            continue
        outcome_after = result_outcome(r_after, safe=after.safe_mode)
        if is_attack_payload(r_before.payload):
            if outcome_before == OUTCOME_FALSE_NEGATIVE and outcome_after != OUTCOME_FALSE_NEGATIVE:
                fixed += 1
            elif outcome_before == OUTCOME_TRUE_BLOCK and outcome_after == OUTCOME_FALSE_NEGATIVE:
                regressed += 1
        if outcome_after == OUTCOME_FALSE_POSITIVE and outcome_before != OUTCOME_FALSE_POSITIVE:
            introduced_fp += 1

    return RescanAnalysis(
        remaining=remaining,
        fixed=fixed,
        introduced_false_positives=introduced_fp,
        regressed_attacks=regressed,
        unreplayed_correct=unreplayed,
    )


def _print_analysis(analysis: RescanAnalysis, *, full: bool, max_vulns: int) -> None:
    print(f"Fixed: {analysis.fixed}")
    print(f"Vulnerabilities remaining: {analysis.remaining} (threshold {max_vulns})")
    print(f"False positives introduced by the new rules: {analysis.introduced_false_positives}")
    print(f"Previously blocked attacks that now get through: {analysis.regressed_attacks}")
    if not full:
        print(
            f"Not replayed: {analysis.unreplayed_correct} payloads that behaved correctly before. "
            "A rescan only replays payloads that got through, so it cannot see regressions or "
            "over-blocking among the rest. Use --full in CI."
        )


async def _run_after_scan(
    scanner: Scanner,
    before: ScanReport,
    *,
    target: str,
    full: bool,
    discover: bool,
    safe: bool,
) -> ScanReport:
    """Take the post-hardening scan: a complete scan with `full`, else a rescan."""
    if full:
        return await scanner.run_scan(proxy_url=target, discover=discover, safe=safe)
    return await scanner.run_rescan(target, before, safe=safe)


def _claude_config_path() -> Path:
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise SystemExit("error: APPDATA is not set")
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    return home / ".config" / "claude" / "claude_desktop_config.json"


def _load_claude_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"mcpServers": {}}
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"error: invalid JSON object in {path}")
    if "mcpServers" not in data or data["mcpServers"] is None:
        data["mcpServers"] = {}
    if not isinstance(data["mcpServers"], dict):
        raise SystemExit(f"error: mcpServers must be an object in {path}")
    return data


def _stdio_entry_from_command(policy_abs: str, command: str) -> dict[str, Any]:
    cmd, child_args = _split_command(command)
    return {
        "command": sys.executable,
        "args": _wrap_stdio_args(policy_abs, cmd, child_args),
        "env": {"AGENTPARRY_POLICY": policy_abs},
    }


def _stdio_entry_from_existing(policy_abs: str, entry: dict[str, Any]) -> dict[str, Any]:
    if entry.get("url") is not None and not entry.get("command"):
        raise SystemExit(
            "error: this server entry is URL-based; AgentParry stdio wrap only supports command-based MCP servers"
        )
    orig_cmd = entry.get("command")
    if not isinstance(orig_cmd, str) or not orig_cmd.strip():
        raise SystemExit("error: existing server entry has no valid command string")
    orig_args = entry.get("args", [])
    if orig_args is None:
        orig_args = []
    if not isinstance(orig_args, list) or not all(isinstance(a, str) for a in orig_args):
        raise SystemExit("error: existing server args must be a list of strings")
    orig_env = entry.get("env")
    if orig_env is None:
        env: dict[str, str] = {}
    elif isinstance(orig_env, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in orig_env.items()):
        env = dict(orig_env)
    else:
        raise SystemExit("error: existing server env must be an object of string keys and string values")
    env["AGENTPARRY_POLICY"] = policy_abs
    return {
        "command": sys.executable,
        "args": _wrap_stdio_args(policy_abs, orig_cmd, orig_args),
        "env": env,
    }


def cmd_install_claude(args: argparse.Namespace) -> int:
    path = _claude_config_path()
    policy_abs = str(Path(args.policy).expanduser().resolve())

    data = _load_claude_config(path)
    servers: dict[str, Any] = data["mcpServers"]
    name = args.server_name

    if name in servers:
        entry = servers[name]
        if not isinstance(entry, dict):
            raise SystemExit(f"error: mcpServers[{name!r}] must be an object")
        new_entry = _stdio_entry_from_existing(policy_abs, entry)
    else:
        if not args.command:
            raise SystemExit("error: --command is required when adding a new server")
        new_entry = _stdio_entry_from_command(policy_abs, args.command)

    backup = path.with_suffix(path.suffix + ".bak")
    if path.exists():
        shutil.copy2(path, backup)

    servers[name] = new_entry
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    print("Restart Claude Desktop to activate AgentParry protection")
    return 0


def _openclaw_path() -> Path:
    return Path.home() / ".openclaw" / "openclaw.json"


def _load_openclaw(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"mcp": {"servers": {}}}
    with path.open(encoding="utf-8") as f:
        data = json5.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"error: root of {path} must be an object")
    return data


def cmd_install_openclaw(args: argparse.Namespace) -> int:
    path = _openclaw_path()
    policy_abs = str(Path(args.policy).expanduser().resolve())

    data = _load_openclaw(path)
    mcp = data.setdefault("mcp", {})
    if not isinstance(mcp, dict):
        raise SystemExit("error: mcp must be an object")
    servers = mcp.setdefault("servers", {})
    if not isinstance(servers, dict):
        raise SystemExit("error: mcp.servers must be an object")

    if args.stdio:
        if not args.command:
            raise SystemExit("error: --command is required with --stdio")
        servers["agentparry"] = _stdio_entry_from_command(policy_abs, args.command)
    else:
        servers["agentparry"] = {
            "url": args.url,
            "transport": "streamable-http",
        }

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    print("Restart your OpenClaw gateway to activate")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentparry",
        description="AgentParry: scan, protect, and verify AI agent MCP traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_wrap = sub.add_parser(
        "wrap",
        help="Run the stdio MCP proxy around a server command",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            '  agentparry wrap --command "npx some-mcp-server" --policy config/default_policy.yaml\n'
        ),
    )
    p_wrap.add_argument("--command", required=True, help="Shell command line for the real MCP server")
    p_wrap.add_argument(
        "--policy",
        default="config/default_policy.yaml",
        help="Policy YAML (default: config/default_policy.yaml)",
    )
    p_wrap.add_argument("--log", metavar="PATH", help="Log file (default: ~/.agentparry/proxy.log)")
    p_wrap.add_argument("--verbose", action="store_true", help="Verbose logging to stderr and log file")
    p_wrap.set_defaults(handler=cmd_wrap)

    p_scan = sub.add_parser(
        "scan",
        help="Run attack payloads against a proxy or re-print a saved report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  agentparry scan --target http://localhost:9090/mcp --output reports/\n"
            "  agentparry scan --target http://localhost:9090/mcp --discover --format both\n"
            "  agentparry scan --target http://localhost:9090/mcp --safe --format md --output reports/scan.md\n"
            "  agentparry scan --report-only reports/scan_2026-04-12.json\n"
        ),
    )
    p_scan.add_argument(
        "--target",
        default=None,
        metavar="URL",
        help=f"Proxy JSON-RPC URL (default: {PROXY_URL} when not using --report-only)",
    )
    p_scan.add_argument(
        "--report-only",
        metavar="PATH",
        dest="report_only",
        help="Load a saved scan JSON and print the report (no network)",
    )
    p_scan.add_argument("--payloads", default="attacks/payloads.yaml", help="Attack payloads YAML")
    p_scan.add_argument(
        "--output",
        default="reports/",
        help="Output directory or file (.json / .md) depending on --format",
    )
    p_scan.add_argument(
        "--format",
        choices=("json", "md", "both"),
        default="json",
        help="Write JSON, Markdown, or both (default: json)",
    )
    p_scan.add_argument(
        "--discover",
        action="store_true",
        help="Call tools/list first; remap YAML payloads and add schema-driven probes",
    )
    p_scan.add_argument(
        "--safe",
        action="store_true",
        help="Input-side checks only: proxy evaluates policy but does not forward tool calls",
    )
    p_scan.set_defaults(handler=cmd_scan)

    p_claude = sub.add_parser(
        "install-claude",
        help="Wrap an MCP server in Claude Desktop config via AgentParry stdio proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Resolves claude_desktop_config.json per OS, backs up to .bak, and rewrites or adds mcpServers entry.\n"
            "Command-based servers only (not URL-only entries).\n"
            "Example:\n"
            '  agentparry install-claude --server-name my-server --command "npx some-mcp-server"\n'
        ),
    )
    p_claude.add_argument("--server-name", required=True, help="Name under mcpServers")
    p_claude.add_argument(
        "--command",
        default=None,
        help="Required for a new server: command line to wrap",
    )
    p_claude.add_argument(
        "--policy",
        default="config/default_policy.yaml",
        help="Policy YAML path stored as absolute in config (default: config/default_policy.yaml)",
    )
    p_claude.set_defaults(handler=cmd_install_claude)

    p_open = sub.add_parser(
        "install-openclaw",
        help="Add AgentParry to OpenClaw ~/.openclaw/openclaw.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Default: HTTP server at url with transport streamable-http.\n"
            "Use --stdio for a command-based entry (requires --command).\n"
            "JSON5 input is accepted; output is normalized JSON.\n"
        ),
    )
    p_open.add_argument(
        "--url",
        default="http://localhost:9090/mcp",
        help="MCP URL when not using --stdio (default: http://localhost:9090/mcp)",
    )
    p_open.add_argument(
        "--stdio",
        action="store_true",
        help="Register a stdio proxy command instead of streamable-http URL",
    )
    p_open.add_argument(
        "--command",
        default=None,
        help="With --stdio: shell command for the wrapped MCP server",
    )
    p_open.add_argument(
        "--policy",
        default="config/default_policy.yaml",
        help="Policy YAML for --stdio (default: config/default_policy.yaml)",
    )
    p_open.set_defaults(handler=cmd_install_openclaw)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    handler = args.handler
    raise SystemExit(handler(args))


if __name__ == "__main__":
    main()
