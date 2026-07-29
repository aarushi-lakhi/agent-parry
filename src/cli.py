"""AgentParry CLI: wrap, scan, and install helpers."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

import json5

from src.models import PROXY_URL, ScanReport
from src.scanner import Scanner, save_scan_outputs
from src.stdio_proxy import main_argv as stdio_main_argv


def _split_command(command: str) -> tuple[str, list[str]]:
    parts = shlex.split(command, posix=os.name != "nt")
    if not parts:
        raise SystemExit("error: --command produced no tokens")
    return parts[0], parts[1:]


_STDIO_PROXY_ARGS_PREFIX = ["-m", "src.stdio_proxy"]


def _wrap_stdio_args(policy_abs: str, cmd: str, child_args: list[str]) -> list[str]:
    wrap_tail = ["--wrap", cmd]
    if child_args:
        wrap_tail.extend(["--", *child_args])
    return [
        *_STDIO_PROXY_ARGS_PREFIX,
        "--policy",
        policy_abs,
        *wrap_tail,
    ]


def _is_wrapped_stdio_args(args: Any) -> bool:
    """Report whether an arg list already launches the AgentParry stdio proxy.

    Matches on the arg shape rather than on the entry's ``command``, because the
    interpreter path recorded at install time varies by machine and virtualenv.

    Args:
        args: Candidate ``args`` value from an MCP server entry, any type.

    Returns:
        True when the args invoke ``-m src.stdio_proxy``.
    """
    return isinstance(args, list) and args[:2] == _STDIO_PROXY_ARGS_PREFIX


def _repolicy_stdio_args(policy_abs: str, args: list[str]) -> list[str]:
    """Point an already-wrapped arg list at a different policy file.

    Only the proxy's own options are scanned; the search stops at ``--wrap`` or
    ``--`` so a ``--policy`` flag belonging to the wrapped child is left alone.

    Args:
        policy_abs: Absolute path to the policy file to install.
        args: Args of an entry for which `_is_wrapped_stdio_args` is True.

    Returns:
        A new arg list wrapping the same child command with the new policy.
    """
    out = list(args)
    i = len(_STDIO_PROXY_ARGS_PREFIX)
    while i < len(out) and out[i] not in ("--wrap", "--"):
        if out[i] == "--policy" and i + 1 < len(out):
            out[i + 1] = policy_abs
            return out
        i += 1
    out[len(_STDIO_PROXY_ARGS_PREFIX) : len(_STDIO_PROXY_ARGS_PREFIX)] = ["--policy", policy_abs]
    return out


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


_REGENERATED_ENTRY_KEYS = frozenset(
    {
        # Rebuilt to point at the proxy.
        "command",
        "args",
        "env",
        "type",
        "url",
    }
)


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

    if _is_wrapped_stdio_args(orig_args):
        args = _repolicy_stdio_args(policy_abs, orig_args)
    else:
        args = _wrap_stdio_args(policy_abs, orig_cmd, orig_args)

    new_entry: dict[str, Any] = {
        "command": sys.executable,
        "args": args,
        "env": env,
    }
    for key, value in entry.items():
        if key not in _REGENERATED_ENTRY_KEYS:
            new_entry[key] = value
    return new_entry


def cmd_install_claude(args: argparse.Namespace) -> int:
    path = _claude_config_path()
    policy_abs = str(Path(args.policy).expanduser().resolve())

    data = _load_claude_config(path)
    servers: dict[str, Any] = data["mcpServers"]
    name = args.server_name

    already_wrapped = False
    if name in servers:
        entry = servers[name]
        if not isinstance(entry, dict):
            raise SystemExit(f"error: mcpServers[{name!r}] must be an object")
        already_wrapped = _is_wrapped_stdio_args(entry.get("args"))
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

    if already_wrapped:
        print(f"{name!r} was already wrapped by AgentParry; kept the same child command and set policy to {policy_abs}")
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
