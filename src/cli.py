"""AgentParry CLI: wrap, scan, harden, verify, replay, and install helpers."""

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

from src.audit import default_audit_path
from src.models import PROXY_URL, ScanReport
from src.replay import (
    BUCKET_WIDTHS,
    DEFAULT_BUCKET,
    DEFAULT_TOP,
    MAX_SAMPLES,
    build_report,
    read_log,
    render_text,
)
from src.rule_generator import RuleGenerator, plan_autogen_merge, write_policy_text
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
    if args.audit:
        proxy_argv.extend(["--audit", args.audit])
    if args.no_audit:
        proxy_argv.append("--no-audit")
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
        include_known_gaps=args.include_known_gaps,
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


def _count_remaining(report: ScanReport) -> int:
    """Attack payloads the policy still lets through, by outcome."""
    return sum(
        1
        for r in report.results
        if result_outcome(r, safe=report.safe_mode) == OUTCOME_FALSE_NEGATIVE
    )


def _analyze_rescan(before: ScanReport, after: ScanReport) -> RescanAnalysis:
    """Compare two reports by outcome rather than by flags.

    `false_negative` is the portable measure of "attack still gets through": in
    safe mode an allowed attack is `evaluated`, never `passed_through`, so
    counting the flag would report a clean sheet.
    """
    after_by_id = {r.payload.id: r for r in after.results}

    remaining = _count_remaining(after)

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
    include_known_gaps: bool = False,
) -> ScanReport:
    """Take the post-hardening scan: a complete scan with `full`, else a rescan."""
    if full:
        return await scanner.run_scan(
            proxy_url=target,
            discover=discover,
            safe=safe,
            include_known_gaps=include_known_gaps,
        )
    return await scanner.run_rescan(
        target, before, safe=safe, include_known_gaps=include_known_gaps
    )


async def _cmd_harden_live(args: argparse.Namespace) -> int:
    scanner = Scanner(payloads_path=args.payloads)
    await _probe_target(args.target, safe=args.safe)

    before = await scanner.run_scan(
        proxy_url=args.target,
        discover=args.discover,
        safe=args.safe,
        include_known_gaps=args.include_known_gaps,
    )
    scanner.print_report(before)
    if args.output:
        for path in save_scan_outputs(scanner, before, args.output, args.format):
            print(f"Report saved: {path}", file=sys.stderr)

    rules = RuleGenerator().generate_rules(before, include_policy_allowed=args.safe)
    if not rules:
        print("No autogen rules to add; policy left unchanged.")
        return vulnerability_exit_code(_count_remaining(before), args.max_vulns)

    plan = plan_autogen_merge(rules, args.policy)
    print()
    print(
        f"Rules: {len(plan.added)} new, {len(plan.replaced)} replaced, "
        f"{len(plan.kept_autogen)} existing autogen kept, {len(plan.handwritten)} handwritten kept"
    )
    diff = plan.diff(args.policy)
    print(diff if diff else "(no change to the policy file)")

    if args.dry_run:
        print("Dry run: nothing written.")
        return EXIT_OK

    if not plan.changed:
        print("Policy already contains these rules; nothing written.")
        return vulnerability_exit_code(_count_remaining(before), args.max_vulns)

    if not args.yes and not _confirm(f"Write these {len(rules)} rules to {args.policy}? [y/N] "):
        print("Aborted; policy left unchanged.")
        return EXIT_ABORTED

    backup = write_policy_text(plan.after_text, args.policy)
    if backup:
        print(f"Backup: {backup}")
    print(f"Policy updated: {args.policy}")

    if args.no_reload:
        print("Skipped policy reload (--no-reload); reload the proxy yourself for this to take effect.")
    else:
        await _reload_policy(args.target)
    print(STDIO_RESTART_NOTE)

    after = await _run_after_scan(
        scanner,
        before,
        target=args.target,
        full=args.full,
        discover=args.discover,
        safe=args.safe,
        include_known_gaps=args.include_known_gaps,
    )
    scanner.print_comparison(before, after)
    analysis = _analyze_rescan(before, after)
    _print_analysis(analysis, full=args.full, max_vulns=args.max_vulns)
    return vulnerability_exit_code(
        analysis.remaining, args.max_vulns, regression=analysis.regression
    )


def cmd_harden(args: argparse.Namespace) -> int:
    """Scan, generate rules, merge them into the policy, then re-scan."""
    if args.target is None:
        args.target = PROXY_URL
    _guard_live_target(args.target, safe=args.safe, allow_remote=args.allow_remote)

    if not Path(args.policy).is_file():
        raise SystemExit(f"error: policy file not found: {args.policy}")

    if not args.yes and not args.dry_run and not _stdin_is_tty():
        raise SystemExit(
            "error: stdin is not a terminal, so the policy change cannot be confirmed. "
            "Re-run with --yes to accept it, or --dry-run to see the diff."
        )

    try:
        return asyncio.run(_cmd_harden_live(args))
    except FileNotFoundError as exc:
        raise SystemExit(f"error: {exc}") from exc
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


async def _cmd_verify_live(args: argparse.Namespace, before: ScanReport) -> int:
    scanner = Scanner(payloads_path=args.payloads)
    await _probe_target(args.target, safe=args.safe)

    after = await _run_after_scan(
        scanner,
        before,
        target=args.target,
        full=args.full,
        discover=args.discover,
        safe=args.safe,
        include_known_gaps=args.include_known_gaps,
    )
    scanner.print_comparison(before, after)
    analysis = _analyze_rescan(before, after)
    _print_analysis(analysis, full=args.full, max_vulns=args.max_vulns)
    if args.output:
        for path in save_scan_outputs(scanner, after, args.output, args.format):
            print(f"Report saved: {path}", file=sys.stderr)
    return vulnerability_exit_code(
        analysis.remaining, args.max_vulns, regression=analysis.regression
    )


def cmd_verify(args: argparse.Namespace) -> int:
    """Re-scan a target and compare it against a scan taken before the rules landed.

    `--before` is required rather than optional: a baseline scanned inside this
    invocation would be taken after the rules were already in force, so every
    comparison would be against the hardened state and read as a clean sheet.
    """
    before_path = Path(args.before)
    if not before_path.is_file():
        raise SystemExit(f"error: before report not found: {args.before}")
    try:
        before = ScanReport.model_validate_json(before_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(f"error: {args.before} is not a valid scan report: {exc}") from exc

    if before.safe_mode and not args.full:
        raise SystemExit(
            "error: the before report was taken in --safe mode, so it has no passed-through "
            "results for a rescan to replay. Re-run with --full."
        )

    if args.target is None:
        args.target = before.target_url or PROXY_URL
    _guard_live_target(args.target, safe=args.safe, allow_remote=args.allow_remote)

    try:
        return asyncio.run(_cmd_verify_live(args, before))
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


def cmd_replay(args: argparse.Namespace) -> int:
    """Read a recorded audit log back and report on it, optionally against a new policy.

    Exits 3 on a finding the caller asked to gate on: any FAIL_OPEN with
    `--fail-on-fail-open`, or more than `--max-new-blocks` recorded allows that
    the candidate policy would stop.
    """
    log_path = Path(args.log).expanduser() if args.log else default_audit_path()
    if not log_path.is_file():
        raise SystemExit(f"error: audit log not found: {log_path}")
    for label, value in (("--policy", args.policy), ("--against", args.against)):
        if value is not None and not Path(value).expanduser().is_file():
            raise SystemExit(f"error: {label} policy file not found: {value}")

    log = read_log(log_path, include_rotated=args.rotated)
    report = build_report(
        log,
        bucket=args.bucket,
        top=args.top,
        baseline_policy=args.policy,
        candidate_policy=args.against,
        max_samples=args.max_samples,
    )

    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_text(report))

    if args.fail_on_fail_open and report.summary.fail_open > 0:
        return EXIT_VULNERABLE
    gate = args.max_new_blocks
    if gate is not None and report.diff is not None and report.diff.newly_blocked > gate:
        return EXIT_VULNERABLE
    return EXIT_OK


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


CLAUDE_CODE_SCOPES = ("project", "local", "user")


def _claude_code_config_path(scope: str, project_dir: str | None) -> Path:
    """Resolve the file Claude Code reads for a given scope.

    Layouts verified against `claude mcp add` (CLI v2.1.220) writing into a
    throwaway HOME: project scope writes ./.mcp.json, while local and user
    scope both write ~/.claude.json (local nested under projects[cwd]).
    """
    if scope == "project":
        return _project_dir(project_dir) / ".mcp.json"
    if scope in ("local", "user"):
        return Path.home() / ".claude.json"
    raise SystemExit(f"error: unknown scope {scope!r}")


def _project_dir(project_dir: str | None) -> Path:
    return Path(project_dir or ".").expanduser().resolve()


def _load_claude_code_config(path: Path) -> dict[str, Any]:
    """Load a Claude Code config file, preserving every unrelated key."""
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"error: root of {path} must be a JSON object")
    return data


def _claude_code_servers(data: dict[str, Any], scope: str, project_dir: str | None) -> dict[str, Any]:
    """Return the mutable mcpServers mapping for a scope, creating it if absent."""
    if scope == "local":
        projects = data.setdefault("projects", {})
        if not isinstance(projects, dict):
            raise SystemExit("error: projects must be a JSON object")
        entry = projects.setdefault(str(_project_dir(project_dir)), {})
        if not isinstance(entry, dict):
            raise SystemExit("error: each projects entry must be a JSON object")
        container: Any = entry
    else:
        container = data

    servers = container.get("mcpServers")
    if servers is None:
        servers = {}
        container["mcpServers"] = servers
    if not isinstance(servers, dict):
        raise SystemExit("error: mcpServers must be a JSON object")
    return servers


def _claude_code_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Stamp the explicit stdio transport Claude Code records."""
    return {"type": "stdio", **entry}


def cmd_install_claude_code(args: argparse.Namespace) -> int:
    scope = args.scope
    path = _claude_code_config_path(scope, args.project_dir)
    policy_abs = str(Path(args.policy).expanduser().resolve())

    data = _load_claude_code_config(path)
    servers = _claude_code_servers(data, scope, args.project_dir)
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

    if args.python:
        new_entry["command"] = args.python

    backup = path.with_suffix(path.suffix + ".bak")
    if path.exists():
        shutil.copy2(path, backup)

    servers[name] = _claude_code_entry(new_entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    if already_wrapped:
        print(f"{name!r} was already wrapped by AgentParry; kept the same child command and set policy to {policy_abs}")
    if scope == "project":
        print(
            f"warning: {path} is usually committed, and this entry hardcodes "
            f"{new_entry['command']} and an absolute policy path, so it will not "
            "work in another checkout"
        )
    print("Restart Claude Code (or run /mcp) to activate AgentParry protection")
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


def _add_known_gap_arg(parser: argparse.ArgumentParser) -> None:
    """The flag that folds known_gap payloads back into the rates."""
    parser.add_argument(
        "--include-known-gaps",
        action="store_true",
        dest="include_known_gaps",
        help="Count known_gap payloads in the detection rate and vulnerability score too",
    )


def _add_scan_target_args(parser: argparse.ArgumentParser, *, target_default: str) -> None:
    """Target selection and payload-execution safety flags, shared by harden and verify."""
    parser.add_argument(
        "--target",
        default=None,
        metavar="URL",
        help=f"Proxy JSON-RPC URL (default: {target_default})",
    )
    parser.add_argument("--payloads", default="attacks/payloads.yaml", help="Attack payloads YAML")
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Call tools/list first; remap YAML payloads and add schema-driven probes",
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Input-side checks only: the proxy evaluates policy but does not forward tool calls",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        dest="allow_remote",
        help="Permit a non-loopback --target without --safe. The payloads really execute upstream",
    )
    _add_known_gap_arg(parser)


def _add_verify_scope_args(parser: argparse.ArgumentParser) -> None:
    """Rescan scope and the vulnerability threshold, shared by harden and verify."""
    parser.add_argument(
        "--full",
        action="store_true",
        help="Re-run the whole payload set instead of replaying only what got through (CI mode)",
    )
    parser.add_argument(
        "--max-vulns",
        type=int,
        default=0,
        dest="max_vulns",
        metavar="N",
        help="Exit 3 when more than N vulnerabilities remain (default: 0)",
    )


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
    p_wrap.add_argument(
        "--audit",
        metavar="PATH",
        help="JSONL audit log (default: ~/.agentparry/audit.jsonl or AGENTPARRY_AUDIT_PATH)",
    )
    p_wrap.add_argument(
        "--no-audit",
        dest="no_audit",
        action="store_true",
        help="Disable the JSONL audit log (same as AGENTPARRY_AUDIT=0)",
    )
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
    _add_known_gap_arg(p_scan)
    p_scan.set_defaults(handler=cmd_scan)

    p_harden = sub.add_parser(
        "harden",
        help="Scan, merge generated rules into the policy, then re-scan to verify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Additive: existing autogen_ rules are kept, same-named ones replaced, handwritten\n"
            "rules preserved. Backs the policy up to a .bak sibling, prints a unified diff, and\n"
            "asks before writing unless --yes.\n"
            "Exit codes: 0 clean, 1 error, 2 usage, 3 vulnerabilities remain or a regression was\n"
            "found, 4 aborted at the prompt, 130 interrupted.\n"
            "Examples:\n"
            "  agentparry harden --target http://localhost:9090/mcp --dry-run\n"
            "  agentparry harden --target http://localhost:9090/mcp --yes --full\n"
            "  agentparry harden --target https://prod.example/mcp --safe --yes\n"
        ),
    )
    _add_scan_target_args(p_harden, target_default=PROXY_URL)
    p_harden.add_argument(
        "--policy",
        default="config/default_policy.yaml",
        help="Policy YAML to merge rules into (default: config/default_policy.yaml)",
    )
    p_harden.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print the diff and exit 0 without writing anything",
    )
    p_harden.add_argument("--yes", action="store_true", help="Write the policy without confirming")
    p_harden.add_argument(
        "--no-reload",
        action="store_true",
        dest="no_reload",
        help="Do not POST /policy/reload on the target after writing",
    )
    p_harden.add_argument(
        "--output",
        default=None,
        help="Save the pre-hardening scan here, for a later `agentparry verify --before`",
    )
    p_harden.add_argument(
        "--format",
        choices=("json", "md", "both"),
        default="json",
        help="Format for --output (default: json)",
    )
    _add_verify_scope_args(p_harden)
    p_harden.set_defaults(handler=cmd_harden)

    p_verify = sub.add_parser(
        "verify",
        help="Re-scan a target and compare it against a saved pre-hardening scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "--before is required: a baseline taken now would already include the new rules.\n"
            "The default replays only the payloads that got through before, which cannot see\n"
            "regressions or over-blocking among the rest; use --full in CI.\n"
            "Exit codes: 0 clean, 1 error, 2 usage, 3 vulnerabilities remain or a regression was\n"
            "found, 130 interrupted.\n"
            "Examples:\n"
            "  agentparry verify --before reports/scan_2026-04-12.json\n"
            "  agentparry verify --before reports/before.json --full --max-vulns 0\n"
        ),
    )
    p_verify.add_argument(
        "--before",
        required=True,
        metavar="PATH",
        help="Saved scan JSON from before the rules were applied",
    )
    _add_scan_target_args(p_verify, target_default="the before report's target_url")
    p_verify.add_argument(
        "--output",
        default=None,
        help="Save the post-hardening scan here",
    )
    p_verify.add_argument(
        "--format",
        choices=("json", "md", "both"),
        default="json",
        help="Format for --output (default: json)",
    )
    _add_verify_scope_args(p_verify)
    p_verify.set_defaults(handler=cmd_verify)

    p_replay = sub.add_parser(
        "replay",
        help="Re-read a recorded audit log and replay its decisions against a policy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Reads the JSONL audit log written by both proxies. Always reports dead rules,\n"
            "which rules fired on which tools, FAIL_OPEN decisions (a rule crashed and traffic\n"
            "was allowed unchecked), REQUIRE_APPROVAL over stdio (allowed, never prompted),\n"
            "response-side result and metadata decisions, and a decision histogram.\n"
            "A default log stores a keyed HMAC of the arguments, not the arguments, so a\n"
            "pattern_match rule cannot be re-run. Those decisions are reported as\n"
            "indeterminate, never as allowed.\n"
            "Exit codes: 0 clean, 1 error, 2 usage, 3 a gated finding was exceeded.\n"
            "Examples:\n"
            "  agentparry replay\n"
            "  agentparry replay --log /tmp/audit.jsonl --policy config/default_policy.yaml\n"
            "  agentparry replay --policy config/default_policy.yaml --against /tmp/candidate.yaml\n"
            "  agentparry replay --format json --fail-on-fail-open\n"
        ),
    )
    p_replay.add_argument(
        "--log",
        default=None,
        metavar="PATH",
        help="Audit JSONL to read (default: ~/.agentparry/audit.jsonl or AGENTPARRY_AUDIT_PATH)",
    )
    p_replay.add_argument(
        "--rotated",
        action="store_true",
        help="Also read the rotated .1 sibling, oldest first",
    )
    p_replay.add_argument(
        "--policy",
        default=None,
        metavar="PATH",
        help="Policy in force when the log was recorded; enables dead-rule detection",
    )
    p_replay.add_argument(
        "--against",
        default=None,
        metavar="PATH",
        help="Candidate policy to replay the recorded decisions against",
    )
    p_replay.add_argument(
        "--bucket",
        choices=tuple(BUCKET_WIDTHS),
        default=DEFAULT_BUCKET,
        help=f"Histogram bucket width (default: {DEFAULT_BUCKET})",
    )
    p_replay.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP,
        metavar="N",
        help=f"How many rules and tools to list (default: {DEFAULT_TOP})",
    )
    p_replay.add_argument(
        "--max-samples",
        type=int,
        default=MAX_SAMPLES,
        dest="max_samples",
        metavar="N",
        help=f"With --against, how many changed decisions to list (default: {MAX_SAMPLES})",
    )
    p_replay.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    p_replay.add_argument(
        "--fail-on-fail-open",
        action="store_true",
        dest="fail_on_fail_open",
        help="Exit 3 if any decision was FAIL_OPEN",
    )
    p_replay.add_argument(
        "--max-new-blocks",
        type=int,
        default=None,
        dest="max_new_blocks",
        metavar="N",
        help="With --against, exit 3 when more than N recorded allows would now be stopped",
    )
    p_replay.set_defaults(handler=cmd_replay)

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

    p_code = sub.add_parser(
        "install-claude-code",
        help="Wrap an MCP server in Claude Code config via AgentParry stdio proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scopes: project writes ./.mcp.json, local writes projects[cwd].mcpServers in\n"
            "~/.claude.json, user writes top-level mcpServers in ~/.claude.json.\n"
            "Project scope is normally committed, and the entry hardcodes an interpreter\n"
            "path and an absolute policy path, so it will not work in another checkout.\n"
            "Project-scope servers also need in-app approval on first load.\n"
            "Command-based servers only (not URL-only entries).\n"
            "Example:\n"
            '  agentparry install-claude-code --server-name fs --command "npx @scope/fs /tmp"\n'
        ),
    )
    p_code.add_argument("--server-name", required=True, help="Name under mcpServers")
    p_code.add_argument(
        "--command",
        default=None,
        help="Required for a new server: command line to wrap",
    )
    p_code.add_argument(
        "--policy",
        default="config/default_policy.yaml",
        help="Policy YAML path stored as absolute in config (default: config/default_policy.yaml)",
    )
    p_code.add_argument(
        "--scope",
        choices=CLAUDE_CODE_SCOPES,
        default="project",
        help="Which Claude Code config to write (default: project)",
    )
    p_code.add_argument(
        "--project-dir",
        default=None,
        help="Project directory for project and local scope (default: cwd)",
    )
    p_code.add_argument(
        "--python",
        default=None,
        metavar="PATH",
        help=f"Interpreter recorded as the entry command (default: {sys.executable})",
    )
    p_code.set_defaults(handler=cmd_install_claude_code)

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
