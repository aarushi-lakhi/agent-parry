"""AgentParry CLI: quickstart, wrap, scan, harden, verify, replay, pins, and install helpers.

`HELP_OVERVIEW` is the grouped narrative `agentparry --help` prints; the per-command
listing argparse would generate is suppressed in favor of it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import json5

from src import audit
from src.audit import default_audit_path
from src.models import PROXY_URL, AuditAction, AuditTransport, ScanReport, ServerPin
from src.pins import PinStore, accept_pending, forget
from src.policy_lint import (
    LintFinding,
    LintReport,
    introduced_findings,
    lint_policy,
    render_findings,
    render_report,
)
from src.replay import (
    BUCKET_WIDTHS,
    DEFAULT_BUCKET,
    DEFAULT_TOP,
    MAX_SAMPLES,
    build_report,
    read_log,
    render_text,
)
from src.resources import (
    PAYLOADS_DEFAULT_HELP,
    POLICY_DEFAULT_HELP,
    copy_out_policy,
    resolve_payloads,
    resolve_policy,
    user_policy_path,
)
from src.rule_generator import (
    AutogenMergePlan,
    RuleGenerator,
    plan_autogen_merge,
    write_policy_text,
)
from src.scanner import (
    OUTCOME_FALSE_NEGATIVE,
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_TRUE_ALLOW,
    OUTCOME_TRUE_BLOCK,
    SAFE_SCAN_HEADER,
    Scanner,
    compute_confusion_matrix,
    format_rate,
    is_attack_payload,
    result_outcome,
    save_scan_outputs,
)
from src.stdio_proxy import DEFAULT_RELOAD_INTERVAL
from src.stdio_proxy import main_argv as stdio_main_argv

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2  # argparse's own code for a bad command line
EXIT_VULNERABLE = 3
EXIT_ABORTED = 4
EXIT_INTERRUPTED = 130

STDIO_RELOAD_NOTE = (
    "Note: a running `agentparry wrap` session picks this policy up on its own within a few "
    "seconds, and keeps the previous rules if the file does not parse. A session started with "
    "--no-reload-on-change keeps the old rules until you restart your MCP client."
)


def _split_command(command: str) -> tuple[str, list[str]]:
    parts = shlex.split(command, posix=os.name != "nt")
    if not parts:
        raise SystemExit("error: --command produced no tokens")
    return parts[0], parts[1:]


ENTRY_COMMAND = "agentparry"
"""The console script an installed entry invokes, so no interpreter path is recorded."""

_STDIO_PROXY_ARGS_PREFIX = ["-m", "src.stdio_proxy"]
_WRAP_ARGS_PREFIX = ["wrap"]


def _wrap_stdio_args(policy_abs: str | None, cmd: str, child_args: list[str]) -> list[str]:
    """Args for `python -m src.stdio_proxy`, the shape `--python` installs."""
    args = list(_STDIO_PROXY_ARGS_PREFIX)
    if policy_abs:
        args.extend(["--policy", policy_abs])
    args.extend(["--wrap", cmd])
    if child_args:
        args.extend(["--", *child_args])
    return args


def _wrap_cli_args(policy_abs: str | None, cmd: str, child_args: list[str]) -> list[str]:
    """Args for the installed `agentparry` console script.

    Omitting `--policy` is deliberate when the caller did not ask for one: the
    wrapped proxy then resolves the default itself at run time, which is what
    makes a committed entry work in someone else's checkout.
    """
    args = list(_WRAP_ARGS_PREFIX)
    if policy_abs:
        args.extend(["--policy", policy_abs])
    args.extend(["--command", shlex.join([cmd, *child_args])])
    return args


def _is_wrapped_stdio_args(args: Any) -> bool:
    """Report whether an arg list already launches the AgentParry stdio proxy.

    Matches on the arg shape rather than on the entry's ``command``, because both
    the console script and the interpreter path recorded by older installs vary
    by machine and virtualenv.

    Args:
        args: Candidate ``args`` value from an MCP server entry, any type.

    Returns:
        True for either ``agentparry wrap --command ...`` or ``-m src.stdio_proxy``.
    """
    if not isinstance(args, list):
        return False
    if args[:2] == _STDIO_PROXY_ARGS_PREFIX:
        return True
    return args[:1] == _WRAP_ARGS_PREFIX and "--command" in args


def _wrapped_child_command(args: list[str]) -> tuple[str, list[str]]:
    """Recover the wrapped server command from an already-wrapped arg list.

    Only the proxy's own options are scanned, so a ``--policy`` or ``--command``
    flag belonging to the wrapped child is left inside the child command.

    Args:
        args: Args of an entry for which `_is_wrapped_stdio_args` is True.

    Returns:
        The child command and its arguments.
    """
    if args[:2] == _STDIO_PROXY_ARGS_PREFIX:
        i = len(_STDIO_PROXY_ARGS_PREFIX)
        while i < len(args):
            if args[i] == "--wrap":
                tail = args[i + 1 :]
                if not tail:
                    raise SystemExit("error: existing wrapped entry has no server command after --wrap")
                rest = tail[1:]
                if rest[:1] == ["--"]:
                    rest = rest[1:]
                return tail[0], rest
            i += 1
        raise SystemExit("error: existing wrapped entry has no --wrap")
    for i, value in enumerate(args):
        if value == "--command" and i + 1 < len(args):
            return _split_command(args[i + 1])
    raise SystemExit("error: existing wrapped entry has no --command")


def cmd_wrap(args: argparse.Namespace) -> int:
    policy = str(resolve_policy(args.policy).path)
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
    if not args.reload_on_change:
        proxy_argv.append("--no-reload-on-change")
    if args.reload_interval is not None:
        proxy_argv.extend(["--reload-interval", str(args.reload_interval)])
    if args.verbose:
        proxy_argv.append("--verbose")
    proxy_argv.append("--wrap")
    proxy_argv.extend(parts)

    try:
        return stdio_main_argv(proxy_argv)
    except KeyboardInterrupt:
        return 130


async def _cmd_scan_live(args: argparse.Namespace) -> int:
    scanner = Scanner(payloads_path=resolve_payloads(args.payloads).path)
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


def _lint_merge(plan: AutogenMergePlan, policy_path: str | Path, payloads_path: str | Path) -> list[LintFinding]:
    """High-severity findings the merge would add to the policy.

    The candidate text is linted from a tempfile rather than the policy path,
    because linting the path would only see the rules that already shipped and
    the rules being written are the ones worth checking.
    """
    payloads = payloads_path if Path(payloads_path).is_file() else None
    before = lint_policy(policy_path, payloads)
    with tempfile.TemporaryDirectory(prefix="agentparry-harden-") as tmp:
        candidate = Path(tmp) / Path(policy_path).name
        candidate.write_text(plan.after_text, encoding="utf-8")
        after = lint_policy(candidate, payloads)
    return introduced_findings(before, after)


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


COPY_ON_WRITE_NOTE = (
    "The default policy ships inside the package and is not yours to edit, so the merged rules go "
    "to {destination}. Every agentparry command prefers that copy from now on; delete it to go "
    "back to the shipped rules."
)


def _harden_destination(args: argparse.Namespace) -> Path:
    """Where `harden` writes: the resolved policy, or a user copy of a packaged one."""
    if args.policy_packaged:
        return user_policy_path()
    return Path(args.policy)


async def _cmd_harden_live(args: argparse.Namespace) -> int:
    scanner = Scanner(payloads_path=resolve_payloads(args.payloads).path)
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

    introduced: list[LintFinding] = []
    if plan.changed and not args.no_lint:
        introduced = _lint_merge(plan, args.policy, resolve_payloads(args.payloads).path)
    if introduced:
        print()
        print(f"Policy lint: {len(introduced)} high-severity finding(s) introduced by these rules")
        print("\n".join(render_findings(introduced)))

    if args.dry_run:
        print("Dry run: nothing written.")
        return EXIT_OK

    if not plan.changed:
        print("Policy already contains these rules; nothing written.")
        return vulnerability_exit_code(_count_remaining(before), args.max_vulns)

    if introduced and not args.force:
        print(
            "Refusing to write: these rules block legitimate traffic or cannot fire as written. "
            "Fix them, re-run with --force to write them anyway, or --no-lint to skip the check."
        )
        return EXIT_VULNERABLE
    if introduced:
        print("Writing anyway: --force.")

    destination = _harden_destination(args)
    if args.policy_packaged:
        print(COPY_ON_WRITE_NOTE.format(destination=destination))

    if not args.yes and not _confirm(f"Write these {len(rules)} rules to {destination}? [y/N] "):
        print("Aborted; policy left unchanged.")
        return EXIT_ABORTED

    if args.policy_packaged:
        copy_out_policy(Path(args.policy))
    backup = write_policy_text(plan.after_text, destination)
    if backup:
        print(f"Backup: {backup}")
    print(f"Policy updated: {destination}")

    if args.no_reload:
        print("Skipped policy reload (--no-reload); reload the proxy yourself for this to take effect.")
    else:
        await _reload_policy(args.target)
    print(STDIO_RELOAD_NOTE)

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
    """Scan, generate rules, merge them into the policy, then re-scan.

    A packaged default is merged from but never written to; see
    `COPY_ON_WRITE_NOTE`.
    """
    if args.target is None:
        args.target = PROXY_URL
    _guard_live_target(args.target, safe=args.safe, allow_remote=args.allow_remote)

    resolved = resolve_policy(args.policy)
    args.policy = str(resolved.path)
    args.policy_packaged = resolved.packaged
    if not resolved.path.is_file():
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
    scanner = Scanner(payloads_path=resolve_payloads(args.payloads).path)
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


QUICKSTART_MAX_GAPS = 5
QUICKSTART_HEALTH_TIMEOUT = 20.0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _wait_for_health(url: str, timeout: float) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    async with httpx.AsyncClient(timeout=2.0) as client:
        while loop.time() < deadline:
            try:
                if (await client.get(url)).status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.25)
    return False


@contextlib.asynccontextmanager
async def _local_proxy(command: str, policy: str) -> AsyncIterator[str]:
    """Run an AgentParry HTTP proxy in front of `command` for the life of the block.

    AGENTPARRY_UPSTREAM_URL is dropped from the child environment: the proxy
    returns 503 when both upstream settings are present, and the caller's shell
    may already carry one.
    """
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if k != "AGENTPARRY_UPSTREAM_URL"}
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "src.proxy",
            "--upstream-command", command,
            "--policy", policy,
            "--host", "127.0.0.1",
            "--port", str(port),
            "--log-level", "warning",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        if not await _wait_for_health(f"http://127.0.0.1:{port}/health", QUICKSTART_HEALTH_TIMEOUT):
            raise SystemExit(f"error: the proxy did not come up on port {port}; nothing was scanned")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def quickstart_verdict(report: ScanReport) -> list[str]:
    """Three numbers and the payloads still getting through, in reading order."""
    matrix = report.matrix or compute_confusion_matrix(report.results, safe=report.safe_mode)
    gaps = [
        r.payload.id
        for r in report.results
        if result_outcome(r, safe=report.safe_mode) == OUTCOME_FALSE_NEGATIVE
    ]
    lines = [
        f"Attacks stopped:      {matrix.true_block}/{matrix.attack_total}"
        f" (detection {format_rate(matrix.detection_rate)})",
        f"Benign calls allowed: {matrix.true_allow}/{matrix.benign_total}"
        f" (over-block {format_rate(matrix.false_positive_rate)})",
    ]
    if not gaps:
        lines.append("Nothing got through.")
        return lines
    shown = ", ".join(gaps[:QUICKSTART_MAX_GAPS])
    more = f" and {len(gaps) - QUICKSTART_MAX_GAPS} more" if len(gaps) > QUICKSTART_MAX_GAPS else ""
    lines.append(f"Still getting through: {len(gaps)} payload(s): {shown}{more}")
    return lines


def _quickstart_next_steps(target: str, command: str | None) -> list[str]:
    """What to run next, as intent-then-command pairs.

    A `--command` run scanned a throwaway proxy on a port that is already gone,
    so it must not hand back a `--target` for it.
    """
    steps: list[str] = []
    if command:
        steps += [
            "  Keep a proxy in front of that server for real traffic:",
            f'    agentparry wrap --command "{command}"',
            "  Or register it with your MCP client:",
            f'    agentparry install-claude --server-name my-server --command "{command}"',
        ]
    else:
        steps += [
            "  Write rules for what got through, then re-scan:",
            f"    agentparry harden --target {target} --safe --yes",
        ]
    steps += [
        "  Read back what the proxy decided:",
        "    agentparry replay",
    ]
    return steps


async def _cmd_quickstart_live(args: argparse.Namespace, policy: str) -> int:
    scanner = Scanner(payloads_path=resolve_payloads(args.payloads).path)

    async def _scan(target: str) -> ScanReport:
        print(f"[2/3] Safe scan of {target}: policy is evaluated, no call is forwarded upstream")
        await _probe_target(target, safe=True)
        return await scanner.run_scan(proxy_url=target, discover=True, safe=True)

    if args.command:
        print(f"[1/3] Starting an AgentParry proxy in front of: {args.command}")
        async with _local_proxy(args.command, policy) as target:
            report = await _scan(target)
    else:
        target = args.target
        print(f"[1/3] Using the proxy already running at {target}")
        report = await _scan(target)

    print()
    print("[3/3] Verdict")
    for line in quickstart_verdict(report):
        print(f"  {line}")
    print()
    print(f"Policy: {policy}")
    print("Next:")
    for line in _quickstart_next_steps(target, args.command):
        print(line)
    return EXIT_OK


def cmd_quickstart(args: argparse.Namespace) -> int:
    """Scan one server in safe mode and say what to do next.

    Always safe mode, and always exit 0 on a finding: this is the introduction,
    and `harden`, `verify` and `lint-policy` are the commands that gate.
    """
    if bool(args.command) == bool(args.target):
        raise SystemExit("error: pass exactly one of --command or --target")
    policy = str(resolve_policy(args.policy).path)
    try:
        return asyncio.run(_cmd_quickstart_live(args, policy))
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


LINT_FAIL_LEVELS = ("high", "medium", "low", "never")
_LINT_SEVERITY_ORDER = {"high": 1, "medium": 2, "low": 3}


def lint_exit_code(report: LintReport, fail_on: str) -> int:
    """Map a lint report onto an exit code, so CI can gate on over-blocking.

    Shares `EXIT_VULNERABLE` with the scan path: a rule that blocks legitimate
    traffic is a policy defect the same way a passed-through attack is.
    """
    if fail_on == "never":
        return EXIT_OK
    limit = _LINT_SEVERITY_ORDER[fail_on]
    if any(_LINT_SEVERITY_ORDER.get(f.severity, 9) <= limit for f in report.findings):
        return EXIT_VULNERABLE
    return EXIT_OK


def cmd_lint_policy(args: argparse.Namespace) -> int:
    """Analyze a policy file for over-blocking, statically and against the benign corpus."""
    payloads = None if args.no_corpus else resolve_payloads(args.payloads).path
    try:
        report = lint_policy(resolve_policy(args.policy).path, payloads, probes=not args.no_probes)
    except FileNotFoundError as exc:
        raise SystemExit(f"error: {exc}") from exc

    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        print(render_report(report))
    return lint_exit_code(report, args.fail_on)


def _pin_store(args: argparse.Namespace) -> PinStore:
    return PinStore(args.pins)


def _resolve_pin_key(store: PinStore, selector: str) -> str:
    """Resolve a user-supplied selector to exactly one pin key.

    Exact key first, then a unique substring of a key or a target. An ambiguous
    selector is an error rather than a guess, because the next thing the operator
    does with it is transfer trust.
    """
    servers = store.load().servers
    if selector in servers:
        return selector
    matches = sorted(
        key for key, pin in servers.items() if selector in key or (pin.target and selector in pin.target)
    )
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(f"error: no pinned server matches {selector!r} in {store.path}")
    listed = "\n  ".join(matches)
    raise SystemExit(f"error: {selector!r} matches {len(matches)} pinned servers:\n  {listed}")


def _pin_status(pin: ServerPin) -> str:
    if pin.pending is not None:
        return "CHANGED"
    if not pin.trusted:
        return "UNTRUSTED"
    return "ok"


def _print_pin_diff(pin: ServerPin) -> None:
    """Print what changed for one pin, or say that nothing has."""
    print(f"{pin.key}")
    print(f"  target:  {pin.target or '-'}  ({pin.transport.value})")
    if not pin.trusted:
        print(f"  not accepted yet: {pin.untrusted_reason}")
    if pin.pending is None:
        print("  no pending change")
        return
    diff = pin.pending.diff
    print(f"  observed: {pin.pending.observed_at}")
    for name in diff.changed:
        print(f"  changed:  {name}")
    for name in diff.added:
        print(f"  added:    {name}")
    for name in diff.removed:
        print(f"  removed:  {name}")
    if diff.server_info_changed:
        print("  changed:  serverInfo")
    if diff.instructions_changed:
        print("  changed:  initialize instructions")
    for finding in diff.escalated:
        print(f"  [{finding.severity}] {finding.field}: {finding.description}")


def _record_acceptance(pin: ServerPin, detail: str) -> None:
    writer = audit.AuditWriter(transport=AuditTransport.CLI)
    try:
        writer.write(writer.build(action=AuditAction.PIN_ACCEPTED, tool=pin.key, detail=detail))
    finally:
        writer.close()


def cmd_pins_list(args: argparse.Namespace) -> int:
    store = _pin_store(args)
    servers = store.load().servers
    if not servers:
        print(f"No pinned servers in {store.path}")
        return EXIT_OK
    print(f"{store.path}")
    for key, pin in sorted(servers.items()):
        print(
            f"  {_pin_status(pin):<9} tools={len(pin.tools):<3} last_seen={pin.last_seen or '-':<25} {key}"
        )
    return EXIT_OK


def cmd_pins_show(args: argparse.Namespace) -> int:
    store = _pin_store(args)
    key = _resolve_pin_key(store, args.server)
    pin = store.get(key)
    if pin is None:
        raise SystemExit(f"error: no pinned server {key!r}")
    print(pin.model_dump_json(indent=2))
    return EXIT_OK


def cmd_pins_diff(args: argparse.Namespace) -> int:
    """Print pending changes. Exits 3 when any pin is unaccepted, for CI."""
    store = _pin_store(args)
    servers = store.load().servers
    if args.server is not None:
        key = _resolve_pin_key(store, args.server)
        servers = {key: servers[key]}
    if not servers:
        print(f"No pinned servers in {store.path}")
        return EXIT_OK
    outstanding = 0
    for _key, pin in sorted(servers.items()):
        if pin.pending is None and pin.trusted:
            continue
        outstanding += 1
        _print_pin_diff(pin)
    if not outstanding:
        print("Every pinned server matches its pin.")
        return EXIT_OK
    print(f"{outstanding} pinned server(s) need review. Accept with: agentparry pins accept <server>")
    return EXIT_VULNERABLE


def cmd_pins_accept(args: argparse.Namespace) -> int:
    """Promote observed metadata into the pin, after showing what changes."""
    store = _pin_store(args)
    servers = store.load().servers
    if args.all:
        if not args.yes:
            raise SystemExit(
                "error: accepting every pending change transfers trust to whatever those servers now "
                "advertise. Review it with `agentparry pins diff`, then re-run with --yes."
            )
        keys = sorted(key for key, pin in servers.items() if pin.pending is not None or not pin.trusted)
    else:
        if args.server is None:
            raise SystemExit("error: name a server, or pass --all --yes")
        keys = [_resolve_pin_key(store, args.server)]

    if not keys:
        print("Nothing to accept.")
        return EXIT_OK

    for key in keys:
        pin = servers.get(key)
        if pin is not None:
            _print_pin_diff(pin)

    if not args.yes and not _confirm(f"Accept the metadata above for {len(keys)} server(s)? [y/N] "):
        print("Aborted; pins left unchanged.")
        return EXIT_ABORTED

    accepted = 0
    for key in keys:
        pin = accept_pending(store, key)
        if pin is None:
            print(f"Nothing to accept for {key}")
            continue
        accepted += 1
        _record_acceptance(pin, f"pin accepted: {len(pin.tools)} tool(s) now trusted")
        print(f"Accepted {key}")
    return EXIT_OK


def cmd_pins_forget(args: argparse.Namespace) -> int:
    """Delete pins. The next discovery re-pins whatever the server says then."""
    store = _pin_store(args)
    servers = store.load().servers
    if args.all:
        if not args.yes:
            raise SystemExit("error: --all deletes every pin. Re-run with --yes.")
        keys = sorted(servers)
    else:
        if args.server is None:
            raise SystemExit("error: name a server, or pass --all --yes")
        keys = [_resolve_pin_key(store, args.server)]

    if not keys:
        print("Nothing to forget.")
        return EXIT_OK
    if not args.yes and not _confirm(f"Forget {len(keys)} pin(s)? The next run re-pins whatever it sees. [y/N] "):
        print("Aborted; pins left unchanged.")
        return EXIT_ABORTED
    for key in keys:
        if forget(store, key):
            print(f"Forgot {key}")
        else:
            print(f"No pin for {key}")
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


def _stdio_entry(
    policy_abs: str | None,
    cmd: str,
    child_args: list[str],
    *,
    python: str | None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build an MCP server entry that runs the wrapped server through AgentParry."""
    new_env = dict(env or {})
    if policy_abs:
        new_env["AGENTPARRY_POLICY"] = policy_abs
    else:
        new_env.pop("AGENTPARRY_POLICY", None)
    if python:
        return {
            "command": python,
            "args": _wrap_stdio_args(policy_abs, cmd, child_args),
            "env": new_env,
        }
    return {
        "command": ENTRY_COMMAND,
        "args": _wrap_cli_args(policy_abs, cmd, child_args),
        "env": new_env,
    }


def _stdio_entry_from_command(policy_abs: str | None, command: str, *, python: str | None = None) -> dict[str, Any]:
    cmd, child_args = _split_command(command)
    return _stdio_entry(policy_abs, cmd, child_args, python=python)


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


def _stdio_entry_from_existing(
    policy_abs: str | None, entry: dict[str, Any], *, python: str | None = None
) -> dict[str, Any]:
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

    if _is_wrapped_stdio_args(orig_args):
        cmd, child_args = _wrapped_child_command(orig_args)
    else:
        cmd, child_args = orig_cmd, orig_args

    new_entry = _stdio_entry(policy_abs, cmd, child_args, python=python, env=env)
    for key, value in entry.items():
        if key not in _REGENERATED_ENTRY_KEYS:
            new_entry[key] = value
    return new_entry


def _entry_policy(explicit: str | None) -> str | None:
    """Absolute policy path to record in an entry, or None to resolve at run time."""
    if not explicit:
        return None
    return str(Path(explicit).expanduser().resolve())


def _print_entry_policy(policy_abs: str | None) -> None:
    if policy_abs:
        print(f"Policy: {policy_abs}")
        return
    print(
        f"Policy: resolved when the server starts ({POLICY_DEFAULT_HELP}), so the entry stays "
        "portable. Pass --policy to record one path instead."
    )


def cmd_install_claude(args: argparse.Namespace) -> int:
    path = _claude_config_path()
    policy_abs = _entry_policy(args.policy)

    data = _load_claude_config(path)
    servers: dict[str, Any] = data["mcpServers"]
    name = args.server_name

    already_wrapped = False
    if name in servers:
        entry = servers[name]
        if not isinstance(entry, dict):
            raise SystemExit(f"error: mcpServers[{name!r}] must be an object")
        already_wrapped = _is_wrapped_stdio_args(entry.get("args"))
        new_entry = _stdio_entry_from_existing(policy_abs, entry, python=args.python)
    else:
        if not args.command:
            raise SystemExit("error: --command is required when adding a new server")
        new_entry = _stdio_entry_from_command(policy_abs, args.command, python=args.python)

    backup = path.with_suffix(path.suffix + ".bak")
    if path.exists():
        shutil.copy2(path, backup)

    servers[name] = new_entry
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    if already_wrapped:
        print(f"{name!r} was already wrapped by AgentParry; kept the same child command")
    _print_entry_policy(policy_abs)
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
    policy_abs = _entry_policy(args.policy)

    data = _load_claude_code_config(path)
    servers = _claude_code_servers(data, scope, args.project_dir)
    name = args.server_name

    already_wrapped = False
    if name in servers:
        entry = servers[name]
        if not isinstance(entry, dict):
            raise SystemExit(f"error: mcpServers[{name!r}] must be an object")
        already_wrapped = _is_wrapped_stdio_args(entry.get("args"))
        new_entry = _stdio_entry_from_existing(policy_abs, entry, python=args.python)
    else:
        if not args.command:
            raise SystemExit("error: --command is required when adding a new server")
        new_entry = _stdio_entry_from_command(policy_abs, args.command, python=args.python)

    backup = path.with_suffix(path.suffix + ".bak")
    if path.exists():
        shutil.copy2(path, backup)

    servers[name] = _claude_code_entry(new_entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    if already_wrapped:
        print(f"{name!r} was already wrapped by AgentParry; kept the same child command")
    _print_entry_policy(policy_abs)
    if scope == "project" and (policy_abs or args.python):
        print(
            f"warning: {path} is usually committed, and this entry hardcodes an absolute path, "
            "so it will not work in another checkout"
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
    policy_abs = _entry_policy(args.policy)

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
        servers["agentparry"] = _stdio_entry_from_command(policy_abs, args.command, python=args.python)
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


def _add_python_arg(parser: argparse.ArgumentParser) -> None:
    """The escape hatch for a machine with no installed `agentparry` on PATH."""
    parser.add_argument(
        "--python",
        default=None,
        metavar="PATH",
        help=f"Record this interpreter running -m src.stdio_proxy instead of `{ENTRY_COMMAND} wrap`",
    )


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
    parser.add_argument(
        "--payloads",
        default=None,
        help=f"Attack payloads YAML (default: {PAYLOADS_DEFAULT_HELP})",
    )
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


HELP_OVERVIEW = f"""AgentParry: a security layer for MCP tool traffic. Three verbs, in this order.

  START HERE
    quickstart           safe-scan one server and say what to do next

  SCAN, find what a server lets through
    scan                 fire the attack payloads at a proxy, or re-print a saved report
    lint-policy          predict which policy rules over-block, offline

  PROTECT, put a policy in front of live traffic
    wrap                 run the stdio proxy around an MCP server command
    install-claude       register a wrapped server in Claude Desktop
    install-claude-code  register a wrapped server in Claude Code
    install-openclaw     register AgentParry in an OpenClaw gateway
    pins                 review and accept the tool metadata a server advertises

  VERIFY, prove the rules closed the gap
    harden               scan, merge the generated rules into the policy, re-scan
    verify               re-scan and compare against a saved pre-hardening scan
    replay               re-read the audit log and replay its decisions against a policy

`agentparry <command> --help` carries the flags, the exit codes and examples.
No command needs a particular working directory. The policy default is
{POLICY_DEFAULT_HELP};
payloads resolve the same way from AGENTPARRY_PAYLOADS.
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentparry",
        usage="agentparry <command> [options]",
        description=HELP_OVERVIEW,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="<command>",
        help=argparse.SUPPRESS,
        prog="agentparry",
    )

    p_quick = sub.add_parser(
        "quickstart",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Runs one safe scan and prints a verdict. --command starts a throwaway AgentParry\n"
            "proxy in front of that server on a free local port and tears it down afterwards;\n"
            "--target scans a proxy you already have running.\n"
            "Safe mode always: policy is evaluated and no tool call reaches the server, so this\n"
            "is safe to point at a production MCP server. Always exits 0 on a finding; harden,\n"
            "verify and lint-policy are the commands that gate.\n"
            "Examples:\n"
            '  agentparry quickstart --command "npx some-mcp-server"\n'
            "  agentparry quickstart --target http://localhost:9090/mcp\n"
        ),
    )
    p_quick.add_argument("--command", default=None, help="MCP server command line to wrap and scan")
    p_quick.add_argument("--target", default=None, metavar="URL", help="Proxy JSON-RPC URL to scan")
    p_quick.add_argument(
        "--policy",
        default=None,
        help=f"Policy YAML (default: {POLICY_DEFAULT_HELP})",
    )
    p_quick.add_argument(
        "--payloads",
        default=None,
        help=f"Attack payloads YAML (default: {PAYLOADS_DEFAULT_HELP})",
    )
    p_quick.set_defaults(handler=cmd_quickstart)

    p_wrap = sub.add_parser(
        "wrap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            '  agentparry wrap --command "npx some-mcp-server"\n'
        ),
    )
    p_wrap.add_argument("--command", required=True, help="Shell command line for the real MCP server")
    p_wrap.add_argument(
        "--policy",
        default=None,
        help=f"Policy YAML (default: {POLICY_DEFAULT_HELP})",
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
    p_wrap.add_argument(
        "--reload-on-change",
        dest="reload_on_change",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reload the policy file when it changes on disk (default: enabled)",
    )
    p_wrap.add_argument(
        "--reload-interval",
        dest="reload_interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help=f"Policy file poll interval in seconds (default: {DEFAULT_RELOAD_INTERVAL})",
    )
    p_wrap.add_argument("--verbose", action="store_true", help="Verbose logging to stderr and log file")
    p_wrap.set_defaults(handler=cmd_wrap)

    p_scan = sub.add_parser(
        "scan",
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
    p_scan.add_argument(
        "--payloads",
        default=None,
        help=f"Attack payloads YAML (default: {PAYLOADS_DEFAULT_HELP})",
    )
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
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Additive: existing autogen_ rules are kept, same-named ones replaced, handwritten\n"
            "rules preserved. Backs the policy up to a .bak sibling, prints a unified diff, and\n"
            "asks before writing unless --yes.\n"
            "The rules about to be written are linted against the benign payloads in --payloads\n"
            "first, and a merge that introduces a high-severity over-block is refused unless\n"
            "--force. A dry run reports the findings without changing its exit code.\n"
            "Exit codes: 0 clean, 1 error, 2 usage, 3 vulnerabilities remain, a regression was\n"
            "found or the lint refused the write, 4 aborted at the prompt, 130 interrupted.\n"
            "Examples:\n"
            "  agentparry harden --target http://localhost:9090/mcp --dry-run\n"
            "  agentparry harden --target http://localhost:9090/mcp --yes --full\n"
            "  agentparry harden --target https://prod.example/mcp --safe --yes\n"
        ),
    )
    _add_scan_target_args(p_harden, target_default=PROXY_URL)
    p_harden.add_argument(
        "--policy",
        default=None,
        help=f"Policy YAML to merge rules into (default: {POLICY_DEFAULT_HELP})",
    )
    p_harden.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print the diff and exit 0 without writing anything",
    )
    p_harden.add_argument("--yes", action="store_true", help="Write the policy without confirming")
    p_harden.add_argument(
        "--force",
        action="store_true",
        help="Write even when the new rules introduce a high-severity over-block finding",
    )
    p_harden.add_argument(
        "--no-lint",
        action="store_true",
        dest="no_lint",
        help="Do not lint the rules for over-blocking before writing them",
    )
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
            "  agentparry replay --log /tmp/audit.jsonl --policy ~/.agentparry/policy.yaml\n"
            "  agentparry replay --policy ~/.agentparry/policy.yaml --against /tmp/candidate.yaml\n"
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

    p_lint = sub.add_parser(
        "lint-policy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Offline: no proxy, no network. Static checks read each rule's regexes; the empirical\n"
            "half evaluates every rule on its own through PolicyEngine against the benign payloads\n"
            "in --payloads, and reports the matched span of every benign block. --no-corpus falls\n"
            "back to generated plausible-benign strings only.\n"
            "Exit codes: 0 clean, 1 error, 2 usage, 3 findings at or above --fail-on.\n"
            "Examples:\n"
            "  agentparry lint-policy\n"
            "  agentparry lint-policy --policy ~/.agentparry/policy.yaml --format json\n"
            "  agentparry lint-policy --fail-on medium\n"
        ),
    )
    p_lint.add_argument(
        "--policy",
        default=None,
        help=f"Policy YAML to lint (default: {POLICY_DEFAULT_HELP})",
    )
    p_lint.add_argument(
        "--payloads",
        default=None,
        help=f"Payload YAML holding the benign corpus (default: {PAYLOADS_DEFAULT_HELP})",
    )
    p_lint.add_argument(
        "--no-corpus",
        action="store_true",
        dest="no_corpus",
        help="Skip the payload file and rely on generated benign strings",
    )
    p_lint.add_argument(
        "--no-probes",
        action="store_true",
        dest="no_probes",
        help="Static checks and corpus only, no generated benign strings",
    )
    p_lint.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report format (default: text)",
    )
    p_lint.add_argument(
        "--fail-on",
        choices=LINT_FAIL_LEVELS,
        default="high",
        dest="fail_on",
        help="Lowest severity that exits 3 (default: high)",
    )
    p_lint.set_defaults(handler=cmd_lint_policy)

    p_pins = sub.add_parser(
        "pins",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "A pin records what a server advertised the first time it was seen, so a description\n"
            "rewritten later is reported instead of silently reaching the model. It does not\n"
            "protect against a server that is malicious on day one; that is what metadata\n"
            "inspection is for.\n"
            "Exit codes: 0 clean, 1 error, 2 usage, 3 a pin needs review, 4 aborted at the prompt.\n"
            "Examples:\n"
            "  agentparry pins list\n"
            "  agentparry pins diff\n"
            "  agentparry pins accept 'npx some-mcp-server'\n"
            "  agentparry pins accept --all --yes\n"
        ),
    )
    pins_sub = p_pins.add_subparsers(dest="pins_command", required=True)

    def _add_pins_file_arg(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--pins",
            default=None,
            metavar="PATH",
            help="Pin store (default: ~/.agentparry/pins.json or AGENTPARRY_PINS_PATH)",
        )

    p_pins_list = pins_sub.add_parser("list", help="List every pinned server and its status")
    _add_pins_file_arg(p_pins_list)
    p_pins_list.set_defaults(handler=cmd_pins_list)

    p_pins_show = pins_sub.add_parser("show", help="Print one pin as JSON")
    p_pins_show.add_argument("server", help="Pin key, or a unique part of it or of the command")
    _add_pins_file_arg(p_pins_show)
    p_pins_show.set_defaults(handler=cmd_pins_show)

    p_pins_diff = pins_sub.add_parser("diff", help="Show pending metadata changes; exits 3 when any remain")
    p_pins_diff.add_argument("server", nargs="?", default=None, help="Limit to one server")
    _add_pins_file_arg(p_pins_diff)
    p_pins_diff.set_defaults(handler=cmd_pins_diff)

    p_pins_accept = pins_sub.add_parser(
        "accept",
        help="Trust what a server now advertises and clear its pending change",
        epilog="--all requires --yes: accepting transfers trust, so the diff has to be seen first.",
    )
    p_pins_accept.add_argument("server", nargs="?", default=None, help="Pin key, or a unique part of it")
    p_pins_accept.add_argument("--all", action="store_true", help="Accept every pending change (needs --yes)")
    p_pins_accept.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    _add_pins_file_arg(p_pins_accept)
    p_pins_accept.set_defaults(handler=cmd_pins_accept)

    p_pins_forget = pins_sub.add_parser("forget", help="Delete a pin so the next run records a fresh one")
    p_pins_forget.add_argument("server", nargs="?", default=None, help="Pin key, or a unique part of it")
    p_pins_forget.add_argument("--all", action="store_true", help="Delete every pin (needs --yes)")
    p_pins_forget.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    _add_pins_file_arg(p_pins_forget)
    p_pins_forget.set_defaults(handler=cmd_pins_forget)

    p_claude = sub.add_parser(
        "install-claude",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Resolves claude_desktop_config.json per OS, backs up to .bak, and rewrites or adds mcpServers entry.\n"
            f"The entry runs `{ENTRY_COMMAND} wrap`, so it records no interpreter path. Without\n"
            "--policy it records no policy path either and resolves one at run time.\n"
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
        default=None,
        help=f"Policy YAML recorded in the entry (default: {POLICY_DEFAULT_HELP})",
    )
    _add_python_arg(p_claude)
    p_claude.set_defaults(handler=cmd_install_claude)

    p_code = sub.add_parser(
        "install-claude-code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scopes: project writes ./.mcp.json, local writes projects[cwd].mcpServers in\n"
            "~/.claude.json, user writes top-level mcpServers in ~/.claude.json.\n"
            f"The entry runs `{ENTRY_COMMAND} wrap`, so a committed project-scope file carries no\n"
            "interpreter path. --policy and --python both put an absolute path back in it.\n"
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
        default=None,
        help=f"Policy YAML recorded in the entry (default: {POLICY_DEFAULT_HELP})",
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
    _add_python_arg(p_code)
    p_code.set_defaults(handler=cmd_install_claude_code)

    p_open = sub.add_parser(
        "install-openclaw",
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
        default=None,
        help=f"Policy YAML for --stdio (default: {POLICY_DEFAULT_HELP})",
    )
    _add_python_arg(p_open)
    p_open.set_defaults(handler=cmd_install_openclaw)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    handler = args.handler
    raise SystemExit(handler(args))


if __name__ == "__main__":
    main()
