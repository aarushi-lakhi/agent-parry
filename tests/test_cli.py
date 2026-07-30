"""CLI behavior (argv construction, report-only scan, harden and verify)."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from src import cli
from src.models import AttackPayload, AttackResult, ScanReport

LOCAL_TARGET = "http://127.0.0.1:9090/mcp"


def _payload(
    payload_id: str,
    *,
    category: str = "privilege_escalation",
    tool: str = "shell_exec",
    expected: str = "block",
    arguments: dict[str, Any] | None = None,
) -> AttackPayload:
    return AttackPayload(
        id=payload_id,
        name=f"payload {payload_id}",
        category=category,
        tool=tool,
        arguments=arguments if arguments is not None else {"command": "chmod +s /bin/bash"},
        expected_behavior=expected,
        severity="high",
        description="",
    )


def _vulnerable(payload_id: str = "pe-004", **kwargs: Any) -> AttackResult:
    return AttackResult(
        payload=_payload(payload_id, **kwargs),
        passed_through=True,
        observed_behavior="allow",
        outcome="false_negative",
        notes="Passed through unblocked",
    )


def _blocked(payload_id: str = "pe-001", **kwargs: Any) -> AttackResult:
    return AttackResult(
        payload=_payload(payload_id, **kwargs),
        was_blocked=True,
        observed_behavior="block",
        outcome="true_block",
        notes="Blocked by proxy",
    )


def _benign_allowed(payload_id: str = "bn-001") -> AttackResult:
    return AttackResult(
        payload=_payload(payload_id, category="benign", expected="allow"),
        passed_through=True,
        observed_behavior="allow",
        outcome="true_allow",
        notes="Passed through unblocked",
    )


def _benign_blocked(payload_id: str = "bn-001") -> AttackResult:
    return AttackResult(
        payload=_payload(payload_id, category="benign", expected="allow"),
        was_blocked=True,
        observed_behavior="block",
        outcome="false_positive",
        notes="Blocked by proxy",
    )


def _safe_allowed(payload_id: str = "pe-004", **kwargs: Any) -> AttackResult:
    return AttackResult(
        payload=_payload(payload_id, **kwargs),
        evaluated_only=True,
        passed_through=False,
        observed_behavior="evaluated",
        outcome="false_negative",
        notes="Safe scan: policy allowed; upstream not executed",
    )


def _report(
    results: list[AttackResult],
    *,
    target: str = LOCAL_TARGET,
    safe: bool = False,
) -> ScanReport:
    return ScanReport(
        total_attacks=len(results),
        passed=sum(1 for r in results if r.passed_through),
        blocked=sum(1 for r in results if r.was_blocked),
        results=results,
        timestamp=datetime.now(UTC),
        target_url=target,
        safe_mode=safe,
    )


def test_wrap_builds_argv_and_delegates() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        ["wrap", "--command", "npx some-mcp-server", "--policy", "config/default_policy.yaml"]
    )
    with patch.object(cli, "stdio_main_argv", return_value=0) as mock_run:
        code = cli.cmd_wrap(args)
    assert code == 0
    mock_run.assert_called_once_with(
        [
            "--policy",
            "config/default_policy.yaml",
            "--wrap",
            "npx",
            "some-mcp-server",
        ]
    )


def test_wrap_forwards_log_and_verbose() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "wrap",
            "--command",
            "uvx pkg",
            "--policy",
            "pol.yaml",
            "--log",
            "/tmp/ap.log",
            "--verbose",
        ]
    )
    with patch.object(cli, "stdio_main_argv", return_value=0) as mock_run:
        assert cli.cmd_wrap(args) == 0
    mock_run.assert_called_once_with(
        [
            "--policy",
            "pol.yaml",
            "--log",
            "/tmp/ap.log",
            "--verbose",
            "--wrap",
            "uvx",
            "pkg",
        ]
    )


def test_scan_report_only_loads_json(tmp_path: Path) -> None:
    report = {
        "total_attacks": 1,
        "blocked": 1,
        "passed": 0,
        "redacted": 0,
        "vulnerability_score": 0.0,
        "timestamp": "2026-04-12T12:00:00Z",
        "results": [
            {
                "payload": {
                    "id": "t1",
                    "name": "Test",
                    "category": "test",
                    "tool": "noop",
                    "arguments": {},
                    "expected_behavior": "",
                    "severity": "low",
                    "description": "",
                },
                "was_blocked": True,
                "was_redacted": False,
                "passed_through": False,
                "proxy_response": {"error": {"code": 1, "message": "blocked"}},
                "notes": "Blocked by proxy",
            }
        ],
    }
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    parser = cli._build_parser()
    args = parser.parse_args(["scan", "--report-only", str(path)])
    assert cli.cmd_scan(args) == 0


def test_scan_target_and_report_only_mutually_exclusive() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        ["scan", "--target", "http://x/mcp", "--report-only", "f.json"]
    )
    with pytest.raises(SystemExit):
        cli.cmd_scan(args)


def test_install_claude_new_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)

    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "install-claude",
            "--server-name",
            "mine",
            "--command",
            "npx server-bin",
            "--policy",
            str(tmp_path / "pol.yaml"),
        ]
    )
    pol = tmp_path / "pol.yaml"
    pol.write_text("payloads: []\n", encoding="utf-8")

    with patch.object(cli.sys, "executable", "/fake/python"):
        assert cli.cmd_install_claude(args) == 0

    data = json.loads(cfg.read_text(encoding="utf-8"))
    entry = data["mcpServers"]["mine"]
    assert entry["command"] == "/fake/python"
    assert entry["args"][:4] == ["-m", "src.stdio_proxy", "--policy", str(pol.resolve())]
    assert "--wrap" in entry["args"]
    assert entry["env"]["AGENTPARRY_POLICY"] == str(pol.resolve())
    bak = cfg.with_suffix(cfg.suffix + ".bak")
    assert not bak.exists()  # no backup when file did not exist before


def test_install_claude_backup_when_exists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)
    pol = tmp_path / "pol.yaml"
    pol.write_text("x: 1\n", encoding="utf-8")

    parser = cli._build_parser()
    args = parser.parse_args(
        ["install-claude", "--server-name", "s", "--command", "npx x", "--policy", str(pol)]
    )
    with patch.object(cli.sys, "executable", sys.executable):
        assert cli.cmd_install_claude(args) == 0
    bak = Path(str(cfg) + ".bak")
    assert bak.exists()
    assert json.loads(bak.read_text(encoding="utf-8")) == {"mcpServers": {}}


def test_install_openclaw_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "openclaw.json"
    monkeypatch.setattr(cli, "_openclaw_path", lambda: path)

    parser = cli._build_parser()
    args = parser.parse_args(
        ["install-openclaw", "--url", "http://example.test/mcp"]
    )
    assert cli.cmd_install_openclaw(args) == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["mcp"]["servers"]["agentparry"] == {
        "url": "http://example.test/mcp",
        "transport": "streamable-http",
    }


@pytest.mark.parametrize(
    ("url", "loopback"),
    [
        ("http://127.0.0.1:9090/mcp", True),
        ("http://localhost:9090/mcp", True),
        ("http://127.0.0.5:9090/mcp", True),
        ("http://[::1]:9090/mcp", True),
        ("http://10.0.0.4:9090/mcp", False),
        ("https://mcp.example.com/mcp", False),
        ("not a url", False),
        ("", False),
    ],
)
def test_is_loopback_target(url: str, loopback: bool) -> None:
    assert cli._is_loopback_target(url) is loopback


def test_guard_live_target_refuses_remote_without_safe() -> None:
    with pytest.raises(SystemExit) as exc:
        cli._guard_live_target("https://mcp.example.com/mcp", safe=False, allow_remote=False)
    assert "--allow-remote" in str(exc.value)


def test_guard_live_target_allows_safe_and_allow_remote() -> None:
    cli._guard_live_target("https://mcp.example.com/mcp", safe=True, allow_remote=False)
    cli._guard_live_target("https://mcp.example.com/mcp", safe=False, allow_remote=True)
    cli._guard_live_target(LOCAL_TARGET, safe=False, allow_remote=False)


def test_vulnerability_exit_code() -> None:
    assert cli.vulnerability_exit_code(0, 0) == cli.EXIT_OK
    assert cli.vulnerability_exit_code(1, 0) == cli.EXIT_VULNERABLE
    assert cli.vulnerability_exit_code(2, 2) == cli.EXIT_OK
    assert cli.vulnerability_exit_code(3, 2) == cli.EXIT_VULNERABLE
    assert cli.vulnerability_exit_code(0, 5, regression=True) == cli.EXIT_VULNERABLE


def test_policy_reload_url_derives_from_target() -> None:
    assert cli._policy_reload_url("http://127.0.0.1:9090/mcp") == "http://127.0.0.1:9090/policy/reload"
    assert cli._policy_reload_url("https://host/a/b") == "https://host/policy/reload"


def test_analyze_rescan_counts_fixed_remaining_and_unreplayed() -> None:
    before = _report([_vulnerable("a"), _vulnerable("b"), _blocked("c"), _benign_allowed("d")])
    after = _report([_blocked("a"), _vulnerable("b"), _benign_allowed("d")])
    analysis = cli._analyze_rescan(before, after)
    assert analysis.fixed == 1
    assert analysis.remaining == 1
    assert analysis.unreplayed_correct == 1  # "c" was blocked before, never replayed
    assert analysis.introduced_false_positives == 0
    assert not analysis.regression


def test_analyze_rescan_flags_introduced_false_positive() -> None:
    before = _report([_vulnerable("a"), _benign_allowed("d")])
    after = _report([_blocked("a"), _benign_blocked("d")])
    analysis = cli._analyze_rescan(before, after)
    assert analysis.introduced_false_positives == 1
    assert analysis.regression


def test_analyze_rescan_flags_regressed_attack() -> None:
    before = _report([_blocked("a")])
    after = _report([_vulnerable("a")])
    analysis = cli._analyze_rescan(before, after)
    assert analysis.regressed_attacks == 1
    assert analysis.regression


def test_analyze_rescan_counts_safe_mode_allow_as_remaining() -> None:
    after = _report([_safe_allowed("a")], safe=True)
    assert cli._analyze_rescan(_report([]), after).remaining == 1


def test_main_dispatches_wrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["agentparry", "wrap", "--command", "npx x", "--policy", "p.yaml"])
    with patch.object(cli, "stdio_main_argv", return_value=0):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
