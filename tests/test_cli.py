"""CLI behavior (argv construction, report-only scan)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from src import cli


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


def test_main_dispatches_wrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["agentparry", "wrap", "--command", "npx x", "--policy", "p.yaml"])
    with patch.object(cli, "stdio_main_argv", return_value=0):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
