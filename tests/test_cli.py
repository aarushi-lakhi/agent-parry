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


def _install_claude_args(server_name: str, policy: Path, command: str | None = None) -> object:
    argv = ["install-claude", "--server-name", server_name, "--policy", str(policy)]
    if command is not None:
        argv.extend(["--command", command])
    return cli._build_parser().parse_args(argv)


def test_install_claude_wraps_existing_unwrapped_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                        "env": {"TOKEN": "abc"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)
    pol = tmp_path / "pol.yaml"
    pol.write_text("x: 1\n", encoding="utf-8")

    with patch.object(cli.sys, "executable", "/fake/python"):
        assert cli.cmd_install_claude(_install_claude_args("fs", pol)) == 0

    entry = json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"]["fs"]
    assert entry["command"] == "/fake/python"
    assert entry["args"] == [
        "-m",
        "src.stdio_proxy",
        "--policy",
        str(pol.resolve()),
        "--wrap",
        "npx",
        "--",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/data",
    ]
    assert entry["env"] == {"TOKEN": "abc", "AGENTPARRY_POLICY": str(pol.resolve())}


def test_install_claude_rerun_does_not_nest_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(
        json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "srv"]}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)
    first = tmp_path / "first.yaml"
    first.write_text("x: 1\n", encoding="utf-8")
    second = tmp_path / "second.yaml"
    second.write_text("x: 2\n", encoding="utf-8")

    with patch.object(cli.sys, "executable", "/fake/python"):
        assert cli.cmd_install_claude(_install_claude_args("fs", first)) == 0
        after_first = json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"]["fs"]
        # Re-run with a different --policy: retargets in place, no second proxy.
        assert cli.cmd_install_claude(_install_claude_args("fs", second)) == 0

    entry = json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"]["fs"]
    assert entry["args"].count("src.stdio_proxy") == 1
    assert entry["args"].count("--wrap") == 1
    assert entry["args"] == [
        "-m",
        "src.stdio_proxy",
        "--policy",
        str(second.resolve()),
        "--wrap",
        "npx",
        "--",
        "-y",
        "srv",
    ]
    assert entry["env"]["AGENTPARRY_POLICY"] == str(second.resolve())
    # Only the policy moved; the wrapped child command is untouched.
    assert entry["args"][4:] == after_first["args"][4:]


def test_install_claude_rerun_with_same_policy_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(
        json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["srv"]}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)
    pol = tmp_path / "pol.yaml"
    pol.write_text("x: 1\n", encoding="utf-8")

    with patch.object(cli.sys, "executable", "/fake/python"):
        assert cli.cmd_install_claude(_install_claude_args("fs", pol)) == 0
        once = cfg.read_text(encoding="utf-8")
        assert cli.cmd_install_claude(_install_claude_args("fs", pol)) == 0
        twice = cfg.read_text(encoding="utf-8")

    assert once == twice


def test_install_claude_preserves_timeout_and_always_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["srv"],
                        "timeout": 60000,
                        "alwaysLoad": True,
                        "somethingElse": {"nested": 1},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)
    pol = tmp_path / "pol.yaml"
    pol.write_text("x: 1\n", encoding="utf-8")

    with patch.object(cli.sys, "executable", "/fake/python"):
        assert cli.cmd_install_claude(_install_claude_args("fs", pol)) == 0

    entry = json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"]["fs"]
    assert entry["timeout"] == 60000
    assert entry["alwaysLoad"] is True
    assert entry["somethingElse"] == {"nested": 1}
    assert "type" not in entry  # we always emit a stdio entry


def test_install_claude_preserved_fields_survive_a_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(
        json.dumps(
            {"mcpServers": {"fs": {"command": "npx", "args": ["srv"], "timeout": 1234, "alwaysLoad": False}}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)
    pol = tmp_path / "pol.yaml"
    pol.write_text("x: 1\n", encoding="utf-8")

    with patch.object(cli.sys, "executable", "/fake/python"):
        assert cli.cmd_install_claude(_install_claude_args("fs", pol)) == 0
        assert cli.cmd_install_claude(_install_claude_args("fs", pol)) == 0

    entry = json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"]["fs"]
    assert entry["timeout"] == 1234
    assert entry["alwaysLoad"] is False
    assert entry["args"].count("src.stdio_proxy") == 1


def test_install_claude_backup_written_when_wrapping_existing_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "claude_desktop_config.json"
    original = {"mcpServers": {"fs": {"command": "npx", "args": ["srv"]}}}
    cfg.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(cli, "_claude_config_path", lambda: cfg)
    pol = tmp_path / "pol.yaml"
    pol.write_text("x: 1\n", encoding="utf-8")

    with patch.object(cli.sys, "executable", "/fake/python"):
        assert cli.cmd_install_claude(_install_claude_args("fs", pol)) == 0

    bak = Path(str(cfg) + ".bak")
    assert bak.exists()
    assert json.loads(bak.read_text(encoding="utf-8")) == original


def test_is_wrapped_stdio_args_matches_on_shape_not_command() -> None:
    assert cli._is_wrapped_stdio_args(["-m", "src.stdio_proxy", "--policy", "p"])
    assert not cli._is_wrapped_stdio_args(["-y", "@modelcontextprotocol/server-filesystem"])
    assert not cli._is_wrapped_stdio_args([])
    assert not cli._is_wrapped_stdio_args(None)
    assert not cli._is_wrapped_stdio_args("-m src.stdio_proxy")


def test_repolicy_stdio_args_ignores_child_policy_flag() -> None:
    wrapped = cli._wrap_stdio_args("/old.yaml", "npx", ["srv", "--policy", "child.yaml"])
    out = cli._repolicy_stdio_args("/new.yaml", wrapped)
    assert out == [
        "-m",
        "src.stdio_proxy",
        "--policy",
        "/new.yaml",
        "--wrap",
        "npx",
        "--",
        "srv",
        "--policy",
        "child.yaml",
    ]


def test_main_dispatches_wrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["agentparry", "wrap", "--command", "npx x", "--policy", "p.yaml"])
    with patch.object(cli, "stdio_main_argv", return_value=0):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
