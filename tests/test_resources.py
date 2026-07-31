"""Tests for packaged default resolution and cwd independence."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src import cli
from src.policy import PolicyEngine
from src.policy_lint import lint_policy
from src.resources import (
    SOURCE_ENV,
    SOURCE_FLAG,
    SOURCE_PACKAGED,
    SOURCE_USER,
    copy_out_policy,
    packaged_payloads_path,
    packaged_policy_path,
    resolve_payloads,
    resolve_policy,
    user_dir,
    user_payloads_path,
    user_policy_path,
)
from src.scanner import Scanner


def _write_user_policy(text: str = "rules: []\n") -> Path:
    path = user_policy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_packaged_files_ship_and_parse() -> None:
    policy = yaml.safe_load(packaged_policy_path().read_text(encoding="utf-8"))
    payloads = yaml.safe_load(packaged_payloads_path().read_text(encoding="utf-8"))
    assert policy["rules"]
    assert payloads["payloads"]


def test_packaged_paths_are_absolute() -> None:
    assert packaged_policy_path().is_absolute()
    assert packaged_payloads_path().is_absolute()


def test_user_dir_follows_the_home_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTPARRY_HOME", str(tmp_path / "elsewhere"))
    assert user_dir() == tmp_path / "elsewhere"


def test_flag_wins_over_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTPARRY_POLICY", "/env/policy.yaml")
    _write_user_policy()
    resolved = resolve_policy("/flag/policy.yaml")
    assert resolved.source == SOURCE_FLAG
    assert resolved.path == Path("/flag/policy.yaml")
    assert not resolved.packaged


def test_a_relative_flag_stays_relative_to_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert resolve_policy("config/default_policy.yaml").path == Path("config/default_policy.yaml")


def test_env_wins_over_user_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTPARRY_POLICY", "/env/policy.yaml")
    _write_user_policy()
    resolved = resolve_policy()
    assert resolved.source == SOURCE_ENV
    assert resolved.path == Path("/env/policy.yaml")


def test_blank_env_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTPARRY_POLICY", "   ")
    assert resolve_policy().source == SOURCE_PACKAGED


def test_user_copy_wins_over_packaged() -> None:
    path = _write_user_policy()
    resolved = resolve_policy()
    assert resolved.source == SOURCE_USER
    assert resolved.path == path


def test_packaged_is_the_last_resort() -> None:
    resolved = resolve_policy()
    assert resolved.source == SOURCE_PACKAGED
    assert resolved.path == packaged_policy_path()
    assert resolved.packaged


def test_payloads_resolve_the_same_way(monkeypatch: pytest.MonkeyPatch) -> None:
    assert resolve_payloads().path == packaged_payloads_path()
    user = user_payloads_path()
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text("payloads: []\n", encoding="utf-8")
    assert resolve_payloads().source == SOURCE_USER
    monkeypatch.setenv("AGENTPARRY_PAYLOADS", "/env/payloads.yaml")
    assert resolve_payloads().source == SOURCE_ENV
    assert resolve_payloads("/flag/payloads.yaml").source == SOURCE_FLAG


def test_copy_out_policy_materializes_a_writable_copy() -> None:
    path = copy_out_policy()
    assert path == user_policy_path()
    assert path.read_text(encoding="utf-8") == packaged_policy_path().read_text(encoding="utf-8")
    assert resolve_policy().source == SOURCE_USER


def test_policy_engine_loads_rules_from_a_foreign_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert PolicyEngine().get_rules()


def test_scanner_loads_payloads_from_a_foreign_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert Scanner().payloads


def test_lint_policy_runs_from_a_foreign_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = lint_policy()
    assert report.rule_count
    assert report.benign_total
    assert report.policy_path == str(packaged_policy_path())


def test_lint_policy_subcommand_runs_from_a_foreign_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reported bug: every default used to resolve against the current directory."""
    monkeypatch.chdir(tmp_path)
    args = cli._build_parser().parse_args(["lint-policy"])
    assert cli.cmd_lint_policy(args) == cli.EXIT_OK
    assert "policy file not found" not in capsys.readouterr().out


def test_scan_report_only_runs_from_a_foreign_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "scan.json"
    report.write_text(
        '{"total_attacks": 0, "passed": 0, "blocked": 0, "results": [],'
        ' "timestamp": "2026-01-01T00:00:00Z"}',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    args = cli._build_parser().parse_args(["scan", "--report-only", "scan.json"])
    assert cli.cmd_scan(args) == cli.EXIT_OK


def test_wrap_resolves_the_packaged_policy_from_a_foreign_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    forwarded: list[list[str]] = []
    monkeypatch.setattr(cli, "stdio_main_argv", lambda argv: forwarded.append(argv) or 0)
    args = cli._build_parser().parse_args(["wrap", "--command", "npx srv"])
    assert cli.cmd_wrap(args) == 0
    assert forwarded[0][:2] == ["--policy", str(packaged_policy_path())]
