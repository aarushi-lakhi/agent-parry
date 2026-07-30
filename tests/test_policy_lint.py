"""Policy linting: static regex checks, benign-corpus evaluation, CLI wiring."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from src import cli
from src.models import AttackPayload, AttackResult, ScanReport
from src.policy_lint import LintReport, lint_policy, render_report
from src.rule_generator import RuleGenerator

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED_POLICY = REPO_ROOT / "config" / "default_policy.yaml"
COMMITTED_PAYLOADS = REPO_ROOT / "attacks" / "payloads.yaml"


def write_policy(tmp_path: Path, rules: list[dict[str, Any]]) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"rules": rules, "settings": {}}), encoding="utf-8")
    return path


def pattern_rule(
    name: str,
    patterns: list[str],
    *,
    tool: str = "shell_exec",
    field: str = "command",
    action: str = "BLOCK",
) -> dict[str, Any]:
    return {
        "name": name,
        "tool": tool,
        "action": action,
        "message": name,
        "conditions": [{"type": "pattern_match", "field": field, "patterns": patterns}],
    }


def checks_for(report: LintReport, rule: str) -> set[str]:
    return {f.check for f in report.findings if f.rule == rule}


def findings_for(report: LintReport, rule: str, check: str) -> list[Any]:
    return [f for f in report.findings if f.rule == rule and f.check == check]


def lint_rules(tmp_path: Path, rules: list[dict[str, Any]], **kwargs: Any) -> LintReport:
    return lint_policy(write_policy(tmp_path, rules), None, **kwargs)


def committed_report() -> LintReport:
    return lint_policy(COMMITTED_POLICY, COMMITTED_PAYLOADS)


def test_committed_policy_reports_the_three_live_over_blocks() -> None:
    report = committed_report()

    blocked = {(b.rule, b.payload_id): b for b in report.blocks}
    assert set(blocked) == {
        ("autogen_pi-003", "bn-003"),
        ("autogen_pi-004", "bn-004"),
        ("block_dangerous_shell", "bn-007"),
    }

    order_ref = blocked[("autogen_pi-003", "bn-003")]
    assert order_ref.pattern == "[A-Za-z0-9+/=]{40,}"
    assert order_ref.field == "body"
    assert order_ref.matched_text == "8f3b1c9d4e7a2b6c5d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a"
    assert order_ref.span == (17, 65)

    disregard = blocked[("autogen_pi-004", "bn-004")]
    assert disregard.pattern == "disregard.*rules|override.*safety"
    assert disregard.matched_text == "disregard the old onboarding rules"

    sudo = blocked[("block_dangerous_shell", "bn-007")]
    assert sudo.pattern == r"sudo\s+"
    assert sudo.field == "command"
    assert sudo.matched_text == "sudo "

    assert report.over_block_rate == pytest.approx(33.3)
    assert report.high_rules == ["autogen_pi-003", "autogen_pi-004", "block_dangerous_shell"]


def test_require_approval_on_a_benign_payload_is_friction_not_over_block() -> None:
    report = committed_report()
    assert [(a.rule, a.payload_id, a.action) for a in report.approvals] == [
        ("flag_external_email", "bn-002", "REQUIRE_APPROVAL")
    ]
    assert all(b.rule != "flag_external_email" for b in report.blocks)


def test_committed_policy_has_no_dead_patterns() -> None:
    report = committed_report()
    assert findings_for(report, "autogen_pi-003", "dead_pattern") == []
    assert [f for f in report.findings if f.check == "dead_pattern"] == []


def test_committed_policy_linter_noise_is_bounded() -> None:
    report = committed_report()
    assert report.flag_rate is not None and report.flag_rate <= 90.0
    assert report.high_unconfirmed_rate == 0.0
    assert report.unconfirmed_rate is not None and report.unconfirmed_rate <= 60.0


def test_corpus_free_run_still_flags_the_same_rules() -> None:
    report = lint_policy(COMMITTED_POLICY, None)
    assert report.benign_total == 0
    assert report.over_block_rate is None
    assert report.high_rules == ["autogen_pi-003", "autogen_pi-004", "block_dangerous_shell"]
    assert report.corpus_confirmed_rules == []
    assert report.probe_only_rules == ["autogen_pi-003", "autogen_pi-004", "block_dangerous_shell"]


def test_low_floor_generic_class_is_high(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", ["[A-Za-z0-9]{40,}"], field="body")])
    finding = findings_for(report, "r", "low_floor_generic_class")[0]
    assert finding.severity == "high"
    assert "40" in finding.message


def test_high_floor_generic_class_is_not_flagged(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", ["[A-Za-z0-9]{200,}"], field="body")])
    assert "low_floor_generic_class" not in checks_for(report, "r")


def test_empty_pattern_matches_everything(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", [""])])
    finding = findings_for(report, "r", "matches_empty_string")[0]
    assert finding.severity == "high"
    assert "every call" in finding.message


def test_generator_emits_an_empty_pattern_for_a_blank_argument(tmp_path: Path) -> None:
    payload = AttackPayload(
        id="pi-blank",
        name="blank injection",
        category="prompt_injection",
        tool="email_send",
        arguments={"to": "a@b.com", "subject": "s", "body": ""},
        expected_behavior="block",
    )
    report = ScanReport(
        total_attacks=1,
        results=[AttackResult(payload=payload, passed_through=True)],
        timestamp=datetime.now(UTC),
        target_url="http://example.invalid/mcp",
    )
    rules = RuleGenerator().generate_rules(report)
    assert rules[0]["conditions"][0]["patterns"] == [""]

    lint = lint_rules(tmp_path, rules)
    assert findings_for(lint, "autogen_pi-blank", "matches_empty_string")[0].severity == "high"


def test_permissive_pattern_matches_nearly_everything(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", [".+"], field="body")])
    assert findings_for(report, "r", "matches_everything")[0].severity == "high"


def test_unanchored_short_literal_names_an_ordinary_word(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", [r"rm\s+-rf"])])
    finding = findings_for(report, "r", "unanchored_short_literal")[0]
    assert finding.severity == "medium"
    assert finding.example == "forms"
    assert "`rm`" in finding.message


def test_anchored_short_literal_is_not_flagged(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", [r"^rm\s+-rf"])])
    assert "unanchored_short_literal" not in checks_for(report, "r")


def test_wide_bridge_between_prose_words_is_high(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", ["disregard.*rules"], field="body")])
    finding = findings_for(report, "r", "wide_bridge")[0]
    assert finding.severity == "high"
    assert "unbounded gap" in finding.message


def test_bounded_gap_is_not_a_bridge(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", ["disregard.{0,10}rules"], field="body")])
    assert "wide_bridge" not in checks_for(report, "r")


def test_redos_shape_reports_a_complexity_estimate(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", [r"(a+)+$"])])
    finding = findings_for(report, "r", "redos_shape")[0]
    assert "complexity estimate" in finding.message
    assert finding.severity in ("high", "medium")


def test_flat_quantifier_is_not_redos(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", [r"a+b"])])
    assert "redos_shape" not in checks_for(report, "r")


def test_dead_pattern_when_a_rule_cannot_match_its_own_payload(tmp_path: Path) -> None:
    payloads = tmp_path / "payloads.yaml"
    payloads.write_text(
        yaml.safe_dump(
            {
                "payloads": [
                    {
                        "id": "pe-999",
                        "name": "probe",
                        "category": "privilege_escalation",
                        "tool": "shell_exec",
                        "arguments": {"command": "cat ../../../etc/passwd"},
                        "expected_behavior": "block",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    policy = write_policy(tmp_path, [pattern_rule("autogen_pe-999", [r"rm\s+-rf\s+/"])])
    report = lint_policy(policy, payloads)
    finding = findings_for(report, "autogen_pe-999", "dead_pattern")[0]
    assert finding.severity == "high"
    assert "never fire" in finding.message


def test_empty_domain_allowlist_is_high(tmp_path: Path) -> None:
    rule = {
        "name": "r",
        "tool": "email_send",
        "action": "REQUIRE_APPROVAL",
        "message": "r",
        "conditions": [{"type": "domain_allowlist", "field": "to", "allowed_domains": []}],
    }
    report = lint_rules(tmp_path, [rule])
    finding = findings_for(report, "r", "empty_domain_allowlist")[0]
    assert finding.severity == "high"
    assert finding.field == "to"


def test_populated_domain_allowlist_is_not_flagged() -> None:
    report = committed_report()
    assert "empty_domain_allowlist" not in checks_for(report, "flag_external_email")


def test_uncompilable_pattern_is_reported(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", ["([unclosed"])])
    assert findings_for(report, "r", "uncompilable_pattern")[0].severity == "high"


def test_probes_can_be_disabled(tmp_path: Path) -> None:
    rules = [pattern_rule("r", [r"sudo\s+"])]
    with_probes = lint_rules(tmp_path, rules)
    without = lint_rules(tmp_path, rules, probes=False)
    assert "probe_over_block" in checks_for(with_probes, "r")
    assert "probe_over_block" not in checks_for(without, "r")


def test_probe_quotes_the_pattern_keyword_inside_a_benign_command(tmp_path: Path) -> None:
    report = lint_rules(tmp_path, [pattern_rule("r", [r"sudo\s+"])])
    probe = findings_for(report, "r", "probe_over_block")[0]
    assert probe.kind == "mention"
    assert probe.example is not None and probe.example.startswith("echo '")


def test_clean_policy_has_no_findings(tmp_path: Path) -> None:
    rules = [pattern_rule("r", [r"^\s*rm\s+-rf\s+/\s*$"])]
    report = lint_rules(tmp_path, rules)
    assert report.findings == []
    assert report.flagged_rules == []
    assert report.unconfirmed_rate is None


def test_missing_policy_raises() -> None:
    with pytest.raises(FileNotFoundError):
        lint_policy("does/not/exist.yaml", None)


def test_missing_payload_file_raises(tmp_path: Path) -> None:
    policy = write_policy(tmp_path, [pattern_rule("r", ["rm"])])
    with pytest.raises(FileNotFoundError):
        lint_policy(policy, tmp_path / "missing.yaml")


def test_render_report_includes_spans_and_summary() -> None:
    text = render_report(committed_report())
    assert "over-block rate: 3/9 = 33.3%" in text
    assert "BLOCK  bn-007  shell_exec  block_dangerous_shell" in text
    assert "linter unconfirmed rate" in text


def test_cli_exits_vulnerable_on_the_committed_policy() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        ["lint-policy", "--policy", str(COMMITTED_POLICY), "--payloads", str(COMMITTED_PAYLOADS)]
    )
    assert cli.cmd_lint_policy(args) == cli.EXIT_VULNERABLE


def test_cli_fail_on_never_exits_ok() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "lint-policy",
            "--policy",
            str(COMMITTED_POLICY),
            "--payloads",
            str(COMMITTED_PAYLOADS),
            "--fail-on",
            "never",
        ]
    )
    assert cli.cmd_lint_policy(args) == cli.EXIT_OK


def test_cli_json_format_is_parseable(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    policy = write_policy(tmp_path, [pattern_rule("r", ["[A-Za-z0-9]{40,}"], field="body")])
    parser = cli._build_parser()
    args = parser.parse_args(["lint-policy", "--policy", str(policy), "--no-corpus", "--format", "json"])
    assert cli.cmd_lint_policy(args) == cli.EXIT_VULNERABLE
    payload = json.loads(capsys.readouterr().out)
    assert payload["rule_count"] == 1
    assert any(f["check"] == "low_floor_generic_class" for f in payload["findings"])


def test_cli_clean_policy_exits_ok(tmp_path: Path) -> None:
    policy = write_policy(tmp_path, [pattern_rule("r", [r"^\s*rm\s+-rf\s+/\s*$"])])
    parser = cli._build_parser()
    args = parser.parse_args(["lint-policy", "--policy", str(policy), "--no-corpus", "--fail-on", "low"])
    assert cli.cmd_lint_policy(args) == cli.EXIT_OK


def test_cli_missing_policy_is_a_usage_error(tmp_path: Path) -> None:
    parser = cli._build_parser()
    args = parser.parse_args(["lint-policy", "--policy", str(tmp_path / "nope.yaml"), "--no-corpus"])
    with pytest.raises(SystemExit):
        cli.cmd_lint_policy(args)
