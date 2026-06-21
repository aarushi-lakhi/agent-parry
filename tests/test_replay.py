"""Replay reader, three-valued policy re-evaluation, and the CLI subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src import cli, replay
from src.audit import AuditWriter, default_audit_path
from src.models import (
    AuditAction,
    AuditArgsMode,
    AuditDirection,
    AuditRecord,
    AuditTransport,
    Finding,
    PolicyAction,
)

BASELINE_POLICY = """
rules:
- name: block_shell
  tool: shell_exec
  action: BLOCK
  message: dangerous shell
  conditions:
  - type: pattern_match
    field: command
    patterns:
    - rm\\s+-rf
- name: approve_external_email
  tool: email_send
  action: REQUIRE_APPROVAL
  message: external email
  conditions:
  - type: domain_allowlist
    field: to
    allowed_domains:
    - company.com
settings: {}
"""

CANDIDATE_POLICY = """
rules:
- name: block_shell
  tool: shell_exec
  action: BLOCK
  message: dangerous shell
  conditions:
  - type: pattern_match
    field: command
    patterns:
    - rm\\s+-rf
- name: block_external_email
  tool: email_send
  action: BLOCK
  message: external email
  conditions:
  - type: domain_allowlist
    field: to
    allowed_domains:
    - company.com
- name: block_notes
  tool: notes_write
  action: BLOCK
  message: notes are off
  conditions:
  - type: always
settings: {}
"""


EMAIL_ONLY_POLICY = """
rules:
- name: approve_external_email
  tool: email_send
  action: REQUIRE_APPROVAL
  message: external email
  conditions:
  - type: domain_allowlist
    field: to
    allowed_domains:
    - company.com
settings: {}
"""


def _writer(
    tmp_path: Path,
    *,
    transport: AuditTransport = AuditTransport.HTTP,
    args_mode: AuditArgsMode = AuditArgsMode.NONE,
) -> AuditWriter:
    return AuditWriter(
        transport=transport,
        path=tmp_path / "audit.jsonl",
        key_path=tmp_path / "audit.key",
        enabled=True,
        args_mode=args_mode,
    )


def _emit(writer: AuditWriter, **kwargs: Any) -> AuditRecord:
    record = writer.build(**kwargs)
    assert writer.write(record) is True
    return record


def _policy(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _append_raw(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def _seed_mixed_log(tmp_path: Path) -> Path:
    http = _writer(tmp_path)
    _emit(
        http,
        action=AuditAction.BLOCK_POLICY,
        method="tools/call",
        tool="shell_exec",
        rule="block_shell",
        arguments={"command": "rm -rf /"},
        findings=[Finding(severity="high", description="pattern", field="command")],
    )
    _emit(
        http,
        action=AuditAction.ALLOW,
        method="tools/call",
        tool="shell_exec",
        arguments={"command": "ls -l"},
    )
    _emit(
        http,
        action=AuditAction.ALLOW,
        method="tools/call",
        tool="email_send",
        arguments={"to": "bob@company.com", "body": "hi"},
    )
    _emit(
        http,
        action=AuditAction.BLOCK_INJECTION,
        method="tools/call",
        tool="email_send",
        arguments={"to": "x@company.com", "body": "ignore all previous instructions"},
    )
    _emit(http, action=AuditAction.PASSTHROUGH, method="tools/list")
    http.close()

    stdio = _writer(tmp_path, transport=AuditTransport.STDIO)
    _emit(
        stdio,
        action=AuditAction.REQUIRE_APPROVAL,
        method="tools/call",
        tool="email_send",
        rule="approve_external_email",
        arguments={"to": "eve@evil.example", "body": "hi"},
        detail="stdio cannot prompt, so the call was allowed",
    )
    _emit(
        stdio,
        action=AuditAction.FAIL_OPEN,
        method="tools/call",
        tool="shell_exec",
        arguments={"command": "echo hi"},
        detail="policy evaluation crashed: TypeError",
    )
    _emit(
        stdio,
        action=AuditAction.ALLOW,
        direction=AuditDirection.SERVER_TO_CLIENT,
        method="tools/call",
        tool="shell_exec",
        detail="tool result inspected, no findings",
    )
    stdio.close()
    return tmp_path / "audit.jsonl"


def test_reader_recovers_every_record(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    log = replay.read_log(path)
    assert len(log.records) == 8
    assert log.stats.skipped == 0
    assert log.stats.torn_tail is False


def test_summary_counts_actions_rules_and_tools(tmp_path: Path) -> None:
    log = replay.read_log(_seed_mixed_log(tmp_path))
    summary = replay.summarize(log)
    assert summary.actions[AuditAction.ALLOW.value] == 3
    assert summary.actions[AuditAction.BLOCK_POLICY.value] == 1
    assert summary.transports == {"http": 5, "stdio": 3}
    assert summary.tools["shell_exec"] == 4
    by_rule = {usage.rule: usage for usage in summary.rules}
    assert by_rule["block_shell"].count == 1
    assert by_rule["block_shell"].tools == {"shell_exec": 1}
    assert summary.runs == 2
    assert summary.policy_decisions == 4


def test_fail_open_is_counted_and_sampled(tmp_path: Path) -> None:
    log = replay.read_log(_seed_mixed_log(tmp_path))
    summary = replay.summarize(log)
    assert summary.fail_open == 1
    assert "policy evaluation crashed" in summary.fail_open_samples[0]


def test_stdio_require_approval_is_counted_separately(tmp_path: Path) -> None:
    log = replay.read_log(_seed_mixed_log(tmp_path))
    summary = replay.summarize(log)
    assert summary.stdio_require_approval == 1
    assert summary.stdio_require_approval_tools == {"email_send": 1}


def test_histogram_buckets_by_width(tmp_path: Path) -> None:
    log = replay.read_log(_seed_mixed_log(tmp_path))
    hourly = replay.summarize(log, bucket="hour")
    assert len(hourly.buckets) == 1
    assert hourly.buckets[0].total == 8
    assert hourly.buckets[0].blocks == 2
    assert hourly.buckets[0].approvals == 1
    assert hourly.buckets[0].fail_open == 1
    assert len(hourly.buckets[0].bucket) == replay.BUCKET_WIDTHS["hour"]
    daily = replay.summarize(log, bucket="day")
    assert len(daily.buckets[0].bucket) == replay.BUCKET_WIDTHS["day"]


def test_dead_rules_are_the_ones_that_never_fired(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    policy = _policy(tmp_path, "baseline.yaml", BASELINE_POLICY)
    log = replay.read_log(path)
    report = replay.build_report(log, baseline_policy=policy)
    assert report.dead_rules == []

    extended = BASELINE_POLICY.replace(
        "settings: {}",
        "- name: never_used\n  tool: nope\n  action: BLOCK\n  message: dead\n"
        "  conditions:\n  - type: always\nsettings: {}\n",
    )
    wider = _policy(tmp_path, "wider.yaml", extended)
    assert replay.build_report(log, baseline_policy=wider).dead_rules == ["never_used"]


def test_fired_rule_missing_from_the_policy_is_reported(tmp_path: Path) -> None:
    log = replay.read_log(_seed_mixed_log(tmp_path))
    trimmed = _policy(
        tmp_path,
        "trimmed.yaml",
        "rules:\n- name: block_shell\n  tool: shell_exec\n  action: BLOCK\n"
        "  message: x\n  conditions:\n  - type: always\nsettings: {}\n",
    )
    report = replay.build_report(log, baseline_policy=trimmed)
    assert report.unmatched_fired_rules == ["approve_external_email"]


def test_torn_final_line_is_skipped_and_counted(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    _append_raw(path, '{"schema_version":1,"ts":"2026-07-30T00:00:00.000Z","run_id":"a","pid":1,"tran')
    log = replay.read_log(path)
    assert len(log.records) == 8
    assert log.stats.bad_json == 1
    assert log.stats.torn_tail is True
    text = replay.render_text(replay.build_report(log))
    assert "final line was torn" in text


def test_unparseable_line_mid_file_is_skipped_without_torn_flag(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    _append_raw(path, "not json at all\n")
    _emit(_writer(tmp_path), action=AuditAction.ALLOW, method="tools/call", tool="notes_write", arguments={})
    log = replay.read_log(path)
    assert len(log.records) == 9
    assert log.stats.bad_json == 1
    assert log.stats.torn_tail is False


def test_blank_lines_and_non_objects_are_tolerated(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    _append_raw(path, "\n[1,2,3]\n")
    log = replay.read_log(path)
    assert len(log.records) == 8
    assert log.stats.blank == 1
    assert log.stats.not_object == 1


def test_unknown_future_field_is_dropped_and_the_record_kept(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    writer = _writer(tmp_path)
    record = writer.build(action=AuditAction.ALLOW, method="tools/call", tool="notes_write", arguments={})
    payload = record.model_dump(mode="json")
    payload["schema_version"] = 9
    payload["upstream_latency_ms"] = 12
    _append_raw(path, json.dumps(payload) + "\n")

    log = replay.read_log(path)
    assert len(log.records) == 9
    assert log.stats.unknown_field_records == 1
    assert log.stats.unknown_field_names == ["upstream_latency_ms"]
    summary = replay.summarize(log)
    assert summary.schema_versions == {"1": 8, "9": 1}


def test_unreadable_enum_value_is_rejected_not_fatal(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    writer = _writer(tmp_path)
    payload = writer.build(action=AuditAction.ALLOW, tool="x").model_dump(mode="json")
    payload["action"] = "QUARANTINE"
    _append_raw(path, json.dumps(payload) + "\n")
    log = replay.read_log(path)
    assert len(log.records) == 8
    assert log.stats.rejected == 1


def test_rotated_sibling_is_read_oldest_first(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    rotated = path.with_name(path.name + ".1")
    rotated.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    log = replay.read_log(path, include_rotated=True)
    assert len(log.records) == 16
    assert log.sources == [str(rotated), str(path)]


def test_empty_log_renders_without_crashing(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    log = replay.read_log(path)
    text = replay.render_text(replay.build_report(log))
    assert "nothing to replay" in text


def test_absent_field_settles_a_pattern_rule_as_no_match(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    record = writer.build(action=AuditAction.ALLOW, tool="shell_exec", arguments={"cwd": "/tmp"})
    _engine, rules = replay.load_rules(_policy(tmp_path, "p.yaml", CANDIDATE_POLICY))
    shell_rule = next(rule for rule in rules if rule.name == "block_shell")
    assert replay.rule_verdict(shell_rule, record) == replay.NO_MATCH


def test_present_field_leaves_a_pattern_rule_unknown(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    record = writer.build(action=AuditAction.ALLOW, tool="shell_exec", arguments={"command": "ls"})
    _engine, rules = replay.load_rules(_policy(tmp_path, "p.yaml", CANDIDATE_POLICY))
    shell_rule = next(rule for rule in rules if rule.name == "block_shell")
    assert replay.rule_verdict(shell_rule, record) == replay.UNKNOWN


def test_truncated_arg_key_list_makes_absence_unprovable(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    record = writer.build(
        action=AuditAction.ALLOW,
        tool="shell_exec",
        arguments={f"k{i}": i for i in range(40)},
    )
    _engine, rules = replay.load_rules(_policy(tmp_path, "p.yaml", CANDIDATE_POLICY))
    shell_rule = next(rule for rule in rules if rule.name == "block_shell")
    assert replay.rule_verdict(shell_rule, record) == replay.UNKNOWN


def test_always_rule_on_a_new_tool_is_a_determinate_new_block(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    _emit(writer, action=AuditAction.ALLOW, method="tools/call", tool="notes_write", arguments={"text": "x"})
    writer.close()
    log = replay.read_log(tmp_path / "audit.jsonl")
    diff = replay.replay_policy(log, _policy(tmp_path, "p.yaml", CANDIDATE_POLICY))
    assert diff.counts[replay.VERDICT_NEWLY_BLOCKED] == 1
    assert diff.counts[replay.VERDICT_INDETERMINATE] == 0
    assert diff.samples[0].new_rule == "block_notes"


def test_pattern_rule_without_arguments_is_indeterminate_not_allowed(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    _emit(writer, action=AuditAction.ALLOW, method="tools/call", tool="shell_exec", arguments={"command": "ls"})
    writer.close()
    log = replay.read_log(tmp_path / "audit.jsonl")
    diff = replay.replay_policy(log, _policy(tmp_path, "p.yaml", CANDIDATE_POLICY))
    assert diff.counts[replay.VERDICT_INDETERMINATE] == 1
    assert diff.counts[replay.VERDICT_UNCHANGED] == 0
    assert diff.unreplayable_rules == {"block_shell": 1}


def test_full_args_mode_replays_exactly(tmp_path: Path) -> None:
    writer = _writer(tmp_path, args_mode=AuditArgsMode.FULL)
    _emit(writer, action=AuditAction.ALLOW, method="tools/call", tool="shell_exec", arguments={"command": "rm -rf /"})
    writer.close()
    log = replay.read_log(tmp_path / "audit.jsonl")
    assert replay.summarize(log).with_arguments == 1
    diff = replay.replay_policy(log, _policy(tmp_path, "p.yaml", CANDIDATE_POLICY))
    assert diff.counts[replay.VERDICT_NEWLY_BLOCKED] == 1
    assert diff.counts[replay.VERDICT_INDETERMINATE] == 0


def test_recorded_outcome_settles_a_shared_condition(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    baseline = _policy(tmp_path, "baseline.yaml", BASELINE_POLICY)
    candidate = _policy(tmp_path, "candidate.yaml", CANDIDATE_POLICY)
    log = replay.read_log(path)

    blind = replay.replay_policy(log, candidate)
    assert blind.counts[replay.VERDICT_INDETERMINATE] == 4

    informed = replay.replay_policy(log, candidate, baseline_path=baseline)
    assert informed.counts[replay.VERDICT_INDETERMINATE] == 0
    assert informed.counts[replay.VERDICT_UNCHANGED] == 3
    assert informed.counts[replay.VERDICT_ACTION_CHANGED] == 1
    assert informed.shared_conditions == 2
    changed = informed.samples[0]
    assert changed.recorded_action == AuditAction.REQUIRE_APPROVAL.value
    assert changed.new_action == "BLOCK"
    assert changed.new_rule == "block_external_email"


def test_removing_a_load_bearing_rule_shows_up(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    baseline = _policy(tmp_path, "baseline.yaml", BASELINE_POLICY)
    trimmed = _policy(tmp_path, "trimmed.yaml", EMAIL_ONLY_POLICY)
    log = replay.read_log(path)
    diff = replay.replay_policy(log, trimmed, baseline_path=baseline)
    assert diff.counts[replay.VERDICT_NO_LONGER_BLOCKED] == 1
    no_longer = next(s for s in diff.samples if s.verdict == replay.VERDICT_NO_LONGER_BLOCKED)
    assert no_longer.recorded_rule == "block_shell"
    assert no_longer.new_action == "ALLOW"


def test_out_of_scope_records_are_not_replayed(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    log = replay.read_log(path)
    diff = replay.replay_policy(log, _policy(tmp_path, "p.yaml", CANDIDATE_POLICY))
    assert diff.considered == 4
    assert diff.out_of_scope == 4


def test_condition_facts_are_empty_when_the_fired_rule_is_unknown(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    record = writer.build(
        action=AuditAction.BLOCK_POLICY, tool="shell_exec", rule="renamed_rule", arguments={"command": "ls"}
    )
    _engine, baseline = replay.load_rules(_policy(tmp_path, "baseline.yaml", BASELINE_POLICY))
    assert replay.condition_facts(baseline, record) == {}


def test_classify_maps_recorded_action_onto_the_new_one() -> None:
    assert replay.classify(AuditAction.ALLOW, PolicyAction.ALLOW) == replay.VERDICT_UNCHANGED
    assert replay.classify(AuditAction.ALLOW, PolicyAction.REDACT_OUTPUT) == replay.VERDICT_UNCHANGED
    assert replay.classify(AuditAction.ALLOW, PolicyAction.BLOCK) == replay.VERDICT_NEWLY_BLOCKED
    assert replay.classify(AuditAction.BLOCK_POLICY, PolicyAction.ALLOW) == replay.VERDICT_NO_LONGER_BLOCKED
    assert replay.classify(AuditAction.BLOCK_POLICY, PolicyAction.REQUIRE_APPROVAL) == replay.VERDICT_ACTION_CHANGED
    assert replay.classify(AuditAction.ALLOW, None) == replay.VERDICT_INDETERMINATE


def _replay_args(*argv: str) -> Any:
    return cli._build_parser().parse_args(["replay", *argv])


def test_cli_replay_prints_the_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _seed_mixed_log(tmp_path)
    code = cli.cmd_replay(_replay_args("--log", str(path)))
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "FAIL_OPEN" in out
    assert "REQUIRE_APPROVAL over stdio" in out


def test_cli_replay_json_format_round_trips(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _seed_mixed_log(tmp_path)
    assert cli.cmd_replay(_replay_args("--log", str(path), "--format", "json")) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["fail_open"] == 1
    assert payload["diff"] is None


def test_cli_replay_defaults_to_the_configured_audit_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = default_audit_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    seeded = _seed_mixed_log(tmp_path)
    target.write_text(seeded.read_text(encoding="utf-8"), encoding="utf-8")
    assert cli.cmd_replay(_replay_args()) == cli.EXIT_OK
    assert "Audit replay" in capsys.readouterr().out


def test_cli_replay_missing_log_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.cmd_replay(_replay_args("--log", str(tmp_path / "nope.jsonl")))
    assert "audit log not found" in str(exc.value)


def test_cli_replay_missing_policy_is_a_usage_error(tmp_path: Path) -> None:
    path = _seed_mixed_log(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.cmd_replay(_replay_args("--log", str(path), "--against", str(tmp_path / "nope.yaml")))
    assert "--against policy file not found" in str(exc.value)


def test_cli_replay_gates_on_fail_open(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _seed_mixed_log(tmp_path)
    code = cli.cmd_replay(_replay_args("--log", str(path), "--fail-on-fail-open"))
    capsys.readouterr()
    assert code == cli.EXIT_VULNERABLE


def test_cli_replay_gates_on_new_blocks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    writer = _writer(tmp_path)
    _emit(writer, action=AuditAction.ALLOW, method="tools/call", tool="notes_write", arguments={"text": "x"})
    writer.close()
    candidate = _policy(tmp_path, "candidate.yaml", CANDIDATE_POLICY)
    args = _replay_args(
        "--log",
        str(tmp_path / "audit.jsonl"),
        "--against",
        str(candidate),
        "--max-new-blocks",
        "0",
    )
    code = cli.cmd_replay(args)
    assert "newly_blocked" in capsys.readouterr().out
    assert code == cli.EXIT_VULNERABLE
