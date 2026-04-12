"""Track C: discover mapping, safe classification, markdown reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.models import AttackPayload, AttackResult, ScanReport
from src.scanner import (
    Scanner,
    build_dynamic_payloads,
    map_yaml_tool_to_server,
    save_scan_outputs,
)


def test_map_yaml_tool_keyword_bash() -> None:
    assert map_yaml_tool_to_server("shell_exec", ["bash_tool", "other"]) == "bash_tool"


def test_map_yaml_tool_exact_case_insensitive() -> None:
    assert map_yaml_tool_to_server("Email_Send", ["email_send"]) == "email_send"


def test_classify_safe_scan_response() -> None:
    payload = AttackPayload(
        id="x",
        name="n",
        category="c",
        tool="t",
        arguments={},
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"_agentparry": {"safe_scan": True, "would_forward": True}},
    }
    r = Scanner._classify_response(payload, body)
    assert r.evaluated_only is True
    assert r.passed_through is False


def test_build_dynamic_payloads_from_schema() -> None:
    tools = [
        {
            "name": "demo_tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "note": {"type": "string"},
                },
                "required": ["command"],
            },
        }
    ]
    dyn = build_dynamic_payloads(tools)
    ids = {d.id for d in dyn}
    assert any(x.startswith("dyn-cmd-") for x in ids)
    assert any(x.startswith("dyn-pi-") for x in ids)


def test_save_markdown_report_contains_sections(tmp_path: Path) -> None:
    report = ScanReport(
        total_attacks=1,
        blocked=1,
        passed=0,
        redacted=0,
        policy_allowed_safe=0,
        results=[
            AttackResult(
                payload=AttackPayload(
                    id="a",
                    name="Test",
                    category="test",
                    tool="t",
                    arguments={},
                ),
                was_blocked=True,
                notes="Blocked by proxy",
            )
        ],
        vulnerability_score=0.0,
        timestamp=datetime(2026, 4, 12, tzinfo=timezone.utc),
        target_url="http://localhost:9090/mcp",
        safe_mode=False,
        discovered_tools=["email_send"],
    )
    scanner = Scanner(payloads_path=None)
    path = tmp_path / "out.md"
    scanner.save_markdown_report(report, path, suggested_rules=[])
    text = path.read_text(encoding="utf-8")
    assert "# AgentParry Security Scan Report" in text
    assert "Tools discovered" in text
    assert "## Findings" in text
    assert "## Recommended rules" in text


def test_save_scan_outputs_both_writes_two_files(tmp_path: Path) -> None:
    report = ScanReport(
        total_attacks=0,
        blocked=0,
        passed=0,
        redacted=0,
        timestamp=datetime(2026, 4, 12, tzinfo=timezone.utc),
        target_url="http://x/mcp",
    )
    scanner = Scanner(payloads_path=None)
    paths = save_scan_outputs(scanner, report, str(tmp_path), "both")
    assert len(paths) == 2
    assert any(p.endswith(".json") for p in paths)
    assert any(p.endswith(".md") for p in paths)


def test_cli_scan_parses_discover_safe_format() -> None:
    from src import cli

    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "scan",
            "--target",
            "http://localhost:9090/mcp",
            "--discover",
            "--safe",
            "--format",
            "both",
        ]
    )
    assert args.discover is True
    assert args.safe is True
    assert args.format == "both"
