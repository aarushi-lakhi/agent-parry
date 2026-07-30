"""Tests for known_gap payloads: held out of the rates, reported on their own line."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.models import AttackPayload, AttackResult, ScanReport
from src.scanner import (
    OBSERVED_ALLOW,
    OUTCOME_FALSE_NEGATIVE,
    Scanner,
    compute_confusion_matrix,
    is_known_gap,
    vulnerability_score,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = REPO_ROOT / "attacks" / "payloads.yaml"


def _missed(payload_id: str, *, known_gap: bool) -> AttackResult:
    return AttackResult(
        payload=AttackPayload(
            id=payload_id,
            name=payload_id,
            category="path_traversal",
            tool="file_read",
            arguments={"path": "../../../etc/passwd"},
            expected_behavior="block",
            known_gap=known_gap,
        ),
        passed_through=True,
        observed_behavior=OBSERVED_ALLOW,
        outcome=OUTCOME_FALSE_NEGATIVE,
    )


def _blocked(payload_id: str) -> AttackResult:
    return AttackResult(
        payload=AttackPayload(
            id=payload_id,
            name=payload_id,
            category="prompt_injection",
            tool="email_send",
            arguments={"body": "x"},
            expected_behavior="block",
        ),
        was_blocked=True,
        observed_behavior="block",
        outcome="true_block",
    )


def test_a_known_gap_miss_is_held_out_of_the_detection_rate() -> None:
    matrix = compute_confusion_matrix([_blocked("a"), _missed("b", known_gap=True)])
    assert matrix.detection_rate == 100.0
    assert matrix.attack_total == 1
    assert matrix.known_gap == 1
    assert matrix.false_negative == 0


def test_a_plain_miss_still_lowers_the_detection_rate() -> None:
    matrix = compute_confusion_matrix([_blocked("a"), _missed("b", known_gap=False)])
    assert matrix.detection_rate == 50.0
    assert matrix.known_gap == 0


def test_include_known_gaps_folds_them_back_in() -> None:
    matrix = compute_confusion_matrix(
        [_blocked("a"), _missed("b", known_gap=True)], include_known_gaps=True
    )
    assert matrix.detection_rate == 50.0
    assert matrix.false_negative == 1
    assert matrix.known_gap == 1


def test_vulnerability_score_excludes_known_gaps_by_default() -> None:
    results = [_blocked("a"), _missed("b", known_gap=True)]
    assert vulnerability_score(results) == 0.0
    assert vulnerability_score(results, include_known_gaps=True) == 50.0


def test_a_known_gap_only_scan_reports_no_rate_rather_than_zero() -> None:
    matrix = compute_confusion_matrix([_missed("b", known_gap=True)])
    assert matrix.detection_rate is None
    assert matrix.known_gap == 1


def test_payload_without_the_field_defaults_to_not_a_gap() -> None:
    payload = AttackPayload.model_validate(
        {"id": "old", "name": "old", "category": "prompt_injection", "tool": "email_send"}
    )
    assert payload.known_gap is False
    assert is_known_gap(payload) is False


def test_report_round_trips_the_gap_fields() -> None:
    report = ScanReport(
        results=[_missed("b", known_gap=True)],
        matrix=compute_confusion_matrix([_missed("b", known_gap=True)]),
        known_gap_total=1,
        include_known_gaps=False,
    )
    restored = ScanReport.model_validate(json.loads(report.model_dump_json()))
    assert restored.known_gap_total == 1
    assert restored.include_known_gaps is False
    assert restored.matrix is not None
    assert restored.matrix.known_gap == 1


def test_report_persisted_before_the_field_still_validates() -> None:
    restored = ScanReport.model_validate({"total_attacks": 1, "results": []})
    assert restored.known_gap_total == 0
    assert restored.include_known_gaps is False


def test_markdown_lists_the_gaps_and_says_they_are_excluded(tmp_path: Path) -> None:
    results = [_blocked("a"), _missed("pt-001", known_gap=True)]
    report = ScanReport(
        total_attacks=2,
        results=results,
        matrix=compute_confusion_matrix(results),
        known_gap_total=1,
    )
    out = Path(Scanner(payloads_path=None).save_markdown_report(report, tmp_path / "r.md"))
    text = out.read_text(encoding="utf-8")
    assert "## Known gaps" in text
    assert "| Known gaps (held out of the rates) | 1 |" in text
    assert "pt-001" in text
    assert "KNOWN_GAP" in text


def test_markdown_says_so_when_nothing_is_flagged(tmp_path: Path) -> None:
    report = ScanReport(total_attacks=1, results=[_blocked("a")])
    out = Path(Scanner(payloads_path=None).save_markdown_report(report, tmp_path / "r.md"))
    assert "_No payload in this scan declares known_gap._" in out.read_text(encoding="utf-8")


def test_console_report_names_the_flag_to_include_them(capsys: pytest.CaptureFixture[str]) -> None:
    results = [_blocked("a"), _missed("pt-001", known_gap=True)]
    report = ScanReport(
        total_attacks=2, results=results, matrix=compute_confusion_matrix(results), known_gap_total=1
    )
    Scanner(payloads_path=None).print_report(report)
    out = capsys.readouterr().out
    assert "known gaps" in out
    assert "--include-known-gaps" in out


def test_shipped_gaps_are_all_attack_payloads() -> None:
    scanner = Scanner(payloads_path=str(PAYLOADS))
    gaps = [p for p in scanner.payloads if p.known_gap]
    assert gaps
    for payload in gaps:
        assert payload.expected_behavior != "allow", payload.id
        assert payload.description, payload.id


def test_shipped_payloads_cover_every_new_category() -> None:
    scanner = Scanner(payloads_path=str(PAYLOADS))
    categories = {p.category for p in scanner.payloads}
    assert {
        "cross_tool_exfil",
        "encoding",
        "obfuscation",
        "path_traversal",
        "ssrf",
        "terminal_injection",
        "tool_poisoning",
    } <= categories


def test_shipped_sequences_reference_an_earlier_step() -> None:
    scanner = Scanner(payloads_path=str(PAYLOADS))
    sequences = [p for p in scanner.payloads if p.steps]
    assert sequences
    for payload in sequences:
        assert len(payload.steps) >= 2, payload.id
        assert not payload.arguments, payload.id
        rendered = json.dumps([s.arguments for s in payload.steps])
        assert "{{step1." in rendered, payload.id


def test_tool_poisoning_payloads_are_not_mistaken_for_metadata_rows() -> None:
    from src.scanner import is_metadata_payload

    scanner = Scanner(payloads_path=str(PAYLOADS))
    poisoning = [p for p in scanner.payloads if p.category == "tool_poisoning"]
    assert poisoning
    for payload in poisoning:
        assert not is_metadata_payload(payload), payload.id
