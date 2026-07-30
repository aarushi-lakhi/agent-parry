"""Closing-panel summary: detection, over-block, and introduced false positives."""

from __future__ import annotations

from typing import Any

from src.demo import _introduced_false_positives, _summary_lines
from src.models import AttackPayload, AttackResult, ScanReport
from src.scanner import (
    OBSERVED_ALLOW,
    OBSERVED_BLOCK,
    OUTCOME_FALSE_NEGATIVE,
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_TRUE_ALLOW,
    OUTCOME_TRUE_BLOCK,
    compute_confusion_matrix,
    vulnerability_score,
)


def _payload(payload_id: str, *, expected: str) -> AttackPayload:
    return AttackPayload(
        id=payload_id,
        name=f"payload {payload_id}",
        category="benign" if expected == "allow" else "prompt_injection",
        tool="email_send",
        arguments={"body": "x"},
        expected_behavior=expected,
        severity="low",
    )


def stopped(payload_id: str, *, expected: str = "block") -> AttackResult:
    """An attack payload the proxy blocked."""
    return AttackResult(
        payload=_payload(payload_id, expected=expected),
        was_blocked=True,
        observed_behavior=OBSERVED_BLOCK,
        outcome=OUTCOME_TRUE_BLOCK,
    )


def missed(payload_id: str, *, expected: str = "block") -> AttackResult:
    """An attack payload that reached the tool."""
    return AttackResult(
        payload=_payload(payload_id, expected=expected),
        passed_through=True,
        observed_behavior=OBSERVED_ALLOW,
        outcome=OUTCOME_FALSE_NEGATIVE,
    )


def allowed(payload_id: str) -> AttackResult:
    """A benign payload the proxy correctly let through."""
    return AttackResult(
        payload=_payload(payload_id, expected="allow"),
        passed_through=True,
        observed_behavior=OBSERVED_ALLOW,
        outcome=OUTCOME_TRUE_ALLOW,
    )


def over_blocked(payload_id: str) -> AttackResult:
    """A benign payload the proxy wrongly stopped."""
    return AttackResult(
        payload=_payload(payload_id, expected="allow"),
        was_blocked=True,
        observed_behavior=OBSERVED_BLOCK,
        outcome=OUTCOME_FALSE_POSITIVE,
    )


def report(results: list[AttackResult]) -> ScanReport:
    matrix = compute_confusion_matrix(results)
    return ScanReport(
        total_attacks=len(results),
        blocked=sum(1 for r in results if r.was_blocked),
        passed=sum(1 for r in results if r.passed_through and r.payload.expected_behavior != "allow"),
        results=results,
        vulnerability_score=vulnerability_score(results),
        matrix=matrix,
        attack_total=matrix.attack_total,
        benign_total=matrix.benign_total,
    )


def joined(*args: Any) -> str:
    return "\n".join(_summary_lines(*args))


def test_fixed_attacks_without_false_positives_reads_as_a_clean_win() -> None:
    before = report([stopped("a1"), missed("a2"), missed("a3"), allowed("b1"), allowed("b2")])
    after = report([stopped("a2"), stopped("a3"), allowed("b1"), allowed("b2")])

    text = joined(before, after)

    assert "AgentParry demo complete" in text
    assert "over-blocking" not in text
    assert "Attack payloads stopped: 1/3 (detection 33.3%)" in text
    assert "Attack payloads stopped: 2/2 (detection 100.0%)" in text
    assert "Benign payloads allowed: 2/2 (over-block 0.0%)" in text
    assert "The generated rules blocked no benign calls." in text
    assert "more secure" not in text


def test_introduced_false_positives_appear_in_the_panel() -> None:
    before = report([missed("a1"), missed("a2"), allowed("b1"), allowed("b2")])
    after = report([stopped("a1"), stopped("a2"), allowed("b1"), over_blocked("b2")])

    assert _introduced_false_positives(before, after) == 1

    text = joined(before, after)

    assert "over-blocking" in text
    assert "newly blocked 1 benign" in text
    assert "Benign payloads allowed: 1/2 (over-block 50.0%)" in text
    # Detection alone would read 100%; the balanced score has to carry the cost.
    assert "Attack payloads stopped: 2/2 (detection 100.0%)" in text
    assert "Balanced score, detection minus over-block: 50.0%" in text
    assert "blocked no benign calls" not in text


def test_pre_existing_false_positive_is_not_counted_as_introduced() -> None:
    before = report([missed("a1"), over_blocked("b1")])
    after = report([stopped("a1"), over_blocked("b1")])

    assert _introduced_false_positives(before, after) == 0
    assert "blocked no benign calls" in joined(before, after)


def test_no_benign_payloads_renders_n_a_without_crashing() -> None:
    before = report([missed("a1"), missed("a2")])
    after = report([stopped("a1"), stopped("a2")])

    text = joined(before, after)

    assert "Benign payloads allowed: 0/0 (over-block n/a)" in text
    assert "Balanced score, detection minus over-block: 100.0%" in text


def test_attack_counts_exclude_benign_payloads() -> None:
    results = [stopped("a1"), stopped("a2")] + [allowed(f"b{i}") for i in range(5)]
    text = joined(report(results), report(results))

    assert "Attack payloads stopped: 2/2 (detection 100.0%)" in text
    assert "Benign payloads allowed: 5/5" in text
    assert "/7" not in text


def test_empty_report_renders_n_a_everywhere() -> None:
    text = joined(report([]), report([]))

    assert "Attack payloads stopped: 0/0 (detection n/a)" in text
    assert "Benign payloads allowed: 0/0 (over-block n/a)" in text
    assert "Balanced score, detection minus over-block: n/a" in text


def test_missing_rescan_summarizes_the_first_scan_only() -> None:
    before = report([missed("a1"), stopped("a2"), allowed("b1")])

    text = joined(before, None)

    assert "incomplete" in text
    assert "Initial scan, all 3 payloads:" in text
    assert "Attack payloads stopped: 1/2 (detection 50.0%)" in text
    assert "Rescan" not in text


def test_missing_scan_entirely_does_not_crash() -> None:
    assert "no scan to summarize" in joined(None, None)


def test_outcomes_are_recomputed_when_a_report_predates_scoring() -> None:
    """A report saved before outcome existed still scores off its flags."""
    stale = AttackResult(payload=_payload("b1", expected="allow"), was_blocked=True)
    text = joined(report([stale]), report([stale]))

    assert "Benign payloads allowed: 0/1 (over-block 100.0%)" in text
