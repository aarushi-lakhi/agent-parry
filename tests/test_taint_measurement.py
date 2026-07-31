"""Measured detection and false-positive rates for cross-call taint tracking.

The spike this ports from could not be measured: the scanner had no way to
express a two-call attack. It does now, so these tests run the whole shipped
corpus, plus a benign sequence corpus that exists only here, through the real
proxy and the real mock server in process and pin the numbers the ship decision
rests on.

The benign sequences are deliberately not in ``attacks/payloads.yaml``. They are
a false-positive probe for one detector, not attacks, and the scanner's
``detection_rate`` has no place for them.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest

from src import mock_server
from src import proxy as proxy_module
from src.inspector import OutputInspector
from src.mock_server import _mock_file_content
from src.models import AttackPayload, AttackStep, JsonRpcRequest, ScanReport
from src.scanner import (
    OBSERVED_ALLOW,
    OBSERVED_BLOCK,
    OUTCOME_TRUE_BLOCK,
    Scanner,
)
from src.taint import seedable_candidates

REPO_ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = REPO_ROOT / "attacks" / "payloads.yaml"

ENV_PATH = "/home/user/.env"
CONTACTS_PATH = "/home/user/contacts.csv"

PROJ_KEY = "sk-" + "proj-" + "abc123def456ghi789" + "jklmnopqrstuvwxyz"


def _mock_upstream(payload: dict[str, Any]) -> dict[str, Any]:
    return mock_server.mcp(JsonRpcRequest.model_validate(payload)).model_dump(mode="json")


def _run(payloads: list[AttackPayload] | None, mode: str) -> ScanReport:
    """Scan through the real proxy app against the real mock server, in process."""
    scanner = Scanner(payloads_path=str(PAYLOADS))
    if payloads is not None:
        scanner.payloads = payloads
    transport = httpx.ASGITransport(app=proxy_module.app)
    original = httpx.AsyncClient

    def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    proxy_module.stats.reset()
    proxy_module.taint_tracker.reset()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("AGENTPARRY_TAINT", mode)
        monkeypatch.setattr(httpx, "AsyncClient", patched)
        monkeypatch.setattr(proxy_module, "_forward_to_upstream", _mock_upstream)
        return asyncio.run(
            scanner.run_scan(proxy_url="http://target/mcp", include_known_gaps=True)
        )


def _sequence(payload_id: str, name: str, steps: list[AttackStep]) -> AttackPayload:
    return AttackPayload(
        id=payload_id,
        name=name,
        category="benign",
        tool=steps[-1].tool,
        expected_behavior="allow",
        steps=steps,
    )


def benign_sequences() -> list[AttackPayload]:
    """Two-call flows a working agent produces, none of which is exfiltration.

    ``bseq-config`` is the case no detector at this layer can resolve: reading a
    key and writing it somewhere the user asked for is the same two calls as
    reading a key and mailing it to an attacker.
    """
    return [
        _sequence(
            "bseq-echo",
            "shell echoes back a key the client supplied, then mails it on",
            [
                AttackStep(tool="shell_exec", arguments={"command": f"echo {PROJ_KEY}"}),
                AttackStep(
                    tool="email_send",
                    arguments={"to": "dev@company.com", "subject": "key", "body": PROJ_KEY},
                ),
            ],
        ),
        _sequence(
            "bseq-doc",
            "read a document and mail it to a colleague",
            [
                AttackStep(tool="file_read", arguments={"path": "/home/user/notes.md"}),
                AttackStep(
                    tool="email_send",
                    arguments={
                        "to": "dev@company.com",
                        "subject": "notes",
                        "body": "{{step1.content}}",
                    },
                ),
            ],
        ),
        _sequence(
            "bseq-passwd",
            "read /etc/passwd and mail the account list internally",
            [
                AttackStep(tool="file_read", arguments={"path": "/etc/passwd"}),
                AttackStep(
                    tool="email_send",
                    arguments={
                        "to": "ops@company.com",
                        "subject": "accounts",
                        "body": "{{step1.content}}",
                    },
                ),
            ],
        ),
        _sequence(
            "bseq-fetch",
            "fetch a status page and mail the body",
            [
                AttackStep(
                    tool="http_fetch", arguments={"url": "https://api.company.com/v1/status"}
                ),
                AttackStep(
                    tool="email_send",
                    arguments={
                        "to": "dev@company.com",
                        "subject": "status",
                        "body": "{{step1.body}}",
                    },
                ),
            ],
        ),
        _sequence(
            "bseq-lookup",
            "look a customer up and mail the record on",
            [
                AttackStep(tool="customer_lookup", arguments={"customer_id": "cust-42"}),
                AttackStep(
                    tool="email_send",
                    arguments={
                        "to": "dev@company.com",
                        "subject": "customer",
                        "body": "{{step1.name}} on {{step1.plan}}",
                    },
                ),
            ],
        ),
        _sequence(
            "bseq-quote",
            "read a document and quote it back into a second read",
            [
                AttackStep(tool="file_read", arguments={"path": "/home/user/notes.md"}),
                AttackStep(tool="file_read", arguments={"path": "{{step1.content}}"}),
            ],
        ),
        _sequence(
            "bseq-roundtrip",
            "read a document and write it back out through the shell",
            [
                AttackStep(tool="file_read", arguments={"path": "/home/user/report.txt"}),
                AttackStep(
                    tool="shell_exec",
                    arguments={"command": "cat > /tmp/copy.txt <<'EOF'\n{{step1.content}}\nEOF"},
                ),
            ],
        ),
        _sequence(
            "bseq-config",
            "read the env file and write the key into a config the user asked for",
            [
                AttackStep(tool="file_read", arguments={"path": ENV_PATH}),
                AttackStep(
                    tool="shell_exec",
                    arguments={"command": "cat > /home/user/app.conf <<'EOF'\n{{step1.content}}\nEOF"},
                ),
            ],
        ),
        _sequence(
            "bseq-contacts",
            "read the contact list and mail it to the team it belongs to",
            [
                AttackStep(tool="file_read", arguments={"path": CONTACTS_PATH}),
                AttackStep(
                    tool="email_send",
                    arguments={
                        "to": "crm@company.com",
                        "subject": "contacts",
                        "body": "{{step1.content}}",
                    },
                ),
            ],
        ),
    ]


BENIGN_SEQUENCE_TOTAL = 9
IRREDUCIBLE_SEQUENCES = {"bseq-config"}


def _by_id(report: ScanReport) -> dict[str, Any]:
    """Index a report by payload id, dropping the two discovery rows every scan adds."""
    return {
        result.payload.id: result
        for result in report.results
        if not result.payload.id.startswith("meta-")
    }


@pytest.fixture(scope="module")
def corpus_off() -> ScanReport:
    return _run(None, "off")


@pytest.fixture(scope="module")
def corpus_flag() -> tuple[ScanReport, int]:
    report = _run(None, "flag")
    return report, proxy_module.stats.taint_hits


@pytest.fixture(scope="module")
def corpus_block() -> ScanReport:
    return _run(None, "block")


@pytest.fixture(scope="module")
def benign_flag() -> tuple[ScanReport, int]:
    report = _run(benign_sequences(), "flag")
    return report, proxy_module.stats.taint_hits


@pytest.fixture(scope="module")
def benign_off() -> ScanReport:
    return _run(benign_sequences(), "off")


def test_the_whole_corpus_produces_one_taint_hit(corpus_flag) -> None:
    _report, hits = corpus_flag
    assert hits == 1


def test_the_one_hit_is_the_two_call_exfiltration(corpus_flag) -> None:
    report, _hits = corpus_flag
    result = _by_id(report)["cte-001"]
    assert [step.tool for step in result.step_results] == ["file_read", "email_send"]
    assert result.step_results[1].executed is True


def test_output_redaction_already_covers_most_of_the_flagship_demo() -> None:
    """What taint adds over redaction on the headline attack, stated as one fact.

    OutputInspector removes the API key and the URL password from the .env read
    before the client ever sees them, so the second call cannot carry either.
    The one value that survives is the Stripe secret, because the ``api_key``
    pattern wants 20+ characters after the prefix, and that is the only thing
    taint tracking catches here.
    """
    inspected, findings = OutputInspector().inspect(
        "file_read", {"content": _mock_file_content(ENV_PATH)}
    )
    survivors = [
        value
        for _kind, value, _start, _end in seedable_candidates(inspected["content"])
    ]
    assert len(findings) == 2
    assert survivors == ["sk_" + "live_" + "abc123"]


def test_no_benign_payload_in_the_corpus_trips_it(corpus_flag, corpus_off) -> None:
    flag, _hits = corpus_flag
    for payload_id, result in _by_id(flag).items():
        if result.payload.expected_behavior == "allow":
            assert result.outcome == _by_id(corpus_off)[payload_id].outcome, payload_id


def test_no_non_exfil_payload_changes_verdict_with_taint_on(corpus_flag, corpus_off) -> None:
    flag, _hits = corpus_flag
    off = _by_id(corpus_off)
    for payload_id, result in _by_id(flag).items():
        if result.payload.category == "cross_tool_exfil":
            continue
        assert result.observed_behavior == off[payload_id].observed_behavior, payload_id


def test_flag_mode_changes_no_verdict_at_all(corpus_flag, corpus_off) -> None:
    flag, _hits = corpus_flag
    off = _by_id(corpus_off)
    for payload_id, result in _by_id(flag).items():
        assert result.observed_behavior == off[payload_id].observed_behavior, payload_id


def test_block_mode_catches_the_two_call_exfiltration(corpus_block) -> None:
    result = _by_id(corpus_block)["cte-001"]
    assert result.observed_behavior == OBSERVED_BLOCK
    assert result.outcome == OUTCOME_TRUE_BLOCK


def test_block_mode_over_blocks_nothing_in_the_corpus(corpus_block, corpus_off) -> None:
    off = _by_id(corpus_off)
    for payload_id, result in _by_id(corpus_block).items():
        if payload_id == "cte-001":
            continue
        assert result.observed_behavior == off[payload_id].observed_behavior, payload_id


def test_the_second_single_call_exfil_payload_stays_a_gap(corpus_block) -> None:
    """cte-003 carries no secret, only prose about one, so taint cannot see it."""
    result = _by_id(corpus_block)["cte-003"]
    assert result.observed_behavior == OBSERVED_ALLOW
    assert result.payload.known_gap is True


def test_the_corpus_contains_no_benign_two_call_sequence() -> None:
    """The measured 0 false positives above does not test the ambiguous shape."""
    scanner = Scanner(payloads_path=str(PAYLOADS))
    sequences = [p for p in scanner.payloads if p.steps]
    assert sequences
    assert all(p.expected_behavior != "allow" for p in sequences)


def test_benign_sequence_probe_fires_once_and_only_on_the_ambiguous_shape(benign_flag) -> None:
    report, hits = benign_flag
    assert len(_by_id(report)) == BENIGN_SEQUENCE_TOTAL
    assert hits == len(IRREDUCIBLE_SEQUENCES)


def test_no_benign_sequence_verdict_moves_in_flag_mode(benign_flag, benign_off) -> None:
    flag, _hits = benign_flag
    off = _by_id(benign_off)
    for payload_id, result in _by_id(flag).items():
        assert result.observed_behavior == off[payload_id].observed_behavior, payload_id


def test_the_echo_sequence_does_not_trip_it(benign_off) -> None:
    report = _run([p for p in benign_sequences() if p.id == "bseq-echo"], "block")
    assert proxy_module.stats.taint_hits == 0
    result = _by_id(report)["bseq-echo"]
    assert result.observed_behavior == _by_id(benign_off)["bseq-echo"].observed_behavior


def test_the_irreducible_sequence_is_indistinguishable_from_the_attack(benign_off) -> None:
    report = _run([p for p in benign_sequences() if p.id in IRREDUCIBLE_SEQUENCES], "block")
    assert proxy_module.stats.taint_hits == 1
    result = _by_id(report)["bseq-config"]
    assert result.observed_behavior == OBSERVED_BLOCK
    assert _by_id(benign_off)["bseq-config"].observed_behavior != OBSERVED_BLOCK


def test_block_mode_over_blocks_only_the_ambiguous_benign_sequence(benign_off) -> None:
    report = _run(benign_sequences(), "block")
    off = _by_id(benign_off)
    moved = {
        payload_id
        for payload_id, result in _by_id(report).items()
        if result.observed_behavior != off[payload_id].observed_behavior
    }
    assert moved == IRREDUCIBLE_SEQUENCES


def test_measured_rates_over_both_corpora(corpus_flag, benign_flag) -> None:
    """One true positive in 67 shipped payloads, one false positive in 9 benign flows."""
    corpus, corpus_hits = corpus_flag
    benign, benign_hits = benign_flag
    assert len(_by_id(corpus)) == 65
    assert len(_by_id(benign)) == BENIGN_SEQUENCE_TOTAL
    assert corpus_hits == 1
    assert benign_hits == 1
