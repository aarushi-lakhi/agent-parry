"""Shared pytest fixtures.

The isolation fixtures are autouse so a test that never mentions auditing,
pinning or a user policy copy still cannot write to the real ~/.agentparry. Autouse
fixtures do apply to unittest.TestCase methods, which most of this suite uses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src import audit


@pytest.fixture(autouse=True)
def isolate_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the audit log and HMAC key at tmp_path and reset the shared writer.

    The env vars are also inherited by subprocess tests, so the stdio proxy
    spawned in a test writes under tmp_path too.
    """
    monkeypatch.setenv("AGENTPARRY_AUDIT_PATH", str(tmp_path / "audit" / "audit.jsonl"))
    monkeypatch.setenv("AGENTPARRY_AUDIT_KEY_PATH", str(tmp_path / "audit" / "audit.key"))
    monkeypatch.delenv("AGENTPARRY_AUDIT", raising=False)
    monkeypatch.delenv("AGENTPARRY_AUDIT_ARGS", raising=False)
    audit.reset_writer()
    yield
    audit.reset_writer()


@pytest.fixture(autouse=True)
def isolate_pins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the tool-list pin store at tmp_path, subprocesses included."""
    monkeypatch.setenv("AGENTPARRY_PINS_PATH", str(tmp_path / "pins" / "pins.json"))


@pytest.fixture(autouse=True)
def isolate_agentparry_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the user config dir at tmp_path so no test reads or writes a real user policy.

    The directory stays absent unless a test creates it, so default resolution
    falls through to the packaged files exactly as it does on a fresh install.
    """
    monkeypatch.setenv("AGENTPARRY_HOME", str(tmp_path / "home" / ".agentparry"))
    monkeypatch.delenv("AGENTPARRY_POLICY", raising=False)
    monkeypatch.delenv("AGENTPARRY_PAYLOADS", raising=False)
