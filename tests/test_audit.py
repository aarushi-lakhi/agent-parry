"""Tests for the JSONL audit log."""

from __future__ import annotations

import json
import os
import stat
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pydantic
import pytest

from src import audit
from src.inspector import OutputInspector
from src.models import (
    AUDIT_SCHEMA_VERSION,
    AuditAction,
    AuditArgsMode,
    AuditDirection,
    AuditRecord,
    AuditTransport,
    Finding,
)

POSIX_MODES = os.name != "nt" and getattr(os, "geteuid", lambda: 1)() != 0
SKIP_MODES = "mode bits are not meaningful on this platform or as root"


def read_records(path: Path) -> list[dict[str, Any]]:
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


class AuditWriterTestCase(unittest.TestCase):
    """Base class giving each test its own audit path under a pytest tmp dir."""

    def setUp(self) -> None:
        self.audit_path = Path(os.environ["AGENTPARRY_AUDIT_PATH"])
        self.key_path = Path(os.environ["AGENTPARRY_AUDIT_KEY_PATH"])

    def make_writer(self, **kwargs: Any) -> audit.AuditWriter:
        kwargs.setdefault("path", self.audit_path)
        kwargs.setdefault("key_path", self.key_path)
        kwargs.setdefault("transport", AuditTransport.HTTP)
        writer = audit.AuditWriter(**kwargs)
        self.addCleanup(writer.close)
        return writer


class TestSchema(AuditWriterTestCase):
    def test_round_trip(self) -> None:
        writer = self.make_writer()
        record = writer.build(
            action=AuditAction.BLOCK_POLICY,
            method="tools/call",
            tool="shell_exec",
            rule="block_dangerous_shell",
            request_id=0,
            session_id="sess-1",
            arguments={"command": "rm -rf /"},
            findings=[Finding(severity="high", description="d", field="arguments.command", matched_pattern="rm")],
            detail="unit",
        )
        writer.write(record)

        raw = read_records(self.audit_path)[0]
        restored = AuditRecord.model_validate(raw)
        self.assertEqual(restored.model_dump(mode="json"), raw)
        self.assertEqual(restored.schema_version, AUDIT_SCHEMA_VERSION)
        self.assertEqual(restored.action, AuditAction.BLOCK_POLICY)
        self.assertEqual(restored.transport, AuditTransport.HTTP)
        self.assertEqual(restored.direction, AuditDirection.CLIENT_TO_SERVER)
        self.assertEqual(restored.finding_count, 1)
        self.assertEqual(restored.max_severity, "high")

    def test_unknown_field_rejected(self) -> None:
        writer = self.make_writer()
        raw = writer.build(action=AuditAction.ALLOW, tool="t").model_dump(mode="json")
        raw["surprise"] = 1
        with self.assertRaises(pydantic.ValidationError):
            AuditRecord.model_validate(raw)

    def test_request_id_zero_is_recorded(self) -> None:
        # id == 0 is a real JSON-RPC id, so this must not become None.
        writer = self.make_writer()
        self.assertEqual(writer.build(action=AuditAction.ALLOW, request_id=0).request_id, "0")
        self.assertIsNone(writer.build(action=AuditAction.ALLOW, request_id=None).request_id)

    def test_request_id_stringified_for_str_and_int(self) -> None:
        writer = self.make_writer()
        self.assertEqual(writer.build(action=AuditAction.ALLOW, request_id=7).request_id, "7")
        self.assertEqual(writer.build(action=AuditAction.ALLOW, request_id="abc").request_id, "abc")

    def test_ts_is_utc_with_z_suffix(self) -> None:
        writer = self.make_writer()
        ts = writer.build(action=AuditAction.ALLOW).ts
        self.assertTrue(ts.endswith("Z"), ts)
        self.assertNotIn("+00:00", ts)


class TestArgsMode(AuditWriterTestCase):
    def test_default_mode_is_none(self) -> None:
        self.assertIs(audit.resolve_args_mode(), AuditArgsMode.NONE)
        writer = self.make_writer()
        self.assertIs(writer.args_mode, AuditArgsMode.NONE)

    def test_full_requires_the_literal_string(self) -> None:
        for value in ("1", "true", "yes", "on", "FULL", "Full", "full ", ""):
            with self.subTest(value=value), patch.dict(os.environ, {"AGENTPARRY_AUDIT_ARGS": value}):
                expected = AuditArgsMode.FULL if value.strip() == "full" else AuditArgsMode.NONE
                self.assertIs(audit.resolve_args_mode(), expected)

    def test_full_literal_resolves(self) -> None:
        with patch.dict(os.environ, {"AGENTPARRY_AUDIT_ARGS": "full"}):
            self.assertIs(audit.resolve_args_mode(), AuditArgsMode.FULL)

    def test_preview_resolves_case_insensitively(self) -> None:
        for value in ("preview", "Preview", " PREVIEW "):
            with self.subTest(value=value), patch.dict(os.environ, {"AGENTPARRY_AUDIT_ARGS": value}):
                self.assertIs(audit.resolve_args_mode(), AuditArgsMode.PREVIEW)

    def test_default_record_holds_no_raw_secret(self) -> None:
        secret = "sk_" + "live_" + "notarealkey" * 3
        writer = self.make_writer()
        writer.write(
            writer.build(
                action=AuditAction.ALLOW,
                tool="http_post",
                arguments={"api_key": secret, "url": "https://x.test/a?ssn=123-45-6789"},
            )
        )
        text = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(secret, text)
        self.assertNotIn("123-45-6789", text)
        self.assertNotIn("x.test", text)

        record = read_records(self.audit_path)[0]
        self.assertEqual(record["args_mode"], "none")
        self.assertIsNone(record["arguments"])
        self.assertIsNone(record["arg_preview"])
        self.assertEqual(record["arg_keys"], ["api_key", "url"])
        self.assertGreater(record["arg_bytes"], 0)
        self.assertEqual(len(record["arg_hash"]), 64)

    def test_preview_omits_sensitive_keys_and_redacts_pii(self) -> None:
        writer = self.make_writer(args_mode=AuditArgsMode.PREVIEW)
        writer.write(
            writer.build(
                action=AuditAction.ALLOW,
                tool="report",
                arguments={
                    "auth_token": "Bearer abc123",
                    "note": "ssn 123-45-6789",
                    "nested": {"password": "hunter2", "keep": "visible"},
                },
            )
        )
        record = read_records(self.audit_path)[0]
        preview = record["arg_preview"]
        self.assertEqual(record["args_mode"], "preview")
        self.assertNotIn("abc123", preview)
        self.assertNotIn("hunter2", preview)
        self.assertNotIn("123-45-6789", preview)
        self.assertIn(audit.OMITTED, preview)
        self.assertIn("[REDACTED-SSN]", preview)
        self.assertIn("visible", preview)

    def test_preview_is_truncated(self) -> None:
        writer = self.make_writer(args_mode=AuditArgsMode.PREVIEW)
        record = writer.build(action=AuditAction.ALLOW, tool="t", arguments={"blob": "x" * 5000})
        self.assertLessEqual(len(record.arg_preview or ""), audit.MAX_PREVIEW_CHARS)

    def test_full_mode_records_raw_arguments(self) -> None:
        writer = self.make_writer(args_mode=AuditArgsMode.FULL)
        writer.write(writer.build(action=AuditAction.ALLOW, tool="t", arguments={"token": "raw-secret"}))
        record = read_records(self.audit_path)[0]
        self.assertEqual(record["args_mode"], "full")
        self.assertEqual(record["arguments"], {"token": "raw-secret"})

    def test_full_mode_warns_exactly_once(self) -> None:
        with patch.object(audit, "_full_args_warned", False):
            with self.assertLogs("src.audit", level="WARNING") as logs:
                self.make_writer(args_mode=AuditArgsMode.FULL)
            self.assertEqual(len(logs.output), 1)
            self.assertIn("args_mode=full", logs.output[0])
            # A second writer must not warn again.
            logger = __import__("logging").getLogger("src.audit")
            with patch.object(logger, "warning") as mock_warn:
                self.make_writer(args_mode=AuditArgsMode.FULL)
            mock_warn.assert_not_called()


class TestHashing(AuditWriterTestCase):
    def test_hash_is_stable_for_identical_calls(self) -> None:
        key = audit.load_or_create_key(self.key_path)
        args = {"b": 2, "a": [1, {"z": None}]}
        reordered = {"a": [1, {"z": None}], "b": 2}
        self.assertEqual(audit.arg_hash(key, "t", args), audit.arg_hash(key, "t", reordered))

    def test_hash_differs_per_tool(self) -> None:
        key = audit.load_or_create_key(self.key_path)
        args = {"path": "/etc/passwd"}
        self.assertNotEqual(audit.arg_hash(key, "file_read", args), audit.arg_hash(key, "shell_exec", args))

    def test_hash_differs_per_key(self) -> None:
        args = {"path": "/etc/passwd"}
        a = audit.arg_hash(b"a" * 32, "file_read", args)
        b = audit.arg_hash(b"b" * 32, "file_read", args)
        self.assertNotEqual(a, b)

    def test_key_id_tracks_the_key(self) -> None:
        self.assertEqual(len(audit.key_id(b"a" * 32)), audit.KEY_ID_CHARS)
        self.assertNotEqual(audit.key_id(b"a" * 32), audit.key_id(b"b" * 32))

    def test_key_is_persistent_across_writers(self) -> None:
        first = self.make_writer()
        second = self.make_writer()
        args = {"path": "/etc/passwd"}
        a = first.build(action=AuditAction.ALLOW, tool="file_read", arguments=args)
        b = second.build(action=AuditAction.ALLOW, tool="file_read", arguments=args)
        self.assertEqual(a.arg_hash, b.arg_hash)
        self.assertEqual(a.arg_hash_key_id, b.arg_hash_key_id)

    def test_key_created_lazily(self) -> None:
        writer = self.make_writer()
        self.assertFalse(self.key_path.exists())
        writer.build(action=AuditAction.ALLOW, tool="t", arguments={"a": 1})
        self.assertTrue(self.key_path.exists())
        self.assertEqual(len(self.key_path.read_bytes()), audit.KEY_BYTES)

    def test_missing_key_does_not_break_the_record(self) -> None:
        writer = self.make_writer(key_path=self.key_path.parent / "nodir" / "sub" / "k")
        with patch.object(audit, "load_or_create_key", side_effect=PermissionError("nope")):
            record = writer.build(action=AuditAction.ALLOW, tool="t", arguments={"a": 1})
        self.assertIsNone(record.arg_hash)
        self.assertIsNone(record.arg_hash_key_id)
        self.assertEqual(record.arg_keys, ["a"])

    @pytest.mark.skipif(not POSIX_MODES, reason=SKIP_MODES)
    def test_key_file_mode_is_0600(self) -> None:
        audit.load_or_create_key(self.key_path)
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)

    @pytest.mark.skipif(not POSIX_MODES, reason=SKIP_MODES)
    def test_pre_existing_loose_key_is_tightened(self) -> None:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(b"k" * audit.KEY_BYTES)
        os.chmod(self.key_path, 0o644)
        audit.load_or_create_key(self.key_path)
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)


class TestFileHandling(AuditWriterTestCase):
    def test_one_line_per_record_and_monotonic_seq(self) -> None:
        writer = self.make_writer()
        for i in range(5):
            self.assertTrue(writer.write(writer.build(action=AuditAction.ALLOW, tool=f"t{i}")))
        records = read_records(self.audit_path)
        self.assertEqual(len(records), 5)
        self.assertEqual([r["seq"] for r in records], [1, 2, 3, 4, 5])
        self.assertEqual({r["run_id"] for r in records}, {writer.run_id})

    def test_disabled_writer_writes_nothing(self) -> None:
        writer = self.make_writer(enabled=False)
        self.assertFalse(writer.write(writer.build(action=AuditAction.ALLOW)))
        self.assertFalse(self.audit_path.exists())

    def test_audit_env_zero_disables(self) -> None:
        with patch.dict(os.environ, {"AGENTPARRY_AUDIT": "0"}):
            self.assertFalse(audit.audit_enabled())
        self.assertTrue(audit.audit_enabled())

    def test_audit_path_env_override(self) -> None:
        with patch.dict(os.environ, {"AGENTPARRY_AUDIT_PATH": "/tmp/ap-custom.jsonl"}):
            self.assertEqual(audit.default_audit_path(), Path("/tmp/ap-custom.jsonl"))

    @pytest.mark.skipif(not POSIX_MODES, reason=SKIP_MODES)
    def test_log_file_and_dir_mode_bits(self) -> None:
        writer = self.make_writer()
        writer.write(writer.build(action=AuditAction.ALLOW))
        self.assertEqual(stat.S_IMODE(self.audit_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.audit_path.parent.stat().st_mode), 0o700)

    @pytest.mark.skipif(not POSIX_MODES, reason=SKIP_MODES)
    def test_pre_existing_loose_log_file_is_tightened(self) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_path.write_text("", encoding="utf-8")
        os.chmod(self.audit_path, 0o666)
        writer = self.make_writer()
        writer.write(writer.build(action=AuditAction.ALLOW))
        self.assertEqual(stat.S_IMODE(self.audit_path.stat().st_mode), 0o600)

    def test_oversized_record_stays_one_line(self) -> None:
        writer = self.make_writer(args_mode=AuditArgsMode.FULL, max_line_bytes=2048)
        writer.write(
            writer.build(
                action=AuditAction.ALLOW,
                tool="t",
                arguments={"blob": "y" * 50_000},
                findings=[Finding(severity="high", description="d" * 300) for _ in range(10)],
            )
        )
        raw = self.audit_path.read_text(encoding="utf-8")
        self.assertEqual(raw.count("\n"), 1)
        record = read_records(self.audit_path)[0]
        self.assertIsNone(record["arguments"])
        self.assertIsNone(record["arg_preview"])
        self.assertEqual(record["findings"], [])
        self.assertIn("over line cap", record["detail"])
        # The summary counters survive the drop.
        self.assertEqual(record["finding_count"], 10)
        self.assertEqual(record["max_severity"], "high")

    def test_rotation_moves_one_generation(self) -> None:
        writer = self.make_writer(max_bytes=1500)
        for i in range(60):
            writer.write(writer.build(action=AuditAction.ALLOW, tool=f"tool{i}"))
        rotated = self.audit_path.with_name(self.audit_path.name + ".1")
        self.assertTrue(rotated.exists())
        self.assertLessEqual(self.audit_path.stat().st_size, 1500)
        for path in (self.audit_path, rotated):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    json.loads(line)

    @pytest.mark.skipif(not POSIX_MODES, reason=SKIP_MODES)
    def test_rotated_file_keeps_0600(self) -> None:
        writer = self.make_writer(max_bytes=1500)
        for i in range(60):
            writer.write(writer.build(action=AuditAction.ALLOW, tool=f"tool{i}"))
        rotated = self.audit_path.with_name(self.audit_path.name + ".1")
        self.assertEqual(stat.S_IMODE(rotated.stat().st_mode), 0o600)

    def test_surrogates_do_not_raise(self) -> None:
        writer = self.make_writer(args_mode=AuditArgsMode.FULL)
        hostile = "lone \ud800 surrogate"
        self.assertTrue(writer.write(writer.build(action=AuditAction.ALLOW, tool=hostile, arguments={"a": hostile})))
        records = read_records(self.audit_path)
        self.assertEqual(len(records), 1)
        # errors="replace" on an encode substitutes "?", not U+FFFD.
        self.assertEqual(records[0]["tool"], "lone ? surrogate")

    def test_newlines_in_values_stay_on_one_line(self) -> None:
        writer = self.make_writer(args_mode=AuditArgsMode.FULL)
        writer.write(writer.build(action=AuditAction.ALLOW, tool="t", arguments={"a": "x\ny\r\nz"}))
        self.assertEqual(self.audit_path.read_text(encoding="utf-8").count("\n"), 1)


class TestFailureBehavior(AuditWriterTestCase):
    def test_unwritable_path_returns_false(self) -> None:
        writer = self.make_writer(path=self.audit_path.parent / "not-a-dir")
        writer.path.parent.mkdir(parents=True, exist_ok=True)
        writer.path.write_text("i am a file\n", encoding="utf-8")
        bad = self.make_writer(path=writer.path / "audit.jsonl")
        with patch.object(audit.logging, "getLogger"):
            self.assertFalse(bad.write(bad.build(action=AuditAction.ALLOW)))
        self.assertEqual(bad.drops, 1)

    def test_permission_denied_returns_false(self) -> None:
        writer = self.make_writer()
        with (
            patch.object(audit.os, "open", side_effect=PermissionError(13, "Permission denied")),
            self.assertLogs("src.audit", level="WARNING") as logs,
        ):
            self.assertFalse(writer.write(writer.build(action=AuditAction.ALLOW)))
        self.assertTrue(any("permission denied" in line for line in logs.output))

    def test_disk_full_is_named(self) -> None:
        import errno as errno_mod

        writer = self.make_writer()
        with (
            patch.object(audit.os, "write", side_effect=OSError(errno_mod.ENOSPC, "No space left on device")),
            self.assertLogs("src.audit", level="WARNING") as logs,
        ):
            self.assertFalse(writer.write(writer.build(action=AuditAction.ALLOW)))
        self.assertTrue(any("disk full" in line for line in logs.output))

    def test_short_write_does_not_raise(self) -> None:
        writer = self.make_writer()
        with patch.object(audit.os, "write", return_value=3), self.assertLogs("src.audit", level="WARNING") as logs:
            self.assertFalse(writer.write(writer.build(action=AuditAction.ALLOW)))
        self.assertTrue(any("short write" in line for line in logs.output))

    def test_self_disables_after_repeated_failures(self) -> None:
        writer = self.make_writer()
        attempts = audit.MAX_CONSECUTIVE_FAILURES + 4
        with patch.object(audit.os, "open", side_effect=PermissionError(13, "denied")) as mock_open:
            with self.assertLogs("src.audit", level="WARNING") as logs:
                for _ in range(attempts):
                    self.assertFalse(writer.write(writer.build(action=AuditAction.ALLOW)))
            self.assertEqual(mock_open.call_count, audit.MAX_CONSECUTIVE_FAILURES)
        self.assertFalse(writer.enabled)
        self.assertEqual(writer.drops, audit.MAX_CONSECUTIVE_FAILURES)
        warnings = [line for line in logs.output if "Audit write failed" in line]
        self.assertEqual(len(warnings), audit.MAX_FAILURE_WARNINGS)
        self.assertTrue(any("disabled after" in line for line in logs.output))

    def test_failed_write_does_not_consume_a_seq(self) -> None:
        writer = self.make_writer()
        with patch.object(audit.os, "write", side_effect=OSError(28, "full")), patch.object(audit.logging, "getLogger"):
            writer.write(writer.build(action=AuditAction.ALLOW))
        writer._failures = 0
        writer.enabled = True
        self.assertTrue(writer.write(writer.build(action=AuditAction.ALLOW, tool="ok")))
        self.assertEqual(read_records(self.audit_path)[0]["seq"], 1)


class TestConcurrency(AuditWriterTestCase):
    def test_concurrent_appends_are_not_interleaved(self) -> None:
        writer = self.make_writer()
        threads_count = 8
        per_thread = 40
        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                for i in range(per_thread):
                    writer.write(
                        writer.build(
                            action=AuditAction.ALLOW,
                            tool=f"tool-{idx}",
                            arguments={"i": i, "pad": "p" * 200},
                        )
                    )
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(threads_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        records = read_records(self.audit_path)
        total = threads_count * per_thread
        self.assertEqual(len(records), total)
        self.assertEqual({r["seq"] for r in records}, set(range(1, total + 1)))


class TestConsoleLine(AuditWriterTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.writer = self.make_writer()

    def line(self, action: AuditAction, **kwargs: Any) -> str | None:
        arguments = kwargs.pop("arguments", None)
        record = self.writer.build(action=action, arguments=arguments, **kwargs)
        return audit.format_console_line(record, arguments=arguments)

    def test_legacy_line_shapes(self) -> None:
        args = {"to": "dev@company.com", "subject": "x"}
        compact = '{"to": "dev@company.com", "subject": "x"}'
        cases = [
            (
                self.line(AuditAction.ALLOW, tool="email_send", arguments=args),
                f"[ALLOW]   email_send {compact}",
            ),
            (
                self.line(AuditAction.BLOCK_POLICY, tool="shell_exec", rule="block_shell", arguments=args),
                f"[BLOCK]   shell_exec {compact}  <- block_shell",
            ),
            (
                self.line(AuditAction.REQUIRE_APPROVAL, tool="email_send", rule="flag_ext", arguments=args),
                f"[APPROVE] email_send {compact}  <- flag_ext",
            ),
            (
                self.line(AuditAction.REDACT_OUTPUT, tool="pii_tool", pii_redactions=3),
                "[REDACT]  pii_tool   (3 PII items redacted)",
            ),
            (
                self.line(AuditAction.BLOCK_INJECTION, tool="file_read"),
                "[INJECT]  file_read  prompt injection detected (critical)",
            ),
        ]
        for actual, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(actual, expected)

    def test_short_tool_name_is_padded_to_ten(self) -> None:
        self.assertEqual(self.line(AuditAction.ALLOW, tool="t", arguments={}), "[ALLOW]   t          {}")

    def test_missing_rule_falls_back_to_legacy_default(self) -> None:
        self.assertEqual(
            self.line(AuditAction.BLOCK_POLICY, tool="t", arguments={}),
            "[BLOCK]   t          {}  <- policy_block",
        )
        self.assertEqual(
            self.line(AuditAction.REQUIRE_APPROVAL, tool="t", arguments={}),
            "[APPROVE] t          {}  <- requires_approval",
        )

    def test_console_keeps_raw_arguments(self) -> None:
        secret = "sk_" + "live_" + "notarealkey" * 3
        line = self.line(AuditAction.ALLOW, tool="t", arguments={"api_key": secret})
        self.assertIn(secret, line or "")

    def test_silent_actions_have_no_console_line(self) -> None:
        for action in (
            AuditAction.PASSTHROUGH,
            AuditAction.METHOD_NOT_FOUND,
            AuditAction.INVALID_PARAMS,
            AuditAction.FAIL_OPEN,
        ):
            with self.subTest(action=action):
                self.assertIsNone(self.line(action, tool="t"))


class TestWriterAccessors(unittest.TestCase):
    def test_get_writer_is_a_singleton(self) -> None:
        self.assertIs(audit.get_writer(), audit.get_writer())

    def test_set_and_reset_writer(self) -> None:
        custom = audit.AuditWriter(enabled=False)
        audit.set_writer(custom)
        self.assertIs(audit.get_writer(), custom)
        audit.reset_writer()
        self.assertIsNot(audit.get_writer(), custom)

    def test_default_writer_uses_env_path(self) -> None:
        self.assertEqual(audit.get_writer().path, Path(os.environ["AGENTPARRY_AUDIT_PATH"]))


class TestHelpers(unittest.TestCase):
    def test_omit_sensitive_is_recursive(self) -> None:
        out = audit.omit_sensitive({"Token": "t", "a": [{"secret": "s", "ok": 1}]})
        self.assertEqual(out, {"Token": audit.OMITTED, "a": [{"secret": audit.OMITTED, "ok": 1}]})

    def test_canonical_json_sorts_keys(self) -> None:
        self.assertEqual(audit.canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_build_preview_reuses_output_inspector(self) -> None:
        preview = audit.build_preview("t", {"note": "AKIAABCDEFGHIJKLMNOP"}, OutputInspector())
        self.assertIn("[REDACTED-AWS_KEY]", preview)


if __name__ == "__main__":
    unittest.main()
