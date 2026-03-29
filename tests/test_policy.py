"""Tests for policy engine rule matching and persistence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from src.models import PolicyAction
from src.policy import PolicyEngine


class TestPolicyEngine(unittest.TestCase):
    def _write_policy(self, root: Path, payload: dict) -> Path:
        policy_path = root / "policy.yaml"
        with policy_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle, sort_keys=False)
        return policy_path

    def test_default_allow_when_no_rule_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = self._write_policy(root, {"rules": [], "settings": {}})
            engine = PolicyEngine(policy_path=str(path))
            decision = engine.evaluate("shell_exec", {"command": "echo hi"})
            self.assertEqual(decision.action, PolicyAction.ALLOW)
            self.assertIsNone(decision.rule_name)

    def test_first_match_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_policy(
                Path(tmpdir),
                {
                    "rules": [
                        {
                            "name": "first_block",
                            "tool": "shell_exec",
                            "action": "block",
                            "conditions": [{"type": "always"}],
                            "message": "first",
                        },
                        {
                            "name": "second_allow",
                            "tool": "shell_exec",
                            "action": "allow",
                            "conditions": [{"type": "always"}],
                            "message": "second",
                        },
                    ],
                    "settings": {},
                },
            )
            engine = PolicyEngine(policy_path=str(path))
            decision = engine.evaluate("shell_exec", {"command": "whoami"})
            self.assertEqual(decision.action, PolicyAction.BLOCK)
            self.assertEqual(decision.rule_name, "first_block")
            self.assertEqual(decision.message, "first")

    def test_tool_wildcard_and_pattern_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_policy(
                Path(tmpdir),
                {
                    "rules": [
                        {
                            "name": "block_rm",
                            "tool": "*",
                            "action": "block",
                            "conditions": [
                                {
                                    "type": "pattern_match",
                                    "field": "command",
                                    "patterns": ["rm\\s+-rf"],
                                }
                            ],
                            "message": "blocked rm",
                        }
                    ],
                    "settings": {},
                },
            )
            engine = PolicyEngine(policy_path=str(path))
            decision = engine.evaluate("shell_exec", {"command": "rm -rf /tmp/demo"})
            self.assertEqual(decision.action, PolicyAction.BLOCK)
            self.assertEqual(decision.rule_name, "block_rm")

    def test_domain_allowlist_requires_approval_for_external(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_policy(
                Path(tmpdir),
                {
                    "rules": [
                        {
                            "name": "external_email",
                            "tool": "email_send",
                            "action": "require_approval",
                            "conditions": [
                                {
                                    "type": "domain_allowlist",
                                    "field": "to",
                                    "allowed_domains": ["company.com"],
                                }
                            ],
                            "message": "external",
                        }
                    ],
                    "settings": {},
                },
            )
            engine = PolicyEngine(policy_path=str(path))
            blocked = engine.evaluate("email_send", {"to": "dev@example.com"})
            self.assertEqual(blocked.action, PolicyAction.REQUIRE_APPROVAL)
            allowed = engine.evaluate("email_send", {"to": "dev@company.com"})
            self.assertEqual(allowed.action, PolicyAction.ALLOW)

    def test_empty_domain_allowlist_flags_everything(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_policy(
                Path(tmpdir),
                {
                    "rules": [
                        {
                            "name": "all_external",
                            "tool": "email_send",
                            "action": "require_approval",
                            "conditions": [
                                {
                                    "type": "domain_allowlist",
                                    "field": "to",
                                    "allowed_domains": [],
                                }
                            ],
                            "message": "all",
                        }
                    ],
                    "settings": {},
                },
            )
            engine = PolicyEngine(policy_path=str(path))
            decision = engine.evaluate("email_send", {"to": "dev@company.com"})
            self.assertEqual(decision.action, PolicyAction.REQUIRE_APPROVAL)

    def test_pii_detection_scans_all_argument_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_policy(
                Path(tmpdir),
                {
                    "rules": [
                        {
                            "name": "pii_scan",
                            "tool": "file_read",
                            "action": "block",
                            "conditions": [
                                {
                                    "type": "pii_detection",
                                    "patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"],
                                }
                            ],
                            "message": "pii found",
                        }
                    ],
                    "settings": {},
                },
            )
            engine = PolicyEngine(policy_path=str(path))
            decision = engine.evaluate(
                "file_read",
                {"payload": {"content": "user ssn 123-45-6789", "meta": ["ok"]}},
            )
            self.assertEqual(decision.action, PolicyAction.BLOCK)
            self.assertEqual(decision.rule_name, "pii_scan")

    def test_malformed_rules_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write_policy(
                Path(tmpdir),
                {
                    "rules": [
                        {
                            "name": "bad_regex",
                            "tool": "shell_exec",
                            "action": "block",
                            "conditions": [
                                {
                                    "type": "pattern_match",
                                    "field": "command",
                                    "patterns": ["("],
                                }
                            ],
                            "message": "invalid",
                        },
                        {
                            "name": "good_rule",
                            "tool": "shell_exec",
                            "action": "block",
                            "conditions": [{"type": "always"}],
                            "message": "good",
                        },
                    ],
                    "settings": {},
                },
            )
            engine = PolicyEngine(policy_path=str(path))
            decision = engine.evaluate("shell_exec", {"command": "echo ok"})
            self.assertEqual(decision.action, PolicyAction.BLOCK)
            self.assertEqual(decision.rule_name, "good_rule")

    def test_add_remove_generated_reload_and_get_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = self._write_policy(root, {"rules": [], "settings": {"log_all_calls": True}})
            engine = PolicyEngine(policy_path=str(path))
            engine.add_rule(
                {
                    "name": "autogen_blocker",
                    "tool": "shell_exec",
                    "action": "block",
                    "conditions": [{"type": "always"}],
                    "message": "auto",
                }
            )
            engine.add_rule(
                {
                    "name": "manual_keep",
                    "tool": "shell_exec",
                    "action": "allow",
                    "conditions": [{"type": "always"}],
                    "message": "keep",
                }
            )
            names_before = [rule["name"] for rule in engine.get_rules()]
            self.assertEqual(names_before, ["autogen_blocker", "manual_keep"])

            engine.remove_generated_rules()
            names_after = [rule["name"] for rule in engine.get_rules()]
            self.assertEqual(names_after, ["manual_keep"])

            # Confirm persisted state can be reloaded from disk.
            reloaded = PolicyEngine(policy_path=str(path))
            self.assertEqual([rule["name"] for rule in reloaded.get_rules()], ["manual_keep"])


if __name__ == "__main__":
    unittest.main()
