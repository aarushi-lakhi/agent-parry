"""Tests for the path_containment condition type and the file_read rules using it."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

import yaml

from src.models import PolicyAction
from src.policy import (
    PolicyEngine,
    fold_path,
    folded_path_candidates,
    path_escapes_upward,
    path_segments,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

CLOSED_TRAVERSAL_PAYLOADS = (
    "pt-001",
    "pt-002",
    "pt-003",
    "pt-004",
    "pt-005",
    "pt-006",
    "pt-007",
    "ob-006",
)

FULLWIDTH_SOLIDUS = "\uff0f"


def _condition(**overrides: Any) -> dict[str, Any]:
    condition: dict[str, Any] = {
        "type": "path_containment",
        "field": "path",
        "normalize": {"canonical": True, "decoded": True},
    }
    condition.update(overrides)
    return condition


def _engine(*conditions: dict[str, Any]) -> PolicyEngine:
    rules = [
        {
            "name": f"block_paths_{index}",
            "tool": "file_read",
            "action": "BLOCK",
            "message": "Blocked: path",
            "conditions": [condition],
        }
        for index, condition in enumerate(conditions)
    ]
    return PolicyEngine(policy={"rules": rules, "settings": {}})


class TestFoldPath(unittest.TestCase):
    def test_it_collapses_traversal_after_separator_normalization(self) -> None:
        cases = {
            "../../../etc/passwd": "../../../etc/passwd",
            "/var/www/html/assets/../../../../etc/passwd": "/etc/passwd",
            "..\\..\\etc\\passwd": "../../etc/passwd",
            "//etc//passwd": "/etc/passwd",
            "/etc/./passwd": "/etc/passwd",
            "/ETC/Shadow": "/etc/shadow",
            "  /etc/passwd  ": "/etc/passwd",
            "/var/log/": "/var/log",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(expected, fold_path(raw))

    def test_doubled_dots_stay_a_directory_name(self) -> None:
        self.assertEqual("..../..../etc/passwd", fold_path("....//....//etc/passwd"))

    def test_a_filename_containing_dots_survives(self) -> None:
        self.assertEqual(
            "/home/user/reports/2024..2025-summary.txt",
            fold_path("/home/user/reports/2024..2025-summary.txt"),
        )

    def test_unusable_values_fold_to_empty(self) -> None:
        for raw in ("", "   ", ".", "./", "/etc/passwd\x00.txt", "log\x1b[2Jfile"):
            with self.subTest(raw=raw):
                self.assertEqual("", fold_path(raw))

    def test_escape_detection_reads_the_folded_form(self) -> None:
        self.assertTrue(path_escapes_upward(fold_path("../../etc")))
        self.assertTrue(path_escapes_upward(".."))
        self.assertFalse(path_escapes_upward(fold_path("a/../b")))
        self.assertFalse(path_escapes_upward(fold_path("..../..../etc")))

    def test_segments_drop_empties_and_dots(self) -> None:
        self.assertEqual(("home", "user", ".ssh"), path_segments("/home/./user//.ssh/"))

    def test_candidates_expose_the_decoded_spelling(self) -> None:
        self.assertIn("../../../etc/passwd", folded_path_candidates("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"))
        self.assertIn(
            "../../etc/passwd",
            folded_path_candidates(f"..{FULLWIDTH_SOLIDUS}..{FULLWIDTH_SOLIDUS}etc{FULLWIDTH_SOLIDUS}passwd"),
        )

    def test_candidates_ignore_base64_plaintext(self) -> None:
        candidates = folded_path_candidates("/var/log/L2V0Yy9wYXNzd2Q.log")
        self.assertEqual(["/var/log/l2v0yy9wyxnzd2q.log"], candidates)


class TestTraversalSpellings(unittest.TestCase):
    """Every spelling of the same traversal lands on the same decision."""

    def setUp(self) -> None:
        self.engine = _engine(_condition(denied_paths=["/etc", "etc/passwd"]))

    def test_every_spelling_of_etc_passwd_is_blocked(self) -> None:
        spellings = (
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            f"..{FULLWIDTH_SOLIDUS}..{FULLWIDTH_SOLIDUS}..{FULLWIDTH_SOLIDUS}etc{FULLWIDTH_SOLIDUS}passwd",
            "..\\..\\..\\etc\\passwd",
            "/var/www/html/assets/../../../../etc/passwd",
            "/etc//passwd",
            "/ETC/PASSWD",
            "/etc/./passwd",
        )
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                decision = self.engine.evaluate("file_read", {"path": spelling})
                self.assertEqual(PolicyAction.BLOCK, decision.action)

    def test_the_finding_names_the_folded_path(self) -> None:
        decision = self.engine.evaluate("file_read", {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"})
        self.assertEqual("decoded:percent", decision.findings[0].view)
        self.assertEqual("../../etc/passwd", decision.findings[0].matched_text)

    def test_an_upward_escape_is_flagged_without_any_configured_path(self) -> None:
        engine = _engine(_condition())
        self.assertEqual(
            PolicyAction.BLOCK,
            engine.evaluate("file_read", {"path": "../../../anything"}).action,
        )
        self.assertEqual(
            PolicyAction.ALLOW,
            engine.evaluate("file_read", {"path": "/home/user/notes/../notes.md"}).action,
        )


class TestAllowedRoots(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = _engine(_condition(allowed_roots=["/home/user", "/var/log"]))

    def test_a_path_inside_a_root_is_allowed(self) -> None:
        for path in ("/home/user", "/home/user/README.md", "/var/log/app.log"):
            with self.subTest(path=path):
                self.assertEqual(
                    PolicyAction.ALLOW, self.engine.evaluate("file_read", {"path": path}).action
                )

    def test_a_path_outside_every_root_is_blocked(self) -> None:
        for path in ("/etc/shadow", "/proc/self/environ", "/home/other/notes.md"):
            with self.subTest(path=path):
                self.assertEqual(
                    PolicyAction.BLOCK, self.engine.evaluate("file_read", {"path": path}).action
                )

    def test_a_sibling_directory_sharing_a_prefix_is_not_contained(self) -> None:
        decision = self.engine.evaluate("file_read", {"path": "/home/user-backup/secrets"})
        self.assertEqual(PolicyAction.BLOCK, decision.action)

    def test_a_relative_path_that_does_not_climb_is_left_alone(self) -> None:
        for path in ("notes.md", "reports/q3.csv", "./notes.md"):
            with self.subTest(path=path):
                self.assertEqual(
                    PolicyAction.ALLOW, self.engine.evaluate("file_read", {"path": path}).action
                )

    def test_an_empty_root_list_flags_every_absolute_path(self) -> None:
        engine = _engine(_condition(allowed_roots=[]))
        self.assertEqual(
            PolicyAction.BLOCK, engine.evaluate("file_read", {"path": "/var/log/app.log"}).action
        )

    def test_an_absent_root_list_enforces_no_containment(self) -> None:
        engine = _engine(_condition(denied_paths=["/etc"]))
        self.assertEqual(
            PolicyAction.ALLOW, engine.evaluate("file_read", {"path": "/var/log/app.log"}).action
        )


class TestDeniedPaths(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = _engine(
            _condition(denied_paths=["/etc", "/proc", ".ssh", ".aws/credentials"])
        )

    def test_an_absolute_entry_denies_its_subtree(self) -> None:
        for path in ("/etc", "/etc/shadow", "/etc/ssl/private/key.pem", "/proc/self/environ"):
            with self.subTest(path=path):
                self.assertEqual(
                    PolicyAction.BLOCK, self.engine.evaluate("file_read", {"path": path}).action
                )

    def test_an_absolute_entry_does_not_deny_a_prefix_neighbour(self) -> None:
        self.assertEqual(
            PolicyAction.ALLOW, self.engine.evaluate("file_read", {"path": "/etcetera/notes"}).action
        )

    def test_a_relative_entry_denies_the_segments_anywhere(self) -> None:
        for path in (
            "/home/user/.ssh/id_ed25519",
            "/root/.ssh",
            ".ssh/config",
            "/home/user/.aws/credentials",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    PolicyAction.BLOCK, self.engine.evaluate("file_read", {"path": path}).action
                )

    def test_a_relative_entry_matches_whole_segments_only(self) -> None:
        for path in ("/home/user/.sshconfig", "/home/user/notes.ssh.md", "/home/user/.aws/config"):
            with self.subTest(path=path):
                self.assertEqual(
                    PolicyAction.ALLOW, self.engine.evaluate("file_read", {"path": path}).action
                )

    def test_the_finding_names_the_entry_that_denied_it(self) -> None:
        decision = self.engine.evaluate("file_read", {"path": "/home/user/.ssh/id_ed25519"})
        self.assertEqual(".ssh", decision.findings[0].matched_pattern)


class TestPathConditionShape(unittest.TestCase):
    def test_a_blank_or_absent_path_does_not_match(self) -> None:
        engine = _engine(_condition(allowed_roots=["/home/user"], denied_paths=["/etc"]))
        for arguments in ({}, {"path": ""}, {"path": "   "}, {"other": "/etc/shadow"}):
            with self.subTest(arguments=arguments):
                self.assertEqual(PolicyAction.ALLOW, engine.evaluate("file_read", arguments).action)

    def test_a_path_carrying_a_control_character_is_flagged(self) -> None:
        engine = _engine(_condition(allowed_roots=["/home/user"]))
        decision = engine.evaluate("file_read", {"path": "/home/user/notes.md\x00/etc/shadow"})
        self.assertEqual(PolicyAction.BLOCK, decision.action)
        self.assertIn("control characters", decision.findings[0].description)

    def test_every_element_of_a_list_valued_field_is_checked(self) -> None:
        engine = _engine(_condition(denied_paths=["/etc"]))
        decision = engine.evaluate("file_read", {"path": ["/home/user/a.md", "/etc/shadow"]})
        self.assertEqual(PolicyAction.BLOCK, decision.action)

    def test_a_malformed_condition_drops_the_rule(self) -> None:
        for broken in ({"field": 3}, {"allowed_roots": "/home/user"}, {"denied_paths": "/etc"}):
            with self.subTest(broken=broken):
                engine = _engine(_condition(**broken))
                self.assertEqual(0, engine.active_rule_count)

    def test_unusable_entries_are_dropped_not_treated_as_matching_everything(self) -> None:
        engine = _engine(_condition(denied_paths=["", "   ", "/etc"]))
        self.assertEqual(1, engine.active_rule_count)
        self.assertEqual(
            PolicyAction.ALLOW, engine.evaluate("file_read", {"path": "/home/user/a.md"}).action
        )
        self.assertEqual(
            PolicyAction.BLOCK, engine.evaluate("file_read", {"path": "/etc/shadow"}).action
        )

    def test_raw_only_matching_still_folds_the_original_view(self) -> None:
        engine = _engine(_condition(denied_paths=["/etc"], normalize=False))
        self.assertEqual(
            PolicyAction.BLOCK,
            engine.evaluate("file_read", {"path": "/var/../etc/shadow"}).action,
        )
        self.assertEqual(
            PolicyAction.ALLOW,
            engine.evaluate("file_read", {"path": "%2fetc%2fshadow"}).action,
        )


class TestShippedPolicyClosesTheTraversalGap(unittest.TestCase):
    """The payloads whose known_gap flag was cleared are blocked by the shipped policy."""

    payloads: dict[str, dict[str, Any]]
    engine: PolicyEngine

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = PolicyEngine(policy_path=str(REPO_ROOT / "config" / "default_policy.yaml"))
        with (REPO_ROOT / "attacks" / "payloads.yaml").open(encoding="utf-8") as handle:
            cls.payloads = {p["id"]: p for p in yaml.safe_load(handle)["payloads"]}

    def _action(self, payload_id: str) -> PolicyAction:
        payload = self.payloads[payload_id]
        return self.engine.evaluate(payload["tool"], payload["arguments"]).action

    def test_the_cleared_payloads_no_longer_declare_a_gap(self) -> None:
        for payload_id in CLOSED_TRAVERSAL_PAYLOADS:
            with self.subTest(payload=payload_id):
                self.assertFalse(self.payloads[payload_id].get("known_gap", False))

    def test_the_cleared_payloads_are_blocked(self) -> None:
        for payload_id in CLOSED_TRAVERSAL_PAYLOADS:
            with self.subTest(payload=payload_id):
                self.assertEqual(PolicyAction.BLOCK, self._action(payload_id))

    def test_every_benign_file_read_is_still_allowed(self) -> None:
        benign = [
            p
            for p in self.payloads.values()
            if p["category"] == "benign" and p["tool"] == "file_read"
        ]
        self.assertTrue(benign)
        for payload in benign:
            with self.subTest(payload=payload["id"]):
                self.assertEqual(PolicyAction.ALLOW, self._action(payload["id"]))

    def test_the_pii_reads_still_reach_output_side_redaction(self) -> None:
        for payload_id in ("pl-001", "pl-002"):
            with self.subTest(payload=payload_id):
                self.assertEqual(PolicyAction.ALLOW, self._action(payload_id))


if __name__ == "__main__":
    unittest.main()
