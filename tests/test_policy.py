"""Tests for policy engine rule matching and persistence."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

import yaml

from src.models import PolicyAction
from src.policy import PolicyEngine

ZWSP = "\u200b"
NBSP = "\u00a0"
CYRILLIC_O = "\u043e"


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

    def test_get_settings_returns_a_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            settings = {"result_inspection": {"action": "block", "exempt_tools": ["docs"]}}
            path = self._write_policy(root, {"rules": [], "settings": settings})
            engine = PolicyEngine(policy_path=str(path))

            loaded = engine.get_settings()
            self.assertEqual(settings, loaded)
            loaded["result_inspection"]["action"] = "annotate"
            self.assertEqual("block", engine.get_settings()["result_inspection"]["action"])

    def test_get_settings_on_a_missing_file_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = PolicyEngine(policy_path=str(Path(tmpdir) / "absent.yaml"))
            self.assertEqual({}, engine.get_settings())


class TestHostHelpers(unittest.TestCase):
    def test_normalize_host_casefolds_and_strips_trailing_dot(self) -> None:
        self.assertEqual(PolicyEngine._normalize_host("Example.COM"), "example.com")
        self.assertEqual(PolicyEngine._normalize_host("  example.com.  "), "example.com")

    def test_normalize_host_canonicalizes_ip_literals(self) -> None:
        self.assertEqual(PolicyEngine._normalize_host("[0:0:0:0:0:0:0:1]"), "::1")
        self.assertEqual(PolicyEngine._normalize_host("::1"), "::1")
        self.assertEqual(PolicyEngine._normalize_host("127.0.0.1"), "127.0.0.1")

    def test_normalize_host_idna_encodes_unicode(self) -> None:
        self.assertEqual(PolicyEngine._normalize_host("münchen.example"), "xn--mnchen-3ya.example")

    def test_normalize_host_never_raises_on_bad_labels(self) -> None:
        for value in ("", "a..b", "." * 5, "x" * 80 + ".example", "\udcff.example"):
            with self.subTest(value=value):
                result = PolicyEngine._normalize_host(value)
                self.assertTrue(result is None or isinstance(result, str))

    def test_host_from_token_url_forms(self) -> None:
        cases = {
            "https://api.company.com/v1": "api.company.com",
            "https://api.example.com@evil.com/x": "evil.com",
            "http://evil.com/?u=a@example.com": "evil.com",
            "http://user:pass@company.com:8443/x": "company.com",
            "//company.com/x": "company.com",
            "FTP://Files.Company.COM": "files.company.com",
            "company.com:8443": "company.com",
            "company.com/path": "company.com",
            "company.com": "company.com",
            "dev@company.com": "company.com",
        }
        for token, expected in cases.items():
            with self.subTest(token=token):
                self.assertEqual(PolicyEngine._host_from_token(token), expected)

    def test_host_from_token_returns_none_when_unparseable(self) -> None:
        for token in ("", "   ", "http://", "user@example.com/extra", "user@host:25", "http://[bad"):
            with self.subTest(token=token):
                self.assertIsNone(PolicyEngine._host_from_token(token))

    def test_extract_hosts_recurses_into_lists(self) -> None:
        self.assertEqual(
            PolicyEngine._extract_hosts(["a@evil.com", ("b@company.com",)]),
            ["evil.com", "company.com"],
        )

    def test_extract_hosts_splits_string_tokens(self) -> None:
        self.assertEqual(
            PolicyEngine._extract_hosts("a@evil.com, b@company.com;c@other.net"),
            ["evil.com", "company.com", "other.net"],
        )

    def test_extract_hosts_reports_none_for_empty_values(self) -> None:
        self.assertEqual(PolicyEngine._extract_hosts(None), [None])
        self.assertEqual(PolicyEngine._extract_hosts("   "), [None])


class TestDomainAllowlistHosts(unittest.TestCase):
    def _engine(
        self,
        root: Path,
        allowed_domains: list[str],
        field: str = "url",
        include_subdomains: bool | None = None,
    ) -> PolicyEngine:
        condition: dict = {
            "type": "domain_allowlist",
            "field": field,
            "allowed_domains": allowed_domains,
        }
        if include_subdomains is not None:
            condition["include_subdomains"] = include_subdomains
        policy_path = root / "policy.yaml"
        with policy_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(
                {
                    "rules": [
                        {
                            "name": "external_host",
                            "tool": "http_fetch",
                            "action": "require_approval",
                            "conditions": [condition],
                            "message": "external host",
                        }
                    ],
                    "settings": {},
                },
                handle,
                sort_keys=False,
            )
        return PolicyEngine(policy_path=str(policy_path))

    def _assert(self, engine: PolicyEngine, arguments: dict, expected: PolicyAction) -> None:
        self.assertEqual(engine.evaluate("http_fetch", arguments).action, expected)

    def test_url_field_allows_allowlisted_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["api.company.com"])
            self._assert(engine, {"url": "https://api.company.com/v1/send"}, PolicyAction.ALLOW)

    def test_url_field_flags_other_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["api.company.com"])
            self._assert(engine, {"url": "https://evil.com/v1/send"}, PolicyAction.REQUIRE_APPROVAL)

    def test_userinfo_cannot_spoof_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["api.example.com"])
            self._assert(
                engine,
                {"url": "https://api.example.com@evil.com/x"},
                PolicyAction.REQUIRE_APPROVAL,
            )

    def test_allowlisted_host_in_query_string_does_not_allow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["example.com"])
            self._assert(
                engine,
                {"url": "http://evil.com/?u=a@example.com"},
                PolicyAction.REQUIRE_APPROVAL,
            )

    def test_multiple_recipients_all_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["company.com"], field="to")
            self._assert(
                engine,
                {"to": "a@evil.com, b@company.com"},
                PolicyAction.REQUIRE_APPROVAL,
            )
            self._assert(engine, {"to": "a@company.com, b@company.com"}, PolicyAction.ALLOW)

    def test_list_valued_field_checks_every_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["company.com"], field="to")
            self._assert(engine, {"to": ["a@company.com", "b@company.com"]}, PolicyAction.ALLOW)
            self._assert(
                engine,
                {"to": ["a@company.com", "b@evil.com"]},
                PolicyAction.REQUIRE_APPROVAL,
            )

    def test_schemeless_port_and_trailing_dot_normalize(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["Example.COM", "example.com."])
            for value in ("example.com", "example.com:8443", "example.com.", "//EXAMPLE.com/x"):
                with self.subTest(value=value):
                    self._assert(engine, {"url": value}, PolicyAction.ALLOW)

    def test_idn_and_punycode_are_interchangeable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["xn--mnchen-3ya.example"])
            self._assert(engine, {"url": "https://münchen.example/x"}, PolicyAction.ALLOW)
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["münchen.example"])
            self._assert(engine, {"url": "https://xn--mnchen-3ya.example/x"}, PolicyAction.ALLOW)

    def test_ip_literals_including_compressed_ipv6(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["127.0.0.1", "::1"])
            for value in (
                "http://127.0.0.1:8080/x",
                "127.0.0.1",
                "http://[::1]/x",
                "http://[0:0:0:0:0:0:0:1]:9090/x",
                "[::1]",
            ):
                with self.subTest(value=value):
                    self._assert(engine, {"url": value}, PolicyAction.ALLOW)
            self._assert(engine, {"url": "http://127.0.0.2/x"}, PolicyAction.REQUIRE_APPROVAL)

    def test_unparseable_value_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["example.com"])
            for value in ("http://", "user@example.com/extra", "", None, []):
                with self.subTest(value=value):
                    self._assert(engine, {"url": value}, PolicyAction.REQUIRE_APPROVAL)
            self._assert(engine, {}, PolicyAction.REQUIRE_APPROVAL)

    def test_subdomains_flagged_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["company.com"], field="to")
            self._assert(engine, {"to": "dev@mail.company.com"}, PolicyAction.REQUIRE_APPROVAL)

    def test_include_subdomains_allows_subdomains(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["company.com"], include_subdomains=True)
            self._assert(engine, {"url": "https://mail.company.com/x"}, PolicyAction.ALLOW)
            self._assert(engine, {"url": "https://company.com/x"}, PolicyAction.ALLOW)
            self._assert(engine, {"url": "https://notcompany.com/x"}, PolicyAction.REQUIRE_APPROVAL)
            self._assert(
                engine,
                {"url": "https://company.com.evil.net/x"},
                PolicyAction.REQUIRE_APPROVAL,
            )

    def test_include_subdomains_refuses_bare_tld_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["com"], include_subdomains=True)
            self._assert(engine, {"url": "https://evil.com/x"}, PolicyAction.REQUIRE_APPROVAL)

    def test_include_subdomains_refuses_ip_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), ["127.0.0.1"], include_subdomains=True)
            self._assert(engine, {"url": "http://127.0.0.1/x"}, PolicyAction.ALLOW)
            self._assert(engine, {"url": "http://sub.127.0.0.1/x"}, PolicyAction.REQUIRE_APPROVAL)

    def test_shipped_external_email_rule_unchanged_for_single_address(self) -> None:
        shipped = Path(__file__).resolve().parents[1] / "config" / "default_policy.yaml"
        engine = PolicyEngine(policy_path=str(shipped))
        internal = engine.evaluate("email_send", {"to": "dev@company.com", "subject": "hi", "body": "hi"})
        self.assertEqual(internal.action, PolicyAction.ALLOW)
        external = engine.evaluate("email_send", {"to": "dev@example.com", "subject": "hi", "body": "hi"})
        self.assertEqual(external.action, PolicyAction.REQUIRE_APPROVAL)
        self.assertEqual(external.rule_name, "flag_external_email")


class TestNormalizedRuleMatching(unittest.TestCase):
    """Views apply to pattern_match and pii_detection only."""

    def _engine(
        self,
        root: Path,
        *,
        settings: dict | None = None,
        rule_extra: dict | None = None,
        condition_extra: dict | None = None,
    ) -> PolicyEngine:
        condition: dict = {
            "type": "pattern_match",
            "field": "command",
            "patterns": [r"rm\s+-rf\s+/"],
            **(condition_extra or {}),
        }
        rule: dict = {
            "name": "block_shell",
            "tool": "shell_exec",
            "action": "block",
            "message": "blocked",
            "conditions": [condition],
            **(rule_extra or {}),
        }
        policy_path = root / "policy.yaml"
        with policy_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump({"rules": [rule], "settings": settings or {}}, handle, sort_keys=False)
        return PolicyEngine(policy_path=str(policy_path))

    def _action(self, engine: PolicyEngine, command: str) -> PolicyAction:
        return engine.evaluate("shell_exec", {"command": command}).action

    def test_canonical_view_is_on_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir))
            for label, command in {
                "plain": "rm -rf /",
                "zero-width": f"rm{ZWSP} -rf /",
                "fullwidth": "\uff52\uff4d -rf /",
                "nbsp": f"rm{NBSP}-rf /",
                "tab-run": "rm \t -rf /",
            }.items():
                with self.subTest(label=label):
                    self.assertEqual(PolicyAction.BLOCK, self._action(engine, command))

    def test_decoded_views_are_off_by_default(self) -> None:
        """BLOCK cannot be undone over stdio, so decoding stays opt-in."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir))
            encoded = base64.b64encode(b"rm -rf / --no-preserve-root").decode()
            self.assertEqual(PolicyAction.ALLOW, self._action(engine, encoded))

    def test_rule_level_normalize_can_enable_decoded_views(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), rule_extra={"normalize": {"decoded": True}})
            encoded = base64.b64encode(b"rm -rf / --no-preserve-root").decode()
            self.assertEqual(PolicyAction.BLOCK, self._action(engine, encoded))
            self.assertEqual(PolicyAction.BLOCK, self._action(engine, "rm -rf /"))

    def test_rule_level_normalize_false_restores_raw_matching(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), rule_extra={"normalize": False})
            self.assertEqual(PolicyAction.ALLOW, self._action(engine, f"rm{ZWSP} -rf /"))
            self.assertEqual(PolicyAction.BLOCK, self._action(engine, "rm -rf /"))

    def test_condition_level_normalize_overrides_the_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(
                Path(tmpdir),
                rule_extra={"normalize": False},
                condition_extra={"normalize": True},
            )
            self.assertEqual(PolicyAction.BLOCK, self._action(engine, f"rm{ZWSP} -rf /"))

    def test_global_setting_can_disable_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), settings={"normalization": {"enabled": False}})
            self.assertEqual(PolicyAction.ALLOW, self._action(engine, f"rm{ZWSP} -rf /"))
            self.assertEqual(PolicyAction.BLOCK, self._action(engine, "rm -rf /"))

    def test_global_setting_can_enable_decoded_views(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), settings={"normalization": {"decoded": True}})
            encoded = base64.b64encode(b"rm -rf / --no-preserve-root").decode()
            self.assertEqual(PolicyAction.BLOCK, self._action(engine, encoded))

    def test_unusable_normalization_block_falls_back_to_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), settings={"normalization": "yes please"})
            self.assertEqual(PolicyAction.BLOCK, self._action(engine, f"rm{ZWSP} -rf /"))

    def test_finding_records_the_view_it_matched_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir))
            with self.assertLogs("src.policy", level="INFO") as captured:
                self._action(engine, f"rm{ZWSP} -rf /")
            self.assertIn("canonical", "".join(captured.output))

    def test_decision_carries_the_findings_that_produced_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir))
            command = f"echo x; rm{ZWSP} -rf /"
            decision = engine.evaluate("shell_exec", {"command": command})
            self.assertEqual(PolicyAction.BLOCK, decision.action)
            self.assertEqual(1, len(decision.findings))
            finding = decision.findings[0]
            self.assertEqual("canonical", finding.view)
            self.assertEqual(r"rm\s+-rf\s+/", finding.matched_pattern)
            self.assertEqual("command", finding.field)
            self.assertEqual("rm -rf /", finding.matched_text)
            self.assertIsNotNone(finding.span)
            start, end = finding.span or (0, 0)
            self.assertEqual(f"rm{ZWSP} -rf /", command[start:end])

    def test_allow_carries_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir))
            self.assertEqual([], engine.evaluate("shell_exec", {"command": "ls -la"}).findings)

    def test_pii_detection_uses_views(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            with policy_path.open("w", encoding="utf-8") as handle:
                yaml.safe_dump(
                    {
                        "rules": [
                            {
                                "name": "block_pii",
                                "tool": "email_send",
                                "action": "block",
                                "message": "pii",
                                "conditions": [
                                    {"type": "pii_detection", "patterns": [r"\b\d{3}-\d{2}-\d{4}\b"]}
                                ],
                            }
                        ],
                        "settings": {},
                    },
                    handle,
                    sort_keys=False,
                )
            engine = PolicyEngine(policy_path=str(policy_path))
            decision = engine.evaluate("email_send", {"body": f"ssn 123-45{ZWSP}-6789"})
            self.assertEqual(PolicyAction.BLOCK, decision.action)


class TestDomainAllowlistIsNeverNormalized(unittest.TestCase):
    """Folding is fail-safe for a denylist and fail-OPEN for an allowlist.

    Folding a Cyrillic-o spelling of an allowlisted domain onto its ASCII spelling
    would make an attacker's confusable domain pass. The correct treatment for an
    allowlist is the inverse, flagging mixed-script hosts, and belongs in a
    follow-up. These tests exist so nobody "fixes" this by reflex.
    """

    def _engine(self, root: Path, *, settings: dict | None = None) -> PolicyEngine:
        policy_path = root / "policy.yaml"
        with policy_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(
                {
                    "rules": [
                        {
                            "name": "external_email",
                            "tool": "email_send",
                            "action": "require_approval",
                            "message": "external",
                            "normalize": {"canonical": True, "decoded": True},
                            "conditions": [
                                {
                                    "type": "domain_allowlist",
                                    "field": "to",
                                    "allowed_domains": ["company.com"],
                                }
                            ],
                        }
                    ],
                    "settings": settings or {},
                },
                handle,
                sort_keys=False,
            )
        return PolicyEngine(policy_path=str(policy_path))

    def test_confusable_domain_is_still_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir))
            spoofed = f"alice@c{CYRILLIC_O}mpany.com"
            self.assertNotEqual("alice@company.com", spoofed)
            decision = engine.evaluate("email_send", {"to": spoofed})
            self.assertEqual(PolicyAction.REQUIRE_APPROVAL, decision.action)

    def test_allowlisted_and_external_hosts_are_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir))
            self.assertEqual(
                PolicyAction.ALLOW, engine.evaluate("email_send", {"to": "alice@company.com"}).action
            )
            self.assertEqual(
                PolicyAction.REQUIRE_APPROVAL,
                engine.evaluate("email_send", {"to": "alice@evil.com"}).action,
            )

    def test_allowlist_condition_carries_no_view_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = self._engine(Path(tmpdir), settings={"normalization": {"decoded": True}})
            rule = engine._rules[0]
            self.assertEqual((False, False), rule.conditions[0].normalize)


if __name__ == "__main__":
    unittest.main()
