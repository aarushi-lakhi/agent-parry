"""Rule generator that produces policy rules from scan results."""

from __future__ import annotations

import re
from typing import Any

import yaml
from rich.console import Console
from rich.table import Table

from src.models import AttackResult, ScanReport

console = Console()

_PI_PATTERNS: list[tuple[str, str, str]] = [
    ("ignore.*instructions", "ignore.*instructions", "instruction override"),
    ("SYSTEM:", r"^SYSTEM:|\[SYSTEM\]", "fake SYSTEM prompt"),
    ("disregard", r"disregard.*rules|override.*safety", "safety override"),
]

_BASE64_PATTERN = r"[A-Za-z0-9+/=]{100,}"

_DE_PATTERNS: list[tuple[str, str, str]] = [
    ("curl", r"curl.*-d", "curl POST exfiltration"),
    ("|", r"\|.*nc\s", "netcat pipe exfiltration"),
    ("|", r"\|.*curl", "pipe-to-curl exfiltration"),
    ("wget", r"wget.*--post-file", "wget POST exfiltration"),
]

_PE_PATTERNS: list[tuple[str, str, str]] = [
    ("chmod", r"chmod\s+777", "world-writable permission change"),
    ("rm", r"rm\s+-rf\s+/", "recursive root deletion"),
    ("|", r"curl.*\|\s*bash", "remote script execution"),
    ("chmod", r"chmod\s+\+s", "SUID bit escalation"),
]


class RuleGenerator:
    """Generates policy rules from scan results."""

    def generate_rules(self, report: ScanReport) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        for result in report.results:
            if not result.passed_through:
                continue
            rule = self._rule_for_result(result)
            if rule is not None:
                rules.append(rule)
        return rules

    # ------------------------------------------------------------------
    # Policy YAML management
    # ------------------------------------------------------------------

    def apply_rules(
        self,
        rules: list[dict[str, Any]],
        policy_path: str = "config/default_policy.yaml",
    ) -> None:
        with open(policy_path) as f:
            policy = yaml.safe_load(f) or {}

        existing: list[dict[str, Any]] = policy.get("rules", [])
        existing = [r for r in existing if not r.get("name", "").startswith("autogen_")]

        existing.extend(rules)
        policy["rules"] = existing

        with open(policy_path, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

        for r in rules:
            desc = r.get("description", "")
            console.print(f"  [green]+[/green] {r['name']}: {desc}")

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def print_rules(self, rules: list[dict[str, Any]]) -> None:
        table = Table(title="Generated Rules", show_lines=True)
        table.add_column("Rule Name")
        table.add_column("Tool")
        table.add_column("Action", justify="center")
        table.add_column("What it blocks")

        for r in rules:
            table.add_row(
                r.get("name", ""),
                r.get("tool", ""),
                r.get("action", ""),
                r.get("description", ""),
            )

        console.print()
        console.print(table)
        console.print()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rule_for_result(self, result: AttackResult) -> dict[str, Any] | None:
        payload = result.payload
        category = payload.category

        if category == "prompt_injection":
            return self._rule_prompt_injection(payload.id, payload.arguments)
        if category == "data_exfiltration":
            return self._rule_data_exfiltration(payload.id, payload.arguments)
        if category == "privilege_escalation":
            return self._rule_privilege_escalation(payload.id, payload.arguments)
        if category == "pii_leak":
            return self._rule_pii_leak(payload.id, payload.tool, payload.arguments)
        return None

    @staticmethod
    def _rule_prompt_injection(
        attack_id: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        body: str = arguments.get("body", "")

        if re.search(_BASE64_PATTERN, body):
            pattern = _BASE64_PATTERN
            desc = "blocks base64-encoded prompt injection in email body"
        else:
            pattern = None
            desc = "blocks prompt injection in email body"
            for keyword, pat, label in _PI_PATTERNS:
                if keyword.lower() in body.lower():
                    pattern = pat
                    desc = f"blocks {label} in email body"
                    break
            if pattern is None:
                first_words = " ".join(body.split()[:4])
                pattern = re.escape(first_words)
                desc = "blocks prompt injection in email body"

        return {
            "name": f"autogen_{attack_id}",
            "tool": "email_send",
            "action": "block",
            "match_field": "body",
            "pattern": pattern,
            "description": desc,
        }

    @staticmethod
    def _rule_data_exfiltration(
        attack_id: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        command: str = arguments.get("command", "")

        pattern = r"curl.*-d"
        desc = "blocks data exfiltration via shell"
        for keyword, pat, label in _DE_PATTERNS:
            if keyword in command:
                pattern = pat
                desc = f"blocks {label}"
                break

        return {
            "name": f"autogen_{attack_id}",
            "tool": "shell_exec",
            "action": "block",
            "match_field": "command",
            "pattern": pattern,
            "description": desc,
        }

    @staticmethod
    def _rule_privilege_escalation(
        attack_id: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        command: str = arguments.get("command", "")

        pattern = r"rm\s+-rf\s+/"
        desc = "blocks privilege escalation via shell"
        for keyword, pat, label in _PE_PATTERNS:
            if keyword in command:
                pattern = pat
                desc = f"blocks {label}"
                break

        return {
            "name": f"autogen_{attack_id}",
            "tool": "shell_exec",
            "action": "block",
            "match_field": "command",
            "pattern": pattern,
            "description": desc,
        }

    @staticmethod
    def _rule_pii_leak(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if tool == "file_read":
            file_path: str = arguments.get("path", "")
            filename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
            pattern = re.escape(filename)
            return {
                "name": f"autogen_{attack_id}",
                "tool": "file_read",
                "action": "redact",
                "match_field": "path",
                "pattern": pattern,
                "description": f"redacts output when reading {filename}",
            }

        return {
            "name": f"autogen_{attack_id}",
            "tool": "email_send",
            "action": "block",
            "match_field": "body",
            "pattern": r"\d{3}-\d{2}-\d{4}|4\d{3}[-\s]?\d{4}",
            "description": "blocks emails containing SSN or credit card numbers",
        }
