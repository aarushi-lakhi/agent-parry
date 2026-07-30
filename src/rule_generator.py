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

_BASE64_PATTERN = r"[A-Za-z0-9+/=]{40,}"

_DE_PATTERNS: list[tuple[str, str, str]] = [
    ("curl", r"curl.*-d", "curl POST exfiltration"),
    ("|", r"\|.*nc\s", "netcat pipe exfiltration"),
    ("|", r"\|.*curl", "pipe-to-curl exfiltration"),
    ("wget", r"wget.*--post-file", "wget POST exfiltration"),
]

_PE_PATTERNS: list[tuple[str, str, str]] = [
    ("chmod 777", r"chmod\s+777", "world-writable permission change"),
    ("rm", r"rm\s+-rf\s+/", "recursive root deletion"),
    ("|", r"curl.*\|\s*bash", "remote script execution"),
    ("chmod +s", r"chmod\s+\+s", "SUID bit escalation"),
    ("chmod", r"chmod\s+777|chmod\s+\+s", "dangerous chmod"),
]

_TEXT_FIELDS: tuple[str, ...] = (
    "body",
    "text",
    "message",
    "content",
    "prompt",
    "input",
    "query",
    "instruction",
)
_PATH_FIELDS: tuple[str, ...] = ("path", "filepath", "filename", "file", "url")
_COMMAND_FIELDS: tuple[str, ...] = ("command", "cmd", "shell", "script", *_PATH_FIELDS)

_MAX_ESCAPED_VALUE = 200


def _patterns_for_value(patterns: list[str], value: str) -> list[str]:
    """Return `patterns`, or an escape of `value` when none of them can match it.

    The keyword tables select a pattern by substring, so they happily pick one
    the argument that produced the finding cannot contain: a `dyn-path-` probe
    carrying `../../../etc/passwd` hits no _PE_PATTERNS keyword and takes the
    `rm\\s+-rf\\s+/` fallback, which emits a plausible-looking rule that can
    never fire. Escaping the observed value only blocks that exact payload, but
    that beats a rule which blocks nothing. Generalising the literal is future
    work.

    PolicyEngine compiles rule patterns with re.IGNORECASE, so the check uses
    the same flag; otherwise a pattern that will fire at runtime reads as dead.
    """
    if not value.strip():
        return patterns
    for pattern in patterns:
        try:
            if re.search(pattern, value, flags=re.IGNORECASE):
                return patterns
        except re.error:
            continue
    return [re.escape(value[:_MAX_ESCAPED_VALUE])]


def _is_benign(result: AttackResult) -> bool:
    """True for payloads that were supposed to be allowed.

    Benign payloads pass through by design, and generate_rules keys off
    passed_through, so without this gate save_scan_outputs emits autogen rules
    built from legitimate traffic and demo phase 3 writes them into the policy
    file. Both the expectation and the category are checked, since a payload set
    can carry one without the other.
    """
    payload = result.payload
    return payload.expected_behavior.strip().lower() == "allow" or payload.category == "benign"


class RuleGenerator:
    """Generates policy rules from scan results."""

    def generate_rules(self, report: ScanReport) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        for result in report.results:
            if not result.passed_through:
                continue
            if _is_benign(result):
                continue
            rule = self._rule_for_result(result)
            if rule is not None:
                rules.append(rule)
        return rules


    def apply_rules(
        self,
        rules: list[dict[str, Any]],
        policy_path: str = "config/default_policy.yaml",
    ) -> None:
        with open(policy_path) as f:
            policy = yaml.safe_load(f) or {}

        existing: list[dict[str, Any]] = policy.get("rules", [])
        existing = [r for r in existing if not r.get("name", "").startswith("autogen_")]

        policy["rules"] = rules + existing

        with open(policy_path, "w") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

        for r in rules:
            desc = r.get("description", "")
            console.print(f"  [green]+[/green] {r['name']}: {desc}")


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


    def _rule_for_result(self, result: AttackResult) -> dict[str, Any] | None:
        payload = result.payload
        category = payload.category

        if category == "prompt_injection":
            return self._rule_prompt_injection(payload.id, payload.tool, payload.arguments)
        if category == "data_exfiltration":
            return self._rule_data_exfiltration(payload.id, payload.tool, payload.arguments)
        if category == "privilege_escalation":
            return self._rule_privilege_escalation(payload.id, payload.tool, payload.arguments)
        if category == "pii_leak":
            return self._rule_pii_leak(payload.id, payload.tool, payload.arguments)
        return None

    @staticmethod
    def _select_field(
        arguments: dict[str, Any],
        candidates: tuple[str, ...],
        default_field: str,
    ) -> tuple[str, str]:
        """Pick the argument a rule condition should inspect, with its value.

        Prefers a known field name, then the longest string argument (an attack
        string is far longer than the filler values the scanner puts in other
        required fields), and falls back to the default name when the payload
        carries no string arguments at all.
        """
        by_lower = {key.lower(): key for key in arguments}
        for candidate in candidates:
            key = by_lower.get(candidate)
            if key is not None and isinstance(arguments[key], str):
                return key, arguments[key]

        strings = [(key, value) for key, value in arguments.items() if isinstance(value, str)]
        if strings:
            return max(strings, key=lambda item: len(item[1]))
        return default_field, ""

    @staticmethod
    def _make_rule(
        attack_id: str,
        tool: str,
        action: str,
        field: str,
        patterns: list[str],
        description: str,
        value: str,
    ) -> dict[str, Any]:
        """Build a pattern_match rule, validating the patterns against `value`.

        `value` is the argument the condition inspects, so every category gets
        the same guarantee: the emitted rule matches the payload it came from.
        """
        return {
            "name": f"autogen_{attack_id}",
            "tool": tool,
            "action": action,
            "message": description,
            "description": description,
            "conditions": [
                {
                    "type": "pattern_match",
                    "field": field,
                    "patterns": _patterns_for_value(patterns, value),
                }
            ],
        }

    @staticmethod
    def _rule_prompt_injection(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        field, body = RuleGenerator._select_field(arguments, _TEXT_FIELDS, "body")

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

        return RuleGenerator._make_rule(
            attack_id, tool, "BLOCK", field, [pattern], desc, body,
        )

    @staticmethod
    def _rule_data_exfiltration(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        field, command = RuleGenerator._select_field(arguments, _COMMAND_FIELDS, "command")

        pattern = r"curl.*-d"
        desc = "blocks data exfiltration via shell"
        for keyword, pat, label in _DE_PATTERNS:
            if keyword in command:
                pattern = pat
                desc = f"blocks {label}"
                break

        return RuleGenerator._make_rule(
            attack_id, tool, "BLOCK", field, [pattern], desc, command,
        )

    @staticmethod
    def _rule_privilege_escalation(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        field, command = RuleGenerator._select_field(arguments, _COMMAND_FIELDS, "command")

        pattern = r"rm\s+-rf\s+/"
        desc = "blocks privilege escalation via shell"
        for keyword, pat, label in _PE_PATTERNS:
            if keyword in command:
                pattern = pat
                desc = f"blocks {label}"
                break

        return RuleGenerator._make_rule(
            attack_id, tool, "BLOCK", field, [pattern], desc, command,
        )

    @staticmethod
    def _rule_pii_leak(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        path_keys = {key.lower() for key in arguments} & set(_PATH_FIELDS)
        if path_keys:
            field, file_path = RuleGenerator._select_field(arguments, _PATH_FIELDS, "path")
            filename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
            pattern = re.escape(filename)
            return RuleGenerator._make_rule(
                attack_id, tool, "BLOCK", field, [pattern],
                f"blocks reads of {filename}", file_path,
            )

        field, body = RuleGenerator._select_field(arguments, _TEXT_FIELDS, "body")
        return RuleGenerator._make_rule(
            attack_id, tool, "BLOCK", field,
            [r"\d{3}-\d{2}-\d{4}", r"4\d{3}[-\s]?\d{4}"],
            "blocks emails containing SSN or credit card numbers", body,
        )
