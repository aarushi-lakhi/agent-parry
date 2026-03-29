"""Policy engine for evaluating requests against security rules."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any

import yaml

from src.models import Finding, PolicyAction, PolicyDecision

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Condition:
    """Parsed and precompiled rule condition."""

    type: str
    field: str | None = None
    patterns: list[str] = dc_field(default_factory=list)
    allowed_domains: set[str] = dc_field(default_factory=set)
    compiled_patterns: list[re.Pattern[str]] = dc_field(default_factory=list)


@dataclass(slots=True)
class Rule:
    """Parsed policy rule used at runtime."""

    name: str
    tool: str
    action: PolicyAction
    message: str
    conditions: list[Condition] = dc_field(default_factory=list)


class PolicyEngine:
    """Rule engine that applies first-match-wins policy decisions."""

    def __init__(self, policy_path: str = "config/default_policy.yaml") -> None:
        self.policy_path = Path(policy_path)
        self._raw_policy: dict[str, Any] = {"rules": [], "settings": {}}
        self._raw_rules: list[dict[str, Any]] = []
        self._rules: list[Rule] = []
        self.reload()

    def evaluate(self, tool_name: str, arguments: dict[str, Any]) -> PolicyDecision:
        """Evaluate one tool call against loaded rules in-memory."""
        for rule in self._rules:
            if not self._tool_matches(rule.tool, tool_name):
                continue
            findings: list[Finding] = []
            if self._rule_matches(rule, arguments, findings):
                self._log_rule_match(rule=rule, tool_name=tool_name, findings=findings)
                return PolicyDecision(action=rule.action, rule_name=rule.name, message=rule.message)
        return PolicyDecision(action=PolicyAction.ALLOW)

    def add_rule(self, rule: dict[str, Any]) -> None:
        """Append a rule and persist policy YAML."""
        self._raw_rules.append(rule)
        self._raw_policy["rules"] = self._raw_rules
        self._rebuild_compiled_rules()
        self._save()

    def remove_generated_rules(self) -> None:
        """Remove all generated rules prefixed with autogen_ and persist."""
        self._raw_rules = [
            rule
            for rule in self._raw_rules
            if not str(rule.get("name", "")).startswith("autogen_")
        ]
        self._raw_policy["rules"] = self._raw_rules
        self._rebuild_compiled_rules()
        self._save()

    def reload(self) -> None:
        """Reload policy YAML and recompile runtime rule cache."""
        loaded = self._load_policy()
        self._raw_policy = loaded
        self._raw_rules = list(loaded.get("rules") or [])
        self._rebuild_compiled_rules()

    def get_rules(self) -> list[dict[str, Any]]:
        """Return current raw rule definitions."""
        return list(self._raw_rules)

    def _load_policy(self) -> dict[str, Any]:
        if not self.policy_path.exists():
            logger.warning("Policy file does not exist, using empty policy path=%s", self.policy_path)
            return {"rules": [], "settings": {}}

        try:
            with self.policy_path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or {}
        except Exception:
            logger.exception("Failed to load policy file path=%s", self.policy_path)
            return {"rules": [], "settings": {}}

        if not isinstance(loaded, dict):
            logger.warning("Policy root is not a mapping, using empty policy path=%s", self.policy_path)
            return {"rules": [], "settings": {}}

        loaded.setdefault("rules", [])
        loaded.setdefault("settings", {})
        return loaded

    def _save(self) -> None:
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        with self.policy_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(self._raw_policy, handle, sort_keys=False)

    def _rebuild_compiled_rules(self) -> None:
        compiled_rules: list[Rule] = []
        for index, raw_rule in enumerate(self._raw_rules):
            parsed = self._parse_rule(raw_rule, index)
            if parsed is not None:
                compiled_rules.append(parsed)
        self._rules = compiled_rules
        logger.info("Loaded policy rules compiled=%s raw=%s", len(self._rules), len(self._raw_rules))

    def _parse_rule(self, raw_rule: dict[str, Any], index: int) -> Rule | None:
        if not isinstance(raw_rule, dict):
            logger.warning("Skipping non-dict rule index=%s", index)
            return None

        name = str(raw_rule.get("name") or f"rule_{index}")
        tool = str(raw_rule.get("tool") or "*")
        message = str(raw_rule.get("message") or "")
        action = self._parse_action(raw_rule.get("action"))
        if action is None:
            logger.warning("Skipping rule with invalid action name=%s action=%s", name, raw_rule.get("action"))
            return None

        raw_conditions = raw_rule.get("conditions") or [{"type": "always"}]
        if not isinstance(raw_conditions, list):
            logger.warning("Skipping rule with invalid conditions name=%s", name)
            return None

        conditions: list[Condition] = []
        for cond_index, raw_condition in enumerate(raw_conditions):
            parsed_condition = self._parse_condition(raw_condition, name, cond_index)
            if parsed_condition is None:
                logger.warning("Skipping malformed rule name=%s", name)
                return None
            conditions.append(parsed_condition)

        return Rule(name=name, tool=tool, action=action, message=message, conditions=conditions)

    def _parse_action(self, raw_action: Any) -> PolicyAction | None:
        if isinstance(raw_action, PolicyAction):
            return raw_action
        if not isinstance(raw_action, str):
            return None
        normalized = raw_action.strip().upper()
        mapping = {
            "ALLOW": PolicyAction.ALLOW,
            "BLOCK": PolicyAction.BLOCK,
            "REQUIRE_APPROVAL": PolicyAction.REQUIRE_APPROVAL,
            "REDACT_OUTPUT": PolicyAction.REDACT_OUTPUT,
        }
        return mapping.get(normalized)

    def _parse_condition(
        self,
        raw_condition: Any,
        rule_name: str,
        cond_index: int,
    ) -> Condition | None:
        if not isinstance(raw_condition, dict):
            logger.warning("Condition is not a dict rule=%s condition=%s", rule_name, cond_index)
            return None
        cond_type = str(raw_condition.get("type") or "").strip()
        if cond_type == "":
            logger.warning("Condition missing type rule=%s condition=%s", rule_name, cond_index)
            return None

        if cond_type == "always":
            return Condition(type=cond_type)

        if cond_type == "pattern_match":
            field_name = raw_condition.get("field")
            raw_patterns = raw_condition.get("patterns")
            if not isinstance(field_name, str) or not isinstance(raw_patterns, list):
                return None
            compiled = self._compile_patterns(raw_patterns, rule_name, cond_index)
            if compiled is None:
                return None
            return Condition(
                type=cond_type,
                field=field_name,
                patterns=[str(pattern) for pattern in raw_patterns],
                compiled_patterns=compiled,
            )

        if cond_type == "domain_allowlist":
            field_name = raw_condition.get("field")
            raw_domains = raw_condition.get("allowed_domains")
            if not isinstance(field_name, str) or not isinstance(raw_domains, list):
                return None
            normalized_domains = {
                str(domain).strip().lower()
                for domain in raw_domains
                if str(domain).strip()
            }
            return Condition(type=cond_type, field=field_name, allowed_domains=normalized_domains)

        if cond_type == "pii_detection":
            raw_patterns = raw_condition.get("patterns")
            if not isinstance(raw_patterns, list):
                return None
            compiled = self._compile_patterns(raw_patterns, rule_name, cond_index)
            if compiled is None:
                return None
            return Condition(
                type=cond_type,
                patterns=[str(pattern) for pattern in raw_patterns],
                compiled_patterns=compiled,
            )

        logger.warning(
            "Unknown condition type, skipping rule rule=%s condition=%s type=%s",
            rule_name,
            cond_index,
            cond_type,
        )
        return None

    def _compile_patterns(
        self,
        raw_patterns: list[Any],
        rule_name: str,
        cond_index: int,
    ) -> list[re.Pattern[str]] | None:
        compiled: list[re.Pattern[str]] = []
        for pattern_index, pattern in enumerate(raw_patterns):
            try:
                compiled.append(re.compile(str(pattern), flags=re.IGNORECASE))
            except re.error:
                logger.warning(
                    "Invalid regex pattern, skipping rule rule=%s condition=%s pattern=%s value=%s",
                    rule_name,
                    cond_index,
                    pattern_index,
                    pattern,
                )
                return None
        return compiled

    @staticmethod
    def _tool_matches(rule_tool: str, requested_tool: str) -> bool:
        return rule_tool == "*" or rule_tool == requested_tool

    def _rule_matches(
        self,
        rule: Rule,
        arguments: dict[str, Any],
        findings: list[Finding],
    ) -> bool:
        for condition in rule.conditions:
            if not self._condition_matches(condition, arguments, findings):
                return False
        return True

    def _condition_matches(
        self,
        condition: Condition,
        arguments: dict[str, Any],
        findings: list[Finding],
    ) -> bool:
        if condition.type == "always":
            findings.append(Finding(severity="low", description="Always condition matched"))
            return True

        if condition.type == "pattern_match":
            value = arguments.get(condition.field or "")
            candidate = "" if value is None else str(value)
            for idx, compiled in enumerate(condition.compiled_patterns):
                if compiled.search(candidate):
                    findings.append(
                        Finding(
                            severity="high",
                            description=f"Pattern matched in {condition.field}",
                            field=condition.field,
                            matched_pattern=condition.patterns[idx] if idx < len(condition.patterns) else None,
                        )
                    )
                    return True
            return False

        if condition.type == "domain_allowlist":
            value = arguments.get(condition.field or "")
            domain = self._extract_domain(value)
            # Empty allowlist intentionally flags everything.
            if not condition.allowed_domains:
                findings.append(
                    Finding(
                        severity="medium",
                        description="Domain allowlist is empty; flagging all values",
                        field=condition.field,
                    )
                )
                return True
            if domain is None or domain not in condition.allowed_domains:
                findings.append(
                    Finding(
                        severity="medium",
                        description=f"Domain not allowlisted: {domain or 'unknown'}",
                        field=condition.field,
                    )
                )
                return True
            return False

        if condition.type == "pii_detection":
            flattened_values = self._flatten_values(arguments)
            for candidate in flattened_values:
                for idx, compiled in enumerate(condition.compiled_patterns):
                    if compiled.search(candidate):
                        findings.append(
                            Finding(
                                severity="high",
                                description="PII pattern matched in arguments",
                                matched_pattern=condition.patterns[idx] if idx < len(condition.patterns) else None,
                            )
                        )
                        return True
            return False

        logger.warning("Unhandled condition type during evaluate type=%s", condition.type)
        return False

    @staticmethod
    def _extract_domain(value: Any) -> str | None:
        if value is None:
            return None
        address = str(value).strip()
        if "@" not in address:
            return None
        _, domain = address.rsplit("@", 1)
        normalized = domain.strip().lower()
        return normalized or None

    @classmethod
    def _flatten_values(cls, value: Any) -> list[str]:
        if isinstance(value, dict):
            flattened: list[str] = []
            for nested in value.values():
                flattened.extend(cls._flatten_values(nested))
            return flattened
        if isinstance(value, list):
            flattened = []
            for nested in value:
                flattened.extend(cls._flatten_values(nested))
            return flattened
        return ["" if value is None else str(value)]

    def _log_rule_match(self, rule: Rule, tool_name: str, findings: list[Finding]) -> None:
        finding_summary = [
            {
                "severity": finding.severity,
                "field": finding.field,
                "pattern": finding.matched_pattern,
                "description": finding.description,
            }
            for finding in findings
        ]
        logger.info(
            "Policy rule matched tool=%s rule=%s action=%s message=%s findings=%s",
            tool_name,
            rule.name,
            rule.action.value,
            rule.message,
            finding_summary,
        )
