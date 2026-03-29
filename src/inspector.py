"""Input and output inspectors for prompt injection and PII redaction."""

from __future__ import annotations

import copy
import re
from typing import Any

from src.models import Finding


class InputInspector:
    """Detect suspicious prompt-injection strings in tool arguments."""

    def __init__(self) -> None:
        self._patterns: list[tuple[re.Pattern[str], str, str]] = [
            (
                re.compile(r"ignore\s+(?:all\s|any\s)?(?:previous\s|prior\s)?instructions", re.IGNORECASE),
                "critical",
                "Attempt to ignore instructions",
            ),
            (
                re.compile(r"\b(?:you are now|act as|pretend to be)\b", re.IGNORECASE),
                "high",
                "Role manipulation attempt",
            ),
            (
                re.compile(r"^\s*(?:SYSTEM:|\[SYSTEM\]|<<SYS>>)", re.IGNORECASE),
                "critical",
                "System-level instruction injection at value start",
            ),
            (
                re.compile(r"\b(?:do not follow|disregard|override\s+(?:your|all|the))\b", re.IGNORECASE),
                "high",
                "Instruction override/disregard attempt",
            ),
            (
                re.compile(r"\bforget\s+(?:your|all|everything|previous)\b", re.IGNORECASE),
                "high",
                "Attempt to force instruction forgetting",
            ),
            (
                re.compile(r"[A-Za-z0-9+/=]{100,}"),
                "medium",
                "Suspicious long base64-like payload",
            ),
            (
                re.compile(r"(?:<script|javascript:|onerror=)", re.IGNORECASE),
                "medium",
                "Potential HTML/script injection payload",
            ),
        ]

    def inspect(self, tool_name: str, arguments: dict[str, Any]) -> list[Finding]:
        """Scan all nested string values and return any findings."""
        findings: list[Finding] = []
        for field_path, value in self._iter_strings(arguments):
            for pattern, severity, description in self._patterns:
                if pattern.search(value):
                    findings.append(
                        Finding(
                            severity=severity,  # type: ignore[arg-type]
                            description=f"{description} in {tool_name}",
                            field=field_path,
                            matched_pattern=pattern.pattern,
                        )
                    )
        return findings

    @classmethod
    def _iter_strings(cls, value: Any, path: str = "arguments") -> list[tuple[str, str]]:
        if isinstance(value, dict):
            items: list[tuple[str, str]] = []
            for key, nested in value.items():
                next_path = f"{path}.{key}"
                items.extend(cls._iter_strings(nested, next_path))
            return items
        if isinstance(value, list):
            items = []
            for idx, nested in enumerate(value):
                next_path = f"{path}[{idx}]"
                items.extend(cls._iter_strings(nested, next_path))
            return items
        if isinstance(value, str):
            return [(path, value)]
        return []


class OutputInspector:
    """Detect and redact PII from nested JSON-like tool response payloads."""

    _DEFAULT_PATTERNS: dict[str, str] = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "api_key": r"\b(sk-|pk_|sk_live_|sk_test_)\S{20,}\b",
        "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
        "password_in_url": r"://[^:]+:[^@]+@",
    }
    _REDACTION_LABELS: dict[str, str] = {
        "ssn": "SSN",
        "credit_card": "CC",
        "api_key": "API_KEY",
        "aws_key": "AWS_KEY",
        "password_in_url": "PASSWORD",
    }

    def __init__(self, pii_patterns: dict[str, str] | None = None) -> None:
        source = pii_patterns or self._DEFAULT_PATTERNS
        self._compiled_patterns: list[tuple[str, re.Pattern[str]]] = [
            (name, re.compile(pattern, re.IGNORECASE))
            for name, pattern in source.items()
        ]

    def inspect(self, tool_name: str, response_data: dict[str, Any]) -> tuple[dict[str, Any], list[Finding]]:
        """Return sanitized payload and findings discovered while scanning it."""
        findings: list[Finding] = []
        sanitized = copy.deepcopy(response_data)
        sanitized = self._sanitize_value(sanitized, findings, path="result", tool_name=tool_name)
        if isinstance(sanitized, dict):
            return sanitized, findings
        return {"result": sanitized}, findings

    def _sanitize_value(
        self,
        value: Any,
        findings: list[Finding],
        *,
        path: str,
        tool_name: str,
    ) -> Any:
        if isinstance(value, dict):
            return {
                key: self._sanitize_value(nested, findings, path=f"{path}.{key}", tool_name=tool_name)
                for key, nested in value.items()
            }
        if isinstance(value, list):
            return [
                self._sanitize_value(nested, findings, path=f"{path}[{idx}]", tool_name=tool_name)
                for idx, nested in enumerate(value)
            ]
        if not isinstance(value, str):
            return value

        updated = value
        for pii_type, pattern in self._compiled_patterns:
            matches = list(pattern.finditer(updated))
            if not matches:
                continue

            redaction_label = self._REDACTION_LABELS.get(pii_type, pii_type.upper())
            replacement = f"[REDACTED-{redaction_label}]"
            updated = pattern.sub(replacement, updated)
            for _ in matches:
                findings.append(
                    Finding(
                        severity="medium",
                        description=f"PII detected in {tool_name}: {pii_type}",
                        field=path,
                        matched_pattern=pattern.pattern,
                    )
                )
        return updated
"""Request inspector for detecting malicious patterns."""
