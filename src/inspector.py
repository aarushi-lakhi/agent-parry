"""Input and output inspectors for prompt injection and PII redaction.

Both inspectors match against normalized views of every string rather than the
raw value, so a zero-width space, a fullwidth spelling, a Cyrillic homoglyph or a
base64 wrapper no longer hides a payload. See :mod:`src.normalize`.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any, ClassVar

from src.models import Finding
from src.normalize import (
    Normalizer,
    TextView,
    detection_normalizer,
    is_opaque_blob,
    iter_base64_runs,
    view_priority,
)

logger = logging.getLogger(__name__)

_OPAQUE_BLOB_SIGNAL = "opaque encoded blob"


class InputInspector:
    """Detect suspicious prompt-injection strings in tool arguments."""

    def __init__(self, normalizer: Normalizer | None = None) -> None:
        """Build an inspector, defaulting to canonical plus decoded views.

        Pass :func:`src.normalize.raw_only_normalizer` to match raw input only.
        """
        self._normalizer = normalizer or detection_normalizer()
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
                re.compile(r"(?:<script|javascript:|onerror=)", re.IGNORECASE),
                "medium",
                "Potential HTML/script injection payload",
            ),
            (
                re.compile(
                    r"(?:/etc/(?:passwd|shadow|sudoers)"
                    r"|\.ssh/id_[a-z0-9]+"
                    r"|\.aws/credentials"
                    r"|/proc/self/environ"
                    r"|\.env\b(?!\w))",
                    re.IGNORECASE,
                ),
                "high",
                "Reference to a credential or sensitive system file",
            ),
        ]

    def inspect(self, tool_name: str, arguments: dict[str, Any]) -> list[Finding]:
        """Scan all nested string values and return deduped findings."""
        findings: list[Finding] = []
        for field_path, value in self._iter_strings(arguments):
            views = self._views(value)
            candidates: list[Finding] = []
            for pattern, severity, description in self._patterns:
                for view in views:
                    match = pattern.search(view.text)
                    if match is None:
                        continue
                    candidates.append(
                        Finding(
                            severity=severity,  # type: ignore[arg-type]
                            description=f"{description} in {tool_name}",
                            field=field_path,
                            matched_pattern=pattern.pattern,
                            view=view.name,
                            matched_text=match.group(0),
                            span=view.map_span(*match.span()),
                        )
                    )
            candidates.extend(self._opaque_blob_findings(tool_name, field_path, value))
            findings.extend(self._dedupe(candidates))
        return findings

    def _views(self, value: str) -> list[TextView]:
        return self._normalizer.views(value)

    def _opaque_blob_findings(self, tool_name: str, field_path: str, value: str) -> list[Finding]:
        """Flag long decode-plausible runs that yield no readable text.

        The secondary base64 signal. It stays medium because an opaque blob is
        only ever suspicious shape, never known-bad content: anything that does
        decode to text is matched by the ordinary patterns in a decoded view at
        their ordinary severity instead.
        """
        findings: list[Finding] = []
        for match in iter_base64_runs(value, min_length=40):
            fragment = match.group(0)
            if not is_opaque_blob(fragment):
                continue
            findings.append(
                Finding(
                    severity="medium",
                    description=f"Suspicious {_OPAQUE_BLOB_SIGNAL} in {tool_name}",
                    field=field_path,
                    matched_pattern=_OPAQUE_BLOB_SIGNAL,
                    matched_text=fragment,
                    span=match.span(),
                )
            )
        return findings

    @staticmethod
    def _dedupe(candidates: list[Finding]) -> list[Finding]:
        """Keep one finding per (field, pattern, severity), best view wins.

        Load-bearing, not cosmetic. Without it a single obfuscated payload that
        matches in the original, the canonical view and a decoded view reports
        three times, tripling ProxyStats counters and every scan report line.
        """
        best: dict[tuple[str | None, str | None, str], Finding] = {}
        for finding in candidates:
            key = (finding.field, finding.matched_pattern, finding.severity)
            current = best.get(key)
            if current is None or view_priority(finding.view) < view_priority(current.view):
                best[key] = finding
        return list(best.values())

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

    _DEFAULT_PATTERNS: ClassVar[dict[str, str]] = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "api_key": r"\b(sk-|pk_|sk_live_|sk_test_)\S{20,}\b",
        "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
        "password_in_url": r"://[^:]+:[^@]+@",
    }
    _REDACTION_LABELS: ClassVar[dict[str, str]] = {
        "ssn": "SSN",
        "credit_card": "CC",
        "api_key": "API_KEY",
        "aws_key": "AWS_KEY",
        "password_in_url": "PASSWORD",
    }

    def __init__(
        self,
        pii_patterns: dict[str, str] | None = None,
        normalizer: Normalizer | None = None,
    ) -> None:
        """Build an inspector, defaulting to canonical plus decoded views.

        Detection runs on every view; redaction happens in tiers so the value
        that reaches the caller is still the original text wherever a match can
        be located precisely. Pass :func:`src.normalize.raw_only_normalizer` to
        redact raw input only.
        """
        self._normalizer = normalizer or detection_normalizer()
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
        return self._redact_string(value, findings, path=path, tool_name=tool_name)

    def _redact_string(
        self,
        value: str,
        findings: list[Finding],
        *,
        path: str,
        tool_name: str,
    ) -> str:
        """Redact every PII match found in any view, splicing into the original.

        Redaction tiers, in order of how precisely a match can be located:

        1. matched in the original: the span is exact.
        2. matched in the canonical view with a usable offset map: splice at the
           mapped span, which covers whatever the view stripped in between.
        3. matched in a decoded view: replace the whole encoded fragment, since
           an offset inside decoded plaintext means nothing inside its base64.
        4. no mappable span at all: replace the entire value. Deliberately
           fail-safe, because leaking PII is worse than over-redacting.

        Splices are applied highest offset first so earlier spans stay valid.
        """
        views = self._views(value)
        accepted: list[tuple[int, int, str]] = []
        whole_value_replacement: str | None = None

        for pii_type, pattern in self._compiled_patterns:
            label = self._REDACTION_LABELS.get(pii_type, pii_type.upper())
            replacement = f"[REDACTED-{label}]"
            for view in views:
                for match in pattern.finditer(view.text):
                    span = view.map_span(*match.span())
                    if span is None:
                        logger.warning(
                            "PII matched in %s view with no mappable span, replacing whole value "
                            "tool=%s field=%s type=%s",
                            view.name,
                            tool_name,
                            path,
                            pii_type,
                        )
                        whole_value_replacement = replacement
                        findings.append(
                            self._finding(pii_type, pattern, tool_name, path, view, match.group(0), None)
                        )
                        continue
                    if any(span[0] < end and start < span[1] for start, end, _ in accepted):
                        continue
                    accepted.append((span[0], span[1], replacement))
                    findings.append(
                        self._finding(pii_type, pattern, tool_name, path, view, match.group(0), span)
                    )

        if whole_value_replacement is not None:
            return whole_value_replacement
        if not accepted:
            return value

        updated = value
        for start, end, replacement in sorted(accepted, key=lambda item: item[0], reverse=True):
            updated = updated[:start] + replacement + updated[end:]
        return updated

    def _views(self, value: str) -> list[TextView]:
        return self._normalizer.views(value)

    @staticmethod
    def _finding(
        pii_type: str,
        pattern: re.Pattern[str],
        tool_name: str,
        path: str,
        view: TextView,
        matched_text: str,
        span: tuple[int, int] | None,
    ) -> Finding:
        return Finding(
            severity="medium",
            description=f"PII detected in {tool_name}: {pii_type}",
            field=path,
            matched_pattern=pattern.pattern,
            view=view.name,
            matched_text=matched_text,
            span=span,
        )
