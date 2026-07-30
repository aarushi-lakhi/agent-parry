"""Policy engine for evaluating requests against security rules."""

from __future__ import annotations

import copy
import ipaddress
import logging
import re
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import ValidationError

from src.models import Finding, PolicyAction, PolicyDecision
from src.normalize import (
    VIEW_ORIGINAL,
    Normalizer,
    NormalizerSettings,
    TextView,
    find_invisible,
)

logger = logging.getLogger(__name__)

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_TOKEN_SPLIT_RE = re.compile(r"[,;\s]+")

_NORMALIZABLE_TYPES = frozenset({"pattern_match", "pii_detection"})

ViewFlags = tuple[bool, bool]
"""Resolved (canonical, decoded) view switches for one condition."""

_NO_VIEWS: ViewFlags = (False, False)


@dataclass(slots=True)
class Condition:
    """Parsed and precompiled rule condition."""

    type: str
    field: str | None = None
    patterns: list[str] = dc_field(default_factory=list)
    allowed_domains: set[str] = dc_field(default_factory=set)
    include_subdomains: bool = False
    subdomain_domains: set[str] = dc_field(default_factory=set)
    compiled_patterns: list[re.Pattern[str]] = dc_field(default_factory=list)
    normalize: ViewFlags = _NO_VIEWS


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

    def __init__(
        self,
        policy_path: str = "config/default_policy.yaml",
        policy: dict[str, Any] | None = None,
    ) -> None:
        self.policy_path = Path(policy_path)
        self._raw_policy: dict[str, Any] = {"rules": [], "settings": {}}
        self._raw_rules: list[dict[str, Any]] = []
        self._rules: list[Rule] = []
        self._default_views: ViewFlags = (True, False)
        self._base_settings = NormalizerSettings()
        self._normalizers: dict[ViewFlags, Normalizer] = {}
        if policy is None:
            self.reload()
        else:
            self.load_mapping(policy)

    def evaluate(self, tool_name: str, arguments: dict[str, Any]) -> PolicyDecision:
        """Evaluate one tool call against loaded rules in-memory."""
        view_cache: dict[tuple[bool, bool, str], list[TextView]] = {}
        for rule in self._rules:
            if not self._tool_matches(rule.tool, tool_name):
                continue
            findings: list[Finding] = []
            if self._rule_matches(rule, arguments, findings, view_cache):
                self._log_rule_match(rule=rule, tool_name=tool_name, findings=findings)
                return PolicyDecision(
                    action=rule.action,
                    rule_name=rule.name,
                    message=rule.message,
                    findings=findings,
                )
        return PolicyDecision(action=PolicyAction.ALLOW)

    def _views(
        self,
        condition: Condition,
        text: str,
        view_cache: dict[tuple[bool, bool, str], list[TextView]],
    ) -> list[TextView]:
        if condition.normalize == _NO_VIEWS:
            return [TextView(name=VIEW_ORIGINAL, text=text, original_length=len(text))]
        key = (condition.normalize[0], condition.normalize[1], text)
        cached = view_cache.get(key)
        if cached is None:
            cached = self._normalizer_for(condition.normalize).views(text)
            view_cache[key] = cached
        return cached

    def _normalizer_for(self, flags: ViewFlags) -> Normalizer:
        normalizer = self._normalizers.get(flags)
        if normalizer is None:
            normalizer = Normalizer(
                self._base_settings.model_copy(update={"canonical": flags[0], "decoded": flags[1]})
            )
            self._normalizers[flags] = normalizer
        return normalizer

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
        self.load_mapping(self._load_policy())

    def load_mapping(self, policy: dict[str, Any]) -> None:
        """Adopt an already-parsed policy mapping without reading the file.

        Lets a caller that must validate the YAML itself, such as a hot reload
        that refuses to install an empty policy, compile exactly the document it
        checked rather than re-reading a file that may have changed since.
        """
        self._raw_policy = policy
        self._raw_rules = list(policy.get("rules") or [])
        self._load_normalization_settings(policy.get("settings") or {})
        self._rebuild_compiled_rules()

    def _load_normalization_settings(self, settings: Any) -> None:
        """Read the ``settings.normalization`` block.

        Canonical views default ON: they only ever make a rule match text a human
        reads as identical to what they typed, and the surprise direction is more
        blocking, which is the fail-safe direction.

        Decoded views default OFF. Matching an ``rm -rf /`` rule against the
        plaintext inside an opaque base64 string is a semantic leap the rule
        author did not ask for, and BLOCK cannot be recovered from over stdio.
        Turn them on per rule once you have decided that is what you want.
        """
        self._normalizers.clear()
        raw = settings.get("normalization") if isinstance(settings, dict) else None
        if not isinstance(raw, dict):
            self._base_settings = NormalizerSettings()
            self._default_views = (True, False)
            return

        overrides = {key: value for key, value in raw.items() if key in NormalizerSettings.model_fields}
        try:
            self._base_settings = NormalizerSettings(**overrides)
        except ValidationError:
            logger.exception("Invalid settings.normalization block, using defaults")
            self._base_settings = NormalizerSettings()

        enabled = raw.get("enabled", True)
        if not enabled:
            self._default_views = _NO_VIEWS
            return
        self._default_views = (self._base_settings.canonical, self._base_settings.decoded)

    def _resolve_normalize(self, raw: Any, rule_name: str, inherited: ViewFlags) -> ViewFlags:
        """Resolve a ``normalize:`` override against the value it inherits."""
        if raw is None:
            return inherited
        if isinstance(raw, bool):
            return (True, inherited[1]) if raw else _NO_VIEWS
        if isinstance(raw, dict):
            canonical = raw.get("canonical", inherited[0])
            decoded = raw.get("decoded", inherited[1])
            return (bool(canonical), bool(decoded))
        logger.warning("Ignoring unusable normalize override rule=%s value=%r", rule_name, raw)
        return inherited

    def get_rules(self) -> list[dict[str, Any]]:
        """Return current raw rule definitions."""
        return list(self._raw_rules)

    @property
    def active_rule_count(self) -> int:
        """Number of rules that compiled, so the number that can actually match.

        Lower than ``len(get_rules())`` whenever a rule was malformed and skipped,
        which is the count a caller deciding whether a policy still enforces
        anything has to look at.
        """
        return len(self._rules)

    def get_settings(self) -> dict[str, Any]:
        """Return the raw ``settings`` block, for consumers other than the rules.

        A copy, so a caller cannot mutate loaded policy and have ``_save`` persist
        it on the next ``add_rule``.
        """
        settings = self._raw_policy.get("settings")
        return copy.deepcopy(settings) if isinstance(settings, dict) else {}

    @property
    def compiled_rules(self) -> list[Rule]:
        """Parsed rules in first-match-wins order, each condition carrying its views.

        Rules that failed to parse are absent, the same as at evaluation time, so
        a caller reading this sees what enforcement sees rather than what the file
        claims.
        """
        return list(self._rules)

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

        rule_views = self._resolve_normalize(raw_rule.get("normalize"), name, self._default_views)

        conditions: list[Condition] = []
        for cond_index, raw_condition in enumerate(raw_conditions):
            parsed_condition = self._parse_condition(raw_condition, name, cond_index, rule_views)
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
        rule_views: ViewFlags,
    ) -> Condition | None:
        if not isinstance(raw_condition, dict):
            logger.warning("Condition is not a dict rule=%s condition=%s", rule_name, cond_index)
            return None
        cond_type = str(raw_condition.get("type") or "").strip()
        if cond_type == "":
            logger.warning("Condition missing type rule=%s condition=%s", rule_name, cond_index)
            return None

        views = self._resolve_normalize(raw_condition.get("normalize"), rule_name, rule_views)
        if cond_type not in _NORMALIZABLE_TYPES:
            views = _NO_VIEWS

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
                normalize=views,
            )

        if cond_type == "domain_allowlist":
            # Deliberately never normalized, see _condition_matches.
            field_name = raw_condition.get("field")
            raw_domains = raw_condition.get("allowed_domains")
            if not isinstance(field_name, str) or not isinstance(raw_domains, list):
                return None
            normalized_domains: set[str] = set()
            for domain in raw_domains:
                normalized = self._normalize_host(str(domain))
                if normalized is None:
                    logger.warning(
                        "Dropping unusable allowlist domain rule=%s condition=%s domain=%s",
                        rule_name,
                        cond_index,
                        domain,
                    )
                    continue
                normalized_domains.add(normalized)
            include_subdomains = bool(raw_condition.get("include_subdomains", False))
            subdomain_domains: set[str] = set()
            if include_subdomains:
                for allowed in sorted(normalized_domains):
                    if not self._suffix_eligible(allowed):
                        logger.warning(
                            "Ignoring include_subdomains for this entry rule=%s condition=%s domain=%s",
                            rule_name,
                            cond_index,
                            allowed,
                        )
                        continue
                    subdomain_domains.add(allowed)
            return Condition(
                type=cond_type,
                field=field_name,
                allowed_domains=normalized_domains,
                include_subdomains=include_subdomains,
                subdomain_domains=subdomain_domains,
            )

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
                normalize=views,
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
        view_cache: dict[tuple[bool, bool, str], list[TextView]],
    ) -> bool:
        return all(
            self._condition_matches(condition, arguments, findings, view_cache)
            for condition in rule.conditions
        )

    def _condition_matches(
        self,
        condition: Condition,
        arguments: dict[str, Any],
        findings: list[Finding],
        view_cache: dict[tuple[bool, bool, str], list[TextView]],
    ) -> bool:
        if condition.type == "always":
            findings.append(Finding(severity="low", description="Always condition matched"))
            return True

        if condition.type == "pattern_match":
            value = arguments.get(condition.field or "")
            candidate = "" if value is None else str(value)
            for idx, compiled in enumerate(condition.compiled_patterns):
                for view in self._views(condition, candidate, view_cache):
                    match = compiled.search(view.text)
                    if match is None:
                        continue
                    findings.append(
                        Finding(
                            severity="high",
                            description=f"Pattern matched in {condition.field}",
                            field=condition.field,
                            matched_pattern=condition.patterns[idx] if idx < len(condition.patterns) else None,
                            view=view.name,
                            matched_text=match.group(0),
                            span=view.map_span(*match.span()),
                        )
                    )
                    return True
            return False

        if condition.type == "domain_allowlist":
            value = arguments.get(condition.field or "")
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
            for host in self._extract_hosts(value) or [None]:
                if host is None or not self._host_allowlisted(host, condition):
                    findings.append(
                        Finding(
                            severity="medium",
                            description=f"Domain not allowlisted: {host or 'unknown'}",
                            field=condition.field,
                        )
                    )
                    return True
            return False

        if condition.type == "pii_detection":
            flattened_values = self._flatten_values(arguments)
            for candidate in flattened_values:
                for idx, compiled in enumerate(condition.compiled_patterns):
                    for view in self._views(condition, candidate, view_cache):
                        match = compiled.search(view.text)
                        if match is None:
                            continue
                        findings.append(
                            Finding(
                                severity="high",
                                description="PII pattern matched in arguments",
                                matched_pattern=condition.patterns[idx] if idx < len(condition.patterns) else None,
                                view=view.name,
                                matched_text=match.group(0),
                                span=view.map_span(*match.span()),
                            )
                        )
                        return True
            return False

        logger.warning("Unhandled condition type during evaluate type=%s", condition.type)
        return False

    @staticmethod
    def _host_allowlisted(host: str, condition: Condition) -> bool:
        """Match a host against the allowlist, exact by default.

        ``include_subdomains: true`` opts a condition into suffix matching. It stays
        opt-in because suffix matching by default would silently stop flagging hosts
        like ``mail.company.com`` that an exact allowlist flags today.

        There is no public-suffix list here, so allowlisting something like ``co.uk``
        with ``include_subdomains`` stays the operator's problem.
        """
        if host in condition.allowed_domains:
            return True
        return any(host.endswith(f".{allowed}") for allowed in condition.subdomain_domains)

    @staticmethod
    def _suffix_eligible(allowed: str) -> bool:
        """Reject IP literals and dotless entries so a bare TLD cannot become a suffix rule."""
        if "." not in allowed:
            return False
        try:
            ipaddress.ip_address(allowed)
        except ValueError:
            return True
        return False

    @staticmethod
    def _normalize_host(host: str) -> str | None:
        """Return a comparable host string, or None when nothing usable is left.

        IP literals collapse to their canonical form so ``[0:0:0:0:0:0:0:1]`` and
        ``::1`` compare equal. Names are IDNA-encoded so a Unicode spelling and its
        punycode spelling compare equal.

        A host carrying an invisible or format character is refused outright,
        before IDNA encoding, because the ``idna`` codec's nameprep silently strips
        those: ``comp<ZWSP>any.com`` would otherwise normalize to ``company.com``
        and satisfy an allowlist for it, while the downstream mail or HTTP client
        is free to read the same string as a different host. None here means the
        caller flags the value, so the rule's action applies.

        Deliberately no Unicode normalization or homoglyph folding: folding is
        fail-open for an allowlist, since folding a Cyrillic-o spelling of
        ``company.com`` onto the ASCII one would let a confusable domain through.
        Refusing an invisible character is the opposite move, flagging the host
        rather than making it comparable. Flagging mixed-script hosts is the same
        idea again and belongs in its own check, since unlike an invisible
        character a mixed-script host can be legitimate.

        Never raises. ``src.stdio_proxy`` fails open on policy exceptions, so a raise
        out of here would silently disable enforcement for that call.
        """
        candidate = host.strip().casefold()
        if candidate.endswith("."):
            candidate = candidate[:-1]
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        if not candidate:
            return None
        if find_invisible(candidate):
            logger.warning("Refusing host with invisible characters host=%r", host)
            return None
        try:
            return ipaddress.ip_address(candidate).compressed
        except ValueError:
            pass
        try:
            # The idna codec rejects empty labels and labels over 63 chars.
            return candidate.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            return candidate

    @classmethod
    def _host_from_token(cls, token: str) -> str | None:
        """Extract the host from one URL, email address, or bare hostname token."""
        candidate = token.strip()
        if not candidate:
            return None

        if _SCHEME_RE.match(candidate) or candidate.startswith("//"):
            return cls._host_from_url(candidate)

        at_index = candidate.find("@")
        if at_index != -1 and "/" not in candidate[:at_index]:
            remainder = candidate.rsplit("@", 1)[1]
            if any(char in remainder for char in "/:?@"):
                return None
            return cls._normalize_host(remainder)

        if "/" in candidate or ":" in candidate:
            return cls._host_from_url(f"//{candidate}")

        return cls._normalize_host(candidate)

    @classmethod
    def _extract_hosts(cls, value: Any) -> list[str | None]:
        """Extract every host referenced by one argument value.

        Lists and tuples recurse per element, so a multi-recipient field is checked
        entry by entry instead of being stringified whole. Strings split on commas,
        semicolons, and whitespace. A token that cannot be parsed contributes None so
        callers can fail closed.
        """
        if isinstance(value, (list, tuple)):
            hosts: list[str | None] = []
            for item in value:
                hosts.extend(cls._extract_hosts(item))
            return hosts
        if value is None:
            return [None]
        tokens = [token for token in _TOKEN_SPLIT_RE.split(str(value)) if token]
        if not tokens:
            return [None]
        return [cls._host_from_token(token) for token in tokens]

    @classmethod
    def _host_from_url(cls, url: str) -> str | None:
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            return None
        if not hostname:
            return None
        return cls._normalize_host(hostname)

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
                "view": finding.view,
                "span": finding.span,
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
