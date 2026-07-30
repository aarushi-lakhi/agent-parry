"""Rule generator that produces policy rules from scan results."""

from __future__ import annotations

import difflib
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.table import Table

from src.models import AttackResult, ScanReport
from src.normalize import MIN_OPAQUE_BLOB, decode_base64_fragment, iter_base64_runs
from src.resources import UNSET, Unset
from src.resources import policy_path as resolve_policy_path

logger = logging.getLogger(__name__)

console = Console()

AUTOGEN_PREFIX = "autogen_"

_INSTRUCTION_OBJECT = r"(?:rules|instructions|guidelines|policies|restrictions|directives)"

_SAFETY_OVERRIDE_PATTERN = (
    r"disregard\s+(?:all|any|every|the\s+(?:previous|prior|earlier|preceding|above|system|safety))"
    rf"\b.{{0,30}}\b{_INSTRUCTION_OBJECT}\b"
    r"|override\s+(?:your|all|the)\s+(?:safety|security)\b"
)
"""An instruction to drop a scoped set of instructions, not any later word "rules"."""

_PI_PATTERNS: list[tuple[str, str, str]] = [
    ("ignore.*instructions", "ignore.*instructions", "instruction override"),
    ("SYSTEM:", r"^SYSTEM:|\[SYSTEM\]", "fake SYSTEM prompt"),
    ("disregard", _SAFETY_OVERRIDE_PATTERN, "safety override"),
    ("/etc/passwd", r"/etc/(?:passwd|shadow|sudoers)", "credential file exfiltration"),
]

_DECODED_NORMALIZE = {"decoded": True}

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

    A blank value takes the table pattern untouched, so the escape path here can
    never produce the empty pattern. `_usable_patterns` handles what is left.

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


def _usable_patterns(patterns: list[str], value: str) -> list[str]:
    """Resolve patterns for `value`, dropping any that matches every request.

    A pattern that matches the empty string is found in every input by
    re.search, so a rule carrying one blocks all traffic to its tool. That is
    what a payload with a blank or absent text argument produced, via
    `re.escape("")`. An unparseable pattern is kept, because PolicyEngine
    already refuses the whole rule when a pattern will not compile.
    """
    resolved = _patterns_for_value(patterns, value)
    kept: list[str] = []
    for pattern in resolved:
        try:
            if re.search(pattern, "") is not None:
                continue
        except re.error:
            pass
        kept.append(pattern)
    return kept


def _decoded_blob_text(body: str) -> str | None:
    """Plaintext behind the first long base64 run in `body`, or None when there is none."""
    for match in iter_base64_runs(body, min_length=MIN_OPAQUE_BLOB):
        decoded = decode_base64_fragment(match.group(0))
        if decoded is not None:
            return decoded
    return None


def _injection_pattern(text: str) -> tuple[str, str]:
    """The keyword-table pattern `text` triggers, else an escape of its first four words."""
    for keyword, pattern, label in _PI_PATTERNS:
        if keyword.lower() in text.lower():
            return pattern, label
    return re.escape(" ".join(text.split()[:4])), "prompt injection"


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


def is_autogen_rule(rule: dict[str, Any]) -> bool:
    """True for a rule this module owns, identified by its name prefix."""
    name = rule.get("name")
    return isinstance(name, str) and name.startswith(AUTOGEN_PREFIX)


def merge_autogen_rules(
    existing: list[dict[str, Any]],
    new: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge freshly generated autogen rules into an existing rule list, additively.

    This diverges from `RuleGenerator.apply_rules` on purpose. `apply_rules`
    drops every existing `autogen_*` rule and prepends the new list, which is
    what `src/demo.py` needs: `apply_rules([])` resets the committed policy to
    its handwritten rules so the demo's phase 2 scan finds vulnerabilities to
    fix. Run that same replace against a real policy and the autogen rules that
    were already blocking payloads disappear, the fresh scan therefore reports
    no findings, no replacement rules are generated, and the vulnerabilities are
    silently back. This function keeps them instead: a new rule replaces the
    existing rule of the same name, every other rule survives.

    Ordering matches `apply_rules`: generated rules first, then surviving
    autogen rules, then handwritten rules in their original relative order.
    `PolicyEngine` is first-match-wins, so a generated BLOCK shadows a
    handwritten ALLOW for the same tool. That is pre-existing behavior, kept
    deliberately so merging cannot change which rule decides a call.
    """
    new_names = {r["name"] for r in new if isinstance(r.get("name"), str)}
    kept_autogen = [r for r in existing if is_autogen_rule(r) and r.get("name") not in new_names]
    handwritten = [r for r in existing if not is_autogen_rule(r)]
    return [*new, *kept_autogen, *handwritten]


def load_policy(policy_path: str | Path) -> dict[str, Any]:
    """Load a policy YAML file. Raises FileNotFoundError when it is missing."""
    path = Path(policy_path)
    if not path.is_file():
        raise FileNotFoundError(f"policy file not found: {path}")
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def render_policy(policy: dict[str, Any]) -> str:
    """Serialize a policy dict the way `apply_rules` writes it."""
    return yaml.dump(policy, default_flow_style=False, sort_keys=False)


def policy_diff(before_text: str, after_text: str, *, path: str | Path) -> str:
    """Unified diff between a policy file's current text and its rewritten text.

    Diffs the raw file text, not a re-render of it, so the diff shows everything
    the write will do, including the comments and formatting `yaml.safe_load`
    plus `yaml.dump` discard.
    """
    diff = difflib.unified_diff(
        before_text.splitlines(keepends=True),
        after_text.splitlines(keepends=True),
        fromfile=f"{path} (current)",
        tofile=f"{path} (hardened)",
    )
    return "".join(diff)


@dataclass(frozen=True)
class AutogenMergePlan:
    """A pending additive merge: what it would write, and what it would change."""

    policy: dict[str, Any]
    before_text: str
    after_text: str
    added: list[str] = field(default_factory=list)
    replaced: list[str] = field(default_factory=list)
    kept_autogen: list[str] = field(default_factory=list)
    handwritten: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.before_text != self.after_text

    def diff(self, path: str | Path) -> str:
        return policy_diff(self.before_text, self.after_text, path=path)


def plan_autogen_merge(
    rules: list[dict[str, Any]],
    policy_path: str | Path,
) -> AutogenMergePlan:
    """Compute the additive merge of `rules` into `policy_path` without writing."""
    path = Path(policy_path)
    policy = load_policy(path)
    existing: list[dict[str, Any]] = policy.get("rules") or []
    existing_autogen = {r["name"] for r in existing if is_autogen_rule(r) and isinstance(r.get("name"), str)}

    merged = merge_autogen_rules(existing, rules)
    new_policy = dict(policy)
    new_policy["rules"] = merged

    new_names = [r["name"] for r in rules if isinstance(r.get("name"), str)]
    return AutogenMergePlan(
        policy=new_policy,
        before_text=path.read_text(encoding="utf-8"),
        after_text=render_policy(new_policy),
        added=[n for n in new_names if n not in existing_autogen],
        replaced=[n for n in new_names if n in existing_autogen],
        kept_autogen=[n for n in sorted(existing_autogen) if n not in set(new_names)],
        handwritten=[r["name"] for r in existing if not is_autogen_rule(r) and isinstance(r.get("name"), str)],
    )


def write_policy_text(text: str, policy_path: str | Path) -> str | None:
    """Write policy text, backing the current file up to a `.bak` sibling first.

    Same convention as `cli.cmd_install_claude`: the backup lands next to the
    original with `.bak` appended, and is taken before anything is mutated.
    Returns the backup path, or None when there was no file to back up.
    """
    path = Path(policy_path)
    backup: Path | None = None
    if path.exists():
        backup = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(backup) if backup is not None else None


class RuleGenerator:
    """Generates policy rules from scan results."""

    def generate_rules(
        self,
        report: ScanReport,
        *,
        include_policy_allowed: bool = False,
    ) -> list[dict[str, Any]]:
        """Build autogen rules from a scan report.

        `include_policy_allowed` also considers results the proxy only evaluated
        instead of forwarding, which is every allowed result of a `--safe` scan.
        Without it a safe scan generates nothing, because `evaluated_only`
        results never set `passed_through`. Off by default so `save_scan_outputs`
        and `src/demo.py` keep emitting exactly the rules they did before.
        """
        rules: list[dict[str, Any]] = []
        for result in report.results:
            eligible = result.passed_through or (include_policy_allowed and result.evaluated_only)
            if not eligible:
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
        policy_path: str | Path | Unset = UNSET,
    ) -> None:
        """Replace every autogen rule in the policy with `rules`, in place.

        Destructive and unconditional: no backup, no diff, no confirmation, and
        every pre-existing `autogen_*` rule is dropped. `src/demo.py` depends on
        exactly that, calling `apply_rules([])` to reset the committed policy
        before its phase 2 scan. Anything user-facing wants the additive path:
        `plan_autogen_merge` plus `write_policy_text`, which is what
        `agentparry harden` uses. See `merge_autogen_rules` for why replacing
        silently reintroduces vulnerabilities.

        The default target is the resolved default policy, which in an installed
        tree is package data. Callers that write must resolve a writable path
        first; `agentparry harden` does that with `resources.copy_out_policy`.
        """
        target = resolve_policy_path(policy_path)
        with open(target) as f:
            policy = yaml.safe_load(f) or {}

        existing: list[dict[str, Any]] = policy.get("rules", [])
        existing = [r for r in existing if not r.get("name", "").startswith("autogen_")]

        policy["rules"] = rules + existing

        with open(target, "w") as f:
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
    ) -> dict[str, Any] | None:
        """Build a pattern_match rule, validating the patterns against `value`.

        `value` is the argument the condition inspects, so every category gets
        the same guarantee: the emitted rule matches the payload it came from.

        Returns None when nothing usable is left, rather than a rule whose
        condition matches every call to the tool.
        """
        usable = _usable_patterns(patterns, value)
        if not usable:
            logger.warning(
                "Refusing to generate a match-all rule attack_id=%s tool=%s field=%s",
                attack_id,
                tool,
                field,
            )
            return None
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
                    "patterns": usable,
                }
            ],
        }

    @staticmethod
    def _rule_prompt_injection(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Build a BLOCK rule for one injection payload, from the plaintext it carries.

        When the argument hides its instruction inside base64, the pattern is
        derived from the decoded text and the condition opts into decoded views,
        so the rule matches what the payload says rather than the shape of the
        blob that carried it. A length-based blob pattern blocks every ordinary
        reference number of the same length, and `src.normalize` already exposes
        the plaintext as a view.

        `_make_rule` validates the pattern against whichever text it was derived
        from, and returns None rather than a rule that matches every call, so a
        payload with no usable text yields no rule at all.
        """
        field, body = RuleGenerator._select_field(arguments, _TEXT_FIELDS, "body")

        decoded = _decoded_blob_text(body)
        source = body if decoded is None else decoded
        pattern, label = _injection_pattern(source)
        prefix = "" if decoded is None else "base64-encoded "

        rule = RuleGenerator._make_rule(
            attack_id, tool, "BLOCK", field, [pattern],
            f"blocks {prefix}{label} in email body", source,
        )
        if rule is not None and decoded is not None:
            rule["conditions"][0]["normalize"] = dict(_DECODED_NORMALIZE)
        return rule

    @staticmethod
    def _rule_data_exfiltration(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        field, command = RuleGenerator._select_field(arguments, _COMMAND_FIELDS, "command")

        haystack = command.lower()
        pattern = r"curl.*-d"
        desc = "blocks data exfiltration via shell"
        for keyword, pat, label in _DE_PATTERNS:
            if keyword.lower() in haystack:
                pattern = pat
                desc = f"blocks {label}"
                break

        return RuleGenerator._make_rule(
            attack_id, tool, "BLOCK", field, [pattern], desc, command,
        )

    @staticmethod
    def _rule_privilege_escalation(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        field, command = RuleGenerator._select_field(arguments, _COMMAND_FIELDS, "command")

        haystack = command.lower()
        pattern = r"rm\s+-rf\s+/"
        desc = "blocks privilege escalation via shell"
        for keyword, pat, label in _PE_PATTERNS:
            if keyword.lower() in haystack:
                pattern = pat
                desc = f"blocks {label}"
                break

        return RuleGenerator._make_rule(
            attack_id, tool, "BLOCK", field, [pattern], desc, command,
        )

    @staticmethod
    def _rule_pii_leak(
        attack_id: str, tool: str, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
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
