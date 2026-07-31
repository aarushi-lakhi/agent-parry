"""Regression tests over discovery payloads captured from real MCP servers.

The corpus under ``tests/fixtures/real_servers/`` is what eight reference and
third-party MCP servers actually answered to ``initialize`` and ``tools/list``,
captured once through the proxy by ``scripts/capture_real_corpus.py`` and
sanitized. Every assertion here runs against those files, so the suite stays
hermetic: no network, no ``npx``, no ``uvx``.

The numbers pinned here are the ones ``docs/real-servers.md`` quotes. A change to
the pattern table, the remapping heuristic or the probe generator that moves them
is expected to fail this file and update the document.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import re
import statistics
from pathlib import Path
from typing import Any

import pytest

from src.inspector import (
    INJECTION_PATTERNS,
    MAX_DESCRIPTION_CHARS,
    MAX_METADATA_LEAF_CHARS,
    METADATA_PATTERNS,
    MetadataInspector,
    MetadataInspectorSettings,
)
from src.models import AuditTransport
from src.pins import PinStore, ServerIdentity, ToolPinner, tools_set_fingerprint
from src.scanner import (
    Scanner,
    build_dynamic_payloads,
    filter_and_remap_payloads,
    map_yaml_tool_to_server,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "tests" / "fixtures" / "real_servers"
PAYLOADS = REPO_ROOT / "attacks" / "payloads.yaml"

EXPECTED_SERVERS = {
    "everything": 12,
    "fetch": 1,
    "filesystem": 14,
    "git": 12,
    "memory": 9,
    "playwright": 24,
    "sequential_thinking": 1,
    "time": 2,
}
EXPECTED_TOOL_TOTAL = 75

_SENSITIVE = re.compile(
    r"(?:/Users/[a-z]|/home/(?!USER\b)[a-z]"
    r"|gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"
)


def load_corpus() -> list[dict[str, Any]]:
    """Return every captured server entry, ordered by name."""
    paths = sorted(CORPUS_DIR.glob("*.json"))
    return [json.loads(path.read_text(encoding="utf-8")) for path in paths]


def corpus_ids() -> list[str]:
    """Return the corpus entry names, for parametrize ids."""
    return [path.stem for path in sorted(CORPUS_DIR.glob("*.json"))]


CORPUS = load_corpus()


def tools_of(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the tool objects on an entry's first ``tools/list`` page."""
    return list(entry["tools_list"]["tools"])


def prose_leaves(entry: dict[str, Any]) -> list[str]:
    """Return every tool description plus the server instructions string."""
    out = [t["description"] for t in tools_of(entry) if isinstance(t.get("description"), str)]
    instructions = entry["initialize"].get("instructions")
    if isinstance(instructions, str) and instructions:
        out.append(instructions)
    return out


class TestCorpusShape:
    """The fixture files themselves."""

    def test_expected_servers_present(self) -> None:
        assert {e["server"] for e in CORPUS} == set(EXPECTED_SERVERS)

    def test_tool_counts_match(self) -> None:
        assert {e["server"]: len(tools_of(e)) for e in CORPUS} == EXPECTED_SERVERS
        assert sum(len(tools_of(e)) for e in CORPUS) == EXPECTED_TOOL_TOTAL

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_entry_is_a_wellformed_discovery_pair(self, entry: dict[str, Any]) -> None:
        assert entry["initialize"]["protocolVersion"]
        assert isinstance(entry["initialize"]["serverInfo"], dict)
        for tool in tools_of(entry):
            assert isinstance(tool["name"], str) and tool["name"]
            assert isinstance(tool.get("inputSchema"), dict)

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_no_sensitive_strings_survived_sanitization(self, entry: dict[str, Any]) -> None:
        blob = json.dumps(entry)
        assert _SENSITIVE.search(blob) is None, "sanitizer let a host, home path or token through"


class TestMetadataInspectorOnRealServers:
    """The headline question: does poison detection fire on clean servers?

    Answer, over 75 real tools: not once, from the pattern table or from the
    structural heuristics. Zero findings at any severity, so every threshold
    including ``medium`` leaves all eight catalogues untouched.
    """

    def test_no_injection_pattern_matches_real_prose(self) -> None:
        patterns = INJECTION_PATTERNS + METADATA_PATTERNS
        assert patterns, "no patterns to check against the corpus"
        hits: list[tuple[str, str, str]] = []
        for entry in CORPUS:
            for text in prose_leaves(entry):
                for pattern in patterns:
                    if pattern.pattern.search(text):
                        hits.append((entry["server"], pattern.description, text[:60]))
        assert hits == []

    def test_total_findings_over_the_whole_corpus(self) -> None:
        inspector = MetadataInspector()
        findings = []
        for entry in CORPUS:
            for tool in tools_of(entry):
                findings.extend(inspector.scan_tool(tool))
            instructions = entry["initialize"].get("instructions")
            if isinstance(instructions, str) and instructions:
                findings.extend(inspector.scan_instructions(instructions))
        assert findings == []

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_default_settings_never_damage_a_real_tool(self, entry: dict[str, Any]) -> None:
        inspector = MetadataInspector()
        tools_result = inspector.inspect_tools_list(entry["tools_list"])
        assert tools_result.dropped_tools == []
        assert tools_result.redacted_tools == []
        assert tools_result.blocked is False
        names = [t["name"] for t in tools_result.result["tools"]]
        assert names == [t["name"] for t in tools_of(entry)]

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_default_settings_keep_real_instructions(self, entry: dict[str, Any]) -> None:
        inspector = MetadataInspector()
        before = entry["initialize"].get("instructions")
        after = inspector.inspect_initialize(entry["initialize"]).result.get("instructions")
        assert after == before

    @pytest.mark.parametrize("threshold", ["critical", "high", "medium"])
    def test_every_threshold_is_inert_on_real_servers(self, threshold: str) -> None:
        """Medium used to drop one working tool and redact one the model needs."""
        inspector = MetadataInspector(
            MetadataInspectorSettings(action="redact", severity_threshold=threshold)
        )
        for entry in CORPUS:
            result = inspector.inspect_tools_list(entry["tools_list"])
            assert result.dropped_tools == []
            assert result.redacted_tools == []

    def test_the_gzip_default_url_is_not_an_opaque_blob(self) -> None:
        """A real raw.githubusercontent.com default used to read as encoded bytes."""
        tool = next(t for t in tools_of(_entry("everything")) if t["name"] == "gzip-file-as-resource")
        assert tool["inputSchema"]["properties"]["data"]["default"].startswith("https://")
        findings = MetadataInspector().scan_tool(tool)
        assert [f.matched_pattern for f in findings] == []


class TestRealDescriptionLengths:
    """What real tool descriptions actually measure, and what the cap must clear.

    ``MAX_DESCRIPTION_CHARS`` is the only inspector setting a real server has ever
    tripped. These numbers are why it is 8000 and not 2000, and they fail loudly
    if someone changes the cap without meaning to.
    """

    @staticmethod
    def _lengths() -> list[int]:
        return sorted(
            len(tool["description"])
            for entry in CORPUS
            for tool in tools_of(entry)
            if isinstance(tool.get("description"), str)
        )

    def test_every_real_tool_has_a_description(self) -> None:
        assert len(self._lengths()) == EXPECTED_TOOL_TOTAL

    def test_the_distribution_is_pinned(self) -> None:
        lengths = self._lengths()
        assert (lengths[0], lengths[-1]) == (14, 2781)
        assert statistics.median(lengths) == 57
        assert lengths[math.ceil(0.90 * len(lengths)) - 1] == 323
        assert lengths[math.ceil(0.95 * len(lengths)) - 1] == 360
        assert sum(lengths) == 10_732

    def test_the_outlier_is_alone_and_far_out(self) -> None:
        """Nothing sits between 460 and 2781, so no cap in that range is defensible."""
        lengths = self._lengths()
        assert lengths[-2] == 457
        assert lengths[-1] == 2781

    def test_the_cap_clears_every_real_description_with_headroom(self) -> None:
        lengths = self._lengths()
        assert lengths[-1] < MAX_DESCRIPTION_CHARS < MAX_METADATA_LEAF_CHARS
        assert 2 * lengths[-1] <= MAX_DESCRIPTION_CHARS

    def test_no_real_description_is_oversized(self) -> None:
        inspector = MetadataInspector()
        oversized = [
            tool["name"]
            for entry in CORPUS
            for tool in tools_of(entry)
            for finding in inspector.scan_tool(tool)
            if finding.matched_pattern == "oversized metadata"
        ]
        assert oversized == []

    def test_the_only_real_instructions_string_is_under_the_cap(self) -> None:
        instructions = _entry("everything")["initialize"]["instructions"]
        assert len(instructions) == 1_574
        assert MetadataInspector().scan_instructions(instructions) == []


class TestRemappingAgainstRealToolNames:
    """What ``--discover`` actually does to payload tool names on a real server."""

    YAML_TOOLS = ("email_send", "file_read", "http_fetch", "shell_exec")

    def test_no_yaml_tool_name_exists_on_any_real_server(self) -> None:
        real = {t["name"] for e in CORPUS for t in tools_of(e)}
        assert real.isdisjoint(self.YAML_TOOLS)
        assert {n.lower() for n in real}.isdisjoint(self.YAML_TOOLS)

    def test_mapping_outcome_per_server_is_pinned(self) -> None:
        observed: dict[str, dict[str, str | None]] = {}
        for entry in CORPUS:
            names = sorted(t["name"] for t in tools_of(entry))
            observed[entry["server"]] = {
                yaml_tool: map_yaml_tool_to_server(yaml_tool, names)
                for yaml_tool in self.YAML_TOOLS
            }
        assert observed == {
            "everything": {
                "email_send": "get-annotated-message",
                "file_read": "gzip-file-as-resource",
                "http_fetch": None,
                "shell_exec": None,
            },
            "fetch": {
                "email_send": None,
                "file_read": None,
                "http_fetch": "fetch",
                "shell_exec": None,
            },
            "filesystem": {
                "email_send": "read_file",
                "file_read": "edit_file",
                "http_fetch": None,
                "shell_exec": None,
            },
            "git": {
                "email_send": None,
                "file_read": None,
                "http_fetch": None,
                "shell_exec": "git_show",
            },
            "memory": {
                "email_send": None,
                "file_read": "open_nodes",
                "http_fetch": None,
                "shell_exec": None,
            },
            "playwright": {
                "email_send": "browser_console_messages",
                "file_read": "browser_file_upload",
                "http_fetch": "browser_click",
                "shell_exec": "browser_snapshot",
            },
            "sequential_thinking": {
                "email_send": None,
                "file_read": None,
                "http_fetch": None,
                "shell_exec": None,
            },
            "time": {
                "email_send": None,
                "file_read": None,
                "http_fetch": None,
                "shell_exec": None,
            },
        }

    def test_a_read_payload_lands_on_a_write_tool(self) -> None:
        """The concrete reason a remapped scan must not run outside --safe."""
        names = sorted(t["name"] for t in tools_of(_entry("filesystem")))
        assert map_yaml_tool_to_server("file_read", names) == "edit_file"

    def test_matched_counts_measure_fuzz_not_coverage(self) -> None:
        scanner = Scanner(str(PAYLOADS))
        total = len(scanner.payloads)
        matched = {}
        for entry in CORPUS:
            names = sorted(t["name"] for t in tools_of(entry))
            _, count = filter_and_remap_payloads(scanner.payloads, names)
            matched[entry["server"]] = count
        assert matched["playwright"] == total
        assert matched["sequential_thinking"] == 0
        assert matched["time"] == 0

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_every_remapped_payload_names_a_real_tool(self, entry: dict[str, Any]) -> None:
        scanner = Scanner(str(PAYLOADS))
        names = sorted(t["name"] for t in tools_of(entry))
        mapped, _ = filter_and_remap_payloads(scanner.payloads, names)
        for payload in mapped:
            assert payload.tool in names
            for step in payload.steps:
                assert step.tool in names


class TestDynamicProbesAgainstRealSchemas:
    """Whether schema-driven probes produce arguments a real server will accept."""

    @staticmethod
    def _validity(entry: dict[str, Any]) -> tuple[int, int, int, int]:
        tools = tools_of(entry)
        schemas = {t["name"]: t.get("inputSchema") or {} for t in tools}
        valid = missing = enum_violation = 0
        probes = build_dynamic_payloads(tools, include_benign=True)
        for payload in probes:
            schema = schemas[payload.tool]
            props = schema.get("properties") or {}
            required = set(schema.get("required") or [])
            gaps = required - set(payload.arguments)
            bad_enum = [
                key
                for key, value in payload.arguments.items()
                if "enum" in (props.get(key) or {}) and value not in props[key]["enum"]
            ]
            missing += bool(gaps)
            enum_violation += bool(bad_enum)
            valid += not gaps and not bad_enum
        return len(probes), valid, missing, enum_violation

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_probes_only_target_real_tools(self, entry: dict[str, Any]) -> None:
        names = {t["name"] for t in tools_of(entry)}
        for payload in build_dynamic_payloads(tools_of(entry), include_benign=True):
            assert payload.tool in names

    def test_corpus_wide_probe_validity_is_pinned(self) -> None:
        totals = [0, 0, 0, 0]
        for entry in CORPUS:
            for index, value in enumerate(self._validity(entry)):
                totals[index] += value
        probes, valid, missing, enum_violation = totals
        assert probes == 149
        assert valid == 106
        assert missing == 28
        assert enum_violation == 15

    def test_tools_with_no_top_level_string_get_no_injection_probe(self) -> None:
        unreachable: list[str] = []
        for entry in CORPUS:
            tools = tools_of(entry)
            probed = {p.tool for p in build_dynamic_payloads(tools)}
            unreachable.extend(t["name"] for t in tools if t["name"] not in probed)
        assert len(unreachable) == 22
        assert "read_multiple_files" in unreachable
        assert "create_entities" in unreachable


class TestPinningRealToolLists:
    """Whether a pin taken from a real ``tools/list`` settles and stays settled."""

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_pin_is_created_then_unchanged(self, entry: dict[str, Any], tmp_path: Path) -> None:
        pinner = ToolPinner(store=PinStore(tmp_path / "pins.json"), inspector=MetadataInspector())
        identity = ServerIdentity.for_command(entry["command"], transport=AuditTransport.HTTP)
        statuses = [
            pinner.observe("tools/list", _copy(entry["tools_list"]), [], identity=identity).status
            for _ in range(3)
        ]
        assert statuses == ["created", "unchanged", "unchanged"]

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_initialize_pin_is_created_then_unchanged(
        self, entry: dict[str, Any], tmp_path: Path
    ) -> None:
        pinner = ToolPinner(store=PinStore(tmp_path / "pins.json"), inspector=MetadataInspector())
        identity = ServerIdentity.for_command(entry["command"], transport=AuditTransport.HTTP)
        statuses = [
            pinner.observe("initialize", _copy(entry["initialize"]), [], identity=identity).status
            for _ in range(2)
        ]
        assert statuses == ["created", "unchanged"]

    @pytest.mark.parametrize("entry", CORPUS, ids=corpus_ids())
    def test_set_fingerprint_ignores_tool_order(self, entry: dict[str, Any]) -> None:
        tools = tools_of(entry)
        assert tools_set_fingerprint(tools) == tools_set_fingerprint(list(reversed(tools)))

    def test_no_captured_server_paginates_tools_list(self) -> None:
        assert [e["server"] for e in CORPUS if e["paginated"]] == []
        assert {e["page_count"] for e in CORPUS} == {1}

    @staticmethod
    def _paged_walk(
        pinner: ToolPinner, identity: ServerIdentity, tools: list[dict[str, Any]], pages: int
    ) -> list[Any]:
        """Serve ``tools`` over ``pages`` cursor-linked pages, as a real client would."""
        size = -(-len(tools) // pages)
        chunks = [tools[start : start + size] for start in range(0, len(tools), size)]
        observations = []
        cursor: str | None = None
        for index, chunk in enumerate(chunks):
            result: dict[str, Any] = {"tools": _copy({"t": chunk})["t"]}
            if index + 1 < len(chunks):
                result["nextCursor"] = f"page{index + 2}"
            params = {} if cursor is None else {"cursor": cursor}
            observations.append(pinner.observe("tools/list", result, [], identity=identity, params=params))
            cursor = result.get("nextCursor")
        return observations

    def test_a_paginated_catalogue_converges_like_an_unpaginated_one(self, tmp_path: Path) -> None:
        """Playwright's real 24 tools split across two pages, fetched three times.

        The pin is diffed once per completed walk, so the sequence reads
        created, unchanged, unchanged. Before pages were correlated the last page
        of each walk was diffed as a whole catalogue and reported 12 removed and
        12 added, forever.
        """
        tools = tools_of(_entry("playwright"))
        assert len(tools) == 24
        pinner = ToolPinner(store=PinStore(tmp_path / "pins.json"), inspector=MetadataInspector())
        identity = ServerIdentity.for_command("paged-server", transport=AuditTransport.HTTP)

        for _ in range(3):
            observations = self._paged_walk(pinner, identity, tools, pages=2)
            assert [o.status for o in observations[:-1]] == ["partial"]
            assert all(o.paginated for o in observations)

        assert self._paged_walk(pinner, identity, tools, pages=2)[-1].status == "unchanged"
        pin = PinStore(tmp_path / "pins.json").get(identity.key)
        assert pin is not None
        assert pin.tool_count == 24
        assert pin.set_fingerprint == tools_set_fingerprint(tools)

    @pytest.mark.parametrize("pages", [2, 3, 8, 24])
    def test_page_size_does_not_change_the_pinned_catalogue(self, tmp_path: Path, pages: int) -> None:
        tools = tools_of(_entry("playwright"))
        pinner = ToolPinner(store=PinStore(tmp_path / "pins.json"), inspector=MetadataInspector())
        identity = ServerIdentity.for_command("paged-server", transport=AuditTransport.HTTP)
        assert self._paged_walk(pinner, identity, tools, pages=pages)[-1].status == "created"
        pin = PinStore(tmp_path / "pins.json").get(identity.key)
        assert pin is not None
        assert pin.set_fingerprint == tools_set_fingerprint(tools)

    def test_a_half_fetched_catalogue_is_not_recorded_as_the_whole_one(self, tmp_path: Path) -> None:
        """The failure a per-page pin would cause: a pinned subset, then mass additions."""
        tools = tools_of(_entry("playwright"))
        store = PinStore(tmp_path / "pins.json")
        pinner = ToolPinner(store=store, inspector=MetadataInspector())
        identity = ServerIdentity.for_command("paged-server", transport=AuditTransport.HTTP)

        page = {"tools": _copy({"t": tools[:12]})["t"], "nextCursor": "page2"}
        abandoned = pinner.observe("tools/list", page, [], identity=identity, params={})
        assert abandoned.status == "partial"
        assert store.get(identity.key) is None

        whole = {"tools": _copy({"t": tools})["t"]}
        full = pinner.observe("tools/list", whole, [], identity=identity, params={})
        assert full.status == "created"
        assert full.diff is None


class TestBenignCorpusVersusRealSchemas:
    """Whether the benign over-block corpus resembles real tool arguments."""

    def test_benign_payloads_cover_four_mock_tools_only(self) -> None:
        scanner = Scanner(str(PAYLOADS))
        benign = [p for p in scanner.payloads if p.category == "benign"]
        assert len(benign) == 15
        assert sorted({p.tool for p in benign}) == [
            "email_send",
            "file_read",
            "http_fetch",
            "shell_exec",
        ]

    def test_most_benign_argument_names_appear_on_no_real_server(self) -> None:
        scanner = Scanner(str(PAYLOADS))
        benign_args = {
            key for p in scanner.payloads if p.category == "benign" for key in p.arguments
        }
        real_props = {
            key
            for entry in CORPUS
            for tool in tools_of(entry)
            for key in ((tool.get("inputSchema") or {}).get("properties") or {})
        }
        assert len(real_props) == 98
        assert sorted(benign_args & real_props) == ["path", "url"]

    def test_real_tools_are_wider_than_the_benign_corpus(self) -> None:
        scanner = Scanner(str(PAYLOADS))
        benign_arity = {len(p.arguments) for p in scanner.payloads if p.category == "benign"}
        real_arity = {
            len((tool.get("inputSchema") or {}).get("properties") or {})
            for entry in CORPUS
            for tool in tools_of(entry)
        }
        assert benign_arity == {1, 3}
        assert max(real_arity) == 9

    def test_real_schemas_use_types_the_benign_corpus_never_exercises(self) -> None:
        types: set[str] = set()
        for entry in CORPUS:
            for tool in tools_of(entry):
                props = (tool.get("inputSchema") or {}).get("properties") or {}
                for spec in props.values():
                    types.add((spec or {}).get("type", "untyped"))
        assert {"array", "object", "boolean", "number", "integer"} <= types


class TestCaptureScriptSanitizer:
    """The sanitizer that keeps machine-specific strings out of the corpus."""

    @staticmethod
    def _module() -> Any:
        spec = importlib.util.spec_from_file_location(
            "capture_real_corpus", REPO_ROOT / "scripts" / "capture_real_corpus.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_replaces_scratch_home_and_credential_shapes(self) -> None:
        module = self._module()
        replacements = module.build_replacements("/private/tmp/scratch")
        text = "read /private/tmp/scratch/a.txt with Bearer abcdefghijklmnopqrstuvwxyz012345"
        out = module.sanitize_text(text, replacements)
        assert "/private/tmp/scratch" not in out
        assert "REDACTED_TOKEN" in out

    def test_sanitizes_nested_values_and_keys(self) -> None:
        module = self._module()
        replacements = module.build_replacements("/private/tmp/scratch")
        payload = {"/private/tmp/scratch": ["/private/tmp/scratch/x", {"k": 1}]}
        out = module.sanitize(payload, replacements)
        assert list(out) == [module.SCRATCH_PLACEHOLDER]
        assert out[module.SCRATCH_PLACEHOLDER][0] == f"{module.SCRATCH_PLACEHOLDER}/x"
        assert out[module.SCRATCH_PLACEHOLDER][1] == {"k": 1}

    def test_home_directory_is_replaced_without_a_scratch_dir(self) -> None:
        module = self._module()
        home = os.path.expanduser("~")
        out = module.sanitize_text(f"{home}/.ssh/config", module.build_replacements(None))
        assert home not in out
        assert out.startswith(module.HOME_PLACEHOLDER)


def _entry(name: str) -> dict[str, Any]:
    return next(e for e in CORPUS if e["server"] == name)


def _copy(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))
