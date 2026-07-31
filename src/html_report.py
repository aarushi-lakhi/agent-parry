"""Renders a :class:`~src.models.ScanReport` as one self-contained HTML page.

The output has no external stylesheet, font, script or image, so a report opened
from a Downloads folder with no network still renders. Every value that came
from a payload, a tool response or a rule message is escaped and has its
invisible characters replaced with a visible ``<U+XXXX>`` marker: the corpus
carries HTML tags, ANSI escapes, zero-width characters and bidi overrides on
purpose, and a report that rendered those as live markup would be an injection
vector in the reporting tool.

Rendering is a pure function of the report, so two renders of the same report
produce identical bytes.
"""

from __future__ import annotations

import html
import json
import unicodedata
from typing import Any

import yaml

from src.inspector import InputInspector
from src.models import AttackResult, ConfusionMatrix, Finding, ScanReport
from src.scanner import (
    OBSERVED_EVALUATED,
    OBSERVED_NEUTRALIZE,
    OBSERVED_REDACT,
    OUTCOME_FALSE_NEGATIVE,
    OUTCOME_FALSE_POSITIVE,
    OUTCOME_INDETERMINATE,
    OUTCOME_ORDER,
    OUTCOME_TRUE_ALLOW,
    blocking_rule_message,
    compute_confusion_matrix,
    format_rate,
    is_attack_payload,
    is_known_gap,
    normalize_expected,
    observed_from_result,
    result_outcome,
)

_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cn", "Co", "Cs", "Zl", "Zp", "Zs"})
"""Unicode categories rendered as a marker instead of as themselves.

Zs is in the set because an ideographic or non-breaking space is a homoglyph for
the ASCII space the reader thinks they are looking at. Plain U+0020 is handled
before the lookup.
"""

_OUTCOME_LABELS: dict[str, tuple[str, str]] = {
    OUTCOME_FALSE_NEGATIVE: ("MISSED", "bad"),
    OUTCOME_FALSE_POSITIVE: ("OVER-BLOCKED", "over"),
    OUTCOME_INDETERMINATE: ("UNMEASURED", "warn"),
    OUTCOME_TRUE_ALLOW: ("ALLOWED", "good"),
}

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f7f8fa;
  --card: #ffffff;
  --fg: #15181d;
  --muted: #5a6472;
  --line: #d8dde5;
  --good: #14713f;
  --bad: #b02a20;
  --over: #8d2b8d;
  --warn: #8a5800;
  --info: #17538f;
  --ctl-bg: #efe4f7;
  --ctl-fg: #6b21a8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #11141a;
    --card: #191d25;
    --fg: #e7eaf0;
    --muted: #9aa4b4;
    --line: #303845;
    --good: #58d18d;
    --bad: #ff8e84;
    --over: #e6a2e6;
    --warn: #e2b355;
    --info: #7db6f2;
    --ctl-bg: #33224a;
    --ctl-fg: #dcb6ff;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 1.5rem 1rem 4rem;
  background: var(--bg);
  color: var(--fg);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 62rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2rem 0 .5rem; }
h3 { font-size: .95rem; margin: 1.25rem 0 .35rem; }
p { margin: .5rem 0; }
a { color: var(--info); }
code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.muted { color: var(--muted); }
.meta { list-style: none; padding: 0; margin: .5rem 0 0; color: var(--muted); font-size: .9rem; }
.meta li { margin: .15rem 0; }
.card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 1rem;
  margin: 1.5rem 0;
}
.card > h2:first-child { margin-top: 0; }
.banner {
  border-left: 4px solid var(--warn);
  background: var(--card);
  border-radius: 4px;
  padding: .6rem .8rem;
  margin: .75rem 0;
  font-size: .92rem;
}
.banner.info { border-left-color: var(--info); }
.pair { display: flex; flex-wrap: wrap; gap: .75rem; margin: 0; }
.stat {
  flex: 1 1 12rem;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--card);
  padding: .8rem .9rem;
}
.stat .label { font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); }
.stat .value { font-size: 1.9rem; font-weight: 650; line-height: 1.1; margin: .15rem 0; }
.stat .sub { font-size: .85rem; color: var(--muted); }
.stat.detection .value { color: var(--good); }
.stat.overblock .value { color: var(--over); }
.stat.balanced .value { color: var(--info); }
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; max-width: 100%; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
caption { text-align: left; color: var(--muted); font-size: .85rem; padding-bottom: .4rem; }
th, td { border: 1px solid var(--line); padding: .4rem .55rem; text-align: left; vertical-align: top; }
thead th { background: var(--card); position: sticky; top: 0; }
tbody tr:nth-child(even) td { background: color-mix(in srgb, var(--card) 65%, transparent); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
table.matrix td { text-align: center; }
table.matrix .cellname {
  display: block;
  font-size: .78rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .05em;
}
table.matrix .cellcount { font-size: 1.35rem; font-weight: 650; }
.good { color: var(--good); }
.bad { color: var(--bad); }
.over { color: var(--over); }
.warn { color: var(--warn); }
.info { color: var(--info); }
.badge {
  display: inline-block;
  border: 1px solid currentColor;
  border-radius: 999px;
  padding: 0 .45rem;
  font-size: .75rem;
  font-weight: 600;
  white-space: nowrap;
}
.ctl {
  background: var(--ctl-bg);
  color: var(--ctl-fg);
  border-radius: 3px;
  padding: 0 .15rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .82em;
  white-space: nowrap;
}
pre {
  margin: .35rem 0 0;
  padding: .5rem .6rem;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
  overflow-x: auto;
  font-size: .82rem;
  white-space: pre-wrap;
  word-break: break-word;
}
details summary { cursor: pointer; color: var(--info); font-size: .82rem; }
.fp { border-left: 4px solid var(--over); }
.evidence { border: 1px solid var(--line); border-radius: 6px; padding: .6rem .7rem; margin: .6rem 0; }
.evidence h3 { margin-top: 0; }
.controls { display: flex; flex-wrap: wrap; gap: .4rem; margin: .5rem 0; }
.controls button {
  font: inherit;
  font-size: .82rem;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--fg);
  border-radius: 999px;
  padding: .2rem .7rem;
  cursor: pointer;
}
.controls button[aria-pressed="true"] { border-color: var(--info); color: var(--info); font-weight: 600; }
th[role="button"] { cursor: pointer; }
th[role="button"]::after { content: " \\2195"; color: var(--muted); font-weight: 400; }
footer { margin-top: 3rem; color: var(--muted); font-size: .8rem; }
"""

_SCRIPT = """
(function () {
  var controls = document.getElementById("controls");
  var table = document.getElementById("detail");
  if (!controls || !table || !table.tBodies.length) { return; }
  controls.hidden = false;
  var body = table.tBodies[0];
  var rows = Array.prototype.slice.call(body.rows);
  var buttons = Array.prototype.slice.call(controls.querySelectorAll("button[data-filter]"));

  function apply(want) {
    rows.forEach(function (row) {
      var groups = (row.getAttribute("data-group") || "").split(" ");
      row.hidden = want !== "all" && groups.indexOf(want) < 0;
    });
    buttons.forEach(function (button) {
      button.setAttribute("aria-pressed", String(button.getAttribute("data-filter") === want));
    });
  }

  buttons.forEach(function (button) {
    button.addEventListener("click", function () { apply(button.getAttribute("data-filter")); });
  });

  var direction = {};
  Array.prototype.forEach.call(table.tHead.rows[0].cells, function (cell, index) {
    cell.setAttribute("role", "button");
    cell.setAttribute("tabindex", "0");
    function sort() {
      var descending = direction[index] === "asc";
      direction[index] = descending ? "desc" : "asc";
      rows.sort(function (a, b) {
        var left = (a.cells[index].textContent || "").trim();
        var right = (b.cells[index].textContent || "").trim();
        return descending ? right.localeCompare(left) : left.localeCompare(right);
      });
      rows.forEach(function (row) { body.appendChild(row); });
    }
    cell.addEventListener("click", sort);
    cell.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); sort(); }
    });
  });
})();
"""


def _marker(char: str) -> str:
    return f"&lt;U+{ord(char):04X}&gt;"


def _visible_text(value: Any, *, keep_newlines: bool = False) -> str:
    """Escape a value for HTML, with every invisible character shown as a marker.

    Control and format characters never reach the output as themselves, so a raw
    ESC cannot bleed a terminal escape into a copied line and a zero-width space
    cannot hide inside a rendered payload. ``keep_newlines`` is for a block this
    module laid out itself: a newline inside payload text arrives already escaped
    by the JSON or YAML dump around it.
    """
    parts: list[str] = []
    for char in str(value):
        if char == " " or (keep_newlines and char == "\n"):
            parts.append(char)
        elif unicodedata.category(char) in _INVISIBLE_CATEGORIES:
            parts.append(_marker(char))
        else:
            parts.append(html.escape(char, quote=True))
    return "".join(parts)


def _visible(value: Any, *, keep_newlines: bool = False) -> str:
    """Same as :func:`_visible_text`, with each marker wrapped for styling."""
    parts: list[str] = []
    for char in str(value):
        if char == " " or (keep_newlines and char == "\n"):
            parts.append(char)
        elif unicodedata.category(char) in _INVISIBLE_CATEGORIES:
            parts.append(f'<span class="ctl">{_marker(char)}</span>')
        else:
            parts.append(html.escape(char, quote=True))
    return "".join(parts)


def _arguments_block(arguments: dict[str, Any]) -> str:
    if not arguments:
        return '<span class="muted">none</span>'
    dumped = json.dumps(arguments, indent=2, sort_keys=True, ensure_ascii=False)
    body = _visible(dumped, keep_newlines=True)
    return f"<details><summary>arguments</summary><pre>{body}</pre></details>"


def _outcome_badge(result: AttackResult, *, safe: bool) -> str:
    """Status badge keyed on the outcome, so a false positive cannot read as a win."""
    outcome = result_outcome(result, safe=safe)
    observed = result.observed_behavior or observed_from_result(result, safe=safe)

    if outcome == OUTCOME_FALSE_NEGATIVE:
        if is_known_gap(result.payload):
            return '<span class="badge warn">KNOWN GAP</span>'
        if observed == OBSERVED_NEUTRALIZE:
            return '<span class="badge warn">NEUTRALIZED ONLY</span>'
        return '<span class="badge bad">MISSED</span>'
    if outcome == OUTCOME_TRUE_ALLOW and observed == OBSERVED_EVALUATED:
        return '<span class="badge info">ALLOWED (safe)</span>'
    if outcome not in _OUTCOME_LABELS:
        if observed == OBSERVED_NEUTRALIZE:
            return '<span class="badge info">NEUTRALIZED</span>'
        if observed == OBSERVED_REDACT:
            return '<span class="badge info">REDACTED</span>'
        return '<span class="badge good">BLOCKED</span>'
    label, css = _OUTCOME_LABELS[outcome]
    return f'<span class="badge {css}">{label}</span>'


def _row_groups(result: AttackResult, *, safe: bool) -> str:
    """Filter tokens for one detail row, read by the inline filter script."""
    observed = result.observed_behavior or observed_from_result(result, safe=safe)
    tokens = [result_outcome(result, safe=safe)]
    if is_known_gap(result.payload):
        tokens.append("known_gap")
    if observed == OBSERVED_NEUTRALIZE:
        tokens.append("neutralized")
    return " ".join(tokens)


def _ordered(results: list[AttackResult], *, safe: bool) -> list[AttackResult]:
    return sorted(
        results,
        key=lambda r: (
            OUTCOME_ORDER.get(result_outcome(r, safe=safe), 9),
            r.payload.name,
            r.payload.id,
        ),
    )


def _headline(report: ScanReport, matrix: ConfusionMatrix) -> list[str]:
    """The two rates side by side, never one of them alone."""
    detection_sub = f"{matrix.true_block} of {matrix.attack_total} attack payloads stopped"
    if matrix.attack_total == 0:
        detection_sub = "no observable attack payloads, so detection was not measured"
    over_sub = f"{matrix.false_positive} of {matrix.benign_total} benign payloads refused"
    if matrix.benign_total == 0:
        over_sub = "no benign payloads, so over-blocking was not measured"

    return [
        '<div class="pair">',
        '<div class="stat detection">',
        '<div class="label">Detection</div>',
        f'<div class="value">{format_rate(matrix.detection_rate)}</div>',
        f'<div class="sub">{_visible_text(detection_sub)}</div>',
        "</div>",
        '<div class="stat overblock">',
        '<div class="label">Over-block</div>',
        f'<div class="value">{format_rate(matrix.false_positive_rate)}</div>',
        f'<div class="sub">{_visible_text(over_sub)}</div>',
        "</div>",
        '<div class="stat balanced">',
        '<div class="label">Balanced</div>',
        f'<div class="value">{format_rate(matrix.balanced_score)}</div>',
        '<div class="sub">detection minus over-block</div>',
        "</div>",
        "</div>",
        '<p class="muted">Read detection and over-block together. Detection on its own rises'
        " whenever a rule gets broader, including when it starts refusing legitimate calls,"
        " which is what the over-block figure is here to show.</p>",
    ]


def _matrix_table(matrix: ConfusionMatrix, *, include_known_gaps: bool) -> list[str]:
    gap_scope = "counted in the rates" if include_known_gaps else "held out of the rates"
    return [
        "<h2>Confusion matrix</h2>",
        '<div class="scroll">',
        '<table class="matrix">',
        "<caption>Expected behavior against what the proxy was observed to do.</caption>",
        "<thead><tr><th></th><th>Proxy acted</th><th>Proxy allowed</th></tr></thead>",
        "<tbody>",
        "<tr><th>Expected block or redact</th>"
        f'<td class="good"><span class="cellcount">{matrix.true_block}</span>'
        '<span class="cellname">true block</span></td>'
        f'<td class="bad"><span class="cellcount">{matrix.false_negative}</span>'
        '<span class="cellname">false negative</span></td></tr>',
        "<tr><th>Expected allow</th>"
        f'<td class="over"><span class="cellcount">{matrix.false_positive}</span>'
        '<span class="cellname">false positive</span></td>'
        f'<td class="good"><span class="cellcount">{matrix.true_allow}</span>'
        '<span class="cellname">true allow</span></td></tr>',
        "</tbody>",
        "</table>",
        "</div>",
        '<ul class="meta">',
        f"<li><strong>{matrix.indeterminate}</strong> indeterminate: the call never reached policy,"
        " so nothing about it was measured and it is in no cell above.</li>",
        f"<li><strong>{matrix.neutralized}</strong> neutralized: the injected result was fenced"
        " rather than blocked or redacted. Its own state, counted here whatever it scored.</li>",
        f"<li><strong>{matrix.known_gap}</strong> known gaps ({gap_scope}).</li>",
        "</ul>",
    ]


def _counts_table(report: ScanReport, matrix: ConfusionMatrix) -> list[str]:
    attack_total = report.attack_total or matrix.attack_total
    benign_total = report.benign_total or matrix.benign_total
    rows = [
        ("Total payloads", report.total_attacks),
        ("Attack payloads", attack_total),
        ("Benign payloads", benign_total),
        ("Blocked", report.blocked),
        ("Redacted", report.redacted),
        ("Neutralized", report.neutralized),
        ("Passed through (vulnerable)", report.passed),
        ("Policy allowed (safe, not executed)", report.policy_allowed_safe),
        ("Vulnerability score (attack payloads only)", f"{report.vulnerability_score}%"),
    ]
    lines = [
        "<h2>Counts</h2>",
        '<div class="scroll">',
        "<table>",
        "<thead><tr><th>Metric</th><th class='num'>Value</th></tr></thead>",
        "<tbody>",
    ]
    for label, value in rows:
        lines.append(
            f"<tr><th>{_visible_text(label)}</th>"
            f"<td class='num'>{_visible_text(value)}</td></tr>"
        )
    lines.extend(["</tbody>", "</table>", "</div>"])
    return lines


def _matched_spans(result: AttackResult) -> list[Finding]:
    """Re-inspect a payload's own arguments to locate what a reader can act on.

    The proxy's block error names the rule but carries no span, so the span is
    recovered here by running the same input inspector over the arguments the
    scanner sent. A policy rule with a pattern of its own can block without this
    producing anything, which the section says rather than implying a clean match.
    """
    inspector = InputInspector()
    return inspector.inspect(result.payload.tool, result.payload.arguments)


def _false_positive_section(report: ScanReport, results: list[AttackResult]) -> list[str]:
    lines = ['<section class="card fp">', "<h2>False positives</h2>"]
    if not results:
        if not any(not is_attack_payload(r.payload) for r in report.results):
            lines.append(
                '<p class="muted">No benign payloads in this scan, so over-blocking was not'
                " measured. That is not the same as none.</p>"
            )
        else:
            lines.append('<p class="muted">No benign payload was refused.</p>')
        lines.append("</section>")
        return lines

    lines.append(
        f"<p>{len(results)} legitimate call(s) the policy refused. The rule message names what"
        " to narrow; the matched span is where in the argument it fired.</p>"
    )
    for result in sorted(results, key=lambda r: (r.payload.name, r.payload.id)):
        lines.append('<div class="evidence">')
        lines.append(
            f"<h3>{_visible(result.payload.name)}"
            f' <span class="muted mono">{_visible(result.payload.id)}</span></h3>'
        )
        lines.append(
            f'<p class="muted">tool <code>{_visible(result.payload.tool)}</code>'
            f" &middot; category {_visible(result.payload.category)}</p>"
        )
        lines.append(
            f"<p><strong>Rule:</strong> {_visible(blocking_rule_message(result))}</p>"
        )
        findings = _matched_spans(result)
        if findings:
            lines.append("<p><strong>Matched span:</strong></p>")
            lines.append('<div class="scroll"><table>')
            lines.append(
                "<thead><tr><th>Field</th><th>Span</th><th>Matched text</th>"
                "<th>Pattern</th><th>View</th></tr></thead><tbody>"
            )
            for finding in findings:
                span = "" if finding.span is None else f"{finding.span[0]}-{finding.span[1]}"
                lines.append(
                    f"<tr><td class='mono'>{_visible(finding.field or '')}</td>"
                    f"<td class='mono'>{_visible(span)}</td>"
                    f"<td class='mono'>{_visible(finding.matched_text or '')}</td>"
                    f"<td class='mono'>{_visible(finding.matched_pattern or '')}</td>"
                    f"<td class='mono'>{_visible(finding.view)}</td></tr>"
                )
            lines.append("</tbody></table></div>")
        else:
            lines.append(
                '<p class="muted">No span recovered from the input inspector, so the block came'
                " from a policy rule pattern. The arguments below are what was refused.</p>"
            )
        lines.append(_arguments_block(result.payload.arguments))
        lines.append("</div>")
    lines.append("</section>")
    return lines


def _neutralized_section(report: ScanReport, results: list[AttackResult]) -> list[str]:
    lines = ["<h2>Neutralized</h2>"]
    if not results:
        lines.append(
            '<p class="muted">Nothing was neutralized in this scan.</p>'
        )
        return lines
    lines.append(
        "<p>Results the proxy fenced instead of blocking or redacting. The tool ran and the"
        " model still sees the text, wrapped in a warning, so these are neither blocked nor"
        " passed through.</p>"
    )
    lines.append('<div class="scroll"><table>')
    lines.append(
        "<thead><tr><th>Payload</th><th>Tool</th><th>Expected</th><th>Outcome</th>"
        "<th>Notes</th></tr></thead><tbody>"
    )
    for result in sorted(results, key=lambda r: (r.payload.name, r.payload.id)):
        lines.append(
            f"<tr><td>{_visible(result.payload.name)}</td>"
            f"<td class='mono'>{_visible(result.payload.tool)}</td>"
            f"<td>{_visible(normalize_expected(result.payload.expected_behavior))}</td>"
            f"<td>{_outcome_badge(result, safe=report.safe_mode)}</td>"
            f"<td>{_visible(result.notes)}</td></tr>"
        )
    lines.append("</tbody></table></div>")
    return lines


def _known_gap_section(report: ScanReport, results: list[AttackResult]) -> list[str]:
    lines = ["<h2>Known gaps</h2>"]
    if not results:
        lines.append('<p class="muted">No payload in this scan declares known_gap.</p>')
        return lines
    scope = "counted in" if report.include_known_gaps else "excluded from"
    lines.append(
        f"<p>{len(results)} payload(s) with no detection written for them yet, {scope} the"
        " detection rate above. A gap is not a pass: nothing here was stopped by design."
        " A row that now reads <code>block</code> has started being caught and should lose"
        " its flag.</p>"
    )
    lines.append('<div class="scroll"><table>')
    lines.append(
        "<thead><tr><th>Payload</th><th>Category</th><th>Tool</th><th>Expected</th>"
        "<th>Observed</th><th>What it tests</th></tr></thead><tbody>"
    )
    for result in sorted(results, key=lambda r: (r.payload.category, r.payload.name, r.payload.id)):
        observed = result.observed_behavior or observed_from_result(result, safe=report.safe_mode)
        lines.append(
            f"<tr><td>{_visible(result.payload.name)}</td>"
            f"<td>{_visible(result.payload.category)}</td>"
            f"<td class='mono'>{_visible(result.payload.tool)}</td>"
            f"<td>{_visible(normalize_expected(result.payload.expected_behavior))}</td>"
            f"<td>{_visible(observed)}</td>"
            f"<td>{_visible(result.payload.description)}</td></tr>"
        )
    lines.append("</tbody></table></div>")
    return lines


def _detail_section(report: ScanReport) -> list[str]:
    lines = [
        "<h2>Every payload</h2>",
        '<div class="controls" id="controls" hidden>',
        '<button type="button" data-filter="all" aria-pressed="true">All</button>',
        f'<button type="button" data-filter="{OUTCOME_FALSE_NEGATIVE}">Missed</button>',
        f'<button type="button" data-filter="{OUTCOME_FALSE_POSITIVE}">Over-blocked</button>',
        '<button type="button" data-filter="neutralized">Neutralized</button>',
        '<button type="button" data-filter="known_gap">Known gaps</button>',
        f'<button type="button" data-filter="{OUTCOME_INDETERMINATE}">Unmeasured</button>',
        "</div>",
        '<div class="scroll">',
        '<table id="detail">',
        "<thead><tr><th>Outcome</th><th>Expected</th><th>Observed</th><th>Severity</th>"
        "<th>Category</th><th>Payload</th><th>Tool</th><th>Notes</th><th>Arguments</th>"
        "</tr></thead>",
        "<tbody>",
    ]
    for result in _ordered(report.results, safe=report.safe_mode):
        observed = result.observed_behavior or observed_from_result(result, safe=report.safe_mode)
        gap = ' <span class="badge warn">gap</span>' if is_known_gap(result.payload) else ""
        lines.append(
            f'<tr data-group="{_row_groups(result, safe=report.safe_mode)}">'
            f"<td>{_outcome_badge(result, safe=report.safe_mode)}</td>"
            f"<td>{_visible(normalize_expected(result.payload.expected_behavior))}</td>"
            f"<td>{_visible(observed)}</td>"
            f"<td>{_visible(result.payload.severity)}</td>"
            f"<td>{_visible(result.payload.category)}</td>"
            f"<td>{_visible(result.payload.name)}{gap}<br>"
            f"<span class='muted mono'>{_visible(result.payload.id)}</span></td>"
            f"<td class='mono'>{_visible(result.payload.tool)}</td>"
            f"<td>{_visible(result.notes)}</td>"
            f"<td>{_arguments_block(result.payload.arguments)}</td></tr>"
        )
    lines.extend(["</tbody>", "</table>", "</div>"])
    return lines


def _rules_section(suggested_rules: list[dict[str, Any]] | None) -> list[str]:
    lines = ["<h2>Recommended rules</h2>"]
    if not suggested_rules:
        lines.append(
            '<p class="muted">No autogenerated rules: nothing passed through that a'
            " pattern rule could address.</p>"
        )
        return lines
    dumped = yaml.dump(suggested_rules, default_flow_style=False, sort_keys=False)
    lines.append(f"<pre>{_visible(dumped, keep_newlines=True)}</pre>")
    return lines


def _header(report: ScanReport, matrix: ConfusionMatrix) -> list[str]:
    lines = [
        "<h1>AgentParry security scan report</h1>",
        '<ul class="meta">',
        f"<li>Date (UTC): {_visible_text(report.timestamp.isoformat())}</li>",
        f"<li>Target: <code>{_visible(report.target_url)}</code></li>",
        f"<li>Safe mode: {'yes' if report.safe_mode else 'no'}</li>",
    ]
    if report.discovered_tools:
        tools = ", ".join(report.discovered_tools)
        lines.append(f"<li>Tools discovered: <code>{_visible(tools)}</code></li>")
    if report.payload_stats:
        stats = json.dumps(report.payload_stats, sort_keys=True, ensure_ascii=False)
        lines.append(f"<li>Payload stats: <code>{_visible(stats)}</code></li>")
    lines.append("</ul>")
    if report.safe_mode:
        lines.append(
            '<p class="banner info">Safe mode: nothing was forwarded upstream, so the matrix'
            " below is the only measure of what policy did, and the vulnerability score is"
            " structurally zero.</p>"
        )
    if matrix.known_gap and not report.include_known_gaps:
        lines.append(
            f'<p class="banner">{matrix.known_gap} payload(s) declare known_gap and are held out'
            " of every rate below. They are listed in their own section, not folded into a pass.</p>"
        )
    return lines


def render_html_report(
    report: ScanReport, suggested_rules: list[dict[str, Any]] | None = None
) -> str:
    """Render one scan report as a single self-contained HTML document.

    Deterministic: the only timestamp in the output is the report's own, ids come
    from payloads, and every collection is sorted, so two renders of the same
    report are byte-identical.
    """
    matrix = report.matrix or compute_confusion_matrix(
        report.results, safe=report.safe_mode, include_known_gaps=report.include_known_gaps
    )
    safe = report.safe_mode
    false_positives = [
        r for r in report.results if result_outcome(r, safe=safe) == OUTCOME_FALSE_POSITIVE
    ]
    neutralized = [
        r
        for r in report.results
        if (r.observed_behavior or observed_from_result(r, safe=safe)) == OBSERVED_NEUTRALIZE
    ]
    gaps = [r for r in report.results if is_known_gap(r.payload)]

    body: list[str] = ["<main>"]
    body.extend(_header(report, matrix))
    body.extend(_headline(report, matrix))
    body.extend(_matrix_table(matrix, include_known_gaps=report.include_known_gaps))
    body.extend(_false_positive_section(report, false_positives))
    body.extend(_known_gap_section(report, gaps))
    body.extend(_neutralized_section(report, neutralized))
    body.extend(_counts_table(report, matrix))
    body.extend(_detail_section(report))
    body.extend(_rules_section(suggested_rules))
    body.append(
        "<footer>Generated by AgentParry. Payload text is escaped and invisible characters are"
        " shown as <span class=\"ctl\">&lt;U+XXXX&gt;</span> markers, so nothing in this corpus"
        " renders as live markup or reaches a terminal as an escape sequence.</footer>"
    )
    body.append("</main>")

    title = _visible_text(f"AgentParry scan report - {report.target_url}")
    document = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{title}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        *body,
        f"<script>{_SCRIPT}</script>",
        "</body>",
        "</html>",
        "",
    ]
    return "\n".join(document)
