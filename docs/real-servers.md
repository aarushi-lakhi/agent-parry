# AgentParry against real MCP servers

Every number this project quoted before this document came from `src/mock_server.py`:
four tools we wrote ourselves, described in prose we wrote ourselves. This is what
happened when the same code was pointed at eight real MCP servers.

Discovery only. No `tools/call` was ever sent to any of these servers, so nothing
here required `--safe` and nothing could act.

## The corpus

Captured once through `src/proxy.py` and committed under
`tests/fixtures/real_servers/`. 8 servers, 75 tools, 76 prose leaves.

| Server | Command | Tools |
|---|---|---|
| filesystem | `npx -y @modelcontextprotocol/server-filesystem <dir>` | 14 |
| memory | `npx -y @modelcontextprotocol/server-memory` | 9 |
| sequential-thinking | `npx -y @modelcontextprotocol/server-sequential-thinking` | 1 |
| everything | `npx -y @modelcontextprotocol/server-everything` | 12 |
| playwright | `npx -y @playwright/mcp@latest --isolated --headless` | 24 |
| git | `uvx --with "mcp<2" mcp-server-git --repository <dir>` | 12 |
| fetch | `uvx --with "mcp<2" mcp-server-fetch` | 1 |
| time | `uvx --with "mcp<2" mcp-server-time` | 2 |

All eight answered protocol version `2025-06-18`. Only `everything` returns an
`initialize.instructions` string; the other seven return none, so the
instruction-poisoning surface the `initialize` inspector exists for is absent from
most real servers.

The three Python reference servers fail out of the box. `uvx mcp-server-git`,
`uvx mcp-server-fetch` and `uvx mcp-server-time` all resolve `mcp` 2.x and crash on
import (`cannot import name 'McpError' from 'mcp.shared.exceptions'`, and
`'Server' object has no attribute 'list_tools'` for git). Pinning `--with "mcp<2"`
fixes all three. That is an upstream packaging break, not ours, but anyone
reproducing this capture needs the pin.

Re-run the capture yourself with `scripts/capture_real_corpus.py`.

## MetadataInspector does not false-positive on real tool descriptions

This was the expected failure, and it did not happen.

- **0 of 16 injection patterns matched any of 76 real prose leaves.** Not one hit
  from `INJECTION_PATTERNS` or `METADATA_PATTERNS`, in any severity.
- **0 findings total across 75 tools**, at any severity. The capture originally
  produced two, both `medium`, both from the structural heuristics rather than the
  pattern table, and both were the heuristic being wrong rather than the server
  being suspicious. Fixing them is the section below.
- **The shipped default (`action: redact`, `severity_threshold: critical`) rewrote
  nothing.** 0 tools dropped, 0 descriptions redacted, 0 tool lists blocked, across
  all eight servers. So is `high`, and so, now, is `medium`.

The reason the patterns hold up is that they are narrow in the right place. Real
descriptions do contain imperative prose, but not the *specific* imperative prose
the patterns look for. Measured over the same 76 leaves: `must` appears twice,
`use this tool` twice, `always` once, `only` fourteen times, `ignore` once. The
live patterns require far more than that, and none of the near-misses reach them:
0 hits for `first, you must`, 0 for `before using this tool`, 0 for
`always call X first`, 0 for `do not tell/reveal/mention`, 0 for any XML-ish tag at
all, 0 for a sensitive path.

**The number to start quoting: 0 metadata findings on 75 real tools from 8
servers, at any severity.** That is the real false-positive figure and it
replaces the residual-risk caveat in the `MetadataInspector` docstring.

### The two places it used to damage a working tool

At `severity_threshold: medium` the same corpus used to lose two capabilities.
Both were the heuristic misreading a normal server, and both are fixed.

**`everything`'s `gzip-file-as-resource` was dropped entirely.** The opaque-blob
rule matched `com/modelcontextprotocol/servers/refs/heads/main/README` inside
`inputSchema.properties.data.default`, which holds a real
`raw.githubusercontent.com` URL. The finding sits on a non-prose leaf, so
redaction escalates to dropping the tool.

The obvious fix is to exempt the `default` key the way `pattern` and `format`
already are. That is the wrong fix. A schema default is model-facing text an
attacker controls, and being non-prose it is precisely the leaf where a finding
costs the whole tool, so blinding the rule to it gives up a real surface. The key
is not what made this a false positive: the *value* is a URL, and a URL path is
long, mixed-case, punctuation-heavy and does not decode to text, which is the
blob shape exactly. The same URL in a `description` would have matched too. So
the suppression is on URL spans wherever they appear, on both the argument side
and the metadata side, and `default` stays scanned. A blob sitting next to a URL
is still a finding; a blob that *is* the URL is not.

**`sequential-thinking`'s `sequentialthinking` description was fully redacted.**
That description *is* the tool, a 2781-character spec of how to drive it, and
replacing it with a marker leaves the model a tool it cannot use and no
explanation.

Two things were wrong. `MAX_DESCRIPTION_CHARS = 2000` was too low, and the
finding was `medium`, which made it actionable.

The distribution over all 75 real descriptions:

| | chars |
|---|---|
| min | 14 |
| median | 57 |
| p90 | 323 |
| p95 | 360 |
| second largest | 457 |
| max | 2781 |
| all 75 combined | 10,732 |

74 of 75 sit under 460 and one sits at 2781, so the corpus sets a floor rather
than a target: **any cap between 460 and 2781 catches only a legitimate tool.**
The cap is now **8000**, roughly 2000 tokens, near three times the outlier and
three quarters of what all eight servers spend on all 75 descriptions put
together. It stays below `MAX_METADATA_LEAF_CHARS = 20000` so the signal is still
reachable before a leaf is dropped from scanning entirely.

The finding is also **`low` now, not `medium`**, which means it can never reach a
severity threshold on its own. Length is a fact about the author, not the
content. A wall of text is where an instruction hides, but it is not evidence
that one is there, and the pattern tables and the invisible-character rule are
what find it when it is. An oversize finding still shows up in a report and in
the audit log, where a human can weigh it; what it no longer does is silently
cost the model a tool for the crime of being documented thoroughly.

With both fixed, `severity_threshold: medium` is inert on the corpus too, so
lowering it is no longer a per-server judgement call.

## Tool-name remapping in `--discover` mostly fails, and when it succeeds it lies

30 (server, payload-tool) pairs, four payload tool names against eight servers:

| Mechanism | Count |
|---|---|
| exact match | 0 |
| casefold match | 0 |
| `difflib` fuzzy match | 2 |
| keyword hint | 9 |
| unmapped | 21 |

Not one of the 11 successful mappings is semantically right:

```
file_read   -> edit_file                 (filesystem)
email_send  -> read_file                 (filesystem)
shell_exec  -> git_show                  (git)
file_read   -> open_nodes                (memory)
shell_exec  -> browser_snapshot          (playwright)
http_fetch  -> browser_click             (playwright)
email_send  -> browser_console_messages  (playwright)
```

Two consequences.

**`--discover` is unsafe outside `--safe`, concretely.** `file_read` maps to
`edit_file` on the reference filesystem server. A path-traversal payload written to
test a read tool is delivered to a write tool. It happens to bounce off schema
validation today because `edit_file` also requires `edits`, but the design does not
prevent this, and a server whose write tool has a single required path argument
would take it.

**"Matched N of 65 payloads" measures tool-name count, not coverage.** Against
playwright's 24 tools it reports **65 of 65 matched, 100%**, because with enough
names `difflib` at cutoff 0.55 always finds something. Against sequential-thinking
and time it reports 0. The number tracks how many names the server exposes, and a
scan that reports 100% matched against playwright has tested nothing about
playwright.

Proposal: drop the `difflib` fallback, keep only exact, casefold and explicitly
curated hints, and report unmapped payloads as `unavailable` rather than remapping
them onto a stranger. `--discover` against an unrecognized server should lean on
the schema-driven probes, which at least know what they are aiming at.

## Schema-driven dynamic probes are mostly sensible, with two blind spots

149 probes generated across the corpus:

| Outcome | Count | Share |
|---|---|---|
| schema-valid | 106 | 71% |
| missing a required property | 28 | 19% |
| violates an `enum` | 15 | 10% |
| wrong JSON type for the property | 0 | 0% |

The 71% are genuinely good arguments: `{"path": "../../../etc/passwd"}` to
`read_file`, `{"url": "file:///etc/passwd"}` to `fetch`, the injection string into
`message` on `echo`. That part works.

The two failure modes are both in `fill_defaults`, which only fills *string*
properties:

- **Required non-string arguments are left out.** `get-sum` needs numbers `a` and
  `b`, `read_multiple_files` needs an array `paths`, `edit_file` needs an array
  `edits`. 28 probes are rejected with `-32602` before policy runs, which scores
  `observed=unavailable` / `outcome=indeterminate`. They cost a round trip and
  measure nothing.
- **`enum` constraints are ignored.** 15 probes push the injection string into a
  field constrained to `['error', 'success', 'debug']` or
  `['New York', 'Chicago', 'Los Angeles']`. Same wasted round trip.

Worse, **22 of 75 real tools (29%) get no injection probe at all**, because
`_schema_string_props` only looks at top-level `type: "string"`. Real servers put
strings inside arrays and objects: 17 of 75 tools have an `array` or `object`
property. All 9 of `memory`'s tools with arguments are shaped that way, so the
entire memory server is invisible to the probe generator.

Fixes, in value order: descend into `array`/`object` schemas to find string leaves;
pick a valid `enum` member and append the injection payload rather than replacing
the value; fill required non-strings with a schema-shaped default (`0`, `[]`, `{}`).

## Pinning survives a real `tools/list`, and now survives pagination too

Per server, three consecutive observations of the same real `tools/list`:
`created`, `unchanged`, `unchanged`. Same for `initialize`. Set fingerprints are
order-independent on all eight real catalogues. Nothing spurious, no drift.

**No real server in the corpus paginates `tools/list`.** All eight return a single
page with no `nextCursor`, including playwright at 24 tools.

Which is why this was broken. `_observe_tools_list` used to decide `paginated`
from `nextCursor` on the page in hand. The *last* page of a paginated response has
none, so it was diffed as if it were the complete catalogue. Splitting
playwright's real 24-tool catalogue into two pages produced, on page two, a
`changed` observation with **12 tools removed and 12 added** — a full rug-pull
warning on a server that did nothing. It recurred on every discovery and the pin
never converged. The MCP spec allows cursor pagination on `tools/list`, so this
was a live bug that no reference server happens to trigger.

A `tools/list` cursor walk is now correlated and diffed as one sequence. Pages are
buffered in memory on the pinner and keyed on the **request** `cursor`: a request
with no cursor starts a walk, a request carrying a cursor continues the walk that
handed that cursor out. Nothing reaches the pin store until the page without a
`nextCursor` arrives, so the same split playwright catalogue now reads `partial`,
`created`, then `partial`, `unchanged` on every later discovery. Splitting it 2,
3, 8 or 24 ways pins the identical set fingerprint.

What that costs, stated as assumptions:

- **One walk is in flight per server key at a time.** A second walk starting
  (a request with no cursor) discards whatever the first had buffered.
- **A walk whose first page this proxy never saw is never recorded.** An orphan
  continuation, a cursor that does not match the open walk, and a walk past the
  page or tool budget all end in `partial` with the pin untouched. A half-fetched
  catalogue recorded as the whole one would pin a subset and then report every
  later full listing as a pile of additions, which is worse than recording
  nothing.
- **A client that abandons pagination costs nothing.** The buffer is dropped by
  the next page-one request, or by a 300-second TTL, whichever comes first.
- **Interleaved traffic is fine.** Only `tools/list` touches the walk, so a
  `tools/call` or an `initialize` between pages passes through it.
- **A caller that passes no request params** (the CLI, a direct `observe` call)
  falls back to appending to whatever walk is still open. Weaker, but still
  convergent for a plain sequential fetch.

## The benign corpus does not resemble real traffic

`attacks/payloads.yaml` ships 15 benign payloads over 4 mock tool names, using 6
argument names: `to`, `subject`, `body`, `command`, `path`, `url`. The real corpus
has 98 distinct property names, of which exactly **2 overlap: `path` and `url`**.
Benign payloads carry either 1 or 3 arguments; real tools go up to 9. Real schemas
use `array`, `object`, `boolean`, `number` and `integer` properties, none of which
any benign payload exercises.

**Stop quoting "over-block 0%" as a property of AgentParry.** It is 0 out of 15
hand-written payloads against 4 tool names that exist on none of these eight
servers. Combined with the remapping result above, on a real server those benign
payloads either do not run at all (5 of 8 servers) or run against an arbitrarily
chosen tool, so the figure transfers to nothing. `--discover --safe` does generate
one benign probe per real tool, which is the right shape, but 43 of 149 probes are
schema-invalid, so that measurement is not clean either.

The same caveat applies to the mock-server detection rate. It is a regression
number for a fixed input set, not a measured detection rate against real servers.

## What to stop and start quoting

Stop:

- "over-block 0%" as an AgentParry property. It is 0/15 on four mock tool names.
- "detection 86.2%" as a detection rate. It is a mock-server regression score.
- "matched N of 65 payloads" as discovery coverage. It counts server tool names.

Start:

- 0 metadata findings on 75 real tools from 8 servers, at any severity. Every
  threshold, `medium` included, rewrites nothing.
- 71% of schema-driven probes are schema-valid; 29% of real tools get no injection
  probe at all.
- Pins settle on all 8 real catalogues, and on a synthetic paginated one.

## Reproducing

```bash
python scripts/capture_real_corpus.py \
    --name filesystem \
    --command "npx -y @modelcontextprotocol/server-filesystem /private/tmp/mcp-scratch" \
    --scratch /private/tmp/mcp-scratch
```

Point any filesystem or git server at a throwaway directory you created. The
script sends `initialize` and `tools/list` only, walks `nextCursor` if the server
paginates, and sanitizes your home directory, hostname, username, the scratch path
and credential-shaped literals out of the fixture before writing it.

`tests/test_real_server_corpus.py` runs entirely against the committed fixtures. It
needs no network, no `npx` and no `uvx`.
