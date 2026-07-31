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
- **2 findings total across 75 tools**, both `medium`, both from the structural
  heuristics rather than the pattern table: an opaque base64-shaped blob in
  `everything`'s `gzip-file-as-resource` schema default (it is a real URL fragment),
  and `sequential-thinking`'s 2781-character description tripping the 2000-character
  oversize rule.
- **The shipped default (`action: redact`, `severity_threshold: critical`) rewrote
  nothing.** 0 tools dropped, 0 descriptions redacted, 0 tool lists blocked, across
  all eight servers. `severity_threshold: high` is equally inert.

The reason the patterns hold up is that they are narrow in the right place. Real
descriptions do contain imperative prose, but not the *specific* imperative prose
the patterns look for. Measured over the same 76 leaves: `must` appears twice,
`use this tool` twice, `always` once, `only` fourteen times, `ignore` once. The
live patterns require far more than that, and none of the near-misses reach them:
0 hits for `first, you must`, 0 for `before using this tool`, 0 for
`always call X first`, 0 for `do not tell/reveal/mention`, 0 for any XML-ish tag at
all, 0 for a sensitive path.

**The number to start quoting: 0 actionable metadata findings on 75 real tools from
8 servers, at the shipped default.** That is the real false-positive figure and it
replaces the residual-risk caveat in the `MetadataInspector` docstring.

### The one place it does damage a working tool

`severity_threshold: medium` is not a free tightening. At medium the same corpus
loses two capabilities:

- `everything`'s `gzip-file-as-resource` is **dropped entirely**. The blob finding
  is on `inputSchema.properties.data.default`, a non-prose leaf, so redaction
  escalates to dropping the tool.
- `sequential-thinking`'s `sequentialthinking` description is **fully redacted**.
  That description *is* the tool: it is a 2781-character spec of how to use it, and
  replacing it with a marker leaves the model a tool it cannot drive.

So the critical-only default is doing real work, and lowering it should be an
explicit, per-server decision. `MAX_DESCRIPTION_CHARS = 2000` is also too low for
real servers: one legitimate description in eight already exceeds it.

## Tool-name remapping in `--discover` lied, and now refuses to guess

### What it used to do

Four payload tool names against eight servers produced 11 mappings, and not one of
them was the same kind of thing as the payload:

```
file_read   -> edit_file / read_file     (filesystem, depending on tool order)
email_send  -> read_file                 (filesystem)
file_read   -> gzip-file-as-resource     (everything)
email_send  -> get-annotated-message     (everything)
shell_exec  -> git_show                  (git)
file_read   -> open_nodes / read_graph   (memory)
file_read   -> browser_file_upload       (playwright)
shell_exec  -> browser_snapshot / browser_take_screenshot  (playwright)
http_fetch  -> browser_click / browser_close               (playwright)
email_send  -> browser_console_messages  (playwright)
```

Two causes. `difflib.get_close_matches` at cutoff 0.55 finds a nearest string in any
list of decent size, and the keyword hints matched substrings, which is how `sh`
matched `browser_take_screenshot`. Note the pairs that differ above: the target
depended on the order the server happened to list its tools in, because the old code
took the first hint hit it saw.

**It was unsafe outside `--safe`, concretely.** `file_read` mapped to
`browser_file_upload` on playwright and to `edit_file` on filesystem. A path-traversal
payload written to test a read tool was delivered to a write tool.

### What it does now

A mapping is accepted only on evidence that the candidate does the same kind of thing:

- **The payload's own arguments are the requirement.** `file_read` carries `path`,
  `shell_exec` carries `command`, `email_send` carries `to`/`subject`/`body`. The
  candidate's `inputSchema` has to declare every one of them, with a compatible type
  and no violated `enum`, and every property it marks `required` has to be one the
  payload supplies. That kills `edit_file` (needs `edits`), `browser_file_upload`
  (takes `paths`, an array) and everything on `memory` and `git` at once.
- **The tool's name has to say it does that job**, as whole tokens rather than
  substrings, and must not carry a mutating verb the capability does not claim. That
  is what stops a read payload landing on `create_directory`, which takes exactly one
  required `path` and was the residual risk in the old design.
- **`difflib` only breaks ties** between candidates that already passed both gates.
- **Anything else is unmapped**, reported as a gap, and never sent.

Per server, payloads mapped out of 65:

| Server | Before | After | Mappings after |
|---|---|---|---|
| everything | 35 | 0 | none |
| fetch | 9 | 9 | `http_fetch -> fetch` |
| filesystem | 35 | 15 | `file_read -> read_file` |
| git | 20 | 0 | none |
| memory | 15 | 0 | none |
| playwright | 65 | 9 | `http_fetch -> browser_navigate` |
| sequential-thinking | 0 | 0 | none |
| time | 0 | 0 | none |

179 mapped payloads become 33. All three surviving mappings are the same kind of
thing as the payload; 1 of the previous 11 was. The drop is the point: no server in
this corpus runs shell commands or sends email, so 21 `shell_exec` and 20
`email_send` payloads have nowhere honest to go on any of them.

The one true positive the argument gate costs is playwright's
`browser_run_code_unsafe`, which really does execute code but takes `code` rather
than `command`. The schema-driven probe generator reaches it anyway.

**Recommendation, implemented: refuse low-confidence mappings outside `--safe`.**
Description-only evidence (`weak`) is accepted only in safe mode, where nothing is
forwarded upstream and a wrong guess costs a policy evaluation rather than a real
call. On this corpus the weak tier fires zero times, so the gate costs no coverage
today and bounds the damage of any future loosening.

**Stop reading "matched N of 65" as coverage.** The scan report now carries mapped
and unmapped counts, the accepted mappings with their confidence and the evidence
each rested on, and how many payloads were refused for low confidence. A mapped
payload tested one tool; an unmapped payload tested nothing and says so.

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

## Pinning survives a real `tools/list`. Pagination does not

Per server, three consecutive observations of the same real `tools/list`:
`created`, `unchanged`, `unchanged`. Same for `initialize`. Set fingerprints are
order-independent on all eight real catalogues. Nothing spurious, no drift.

**No real server in the corpus paginates `tools/list`.** All eight return a single
page with no `nextCursor`, including playwright at 24 tools.

Which is why this is broken. `_observe_tools_list` decides `paginated` from
`nextCursor` on the page in hand. The *last* page of a paginated response has no
`nextCursor`, so it is diffed as if it were the complete catalogue. Splitting
playwright's real 24-tool catalogue into two pages produces, on page two, a
`changed` observation with **12 tools removed and 12 added** — a full rug-pull
warning on a server that did nothing. It recurs on every discovery and the pin
never converges. The MCP spec allows cursor pagination on `tools/list`, so this is
a live bug that no reference server happens to trigger.

`test_paginated_tools_list_produces_a_spurious_diff` pins the broken behavior so a
fix is visible when it lands. The fix is to carry the paginated flag across a
cursor walk rather than deriving it per page.

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
- "matched N of 65 payloads" as discovery coverage. Mapped and unmapped are both
  reported now, and neither is coverage.

Start:

- 0 actionable metadata findings on 75 real tools from 8 servers, at the shipped
  default. 2 total findings, both `medium`, both below threshold.
- 71% of schema-driven probes are schema-valid; 29% of real tools get no injection
  probe at all.
- Pins settle on all 8 real catalogues; the paginated path is broken.

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
