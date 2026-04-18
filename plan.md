# AgentParry Roadmap

Eighteen PRs, sequenced. Task IDs are stable identifiers, not execution order; work the waves top to bottom.

Each PR is a `<type>/<kebab-name>` branch into `main`, with its own commit split. Nothing gets pushed without explicit approval.

---

## Wave 0: foundations and live bugs

All small, all independent unless noted. These are either gating infrastructure or things that are wrong right now.

### 1. `chore/ci-and-ruff` (task 1)

CI gates every PR after it, so it goes first.

Measured, not guessed: ruff defaults give 155 violations, 152 of them `E501`. With `line-length = 120` and `select = ["E","F","W","I","UP","B","SIM","C4","RUF"]` it is exactly **32 violations, 17 auto-fixable**.

- Fix 30. Ignore 2: `SIM108` (suggested ternary is >100 chars, readability regression) and `UP042` (`StrEnum` on `PolicyAction`, deferred to its own PR rather than mutating the core enum inside a CI-setup PR).
- `B023` at `scanner.py:138-139` is a **traced false positive**: `fill_defaults` is only called within the same loop iteration. `noqa` with a reason; follow-up hoists it to module level.
- Four `SIM105` sites become `contextlib.suppress`. Three are the stdio fail-open handlers. Prefer rewriting all four and calling it out over a per-file ignore on the most security-sensitive file.
- Pin `ruff==0.15.17` in dev extras. Unpinned lint tools turn CI red on unrelated PRs when a new rule ships.
- Do **not** add `ruff format`: 10 of 20 files, 255 changed lines. Separate optional PR.
- Defer `D` (44 in `src/`, ~101 more in tests) as the best next family, since CLAUDE.md already asks for Google docstrings.

Commits: ruff config → autofixes → manual fixes → workflow.

### 2. `fix/console-markup-injection` (task 18)

`_print_log_line` calls `console.print(line)` with Rich markup enabled, and the line embeds raw tool arguments. An argument containing an unknown lowercase tag like `[notastyle]` raises `MissingStyle`, which the surrounding `except UnicodeEncodeError` does not catch, so an attacker-controlled argument turns a logged tool call into a 500. Valid tags like `[bold]` silently corrupt the line instead.

Fix: `markup=False`. Smallest real bug in the repo.

### 3. `fix/policy-control-plane-auth` (task 2)

`POST /policy/disable` sets `_bypass_all = True` with no authentication, because `_BearerAuthMiddleware` short-circuits when `AGENTPARRY_AUTH_TOKEN` is unset, which is the default.

**Tightening CORS does not fix this.** That request has no body and no custom headers, making it a CORS *simple request*: no preflight, so the origin allowlist is never consulted. A page fires it with `fetch(url, {mode:'no-cors'})` and the side effect lands. Only requiring an `Authorization` header fixes it, because a custom header forces a preflight that a non-allowlisted origin then fails.

- Delete `/policy/disable`, `/policy/enable`, and `_bypass_all` entirely.
- Gate `/policy/reload` and `/policy/rules` behind a new `AGENTPARRY_ADMIN_TOKEN`, **failing closed when unset** (the inversion of today). Separate from the data-plane token, which every MCP client holds and which should not confer policy-reload rights.
- Use a FastAPI dependency, not a second middleware: `add_middleware` prepends, CORS must stay outermost to answer preflights.
- Narrow CORS anyway. It currently lets any page read `/policy/rules` and `/stats`.
- `secrets.compare_digest` for both token comparisons.

Tradeoff: the kill switch is gone. Debugging a bad rule now means editing YAML plus `/policy/reload`, or restarting with a different `--policy`. Worth it.

Ripples: `demo.py` calls disable/enable for its "before" pass and must instead hit the mock server directly, which is more honest anyway ("unprotected agent" currently means "proxy running but neutered"). No stats are lost, since the bypass branch returns before `stats.increment`. Two existing tests change.

### 4. `fix/domain-allowlist-url-hosts` (task 7)

`_extract_domain` returns `None` unless the value contains `@`, and `None` takes the same branch as "not allowlisted". Three bugs, and the reported one is the least bad:

1. A `domain_allowlist` on a `url` field flags every value and can never allow one.
2. **False negative:** `http://evil.com/?u=a@example.com` extracts `example.com`, which is allowlisted, so the rule does not fire. The extractor is steerable into under-blocking.
3. **Live bypass in the shipped policy:** `to: "a@evil.com, b@company.com"` — `rsplit("@", 1)` yields `company.com`, allowlisted, so `flag_external_email` does not fire. Multi-recipient mail to an external address is unflagged today.

Fix with `urlsplit().hostname` (handles userinfo, ports, IPv6 brackets in one call), per-token extraction across comma-separated and list values, and fail-closed on unparseable tokens.

Subdomain semantics: **exact match by default**, opt in per condition with `include_subdomains: true`. Suffix-by-default would silently stop flagging `dev@mail.company.com`, and quietly relaxing enforcement as a side effect of a parsing bugfix is the wrong default.

Traced clean: no existing test changes, and the only `flag_external_email` behavior changes are tightenings.

### 5. `fix/rule-generator-tool-binding` (task 15)

`_rule_prompt_injection` / `_rule_data_exfiltration` / `_rule_privilege_escalation` hardcode `tool="email_send"` or `"shell_exec"` and ignore `payload.tool`. Under `--discover`, where payloads are remapped onto the server's real tool names, every generated rule targets a tool the server does not expose and can never match. Both `harden` and the Markdown report emit rules that look right and do nothing.

### 6. `fix/proxy-policy-flag` (task 14)

`proxy.py:31` builds `PolicyEngine()` at import with the hardcoded default path, and `main()` has no `--policy`. Pointing anything at an alternate policy file is inert, and `/policy/reload` re-reads the old default. Blocks any "write hardened rules elsewhere" workflow.

### 7. `fix/install-claude-double-wrap` (task 17)

Re-running `install-claude` against an already-wrapped entry nests a second proxy inside the first. Detect `args[:2] == ["-m", "src.stdio_proxy"]` and refuse. Also `_stdio_entry_from_existing` silently drops `timeout` and `alwaysLoad`.

### 8. `fix/http-transport-method-parity` (task 6)

The HTTP proxy forwards only `initialize` and `tools/list` and returns `-32601` for everything else, so it cannot proxy a server using `resources/read` or `prompts/get`. The stdio proxy forwards every non-`tools/call` method unchecked. Prerequisite for ever scanning those surfaces.

Decision: namespace allowlist (`notifications/`, `resources/`, `prompts/`, `logging/`, `completion/`, `roots/`, `sampling/`) plus an exact set for `initialize`, `ping`, `tools/list`, `tools/call`.

**Do not prefix-allow `tools/`.** `tools/call` dispatch is exact string equality in both proxies, so a prefix rule would let `tools/Call` or `tools/call2` route a tool invocation down the *uninspected* forward path against a lenient upstream. Treat any casefold match on `tools/call` as `tools/call`.

Keep the asymmetry deliberately: stdio still forwards unknown methods (fail-open is load-bearing; blocking a vendor extension would brick a live session), HTTP still refuses them. Parity is achieved for the known MCP surface, which is the actual complaint.

Out of scope, stated in the PR body: JSON-RPC notifications still 422 on HTTP because `JsonRpcRequest.id` is required.

Stack after PR 3, which deletes the `_bypass_all` branch this restructures.

---

## Wave 1: measurement before detection

### 9. `feat/scan-expected-vs-actual` (task 3)

This lands before any detection work so later PRs can prove they do not over-block.

`expected_behavior` is loaded and never compared to the observed result, so over-blocking is invisible. Add a third axis: expected / observed / outcome, plus a `ConfusionMatrix`.

**Includes a real bug fix.** `_classify_response` treats *any* JSON-RPC error as `was_blocked=True`. The mock server returns `-32601` for an unknown tool and `-32602` for bad params, so a payload aimed at a tool that does not exist scores as a successful block. Against the mock server all three tools exist so it barely shows; under `--discover` against a real server every unmatched payload counts as a win. Read `error.code`: only `-32001` is a proxy block.

Backwards compatibility is mandatory, since `ScanReport` is persisted and re-read via `--report-only`:

- Every new field optional with a default. `matrix` is nullable rather than defaulted to zeros, because a zeroed matrix on an old report is a lie. Render-time fallback recomputes from `results`.
- `vulnerability_score` keeps its formula; the denominator becomes attack-only payloads, which is numerically identical for today's all-block set. Without this, adding benign payloads silently deflates the score.

Ship nine benign `allow` payloads. **Three fail today, which is the point:**

| payload | blocked by | why |
|---|---|---|
| order reference `8f3b1c9d...` in an email body | `autogen_pi-003` | any 40+ char alnum run |
| "please disregard the old onboarding rules doc" | `autogen_pi-004` | `disregard.*rules` |
| `echo 'Docs say to avoid sudo when possible' >> notes.txt` | `block_dangerous_shell` | `sudo\s+` substring |

That is roughly a third of benign traffic over-blocked on day one. Real, defensible, and now measurable.

Headline becomes the detection / over-block **pair**, not one number. A single figure is what let the over-blocking hide. `balanced_score` exists for when one number is needed.

Also required here: `generate_rules` must skip benign payloads, or `save_scan_outputs` emits `autogen_*` rules that block legitimate traffic and demo phase 3 writes them into the policy file.

Safe mode: `expected: redact` is unobservable (the output inspector never runs) and scores `indeterminate`. Note that a safe scan always reports `vulnerability_score 0.0` today, since `evaluated_only` never lands in `passed`; the matrix is the only place safe-mode reality shows up.

---

## Wave 2: shared machinery

Both feed the detection wave. Doing them once here beats retrofitting three times.

### 10. `feat/normalize-before-match` (task 4)

Confirmed empirically: `pi-003`'s 68-char base64 body yields **zero** findings from `InputInspector`, whose pattern is `{100,}` while `rule_generator` uses `{40,}`. The committed autogen rule catches it, so the scan-generate-verify loop was masking the inspector's own blind spot. Zero-width, fullwidth, Cyrillic homoglyph, and percent-encoded variants of "ignore all previous instructions" all return `[]`.

New `src/normalize.py` producing `TextView` objects with offset maps back to the original, so a finding can still quote real input.

**The trap:** do not apply normalized views to `domain_allowlist`. Folding is fail-safe for denylist semantics and fail-**open** for allowlist semantics — folding Cyrillic-о `cоmpany.com` into `company.com` makes an attacker's confusable domain pass the allowlist. Restrict views to `pattern_match` and `pii_detection`. The correct treatment for allowlists is the inverse (flag mixed-script hosts as suspicious) and belongs in a follow-up. Say so in the PR body so a reviewer does not "fix" it by reflex.

Base64 rework, since `{40,}` matches any sha1 hex, sha256 hex, or long identifier:

- Decode fragments at min length 16 and run the ordinary patterns on the decoded view at ordinary severity. `pi-003` becomes `critical`, not `medium`. A JWT decodes to `{"alg":"HS256"}` and matches nothing.
- Keep `{40,}` only as a `medium` "opaque encoded blob" signal for runs that do not decode to text. 40 base64 chars carry 30 bytes, enough for "ignore all prior instructions" (29), so nothing shorter can carry a meaningful instruction. It also matches the value already baked into the autogen rules, keeping the loop self-consistent.

PolicyEngine: canonical view **on** by default (folding only ever makes a user's regex match text a human reads as identical, and the surprise direction is more blocking, which is fail-safe). Decoded views **off** by default — an `rm -rf /` rule suddenly firing on an opaque base64 string is a semantic leap, and BLOCK is unrecoverable over stdio. Global switch in `settings.normalization`, per-rule override.

Budgets: depth 3, 32 fragments, 16 KB per fragment, 64 KB total decoded, 1 MB input. No gzip/zlib in this PR; that is where real decompression bombs live and it needs a ratio guard.

ReDoS gets worse and is explicitly out of scope: decoded views let an attacker deliver a backtracking payload while the raw wire bytes look like inert base64. Budget-based mitigation only; a real fix needs regex timeouts plus a complexity guard in `_compile_patterns`.

Measured: ~1.5 ms per 100 KB ASCII, 8-12 ms non-ASCII, with `str.isascii()` and `is_normalized` fast paths.

### 11. `feat/audit-log` (task 5)

New `src/audit.py` writing JSONL, shared by both proxies, replacing two divergent human-readable log formats.

The load-bearing decision is argument handling. Default is `args_mode=none`:

- **Always on:** HMAC-SHA256 over `tool_name \0 canonical_json(args)`, keyed with a persistent per-install 32-byte key at `~/.agentparry/audit.key` (0600). Plain SHA-256 would be theater here: `{"path":"/etc/passwd"}`, an email, a 9-digit SSN are all low-entropy and fall to a rainbow table instantly. A per-run salt would break the main use case (correlating "this exact call happened again"). Plus `arg_keys` (schema, not secrets) and `arg_bytes`.
- **`AGENTPARRY_AUDIT_ARGS=preview`:** sensitive-key omission plus a pass through the existing `OutputInspector`, truncated to 512 chars. Be honest that `OutputInspector` knows five patterns and will not catch bearer tokens, JWTs, private keys, names, or addresses.
- **`AGENTPARRY_AUDIT_ARGS=full`:** raw. Accept only the literal string `full`, so `1`/`true`/`yes` all resolve to `none` and nobody enables raw-secret logging by copying a boolean-flag habit. One startup warning. Every record stamps `args_mode` so a reader can tell from any single line whether the file is sensitive.

Response payloads are never logged at any tier. One accepted residual leak: `policy.py` builds `f"Domain not allowlisted: {domain}"`, so an email domain (never the local part) reaches the log.

Other decisions:
- `(run_id, seq)` for ordering, since wall-clock `ts` can step backwards under NTP.
- 0600 file via `os.open` + `fchmod` (also tightens a pre-existing loose file), 0700 dir via explicit `chmod` since `mkdir(mode=)` is umask-masked.
- Rotation **in this PR**, single generation. This file grows on every tool call in long-lived Desktop sessions; an unbounded append-only file in `$HOME` is exactly the follow-up that never happens.
- Never `fsync`. One `os.write` of one newline-terminated line to an `O_APPEND` fd, under a `threading.Lock`. Synchronous on the stdio event loop deliberately: no disk wait, and going off-loop would reorder records relative to stdout.
- `write()` returns `bool` and never raises. Self-disables after 5 consecutive failures so a bad path does not warn once per tool call forever.
- Derive the Rich console line from the record. The divergence this PR fixes was caused by two independent formatting paths; a third would recreate it.
- Do not add a fifth module global to `proxy.py`. Use `get_writer()` / `set_writer()` in `audit.py`, plus an **autouse** `conftest.py` fixture so a test that forgets still cannot touch the real `~/.agentparry`.

Highest-value new signal: the three stdio fail-open `except` blocks currently only `logger.exception`. They get `FAIL_OPEN` records, so a broken rule silently degrading to allow-everything becomes machine-detectable.

---

## Wave 3: the actual security features

### 12. `feat/output-injection-detection` (task 8)

Indirect injection: a fetched page, a file, an issue comment carrying instructions aimed at the model. `OutputInspector` only redacts five PII patterns; both proxies already call it on results, so the plumbing exists and the detection does not.

New `ResultInspector` class, not an extension of `OutputInspector` (whose `(sanitized, findings)` contract has exactly one action) nor of `InputInspector` (which takes arguments). Shares an extracted `INJECTION_PATTERNS` table with both.

Default action **neutralize**: wrap the offending text leaf in ASCII untrusted-content fences with a per-leaf `secrets.token_hex(4)` id so the closing fence cannot be forged, and rewrite any literal occurrence of the fence token in attacker text. Content survives, the model is warned, and a false positive costs one wrapper instead of a dead tool call. `block` breaks tasks, `redact` silently corrupts documentation and is defeated by splitting a phrase across spans, `annotate` attaches no warning to the payload the model reads.

Only `critical` and `high` act. `medium` annotates only — the two medium patterns are `{100,}` base64 and `<script|javascript:|onerror=`, which fire on any JWT, sha256 list, minified bundle, or fetched HTML page. In `block` mode, `high` degrades to `neutralize`.

Suppressors: actionable-verb window (±400 chars), code-fence context, unless two or more distinct patterns match the same leaf (real attacks stack; documentation quoting one phrase usually does not).

Scans `content[].text`, `resource.text`, `structuredContent`, and flat mock shapes. Skips base64 `image`/`audio` data and `resource.blob`. `isError: true` results **are** scanned, since tool error text is model-visible.

New error code `-32002` for the output direction.

Residual risk stated plainly: reading this repo's own `README.md` or `attacks/payloads.yaml` through the proxy will produce wrapped text, because those phrases sit unfenced next to "exfiltrate" and "send". Regex cannot distinguish text that instructs the model from text that quotes text that instructs the model. Neutralize is a signal, not a control — a model can still obey wrapped content.

Normalize dependency is **soft**: degrades to raw-text matching, so this can land before PR 10 if convenient.

### 13. `feat/inspect-tool-metadata` (task 9)

The highest-value gap. `tools/list` is forwarded with zero inspection, so tool-description poisoning walks straight to the model and never appears in any `tools/call` argument.

Walk the whole tool object generically rather than an allowlist of keys, so spec additions (`title`, `annotations`, `outputSchema`) are covered for free. That reaches nested property descriptions, enum members, defaults, const, examples, and property key names.

Also inspect `initialize`'s `result.instructions`, which clients splice directly into the system prompt and which **the scanner never even fetches today**.

Metadata-specific patterns beyond `InputInspector`'s: `<IMPORTANT>` pseudo-tags, "do not tell the user", any invisible characters at all, "before calling this tool", sensitive paths in prose. Suppress the base64 rule when the leaf key is `pattern`/`format`/`$schema`, or JSON Schema regexes false-positive.

Default `redact` at `min_severity: critical`, escalating to `drop` for that one tool when the finding sits in a structurally load-bearing value (enum member, default, tool name) that cannot be rewritten without breaking client-side schema validation.

Three implementation traps:
- `stdio_proxy.py:346` pops and **discards** the pending method. Capture it, or stdio cannot dispatch metadata responses at all.
- The mock server's poisoned tool needs a `tools/call` branch, or `-32601` counts as blocked and inflates the score (see PR 9's error-code fix).
- Must honor `_bypass_all` or `demo.py`'s before/after pass is wrong, and must **not** be gated behind `--discover`, since `demo.py:174` calls `run_scan` without it.

Biggest risk: real tool descriptions legitimately contain imperative prose, and `redact` on a false positive silently degrades a working tool. The pattern set needs tuning against a corpus of real MCP servers before anyone trusts `redact`.

### 14. `feat/pin-tool-list` (task 10)

Stacks on PR 13. A server can pass inspection on day one and change a description later.

Fingerprint the **raw** canonical JSON, not the normalized text. Normalizing before hashing would let an attacker flip zero-width characters freely, and a change that only adds invisible instructions would hash identically. Whitespace churn causing a diff is the correct trade for a security pin.

Set-level hash sorts by name, so legitimate reordering does not trigger while additions and removals do.

Server identity: stdio keys on the wrapped argv (available before any traffic), HTTP on the upstream URL or command from env. **Never key on `serverInfo.name`** — it is attacker-controlled, so a malicious server would rename itself to dodge its own pin. Record it inside the pin instead, where a change to it is itself a reported diff.

First run records the pin **without** diffing and reports `PIN_CREATED`. Flagging everything as changed trains users to ignore the warning. Be honest in the docs: the pin does not protect against a day-one-malicious server (that is PR 13's job), it closes only the change-over-time hole. If PR 13 found a critical finding, write the pin `trusted: false` and re-report until accepted.

Default action `warn`, but re-run content inspection on changed metadata with severity escalated one level. So "changed **and** now matches a pattern" blocks, while routine maintainer description updates do not. Hard-blocking on any diff makes the proxy unusable and users turn it off.

Real clients cache `tools/list` and may never re-call it in a session, so rug pulls land across restarts. That is exactly why the pin lives on disk.

Multi-client (Desktop and Code wrapping the same server): keep steady state read-only by throttling `last_seen` to 24h, which makes contention mostly moot. Writes go through `flock` plus `os.replace`, merging per-server-key rather than overwriting, and skip on lock timeout since pins are advisory and must never block the MCP stream.

Highest-uncertainty item in the whole roadmap: pagination. A `nextCursor` second page looks like "3 tools removed" to a set-level hash. No in-repo server paginates, so this is unverified. Mitigation is to skip set-level diffing when `nextCursor` is present, with a logged reason.

New `agentparry pins list/show/diff/accept/forget`. `accept --all` requires `--yes`, since accepting transfers trust.

---

## Wave 4: product surface

### 15. `feat/expand-attack-payloads` (task 11)

~45 payloads: tool poisoning, obfuscation, encoding chains, SSRF, cross-tool exfil, terminal injection, path traversal, benign.

Standout payload: `http_fetch` to `http://127.0.0.1:9090/policy/disable`, i.e. SSRF against AgentParry's own control plane. Same hole PR 3 closes.

`file_read` has **zero** policy rules today, so the whole path-traversal group fails.

Key sequencing problem: most of these fail until PRs 10, 12, and 13 land, which would drop detection rate from ~87% to ~25% in one commit. Recommend an optional `known_gap` flag reported separately, or detection rate stops working as a CI gate the moment this lands.

Needs a new `http_fetch` mock tool (pure stub, no real network) and breaks `tests/test_mock_server.py:43`, which asserts the exact tool-name list. Hold the two true multi-step cross-tool payloads until a sequence executor exists; a payload the runner cannot execute is just `indeterminate` noise.

### 16. `feat/harden-and-verify-cli` (task 12)

`run_rescan` and `print_comparison` exist but are reachable only through `demo.py`, so the "verify" claim is demo-only.

`apply_rules` currently rewrites `config/default_policy.yaml` in place and drops every existing `autogen_*` rule. The committed file holds four. A naive harden run deletes them, and since they currently block their payloads the scan sees no findings, generates no replacement, and **the vulnerabilities silently come back**. Additive merge is mandatory: backup, unified diff, explicit confirmation, `--dry-run`.

`harden --safe` generates zero rules today, because `generate_rules` filters on `passed_through` while safe mode sets `evaluated_only`. Needs an `include_policy_allowed` path.

`verify --before` takes a saved JSON report; a fresh in-invocation scan would be taken *after* the rules landed and be meaningless. Default `run_rescan` only replays previously-failing payloads and therefore cannot see regressions, so `--full` exists and is the recommended CI mode.

Exit codes: 0 clean, 1 error, 2 usage, 3 vulnerabilities above `--max-vulns` or a regression, 4 aborted, 130 interrupt.

Safety: refuse a non-loopback target without `--safe` unless `--allow-remote`. Without `--safe`, harden actually executes `rm -rf /` and `curl | bash` upstream.

### 17. `feat/stdio-policy-reload` (task 16)

`stdio_proxy.py:469` builds `PolicyEngine` once inside `main`, with no HTTP surface and no signal handler, so a policy change can never take effect in a live `agentparry wrap` session. Today the only remedy is restarting the MCP client. Options: SIGHUP, mtime watch, control file. Touches the deliberate fail-open path, so it gets its own PR.

### 18. `feat/install-claude-code` (task 13)

Schema confirmed three independent ways: a real `.mcp.json` on this machine, `claude mcp add --help` (v2.1.220), and the zod schemas in the binary. Top-level `mcpServers`; the stdio member is `{type?: "stdio", command (non-empty), args (default []), env?, timeout?, alwaysLoad?}`. The existing `_stdio_entry_from_command` already emits a valid entry.

**Not confirmed:** the `--scope user` layout in `~/.claude.json`. Top-level `mcpServers` is `{}` locally with no stdio example anywhere, so confirm before shipping that scope.

Main design risk: `--scope project` writes a committed `.mcp.json` embedding `sys.executable` and an absolute policy path, which breaks for every other checkout. Mitigate with `--python` plus a printed warning. Consider `{"command": "agentparry", "args": ["wrap", ...]}` as a follow-up so it resolves off `PATH`.

`--scope local` (`projects[cwd]` in `~/.claude.json`) deliberately unsupported, noted so the gap is explicit rather than accidental.

---

## Cross-cutting notes

- `demo.py` is load-bearing for three PRs (3, 13, 14) and its closing "your agent is X% more secure" panel needs a false-positive line after PR 9, or it reads as dishonest.
- `_bypass_all` removal in PR 3 ripples into PRs 8 and 13, which both must decide what to do when enforcement is off. PR 3 deleting it outright simplifies both.
- Three PRs want `PolicyEngine.get_settings()`, which does not exist. Whichever lands first adds it.
- Two PRs want `INJECTION_PATTERNS` extracted from `InputInspector`. Same rule.
- The dead trailing docstring at `inspector.py:163` gets deleted by whichever of PRs 10, 12, 13 lands first.
- Batched JSON-RPC arrays bypass inspection over stdio and 422 on HTTP. Pre-existing, flagged, not fixed by any PR here.
