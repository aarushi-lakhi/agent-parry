# AgentParry

AgentParry helps you **scan**, **protect**, and **verify** autonomous AI agents against prompt injection, data exfiltration, and privilege escalation.

## Features

- **HTTP proxy** (`src/proxy.py`): FastAPI service that inspects JSON-RPC to an upstream MCP-style endpoint, applies policy, and redacts sensitive output.
- **Stdio MCP proxy** (`src/stdio_proxy.py`): Drop-in wrapper for real MCP servers over stdin/stdout—intended for **Claude Desktop** and **Claude Code**, where the client spawns the MCP process and speaks newline-delimited JSON-RPC (and optionally `Content-Length` framing).
- **Audit log** (`src/audit.py`): one JSONL line per policy decision, same schema from both transports.
- **Closed loop** (`agentparry harden` / `agentparry verify`): scan, generate policy rules from the findings, re-scan, and report both what got fixed and what the new rules broke.

## Stdio proxy (Claude / MCP)

Run from the repository root so `config/default_policy.yaml` resolves correctly:

```bash
python -m src.stdio_proxy --wrap npx -- some-mcp-server
python -m src.stdio_proxy --wrap uvx -- some-mcp-package
```

Put AgentParry flags **before** `--wrap`. After `--wrap`, the first token is the server executable; use `--` before the wrapped server’s own arguments.

| Option | Meaning |
|--------|--------|
| `--policy PATH` | Policy YAML (default: `config/default_policy.yaml`, or `AGENTPARRY_POLICY` if set) |
| `--log PATH` | Log file (default: `~/.agentparry/proxy.log`) |
| `--audit PATH` | JSONL audit log (default: `~/.agentparry/audit.jsonl`, or `AGENTPARRY_AUDIT_PATH`) |
| `--no-audit` | Disable the audit log |
| `--verbose` | Extra logging to stderr and the log file |
| `--wrap CMD` | Command to spawn the real MCP server |

**Important:** stdout is reserved for JSON-RPC only. Diagnostics go to the log file and (with `--verbose`) stderr.

When the client closes stdin, the proxy closes the wrapped server’s stdin (EOF) so responses for already-forwarded requests can still be read; if the child is still running after that, it is stopped during proxy teardown.

See `python -m src.stdio_proxy --help` for examples.

## Scanning

`src/scanner.py` replays `attacks/payloads.yaml` through a running proxy and scores each payload on three axes: what the payload **expected** (`block`, `redact` or `allow`), what was **observed** in the response, and the **outcome** of comparing the two.

```bash
agentparry scan --target http://localhost:9090/mcp --format both
agentparry scan --target http://localhost:9090/mcp --safe --format md
```

Outcomes roll up into a confusion matrix, so a scan reports a pair of numbers instead of one:

| Outcome | Meaning |
|---|---|
| `true_block` | attack payload stopped (a stricter response satisfies a weaker expectation, so a block satisfies `redact`) |
| `false_negative` | attack payload reached the tool |
| `true_allow` | benign payload allowed |
| `false_positive` | benign payload blocked, which is over-blocking |
| `indeterminate` | not measurable: upstream rejected the call (`-32601` / `-32602`), or safe mode meant the output inspector never ran |

`vulnerability_score` counts attack payloads only, so adding benign payloads cannot deflate it. `detection_rate`, `false_positive_rate` and `balanced_score` return `n/a` when their denominator is empty, because "no benign payloads" is not "zero over-blocking". The payload set ships nine `expected_behavior: allow` payloads and the default policy over-blocks three of them; the scan report's "False positives" section names the rule at fault.

Only error code `-32001` counts as a proxy block. `-32601` and `-32602` mean the call never reached policy evaluation and score as indeterminate.

## Hardening and verifying

`agentparry harden` runs the closed loop the demo used to keep to itself: scan the target, turn the findings into `autogen_*` rules, merge them into the policy, then re-scan and compare.

```bash
agentparry harden --target http://localhost:9090/mcp --dry-run
agentparry harden --target http://localhost:9090/mcp --yes --full
agentparry verify --before reports/before.json --full
```

The merge is additive. `merge_autogen_rules` keeps existing `autogen_*` rules, replaces only same-named ones, and keeps handwritten rules. `RuleGenerator.apply_rules` still does the opposite, dropping every `autogen_*` rule before prepending the new list, because `src/demo.py` calls `apply_rules([])` to reset the committed policy before its phase 2 scan. Replacing rather than merging is what makes a naive harden run dangerous: the four committed autogen rules currently block their payloads, so a fresh scan finds nothing, generates no replacements, and the rules that were doing the blocking are gone.

Generated rules stay ahead of handwritten ones, matching `apply_rules`. `PolicyEngine` is first-match-wins, so a generated BLOCK shadows a handwritten ALLOW for the same tool. That is pre-existing behavior, preserved deliberately.

Before writing, `harden` backs the policy up to a `.bak` sibling, prints a unified diff against the file's raw text (so the comments and formatting `yaml.dump` discards show up as removals), and asks for confirmation unless `--yes`. `--dry-run` prints the diff and exits 0. On a non-tty it refuses to prompt rather than assuming yes.

| Flag | Meaning |
|---|---|
| `--safe` | Input-side only. Also switches rule generation to `include_policy_allowed`, since a safe scan records `evaluated_only` instead of `passed_through` and would otherwise generate nothing |
| `--allow-remote` | Required for a non-loopback `--target` without `--safe`, because the payload set really runs `rm -rf /` and `curl ... \| bash` upstream |
| `--full` | Re-run the whole payload set after applying rules instead of replaying only what got through. The CI mode |
| `--max-vulns N` | Tolerate up to N remaining vulnerabilities before exiting 3 |
| `--no-reload` | Skip the `POST /policy/reload` attempt |

`verify` requires `--before` pointing at a saved scan JSON. A baseline scanned in the same invocation would be taken after the rules landed, so the comparison would always look clean. `--target` defaults to the before report's `target_url`. A `--safe` before report has no passed-through results to replay, so `verify` refuses it without `--full`.

Without `--full` both commands use `Scanner.run_rescan`, which replays only the payloads that previously got through. It therefore cannot see a payload that used to behave correctly and now does not, nor over-blocking among payloads it never replays, so both commands print how many previously correct payloads were skipped. Both also report false positives the new rules introduced: closing four holes while breaking three legitimate calls is not a clean run.

**Writing rules only helps if something reloads them.** `harden` attempts `POST /policy/reload` on the host derived from `--target`, sending `AGENTPARRY_ADMIN_TOKEN` as a bearer token when it is set, and treats any failure as a warning since the file on disk is already updated. The stdio proxy is worse off: it builds its `PolicyEngine` once at startup and has no reload path at all, so a hardening run can never take effect in a live `agentparry wrap` session. `harden` prints a line saying the MCP client has to be restarted.

Exit codes, since both are meant for CI:

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Error |
| 2 | Bad command line |
| 3 | Vulnerabilities remain above `--max-vulns`, or a regression was detected |
| 4 | `harden` aborted at the confirmation prompt |
| 130 | Interrupted |

## HTTP proxy

Run the FastAPI app (for example with uvicorn) and point your client at the proxy’s `/mcp` route; configure upstream URL in `src/models.py` (`MOCK_SERVER_URL`) or your deployment.

## Audit log

Both proxies append one JSON object per line to `~/.agentparry/audit.jsonl` for every policy decision, including the ones that produce no console output: invalid params, unknown-method passthrough, and the stdio fail-open paths where a broken rule degrades to allow-everything. The record schema is `AuditRecord` in `src/models.py`.

| Variable | Meaning |
|---|---|
| `AGENTPARRY_AUDIT_PATH` | Override the log path (default `~/.agentparry/audit.jsonl`) |
| `AGENTPARRY_AUDIT=0` | Disable auditing |
| `AGENTPARRY_AUDIT_ARGS` | `none` (default), `preview`, or `full` |
| `AGENTPARRY_AUDIT_KEY_PATH` | Override the HMAC key path (default `~/.agentparry/audit.key`) |

Order records by `(run_id, seq)`, not by `ts`: wall-clock time can step backwards under NTP.

The file is `0600` inside a `0700` directory, and rotates once at 8 MB to `audit.jsonl.1`. There is no `fsync`, so a hard crash can lose the tail.

### Argument tiers

Tool arguments are the sensitive part, so the default records no values at all.

- **`none` (default).** `arg_hash` is HMAC-SHA256 over `tool_name \0 canonical_json(arguments)`, keyed with a persistent 32-byte per-install key at `~/.agentparry/audit.key` (`0600`, created on first use). Keyed rather than a plain digest because a file path, an email address, or a 9-digit SSN are all low-entropy enough to fall to a rainbow table. `arg_hash_key_id` is a short digest of the key, so a rotated key is visible. Also recorded: the sorted top-level argument key **names** and the canonical-JSON byte length.
- **`preview`.** Adds `arg_preview`: values under sensitive-looking keys are dropped, the rest goes through the same `OutputInspector` used on responses, then it is truncated. That inspector knows exactly five patterns (SSN, credit card, `sk-`-style API keys, AWS access key ids, credentials embedded in a URL). It will **not** catch bearer tokens, JWTs, private keys, names, or addresses. Treat a `preview` file as sensitive.
- **`full`.** Raw arguments, secrets included. Only the literal string `full` enables it, so `1`, `true`, and `yes` all resolve to `none`.

Every record stamps `args_mode`, so any single line tells you whether the file is sensitive. Response payloads are never recorded at any tier, only a redaction count and finding summaries; a finding's `pattern` is the regex source, never the matched text.

The console output of the HTTP proxy still shows raw arguments. That is deliberate: the console is ephemeral and local, the file is persistent and may be shipped somewhere.

## Development

Install dependencies and optional test tooling:

```bash
pip install -e ".[dev]"
```

Run the test suite:

```bash
python -m pytest tests/ -q
```

Stdio proxy behavior is covered by `tests/test_stdio_proxy.py` (unit tests plus a small subprocess harness under `tests/fixtures/mcp_stdio_stub.py`).
