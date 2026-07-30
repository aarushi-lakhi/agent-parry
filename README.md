# AgentParry

AgentParry helps you **scan**, **protect**, and **verify** autonomous AI agents against prompt injection, data exfiltration, and privilege escalation.

## Features

- **HTTP proxy** (`src/proxy.py`): FastAPI service that inspects JSON-RPC to an upstream MCP-style endpoint, applies policy, and redacts sensitive output.
- **Stdio MCP proxy** (`src/stdio_proxy.py`): Drop-in wrapper for real MCP servers over stdin/stdout—intended for **Claude Desktop** and **Claude Code**, where the client spawns the MCP process and speaks newline-delimited JSON-RPC (and optionally `Content-Length` framing).
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
