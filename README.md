# AgentParry

AgentParry helps you **scan**, **protect**, and **verify** autonomous AI agents against prompt injection, data exfiltration, and privilege escalation.

## Features

- **HTTP proxy** (`src/proxy.py`): FastAPI service that inspects JSON-RPC to an upstream MCP-style endpoint, applies policy, and redacts sensitive output.
- **Stdio MCP proxy** (`src/stdio_proxy.py`): Drop-in wrapper for real MCP servers over stdin/stdout—intended for **Claude Desktop** and **Claude Code**, where the client spawns the MCP process and speaks newline-delimited JSON-RPC (and optionally `Content-Length` framing).

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
