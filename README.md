# AgentParry

AgentParry helps you **scan**, **protect**, and **verify** autonomous AI agents against prompt injection, data exfiltration, and privilege escalation.

## Features

- **HTTP proxy** (`src/proxy.py`): FastAPI service that inspects JSON-RPC to an upstream MCP-style endpoint, applies policy, and redacts sensitive output.
- **Stdio MCP proxy** (`src/stdio_proxy.py`): Drop-in wrapper for real MCP servers over stdin/stdout—intended for **Claude Desktop** and **Claude Code**, where the client spawns the MCP process and speaks newline-delimited JSON-RPC (and optionally `Content-Length` framing).
- **Audit log** (`src/audit.py`): one JSONL line per policy decision, same schema from both transports.

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
