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
