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

## Normalization

Detection regexes used to run on raw input, so `ignore all previous instructions` was bypassed by a zero-width space, a fullwidth spelling, a Cyrillic homoglyph, or base64. `src/normalize.py` builds normalized **views** of every string before matching. Each view keeps an offset map back to the original, so a finding still quotes real input and a redaction still splices into the real value.

| View | What it is |
|---|---|
| `original` | The raw value, unchanged. |
| `canonical` | Format characters removed (all `Cf` plus U+034F), NFKC folded, mixed-script homoglyphs folded, runs of horizontal whitespace collapsed. Newlines survive, because the `SYSTEM:` pattern is `^`-anchored. |
| `decoded:base64` / `decoded:hex` / `decoded:percent` | The plaintext inside an encoded fragment, when it decodes to printable UTF-8. Nested up to 3 levels. |

Homoglyph folding is scoped to `\w+` tokens containing both an ASCII letter and a confusable, so Cyrillic prose and `café naïve` come back byte-identical. Views whose text equals a higher-priority view are dropped, so clean ASCII costs one regex pass.

Findings gained `view`, `matched_text` (truncated to 120 chars) and `span`. All default, so scan-report JSON written before this still validates.

### Policy settings

Set under `settings.normalization` in the policy YAML. Override per rule or per condition with `normalize: false`, `normalize: true`, or `normalize: {canonical: true, decoded: true}`.

```yaml
settings:
  normalization:
    enabled: true
    canonical: true   # on by default
    decoded: false    # opt in per rule
```

`canonical` is on by default: it only ever makes a rule match text a human reads as identical to what they typed, and the surprise direction is more blocking. `decoded` is off by default because matching an `rm -rf /` rule against plaintext hidden in an opaque base64 string is a semantic leap the rule author did not ask for, and `BLOCK` cannot be recovered from over stdio. The inspectors, which only report findings, enable both.

Views apply to `pattern_match` and `pii_detection` only. **`domain_allowlist` is deliberately never normalized**: folding is fail-safe for a denylist and fail-open for an allowlist, since folding a Cyrillic-o spelling of an allowlisted domain onto its ASCII spelling would let an attacker's confusable domain pass. The correct treatment for allowlists is the inverse, flagging mixed-script hosts, and is a separate change.

### Limits

Module constants in `src/normalize.py`, all enforced and tested. Above the input limit the canonical view is the original and a warning is logged.

| Limit | Value |
|---|---|
| Max input | 1,000,000 chars |
| Decode depth | 3 |
| Fragments per string | 32 |
| Bytes per single decode | 16,000 |
| Total decoded bytes per string | 64,000 |

There is no gzip, zlib, or deflate decoding. Decompression is where ratio bombs live and needs its own expansion-ratio guard, so a compressed payload never becomes a view.

### Base64 signals

The old `[A-Za-z0-9+/=]{100,}` pattern missed a 68-char payload, and `{40,}` on a bare character class matches any sha1 or sha256 digest. Two signals replace it:

- **Primary**, from 16 chars: decode the fragment and, if it is printable UTF-8, run the ordinary patterns against the decoded view at their ordinary severity. A JWT decodes to `{"alg":...}` and matches nothing.
- **Secondary**, from 40 chars: a decode-plausible run that does not decode to text is a medium "opaque encoded blob". Pure-hex and single-case runs are excluded so digests and identifiers stay quiet. 40 matches the value baked into `src/rule_generator.py`, keeping the scan-generate-verify loop self-consistent.

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
