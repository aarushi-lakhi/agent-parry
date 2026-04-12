"""Minimal stdio JSON-RPC responder for stdio_proxy integration tests."""

from __future__ import annotations

import json
import sys


def main() -> None:
    stdin = sys.stdin.buffer

    def read_message() -> dict[str, object] | None:
        first = stdin.readline()
        if not first:
            return None
        line = first.decode("utf-8").strip()
        if not line:
            return read_message()
        return json.loads(line)

    while True:
        req = read_message()
        if req is None:
            break
        rid = req.get("id")
        method = req.get("method")
        if method == "tools/call":
            params = req.get("params") if isinstance(req.get("params"), dict) else {}
            name = params.get("name", "")
            if name == "pii_tool":
                result: dict[str, object] = {"body": "Contact: 123-45-6789"}
            else:
                result = {"ok": True}
            out = {"jsonrpc": "2.0", "id": rid, "result": result}
        else:
            out = {"jsonrpc": "2.0", "id": rid, "result": {}}
        sys.stdout.buffer.write((json.dumps(out, separators=(",", ":")) + "\n").encode("utf-8"))
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
