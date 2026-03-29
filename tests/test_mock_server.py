"""Tests for the mock dangerous MCP server."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from src.mock_server import app


class TestMockServer(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_health(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_initialize(self) -> None:
        response = self.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["result"],
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-dangerous-server", "version": "1.0"},
            },
        )

    def test_tools_list(self) -> None:
        response = self.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        self.assertEqual(response.status_code, 200)
        tools = response.json()["result"]["tools"]
        self.assertEqual([tool["name"] for tool in tools], ["email_send", "shell_exec", "file_read"])
        self.assertEqual(tools[0]["inputSchema"]["required"], ["to", "subject", "body"])
        self.assertEqual(tools[1]["inputSchema"]["required"], ["command"])
        self.assertEqual(tools[2]["inputSchema"]["required"], ["path"])

    def test_tools_call_email_send(self) -> None:
        response = self.client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "email_send",
                    "arguments": {
                        "to": "alice@example.com",
                        "subject": "Hello",
                        "body": "Test body",
                    },
                },
            },
        )
        self.assertEqual(
            response.json()["result"],
            {"status": "sent", "to": "alice@example.com", "subject": "Hello"},
        )

    def test_tools_call_shell_exec(self) -> None:
        response = self.client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "shell_exec",
                    "arguments": {"command": "whoami"},
                },
            },
        )
        self.assertEqual(
            response.json()["result"],
            {"stdout": "[mock] executed: whoami", "exit_code": 0},
        )

    def test_tools_call_file_read_sensitive_paths(self) -> None:
        cases = {
            "/home/user/contacts.csv": "Name,Email,SSN,CC\nJohn Doe,john@example.com,123-45-6789,4111-1111-1111-1111\nJane Smith,jane@example.com,987-65-4321,5500-0000-0000-0004",
            "/home/user/.env": "DATABASE_URL=postgres://prod:secret@db.internal:5432/main\nAPI_KEY=sk-proj-abc123def456ghi789jklmnopqrstuvwxyz\nSTRIPE_SECRET=sk_live_abc123",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
        }

        for path, expected in cases.items():
            with self.subTest(path=path):
                response = self.client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {"name": "file_read", "arguments": {"path": path}},
                    },
                )
                self.assertEqual(response.json()["result"], {"content": expected})

    def test_tools_call_file_read_fallback(self) -> None:
        path = "/tmp/demo.txt"
        response = self.client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "file_read", "arguments": {"path": path}},
            },
        )
        self.assertEqual(response.json()["result"], {"content": f"File contents of {path}"})

    def test_unknown_method_returns_jsonrpc_error(self) -> None:
        response = self.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": "req-1", "method": "unknown/method"},
        )
        payload = response.json()
        self.assertEqual(payload["id"], "req-1")
        self.assertEqual(payload["error"]["code"], -32601)
        self.assertIn("Method not found", payload["error"]["message"])

    def test_unknown_tool_returns_jsonrpc_error(self) -> None:
        response = self.client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "danger_tool", "arguments": {}},
            },
        )
        payload = response.json()
        self.assertEqual(payload["error"]["code"], -32601)
        self.assertIn("Unknown tool", payload["error"]["message"])

    def test_invalid_params_return_jsonrpc_error(self) -> None:
        response = self.client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "shell_exec", "arguments": {"command": 123}},
            },
        )
        payload = response.json()
        self.assertEqual(payload["error"]["code"], -32602)
        self.assertIn("Invalid params", payload["error"]["message"])


if __name__ == "__main__":
    unittest.main()
