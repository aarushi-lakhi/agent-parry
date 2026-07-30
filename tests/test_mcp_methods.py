"""MCP method classification shared by both transports."""

from __future__ import annotations

import pytest

from src.models import is_known_mcp_method, is_tools_call


@pytest.mark.parametrize(
    "method",
    ["initialize", "initialized", "ping", "tools/list", "tools/call"],
)
def test_exact_methods_are_known(method: str) -> None:
    assert is_known_mcp_method(method) is True


@pytest.mark.parametrize(
    "method",
    [
        "notifications/initialized",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "prompts/get",
        "prompts/list",
        "logging/setLevel",
        "completion/complete",
        "roots/list",
        "sampling/createMessage",
    ],
)
def test_passthrough_prefixes_are_known(method: str) -> None:
    assert is_known_mcp_method(method) is True


@pytest.mark.parametrize(
    "method",
    ["tools/call2", "tools/Call", "tools/", "tools/evil", "tools/CALL"],
)
def test_tools_namespace_is_closed(method: str) -> None:
    assert is_known_mcp_method(method) is False


@pytest.mark.parametrize(
    "method",
    ["", "evil/exec", "resources", "notifications", "shell", "Resources/read"],
)
def test_unknown_methods_are_rejected(method: str) -> None:
    assert is_known_mcp_method(method) is False


@pytest.mark.parametrize("method", ["tools/call", "tools/Call", "TOOLS/CALL"])
def test_is_tools_call_matches_case_variants(method: str) -> None:
    assert is_tools_call(method) is True


@pytest.mark.parametrize("method", ["tools/call2", "tools/list", "", "call"])
def test_is_tools_call_rejects_others(method: str) -> None:
    assert is_tools_call(method) is False
