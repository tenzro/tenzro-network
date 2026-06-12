"""Shared fixtures for the Tenzro MCP server test suite.

All network IO is mocked. Tool tests monkeypatch ``rpc_call`` / ``api_call``
at the ``tenzro_mcp_server.server`` module boundary (the names the tools
close over); rpc_client tests mock ``httpx.AsyncClient`` directly.
"""

from unittest.mock import AsyncMock

import pytest

import tenzro_mcp_server.server as server


@pytest.fixture
def mock_rpc(monkeypatch):
    """Replace server.rpc_call with an AsyncMock returning a sentinel result."""
    mock = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(server, "rpc_call", mock)
    return mock


@pytest.fixture
def mock_api(monkeypatch):
    """Replace server.api_call with an AsyncMock returning a sentinel result."""
    mock = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(server, "api_call", mock)
    return mock
