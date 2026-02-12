import asyncio

import pytest

from core.mcp_server import AUTH_FAILED, AUTH_REQUIRED, BondMCPServer


class DummyRegistry:
    def list_tools(self):
        return []


class DummyDispatcher:
    def __init__(self):
        self.calls = []

    async def handle_mcp_call(self, tool_name, arguments, request_id=None):
        self.calls.append((tool_name, arguments, request_id))
        return {"content": [{"type": "text", "text": "ok"}]}


def _server(auth_token=None):
    return BondMCPServer(
        dispatcher=DummyDispatcher(),
        registry=DummyRegistry(),
        auth_token=auth_token,
    )


def test_auth_required_when_token_missing():
    server = _server(auth_token="secret")
    err = server._check_auth({"id": 1, "params": {}})
    assert err["error"]["code"] == AUTH_REQUIRED


def test_auth_failed_when_token_wrong():
    server = _server(auth_token="secret")
    err = server._check_auth({"id": 2, "params": {"_meta": {"auth_token": "wrong"}}})
    assert err["error"]["code"] == AUTH_FAILED


def test_auth_failed_when_token_type_invalid():
    server = _server(auth_token="secret")
    err = server._check_auth({"id": 3, "params": {"_meta": {"auth_token": 123}}})
    assert err["error"]["code"] == AUTH_FAILED


def test_auth_accepts_valid_token():
    server = _server(auth_token="secret")
    assert server._check_auth({"id": 4, "params": {"_meta": {"auth_token": "secret"}}}) is None


def test_initialize_rejects_second_call():
    server = _server()
    result = server.handle_initialize({})
    assert result["serverInfo"]["name"] == "bond-mcp-server"
    with pytest.raises(ValueError, match="Already initialized"):
        server.handle_initialize({})


def test_handle_call_tool_rejects_non_object_arguments():
    server = _server()
    result = asyncio.run(
        server.handle_call_tool({"name": "demo", "arguments": []}, req_id=10)
    )
    assert result["isError"] is True
    assert result["content"][0]["text"] == "arguments must be an object"


def test_handle_call_tool_forwards_string_request_id():
    server = _server()
    dispatcher = server.dispatcher
    asyncio.run(
        server.handle_call_tool(
            {"name": "demo_tool", "arguments": {"x": 1}},
            req_id=42,
        )
    )
    assert dispatcher.calls == [("demo_tool", {"x": 1}, "42")]
