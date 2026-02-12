"""Sample Bond plugin for integration testing.

Self-contained MCP server (no external dependencies).
Implements JSON-RPC 2.0 over stdin/stdout with two tools: greet, add.
"""
import sys
import json

TOOLS = [
    {
        "name": "greet",
        "description": "Says hello to someone",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Who to greet"}
            },
        },
    },
    {
        "name": "add",
        "description": "Adds two numbers",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
            },
            "required": ["a", "b"],
        },
    },
]


def handle_tool_call(name, arguments):
    if name == "greet":
        who = arguments.get("name", "World")
        return f"Hello, {who}!"
    if name == "add":
        return json.dumps({"result": arguments.get("a", 0) + arguments.get("b", 0)})
    return None


def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            continue

        method = req.get("method", "")
        req_id = req.get("id")
        params = req.get("params", {})

        # Notifications (no id) — no response
        if req_id is None:
            continue

        if method == "initialize":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "sample-test", "version": "0.1.0"},
            }}
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments", {})
            result = handle_tool_call(name, arguments)
            if result is not None:
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": str(result)}],
                }}
            else:
                resp = {"jsonrpc": "2.0", "id": req_id, "error": {
                    "code": -32602, "message": f"Unknown tool: {name}",
                }}
        elif method == "ping":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
        else:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32601, "message": "Method not found",
            }}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
