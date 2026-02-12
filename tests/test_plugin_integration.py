"""Integration test for Bond plugin system.

Tests:
1. Sample plugin MCP handshake (initialize → initialized → tools/list)
2. Tool call via JSON-RPC
3. PluginDescriptor loading from bond-plugin.json
4. PluginBridge subprocess lifecycle
"""

import asyncio
import json
import os
import sys
import subprocess

# Add Bond root to path
BOND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BOND_ROOT)

SAMPLE_PLUGIN_DIR = os.path.join(BOND_ROOT, 'tests', 'sample-plugin')


def send_receive(proc, request: dict, timeout: float = 5.0) -> dict:
    """Send a JSON-RPC request and read response."""
    line = json.dumps(request) + "\n"
    proc.stdin.write(line.encode('utf-8'))
    proc.stdin.flush()

    # Read response line
    import select
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            return json.loads(line.decode('utf-8').strip())
        time.sleep(0.05)
    raise TimeoutError("No response from plugin")


def send_notification(proc, notification: dict):
    """Send a JSON-RPC notification (no response expected)."""
    line = json.dumps(notification) + "\n"
    proc.stdin.write(line.encode('utf-8'))
    proc.stdin.flush()


def test_raw_protocol():
    """Test 1: Raw stdin/stdout MCP protocol with sample plugin."""
    print("Test 1: Raw MCP protocol...")

    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, "-u", "server.py"],
        cwd=SAMPLE_PLUGIN_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    try:
        # Step 1: initialize
        resp = send_receive(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "bond-test", "version": "0.1.0"}
            }
        })
        assert resp["id"] == 1, f"Expected id=1, got {resp['id']}"
        assert "result" in resp, f"Expected result in response: {resp}"
        assert resp["result"]["serverInfo"]["name"] == "sample-test"
        print("  [PASS] initialize handshake")

        # Step 2: notifications/initialized
        send_notification(proc, {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        print("  [PASS] notifications/initialized sent")

        # Step 3: tools/list
        resp = send_receive(proc, {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })
        assert resp["id"] == 2
        tools = resp["result"]["tools"]
        assert len(tools) == 2, f"Expected 2 tools, got {len(tools)}"
        tool_names = {t["name"] for t in tools}
        assert "greet" in tool_names, f"Missing 'greet' tool: {tool_names}"
        assert "add" in tool_names, f"Missing 'add' tool: {tool_names}"
        print(f"  [PASS] tools/list: {tool_names}")

        # Step 4: tools/call — greet
        resp = send_receive(proc, {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "greet", "arguments": {"name": "Bond"}}
        })
        assert resp["id"] == 3
        text = resp["result"]["content"][0]["text"]
        assert "Hello, Bond!" in text, f"Unexpected greet result: {text}"
        print(f"  [PASS] tools/call greet: {text}")

        # Step 5: tools/call — add
        resp = send_receive(proc, {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 17, "b": 25}}
        })
        assert resp["id"] == 4
        result_text = resp["result"]["content"][0]["text"]
        result_data = json.loads(result_text)
        assert result_data["result"] == 42, f"Expected 42, got {result_data}"
        print(f"  [PASS] tools/call add: 17+25={result_data['result']}")

        # Step 6: ping
        resp = send_receive(proc, {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "ping",
            "params": {}
        })
        assert resp["id"] == 5
        assert resp["result"] == {}
        print("  [PASS] ping")

        # Step 7: unknown method
        resp = send_receive(proc, {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "nonexistent/method",
            "params": {}
        })
        assert resp["id"] == 6
        assert "error" in resp
        assert resp["error"]["code"] == -32601
        print("  [PASS] unknown method returns -32601")

        print("Test 1: ALL PASS")

    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_plugin_descriptor():
    """Test 2: PluginDescriptor loads from bond-plugin.json."""
    print("\nTest 2: PluginDescriptor from JSON...")

    from models.models import PluginDescriptor, SafetyLevel

    manifest_path = os.path.join(SAMPLE_PLUGIN_DIR, "bond-plugin.json")
    desc = PluginDescriptor.from_json(manifest_path)

    assert desc.name == "sample-test", f"Expected 'sample-test', got '{desc.name}'"
    assert desc.version == "0.1.0"
    # Command is resolved to absolute path at validation time (hijack prevention)
    assert os.path.isabs(desc.command), f"Expected absolute path, got '{desc.command}'"
    assert "python" in desc.command.lower(), f"Expected python in path, got '{desc.command}'"
    assert desc.args == ["-u", "server.py"]
    assert desc.max_safety_level == SafetyLevel.MODERATE
    assert desc.max_inflight == 1
    assert desc.timeout_seconds == 10.0
    assert desc.tools_prefix == "sample_test"  # auto-derived

    print(f"  [PASS] name={desc.name}")
    print(f"  [PASS] tools_prefix={desc.tools_prefix}")
    print(f"  [PASS] safety={desc.max_safety_level.value}")

    # Test env building
    env = desc.build_subprocess_env()
    assert "PATH" in env, "PATH must be in subprocess env"
    print(f"  [PASS] env has {len(env)} keys (PATH + platform essentials)")

    print("Test 2: ALL PASS")


def test_plugin_bridge():
    """Test 3: PluginBridge full lifecycle."""
    print("\nTest 3: PluginBridge lifecycle...")

    from models.models import PluginDescriptor
    from core.plugin_bridge import PluginBridge

    manifest_path = os.path.join(SAMPLE_PLUGIN_DIR, "bond-plugin.json")
    desc = PluginDescriptor.from_json(manifest_path)
    desc.working_dir = SAMPLE_PLUGIN_DIR

    async def _run_bridge_test():
        bridge = PluginBridge(desc)

        # Start
        ok = await bridge.start()
        assert ok, "PluginBridge.start() failed"
        print("  [PASS] bridge.start()")

        assert bridge.is_alive, "Bridge should be alive"
        assert not bridge.is_degraded, "Bridge should not be degraded"
        print("  [PASS] is_alive=True, is_degraded=False")

        # Check tools
        tools = bridge.get_tools()
        assert len(tools) == 2, f"Expected 2 tools, got {len(tools)}"
        tool_names = {t.name for t in tools}
        assert "sample_test_greet" in tool_names, f"Missing prefixed greet: {tool_names}"
        assert "sample_test_add" in tool_names, f"Missing prefixed add: {tool_names}"
        print(f"  [PASS] tools: {tool_names}")

        # Check tool metadata
        for tool in tools:
            assert tool.module_id == "plugin:sample-test"
            assert tool.safety_level == desc.max_safety_level
        print("  [PASS] tool metadata (module_id, safety_level)")

        # Call greet
        result = await bridge.call_tool("greet", {"name": "Integration"})
        assert not result.get("isError", False), f"greet returned error: {result}"
        print(f"  [PASS] call_tool greet: {result}")

        # Call add
        result = await bridge.call_tool("add", {"a": 100, "b": 200})
        assert not result.get("isError", False), f"add returned error: {result}"
        print(f"  [PASS] call_tool add: {result}")

        # Stop
        await bridge.stop()
        assert not bridge.is_alive, "Bridge should not be alive after stop"
        print("  [PASS] bridge.stop()")

    asyncio.run(_run_bridge_test())
    print("Test 3: ALL PASS")


if __name__ == "__main__":
    import logging
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    passed = 0
    failed = 0

    for test in [test_raw_protocol, test_plugin_descriptor, test_plugin_bridge]:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"\n  [FAIL] {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
    print("ALL TESTS PASSED")
