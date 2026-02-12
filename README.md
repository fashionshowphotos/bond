# Bond

Universal MCP (Model Context Protocol) server that gives desktop applications AI-powered tools.
Connects to OnlyOffice, LibreOffice, or any MCP-compatible host. Written in Python with
enterprise-grade security hardening.

**Version:** 0.2.0
**Protocol:** MCP 2024-11-05 (JSON-RPC 2.0 over stdin/stdout)
**License:** Free for non-commercial use; paid license required for commercial use

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [What It Does](#what-it-does)
3. [Installation](#installation)
4. [Running the Server](#running-the-server)
5. [VS Code Extension](#vs-code-extension)
6. [Tool Reference](#tool-reference)
7. [Governance & Security](#governance--security)
8. [Environment Variables](#environment-variables)
9. [CLI Flags](#cli-flags)
10. [Plugin System](#plugin-system)
11. [OnlyOffice Integration](#onlyoffice-integration)
12. [Smoke Tests](#smoke-tests)
13. [Architecture](#architecture)
14. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run tests (18 tests, should pass in <1s)
python -m pytest -q

# 3. Start the server (local/dev mode)
python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules

# Or use the batch launcher:
bond_mcp.bat
```

The server reads JSON-RPC from stdin and writes responses to stdout. Logs go to stderr.

---

## What It Does

Bond exposes **16 tools across 4 modules** via the MCP protocol:

| Module | Tools | Purpose |
|--------|-------|---------|
| **filesystem** (5) | `read_file`, `write_file`, `list_directory`, `search_files`, `file_info` | Sandboxed file operations with TOCTOU protection |
| **firejumper** (4) | `firejumper_latch`, `firejumper_execute`, `firejumper_screenshot`, `firejumper_list_learned` | VLM-powered UI automation (learn and control any program) |
| **web_bridge** (3) | `ask_web_ai`, `read_web_ai`, `list_available_automations` | Query external Web AIs (ChatGPT, DeepSeek, Claude, Gemini, Grok, Kimi) |
| **orchestrator** (4) | `get_status`, `update_status`, `append_ledger`, `read_ledger` | Task orchestration with JSONL audit ledger |

Any MCP-compatible client can call these tools: OnlyOffice, Claude Desktop, LibreOffice, or custom clients.

---

## Installation

### Prerequisites

- **Python 3.10+** (tested on 3.11, 3.13)
- **pip** for dependency management
- **Node.js** (optional, only for Firejumper ConnectorStore features)

### Steps

```bash
pip install -r requirements.txt
```

Dependencies are minimal:
- `websockets>=12.0` (Web Bridge WebSocket client)
- `aiohttp>=3.9` (Firejumper VLM HTTP client)

The core server itself uses only Python stdlib.

---

## Running the Server

### Local/Dev Mode

This repo ships without `modules/module_manifests.json`, so the `--insecure-allow-unverified-modules` flag is required for tools to load:

```bash
python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules
```

The `-u` flag forces unbuffered stdout, which is critical for MCP clients that read line-by-line.

### Production Mode

For production, create a manifest file and remove the insecure flag:

```bash
python -u bond_server.py \
  --policy BROAD \
  --auth-token-file /path/to/token \
  --rate-limit 50 \
  --require-plugin-hashes
```

### Windows Batch Launcher

```cmd
bond_mcp.bat
```

This runs the default dev command. For hosts that are sensitive to spaces in paths (like OnlyOffice), use `bond_launcher.py` from a simple path like `C:\Bond\`.

---

## VS Code Extension

The **Bond VS Code Extension** (`coherent-light.bond-vscode`) provides a control panel for the server directly in your editor.

### Commands (Ctrl+Shift+P)

| Command | What It Does |
|---------|-------------|
| **Bond: Start** | Starts the server as a child process |
| **Bond: Stop** | Sends SIGINT, waits 5s, then force-kills |
| **Bond: Restart** | Stop + Start |
| **Bond: Status** | Shows running state, PID, root path, and command |
| **Bond: Run Tests** | Opens a terminal and runs `python -m pytest -q` |
| **Bond: Open README** | Opens this file in the editor |
| **Bond: Open Project Root** | Opens the project folder in your file manager |

### Status Bar

A status bar item shows the server state:
- `▶ Bond` = running (click for status details)
- `⊘ Bond` = stopped

### Settings (`settings.json`)

```jsonc
{
  // Absolute path to Bond project root (auto-detected if workspace contains bond_server.py)
  "bond.rootPath": "",

  // Command used by Bond: Start
  "bond.runCommand": "python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules",

  // Command used by Bond: Run Tests
  "bond.testCommand": "python -m pytest -q",

  // Auto-start server when VS Code opens
  "bond.autoStart": false,

  // Show output panel when server starts
  "bond.showOutputOnStart": true
}
```

### Installation

The extension is installed from the `vscode-extension/` folder:

```powershell
# PowerShell installer script
.\scripts\install_vscode_extension.ps1
```

Or install manually by copying `vscode-extension/` to your VS Code extensions directory.

---

## Tool Reference

### Filesystem Module

Requires `BOND_SANDBOX_ROOT` to be set. All paths are relative to (or must resolve within) the sandbox. Without the sandbox configured, all file operations are refused (fail-closed).

#### `read_file`
Read a text file within the sandbox.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | File path (relative to sandbox or absolute within sandbox) |

**Safety:** SAFE | **Max file size:** 16 MB | **Binary files:** Rejected

#### `write_file`
Write content to a file within the sandbox. Uses atomic writes (temp file + rename).

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | File path to write |
| `content` | string | Content to write |

**Safety:** MODERATE | **Max content:** 16 MB | **Symlinks:** Refused

#### `list_directory`
List directory contents within the sandbox.

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | Directory path |

**Safety:** SAFE | **Max entries:** 10,000

#### `search_files`
Search for files matching a glob pattern within the sandbox.

| Parameter | Type | Description |
|-----------|------|-------------|
| `pattern` | string | Glob pattern (no `**` recursive, max depth 3) |
| `directory` | string | Directory to search in |

**Safety:** SAFE

#### `file_info`
Get file metadata (size, timestamps, type).

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | File path |

**Safety:** SAFE | **Returns:** exists, is_file, is_dir, is_symlink, size_bytes, modified, created

---

### Firejumper Module

VLM-powered UI automation. Learns any program's interface through screenshot analysis and can replay actions. Requires `OPENROUTER_API_KEY` for VLM features and `FIREJUMPER_DIR` for ConnectorStore.

#### `firejumper_latch`
Learn a program's UI by taking a screenshot and analyzing it with a VLM. Identifies input, output, and submit roles. Observation-only (no clicks). Persists learned layout to ConnectorStore.

| Parameter | Type | Description |
|-----------|------|-------------|
| `program_name` | string | Program name (e.g. "Notepad", "PowerPoint") |
| `window_title_pattern` | string | Window title pattern (optional) |

**Safety:** MODERATE | **Confidence threshold:** 0.75 | **VLM:** google/gemini-2.0-flash-001

#### `firejumper_execute`
Execute an action in a previously learned program. Clicks, types, or both. Requires governance approval before execution.

| Parameter | Type | Description |
|-----------|------|-------------|
| `program_name` | string | Learned program name |
| `action` | string | `click`, `type`, or `click_and_type` |
| `role` | string | UI role: `input`, `output`, or `submit` |
| `text` | string | Text to type (required for type actions) |

**Safety:** DESTRUCTIVE | **Requires:** Prior `firejumper_latch` + governance check

#### `firejumper_screenshot`
Capture a screenshot. Optionally analyze it with a VLM query.

| Parameter | Type | Description |
|-----------|------|-------------|
| `analyze` | boolean | Analyze with VLM (default: false) |
| `query` | string | VLM query (if analyze=true) |

**Safety:** SAFE

#### `firejumper_list_learned`
List all programs that have been learned via `firejumper_latch`.

**Parameters:** None
**Safety:** SAFE

---

### Web Bridge Module

Queries external Web AIs through the Firejumper Hub (WebSocket bridge). Requires a running Firejumper Hub at `FIREJUMPER_HUB` (default: `ws://localhost:7201`).

#### `ask_web_ai`
Send a prompt to an external Web AI and wait for the response.

| Parameter | Type | Description |
|-----------|------|-------------|
| `model` | string | Target AI: `chatgpt`, `deepseek`, `claude`, `gemini`, `grok`, `kimi` |
| `prompt` | string | The question or task |
| `force_new_chat` | boolean | Start a fresh conversation (optional, default: false) |
| `session_id` | string | Session ID for conversation isolation (optional, e.g. `claude-1`) |

**Safety:** MODERATE | **Timeout:** 180s (for slow reasoning models)

#### `read_web_ai`
Read the last response from a Web AI without sending a new prompt.

| Parameter | Type | Description |
|-----------|------|-------------|
| `model` | string | Target AI ID |

**Safety:** SAFE

#### `list_available_automations`
List which Web AIs are currently active and ready.

**Parameters:** None
**Safety:** SAFE

---

### Orchestrator Module

Task orchestration with persistent status tracking and a JSONL audit ledger. Data is stored in `BOND_SANDBOX_ROOT/orchestrator_state/` by default.

#### `get_status`
Read the current orchestrator status (mode, active jobs, last update).

**Parameters:** None
**Safety:** SAFE

#### `update_status`
Update the runtime status snapshot.

| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | string | `IDLE`, `RUNNING`, `WAITING`, or `ERROR` |
| `summary` | string | Short text summary of current state (max 4096 chars) |
| `job_id` | string | Current job ID (optional) |

**Safety:** MODERATE

#### `append_ledger`
Append an entry to the JSONL audit trail. Auto-timestamps each entry.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entry` | object | JSON object to append (type, jobId, details, etc.) |

**Safety:** MODERATE | **Max entry:** 64 KB | **Max ledger:** 100 MB | **Max depth:** 20

#### `read_ledger`
Read recent entries from the audit ledger.

| Parameter | Type | Description |
|-----------|------|-------------|
| `lines` | integer | Number of recent entries (default: 20, max: 1000) |

**Safety:** SAFE

---

## Governance & Security

Bond uses a 4-tier governance system that controls which tools can execute based on their safety level.

### Policy Modes

| Policy Mode | Allows Up To | Use Case |
|-------------|-------------|----------|
| `OBSERVE_ONLY` | SAFE tools only | Read-only monitoring |
| `RESTRICTED` | SAFE + MODERATE | Normal development (default) |
| `BROAD` | SAFE + MODERATE + DESTRUCTIVE | Full automation |
| `FULL_AUTO` | All including CRITICAL | Unattended operation |

### Safety Levels

Each tool has a safety level:
- **SAFE**: Read-only, no side effects (`read_file`, `list_directory`, `get_status`)
- **MODERATE**: Writes data but reversible (`write_file`, `update_status`, `ask_web_ai`)
- **DESTRUCTIVE**: Clicks/types in programs, hard to undo (`firejumper_execute`)
- **CRITICAL**: Reserved for future high-risk operations

### Security Hardening

Bond includes defense-in-depth:

- **Sandbox containment**: All file ops confined to `BOND_SANDBOX_ROOT` (fail-closed without it)
- **TOCTOU protection**: O_NOFOLLOW opens + fd path verification via `GetFinalPathNameByHandleW`
- **Symlink defense**: Pre-open + post-open checks, refuse symlink writes
- **Path traversal blocking**: Rejects `..`, absolute paths, Windows ADS, device names
- **Blocked patterns**: `.ssh`, `.env`, `.pem`, `.key`, `shadow`, `passwd`, etc.
- **Auth tokens**: Bearer token via file (recommended) > env var > CLI (deprecated)
- **Rate limiting**: Global + per-tool sliding window (default: 100 calls/min)
- **Module verification**: SHA-256 manifest hashes (production mode)
- **Plugin isolation**: Out-of-process subprocesses with env allowlisting
- **Audit logging**: JSONL task logs with integrity chaining and parameter redaction
- **Request size limits**: 10 MB max JSON-RPC line
- **Timing-safe comparisons**: `hmac.compare_digest` for token/hash checks

---

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `BOND_SANDBOX_ROOT` | Yes (for file ops) | — | Root directory for sandboxed file operations |
| `ORCHESTRATOR_DATA_ROOT` | No | `$BOND_SANDBOX_ROOT/orchestrator_state` | Override orchestrator data directory |
| `OPENROUTER_API_KEY` | No | — | API key for Firejumper VLM analysis |
| `FIREJUMPER_DIR` | No | — | Path to ConnectorStore (Node.js) |
| `FIREJUMPER_HUB` | No | `ws://localhost:7201` | WebSocket hub URL for Web Bridge |
| `FIREJUMPER_SCREEN_WIDTH` | No | `1920` | Screen width for screenshot capture |
| `FIREJUMPER_SCREEN_HEIGHT` | No | `1080` | Screen height for screenshot capture |
| `BOND_MCP_AUTH_TOKEN` | No | — | MCP authentication token |
| `BOND_DIR` | No | — | Override Bond directory (launcher only) |

### Feature Availability by Environment

| Feature | Required Variables |
|---------|--------------------|
| Filesystem tools | `BOND_SANDBOX_ROOT` |
| Orchestrator | `BOND_SANDBOX_ROOT` or `ORCHESTRATOR_DATA_ROOT` |
| Firejumper VLM (latch/screenshot) | `OPENROUTER_API_KEY` |
| Firejumper ConnectorStore | `FIREJUMPER_DIR` |
| Web Bridge | `FIREJUMPER_HUB` (running Firejumper Hub) |

---

## CLI Flags

```
python -u bond_server.py [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | `RESTRICTED` | Governance tier: `OBSERVE_ONLY`, `RESTRICTED`, `BROAD`, `FULL_AUTO` |
| `--modules-dir` | `modules` | Directory containing tool modules |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `--log-file` | — | Additional log file (logs go to stderr by default) |
| `--log-dir` | `logs` | Directory for JSONL task audit logs |
| `--auth-token-file` | — | Path to file containing auth token (recommended) |
| `--auth-token` | — | Auth token via CLI (deprecated, visible in `ps`) |
| `--insecure-allow-unverified-modules` | off | Skip SHA-256 manifest verification |
| `--rate-limit` | `100` | Global rate limit (calls/minute, range: 1-10000) |
| `--plugins-dir` | — | Plugin directory (repeatable for multiple dirs) |
| `--allow-entry-points` | off | Enable pip entry_points plugin discovery (supply chain risk) |
| `--require-plugin-hashes` | off | Reject plugins without `files_sha256` |

---

## Plugin System

Bond supports out-of-process plugins that run as separate MCP servers in subprocesses.

### Creating a Plugin

1. Create a directory with a `bond-plugin.json` manifest:

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "command": "python",
  "args": ["-u", "server.py"],
  "env_allowlist": ["MY_API_KEY"],
  "max_safety_level": "MODERATE",
  "max_inflight": 1,
  "timeout_seconds": 30,
  "files_sha256": {
    "server.py": "abc123..."
  }
}
```

2. Implement a JSON-RPC MCP server in `server.py` that responds to `tools/list` and `tools/call`.

3. Place the folder in a `--plugins-dir` directory.

### Plugin Security

- Plugins run in **isolated subprocesses** (never in-process)
- Environment is **empty by default**, only allowlisted keys are forwarded
- Dangerous env vars are **always blocked** (`LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS`, etc.)
- Plugin-declared safety levels are **ignored**; the manifest ceiling is enforced
- Tool names are prefixed (`{plugin_name}_{tool_name}`) to prevent collisions
- File integrity verified via SHA-256 hashes when `--require-plugin-hashes` is set
- Circuit breaker: max 3 restarts with exponential backoff

---

## OnlyOffice Integration

Connect Bond as an MCP server in OnlyOffice:

1. In OnlyOffice settings, add an MCP server
2. Point the command at `bond_mcp.bat` or:
   ```
   python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules
   ```
3. Use unbuffered Python (`-u` flag) — required for line-by-line JSON-RPC
4. If your path has spaces, use `bond_launcher.py` from a simple path like `C:\Bond\`

**Note:** OnlyOffice can skip the MCP `initialize` handshake and call `tools/list` directly. Bond supports both flows.

---

## Smoke Tests

### Unit Tests

```bash
python -m pytest -q
# Expected: 18 passed in <1s
```

### MCP Handshake Test

```powershell
@'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
'@ | python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules
```

Expected: Two JSON responses — `initialize` result with `protocolVersion`, then `tools/list` with 16 tools.

### OnlyOffice-Style Test (No Initialize)

```powershell
@'
{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}
'@ | python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules
```

Expected: `tools/list` returns an array of 16 tools (not `[]`).

### Tool Call Test

```powershell
@'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_status","arguments":{}}}
'@ | python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules
```

Expected: `get_status` returns `{"mode": "UNKNOWN", "summary": "No runtime snapshot found"}` (normal without orchestrator data).

---

## Architecture

```
bond_server.py           Main entry point. Parses CLI args, wires components,
│                        runs async MCP stdio loop.
│
bond_launcher.py         Thin wrapper for no-spaces-path compatibility.
bond_mcp.bat             Windows batch launcher (default dev command).
│
├── core/
│   ├── mcp_server.py    MCP JSON-RPC protocol handler (hardened).
│   │                    Request validation, auth, size limits, error handling.
│   │
│   ├── dispatcher.py    Tool execution engine. Rate limiting, parameter
│   │                    validation, timeout management, error sanitization.
│   │
│   ├── module_loader.py Dynamic module loading with SHA-256 manifest
│   │                    verification. Allowlist-based, fail-closed.
│   │
│   ├── governance.py    Policy enforcement gate. 4 tiers, per-tool safety
│   │                    levels, scoped overrides.
│   │
│   ├── task_logger.py   JSONL audit logging. Integrity chaining (hash of
│   │                    previous entry), parameter redaction, log rotation.
│   │
│   ├── plugin_bridge.py Out-of-process plugin subprocess manager. Handshake
│   │                    protocol, crash recovery, circuit breaker.
│   │
│   └── fs_utils.py      Windows-safe path resolution
│                        (GetFinalPathNameByHandleW).
│
├── modules/
│   ├── filesystem.py    Sandboxed file ops (5 tools). TOCTOU-safe.
│   ├── firejumper.py    VLM UI automation (4 tools). ConnectorSpec v0.2.1.
│   ├── web_bridge.py    Web AI bridge (3 tools). WebSocket to Firejumper Hub.
│   └── orchestrator.py  Task orchestration (4 tools). JSONL audit ledger.
│
├── models/
│   └── models.py        Data models: Tool, SafetyLevel, PolicyMode,
│                        GovernanceDecision, PluginDescriptor, etc.
│
├── tests/
│   ├── test_mcp_minimal.py          MCP protocol compliance
│   ├── test_mcp_server_auth.py      Authentication
│   ├── test_dispatcher_validation.py Parameter/rate limiting
│   └── test_plugin_integration.py   Plugin lifecycle
│
└── vscode-extension/
    ├── package.json     Extension metadata
    └── extension.cjs    VS Code integration (start/stop/status)
```

### Data Flow

```
MCP Client (OnlyOffice / Claude Desktop / etc.)
    │
    │  JSON-RPC over stdin/stdout
    ▼
BondMCPServer (core/mcp_server.py)
    │  Auth check → Request validation → Size limits
    ▼
CoreDispatcher (core/dispatcher.py)
    │  Rate limit → Parameter validation → Governance check
    ▼
GovernanceGate (core/governance.py)
    │  Policy tier → Safety level → Override check
    ▼
Tool Handler (modules/*.py)
    │  Sandbox containment → TOCTOU protection → Execute
    ▼
TaskLogger (core/task_logger.py)
    │  Log result → Integrity chain → Redact sensitive params
    ▼
JSON-RPC Response → stdout → MCP Client
```

---

## Troubleshooting

### "Module manifest verification" / 0 tools loaded
You're running in production mode without a manifest file. Add `--insecure-allow-unverified-modules` for local/dev.

### "Filesystem module initialized WITHOUT sandbox root"
Set `BOND_SANDBOX_ROOT` environment variable to a writable directory (e.g. `./io`).

### "OPENROUTER_API_KEY not set - VLM disabled"
Firejumper VLM features require an OpenRouter API key. Set `OPENROUTER_API_KEY`.

### "ConnectorStore not found"
Set `FIREJUMPER_DIR` to the path containing the Firejumper `core/connector_store.js`.

### "Failed to connect to Firejumper Hub"
The Web Bridge needs a running Firejumper Hub at `ws://localhost:7201` (or custom `FIREJUMPER_HUB`).

### Tools load but all calls return errors
Check the governance policy. `OBSERVE_ONLY` blocks all writes. Use `--policy RESTRICTED` or higher.

### OnlyOffice can't find the server
- Use `bond_mcp.bat` or a path without spaces
- Make sure Python is on PATH
- Use `-u` for unbuffered output

### VS Code extension shows "Bond is stopped"
Run **Bond: Start** from the command palette (Ctrl+Shift+P). If it fails, check the Bond output channel for errors.

---

## Requirements

- Python 3.10+
- Core server: stdlib only
- Module dependencies: `websockets>=12.0`, `aiohttp>=3.9` (see `requirements.txt`)
- Optional: Node.js (for Firejumper ConnectorStore)

## License

Bond is source-available with dual usage terms:

- Non-commercial use is allowed under the terms in `LICENSE`.
- Commercial use requires a paid commercial license from Coherent Light.

See `LICENSE` for full terms. For commercial licensing, use https://coherentlight.com.
