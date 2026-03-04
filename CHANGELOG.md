# Changelog

## 0.2.0 (2026-03-04)

Initial public release.

### Tools (24 across 6 modules)
- **filesystem** (6): `read_file`, `write_file`, `read_file_hash`, `list_directory`, `search_files`, `file_info`
- **firejumper** (4): `firejumper_latch`, `firejumper_execute`, `firejumper_screenshot`, `firejumper_list_learned`
- **web_bridge** (3): `ask_web_ai`, `read_web_ai`, `list_available_automations`
- **orchestrator** (4): `get_status`, `update_status`, `append_ledger`, `read_ledger`
- **bus_ipc** (3): `list_agents`, `send_to_agent`, `wait_for_reply`
- **bus_v5** (4): `bus_post`, `bus_post_wait`, `bus_actors`, `bus_status`

### HTTP + SSE Transport (new)
- Remote MCP access via HTTP + Server-Sent Events
- `POST /mcp` for JSON-RPC requests (same protocol as stdio)
- `GET /mcp` for SSE notification stream
- `GET /health` for health check (no auth)
- `DELETE /mcp` for session cleanup
- Bearer token auth via `Authorization` header
- Session management with `Mcp-Session-Id` header (auto-created, 1hr TTL)
- CORS headers for browser-based clients
- CLI: `--http --http-port 8900 --http-host 0.0.0.0`
- Enables: phone Claude Code → Bond on desktop → full tool access

### bus_v5 module (new)
- Multi-agent message bus via Bus v5 WebSocket gateway (port 18900)
- Offline queuing: messages held until recipient connects
- Fan-out: `to="all"` sends to every connected actor
- Reply correlation: `bus_post_wait` with request_id-based matching
- Actor discovery: `bus_actors` lists all connected agents
- Gateway health: `bus_status` with port, uptime, queue depth
- Env-configurable: BUS_V5_DIR, BUS_V5_PORT, BOND_BUS_V5_ACTOR

### Security
- 4-tier governance system (OBSERVE_ONLY, RESTRICTED, BROAD, FULL_AUTO)
- Sandboxed filesystem with TOCTOU protection and symlink defense
- SHA-256 module manifest verification (production mode)
- Out-of-process plugin system with circuit breaker and env allowlisting
- Bearer token auth with timing-safe comparison (stdio and HTTP)
- JSONL audit logging with integrity chaining and parameter redaction
- Rate limiting (global + per-tool sliding window)

### Infrastructure
- `--version` flag on CLI
- `scripts/generate_manifests.py` for production manifest generation
- VS Code extension for server lifecycle management
- Windows batch launcher + Python path wrapper for spaces-in-path compatibility

### Hosts
- Claude Desktop, Claude Code, OnlyOffice, LibreOffice, any MCP-compatible client
- Remote Claude Code instances via HTTP+SSE transport
