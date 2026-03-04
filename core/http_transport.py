"""Bond MCP Server — HTTP + SSE Transport (Streamable HTTP)

Implements the MCP "Streamable HTTP" transport spec:
  POST /mcp   — JSON-RPC request → JSON-RPC response (or SSE stream)
  GET  /mcp   — SSE stream for server-initiated notifications
  GET  /health — Health check (no auth)

This allows remote MCP clients (like Claude Code on a phone) to connect
to Bond over the network instead of requiring a local stdio pipe.

Usage:
  python -u bond_server.py --http --http-port 8900

Security:
  - Bearer token auth on every request (same token as stdio mode)
  - Bind to 127.0.0.1 by default (--http-host 0.0.0.0 for remote access)
  - CORS headers for browser-based clients
  - Request size limits carried over from MCP server
  - Session tracking with Mcp-Session-Id header
"""

from __future__ import annotations
import asyncio
import json
import logging
import secrets
import time
import hmac as hmac_mod
from typing import Optional, Dict, Any

from aiohttp import web

logger = logging.getLogger("bond.http_transport")

# Limits
MAX_REQUEST_BODY = 10 * 1024 * 1024  # 10 MB (same as stdio)
MAX_SESSIONS = 100
SESSION_TTL_S = 3600  # 1 hour idle timeout
MAX_SSE_PER_SESSION = 3  # B2: prevent SSE connection exhaustion
SSE_MAX_LIFETIME_S = 7200  # B2: 2-hour max SSE connection lifetime


class HttpTransport:
    """HTTP + SSE transport for BondMCPServer.

    Wraps the same BondMCPServer instance that run_stdio() uses,
    but accepts requests over HTTP instead of stdin/stdout.
    """

    def __init__(
        self,
        mcp_server,  # BondMCPServer instance
        host: str = "127.0.0.1",
        port: int = 8900,
        auth_token: Optional[str] = None,
    ):
        self.mcp = mcp_server
        self.host = host
        self.port = port
        self.auth_token = auth_token

        # Session management
        self._sessions: Dict[str, dict] = {}  # session_id → {created, last_seen, sse_queues}

        # App
        self.app = web.Application(client_max_size=MAX_REQUEST_BODY)
        self._setup_routes()
        self._setup_middleware()

    def _setup_routes(self):
        self.app.router.add_route("POST", "/mcp", self._handle_post)
        self.app.router.add_route("GET", "/mcp", self._handle_sse)
        self.app.router.add_route("DELETE", "/mcp", self._handle_delete_session)
        self.app.router.add_route("GET", "/health", self._handle_health)
        # OPTIONS for CORS preflight
        self.app.router.add_route("OPTIONS", "/mcp", self._handle_options)

    def _setup_middleware(self):
        # B3: When auth is configured, reflect Origin instead of wildcard
        # (Access-Control-Allow-Origin: * breaks credentialed requests)
        auth_configured = bool(self.auth_token)

        @web.middleware
        async def cors_middleware(request, handler):
            resp = await handler(request)
            if auth_configured:
                origin = request.headers.get("Origin", "")
                resp.headers["Access-Control-Allow-Origin"] = origin or "*"
                resp.headers["Access-Control-Allow-Credentials"] = "true"
            else:
                resp.headers["Access-Control-Allow-Origin"] = "*"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Mcp-Session-Id"
            resp.headers["Access-Control-Expose-Headers"] = "Mcp-Session-Id"
            return resp

        self.app.middlewares.append(cors_middleware)

    # ── Auth ─────────────────────────────────────────────────────────────────

    def _check_bearer_auth(self, request: web.Request) -> Optional[web.Response]:
        """Validate Bearer token. Returns error response or None if OK."""
        if not self.auth_token:
            return None  # Auth not configured

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32000, "message": "Authorization required. Use Bearer token."}},
                status=401,
            )

        provided = auth_header[7:]  # Strip "Bearer "
        if not hmac_mod.compare_digest(provided, self.auth_token):
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32001, "message": "Authentication failed."}},
                status=403,
            )

        return None

    # ── Session Management ───────────────────────────────────────────────────

    def _get_or_create_session(self, request: web.Request) -> str:
        """Get existing session or create new one."""
        session_id = request.headers.get("Mcp-Session-Id")

        if session_id and session_id in self._sessions:
            self._sessions[session_id]["last_seen"] = time.time()
            return session_id

        return self._get_or_create_session_direct()

    def _get_or_create_session_direct(self) -> str:
        """Create a new session without a request (for P2 recovery)."""
        if len(self._sessions) >= MAX_SESSIONS:
            self._evict_oldest_session()

        session_id = secrets.token_hex(16)
        self._sessions[session_id] = {
            "created": time.time(),
            "last_seen": time.time(),
            "sse_queues": [],
            "initialized": False,
        }
        return session_id

    def _poison_session_queues(self, session: dict):
        """P2: Send poison pill (None) to all SSE queues so they exit cleanly."""
        for queue in session.get("sse_queues", []):
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                pass

    def _evict_oldest_session(self):
        """Remove the oldest idle session."""
        if not self._sessions:
            return
        oldest_id = min(self._sessions, key=lambda k: self._sessions[k]["last_seen"])
        self._poison_session_queues(self._sessions[oldest_id])
        del self._sessions[oldest_id]
        logger.info("Evicted idle session: %s", oldest_id[:8])

    def _cleanup_expired_sessions(self):
        """Remove sessions idle for longer than TTL."""
        now = time.time()
        expired = [k for k, v in self._sessions.items() if now - v["last_seen"] > SESSION_TTL_S]
        for k in expired:
            self._poison_session_queues(self._sessions[k])
            del self._sessions[k]
            logger.debug("Expired session: %s", k[:8])

    # ── Handlers ─────────────────────────────────────────────────────────────

    async def _handle_options(self, request: web.Request) -> web.Response:
        """CORS preflight."""
        return web.Response(status=204)

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Health check — no auth required."""
        self._cleanup_expired_sessions()
        return web.json_response({
            "status": "ok",
            "server": self.mcp.server_name,
            "version": self.mcp.server_version,
            "transport": "http+sse",
            "sessions": len(self._sessions),
            "tools": self.mcp.registry.tool_count,
        })

    async def _handle_post(self, request: web.Request) -> web.Response:
        """Handle POST /mcp — JSON-RPC request → response.

        MCP Streamable HTTP spec:
        - Accept: application/json → single JSON-RPC response
        - Accept: text/event-stream → SSE stream (for streaming results)
        """
        # Auth check
        auth_err = self._check_bearer_auth(request)
        if auth_err:
            return auth_err

        # Session
        session_id = self._get_or_create_session(request)

        # B1: Early content-length check (reject before reading body into memory)
        # content_length is None for chunked encoding — only check when present
        content_length = request.content_length
        if content_length is not None and content_length > MAX_REQUEST_BODY:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32003, "message": f"Request exceeds {MAX_REQUEST_BODY} byte limit"}},
                status=413,
                headers={"Mcp-Session-Id": session_id},
            )

        # Read body
        try:
            body = await request.read()
        except Exception:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32700, "message": "Failed to read request body"}},
                status=400,
            )

        if len(body) > MAX_REQUEST_BODY:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32003, "message": f"Request exceeds {MAX_REQUEST_BODY} byte limit"}},
                status=413,
            )

        # Parse JSON
        try:
            rpc_request = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32700, "message": "Invalid JSON"}},
                status=400,
            )

        if not isinstance(rpc_request, dict):
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32600, "message": "Request must be a JSON object"}},
                status=400,
            )

        # Check if client wants SSE
        accept = request.headers.get("Accept", "")
        use_sse = "text/event-stream" in accept

        # Process the JSON-RPC request through the MCP server
        response = await self._process_rpc(rpc_request, session_id)

        if response is None:
            # Notification — no response needed
            return web.Response(status=202, headers={"Mcp-Session-Id": session_id})

        if use_sse:
            # Stream as SSE
            sse_response = web.StreamResponse(
                status=200,
                headers={
                    "Content-Type": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Mcp-Session-Id": session_id,
                },
            )
            await sse_response.prepare(request)
            data = json.dumps(response)
            await sse_response.write(f"event: message\ndata: {data}\n\n".encode())
            await sse_response.write_eof()
            return sse_response

        # Standard JSON response
        return web.json_response(
            response,
            headers={"Mcp-Session-Id": session_id},
        )

    async def _handle_sse(self, request: web.Request) -> web.StreamResponse:
        """Handle GET /mcp — SSE stream for server-initiated notifications.

        Keeps the connection open for server push (future use: tool progress,
        status updates, bus messages).
        """
        auth_err = self._check_bearer_auth(request)
        if auth_err:
            return auth_err

        session_id = request.headers.get("Mcp-Session-Id")
        if not session_id or session_id not in self._sessions:
            return web.json_response(
                {"error": "Invalid or missing Mcp-Session-Id"},
                status=400,
            )

        # B2: Enforce per-session SSE connection limit
        session = self._sessions[session_id]
        if len(session["sse_queues"]) >= MAX_SSE_PER_SESSION:
            return web.json_response(
                {"error": f"SSE connection limit ({MAX_SSE_PER_SESSION}) reached for this session"},
                status=429,
            )

        sse_response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Mcp-Session-Id": session_id,
            },
        )
        await sse_response.prepare(request)

        # Create a queue for this SSE connection
        queue: asyncio.Queue = asyncio.Queue()
        session["sse_queues"].append(queue)

        # B2: Track connection start for max lifetime enforcement
        started_at = time.time()

        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    # P2: None is the poison pill — session was evicted/deleted
                    if msg is None:
                        break
                    data = json.dumps(msg)
                    await sse_response.write(f"event: message\ndata: {data}\n\n".encode())
                except asyncio.TimeoutError:
                    # B2: Check max lifetime
                    if time.time() - started_at > SSE_MAX_LIFETIME_S:
                        logger.debug("SSE connection hit max lifetime (%ds)", SSE_MAX_LIFETIME_S)
                        break
                    # Send keepalive comment
                    await sse_response.write(b": keepalive\n\n")
                except (ConnectionResetError, ConnectionAbortedError):
                    break
        finally:
            if session_id in self._sessions:
                try:
                    self._sessions[session_id]["sse_queues"].remove(queue)
                except ValueError:
                    pass

        return sse_response

    async def _handle_delete_session(self, request: web.Request) -> web.Response:
        """Handle DELETE /mcp — close session."""
        auth_err = self._check_bearer_auth(request)
        if auth_err:
            return auth_err

        session_id = request.headers.get("Mcp-Session-Id")
        if session_id and session_id in self._sessions:
            self._poison_session_queues(self._sessions[session_id])
            del self._sessions[session_id]
            logger.info("Session closed: %s", session_id[:8])

        return web.Response(status=204)

    # ── RPC Processing ───────────────────────────────────────────────────────

    async def _process_rpc(self, request: dict, session_id: str) -> Optional[dict]:
        """Process a JSON-RPC request through the MCP server.

        Reuses the same validation and dispatch logic as run_stdio(),
        but returns the response dict instead of writing to stdout.

        P1: Uses per-session 'initialized' tracking instead of relying on
        the global _initialized flag for session-level init state. The global
        flag is only used once to bootstrap the underlying MCP server.
        """
        # Validate JSON-RPC
        if request.get("jsonrpc") != "2.0":
            return self.mcp._make_error(request.get("id"), -32600, "Invalid jsonrpc version")

        method = request.get("method")
        if not isinstance(method, str) or not method:
            return self.mcp._make_error(request.get("id"), -32600, "Invalid method")

        req_id = request.get("id")
        is_notification = "id" not in request

        params = request.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return self.mcp._make_error(req_id, -32602, "params must be an object")

        # P2: Verify session still exists (could be evicted between handler and here)
        session = self._sessions.get(session_id)
        if session is None:
            # Session was evicted — re-create it
            session_id = self._get_or_create_session_direct()
            session = self._sessions[session_id]

        # Route to handler
        try:
            if method == "initialize":
                # P1: First initialize bootstraps the MCP server; subsequent
                # sessions get the same capabilities without touching global state
                if not self.mcp._initialized:
                    # First init — bootstrap via handle_initialize (sets global flag)
                    result = self.mcp.handle_initialize(params)
                else:
                    # Per-session init — return server info without touching global
                    client_info = params.get("clientInfo", {})
                    logger.info(
                        "HTTP session %s initialize (client=%s)",
                        session_id[:8],
                        client_info.get("name", "unknown"),
                    )
                    result = {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {
                            "name": self.mcp.server_name,
                            "version": self.mcp.server_version,
                        },
                    }
                session["initialized"] = True
                return self.mcp._make_response(req_id, result)

            elif method == "notifications/initialized":
                session["initialized"] = True
                return None  # Notification — no response

            elif method == "tools/list":
                # Ensure global MCP server is bootstrapped (for dispatcher)
                if not self.mcp._initialized:
                    logger.info("Auto-init MCP server (HTTP session %s called tools/list before initialize)", session_id[:8])
                    self.mcp._initialized = True
                result = self.mcp.handle_list_tools()
                return self.mcp._make_response(req_id, result)

            elif method == "tools/call":
                if not self.mcp._initialized:
                    logger.info("Auto-init MCP server (HTTP session %s called tools/call before initialize)", session_id[:8])
                    self.mcp._initialized = True
                result = await self.mcp.handle_call_tool(params, req_id)
                return self.mcp._make_response(req_id, result)

            elif method == "ping":
                return self.mcp._make_response(req_id, {})

            else:
                if is_notification:
                    return None
                return self.mcp._make_error(req_id, -32601, f"Method not found: {method}")

        except Exception as e:
            logger.error("Handler error for method=%s: %s", method, e, exc_info=True)
            if is_notification:
                return None
            return self.mcp._make_error(req_id, -32603, "Internal server error")

    # ── Run ──────────────────────────────────────────────────────────────────

    async def run(self):
        """Start the HTTP server."""
        runner = web.AppRunner(self.app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        # B5: Guard against double cleanup
        cleaned_up = False

        logger.info(
            "Bond HTTP+SSE transport listening on http://%s:%d/mcp (auth=%s)",
            self.host, self.port, "enabled" if self.auth_token else "disabled",
        )
        print(
            f"Bond HTTP+SSE transport: http://{self.host}:{self.port}/mcp",
            file=__import__("sys").stderr,
        )

        # Keep running until shutdown
        try:
            while not self.mcp._shutting_down:
                await asyncio.sleep(1)
                self._cleanup_expired_sessions()
        finally:
            if not cleaned_up:
                cleaned_up = True
                # Poison all remaining SSE connections before cleanup
                for session in self._sessions.values():
                    self._poison_session_queues(session)
                await runner.cleanup()
                logger.info("HTTP transport stopped")
