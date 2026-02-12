"""Bond MCP Server — MCP Protocol Handler (Hardened)

Changes from original:
- JSON-RPC 2.0 compliance (jsonrpc field, proper error codes)
- MCP initialize/initialized handshake with capability negotiation
- Request size limits (prevent memory exhaustion)
- Optional bearer token authentication
- Request ID tracking through dispatch chain
- Proper error code taxonomy
- Notification support (no response required)
- Graceful shutdown signaling
"""

from __future__ import annotations
import hmac
import json
import sys
import asyncio
import logging
from typing import Optional, Dict, Any

from core.dispatcher import CoreDispatcher
from core.module_loader import ToolRegistry

logger = logging.getLogger("bond.mcp_server")

# Limits
MAX_REQUEST_LINE_BYTES = 10 * 1024 * 1024  # 10 MB max per JSON-RPC line
JSONRPC_VERSION = "2.0"

# Standard JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# Custom error codes (MCP range)
AUTH_REQUIRED = -32000
AUTH_FAILED = -32001
RATE_LIMITED = -32002
REQUEST_TOO_LARGE = -32003


class BondMCPServer:
    def __init__(
        self,
        dispatcher: CoreDispatcher,
        registry: ToolRegistry,
        auth_token: Optional[str] = None,
        server_name: str = "bond-mcp-server",
        server_version: str = "0.2.0",
    ):
        self.dispatcher = dispatcher
        self.registry = registry
        self.auth_token = auth_token  # Caller (bond_server.py) resolves env var — no double read
        if self.auth_token is not None:
            if not isinstance(self.auth_token, str):
                raise ValueError("auth_token must be a string")
            if not self.auth_token or not self.auth_token.strip():
                raise ValueError("auth_token cannot be empty or whitespace-only")
        self.server_name = server_name
        self.server_version = server_version
        self._initialized = False
        self._init_confirmed = False  # True after notifications/initialized received
        self._shutting_down = False

    def _make_response(self, req_id: Any, result: Any) -> dict:
        return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "result": result}

    def _make_error(self, req_id: Any, code: int, message: str, data: Any = None) -> dict:
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "error": error}

    def _check_auth(self, request: dict) -> Optional[dict]:
        """Validate authentication if configured. Returns error response or None."""
        if not self.auth_token:
            return None  # Auth not configured

        # Auth can be in params._meta.auth_token or in a top-level auth field
        raw_params = request.get("params") or {}
        meta = raw_params.get("_meta") if isinstance(raw_params, dict) else None
        if not isinstance(meta, dict):
            meta = {}
        provided_token = meta.get("auth_token") or request.get("auth_token")

        if not provided_token:
            return self._make_error(
                request.get("id"), AUTH_REQUIRED,
                "Authentication required. Provide auth_token in params._meta."
            )

        # Type validation: compare_digest requires strings
        if not isinstance(provided_token, str):
            logger.warning(f"Authentication failed: invalid token type for request {request.get('id')}")
            return self._make_error(
                request.get("id"), AUTH_FAILED,
                "Authentication failed."
            )

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(provided_token, self.auth_token):
            logger.warning(f"Authentication failed for request {request.get('id')}")
            return self._make_error(
                request.get("id"), AUTH_FAILED,
                "Authentication failed."
            )

        return None

    def handle_initialize(self, params: dict) -> dict:
        """MCP initialize handshake — declare server capabilities."""
        if self._initialized:
            logger.warning("Re-initialization attempt rejected")
            raise ValueError("Already initialized")

        self._initialized = True
        client_info = params.get("clientInfo", {})

        # Sanitize client info to prevent log injection
        def _sanitize_log(s):
            if not isinstance(s, str):
                return "invalid"
            return s.replace('\n', '\\n').replace('\r', '\\r').replace('\x00', '')

        logger.info(
            f"MCP initialize: client={_sanitize_log(client_info.get('name', 'unknown'))} "
            f"version={_sanitize_log(client_info.get('version', 'unknown'))}"
        )
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.server_name,
                "version": self.server_version,
            },
        }

    def handle_list_tools(self) -> dict:
        return {"tools": self.registry.list_tools()}

    async def handle_call_tool(self, request: dict, req_id: Any) -> dict:
        """Handle tools/call — returns MCP tool result (not JSON-RPC error dicts).

        Since tools/call results are wrapped in _make_response by the caller,
        all returns must be MCP content dicts, not JSON-RPC error objects.
        """
        tool_name = request.get("name")
        arguments = request.get("arguments", {})

        if not tool_name:
            return {"content": [{"type": "text", "text": "Missing tool name"}], "isError": True}

        if not isinstance(arguments, dict):
            return {"content": [{"type": "text", "text": "arguments must be an object"}], "isError": True}

        # Pass request_id for correlation
        request_id = str(req_id) if req_id is not None else None
        result = await self.dispatcher.handle_mcp_call(tool_name, arguments, request_id)
        return result

    async def run_stdio(self) -> None:
        """Main stdio transport loop with hardened message handling."""
        loop = asyncio.get_running_loop()
        logger.info(f"{self.server_name} v{self.server_version} starting stdio transport")

        def _readline_limited():
            """Read at most MAX_REQUEST_LINE_BYTES + 1 to detect oversize."""
            return sys.stdin.buffer.readline(MAX_REQUEST_LINE_BYTES + 1)

        def _drain_line():
            """Drain remainder of an oversized line to keep stream aligned."""
            while True:
                chunk = sys.stdin.buffer.readline(1024 * 1024)
                if not chunk or chunk.endswith(b"\n"):
                    break

        while not self._shutting_down:
            try:
                line_bytes = await loop.run_in_executor(None, _readline_limited)
            except (EOFError, KeyboardInterrupt):
                break

            if not line_bytes:
                break

            # Request size check (before decoding — prevents memory bomb)
            if len(line_bytes) > MAX_REQUEST_LINE_BYTES:
                logger.warning(f"Request too large: {len(line_bytes)} bytes")
                if not line_bytes.endswith(b"\n"):
                    await loop.run_in_executor(None, _drain_line)
                self._write_response(
                    self._make_error(None, REQUEST_TOO_LARGE,
                                     f"Request exceeds {MAX_REQUEST_LINE_BYTES} byte limit")
                )
                continue

            line = line_bytes.decode("utf-8", errors="replace")

            logger.debug(f"MCP RECV: {line.strip()[:200]}")

            # Parse JSON
            try:
                request = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error: {e}")
                self._write_response(
                    self._make_error(None, PARSE_ERROR, "Invalid JSON")
                )
                continue
            except RecursionError:
                logger.warning("JSON recursion limit exceeded (deeply nested payload)")
                self._write_response(
                    self._make_error(None, PARSE_ERROR, "JSON structure too deep")
                )
                continue

            # --- JSON-RPC request validation ---
            # Explicitly reject batch requests (arrays) — prevents amplification attacks
            if isinstance(request, list):
                self._write_response(
                    self._make_error(None, INVALID_REQUEST,
                                     "Batch requests are not supported. Send requests individually.")
                )
                continue

            if not isinstance(request, dict):
                self._write_response(self._make_error(None, INVALID_REQUEST, "Invalid request (not an object)"))
                continue

            if request.get("jsonrpc") != JSONRPC_VERSION:
                self._write_response(self._make_error(request.get("id"), INVALID_REQUEST, "Invalid jsonrpc version"))
                continue

            method = request.get("method")
            if not isinstance(method, str) or not method:
                self._write_response(self._make_error(request.get("id"), INVALID_REQUEST, "Invalid method"))
                continue

            req_id = request.get("id", None)
            if "id" in request:
                if isinstance(req_id, (dict, list, set, bytes)):
                    self._write_response(self._make_error(None, INVALID_REQUEST, "Invalid id type"))
                    continue
                try:
                    json.dumps(req_id)
                except (TypeError, ValueError):
                    self._write_response(self._make_error(None, INVALID_REQUEST, "Invalid id type"))
                    continue

            params = request.get("params", {})
            if params is None:
                params = {}
            if not isinstance(params, dict):
                self._write_response(self._make_error(req_id, INVALID_PARAMS, "params must be an object"))
                continue

            # Check if this is a notification (no id = no response expected)
            is_notification = "id" not in request

            # Handshake handling — lenient for clients like OnlyOffice that skip initialize
            if method == "initialize":
                pass  # always allowed
            elif method == "notifications/initialized":
                if not self._initialized:
                    continue
            elif method == "ping":
                pass  # always allowed
            else:
                # Auto-initialize if client skipped handshake entirely (OnlyOffice does this)
                if not self._initialized:
                    logger.info("Auto-initializing (client skipped initialize handshake)")
                    self._initialized = True
                    self._init_confirmed = True
                elif not self._init_confirmed:
                    self._init_confirmed = True
                    logger.info("Client implicitly confirmed initialization")

            # Authentication check FIRST (skip for handshake methods)
            if method not in ("initialize", "notifications/initialized"):
                auth_error = self._check_auth(request)
                if auth_error:
                    if not is_notification:
                        self._write_response(auth_error)
                    continue

            # Strip auth tokens from params AND top-level request before dispatch/logging
            # Defensive copy to avoid mutating the original request object
            if isinstance(params, dict):
                params = params.copy()
                meta = params.get("_meta")
                if isinstance(meta, dict):
                    meta = meta.copy()
                    meta.pop("auth_token", None)
                    if not meta:
                        params.pop("_meta", None)
                    else:
                        params["_meta"] = meta
            # Also strip top-level auth_token from request to prevent downstream leakage
            request.pop("auth_token", None)

            try:
                if method == "initialize":
                    response = self.handle_initialize(params)
                    self._write_response(self._make_response(req_id, response))

                elif method == "notifications/initialized":
                    # Client acknowledges initialization — no response needed
                    self._init_confirmed = True
                    logger.info("Client initialization confirmed")

                elif method == "tools/list":
                    response = self.handle_list_tools()
                    self._write_response(self._make_response(req_id, response))

                elif method == "tools/call":
                    result = await self.handle_call_tool(params, req_id)
                    # MCP spec: tool errors are successful JSON-RPC responses
                    # with isError=true in the result, NOT JSON-RPC error objects.
                    # JSON-RPC errors are reserved for protocol-level failures.
                    self._write_response(self._make_response(req_id, result))

                elif method == "ping":
                    self._write_response(self._make_response(req_id, {}))

                else:
                    if not is_notification:
                        self._write_response(
                            self._make_error(req_id, METHOD_NOT_FOUND,
                                             f"Method not found: {method}")
                        )

            except Exception as e:
                logger.error(f"Handler error for method={method}: {e}", exc_info=True)
                if not is_notification:
                    self._write_response(
                        self._make_error(req_id, INTERNAL_ERROR,
                                         "Internal server error")
                    )

        logger.info("MCP server stdio loop ended")

    def _write_response(self, response: dict) -> None:
        try:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except TypeError as e:
            logger.error(f"JSON serialization failed: {e}")
            try:
                fallback = {
                    "jsonrpc": JSONRPC_VERSION,
                    "id": None,
                    "error": {"code": INTERNAL_ERROR, "message": "Response serialization failed"}
                }
                sys.stdout.write(json.dumps(fallback) + "\n")
                sys.stdout.flush()
            except Exception:
                logger.critical("Failed to serialize fallback error response")
        except (BrokenPipeError, OSError) as e:
            logger.error(f"Failed to write response: {e}")
            self._shutting_down = True

    def request_shutdown(self) -> None:
        self._shutting_down = True
        logger.info("Shutdown requested")
