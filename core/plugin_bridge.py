"""Bond MCP Server — Plugin Bridge (Subprocess Manager)

Manages out-of-process plugins. Each plugin is a separate MCP server
running as a subprocess. Bond communicates via newline-delimited JSON-RPC
over stdin/stdout.

All third-party plugins run out-of-process only — no in-process promotion.

Security model:
- Pre-launch SHA-256 verification of plugin code files
- TOCTOU prevention: verified files copied to Bond cache before launch
- Subprocess env: only allowlisted keys (+ PATH, SYSTEMROOT, etc.)
- Safety ceiling: plugin-declared levels IGNORED, descriptor ceiling applied
- Schema sanitization: block remote $ref, enforce max depth
- Auth tokens / _meta fields stripped from all outbound params

Reviewed and approved by 6-AI consensus (ChatGPT, DeepSeek, Gemini, Grok,
Kimi, Claude) across 4 review rounds.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set

from models.models import PluginDescriptor, SafetyLevel, Tool

logger = logging.getLogger(__name__)

# --- Constants ---
MAX_LINE_BYTES = 2 * 1024 * 1024       # 2 MB per JSON-RPC line
MAX_TOOLS_LIST_BYTES = 2 * 1024 * 1024  # 2 MB tools/list payload
MAX_RESULT_BYTES = 1 * 1024 * 1024      # 1 MB per tool result
SCHEMA_MAX_DEPTH = 10                    # Max JSON Schema nesting
SCHEMA_MAX_REFS = 50                     # Max $ref resolutions
HANDSHAKE_TIMEOUT = 10.0                 # Seconds for initialize + tools/list
HEARTBEAT_PING_TIMEOUT = 5.0            # Seconds to wait for ping response
HEARTBEAT_MISS_LIMIT = 3                # Missed pings before declaring dead
SEMAPHORE_ACQUIRE_TIMEOUT = 30.0        # Seconds to wait for inflight slot
GRACEFUL_STOP_TIMEOUT = 5.0             # Seconds for graceful subprocess exit
MCP_PROTOCOL_VERSION = "2024-11-05"     # Centralized MCP protocol version
POSIX_KILL_GRACE = 3.0                  # Seconds between SIGTERM and SIGKILL
DRAIN_TIMEOUT = 10.0                    # Seconds to wait for stdin.drain()
DEV_COPY_MAX_BYTES = 100 * 1024 * 1024  # 100 MB dev-mode copy cap


def _safe_exc(e: Exception, max_len: int = 200) -> str:
    """Sanitize exception for logging: strip CR/LF, truncate."""
    return str(e)[:max_len].replace('\r', ' ').replace('\n', ' ')


class PluginCrashError(Exception):
    """Raised when a plugin subprocess crashes or is killed."""
    pass


class PluginOfflineError(Exception):
    """Raised when circuit breaker is open (plugin offline)."""
    pass


class PluginBridge:
    """Manages lifecycle of an out-of-process MCP plugin."""

    def __init__(self, descriptor: PluginDescriptor):
        self.descriptor = descriptor
        self._process: Optional[asyncio.subprocess.Process] = None
        self._stdout_reader: Optional[asyncio.Task] = None
        self._stderr_reader: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._pending: Dict[int, asyncio.Future] = {}
        self._inflight_sem: Optional[asyncio.Semaphore] = None
        self._next_id: int = 1
        self._tools: List[Tool] = []
        self._restart_count: int = 0
        self._circuit_open: bool = False
        self._backoff_until: float = 0.0
        self._stderr_buffer: deque = deque(maxlen=50)
        self._cache_dir: Optional[str] = None   # Only set when _copy_to_cache creates a temp dir
        self._launch_dir: Optional[str] = None  # Subprocess cwd (cache copy or source working_dir)
        self._alive: bool = False
        self._lock = asyncio.Lock()
        self._inflight_count: int = 0
        self._inflight_since: Optional[float] = None  # monotonic time inflight became > 0

        # Allowlist of param keys per tool (from inputSchema.properties)
        # Maps raw_tool_name → frozenset of allowed keys (None = no restriction)
        self._tool_allowed_params: Dict[str, Optional[frozenset]] = {}

        # Windows Job Object handle (ctypes)
        self._job_handle = None

    # --- Public API ---

    async def start(self) -> bool:
        """Launch plugin subprocess, complete MCP handshake, discover tools.

        Returns True if plugin started successfully, False on any failure.
        """
        try:
            # 1. Copy to cache (hash-while-copy when hashes present)
            if self.descriptor.files_sha256:
                self._cache_dir = self._copy_to_cache()
                self._launch_dir = self._cache_dir
                logger.info(
                    "Plugin %r: files verified + cached at %s",
                    self.descriptor.name, self._cache_dir
                )
            else:
                # No hashes: run from source dir. _cache_dir stays None so
                # _cleanup_cache() will NOT delete the source directory.
                self._cache_dir = None
                self._launch_dir = self.descriptor.working_dir
                logger.debug(
                    "Plugin %r: no file hashes — running from source",
                    self.descriptor.name
                )

            # 2. Spawn subprocess
            if not await self._spawn_process():
                return False

            # 3. Start reader loops
            self._stdout_reader = asyncio.create_task(
                self._stdout_reader_loop(),
                name=f"plugin-{self.descriptor.name}-stdout"
            )
            self._stderr_reader = asyncio.create_task(
                self._stderr_reader_loop(),
                name=f"plugin-{self.descriptor.name}-stderr"
            )

            # 4. MCP lifecycle: initialize → initialized → tools/list
            if not await self._mcp_handshake():
                await self._kill_process_tree()
                return False

            # 5. Discover and validate tools
            tools_data = await self._mcp_tools_list()
            if tools_data is None:
                await self._kill_process_tree()
                return False

            self._tools = self._process_tools(tools_data)
            if self._tools is None:
                await self._kill_process_tree()
                return False

            # 6. Initialize concurrency control
            self._inflight_sem = asyncio.Semaphore(
                self.descriptor.max_inflight
            )
            self._alive = True

            # 7. Start heartbeat
            self._heartbeat_task = asyncio.create_task(
                self._heartbeat_loop(),
                name=f"plugin-{self.descriptor.name}-heartbeat"
            )

            logger.info(
                "Plugin %r v%r started: %d tools, max_inflight=%d",
                self.descriptor.name, self.descriptor.version,
                len(self._tools), self.descriptor.max_inflight
            )
            return True

        except Exception as e:
            logger.error(
                "Plugin %r failed to start: %s",
                self.descriptor.name, _safe_exc(e)
            )
            await self._cleanup()
            return False

    async def call_tool(self, tool_name: str, params: dict) -> dict:
        """Call a tool on the plugin subprocess.

        Supports concurrent calls via request ID routing.
        Respects max_inflight semaphore and circuit breaker.
        """
        # Circuit breaker check — under lock to prevent multiple concurrent
        # callers from all entering the half-open recovery path simultaneously
        if self._circuit_open:
            async with self._lock:
                # Re-check after acquiring lock (another caller may have recovered)
                if not self._circuit_open:
                    pass  # Already recovered — proceed to call
                else:
                    now = time.monotonic()
                    if now < self._backoff_until:
                        logger.debug(
                            "Plugin %r offline, last stderr: %s",
                            self.descriptor.name, self._get_stderr_context()
                        )
                        raise PluginOfflineError(
                            f"Plugin '{self.descriptor.name}' is offline "
                            f"(circuit breaker open)"
                        )
                    # Half-open: attempt recovery (only one caller runs this)
                    if not await self._attempt_recovery():
                        raise PluginOfflineError(
                            f"Plugin '{self.descriptor.name}' recovery failed"
                        )

        # Check process is alive
        if not self._alive or self._process is None:
            raise PluginCrashError(
                f"Plugin '{self.descriptor.name}' process is not running"
            )

        # Validate tool_name against known tools from tools/list — prevents
        # invoking hidden/undeclared plugin tools that bypass safety gating
        if tool_name not in self._tool_allowed_params:
            return self._error_result(
                f"Unknown tool {tool_name!r} — not in plugin's tools/list"
            )

        # Acquire inflight slot
        acquired = False
        try:
            await asyncio.wait_for(
                self._inflight_sem.acquire(),
                timeout=SEMAPHORE_ACQUIRE_TIMEOUT
            )
            acquired = True
        except asyncio.TimeoutError:
            return self._error_result(
                f"Plugin '{self.descriptor.name}' overloaded "
                f"(max_inflight={self.descriptor.max_inflight})"
            )

        # From here, acquired=True — the finally block will release.
        async with self._lock:
            self._inflight_count += 1
        try:
            # Sanitize params: allowlist from inputSchema properties (preferred),
            # or fall back to blocklist stripping for tools with no schema
            clean_params = self._sanitize_params(params, tool_name)

            # Pre-serialization size check: estimate param size BEFORE
            # json.dumps to prevent OOM from huge attacker-controlled params.
            if self._estimate_obj_bytes(clean_params) > MAX_LINE_BYTES:
                return self._error_result(
                    f"Tool params too large (pre-serialization estimate "
                    f"exceeds {MAX_LINE_BYTES:,} bytes)"
                )

            # Assign request ID and create Future
            request_id = self._next_id
            self._next_id += 1
            loop = asyncio.get_running_loop()
            future: asyncio.Future = loop.create_future()
            self._pending[request_id] = future

            # Build JSON-RPC request
            request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": clean_params
                }
            }

            # Send to subprocess stdin (cap outbound size to prevent memory DoS
            # from huge tool params flowing through to the plugin subprocess)
            try:
                line = json.dumps(request) + "\n"
                line_bytes = line.encode('utf-8')
                if len(line_bytes) > MAX_LINE_BYTES:
                    self._pending.pop(request_id, None)
                    future.cancel()
                    return self._error_result(
                        f"Outbound request too large "
                        f"({len(line_bytes):,} bytes, max {MAX_LINE_BYTES:,})"
                    )
                self._process.stdin.write(line_bytes)
                await asyncio.wait_for(
                    self._process.stdin.drain(), timeout=DRAIN_TIMEOUT
                )
            except asyncio.TimeoutError:
                self._pending.pop(request_id, None)
                future.cancel()
                asyncio.create_task(self._handle_process_death())
                raise PluginCrashError(
                    f"Plugin '{self.descriptor.name}' stdin drain timed out "
                    f"(plugin not reading stdin)"
                )
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                self._pending.pop(request_id, None)
                future.cancel()
                asyncio.create_task(self._handle_process_death())
                raise PluginCrashError(
                    f"Plugin '{self.descriptor.name}' pipe broken: {e}"
                )

            # Wait for response
            try:
                result = await asyncio.wait_for(
                    future,
                    timeout=self.descriptor.timeout_seconds
                )
                # Enforce result size limit (all JSON-serializable types, not just dict)
                try:
                    result_size = len(json.dumps(result))
                except (TypeError, ValueError, RecursionError):
                    result_size = 0
                if result_size > MAX_RESULT_BYTES:
                    logger.warning(
                        "Plugin %r tool %r: result too large (%d bytes, max %d)",
                        self.descriptor.name, tool_name, result_size, MAX_RESULT_BYTES
                    )
                    return self._error_result(
                        f"Plugin result exceeds size limit ({result_size} bytes)"
                    )
                # Successful call resets restart count
                self._restart_count = 0
                return result
            except asyncio.TimeoutError:
                self._pending.pop(request_id, None)
                future.cancel()
                logger.warning(
                    "Plugin %r tool %r timed out after %ss",
                    self.descriptor.name, tool_name,
                    self.descriptor.timeout_seconds
                )
                asyncio.create_task(self._handle_process_death())
                return self._error_result(
                    f"Plugin '{self.descriptor.name}' timed out"
                )
            except PluginCrashError:
                return self._error_result(
                    f"Plugin '{self.descriptor.name}' crashed during call"
                )
            except asyncio.CancelledError:
                # Upstream cancellation (e.g. client disconnect) — clean up
                # the pending entry so it doesn't leak memory
                self._pending.pop(request_id, None)
                future.cancel()
                raise
            except RuntimeError as e:
                # JSON-RPC error from plugin (e.g. unknown tool, invalid params)
                return self._error_result(str(e))

        finally:
            if acquired:
                async with self._lock:
                    self._inflight_count -= 1
                self._inflight_sem.release()

    async def stop(self):
        """Gracefully stop the plugin subprocess."""
        logger.info("Stopping plugin %r...", self.descriptor.name)
        self._alive = False
        await self._cleanup()
        logger.info("Plugin %r stopped", self.descriptor.name)

    def get_tools(self) -> List[Tool]:
        """Return cached tool list (prefixed, safety-capped, schema-sanitized)."""
        return list(self._tools)

    @property
    def is_alive(self) -> bool:
        """Process running AND circuit closed."""
        return self._alive and not self._circuit_open

    @property
    def is_degraded(self) -> bool:
        """Circuit breaker open (plugin offline)."""
        return self._circuit_open

    # --- Subprocess Lifecycle ---

    async def _spawn_process(self) -> bool:
        """Spawn the plugin subprocess with proper isolation."""
        try:
            env = self.descriptor.build_subprocess_env()
            cwd = self._launch_dir or self.descriptor.working_dir

            kwargs = {
                'stdin': asyncio.subprocess.PIPE,
                'stdout': asyncio.subprocess.PIPE,
                'stderr': asyncio.subprocess.PIPE,
                'env': env,
                'cwd': cwd,
                # Match protocol line limit: default 64KB causes
                # LimitOverrunError for valid lines > 64KB but < 2MB.
                'limit': MAX_LINE_BYTES,
            }

            # Platform-specific process group handling
            if sys.platform == 'win32':
                # CREATE_NEW_PROCESS_GROUP for clean termination
                kwargs['creationflags'] = (
                    0x00000200  # CREATE_NEW_PROCESS_GROUP
                )
            else:
                # POSIX: new session for killpg
                kwargs['start_new_session'] = True

            cmd = [self.descriptor.command] + self.descriptor.args
            self._process = await asyncio.create_subprocess_exec(
                *cmd, **kwargs
            )

            # Windows: assign to Job Object for process tree cleanup
            if sys.platform == 'win32':
                self._setup_windows_job_object()

            logger.debug(
                "Plugin %r spawned (PID %d)",
                self.descriptor.name, self._process.pid
            )
            return True

        except Exception as e:
            logger.error(
                "Plugin %r spawn failed: %s",
                self.descriptor.name, _safe_exc(e)
            )
            return False

    def _setup_windows_job_object(self):
        """Create Windows Job Object and assign plugin process to it.

        This ensures the entire process tree is killed on termination.
        CREATE_BREAKAWAY_FROM_JOB is OFF by default for security.
        """
        if sys.platform != 'win32' or self._process is None:
            return

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32

            # Create Job Object
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                logger.warning(
                    "Plugin %r: CreateJobObjectW failed",
                    self.descriptor.name
                )
                return

            # Configure: kill all processes when job closes
            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),  # ULONG_PTR
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation",
                     JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", ctypes.c_byte * 48),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE

            # If allow_breakaway is True, also set BREAKAWAY_OK
            if self.descriptor.allow_breakaway:
                info.BasicLimitInformation.LimitFlags |= 0x0800

            kernel32.SetInformationJobObject(
                job,
                9,  # JobObjectExtendedLimitInformation
                ctypes.byref(info),
                ctypes.sizeof(info)
            )

            # Open process handle and assign to job
            # Minimum rights for AssignProcessToJobObject:
            # PROCESS_SET_QUOTA (0x0100) + PROCESS_TERMINATE (0x0001)
            PROCESS_SET_QUOTA = 0x0100
            PROCESS_TERMINATE = 0x0001
            handle = kernel32.OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, self._process.pid
            )
            if handle:
                result = kernel32.AssignProcessToJobObject(job, handle)
                if not result:
                    # May fail if process is already in a job and
                    # BREAKAWAY_FROM_JOB wasn't set on parent
                    logger.warning(
                        "Plugin %r: AssignProcessToJobObject failed "
                        "(process may already be in a job)",
                        self.descriptor.name
                    )
                kernel32.CloseHandle(handle)

            self._job_handle = job
            logger.debug(
                "Plugin %r: Job Object assigned",
                self.descriptor.name
            )

        except Exception as e:
            logger.warning(
                "Plugin %r: Job Object setup failed: %s",
                self.descriptor.name, _safe_exc(e)
            )

    # --- MCP Protocol ---

    async def _mcp_handshake(self) -> bool:
        """Complete MCP initialize → initialized → ready handshake."""
        try:
            # Send initialize request
            init_result = await self._send_request(
                "initialize",
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "bond-mcp-gateway",
                        "version": "0.2.0"
                    }
                },
                timeout=HANDSHAKE_TIMEOUT
            )

            if init_result is None:
                logger.error(
                    "Plugin %r: initialize handshake failed",
                    self.descriptor.name
                )
                return False

            # Send initialized notification (no response expected)
            notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }
            line = json.dumps(notification) + "\n"
            self._process.stdin.write(line.encode('utf-8'))
            await asyncio.wait_for(
                self._process.stdin.drain(), timeout=DRAIN_TIMEOUT
            )

            logger.debug(
                "Plugin %r: MCP handshake complete",
                self.descriptor.name
            )
            return True

        except Exception as e:
            logger.error(
                "Plugin %r: handshake error: %s",
                self.descriptor.name, _safe_exc(e)
            )
            return False

    async def _mcp_tools_list(self) -> Optional[dict]:
        """Request tools/list from plugin. Returns raw response or None."""
        try:
            result = await self._send_request(
                "tools/list", {}, timeout=HANDSHAKE_TIMEOUT
            )
            if result is None:
                logger.error(
                    "Plugin %r: tools/list failed",
                    self.descriptor.name
                )
                return None

            # Enforce size limit on tools/list payload
            try:
                payload_size = len(json.dumps(result))
            except (TypeError, ValueError, RecursionError):
                logger.error(
                    "Plugin %r: tools/list payload not serializable",
                    self.descriptor.name
                )
                return None
            if payload_size > MAX_TOOLS_LIST_BYTES:
                logger.error(
                    "Plugin %r: tools/list payload too large (%d bytes, max %d)",
                    self.descriptor.name, payload_size, MAX_TOOLS_LIST_BYTES
                )
                return None

            return result

        except Exception as e:
            logger.error(
                "Plugin %r: tools/list error: %s",
                self.descriptor.name, _safe_exc(e)
            )
            return None

    async def _send_request(
        self, method: str, params: dict, timeout: float = 10.0
    ) -> Optional[dict]:
        """Send a JSON-RPC request and wait for response by ID.

        Returns the result dict on success, None on timeout/pipe error.
        JSON-RPC errors from the plugin are also returned as None (logged).
        """
        if self._process is None or self._process.stdin is None:
            return None

        request_id = self._next_id
        self._next_id += 1
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[request_id] = future

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }

        try:
            line = json.dumps(request) + "\n"
            self._process.stdin.write(line.encode('utf-8'))
            await asyncio.wait_for(
                self._process.stdin.drain(), timeout=DRAIN_TIMEOUT
            )
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            self._pending.pop(request_id, None)
            future.cancel()
            logger.warning(
                "Plugin %r: %s timed out after %ss",
                self.descriptor.name, method, timeout
            )
            return None
        except RuntimeError as e:
            # JSON-RPC error from plugin (set_exception in stdout reader)
            logger.warning(
                "Plugin %r: %s returned error: %s",
                self.descriptor.name, method, _safe_exc(e)
            )
            return None
        except (BrokenPipeError, ConnectionResetError, OSError):
            self._pending.pop(request_id, None)
            future.cancel()
            return None

    # --- Reader Loops ---

    async def _stdout_reader_loop(self):
        """Dedicated background task: reads and routes JSON-RPC responses.

        Uses a periodic timeout on readline() so that if the subprocess
        hangs mid-line (no newline, no EOF), we detect process death
        instead of blocking forever.
        """
        try:
            while self._process and self._process.stdout:
                try:
                    line_bytes = await asyncio.wait_for(
                        self._process.stdout.readline(),
                        timeout=self.descriptor.heartbeat_interval * 2,
                    )
                except asyncio.TimeoutError:
                    # readline timed out — check if process is still alive
                    if self._process.returncode is not None:
                        break  # process already exited
                    continue  # process alive, keep waiting
                except (ConnectionResetError, BrokenPipeError):
                    break

                if not line_bytes:
                    # EOF — process exited
                    break

                # Size check
                if len(line_bytes) > MAX_LINE_BYTES:
                    logger.warning(
                        "Plugin %r: oversized line (%d bytes) discarded",
                        self.descriptor.name, len(line_bytes)
                    )
                    continue

                # Parse JSON
                try:
                    line_str = line_bytes.decode('utf-8').strip()
                    if not line_str:
                        continue
                    msg = json.loads(line_str)
                except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
                    # Sanitize error string to prevent log injection
                    safe_err = str(e)[:100].replace('\r', ' ').replace('\n', ' ')
                    logger.warning(
                        "Plugin %r: non-JSON on stdout: %s",
                        self.descriptor.name, safe_err
                    )
                    continue

                if not isinstance(msg, dict):
                    logger.warning(
                        "Plugin %r: non-object on stdout",
                        self.descriptor.name
                    )
                    continue

                # Route by type
                if 'id' in msg and 'method' not in msg:
                    # Response to our request
                    req_id = msg.get('id')
                    # Reject non-scalar IDs (nested objects could amplify)
                    if not isinstance(req_id, (int, str, type(None))):
                        continue
                    # Coerce string IDs to int (plugins may return "1" vs 1)
                    if isinstance(req_id, str):
                        try:
                            req_id = int(req_id)
                        except (ValueError, TypeError):
                            continue  # Not a known request ID format
                    future = self._pending.pop(req_id, None)
                    if future and not future.done():
                        if 'error' in msg:
                            err_msg = (
                                msg['error'].get('message', 'Plugin error')
                                if isinstance(msg['error'], dict)
                                else str(msg['error'])
                            )
                            # Sanitize: plugin-controlled, could contain CR/LF
                            err_msg = str(err_msg)[:500].replace('\r', ' ').replace('\n', ' ')
                            future.set_exception(
                                RuntimeError(f"JSON-RPC error: {err_msg}")
                            )
                        else:
                            result = msg.get('result', {})
                            future.set_result(result)
                    elif future is None:
                        logger.debug(
                            "Plugin %r: response for unknown ID %s",
                            self.descriptor.name, req_id
                        )

                elif 'method' in msg and 'id' in msg:
                    # Server-initiated request — we must respond
                    await self._handle_server_request(msg)

                elif 'method' in msg and 'id' not in msg:
                    # Notification — log and ignore
                    # Sanitize method name (untrusted, could contain CR/LF)
                    notif_method = str(msg.get('method', ''))[:200].replace('\r', ' ').replace('\n', ' ')
                    logger.debug(
                        "Plugin %r: notification: %s",
                        self.descriptor.name, notif_method
                    )

                else:
                    logger.warning(
                        "Plugin %r: unrecognized message format",
                        self.descriptor.name
                    )

        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(
                "Plugin %r: stdout reader error: %s",
                self.descriptor.name, _safe_exc(e)
            )
        finally:
            # Process exited or reader killed — schedule death handling.
            # Do NOT reject pending here; _handle_process_death does it
            # under the lock to avoid double-rejection race.
            if self._alive:
                asyncio.create_task(self._handle_process_death())

    async def _stderr_reader_loop(self):
        """Captures stderr for diagnostics."""
        try:
            while self._process and self._process.stderr:
                try:
                    line_bytes = await asyncio.wait_for(
                        self._process.stderr.readline(),
                        timeout=self.descriptor.heartbeat_interval * 2,
                    )
                except asyncio.TimeoutError:
                    if self._process.returncode is not None:
                        break
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    break

                if not line_bytes:
                    break

                # Size check (same as stdout)
                if len(line_bytes) > MAX_LINE_BYTES:
                    logger.warning(
                        "Plugin %r: oversized stderr line (%d bytes) discarded",
                        self.descriptor.name, len(line_bytes)
                    )
                    continue

                try:
                    line_str = line_bytes.decode('utf-8', errors='replace').rstrip()
                except Exception:
                    continue

                if line_str:
                    # Sanitize: strip CR/LF to prevent log injection
                    safe_line = line_str.replace('\r', ' ').replace('\n', ' ')
                    # Truncate for buffer (limit memory: 50 lines x 1000 chars)
                    buffered = safe_line[:1000] + "..." if len(safe_line) > 1000 else safe_line
                    self._stderr_buffer.append(buffered)
                    logger.debug(
                        "Plugin %r stderr: %s",
                        self.descriptor.name, safe_line[:200]
                    )

        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.debug(
                "Plugin %r: stderr reader error: %s",
                self.descriptor.name, _safe_exc(e)
            )

    async def _handle_server_request(self, msg: dict):
        """Handle server-initiated requests (ping, etc.)."""
        method = msg.get('method', '')
        req_id = msg.get('id')
        # Reject non-scalar IDs to prevent amplification via nested objects
        if not isinstance(req_id, (int, str, type(None))):
            req_id = None

        if method == 'ping':
            response = {"jsonrpc": "2.0", "id": req_id, "result": {}}
        else:
            # MethodNotFound for anything we don't support.
            # Sanitize method name (attacker-controlled, could contain CR/LF
            # or be arbitrarily large — cap and strip control chars)
            safe_method = str(method)[:200].replace('\r', ' ').replace('\n', ' ')
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {safe_method}"
                }
            }

        try:
            line = json.dumps(response) + "\n"
            self._process.stdin.write(line.encode('utf-8'))
            await asyncio.wait_for(
                self._process.stdin.drain(), timeout=DRAIN_TIMEOUT
            )
        except (asyncio.TimeoutError, BrokenPipeError, ConnectionResetError, OSError):
            pass  # Process is dying or not reading stdin, nothing to do

    # --- Heartbeat ---

    async def _heartbeat_loop(self):
        """Periodic ping to detect silent plugin deaths."""
        missed = 0

        try:
            while self._alive:
                await asyncio.sleep(self.descriptor.heartbeat_interval)

                if not self._alive:
                    break

                # Skip ping while calls are in-flight (busy plugin can't
                # respond to ping when max_inflight=1).
                # Check under lock to avoid race with call_tool.
                async with self._lock:
                    inflight = self._inflight_count
                if inflight > 0:
                    # Track wall-clock time inflight to detect stuck counters
                    # or hung calls that exceed the call timeout.
                    if self._inflight_since is None:
                        self._inflight_since = time.monotonic()
                    elif (time.monotonic() - self._inflight_since
                          > self.descriptor.timeout_seconds * 2):
                        # Inflight stuck for >2x timeout — likely a leaked
                        # counter or hung call. Fall through to ping instead
                        # of skipping, so we can detect a dead plugin.
                        logger.warning(
                            "Plugin %r: inflight stuck for >2x timeout "
                            "(%.0fs) — forcing heartbeat ping",
                            self.descriptor.name,
                            time.monotonic() - self._inflight_since,
                        )
                        self._inflight_since = None  # Reset for next cycle
                    else:
                        missed = 0  # Reset: plugin is actively processing
                        continue
                else:
                    self._inflight_since = None

                # Send ping
                try:
                    result = await self._send_request(
                        "ping", {}, timeout=HEARTBEAT_PING_TIMEOUT
                    )
                    if result is not None:
                        missed = 0  # Plugin responded
                    else:
                        missed += 1
                        logger.warning(
                            "Plugin %r: missed heartbeat (%d/%d)",
                            self.descriptor.name, missed,
                            HEARTBEAT_MISS_LIMIT
                        )
                except Exception:
                    missed += 1

                if missed >= HEARTBEAT_MISS_LIMIT:
                    logger.error(
                        "Plugin %r: %d missed heartbeats — declaring dead",
                        self.descriptor.name, missed
                    )
                    asyncio.create_task(self._handle_process_death())
                    break

        except asyncio.CancelledError:
            return

    # --- Circuit Breaker & Recovery ---

    async def _handle_process_death(self):
        """Handle unexpected plugin process death.

        Lock scope minimized: state flip + pending rejection under lock,
        heavy I/O (kill/restart) outside lock to avoid stalling callers.
        """
        # Phase 1: under lock — flip state, snapshot and reject pending
        async with self._lock:
            if not self._alive:
                return  # Already handled
            self._alive = False
            self._restart_count += 1
            restart_num = self._restart_count
            self._reject_all_pending("Plugin process died")

        logger.warning(
            "Plugin %r: process died (restart %d/%d)",
            self.descriptor.name, restart_num,
            self.descriptor.max_restarts
        )

        # Phase 2: outside lock — heavy I/O
        await self._kill_process_tree()

        if restart_num > self.descriptor.max_restarts:
            self._open_circuit()
        else:
            success = await self._do_restart()
            if not success:
                self._open_circuit()

    def _open_circuit(self):
        """Open circuit breaker with exponential backoff."""
        self._circuit_open = True
        backoff = min(
            self.descriptor.backoff_base * (3 ** self._restart_count),
            self.descriptor.backoff_cap
        )
        self._backoff_until = time.monotonic() + backoff
        logger.error(
            "Plugin %r: circuit breaker OPEN (backoff %.0fs)",
            self.descriptor.name, backoff
        )

    async def _attempt_recovery(self) -> bool:
        """Half-open circuit breaker probe using tools/list."""
        async with self._lock:
            # Another caller may have already recovered while we waited
            if not self._circuit_open:
                return True

            logger.info(
                "Plugin %r: attempting half-open recovery...",
                self.descriptor.name
            )

            success = await self._do_restart()
            if success:
                # Probe with tools/list (deterministic, no side effects)
                tools_data = await self._mcp_tools_list()
                if tools_data is not None:
                    self._circuit_open = False
                    self._restart_count = 0
                    new_tools = self._process_tools(tools_data)
                    if new_tools is not None:
                        self._tools = new_tools
                    logger.info(
                        "Plugin %r: circuit breaker CLOSED (recovered)",
                        self.descriptor.name
                    )
                    return True
                else:
                    await self._kill_process_tree()

            # Recovery failed — extend backoff
            # Cap restart_count to prevent unbounded 3**n exponentiation
            self._restart_count = min(self._restart_count + 1, 40)
            self._open_circuit()
            return False

    async def _do_restart(self) -> bool:
        """Spawn a fresh process and complete handshake."""
        # Clean up old process
        await self._cleanup_process()

        # Spawn new
        if not await self._spawn_process():
            return False

        # Start readers
        self._stdout_reader = asyncio.create_task(
            self._stdout_reader_loop(),
            name=f"plugin-{self.descriptor.name}-stdout"
        )
        self._stderr_reader = asyncio.create_task(
            self._stderr_reader_loop(),
            name=f"plugin-{self.descriptor.name}-stderr"
        )

        # MCP handshake
        if not await self._mcp_handshake():
            await self._kill_process_tree()
            return False

        # Re-validate tools are available after restart (don't mark alive
        # without confirming tool availability — a call could arrive before
        # the circuit breaker probe does tools/list)
        tools_data = await self._mcp_tools_list()
        if tools_data is None:
            logger.warning(
                "Plugin %r: tools/list failed after restart",
                self.descriptor.name,
            )
            await self._kill_process_tree()
            return False
        new_tools = self._process_tools(tools_data)
        if new_tools is not None:
            self._tools = new_tools

        self._alive = True

        # Restart heartbeat
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(),
            name=f"plugin-{self.descriptor.name}-heartbeat"
        )

        return True

    # --- Process Cleanup ---

    async def _kill_process_tree(self):
        """Kill the plugin process and all its children."""
        if self._process is None:
            return

        pid = self._process.pid

        try:
            if sys.platform == 'win32':
                job_killed = False
                # Windows: use Job Object if available
                if self._job_handle:
                    try:
                        import ctypes
                        ctypes.windll.kernel32.TerminateJobObject(
                            self._job_handle, 1
                        )
                        job_killed = True
                        logger.debug(
                            "Plugin %r: Job Object terminated",
                            self.descriptor.name
                        )
                    except Exception as e:
                        logger.debug(
                            "Plugin %r: Job termination failed: %s",
                            self.descriptor.name, _safe_exc(e)
                        )
                    finally:
                        # Always nullify to prevent double-close
                        try:
                            import ctypes as _ct
                            _ct.windll.kernel32.CloseHandle(self._job_handle)
                        except Exception:
                            pass
                        self._job_handle = None
                if not job_killed:
                    # Fallback: taskkill /T for full process tree kill
                    try:
                        import subprocess as _sp
                        _sp.run(
                            ['taskkill', '/F', '/T', '/PID', str(pid)],
                            capture_output=True, timeout=10,
                        )
                        logger.debug(
                            "Plugin %r: taskkill tree kill (PID %d)",
                            self.descriptor.name, pid
                        )
                    except Exception as e:
                        logger.debug(
                            "Plugin %r: taskkill fallback failed: %s",
                            self.descriptor.name, _safe_exc(e)
                        )
                        # Last resort: kill main process only
                        try:
                            self._process.kill()
                        except ProcessLookupError:
                            pass
            else:
                # POSIX: kill process group
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGTERM)
                    # Grace period
                    await asyncio.sleep(POSIX_KILL_GRACE)
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # Already exited
                except ProcessLookupError:
                    pass  # Already exited
                except PermissionError:
                    # Fallback to killing just the process
                    try:
                        self._process.kill()
                    except ProcessLookupError:
                        pass

        except Exception as e:
            logger.debug(
                "Plugin %r: kill error: %s",
                self.descriptor.name, _safe_exc(e)
            )

        # Wait for process to finish
        try:
            await asyncio.wait_for(
                self._process.wait(),
                timeout=GRACEFUL_STOP_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Plugin %r: process didn't exit after kill",
                self.descriptor.name
            )

    async def _cleanup_process(self):
        """Cancel reader tasks and clean up process handles."""
        for task in (self._stdout_reader, self._stderr_reader,
                     self._heartbeat_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        self._stdout_reader = None
        self._stderr_reader = None
        self._heartbeat_task = None
        self._process = None

        # Close Windows Job handle
        if self._job_handle and sys.platform == 'win32':
            try:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(self._job_handle)
            except Exception:
                pass
            self._job_handle = None

    async def _cleanup(self):
        """Full cleanup: kill process, cancel tasks, remove cache."""
        self._alive = False
        self._reject_all_pending("Plugin stopping")

        if self._process:
            await self._kill_process_tree()
        await self._cleanup_process()
        self._cleanup_cache()

    # --- Tool Processing ---

    def _process_tools(self, tools_data: dict) -> Optional[List[Tool]]:
        """Convert MCP tools/list response to Bond Tool objects.

        Applies: prefix, safety ceiling, schema sanitization.
        Clears _tool_allowed_params first so stale entries from previous
        tools/list responses don't persist across restarts.
        """
        self._tool_allowed_params.clear()
        raw_tools = tools_data.get('tools', [])
        if not isinstance(raw_tools, list):
            logger.error(
                "Plugin %r: tools/list 'tools' is not a list",
                self.descriptor.name
            )
            return None

        MAX_TOOLS_PER_PLUGIN = 500

        result = []
        seen_names: set = set()
        prefix = self.descriptor.tools_prefix

        # Validate prefix starts with letter (Bond tool names require ^[a-zA-Z])
        if prefix and not prefix[0].isalpha():
            logger.error(
                "Plugin %r: tools_prefix %r must start with a letter "
                "(Bond tool names require ^[a-zA-Z])",
                self.descriptor.name, prefix
            )
            return None

        if len(raw_tools) > MAX_TOOLS_PER_PLUGIN:
            logger.error(
                "Plugin %r: declares %d tools (max %d) — rejecting",
                self.descriptor.name, len(raw_tools), MAX_TOOLS_PER_PLUGIN,
            )
            return None

        for raw in raw_tools:
            if not isinstance(raw, dict):
                continue

            raw_name = raw.get('name', '')
            if not raw_name:
                continue

            # Prefix tool name
            prefixed_name = f"{prefix}_{raw_name}" if prefix else raw_name

            # Sanitize name for Bond compatibility
            safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', prefixed_name)

            # Detect collision from sanitization (e.g. a:b and a?b both → a_b)
            if safe_name in seen_names:
                # Sanitize raw_name for log (untrusted, could contain CR/LF)
                safe_raw = str(raw_name)[:200].replace('\r', ' ').replace('\n', ' ')
                logger.warning(
                    "Plugin %r: tool name collision after sanitization: "
                    "%r → %r (skipping duplicate)",
                    self.descriptor.name, safe_raw, safe_name
                )
                continue
            seen_names.add(safe_name)

            # Apply safety ceiling (ignore plugin-declared level)
            safety = self.descriptor.max_safety_level

            # Sanitize schema
            input_schema = raw.get('inputSchema', {})
            if isinstance(input_schema, dict):
                input_schema = self._sanitize_schema(input_schema)

            # Convert MCP inputSchema to Bond parameters format
            parameters = self._schema_to_parameters(input_schema)

            # Build allowlist of param keys from inputSchema.properties
            # (used by _sanitize_params to only forward declared keys)
            raw_props = input_schema.get('properties', {}) if isinstance(input_schema, dict) else {}
            if isinstance(raw_props, dict) and raw_props:
                self._tool_allowed_params[raw_name] = frozenset(raw_props.keys())
            else:
                self._tool_allowed_params[raw_name] = None  # No restriction (no schema)

            try:
                tool = Tool(
                    name=safe_name,
                    description=raw.get('description', ''),
                    parameters=parameters,
                    handler=self._make_tool_handler(raw_name),
                    safety_level=safety,
                    module_id=f"plugin:{self.descriptor.name}",
                    max_execution_seconds=self.descriptor.timeout_seconds,
                )
                result.append(tool)
            except ValueError as e:
                # Sanitize raw_name (plugin-controlled, could inject CR/LF)
                safe_raw = str(raw_name)[:200].replace('\r', ' ').replace('\n', ' ')
                logger.warning(
                    "Plugin %r: invalid tool %r: %s",
                    self.descriptor.name, safe_raw, e
                )

        if not result:
            logger.warning(
                "Plugin %r: no valid tools found",
                self.descriptor.name
            )

        return result

    def _make_tool_handler(self, raw_tool_name: str):
        """Create an async handler that routes to this plugin's call_tool."""
        bridge = self

        async def handler(**kwargs):
            result = await bridge.call_tool(raw_tool_name, kwargs)
            if isinstance(result, dict):
                if 'content' in result:
                    # MCP format — extract text
                    content = result.get('content', [])
                    if isinstance(content, list) and content:
                        text_parts = []
                        for item in content:
                            if isinstance(item, dict) and 'text' in item:
                                text_parts.append(item['text'])
                        return '\n'.join(text_parts) if text_parts else str(result)
                return result
            return str(result)

        return handler

    def _sanitize_schema(
        self, schema: dict, depth: int = 0,
        _ref_counter: Optional[List[int]] = None,
    ) -> dict:
        """Sanitize a JSON Schema: block remote $ref, enforce limits.

        _ref_counter is a mutable single-element list [count] shared across
        the entire recursive traversal so the global $ref cap is enforced.
        """
        if _ref_counter is None:
            _ref_counter = [0]

        if depth > SCHEMA_MAX_DEPTH:
            return {"type": "object"}

        if not isinstance(schema, dict):
            return {"type": "object"}

        result = {}
        for key, value in schema.items():
            if key == '$ref':
                if isinstance(value, str):
                    # Only allow local JSON Pointer refs (#/...)
                    if not value.startswith('#'):
                        logger.warning(
                            "Plugin %r: non-local $ref blocked: %s",
                            self.descriptor.name,
                            value[:100].replace('\r', ' ').replace('\n', ' ')
                        )
                        continue
                    # Cap total local refs (global counter)
                    if _ref_counter[0] >= SCHEMA_MAX_REFS:
                        logger.warning(
                            "Plugin %r: $ref limit reached (%d)",
                            self.descriptor.name, SCHEMA_MAX_REFS
                        )
                        continue
                    result[key] = value
                    _ref_counter[0] += 1
                continue

            if isinstance(value, dict):
                result[key] = self._sanitize_schema(
                    value, depth + 1, _ref_counter
                )
            elif isinstance(value, list):
                result[key] = [
                    self._sanitize_schema(item, depth + 1, _ref_counter)
                    if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                result[key] = value

        return result

    def _schema_to_parameters(self, schema: dict) -> Dict:
        """Convert MCP inputSchema (JSON Schema) to Bond parameters format."""
        if not isinstance(schema, dict):
            return {}

        properties = schema.get('properties', {})
        required = set(schema.get('required', []))
        result = {}

        for name, prop in properties.items():
            if not isinstance(prop, dict):
                continue

            param = {
                'type': prop.get('type', 'string'),
                'description': prop.get('description', ''),
            }

            if name not in required:
                param['optional'] = True

            if 'enum' in prop:
                param['enum'] = prop['enum']

            if 'default' in prop:
                param['default'] = prop['default']

            result[name] = param

        return result

    # --- Utility ---

    _AUTH_KEYS = frozenset({
        '_meta', 'auth_token', 'authorization', 'api_key',
        'access_token', 'bearer_token', 'secret', 'password',
        'token', 'credential', 'credentials',
    })

    @staticmethod
    def _estimate_obj_bytes(obj, _limit: int = 0) -> int:
        """Quick recursive estimate of JSON-serialized byte size.

        Returns an approximate count.  Aborts early once the estimate
        exceeds ``_limit`` (defaults to MAX_LINE_BYTES) to avoid
        spending time on pathologically large structures.
        """
        if _limit <= 0:
            _limit = MAX_LINE_BYTES
        counter = [0]

        def _walk(o, depth=0):
            if counter[0] > _limit or depth > 30:
                counter[0] = _limit + 1
                return
            if isinstance(o, str):
                counter[0] += len(o) + 2  # quotes
            elif isinstance(o, bytes):
                counter[0] += len(o) + 2
            elif isinstance(o, dict):
                counter[0] += 2  # braces
                for k, v in o.items():
                    counter[0] += len(str(k)) + 4  # key + quotes + colon + comma
                    _walk(v, depth + 1)
                    if counter[0] > _limit:
                        return
            elif isinstance(o, (list, tuple)):
                counter[0] += 2  # brackets
                for item in o:
                    _walk(item, depth + 1)
                    if counter[0] > _limit:
                        return
            else:
                counter[0] += 20  # numbers, bools, None

        _walk(obj)
        return counter[0]

    def _sanitize_params(self, params: dict, tool_name: str = '') -> dict:
        """Sanitize outbound params using allowlist (preferred) or blocklist.

        If the tool has a declared inputSchema with properties, only forward
        keys that appear in that schema (allowlist). This is stronger than
        the blocklist approach because it prevents any undeclared keys from
        reaching the plugin — including creatively named auth tokens.

        Falls back to blocklist stripping for tools with no schema.
        """
        if not isinstance(params, dict):
            return {}
        allowed = self._tool_allowed_params.get(tool_name)
        if allowed is not None:
            # Allowlist: only forward keys declared in inputSchema.properties.
            # ALSO strip auth keys even if they appear in the schema — a
            # malicious plugin could declare "auth_token" as a property to
            # trick the allowlist into forwarding sensitive tokens.
            # Then recursively strip nested auth tokens from values (a
            # caller could pass {"config": {"authorization": "Bearer SECRET"}}).
            filtered = {
                k: v for k, v in params.items()
                if k in allowed and k.lower() not in self._AUTH_KEYS
            }
            return {
                k: self._strip_auth_recursive(v, depth=0) if isinstance(v, (dict, list)) else v
                for k, v in filtered.items()
            }
        # Fallback: blocklist stripping (tool has no schema or permissive schema)
        return self._strip_auth_recursive(params, depth=0)

    def _strip_auth_recursive(self, obj, depth: int):
        """Walk dicts/lists and remove auth-related keys at any nesting level."""
        if depth > 20:
            # Depth limit: replace with safe sentinel (never pass through raw)
            if isinstance(obj, dict):
                return {}
            if isinstance(obj, list):
                return []
            return obj
        if isinstance(obj, dict):
            clean = {}
            for key, value in obj.items():
                if key.lower() in self._AUTH_KEYS:
                    continue
                clean[key] = self._strip_auth_recursive(value, depth + 1)
            return clean
        if isinstance(obj, list):
            return [self._strip_auth_recursive(item, depth + 1) for item in obj]
        return obj

    def _reject_all_pending(self, reason: str):
        """Reject all pending Futures immediately."""
        for req_id, future in list(self._pending.items()):
            if not future.done():
                future.set_exception(PluginCrashError(reason))
        self._pending.clear()

    def _get_stderr_context(self) -> str:
        """Get last few stderr lines for error context."""
        lines = list(self._stderr_buffer)
        if not lines:
            return "(no stderr captured)"
        return " | ".join(lines[-3:])[:500]

    def _copy_to_cache(self) -> str:
        """Copy plugin files to Bond-managed cache, verifying hashes during copy.

        TOCTOU-safe: hashes are computed on the bytes being copied (not on
        a separate read pass), so the verified bytes are exactly what ends
        up in cache.  Each instance gets a unique cache dir (PID + timestamp)
        to avoid race conditions when the same plugin is started concurrently.
        """
        cache_base = os.path.join(
            tempfile.gettempdir(), 'bond_plugin_cache'
        )
        # mode=0o700: only owner can list/enter cache dir (shared system defense)
        os.makedirs(cache_base, mode=0o700, exist_ok=True)

        # Verify cache_base is not a symlink and is owned by us (prevents
        # pre-creation attack where attacker plants a symlink to their dir)
        cb_stat = os.lstat(cache_base)
        import stat as _stat
        if _stat.S_ISLNK(cb_stat.st_mode):
            raise ValueError(
                f"Cache base {cache_base} is a symlink — refusing (possible attack)"
            )
        if not _stat.S_ISDIR(cb_stat.st_mode):
            raise ValueError(
                f"Cache base {cache_base} is not a directory"
            )
        if hasattr(os, 'getuid') and cb_stat.st_uid != os.getuid():
            raise ValueError(
                f"Cache base {cache_base} not owned by current user "
                f"(uid {cb_stat.st_uid} != {os.getuid()})"
            )

        # Sanitize prefix to [a-z0-9_] only — prevents path traversal
        # via attacker-controlled name/version containing ".." or os.sep
        safe_name = re.sub(r'[^a-z0-9]', '_', self.descriptor.name)[:50]
        safe_ver = re.sub(r'[^a-z0-9]', '_', self.descriptor.version)[:20]
        # mkdtemp guarantees unique directory (safe against race conditions)
        plugin_cache = tempfile.mkdtemp(
            prefix=f"{safe_name}_{safe_ver}_",
            dir=cache_base,
        )

        if self.descriptor.files_sha256:
            # Strict mode: copy only verified files, hashing during copy.
            # Track cumulative bytes to prevent DoS via many small files.
            working_real = os.path.realpath(self.descriptor.working_dir)
            cache_real = os.path.realpath(plugin_cache)
            strict_total_bytes = 0

            for rel_path, expected_hash in self.descriptor.files_sha256.items():
                # Validate hash format before any filesystem work
                if not isinstance(expected_hash, str) or not re.match(r'^[0-9a-f]{64}$', expected_hash):
                    raise ValueError(
                        f"Invalid SHA-256 hash format for '{rel_path}'"
                    )

                # Path containment: reject traversal, absolute, and symlinks
                normalized = os.path.normpath(rel_path)
                if os.path.isabs(normalized) or normalized.startswith('..'):
                    raise ValueError(
                        f"Path traversal in files_sha256: {rel_path}"
                    )

                src = os.path.join(self.descriptor.working_dir, normalized)
                dst = os.path.join(plugin_cache, normalized)

                # Belt-and-braces: realpath must stay inside working_dir
                # Use commonpath + normcase (handles Windows case-insensitivity,
                # UNC paths, drive letters — same pattern as verify_plugin_files)
                src_real = os.path.realpath(src)
                try:
                    src_common = os.path.commonpath([
                        os.path.normcase(working_real),
                        os.path.normcase(src_real),
                    ])
                except ValueError:
                    raise ValueError(
                        f"Source escapes working_dir: {rel_path}"
                    )
                if src_common != os.path.normcase(working_real):
                    raise ValueError(
                        f"Source escapes working_dir: {rel_path}"
                    )

                dst_real = os.path.realpath(dst)
                try:
                    dst_common = os.path.commonpath([
                        os.path.normcase(cache_real),
                        os.path.normcase(dst_real),
                    ])
                except ValueError:
                    raise ValueError(
                        f"Destination escapes cache: {rel_path}"
                    )
                if dst_common != os.path.normcase(cache_real):
                    raise ValueError(
                        f"Destination escapes cache: {rel_path}"
                    )

                # TOCTOU-safe: open with O_NOFOLLOW, then fstat on the fd.
                # This prevents symlink/file swap between check and read.
                open_flags = os.O_RDONLY
                if hasattr(os, 'O_NOFOLLOW'):
                    open_flags |= os.O_NOFOLLOW
                try:
                    src_fd = os.open(src, open_flags)
                except OSError as e:
                    # O_NOFOLLOW on symlink → ELOOP (errno 40)
                    if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                        raise ValueError(
                            f"Symlink not allowed in plugin files: {rel_path}"
                        )
                    raise

                src_fd_owned = True
                try:
                    src_fstat = os.fstat(src_fd)

                    # Reject non-regular files (FIFO, device, socket)
                    if not stat.S_ISREG(src_fstat.st_mode):
                        raise ValueError(
                            f"Plugin file '{rel_path}' is not a regular file "
                            f"(mode={oct(src_fstat.st_mode)})"
                        )

                    # Size check on the open fd (no TOCTOU gap)
                    from models.models import ModuleManifest
                    src_size = src_fstat.st_size
                    if src_size > ModuleManifest.MAX_HASH_FILE_SIZE:
                        raise ValueError(
                            f"Plugin file '{rel_path}' too large for hashing "
                            f"({src_size:,} bytes, limit "
                            f"{ModuleManifest.MAX_HASH_FILE_SIZE:,})"
                        )

                    # Hash-while-copy from the SAME fd (no re-open gap)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    hasher = hashlib.sha256()
                    bytes_copied = 0
                    with os.fdopen(src_fd, 'rb') as f_src, open(dst, 'wb') as f_dst:
                        src_fd_owned = False  # fdopen took ownership
                        while True:
                            chunk = f_src.read(65536)
                            if not chunk:
                                break
                            bytes_copied += len(chunk)
                            strict_total_bytes += len(chunk)
                            if bytes_copied > ModuleManifest.MAX_HASH_FILE_SIZE:
                                raise ValueError(
                                    f"Plugin file '{rel_path}' grew during copy"
                                )
                            if strict_total_bytes > DEV_COPY_MAX_BYTES:
                                raise ValueError(
                                    f"Plugin total copy size exceeds cap "
                                    f"({DEV_COPY_MAX_BYTES // (1024*1024)} MB)"
                                )
                            hasher.update(chunk)
                            f_dst.write(chunk)
                finally:
                    if src_fd_owned:
                        os.close(src_fd)

                actual_hash = hasher.hexdigest()
                if not hmac.compare_digest(actual_hash, expected_hash):
                    # Remove the partial cache — it's tainted
                    shutil.rmtree(plugin_cache, ignore_errors=True)
                    raise ValueError(
                        f"Hash mismatch for {rel_path}: "
                        f"expected {expected_hash[:16]}..., "
                        f"got {actual_hash[:16]}..."
                    )

                # Preserve metadata from cached fstat (NOT from reopening src,
                # which has a micro TOCTOU gap — src could be swapped after
                # fdopen close and before copystat reopens by path)
                try:
                    os.utime(dst, ns=(src_fstat.st_atime_ns, src_fstat.st_mtime_ns))
                except (AttributeError, OSError):
                    pass  # Best-effort; cache is ephemeral
        else:
            # Dev mode (no hashes): copy entire plugin directory with
            # size enforcement DURING copy using actual bytes copied (not
            # pre-scan getsize, which has TOCTOU: files can grow between
            # scan and copy).
            total_copied = [0]  # mutable for nested function

            def _size_limited_copy2(src_path, dst_path):
                """shutil.copy2 replacement that tracks actual bytes copied.

                Uses os.open(O_NOFOLLOW) + fstat to eliminate TOCTOU gap
                between the lstat check and the read (same pattern as strict
                hash mode).
                """
                import stat as _stat
                # TOCTOU-safe open: O_NOFOLLOW prevents symlink following
                open_flags = os.O_RDONLY
                if hasattr(os, 'O_NOFOLLOW'):
                    open_flags |= os.O_NOFOLLOW
                try:
                    src_fd = os.open(src_path, open_flags)
                except OSError as e:
                    if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                        logger.warning(
                            "Plugin %r: skipping symlink in dev copy: %s",
                            self.descriptor.name,
                            os.path.basename(src_path).replace('\r', ' ').replace('\n', ' '),
                        )
                        return dst_path
                    raise

                src_fd_owned = True
                try:
                    src_st = os.fstat(src_fd)
                    if not _stat.S_ISREG(src_st.st_mode):
                        logger.warning(
                            "Plugin %r: skipping non-regular file in dev copy: %s",
                            self.descriptor.name,
                            os.path.basename(src_path).replace('\r', ' ').replace('\n', ' '),
                        )
                        return dst_path
                    # Read from the verified fd — no re-open gap
                    with os.fdopen(src_fd, 'rb') as sf:
                        src_fd_owned = False  # fdopen took ownership
                        with open(dst_path, 'wb') as df:
                            while True:
                                chunk = sf.read(65536)
                                if not chunk:
                                    break
                                total_copied[0] += len(chunk)
                                if total_copied[0] > DEV_COPY_MAX_BYTES:
                                    raise ValueError(
                                        f"Plugin working_dir exceeds dev-mode size cap "
                                        f"({DEV_COPY_MAX_BYTES // (1024*1024)} MB)"
                                    )
                                df.write(chunk)
                    # Preserve metadata from cached fstat
                    try:
                        os.utime(dst_path, ns=(src_st.st_atime_ns, src_st.st_mtime_ns))
                    except (AttributeError, OSError):
                        pass
                finally:
                    if src_fd_owned:
                        os.close(src_fd)
                return dst_path

            def _ignore_symlinks(directory, contents):
                """Ignore symlinks entirely — they could point outside the
                plugin directory and exfiltrate arbitrary readable files."""
                return [c for c in contents
                        if os.path.islink(os.path.join(directory, c))]

            shutil.copytree(
                self.descriptor.working_dir,
                plugin_cache,
                copy_function=_size_limited_copy2,
                ignore=_ignore_symlinks,
                symlinks=False,
                dirs_exist_ok=True,
            )

        # Store path so stop() can clean it up
        self._cache_dir = plugin_cache
        return plugin_cache

    def _cleanup_cache(self):
        """Remove the instance-specific cache directory.

        Only deletes _cache_dir, which is ONLY set by _copy_to_cache().
        In dev mode (no hashes), _cache_dir is None — nothing to delete.
        The plugin's source working_dir is NEVER stored in _cache_dir.
        """
        cache_dir = getattr(self, '_cache_dir', None)
        if cache_dir and os.path.isdir(cache_dir):
            try:
                shutil.rmtree(cache_dir)
            except OSError as exc:
                logger.debug(
                    "Plugin %r: cache cleanup failed: %s",
                    self.descriptor.name, _safe_exc(exc)
                )

    @staticmethod
    def _error_result(message: str) -> dict:
        """Create an MCP error result."""
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True
        }
