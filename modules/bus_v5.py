"""
Bond Module: Bus v5

Unified multi-agent message bus integration via Bus v5 gateway (WebSocket).
Routes messages to ANY actor — IDE AIs (via IPC adapter), browser AIs (via
AI Bridge adapter), other Claude Code instances, or custom agents.

Advantages over bus_ipc (direct IPC Bridge):
  - Offline queuing: messages held until recipient connects
  - Fan-out: send to all actors with to="all"
  - Two-AI gate: HMAC approval before code execution
  - Unified addressing: canonical {ide}-{ai}-{n} actor IDs
  - Reply correlation: request_id-based request-reply pattern

Requires Bus v5 gateway running on port 18900 (or BUS_V5_PORT).

Tools (4):
  bus_post          — Send a message to any Bus v5 actor
  bus_post_wait     — Send and wait for a reply
  bus_actors        — List connected actors from gateway status
  bus_status        — Gateway health check

Error codes:
  GATEWAY_DOWN      — Cannot reach Bus v5 gateway
  POST_TIMEOUT      — Gateway did not ACK within deadline
  REPLY_TIMEOUT     — No reply received within deadline
  INVALID_TARGET    — Target actor ID failed validation
  INVALID_MESSAGE   — Message empty or exceeds limit
  CLIENT_ERROR      — client.cjs exited with error
  STATUS_UNAVAIL    — gateway_status.json not readable
"""

import os
import json
import time
import re
import shutil
import logging
import secrets
import subprocess
from typing import Optional

from core.module_loader import BondModule
from models.models import Tool, SafetyLevel

logger = logging.getLogger("bond.bus_v5")

# ── Validation ──────────────────────────────────────────────────────────────

# Actor IDs: {ide}-{ai}-{n} or simple names like "all", "bond-mcp"
_ACTOR_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')

MAX_SUBJECT_CHARS = 256
MAX_BODY_CHARS = 64_000  # 64KB — generous for code snippets
MAX_ACTORS_IN_STATUS = 200


def _validate_actor(actor_id: str) -> Optional[str]:
    """Return error string if invalid, None if OK."""
    if not actor_id or not isinstance(actor_id, str):
        return "actor_id is required"
    actor_id = actor_id.strip().lower()
    if not _ACTOR_RE.match(actor_id):
        return f"Invalid actor_id format: {actor_id!r} (must be lowercase alphanumeric/hyphens, 1-64 chars)"
    return None


class BusV5Module(BondModule):
    module_id = "bus_v5"

    _MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def initialize(self, core):
        self.core = core
        self._project_root = os.path.realpath(os.path.join(self._MODULE_DIR, "..", ".."))

        # Resolve paths
        self._bus_dir = os.environ.get(
            "BUS_V5_DIR",
            os.path.join(self._project_root, "15 - Bus v5"),
        )
        self._client_path = os.path.join(self._bus_dir, "runtime", "client.cjs")
        self._train_dir = os.environ.get(
            "BUS_V5_TRAIN_PATH",
            os.path.join(self._bus_dir, "_train"),
        )
        self._status_file = os.path.join(self._train_dir, "gateway_status.json")
        self._port = int(os.environ.get("BUS_V5_PORT", "18900"))
        self._actor = os.environ.get("BOND_BUS_V5_ACTOR", "bond-mcp")

        # Timeouts
        self._post_timeout_s = int(os.environ.get("BUS_V5_POST_TIMEOUT_MS", "15000")) / 1000
        self._reply_timeout_s = int(os.environ.get("BUS_V5_REPLY_TIMEOUT_MS", "60000")) / 1000

        client_ok = os.path.isfile(self._client_path)
        node_ok = shutil.which("node") is not None

        logger.info(
            "BusV5Module initialized: bus_dir=%s client=%s (exists=%s) node=%s port=%d actor=%s",
            self._bus_dir, self._client_path, client_ok, node_ok, self._port, self._actor,
        )

    def shutdown(self):
        pass

    # ── Tool Registration ────────────────────────────────────────────────────

    def register_tools(self):
        return [
            Tool(
                name="bus_post",
                description=(
                    "Send a message to any Bus v5 actor. Targets can be IDE AIs "
                    "(copilot, codex, antigravity), browser AIs (claude-2, gpt-1), "
                    "other Claude Code instances, or 'all' for fan-out."
                ),
                parameters={
                    "to": {
                        "type": "string",
                        "description": (
                            "Target actor ID (e.g. 'codex-2', 'copilot', 'windsurf-claude-1', "
                            "or 'all' for fan-out to every connected actor)"
                        ),
                    },
                    "subject": {
                        "type": "string",
                        "description": "Message subject (max 256 chars)",
                    },
                    "body": {
                        "type": "string",
                        "description": "Message body (max 64KB)",
                    },
                    "msg_type": {
                        "type": "string",
                        "description": "Message type: 'note' (default), 'task', 'review', 'approval'",
                        "optional": True,
                    },
                },
                handler=self.bus_post,
                safety_level=SafetyLevel.MODERATE,
                module_id=self.module_id,
            ),
            Tool(
                name="bus_post_wait",
                description=(
                    "Send a message and wait for a reply. Uses Bus v5 request-reply "
                    "correlation (request_id). Times out after BUS_V5_REPLY_TIMEOUT_MS "
                    "(default 60s)."
                ),
                parameters={
                    "to": {
                        "type": "string",
                        "description": "Target actor ID",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Message subject",
                    },
                    "body": {
                        "type": "string",
                        "description": "Message body",
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Reply timeout in ms (default: 60000)",
                        "optional": True,
                    },
                    "msg_type": {
                        "type": "string",
                        "description": "Message type (default: 'note')",
                        "optional": True,
                    },
                },
                handler=self.bus_post_wait,
                safety_level=SafetyLevel.MODERATE,
                module_id=self.module_id,
            ),
            Tool(
                name="bus_actors",
                description=(
                    "List actors currently registered with the Bus v5 gateway. "
                    "Shows who is online and reachable."
                ),
                parameters={},
                handler=self.bus_actors,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
            Tool(
                name="bus_status",
                description=(
                    "Check Bus v5 gateway health. Returns port, uptime, connected "
                    "actor count, and offline queue depth."
                ),
                parameters={},
                handler=self.bus_status,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
        ]

    # ── Handlers ─────────────────────────────────────────────────────────────

    def bus_post(
        self,
        to: str,
        subject: str,
        body: str,
        msg_type: Optional[str] = None,
    ):
        # Validate
        err = _validate_actor(to)
        if err:
            return {"status": "failed", "error_code": "INVALID_TARGET", "error": err}

        if not body or not body.strip():
            return {"status": "failed", "error_code": "INVALID_MESSAGE", "error": "Body is empty"}
        if len(body) > MAX_BODY_CHARS:
            return {"status": "failed", "error_code": "INVALID_MESSAGE", "error": f"Body too long (max {MAX_BODY_CHARS})"}
        if subject and len(subject) > MAX_SUBJECT_CHARS:
            return {"status": "failed", "error_code": "INVALID_MESSAGE", "error": f"Subject too long (max {MAX_SUBJECT_CHARS})"}

        return self._run_client(
            to=to, subject=subject or "", body=body,
            msg_type=msg_type or "note", wait=False,
            timeout_s=self._post_timeout_s,
        )

    def bus_post_wait(
        self,
        to: str,
        subject: str,
        body: str,
        timeout_ms: Optional[int] = None,
        msg_type: Optional[str] = None,
    ):
        err = _validate_actor(to)
        if err:
            return {"status": "failed", "error_code": "INVALID_TARGET", "error": err}

        if not body or not body.strip():
            return {"status": "failed", "error_code": "INVALID_MESSAGE", "error": "Body is empty"}
        if len(body) > MAX_BODY_CHARS:
            return {"status": "failed", "error_code": "INVALID_MESSAGE", "error": f"Body too long (max {MAX_BODY_CHARS})"}

        timeout_s = (timeout_ms / 1000) if timeout_ms else self._reply_timeout_s

        return self._run_client(
            to=to, subject=subject or "", body=body,
            msg_type=msg_type or "note", wait=True,
            timeout_s=timeout_s,
        )

    def bus_actors(self):
        status = self._read_gateway_status()
        if status is None:
            return {"status": "unavailable", "error_code": "STATUS_UNAVAIL", "actors": []}

        actors = status.get("actors", [])
        return {
            "status": "ok",
            "actors": actors[:MAX_ACTORS_IN_STATUS],
            "count": len(actors),
            "gateway_pid": status.get("pid"),
        }

    def bus_status(self):
        status = self._read_gateway_status()
        if status is None:
            return {
                "status": "down",
                "error_code": "GATEWAY_DOWN",
                "error": f"Cannot read {self._status_file}",
                "port": self._port,
            }

        return {
            "status": "ok",
            "port": status.get("port", self._port),
            "pid": status.get("pid"),
            "started_at": status.get("started_at"),
            "actor_count": len(status.get("actors", [])),
            "offline_queue_depth": status.get("offline_queue_depth", 0),
            "uptime_s": status.get("uptime_s"),
        }

    # ── Internal ─────────────────────────────────────────────────────────────

    def _run_client(self, to: str, subject: str, body: str, msg_type: str,
                    wait: bool, timeout_s: float):
        """Shell out to Bus v5 client.cjs CLI."""
        node_path = shutil.which("node")
        if not node_path:
            return {"status": "failed", "error_code": "GATEWAY_DOWN", "error": "Node.js not found in PATH"}

        if not os.path.isfile(self._client_path):
            return {
                "status": "failed", "error_code": "GATEWAY_DOWN",
                "error": f"Bus v5 client not found: {self._client_path}",
            }

        cmd = [
            node_path, self._client_path,
            "--from", self._actor,
            "--to", to.strip().lower(),
            "--subject", subject,
            "--body", body,
            "--msg-type", msg_type,
        ]
        if wait:
            cmd.append("--wait")
            cmd.extend(["--timeout", str(int(timeout_s * 1000))])

        env = {**os.environ}
        env["BUS_V5_PORT"] = str(self._port)
        if self._train_dir:
            env["BUS_V5_TRAIN_PATH"] = self._train_dir

        try:
            t_start = time.time()
            # Give subprocess extra headroom beyond the bus timeout
            proc_timeout = timeout_s + 10
            result = subprocess.run(
                cmd,
                timeout=proc_timeout,
                capture_output=True,
                env=env,
            )
            duration_ms = int((time.time() - t_start) * 1000)

            stdout = (result.stdout or b"").decode("utf-8", errors="replace").strip()
            stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()

            if result.returncode == 0:
                # Parse JSON output from client
                response = None
                if stdout:
                    try:
                        response = json.loads(stdout)
                    except json.JSONDecodeError:
                        response = {"raw": stdout[:2000]}

                logger.info("[bus_v5] to=%s status=ok duration=%dms wait=%s", to, duration_ms, wait)
                return {
                    "status": "ok",
                    "response": response,
                    "duration_ms": duration_ms,
                    "error": None,
                    "error_code": None,
                }
            else:
                error_hint = stderr[:500] or stdout[:500] or f"exit code {result.returncode}"
                logger.warning("[bus_v5] to=%s exit=%d error=%s", to, result.returncode, error_hint[:200])
                return {
                    "status": "failed",
                    "error_code": "CLIENT_ERROR",
                    "error": error_hint,
                    "duration_ms": duration_ms,
                }

        except subprocess.TimeoutExpired:
            logger.warning("[bus_v5] to=%s timeout after %.1fs", to, timeout_s)
            return {
                "status": "timeout",
                "error_code": "POST_TIMEOUT" if not wait else "REPLY_TIMEOUT",
                "error": f"Timed out after {timeout_s}s",
            }
        except Exception as e:
            logger.error("[bus_v5] to=%s error: %s", to, type(e).__name__)
            return {
                "status": "failed",
                "error_code": "CLIENT_ERROR",
                "error": str(e)[:500],
            }

    def _read_gateway_status(self) -> Optional[dict]:
        """Read gateway_status.json from the _train/ directory."""
        try:
            if not os.path.isfile(self._status_file):
                return None
            with open(self._status_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Cannot read gateway_status.json: %s", e)
            return None
