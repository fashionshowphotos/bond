"""
Bond Module: Bus IPC

Bridge Claude Code Desktop → VS Code hub via Bond MCP.
Sends messages to Copilot, Codex, Antigravity via the IPC Bridge.
Allows AFK comms: Claude Code Desktop → VS Code agents without browser automation.

Tools (3):
  list_agents       — List configured targets + reachability status
  send_to_agent     — Send message to an agent via IPC Bridge
  wait_for_reply    — Poll for reply to a previously sent message

Error codes:
  TARGET_NOT_FOUND  — target_id not in configured allowlist
  INVALID_MESSAGE   — message empty or exceeds max_message_chars
  INVALID_CONFIG    — node or ipc_client not found
  IPC_DOWN          — IPC Bridge returned exit code 2 (no instances)
  CLIENT_ERROR      — IPC client exited with non-zero code
  TIMEOUT           — subprocess or poll exceeded deadline
  UNKNOWN_MSG_ID    — message_id not found in sent tracking
"""

import os
import glob
import json
import time
import shutil
import logging
import secrets
import subprocess
from typing import Optional

from core.module_loader import BondModule
from models.models import Tool, SafetyLevel

logger = logging.getLogger("bond.bus_ipc")

# Idempotency window: deduplicate sends within this TTL (seconds)
_IDEMPOTENCY_TTL = 60

# In-memory tracking (module-level, lives for server lifetime)
_sent_messages: dict = {}    # message_id → {target, sent_at, status, outbox_path}
_idempotency_map: dict = {}  # idempotency_key → {message_id, sent_at}


def _cleanup_expired():
    """Evict expired idempotency entries."""
    now = time.time()
    expired = [k for k, v in _idempotency_map.items() if now - v["sent_at"] > _IDEMPOTENCY_TTL]
    for k in expired:
        del _idempotency_map[k]


def _generate_message_id() -> str:
    """Generate a unique message_id: msg_{ms_timestamp}_{8_random_hex}."""
    return f"msg_{int(time.time() * 1000)}_{secrets.token_hex(4)}"


def _resolve_project_root(module_dir: str) -> str:
    """Resolve <project_root> (Coherent Light Designs/) from module directory."""
    # modules/ → Bond/ → project_root/
    return os.path.realpath(os.path.join(module_dir, "..", ".."))


class BusIpcModule(BondModule):
    module_id = "bus_ipc"

    _MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
    _DEFAULT_CONFIG_PATH = os.path.join(_MODULE_DIR, "..", "bond_ipc_config.json")

    # --- Lifecycle ---

    def initialize(self, core):
        self.core = core
        self._cfg = self._load_config()
        self._project_root = _resolve_project_root(self._MODULE_DIR)
        self._io_dir = os.path.join(self._project_root, "io")
        logger.info(
            "BusIpcModule initialized: targets=%s ipc_client=%s io=%s",
            self._cfg["targets"],
            self._cfg["ipc_client_path"],
            self._io_dir,
        )

    def shutdown(self):
        pass

    # --- Config ---

    def _load_config(self) -> dict:
        defaults = {
            "ipc_client_path": os.path.join("..", "..", "8 - Bus v1", "codex_ipc_client.cjs"),
            "targets": ["copilot", "codex", "antigravity"],
            "max_message_chars": 4000,
            "send_timeout_ms": 15000,
            "wait_timeout_ms": 30000,
        }
        cfg_path = os.path.realpath(self._DEFAULT_CONFIG_PATH)
        if os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                defaults.update(loaded)
            except Exception as e:
                logger.warning("Could not load bond_ipc_config.json: %s — using defaults", e)

        # Resolve ipc_client_path relative to module directory if not absolute
        raw = defaults["ipc_client_path"]
        if not os.path.isabs(raw):
            defaults["ipc_client_path"] = os.path.realpath(
                os.path.join(self._MODULE_DIR, raw)
            )
        return defaults

    # --- Tool Registration ---

    def register_tools(self):
        return [
            Tool(
                name="list_agents",
                description=(
                    "List configured IPC targets (copilot, codex, antigravity) "
                    "with their reachability status."
                ),
                parameters={},
                handler=self.list_agents,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
            Tool(
                name="send_to_agent",
                description=(
                    "Send a message to a VS Code agent (copilot, codex, or antigravity) "
                    "via the IPC Bridge. Returns message_id for reply correlation."
                ),
                parameters={
                    "target_id": {
                        "type": "string",
                        "description": "Target agent: 'copilot', 'codex', or 'antigravity'",
                        "enum": ["copilot", "codex", "antigravity"],
                    },
                    "message": {
                        "type": "string",
                        "description": "Message text to send (max 4000 chars by default)",
                    },
                    "idempotency_key": {
                        "type": "string",
                        "description": "Optional key to deduplicate sends within 60s",
                        "optional": True,
                    },
                },
                handler=self.send_to_agent,
                safety_level=SafetyLevel.MODERATE,
                module_id=self.module_id,
            ),
            Tool(
                name="wait_for_reply",
                description=(
                    "Poll for a reply to a previously sent message. "
                    "Scans io/ for reply files matching the message_id."
                ),
                parameters={
                    "target_id": {
                        "type": "string",
                        "description": "Target agent the message was sent to",
                    },
                    "message_id": {
                        "type": "string",
                        "description": "message_id returned from send_to_agent",
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Max wait time in ms (default: 30000)",
                        "optional": True,
                    },
                },
                handler=self.wait_for_reply,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
        ]

    # --- Handlers ---

    def list_agents(self):
        node_path = shutil.which("node")
        node_ok = node_path is not None
        ipc_ok = os.path.isfile(self._cfg["ipc_client_path"])
        reachable = node_ok and ipc_ok

        return [
            {
                "id": target,
                "name": target.capitalize(),
                "configured": True,
                "reachable": reachable,
            }
            for target in self._cfg["targets"]
        ]

    def send_to_agent(
        self,
        target_id: str,
        message: str,
        idempotency_key: Optional[str] = None,
    ):
        # Allowlist check — no subprocess call on unknown targets
        if target_id not in self._cfg["targets"]:
            return {
                "status": "failed", "error_code": "TARGET_NOT_FOUND",
                "error": f"Unknown target: {target_id}", "message_id": None,
            }

        # Message validation
        if not message or not message.strip():
            return {
                "status": "failed", "error_code": "INVALID_MESSAGE",
                "error": "Message is empty", "message_id": None,
            }
        max_chars = self._cfg["max_message_chars"]
        if len(message) > max_chars:
            return {
                "status": "failed", "error_code": "INVALID_MESSAGE",
                "error": f"Message too long (max {max_chars} chars)", "message_id": None,
            }

        # Idempotency dedup
        if idempotency_key:
            _cleanup_expired()
            if idempotency_key in _idempotency_map:
                existing = _idempotency_map[idempotency_key]
                return {"message_id": existing["message_id"], "status": "sent", "error": None, "error_code": None}

        # Resolve Node.js
        node_path = shutil.which("node")
        if not node_path:
            return {
                "status": "failed", "error_code": "INVALID_CONFIG",
                "error": "Node.js not found in PATH", "message_id": None,
            }

        # Re-read config on each send to pick up path fixes without restart
        fresh_cfg = self._load_config()
        ipc_client = fresh_cfg["ipc_client_path"]
        if not os.path.isfile(ipc_client):
            return {
                "status": "failed", "error_code": "INVALID_CONFIG",
                "error": f"IPC client not found: {ipc_client}", "message_id": None,
            }

        # Generate unique message_id
        message_id = _generate_message_id()

        # Write message to persistent io/ directory with frontmatter.
        # The IPC client reads this file AND tells the recipient its path.
        # The file MUST persist so the recipient can read it.
        outbox_path = self._write_bus_message(message_id, target_id, message)

        try:
            t_start = time.time()
            # --actor must match the message's "to:" field (recipient gate check)
            # --target selects the IPC Bridge adapter (codex, copilot, etc.)
            # The sender identity is preserved in frontmatter "from: bond-mcp"
            result = subprocess.run(
                [node_path, ipc_client, outbox_path, "--actor", target_id, "--target", target_id],
                timeout=self._cfg["send_timeout_ms"] / 1000,
                capture_output=True,
            )
            duration_ms = int((time.time() - t_start) * 1000)

            exit_code = result.returncode
            if exit_code == 0:
                status, err, err_code = "sent", None, None
            elif exit_code == 2:
                status, err, err_code = "failed", "IPC Bridge unavailable (no VS Code instances found)", "IPC_DOWN"
            elif exit_code == 4:
                # Recipient gate filter — should not happen with correct --actor flag
                stderr_hint = (result.stderr or b"").decode("utf-8", errors="replace").strip()[:200]
                status, err, err_code = "failed", f"Recipient gate rejected (exit 4): {stderr_hint}", "RECIPIENT_GATE"
            else:
                stderr_hint = (result.stderr or b"").decode("utf-8", errors="replace").strip()[:200]
                status, err, err_code = "failed", f"IPC client exit {exit_code}: {stderr_hint}", "CLIENT_ERROR"

            logger.info("[bus_ipc] target=%s status=%s duration=%dms", target_id, status, duration_ms)

        except subprocess.TimeoutExpired:
            timeout_s = self._cfg["send_timeout_ms"] / 1000
            logger.info("[bus_ipc] target=%s status=timeout", target_id)
            _sent_messages[message_id] = {
                "target": target_id, "sent_at": time.time(),
                "status": "timeout", "outbox_path": outbox_path,
            }
            return {
                "status": "timeout", "error_code": "TIMEOUT",
                "error": f"IPC client timed out after {timeout_s}s",
                "message_id": message_id,
            }

        except Exception as e:
            logger.error("[bus_ipc] target=%s send error: %s", target_id, type(e).__name__)
            return {
                "status": "failed", "error_code": "CLIENT_ERROR",
                "error": "Send failed", "message_id": message_id,
            }

        # Record in-memory state
        _sent_messages[message_id] = {
            "target": target_id, "sent_at": time.time(),
            "status": status, "outbox_path": outbox_path,
        }
        if idempotency_key:
            _idempotency_map[idempotency_key] = {"message_id": message_id, "sent_at": time.time()}

        return {"message_id": message_id, "status": status, "error": err, "error_code": err_code}

    def wait_for_reply(
        self,
        target_id: str,
        message_id: str,
        timeout_ms: Optional[int] = None,
    ):
        if message_id not in _sent_messages:
            return {
                "status": "failed", "reply": None,
                "error": "Unknown message_id", "error_code": "UNKNOWN_MSG_ID",
            }

        timeout_s = (timeout_ms or self._cfg["wait_timeout_ms"]) / 1000

        # Poll io/ directory for reply files matching our message_id.
        # The IPC client's reply contract tells recipients to write:
        #   reply_<name>_to_bond-mcp_<message_id>.md
        # We scan for any file containing the message_id.
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            reply = self._find_reply_file(message_id)
            if reply is not None:
                return {
                    "status": "done", "reply": reply,
                    "error": None, "error_code": None,
                }
            time.sleep(0.5)

        return {
            "status": "timeout", "reply": None,
            "error": f"No reply within {timeout_s}s", "error_code": "TIMEOUT",
        }

    # --- Internal ---

    def _write_bus_message(self, message_id: str, target_id: str, body: str) -> str:
        """Write a bus message with frontmatter to io/ so the IPC client and recipient can read it."""
        os.makedirs(self._io_dir, exist_ok=True)

        filename = f"msg_bond-mcp_to_{target_id}_{message_id}.md"
        filepath = os.path.join(self._io_dir, filename)

        frontmatter = (
            f"---\n"
            f"from: bond-mcp\n"
            f"to: {target_id}\n"
            f"type: task\n"
            f"msg_id: {message_id}\n"
            f"reply_to: bond-mcp\n"
            f"subject: bus_ipc message\n"
            f"created_at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"---\n"
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(frontmatter)
            f.write(body)

        return filepath

    def _find_reply_file(self, message_id: str) -> Optional[str]:
        """Scan io/ for a reply file containing message_id. Returns reply body or None."""
        pattern = os.path.join(self._io_dir, f"reply_*_{message_id}*")
        matches = glob.glob(pattern)
        if not matches:
            return None

        # Take the first match (newest if multiple)
        reply_path = matches[0]
        try:
            with open(reply_path, "r", encoding="utf-8") as f:
                raw = f.read()
        except Exception:
            return None

        # Parse frontmatter to extract body
        if raw.startswith("---"):
            lines = raw.split("\n")
            end_idx = -1
            for i in range(1, len(lines)):
                if lines[i].strip() == "---":
                    end_idx = i
                    break
            if end_idx > 0:
                return "\n".join(lines[end_idx + 1:]).strip()

        return raw.strip()
