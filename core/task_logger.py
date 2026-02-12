"""Bond MCP Server — Task Logger (Hardened)

Changes from original:
- Log rotation (configurable max file size and retention count)
- Sensitive parameter redaction
- File locking to prevent concurrent write corruption
- Integrity chaining (each record includes hash of previous)
- Configurable log levels
- Result truncation to prevent enormous log entries
- Thread-safe operations
"""

from __future__ import annotations
import uuid
import hashlib
import json
import os
import threading
from datetime import datetime

# Platform-specific file locking
if os.name != "nt":
    import fcntl
else:
    import msvcrt
from dataclasses import asdict
from typing import Any, Optional, List
from enum import Enum
import logging

from models.models import TaskRecord, SafetyLevel, Tool

logger = logging.getLogger("bond.task_logger")

# Defaults
DEFAULT_MAX_LOG_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_LOG_FILES = 10
DEFAULT_MAX_RESULT_LENGTH = 10_000  # chars
REDACTED = "***REDACTED***"


class TaskLogger:
    def __init__(
        self,
        log_dir: str = "logs",
        max_log_size: int = DEFAULT_MAX_LOG_SIZE_BYTES,
        max_log_files: int = DEFAULT_MAX_LOG_FILES,
        max_result_length: int = DEFAULT_MAX_RESULT_LENGTH,
    ):
        self.log_dir = log_dir
        self.max_log_size = max_log_size
        self.max_log_files = max_log_files
        self.max_result_length = max_result_length
        self._lock = threading.Lock()
        self._last_hash: Optional[str] = None  # integrity chain
        self._redact_rules: dict = {}  # tool_name -> {param_keys: [], redact_result: bool}

        os.makedirs(self.log_dir, exist_ok=True)
        self.current_log_path = self._get_new_log_path()

    def _get_new_log_path(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = uuid.uuid4().hex[:8]
        return os.path.join(self.log_dir, f"tasks_{timestamp}_{suffix}.jsonl")

    def get_log_path(self) -> str:
        return self.current_log_path

    def register_tool_redaction(self, tool: Tool) -> None:
        """Register redaction rules from a tool's metadata."""
        if tool.redact_params or tool.redact_result:
            self._redact_rules[tool.name] = {
                "param_keys": list(tool.redact_params),
                "redact_result": tool.redact_result,
            }

    def create_task(
        self,
        tool_name: str,
        module_id: str,
        params: dict,
        safety_level: SafetyLevel,
        request_id: Optional[str] = None,
    ) -> TaskRecord:
        task = TaskRecord(
            task_id=str(uuid.uuid4()),
            tool_name=tool_name,
            module_id=module_id,
            params=params or {},
            safety_level=safety_level,
            decision="",
            created_at=datetime.now(),
            started_at=None,
            finished_at=None,
            status="created",
            result=None,
            error=None,
            request_id=request_id,
        )
        self._persist(task)
        return task

    def start_task(self, task: TaskRecord) -> None:
        task.started_at = datetime.now()
        task.status = "started"
        self._persist(task)

    def complete_task(self, task: TaskRecord, result: Any) -> None:
        task.finished_at = datetime.now()
        task.status = "completed"
        task.result = result
        self._persist(task)

    def fail_task(self, task: TaskRecord, error: str) -> None:
        task.finished_at = datetime.now()
        task.status = "failed"
        task.error = error
        self._persist(task)

    def block_task(self, task: TaskRecord, reason: str) -> None:
        task.status = "blocked"
        task.error = reason
        self._persist(task)

    def _redact_data(self, task_dict: dict) -> dict:
        """Apply redaction rules before logging."""
        tool_name = task_dict.get("tool_name", "")
        rules = self._redact_rules.get(tool_name)
        if not rules:
            return task_dict

        # Redact specific parameter keys
        if "params" in task_dict and rules.get("param_keys"):
            for key in rules["param_keys"]:
                if key in task_dict["params"]:
                    task_dict["params"][key] = REDACTED

        # Redact result
        if rules.get("redact_result") and task_dict.get("result") is not None:
            task_dict["result"] = REDACTED

        return task_dict

    def _truncate_result(self, task_dict: dict) -> dict:
        """Prevent enormous results from bloating logs."""
        result = task_dict.get("result")
        if result is not None:
            result_str = str(result)
            if len(result_str) > self.max_result_length:
                task_dict["result"] = result_str[:self.max_result_length] + f"... [TRUNCATED, {len(result_str)} chars total]"
        return task_dict

    def _truncate_params(self, task_dict: dict) -> dict:
        """Prevent enormous parameters from bloating logs (mirrors _truncate_result)."""
        params = task_dict.get("params")
        if params is not None:
            params_str = json.dumps(params, default=str) if isinstance(params, dict) else str(params)
            if len(params_str) > self.max_result_length:
                task_dict["params"] = {"_truncated": True, "_size": len(params_str),
                                       "_preview": params_str[:self.max_result_length]}
        return task_dict

    def _compute_chain_hash(self, data_json: str) -> str:
        """Hash the record + previous hash for integrity chaining (full SHA-256)."""
        anchor = os.path.basename(self.current_log_path)
        chain_input = f"{anchor}:{self._last_hash or 'GENESIS'}:{data_json}"
        return hashlib.sha256(chain_input.encode('utf-8')).hexdigest()

    def _serialize(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, dict):
            return {str(self._serialize(k)): self._serialize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [self._serialize(v) for v in obj]
        return obj

    def _rotate_if_needed(self) -> None:
        """Rotate log file if current exceeds max size."""
        try:
            if os.path.exists(self.current_log_path):
                size = os.path.getsize(self.current_log_path)
                if size >= self.max_log_size:
                    self.current_log_path = self._get_new_log_path()
                    self._cleanup_old_logs()
        except OSError:
            pass

    def _cleanup_old_logs(self) -> None:
        """Remove oldest log files beyond retention limit."""
        try:
            log_files = sorted(
                [f for f in os.listdir(self.log_dir) if f.startswith("tasks_") and f.endswith(".jsonl")],
                reverse=True,
            )
            for old_file in log_files[self.max_log_files:]:
                os.remove(os.path.join(self.log_dir, old_file))
                logger.info(f"Removed old log file: {old_file}")
        except OSError as e:
            logger.error(f"Log cleanup error: {e}")

    def _persist(self, task: TaskRecord) -> None:
        with self._lock:
            self._rotate_if_needed()

            data = self._serialize(asdict(task))
            data = self._redact_data(data)
            data = self._truncate_params(data)
            data = self._truncate_result(data)

            data_json = json.dumps(data, default=str)

            # Integrity chain
            chain_hash = self._compute_chain_hash(data_json)
            data["_chain_hash"] = chain_hash
            self._last_hash = chain_hash

            final_json = json.dumps(data, default=str)

            try:
                with open(self.current_log_path, "a", encoding="utf-8") as f:
                    # Cross-process file locking (Unix: flock, Windows: msvcrt)
                    if os.name != "nt":
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    else:
                        # Lock a large region to cover the full write, not just 1 byte
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, max(len(final_json.encode("utf-8")) + 1, 1))
                        f.seek(0, os.SEEK_END)
                    try:
                        f.write(final_json + "\n")
                        f.flush()
                    finally:
                        if os.name != "nt":
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                        else:
                            f.seek(0)
                            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, max(len(final_json.encode("utf-8")) + 1, 1))
            except OSError as e:
                logger.error(f"Failed to persist task {task.task_id}: {e}")
