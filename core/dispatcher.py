"""Bond MCP Server — Core Dispatcher (Hardened)

Changes from original:
- Execution timeout via asyncio.wait_for (per-tool configurable)
- Input parameter validation against tool schema
- Error sanitization (no internal details leaked to client)
- Rate limiting (configurable per-tool and global)
- Request ID correlation through the full call chain
- Proper ActionType enum handling
- Result size limiting
"""

from __future__ import annotations
import asyncio
import concurrent.futures
import copy
import logging
import threading
import time
import uuid
from collections import defaultdict
from typing import Optional, Dict, Any

from models.models import Tool, ActionType
from core.module_loader import ToolRegistry
from core.governance import GovernanceGate
from core.task_logger import TaskLogger

logger = logging.getLogger("bond.dispatcher")

# Defaults
DEFAULT_GLOBAL_RATE_LIMIT = 100  # calls per minute
DEFAULT_TOOL_RATE_LIMIT = 30  # calls per minute per tool
MAX_RESULT_SIZE = 1_000_000  # 1MB max result returned to client
MAX_PARAM_DEPTH = 64         # Max nesting depth for params (prevents stack overflow on deepcopy)
MAX_PARAM_SIZE = 500_000     # Max total serialized size of params in chars


def _check_param_safety(params: dict) -> Optional[str]:
    """Check params for excessive depth or size before deepcopy.

    Returns error string if unsafe, None if OK.
    """
    import json
    try:
        serialized = json.dumps(params)
    except (TypeError, ValueError, RecursionError):
        return "Parameters are not JSON-serializable"

    if len(serialized) > MAX_PARAM_SIZE:
        return f"Parameters too large ({len(serialized):,} chars, limit {MAX_PARAM_SIZE:,})"

    def _check_depth(obj, depth=0):
        if depth > MAX_PARAM_DEPTH:
            return True
        if isinstance(obj, dict):
            return any(_check_depth(v, depth + 1) for v in obj.values())
        if isinstance(obj, (list, tuple)):
            return any(_check_depth(v, depth + 1) for v in obj)
        return False

    if _check_depth(params):
        return f"Parameters exceed max nesting depth ({MAX_PARAM_DEPTH})"

    return None


class RateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self, max_calls: int, window_seconds: float = 60.0):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: list = []
        self._lock = threading.Lock()

    def check(self) -> bool:
        now = time.monotonic()
        with self._lock:
            self._calls = [t for t in self._calls if now - t < self.window_seconds]
            if len(self._calls) >= self.max_calls:
                return False
            self._calls.append(now)
            return True

    @property
    def remaining(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._calls = [t for t in self._calls if now - t < self.window_seconds]
            return max(0, self.max_calls - len(self._calls))


class CoreDispatcher:
    def __init__(
        self,
        registry: ToolRegistry,
        governance: GovernanceGate,
        task_logger: TaskLogger,
        global_rate_limit: int = DEFAULT_GLOBAL_RATE_LIMIT,
        tool_rate_limit: int = DEFAULT_TOOL_RATE_LIMIT,
    ):
        self.registry = registry
        self.governance = governance
        self.task_logger = task_logger
        self._global_limiter = RateLimiter(global_rate_limit)
        self._tool_limiters: Dict[str, RateLimiter] = defaultdict(
            lambda: RateLimiter(tool_rate_limit)
        )
        self._executor = self._create_executor()

    @staticmethod
    def _create_executor():
        return concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def _reset_executor(self):
        """Reset executor after timeout to prevent dead worker exhaustion."""
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            logger.exception("Failed to shutdown executor")
        self._executor = self._create_executor()
        logger.warning("Executor reset after timeout to prevent dead worker exhaustion")

    async def handle_mcp_call(
        self,
        tool_name: str,
        params: dict,
        request_id: Optional[str] = None,
    ) -> dict:
        """Handle an MCP tool call with full safety pipeline.

        Pipeline: validate → rate-limit → governance → execute (with timeout) → respond
        """
        if request_id is None:
            request_id = str(uuid.uuid4())

        # --- Tool lookup ---
        tool = self.registry.get(tool_name)
        if not tool:
            logger.warning(f"[{request_id}] Tool not found: {tool_name}")
            return self._error_response(f"Tool '{tool_name}' not found")

        params = params or {}

        # --- Input validation ---
        validation_error = self._validate_params(tool, params)
        if validation_error:
            logger.warning(f"[{request_id}] Validation failed for {tool_name}: {validation_error}")
            return self._error_response(f"Invalid parameters: {validation_error}")

        # --- Rate limiting ---
        if not self._global_limiter.check():
            logger.warning(f"[{request_id}] Global rate limit exceeded")
            return self._error_response("Rate limit exceeded. Try again shortly.")

        if not self._tool_limiters[tool_name].check():
            logger.warning(f"[{request_id}] Tool rate limit exceeded: {tool_name}")
            return self._error_response(f"Rate limit for '{tool_name}' exceeded.")

        # Guard against stack overflow / memory bomb before deepcopy
        safety_error = _check_param_safety(params)
        if safety_error:
            logger.warning(f"[{request_id}] Param safety check failed for {tool_name}: {safety_error}")
            return self._error_response(f"Invalid parameters: {safety_error}")

        # Deep-copy params: frozen view for governance + logging, separate copy for handler
        safe_params = copy.deepcopy(params)
        call_params = copy.deepcopy(params)

        # --- Create task record (uses frozen params) ---
        task = self.task_logger.create_task(
            tool_name, tool.module_id, safe_params, tool.safety_level, request_id
        )

        # --- Governance evaluation (uses frozen params) ---
        decision = self.governance.evaluate(tool, safe_params, request_id)
        task.decision = decision.action.value

        if decision.action != ActionType.ALLOW:
            self.task_logger.block_task(task, decision.reason)
            logger.info(
                f"[{request_id}] Blocked: tool={tool_name} "
                f"action={decision.action.value} reason={decision.reason}"
            )
            # Do not disclose internal policy details to clients
            return self._error_response("Blocked by policy.")

        # --- Execute with timeout ---
        try:
            self.task_logger.start_task(task)
            handler = tool.handler
            timeout = tool.max_execution_seconds

            if asyncio.iscoroutinefunction(handler):
                result = await asyncio.wait_for(handler(**call_params), timeout=timeout)
            else:
                loop = asyncio.get_running_loop()
                future = loop.run_in_executor(self._executor, lambda: handler(**call_params))
                try:
                    result = await asyncio.wait_for(future, timeout=timeout)
                except asyncio.TimeoutError:
                    future.cancel()
                    self._reset_executor()
                    raise

            # Truncate oversized results (avoid double str() and expensive __str__)
            try:
                if isinstance(result, str):
                    truncated = len(result) > MAX_RESULT_SIZE
                    result_str = result[:MAX_RESULT_SIZE]
                else:
                    result_str = str(result)
                    truncated = len(result_str) > MAX_RESULT_SIZE
                    if truncated:
                        result_str = result_str[:MAX_RESULT_SIZE]
            except Exception:
                result_str = "[unstringifiable result]"
                truncated = False

            if truncated:
                result_str += f"\n... [TRUNCATED at {MAX_RESULT_SIZE} chars]"
                logger.warning(f"[{request_id}] Result truncated for {tool_name}")

            self.task_logger.complete_task(task, result_str)
            return {"content": [{"type": "text", "text": result_str}]}

        except asyncio.TimeoutError:
            error_msg = f"Tool '{tool_name}' exceeded {tool.max_execution_seconds}s timeout"
            self.task_logger.fail_task(task, error_msg)
            logger.error(f"[{request_id}] Timeout: {error_msg}")
            return self._error_response("Tool execution timed out.")

        except Exception as e:
            # Log full error internally, return sanitized message to client
            logger.error(f"[{request_id}] Tool execution error: {tool_name}: {e}", exc_info=True)
            self.task_logger.fail_task(task, str(e))
            return self._error_response("Internal tool error. Check server logs.")

    def _validate_params(self, tool: Tool, params: dict) -> Optional[str]:
        """Validate params against the tool's parameter schema.

        Checks:
        - All required params are present
        - No unknown params
        - Basic type validation for declared types
        """
        schema = tool.parameters
        if not schema:
            if params:
                return "Tool accepts no parameters"
            return None

        # Check for unknown parameters
        unknown = set(params.keys()) - set(schema.keys())
        if unknown:
            return f"Unknown parameters: {', '.join(sorted(unknown))}"

        # Check required params (all declared params are required unless marked optional)
        for param_name, param_def in schema.items():
            if param_name not in params:
                if isinstance(param_def, dict) and param_def.get("optional", False):
                    continue
                return f"Missing required parameter: '{param_name}'"

            # Basic type checking
            if isinstance(param_def, dict) and "type" in param_def:
                expected_type = param_def["type"]
                value = params[param_name]
                if not self._check_type(value, expected_type):
                    return f"Parameter '{param_name}' expected type '{expected_type}', got '{type(value).__name__}'"

        return None

    @staticmethod
    def _check_type(value: Any, expected: str) -> bool:
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)

        type_map = {
            "string": str,
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        expected_types = type_map.get(expected)
        if expected_types is None:
            return True  # Unknown type → pass through
        return isinstance(value, expected_types)

    @staticmethod
    def _error_response(message: str) -> dict:
        return {"content": [{"type": "text", "text": message}], "isError": True}
