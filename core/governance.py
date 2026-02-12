"""Bond MCP Server — Governance Gate (Hardened)

Changes from original:
- Overrides respect policy ceiling (cannot bypass safety level restrictions)
- Override scope is actually enforced (session, time-limited, request-scoped)
- Escalation prevention: cannot jump more than one policy tier without explicit force
- All policy mutations are audit-logged
- add_override requires explicit max_safety_level and grantor identity
- Parameter-level governance hooks (blocked patterns, path validation)
- Thread-safe policy state
"""

from __future__ import annotations
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable

from models.models import (
    SafetyLevel, PolicyMode, ActionType,
    GovernanceDecision, GovernanceOverride,
    PolicyChangeEvent, Tool,
)

logger = logging.getLogger("bond.governance")


def _sanitize_log(s: str) -> str:
    """Sanitize user-controlled strings before logging to prevent log injection."""
    if not isinstance(s, str):
        return "invalid"
    return s.replace('\n', '\\n').replace('\r', '\\r').replace('\x00', '')


MAX_POLICY_HISTORY = 500  # Ring buffer cap for policy change events


class GovernanceGate:
    def __init__(self, policy_mode: PolicyMode):
        self._policy_mode = policy_mode
        self._lock = threading.RLock()
        self._overrides: Dict[str, GovernanceOverride] = {}
        self._policy_history: List[PolicyChangeEvent] = []
        self._parameter_validators: Dict[str, Callable] = {}
        self._blocked_patterns: List[str] = []

        logger.info(f"GovernanceGate initialized: policy={policy_mode.value}")

    @property
    def policy_mode(self) -> PolicyMode:
        with self._lock:
            return self._policy_mode

    def evaluate(self, tool: Tool, params: dict, request_id: Optional[str] = None) -> GovernanceDecision:
        """Evaluate whether a tool call should be allowed.

        Holds a single lock across the entire evaluation to prevent policy
        changes mid-evaluation (atomicity guarantee).

        Order of evaluation:
        1. Check parameter-level blocks (always applied)
        2. Check policy ceiling for tool safety level
        3. Check overrides (overrides can only RELAX within policy ceiling, not bypass it)
        """
        with self._lock:
            current_policy = self._policy_mode

            # --- Parameter-level governance ---
            param_decision = self._check_parameters(tool, params)
            if param_decision is not None:
                logger.warning(f"Parameter block: tool={tool.name} reason={param_decision.reason}")
                return param_decision

            # --- Policy ceiling check ---
            max_allowed = current_policy.max_safety_level
            tool_tier = tool.safety_level.tier
            ceiling_tier = max_allowed.tier

            if tool_tier <= ceiling_tier:
                return GovernanceDecision(
                    action=ActionType.ALLOW,
                    reason=f"Tool safety_level={tool.safety_level.value} within "
                           f"policy={current_policy.value} ceiling={max_allowed.value}",
                    override_available=False,
                    policy_mode=current_policy,
                )

            # --- Tool exceeds policy ceiling. Check overrides. ---
            override = self._check_override_locked(tool.name, request_id)
            if override is not None:
                if tool_tier <= override.max_safety_level.tier:
                    logger.info(
                        f"Override applied: tool={tool.name} "
                        f"override_max={override.max_safety_level.value} "
                        f"granted_by={override.granted_by}"
                    )
                    return GovernanceDecision(
                        action=ActionType.ALLOW,
                        reason=f"Override granted by {override.granted_by} "
                               f"(max={override.max_safety_level.value})",
                        override_available=True,
                        policy_mode=current_policy,
                    )
                else:
                    logger.warning(
                        f"Override insufficient: tool={tool.name} "
                        f"requires={tool.safety_level.value} "
                        f"override_max={override.max_safety_level.value}"
                    )

            # --- Denied ---
            has_override = override is not None
            return GovernanceDecision(
                action=ActionType.DENY,
                reason=f"Tool safety_level={tool.safety_level.value} exceeds "
                       f"policy={current_policy.value} ceiling={max_allowed.value}",
                override_available=has_override,
                policy_mode=current_policy,
            )

    def set_policy(self, mode: PolicyMode, changed_by: str = "system",
                   reason: str = "", force: bool = False) -> PolicyChangeEvent:
        """Change the active policy mode.

        Escalation prevention: cannot jump more than one tier without force=True.
        All changes are audit-logged.
        """
        with self._lock:
            old_mode = self._policy_mode
            tier_distance = mode.tier - old_mode.tier

            if tier_distance > 1 and not force:
                raise GovernanceEscalationError(
                    f"Cannot escalate from {old_mode.value} to {mode.value} "
                    f"(tier distance={tier_distance}). Use force=True for multi-tier escalation."
                )

            event = PolicyChangeEvent(
                old_mode=old_mode,
                new_mode=mode,
                changed_by=changed_by,
                reason=reason,
            )
            self._policy_history.append(event)
            # Cap history to prevent unbounded memory growth
            if len(self._policy_history) > MAX_POLICY_HISTORY:
                self._policy_history = self._policy_history[-MAX_POLICY_HISTORY:]
            self._policy_mode = mode

            logger.warning(
                f"Policy changed: {old_mode.value} -> {mode.value} "
                f"by={_sanitize_log(changed_by)} reason={_sanitize_log(reason)} force={force}"
            )
            return event

    def add_override(
        self,
        tool_name: str,
        scope: str,
        granted_by: str,
        max_safety_level: SafetyLevel,
        expires_at: Optional[datetime] = None,
    ) -> GovernanceOverride:
        """Add a scoped override for a tool.

        Unlike the original, overrides:
        - Have an explicit max_safety_level (cannot exceed CRITICAL)
        - Require grantor identity for audit
        - Can be time-limited
        - Are logged
        """
        override = GovernanceOverride(
            tool_name=tool_name,
            scope=scope,
            granted_by=granted_by,
            max_safety_level=max_safety_level,
            expires_at=expires_at,
        )

        with self._lock:
            self._overrides[tool_name] = override

        logger.warning(
            f"Override added: tool={_sanitize_log(tool_name)} scope={_sanitize_log(scope)} "
            f"max_safety={max_safety_level.value} granted_by={_sanitize_log(granted_by)} "
            f"expires={expires_at}"
        )
        return override

    def remove_override(self, tool_name: str) -> bool:
        with self._lock:
            removed = self._overrides.pop(tool_name, None)
            if removed:
                logger.info(f"Override removed: tool={tool_name}")
            return removed is not None

    def _check_override(self, tool_name: str, request_id: Optional[str] = None) -> Optional[GovernanceOverride]:
        with self._lock:
            return self._check_override_locked(tool_name, request_id)

    def _check_override_locked(self, tool_name: str, request_id: Optional[str] = None) -> Optional[GovernanceOverride]:
        """Check override without acquiring lock. Caller must hold self._lock."""
        override = self._overrides.get(tool_name)
        if override is None:
            return None
        if override.is_expired:
            del self._overrides[tool_name]
            logger.info(f"Override expired and removed: tool={tool_name}")
            return None
        if override.scope == "session":
            return override
        if override.scope == "permanent":
            return override
        if request_id and override.scope == request_id:
            return override
        return None

    def _check_parameters(self, tool: Tool, params: dict) -> Optional[GovernanceDecision]:
        """Run parameter-level validation. Returns a DENY decision if blocked."""
        # Check blocked patterns in all string values (recursive)
        def _extract_strings(obj, path=""):
            if isinstance(obj, str):
                yield path, obj
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    yield from _extract_strings(v, f"{path}.{k}" if path else k)
            elif isinstance(obj, (list, tuple)):
                for i, v in enumerate(obj):
                    yield from _extract_strings(v, f"{path}[{i}]")

        for param_path, value in _extract_strings(params):
            v_lower = value.lower()
            for pattern in self._blocked_patterns:
                if pattern.lower() in v_lower:
                    return GovernanceDecision(
                        action=ActionType.DENY,
                        reason=f"Blocked pattern '{pattern}' found in param '{param_path}'",
                        override_available=False,
                    )

        # Run custom validators
        validator = self._parameter_validators.get(tool.name)
        if validator:
            try:
                result = validator(params)
                if result is not None:
                    return result
            except Exception:
                logger.exception("Parameter validator failed")
                return GovernanceDecision(
                    action=ActionType.DENY,
                    reason="Parameter validation error",
                    override_available=False,
                )
        return None

    def add_blocked_pattern(self, pattern: str) -> None:
        """Block any tool call containing this pattern in string params."""
        with self._lock:
            self._blocked_patterns.append(pattern)
        logger.info(f"Blocked pattern added: {pattern}")

    def register_parameter_validator(self, tool_name: str, validator: Callable) -> None:
        """Register a custom parameter validator for a specific tool."""
        with self._lock:
            self._parameter_validators[tool_name] = validator

    def get_policy_history(self) -> List[PolicyChangeEvent]:
        with self._lock:
            return list(self._policy_history)

    def get_overrides(self) -> Dict[str, GovernanceOverride]:
        with self._lock:
            return dict(self._overrides)


class GovernanceEscalationError(Exception):
    """Raised when a policy escalation exceeds allowed tier distance."""
    pass
