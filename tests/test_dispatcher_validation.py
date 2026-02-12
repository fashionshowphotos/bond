import json

import pytest

from core.dispatcher import (
    CoreDispatcher,
    MAX_PARAM_DEPTH,
    MAX_PARAM_SIZE,
    _check_param_safety,
)
from core.governance import GovernanceGate
from core.module_loader import ToolRegistry
from core.task_logger import TaskLogger
from models.models import PolicyMode, SafetyLevel, Tool


def _make_tool(parameters):
    return Tool(
        name="demo_tool",
        description="Demo",
        parameters=parameters,
        handler=lambda **_: "ok",
        safety_level=SafetyLevel.SAFE,
        module_id="test",
    )


@pytest.fixture
def dispatcher(tmp_path):
    registry = ToolRegistry()
    governance = GovernanceGate(PolicyMode.FULL_AUTO)
    task_logger = TaskLogger(log_dir=str(tmp_path / "logs"))
    d = CoreDispatcher(registry, governance, task_logger)
    try:
        yield d
    finally:
        d._executor.shutdown(wait=False, cancel_futures=True)


def test_check_type_rejects_bool_for_integer_and_number():
    assert CoreDispatcher._check_type(5, "integer")
    assert not CoreDispatcher._check_type(True, "integer")

    assert CoreDispatcher._check_type(5, "number")
    assert CoreDispatcher._check_type(3.14, "number")
    assert not CoreDispatcher._check_type(True, "number")


def test_validate_params_optional_field_is_not_required(dispatcher):
    tool = _make_tool(
        {
            "path": {"type": "string"},
            "mode": {"type": "string", "optional": True},
        }
    )
    assert dispatcher._validate_params(tool, {"path": "notes.txt"}) is None


def test_validate_params_rejects_unknown_param(dispatcher):
    tool = _make_tool({"path": {"type": "string"}})
    error = dispatcher._validate_params(tool, {"path": "a.txt", "extra": 1})
    assert error == "Unknown parameters: extra"


def test_validate_params_rejects_missing_required(dispatcher):
    tool = _make_tool({"path": {"type": "string"}})
    error = dispatcher._validate_params(tool, {})
    assert error == "Missing required parameter: 'path'"


def test_validate_params_rejects_bool_for_integer(dispatcher):
    tool = _make_tool({"count": {"type": "integer"}})
    error = dispatcher._validate_params(tool, {"count": True})
    assert error == "Parameter 'count' expected type 'integer', got 'bool'"


def test_check_param_safety_rejects_non_serializable_params():
    class NotSerializable:
        pass

    error = _check_param_safety({"value": NotSerializable()})
    assert error == "Parameters are not JSON-serializable"


def test_check_param_safety_rejects_too_deep_params():
    value = {}
    current = value
    for _ in range(MAX_PARAM_DEPTH + 1):
        nxt = {}
        current["x"] = nxt
        current = nxt

    error = _check_param_safety(value)
    assert error == f"Parameters exceed max nesting depth ({MAX_PARAM_DEPTH})"


def test_check_param_safety_rejects_oversized_params():
    payload = {"blob": "x" * MAX_PARAM_SIZE}
    actual_size = len(json.dumps(payload))
    error = _check_param_safety(payload)
    assert error == f"Parameters too large ({actual_size:,} chars, limit {MAX_PARAM_SIZE:,})"
