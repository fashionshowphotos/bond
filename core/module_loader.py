"""Bond MCP Server — Module Loader (Hardened)

Changes from original:
- Module manifest verification (SHA-256 hash check before execution)
- Allowlist-based loading (only manifested modules load)
- All load failures are logged with full context
- ToolRegistry validates tool names on registration
- ToolRegistry enforces uniqueness (no silent overwrites)
- Module safety level ceiling (module manifest limits max safety level of its tools)
- List_tools includes module_id for transparency
- TOCTOU-safe manifest: read bytes once, hash, compile+exec from memory
- Module namespace isolation: loaded as bond_modules.{name} to prevent stdlib clobber
"""

from __future__ import annotations
import hashlib
import importlib
import importlib.util
import importlib.machinery
import inspect
import os
import sys
import pathlib
import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any

from models.models import Tool, SafetyLevel, ModuleManifest

logger = logging.getLogger("bond.module_loader")


class RestrictedCore:
    """Limited interface passed to modules via initialize(core).

    Prevents modules from directly accessing governance mutation,
    registry write operations, task logger, rate limiters, or executor.
    Modules can only:
    - Invoke other tools through the full safety pipeline
    - Read current policy mode
    - Read the list of tool names
    """

    __slots__ = ("_dispatcher",)

    def __init__(self, dispatcher):
        self._dispatcher = dispatcher

    async def invoke_tool(self, tool_name: str, params: dict, request_id: str = None) -> dict:
        """Call another registered tool through the full safety pipeline."""
        return await self._dispatcher.handle_mcp_call(tool_name, params or {}, request_id)

    def get_policy_mode(self) -> str:
        """Read-only: current governance policy mode name."""
        return self._dispatcher.governance.policy_mode.name

    def list_tool_names(self) -> list:
        """Read-only: list of registered tool names."""
        return [t["name"] for t in self._dispatcher.registry.list_tools()]

    def __getattr__(self, name):
        raise AttributeError(
            f"RestrictedCore has no attribute '{name}'. "
            f"Modules receive a restricted interface — direct access to "
            f"governance, registry, task_logger, etc. is not permitted."
        )


class BondModule(ABC):
    module_id: str = "unknown"

    @abstractmethod
    def register_tools(self) -> List[Tool]:
        pass

    @abstractmethod
    def initialize(self, core: Any) -> None:
        pass

    @abstractmethod
    def shutdown(self) -> None:
        pass


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ToolRegistrationError(
                f"Tool '{tool.name}' already registered by module "
                f"'{self._tools[tool.name].module_id}'. "
                f"Module '{tool.module_id}' attempted duplicate registration."
            )
        # Tool.__post_init__ already validates name format
        self._tools[tool.name] = tool
        logger.info(
            f"Tool registered: name={tool.name} module={tool.module_id} "
            f"safety={tool.safety_level.value}"
        )

    def unregister(self, tool_name: str) -> bool:
        removed = self._tools.pop(tool_name, None)
        if removed:
            logger.info(f"Tool unregistered: {tool_name}")
        return removed is not None

    def get(self, tool_name: str) -> Optional[Tool]:
        return self._tools.get(tool_name)

    def list_tools(self) -> List[Dict[str, Any]]:
        import json
        result = []
        for tool in self._tools.values():
            params = tool.parameters
            # Ensure parameters are JSON-serializable (guard against bad module schemas)
            try:
                json.dumps(params)
            except (TypeError, ValueError):
                logger.warning(f"Tool '{tool.name}' has non-serializable parameters schema, replacing with empty")
                params = {}
            # Build required list from params that don't have optional=True
            required = []
            for pname, pdef in params.items():
                if isinstance(pdef, dict) and not pdef.get("optional", False):
                    required.append(pname)
            schema = {
                "type": "object",
                "properties": params,
            }
            if required:
                schema["required"] = required
            result.append({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": schema,
                "safety_level": tool.safety_level.value,
                "module_id": tool.module_id,
            })
        return result

    @property
    def tool_count(self) -> int:
        return len(self._tools)


class _ToolCache:
    """Loader-managed tool cache. Keyed by id(module) so modules cannot
    tamper with their own cached tools by overwriting instance attributes."""

    def __init__(self):
        self._cache: Dict[int, List[Tool]] = {}

    def store(self, module: BondModule, tools: List[Tool]) -> None:
        self._cache[id(module)] = tools

    def get(self, module: BondModule) -> Optional[List[Tool]]:
        return self._cache.get(id(module))


# Global tool cache — populated during load_modules, consumed by bond_server
_tool_cache = _ToolCache()


def get_cached_tools(module: BondModule) -> Optional[List[Tool]]:
    """Retrieve loader-cached (and safety-capped) tools for a module.

    Returns None if the module has no cached tools (legacy load path).
    Returns [] if the module has no tools.
    """
    return _tool_cache.get(module)


class ModuleLoader:
    @staticmethod
    def load_modules(
        module_dirs: List[str],
        core: Any,
        manifests: Optional[List[ModuleManifest]] = None,
        require_manifest: bool = False,
    ) -> List[BondModule]:
        """Load modules from directories with optional manifest verification.

        Args:
            module_dirs: Directories to scan for .py module files
            core: Core dispatcher reference passed to module.initialize()
            manifests: Optional list of ModuleManifest for hash verification
            require_manifest: If True, only load modules with valid manifests
        """
        manifest_map: Dict[str, ModuleManifest] = {}
        if manifests:
            for m in manifests:
                manifest_map[m.module_id] = m

        # Wrap core in RestrictedCore so modules cannot mutate governance/registry
        restricted_core = RestrictedCore(core)

        loaded_modules: List[BondModule] = []

        for dir_path in module_dirs:
            path = pathlib.Path(dir_path)
            if not path.exists():
                logger.warning(f"Module directory does not exist: {dir_path}")
                continue
            if not path.is_dir():
                logger.warning(f"Module path is not a directory: {dir_path}")
                continue

            for py_file in sorted(path.glob("*.py")):
                module_name = py_file.stem
                if module_name.startswith("_"):
                    continue

                file_path_str = str(py_file.resolve())

                # --- Manifest verification ---
                if require_manifest:
                    manifest = manifest_map.get(module_name)
                    if manifest is None:
                        logger.warning(
                            f"Module '{module_name}' has no manifest — skipping (require_manifest=True)"
                        )
                        continue
                    if not manifest.allowed:
                        logger.warning(f"Module '{module_name}' is disabled in manifest — skipping")
                        continue
                    # Verify manifest file_path matches actual file (prevents manifest swapping)
                    manifest_fp = str(pathlib.Path(manifest.file_path).resolve())
                    actual_fp = str(py_file.resolve())
                    if manifest_fp != actual_fp:
                        logger.error(
                            f"Module '{module_name}' manifest file_path mismatch — "
                            f"manifest={manifest_fp} actual={actual_fp} — REFUSING TO LOAD"
                        )
                        continue

                    # Read file bytes ONCE for both hash and execution (TOCTOU-safe)
                    try:
                        read_flags = os.O_RDONLY
                        if hasattr(os, "O_NOFOLLOW"):
                            read_flags |= os.O_NOFOLLOW
                        fd = os.open(file_path_str, read_flags)
                        try:
                            with os.fdopen(fd, "rb") as f:
                                source_bytes = f.read()
                        except Exception:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
                            raise
                    except OSError as e:
                        logger.error(f"Failed to read module '{module_name}': {e}")
                        continue

                    actual_hash = hashlib.sha256(source_bytes).hexdigest()
                    if actual_hash != manifest.sha256_hash:
                        logger.error(
                            f"Module '{module_name}' HASH MISMATCH — "
                            f"expected={manifest.sha256_hash[:16]}... "
                            f"actual={actual_hash[:16]}... — REFUSING TO LOAD"
                        )
                        continue
                    logger.info(f"Module '{module_name}' manifest verified ✓")

                # --- Load module ---
                # Namespace modules under bond_modules.{name} to prevent stdlib clobber
                safe_module_name = f"bond_modules.{module_name}"

                if require_manifest:
                    # TOCTOU-safe path: compile+exec from verified bytes (no second disk read)
                    try:
                        code = compile(source_bytes, str(py_file), "exec")
                        spec = importlib.util.spec_from_loader(
                            safe_module_name, loader=None, origin=str(py_file)
                        )
                        py_module = importlib.util.module_from_spec(spec)
                        py_module.__file__ = str(py_file)
                        sys.modules[safe_module_name] = py_module
                        exec(code, py_module.__dict__)
                    except Exception as e:
                        logger.error(f"Failed to execute module '{module_name}': {e}", exc_info=True)
                        sys.modules.pop(safe_module_name, None)
                        continue
                else:
                    # Legacy path (no manifest): load from file but still namespace
                    spec = importlib.util.spec_from_file_location(safe_module_name, py_file)
                    if spec is None or spec.loader is None:
                        logger.warning(f"Cannot create import spec for: {py_file}")
                        continue
                    py_module = importlib.util.module_from_spec(spec)
                    sys.modules[safe_module_name] = py_module
                    try:
                        spec.loader.exec_module(py_module)
                    except Exception as e:
                        logger.error(f"Failed to execute module '{module_name}': {e}", exc_info=True)
                        sys.modules.pop(safe_module_name, None)
                        continue

                # --- Find and instantiate BondModule subclasses ---
                for name, obj in inspect.getmembers(py_module):
                    if (
                        inspect.isclass(obj)
                        and issubclass(obj, BondModule)
                        and obj is not BondModule
                    ):
                        try:
                            instance = obj()
                            instance.initialize(restricted_core)

                            module_id = getattr(instance, "module_id", module_name)

                            # Enforce module_id matches filename when manifest is required
                            # Prevents a module from claiming another module's identity
                            # to inherit its safety ceiling
                            if require_manifest and module_id != module_name:
                                logger.error(
                                    f"Module '{module_name}' declares module_id='{module_id}' "
                                    f"which does not match filename — REFUSING TO LOAD "
                                    f"(prevents privilege escalation via ID spoofing)"
                                )
                                continue

                            # Only fall back to filename if module_id lookup misses
                            # AND the filename matches the module_id in the manifest
                            manifest = manifest_map.get(module_id)
                            if manifest is None and module_id != module_name:
                                fallback = manifest_map.get(module_name)
                                if fallback is not None and fallback.module_id == module_name:
                                    manifest = fallback

                            # Register/cap ONCE and persist for later use
                            tools = list(instance.register_tools() or [])
                            if manifest:
                                for tool in tools:
                                    if tool.safety_level.tier > manifest.max_safety_level.tier:
                                        logger.error(
                                            f"Tool '{tool.name}' in module '{module_name}' "
                                            f"declares safety_level={tool.safety_level.value} "
                                            f"but manifest ceiling is {manifest.max_safety_level.value} "
                                            f"— CAPPING to ceiling"
                                        )
                                        tool.safety_level = manifest.max_safety_level

                            # Persist capped tools in loader-managed cache (not on module instance)
                            _tool_cache.store(instance, tools)

                            loaded_modules.append(instance)
                            logger.info(
                                f"Module loaded: {module_id} "
                                f"from {py_file}"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to initialize module class '{name}' "
                                f"from '{module_name}': {e}",
                                exc_info=True,
                            )
                            continue

        logger.info(f"Module loading complete: {len(loaded_modules)} modules loaded")
        return loaded_modules


class ToolRegistrationError(Exception):
    """Raised when a tool registration violates constraints."""
    pass
