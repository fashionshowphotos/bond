"""Bond MCP Server — Main Entry Point (Hardened)

Changes from original:
- Structured logging configuration
- Graceful shutdown with proper ordering (server → modules → logger)
- Signal handlers that actually exit
- Optional auth token from env/args
- Module manifest support
- Health info on startup
- Error handling for startup failures
"""

from __future__ import annotations
import argparse
import asyncio
import signal
import atexit
import logging
import sys
import os
import threading

# Ensure Bond's own directory is on sys.path (required when launched by external hosts like OnlyOffice)
_BOND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BOND_DIR not in sys.path:
    sys.path.insert(0, _BOND_DIR)

import json
import re

from core.module_loader import ModuleLoader, ToolRegistry, get_cached_tools
from core.governance import GovernanceGate
from core.task_logger import TaskLogger
from core.dispatcher import CoreDispatcher
from core.mcp_server import BondMCPServer
from core.plugin_bridge import PluginBridge
import stat

from models.models import PolicyMode, ModuleManifest, SafetyLevel, PluginDescriptor


def configure_logging(level: str = "INFO", log_file: str | None = None) -> None:
    """Set up structured logging to stderr (stdout is reserved for MCP JSON-RPC)."""
    handlers = [logging.StreamHandler(sys.stderr)]
    if log_file:
        # TOCTOU-safe log file open: use os.open with O_NOFOLLOW to prevent
        # symlink attacks, then fstat to reject non-regular files.
        log_path = os.path.realpath(log_file)
        try:
            open_flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, 'O_NOFOLLOW'):
                open_flags |= os.O_NOFOLLOW
            log_fd = os.open(log_path, open_flags, 0o644)
            fd_stat = os.fstat(log_fd)
            if not stat.S_ISREG(fd_stat.st_mode):
                os.close(log_fd)
                print(f"WARNING: --log-file {log_file!r} is not a regular file, ignoring",
                      file=sys.stderr)
            else:
                log_stream = os.fdopen(log_fd, "a")
                handlers.append(logging.StreamHandler(log_stream))
        except OSError as e:
            print(f"WARNING: --log-file {log_file!r} open failed: {e}, ignoring",
                  file=sys.stderr)

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )


async def discover_and_launch_plugins(
    plugins_dirs: list,
    tool_registry: ToolRegistry,
    logger: logging.Logger,
    allow_entry_points: bool = False,
    require_hashes: bool = False,
) -> list:
    """Discover, validate, and launch out-of-process plugins.

    Scans --plugins-dir directories for bond-plugin.json manifests.
    Optionally discovers plugins registered via pip entry_points
    (only when allow_entry_points=True — supply chain risk).
    Deduplicates by name, checks tool name collisions, launches each.

    Returns list of active PluginBridge instances.
    """
    descriptors: list = []
    active_plugins: list = []

    # 1. Scan --plugins-dir for bond-plugin.json
    for plugins_dir in plugins_dirs:
        if not os.path.isdir(plugins_dir):
            logger.warning("Plugins dir not found: %r", plugins_dir)
            continue
        for entry in os.scandir(plugins_dir):
            if entry.is_symlink():
                logger.warning("Skipping symlink in plugins dir: %r", entry.name)
                continue
            if entry.is_dir():
                # Resolve to real path and verify containment (TOCTOU defense:
                # directory could be swapped for symlink between scandir and open)
                real_entry = os.path.realpath(entry.path)
                real_pdir = os.path.realpath(plugins_dir)
                try:
                    common = os.path.commonpath([
                        os.path.normcase(real_pdir),
                        os.path.normcase(real_entry),
                    ])
                except ValueError:
                    logger.warning(
                        "Plugin dir %r skipped: commonpath check failed "
                        "(different drives or path error)",
                        entry.name,
                    )
                    continue
                if common != os.path.normcase(real_pdir):
                    logger.warning(
                        "Plugin dir %r resolves outside plugins dir — skipping",
                        entry.name,
                    )
                    continue
                manifest = os.path.join(real_entry, "bond-plugin.json")
                if os.path.exists(manifest):
                    # S_ISREG check moved into PluginDescriptor.from_json
                    # (fstat on open fd — no TOCTOU gap between stat and open)
                    try:
                        desc = PluginDescriptor.from_json(manifest)
                        descriptors.append(desc)
                        logger.debug(
                            "Found plugin manifest: %r (%r)",
                            desc.name, manifest
                        )
                    except Exception as e:
                        # Use repr() for paths — attacker-controlled filenames
                        # could contain control chars for log injection
                        logger.error("Bad manifest %r: %s", manifest, e)

    # 2. Scan pip entry_points (disabled by default — supply chain risk)
    if allow_entry_points:
        logger.warning(
            "pip entry_points plugin discovery ENABLED (--allow-entry-points). "
            "Any installed package declaring a 'bond.plugins' entry point will "
            "be loaded and executed. This is a supply chain risk."
        )
        try:
            from importlib.metadata import entry_points
            for ep in entry_points(group="bond.plugins"):
                try:
                    desc = ep.load()()
                    if isinstance(desc, PluginDescriptor):
                        descriptors.append(desc)
                        logger.debug(
                            "Found entry_point plugin: %r", desc.name
                        )
                    else:
                        logger.warning(
                            "Entry point %r returned %s, expected PluginDescriptor",
                            ep.name, type(desc).__name__
                        )
                except Exception as e:
                    logger.error("Entry point %r failed: %s", ep.name, e)
        except ImportError:
            pass

    if not descriptors:
        return active_plugins

    # 3. Deduplicate by name
    seen: set = set()
    valid: list = []
    for desc in descriptors:
        if desc.name in seen:
            logger.error(
                "Duplicate plugin %r from %r — skipping later occurrence",
                desc.name, desc.working_dir or "entry_point"
            )
            continue
        seen.add(desc.name)
        valid.append(desc)

    # 4. Launch each plugin
    for desc in valid:
        # Enforce hash requirement (production mode)
        if require_hashes and not desc.files_sha256:
            logger.error(
                "Plugin %r rejected: --require-plugin-hashes is set but "
                "files_sha256 is empty (no integrity verification)",
                desc.name,
            )
            continue

        bridge = PluginBridge(desc)
        if await bridge.start():
            # Check tool name collisions with existing registry
            collision = False
            for tool in bridge.get_tools():
                existing = tool_registry.get(tool.name)
                if existing is not None:
                    logger.error(
                        "Tool %r from plugin %r collides with "
                        "existing tool (module %r) — rejecting plugin",
                        tool.name, desc.name, existing.module_id
                    )
                    collision = True
                    break

            if collision:
                await bridge.stop()
                continue

            # Register all tools
            for tool in bridge.get_tools():
                tool_registry.register(tool)

            active_plugins.append(bridge)
            logger.info(
                "Plugin %r v%r: %d tools loaded",
                desc.name, desc.version, len(bridge.get_tools())
            )
        else:
            logger.error("Plugin %r failed to start", desc.name)

    return active_plugins


async def shutdown_plugins(
    plugins: list,
    logger: logging.Logger,
    timeout: float = 10.0,
) -> None:
    """Gracefully stop all active plugins."""
    for bridge in plugins:
        try:
            await asyncio.wait_for(bridge.stop(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "Plugin %r forced kill on shutdown timeout",
                bridge.descriptor.name
            )
        except Exception as e:
            logger.error(
                "Error stopping plugin %r: %s",
                bridge.descriptor.name, e
            )


def main():
    parser = argparse.ArgumentParser(description="Bond MCP Server (Hardened)")
    parser.add_argument(
        "--policy",
        type=str,
        choices=["OBSERVE_ONLY", "RESTRICTED", "BROAD", "FULL_AUTO"],
        default="RESTRICTED",
        help="Governance policy mode (default: RESTRICTED)",
    )
    parser.add_argument("--modules-dir", type=str, default="modules", help="Module directory path")
    parser.add_argument(
        "--log-level", type=str, default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)",
    )
    parser.add_argument("--log-file", type=str, default=None, help="Log file path (in addition to stderr)")
    parser.add_argument("--log-dir", type=str, default="logs", help="Task log directory")
    parser.add_argument(
        "--auth-token-file", type=str, default=None,
        help="Path to file containing MCP auth token (recommended over --auth-token)",
    )
    parser.add_argument(
        "--auth-token", type=str, default=None,
        help="[DEPRECATED] MCP auth token via CLI arg (visible in process list! Use --auth-token-file or BOND_MCP_AUTH_TOKEN env instead)",
    )
    parser.add_argument(
        "--insecure-allow-unverified-modules", action="store_true",
        help="Disable module manifest verification (NOT recommended for production)",
    )
    parser.add_argument(
        "--rate-limit", type=int, default=100,
        help="Global rate limit (calls/minute, min 1, default: 100)",
    )
    parser.add_argument(
        "--plugins-dir", action="append", default=[],
        help="Directory containing plugin folders with bond-plugin.json (repeatable)",
    )
    parser.add_argument(
        "--allow-entry-points", action="store_true",
        help="Enable pip entry_points plugin discovery (supply chain risk — disabled by default)",
    )
    parser.add_argument(
        "--require-plugin-hashes", action="store_true",
        help="Reject plugins with empty files_sha256 (recommended for production)",
    )
    args = parser.parse_args()

    # --- Input validation ---
    if args.rate_limit < 1:
        parser.error("--rate-limit must be >= 1")
    if args.rate_limit > 10000:
        parser.error("--rate-limit must be <= 10000")

    # --- Logging ---
    configure_logging(args.log_level, args.log_file)
    logger = logging.getLogger("bond.server")

    # --- Auth token resolution (file > env > deprecated CLI arg) ---
    auth_token = None
    if args.auth_token_file:
        try:
            # Non-blocking open with O_NOFOLLOW: prevents symlink attacks
            # and FIFO/device hang (open() on FIFO blocks until a writer connects)
            _MAX_TOKEN_BYTES = 4096
            _open_flags = os.O_RDONLY
            if hasattr(os, 'O_NOFOLLOW'):
                _open_flags |= os.O_NOFOLLOW
            if hasattr(os, 'O_NONBLOCK'):
                _open_flags |= os.O_NONBLOCK
            _token_fd = os.open(args.auth_token_file, _open_flags)
            try:
                fd_stat = os.fstat(_token_fd)
                if not stat.S_ISREG(fd_stat.st_mode):
                    logger.error(
                        "Auth token file %r is not a regular file — refusing",
                        args.auth_token_file,
                    )
                    sys.exit(1)
                # Permission check: warn if token file is world-readable (shared system risk)
                if os.name != 'nt' and fd_stat.st_mode & 0o077:
                    logger.warning(
                        "Auth token file %r has overly permissive permissions "
                        "(mode %s). Recommend chmod 600.",
                        args.auth_token_file, oct(fd_stat.st_mode & 0o777),
                    )
                if fd_stat.st_size > _MAX_TOKEN_BYTES:
                    logger.error(
                        "Auth token file too large (%d bytes, max %d)",
                        fd_stat.st_size, _MAX_TOKEN_BYTES,
                    )
                    sys.exit(1)
                with os.fdopen(_token_fd, "rb") as f:
                    _token_fd = -1  # fdopen took ownership
                    raw_token = f.read(_MAX_TOKEN_BYTES + 1)
                    if len(raw_token) > _MAX_TOKEN_BYTES:
                        logger.error("Auth token file grew during read (TOCTOU)")
                        sys.exit(1)
            finally:
                if _token_fd >= 0:
                    os.close(_token_fd)
            auth_token = raw_token.decode("utf-8", errors="replace").strip()
            if not auth_token:
                logger.error("Auth token file is empty: %r", args.auth_token_file)
                sys.exit(1)
        except FileNotFoundError:
            logger.error("Auth token file not found: %r", args.auth_token_file)
            sys.exit(1)
    elif "BOND_MCP_AUTH_TOKEN" in os.environ:
        auth_token = os.environ["BOND_MCP_AUTH_TOKEN"].strip()
        if not auth_token:
            logger.error(
                "BOND_MCP_AUTH_TOKEN env var is set but empty. "
                "Refusing to start with empty auth token (fail-closed)."
            )
            sys.exit(1)
    elif args.auth_token is not None:
        auth_token = args.auth_token.strip() if args.auth_token else ""
        if not auth_token:
            logger.error(
                "--auth-token provided but empty. "
                "Refusing to start with empty auth token (fail-closed)."
            )
            sys.exit(1)
        logger.warning(
            "Using --auth-token CLI argument. This exposes the token in the "
            "process list! Use --auth-token-file or BOND_MCP_AUTH_TOKEN env var instead."
        )
        # Best-effort scrub: overwrite the token value in sys.argv so
        # /proc/<pid>/cmdline doesn't leak it (not guaranteed on all OSes,
        # but reduces exposure window on Linux)
        for i, arg in enumerate(sys.argv):
            if arg == '--auth-token' and i + 1 < len(sys.argv):
                sys.argv[i + 1] = '***'
            elif arg.startswith('--auth-token='):
                sys.argv[i] = '--auth-token=***'

    # --- Manifest mode (default: ON, opt-out with --insecure-allow-unverified-modules) ---
    require_manifest = not args.insecure_allow_unverified_modules
    if not require_manifest:
        logger.warning(
            "Module manifest verification DISABLED (--insecure-allow-unverified-modules). "
            "Any .py file in the modules directory will be loaded and executed."
        )

    try:
        # --- Core components ---
        policy_mode = PolicyMode[args.policy]
        tool_registry = ToolRegistry()
        governance_gate = GovernanceGate(policy_mode)
        task_logger = TaskLogger(log_dir=args.log_dir)
        core_dispatcher = CoreDispatcher(
            tool_registry, governance_gate, task_logger,
            global_rate_limit=args.rate_limit,
        )

        # --- Load manifests ---
        _MAX_MODULE_MANIFEST_BYTES = 2 * 1024 * 1024  # 2 MB cap

        def load_manifests(manifest_path: str) -> list:
            if not os.path.exists(manifest_path):
                return []
            # Size-capped read pattern: fstat + read(cap) + json.loads
            # (matches PluginDescriptor.from_json pattern for consistency)
            # Reject non-regular files (FIFO/device → startup hang)
            # Non-blocking open prevents FIFO/device startup hang
            _open_flags = os.O_RDONLY
            if hasattr(os, 'O_NOFOLLOW'):
                _open_flags |= os.O_NOFOLLOW
            if hasattr(os, 'O_NONBLOCK'):
                _open_flags |= os.O_NONBLOCK
            try:
                _manifest_fd = os.open(manifest_path, _open_flags)
            except OSError as e:
                logger.error("Cannot open module manifest %r: %s", manifest_path, e)
                return []
            try:
                fd_stat = os.fstat(_manifest_fd)
                if not stat.S_ISREG(fd_stat.st_mode):
                    logger.error(
                        "Module manifest %r is not a regular file — skipping",
                        manifest_path,
                    )
                    os.close(_manifest_fd)
                    return []
                file_size = fd_stat.st_size
                if file_size > _MAX_MODULE_MANIFEST_BYTES:
                    logger.error(
                        "Module manifest %r too large (%s bytes, limit %s)",
                        manifest_path, file_size, _MAX_MODULE_MANIFEST_BYTES,
                    )
                    os.close(_manifest_fd)
                    return []
                with os.fdopen(_manifest_fd, "rb") as f_raw:
                    _manifest_fd = -1  # fdopen took ownership
                    raw_bytes = f_raw.read(_MAX_MODULE_MANIFEST_BYTES + 1)
                    if len(raw_bytes) > _MAX_MODULE_MANIFEST_BYTES:
                        logger.error(
                            "Module manifest %r grew during read (TOCTOU)",
                            manifest_path,
                        )
                        return []
            except OSError as e:
                logger.error("Cannot read module manifest %r: %s", manifest_path, e)
                if _manifest_fd >= 0:
                    os.close(_manifest_fd)
                return []
            try:
                raw = json.loads(raw_bytes.decode("utf-8"))
            except (RecursionError, json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(
                    "Failed to parse module manifest %r: %s",
                    manifest_path, type(e).__name__,
                )
                return []
            if not isinstance(raw, dict):
                logger.error(
                    "Module manifest %r: root is not a JSON object (got %s)",
                    manifest_path, type(raw).__name__,
                )
                return []
            raw_manifests = raw.get("manifests", [])
            if not isinstance(raw_manifests, list):
                logger.error(
                    "Module manifest %r: 'manifests' is not a list",
                    manifest_path,
                )
                return []
            manifests = []
            for i, m in enumerate(raw_manifests):
                if not isinstance(m, dict):
                    logger.error("Invalid manifest entry at index %d: not a dict — skipping", i)
                    continue
                try:
                    # Validate field types before construction
                    raw_module_id = m.get("module_id")
                    raw_file_path = m.get("file_path")
                    raw_sha256 = m.get("sha256_hash")
                    if not isinstance(raw_module_id, str) or not raw_module_id:
                        logger.error("Manifest entry %d: module_id must be a non-empty string — skipping", i)
                        continue
                    if not isinstance(raw_file_path, str) or not raw_file_path:
                        logger.error("Manifest entry %d: file_path must be a non-empty string — skipping", i)
                        continue
                    # Path traversal defense: reject absolute paths, .. components,
                    # and Windows drive-relative paths (e.g. "C:foo" — isabs returns
                    # False but os.path.join discards the base when a drive is present)
                    _drive, _ = os.path.splitdrive(raw_file_path)
                    if _drive or os.path.isabs(raw_file_path) or '..' in os.path.normpath(raw_file_path).split(os.sep):
                        logger.error("Manifest entry %d: file_path contains path traversal — skipping", i)
                        continue
                    # Sanitize module_id for log injection (alphanumeric + underscores only)
                    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', raw_module_id):
                        logger.error("Manifest entry %d: module_id contains invalid characters — skipping", i)
                        continue
                    if not isinstance(raw_sha256, str) or not re.match(r'^[0-9a-f]{64}$', raw_sha256):
                        logger.error("Manifest entry %d: sha256_hash must be a 64-char hex string — skipping", i)
                        continue
                    raw_allowed = m.get("allowed", True)
                    if not isinstance(raw_allowed, bool):
                        logger.error(
                            "Manifest entry %d: 'allowed' must be boolean, "
                            "got %s (%r) — skipping",
                            i, type(raw_allowed).__name__, raw_allowed,
                        )
                        continue
                    # Validate safety level against allowlist (future enum
                    # members like ADMIN/BYPASS should not be settable from manifests)
                    _MANIFEST_ALLOWED_SAFETY = {"LOW", "MODERATE", "HIGH"}
                    raw_safety = m.get("max_safety_level", "MODERATE")
                    if raw_safety not in _MANIFEST_ALLOWED_SAFETY:
                        logger.error(
                            "Manifest entry %d: disallowed max_safety_level %r — skipping",
                            i, raw_safety,
                        )
                        continue
                    manifests.append(ModuleManifest(
                        module_id=raw_module_id,
                        file_path=raw_file_path,
                        sha256_hash=raw_sha256,
                        allowed=raw_allowed,
                        max_safety_level=SafetyLevel[raw_safety],
                    ))
                except (KeyError, ValueError) as e:
                    logger.error("Invalid manifest entry at index %d: %s — skipping", i, e)
            # Filter out disallowed modules
            allowed = [m for m in manifests if m.allowed]
            blocked = len(manifests) - len(allowed)
            if blocked:
                logger.info("Filtered %d disallowed module(s) from manifest", blocked)
            return allowed

        manifest_path = os.path.join(args.modules_dir, "module_manifests.json")
        manifests = load_manifests(manifest_path)

        # --- Load modules ---
        modules = ModuleLoader.load_modules(
            [args.modules_dir],
            core_dispatcher,
            manifests=manifests,
            require_manifest=require_manifest,
        )

        for mod in modules:
            # Use loader-managed cache (prevents modules from tampering with cached tools)
            # IMPORTANT: use 'is not None' — empty list [] is valid (module has no tools)
            cached = get_cached_tools(mod)
            tools = cached if cached is not None else (mod.register_tools() or [])
            for tool in tools:
                tool_registry.register(tool)
                task_logger.register_tool_redaction(tool)

        # --- Server ---
        server = BondMCPServer(core_dispatcher, tool_registry, auth_token=auth_token)

        # --- Shutdown handling ---
        # RLock (not Lock) because Python signal handlers run on the main thread:
        # if a signal fires while shutdown() is already executing (same thread
        # holds the lock), Lock would deadlock. RLock is reentrant.
        _shutdown_lock = threading.RLock()
        shutdown_called = False
        active_plugins: list = []

        def shutdown(sig=None, frame=None):
            nonlocal shutdown_called
            with _shutdown_lock:
                if shutdown_called:
                    return
                shutdown_called = True

            sig_name = signal.Signals(sig).name if sig else "manual"
            logger.info("Shutting down (signal=%s)...", sig_name)

            server.request_shutdown()
            for mod in modules:
                mod_id = getattr(mod, 'module_id', '?')
                try:
                    # Run shutdown with a 5s timeout to prevent hanging
                    t = threading.Thread(
                        target=mod.shutdown, name=f"shutdown-{mod_id}", daemon=True
                    )
                    t.start()
                    t.join(timeout=5.0)
                    if t.is_alive():
                        logger.warning("Module %s shutdown timed out (5s)", mod_id)
                except Exception as e:
                    logger.error("Error shutting down module %s: %s", mod_id, e)

            # Plugin shutdown handled in _async_main finally block (not here —
            # create_task from signal handler gets cancelled when asyncio.run tears down)

            logger.info("Shutdown requested (will exit when stdio loop ends)")
            # Do NOT sys.exit() here; allow asyncio.run() to unwind

        signal.signal(signal.SIGINT, shutdown)
        if hasattr(signal, "SIGTERM"):
            try:
                signal.signal(signal.SIGTERM, shutdown)
            except Exception:
                logger.warning("SIGTERM handler not supported on this platform")
        # shutdown() is reentrant (RLock + shutdown_called flag), so call
        # unconditionally — simpler and correct under GIL-free Python (PEP 703)
        atexit.register(shutdown)

        # --- Async startup (plugin discovery + server run) ---
        async def _async_main():
            nonlocal active_plugins

            # Discover and launch plugins
            if args.plugins_dir:
                active_plugins = await discover_and_launch_plugins(
                    args.plugins_dir, tool_registry, logger,
                    allow_entry_points=args.allow_entry_points,
                    require_hashes=args.require_plugin_hashes,
                )

            # Startup banner
            tool_count = tool_registry.tool_count
            module_count = len(modules)
            plugin_count = len(active_plugins)
            auth_status = "enabled" if auth_token else "disabled"
            logger.info(
                "Bond MCP Server started: policy=%s tools=%d modules=%d "
                "plugins=%d auth=%s rate_limit=%d/min task_log=%s",
                args.policy, tool_count, module_count,
                plugin_count, auth_status, args.rate_limit,
                task_logger.get_log_path(),
            )
            print(
                f"Bond MCP Server (policy={args.policy}, {tool_count} tools, "
                f"{module_count} modules, {plugin_count} plugins, "
                f"auth={auth_status})",
                file=sys.stderr,
            )

            # Run MCP stdio loop — always clean up plugins on exit
            try:
                await server.run_stdio()
            finally:
                if active_plugins:
                    await shutdown_plugins(active_plugins, logger)

        asyncio.run(_async_main())

    except Exception as e:
        logger.critical("Server startup failed: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
