"""Bond MCP Server — Data Models (Hardened)

Changes from original:
- GovernanceDecision.action is now an enum (prevents typo-based bypass)
- Added ActionType enum for type-safe governance decisions
- Added PolicyEscalation guard with tier distances
- Added RequestContext for audit-enriched dispatch
- Added ModuleManifest for verified module loading
- Tool parameters include max_execution_seconds
- TaskRecord includes request_id for correlation
- Added field validation via __post_init__
- Added PluginDescriptor for out-of-process plugin subprocess management
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from typing import Optional, Any, Callable, Dict, List
import hashlib
import hmac
import json
import logging
import math
import os
import re
import shutil
import unicodedata

_logger = logging.getLogger(__name__)


def _verify_fd_path_in_container(fd: int, container: str) -> None:
    """Verify an open fd actually points inside container.

    Closes the gap where intermediate directories could be swapped with
    symlinks between realpath check and os.open (O_NOFOLLOW only protects
    the final component).

    Uses platform-specific fd path resolution:
    - Windows: GetFinalPathNameByHandleW
    - Linux: /proc/self/fd/{fd}
    - macOS: fcntl.F_GETPATH
    """
    actual = None

    if os.name == "nt":
        try:
            import ctypes
            import ctypes.wintypes
            import msvcrt
            kernel32 = ctypes.windll.kernel32
            GetFinalPathNameByHandleW = kernel32.GetFinalPathNameByHandleW
            GetFinalPathNameByHandleW.argtypes = [
                ctypes.wintypes.HANDLE, ctypes.wintypes.LPWSTR,
                ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
            ]
            GetFinalPathNameByHandleW.restype = ctypes.wintypes.DWORD
            handle = msvcrt.get_osfhandle(fd)
            buf = ctypes.create_unicode_buffer(1024)
            result = GetFinalPathNameByHandleW(handle, buf, 1024, 0)
            if 0 < result < 1024:
                final_path = buf.value
                if final_path.startswith("\\\\?\\"):
                    final_path = final_path[4:]
                actual = final_path
        except Exception:
            pass

    if actual is None:
        proc_path = f"/proc/self/fd/{fd}"
        if hasattr(os, "readlink") and os.path.exists(proc_path):
            try:
                actual = os.readlink(proc_path)
            except OSError:
                pass

    if actual is None:
        try:
            import fcntl
            import sys
            f_getpath = getattr(fcntl, 'F_GETPATH', None)
            if f_getpath is not None and sys.platform == 'darwin':
                buf = fcntl.fcntl(fd, f_getpath, b'\0' * 1024)
                actual = buf.split(b'\0', 1)[0].decode('utf-8')
        except (ImportError, OSError, UnicodeDecodeError):
            pass

    if actual is None:
        # Cannot verify — fail closed (intermediate dir attacks are real)
        os.close(fd)
        raise ValueError(
            "fd path verification unavailable — cannot guarantee "
            "intermediate directories were not swapped"
        )

    actual_norm = os.path.normcase(actual)
    container_norm = os.path.normcase(os.path.realpath(container))
    if not actual_norm.startswith(container_norm + os.sep) and actual_norm != container_norm:
        os.close(fd)
        raise ValueError(
            "TOCTOU detected: fd resolves outside working_dir "
            "(possible intermediate directory swap)"
        )


class SafetyLevel(Enum):
    SAFE = "SAFE"
    MODERATE = "MODERATE"
    DESTRUCTIVE = "DESTRUCTIVE"
    CRITICAL = "CRITICAL"

    @property
    def tier(self) -> int:
        return {
            SafetyLevel.SAFE: 0,
            SafetyLevel.MODERATE: 1,
            SafetyLevel.DESTRUCTIVE: 2,
            SafetyLevel.CRITICAL: 3,
        }[self]


class PolicyMode(Enum):
    OBSERVE_ONLY = "OBSERVE_ONLY"
    RESTRICTED = "RESTRICTED"
    BROAD = "BROAD"
    FULL_AUTO = "FULL_AUTO"

    @property
    def tier(self) -> int:
        return {
            PolicyMode.OBSERVE_ONLY: 0,
            PolicyMode.RESTRICTED: 1,
            PolicyMode.BROAD: 2,
            PolicyMode.FULL_AUTO: 3,
        }[self]

    @property
    def max_safety_level(self) -> SafetyLevel:
        """The highest safety level this policy mode will allow."""
        return {
            PolicyMode.OBSERVE_ONLY: SafetyLevel.SAFE,
            PolicyMode.RESTRICTED: SafetyLevel.MODERATE,
            PolicyMode.BROAD: SafetyLevel.DESTRUCTIVE,
            PolicyMode.FULL_AUTO: SafetyLevel.CRITICAL,
        }[self]


class ActionType(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


@dataclass
class Tool:
    name: str
    description: str
    parameters: Dict
    handler: Callable
    safety_level: SafetyLevel
    module_id: str
    max_execution_seconds: float = 30.0
    required_capabilities: List[str] = field(default_factory=list)
    redact_params: List[str] = field(default_factory=list)  # param keys to redact in logs
    redact_result: bool = False  # whether to redact handler result in logs

    def __post_init__(self):
        if not self.name or not self.name.strip():
            raise ValueError("Tool name cannot be empty")
        if not self.module_id or not self.module_id.strip():
            raise ValueError("Tool module_id cannot be empty")
        if (not isinstance(self.max_execution_seconds, (int, float))
                or isinstance(self.max_execution_seconds, bool)
                or not math.isfinite(self.max_execution_seconds)
                or self.max_execution_seconds <= 0):
            raise ValueError("max_execution_seconds must be a finite positive number")
        if self.max_execution_seconds > 3600:
            raise ValueError("max_execution_seconds must be <= 3600 (1 hour)")
        if isinstance(self.description, str) and len(self.description) > 4096:
            raise ValueError("Tool description must be <= 4096 characters")
        # Sanitize name: alphanumeric, underscores, hyphens only (must start with letter)
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_\-]*$', self.name):
            raise ValueError(f"Tool name {self.name!r} contains invalid characters")


@dataclass
class TaskRecord:
    task_id: str
    tool_name: str
    module_id: str
    params: Dict
    safety_level: SafetyLevel
    decision: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    status: str
    result: Optional[Any]
    error: Optional[str]
    request_id: Optional[str] = None  # correlate with MCP request


@dataclass
class GovernanceDecision:
    action: ActionType
    reason: str
    override_available: bool
    policy_mode: Optional[PolicyMode] = None
    evaluated_at: Optional[datetime] = None

    def __post_init__(self):
        if self.evaluated_at is None:
            self.evaluated_at = datetime.now(timezone.utc)


_VALID_OVERRIDE_SCOPES = frozenset({"session", "permanent"})


@dataclass
class GovernanceOverride:
    """A scoped override for a specific tool."""
    tool_name: str
    scope: str  # "session", "permanent", or a specific request_id (uuid4-like)
    granted_by: str  # who/what authorized this override
    max_safety_level: SafetyLevel  # override cannot exceed this
    expires_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if not self.tool_name or not isinstance(self.tool_name, str):
            raise ValueError("GovernanceOverride: tool_name must be a non-empty string")
        if not isinstance(self.scope, str) or not self.scope:
            raise ValueError("GovernanceOverride: scope must be a non-empty string")
        if len(self.scope) > 256:
            raise ValueError("GovernanceOverride: scope must be <= 256 characters")
        # scope must be a known keyword or a request_id (alphanumeric + hyphens)
        if self.scope not in _VALID_OVERRIDE_SCOPES:
            if not re.match(r'^[a-zA-Z0-9_-]+$', self.scope):
                raise ValueError(
                    f"GovernanceOverride: scope must be 'session', 'permanent', "
                    f"or a valid request_id, got {self.scope!r}"
                )
        if not isinstance(self.granted_by, str) or not self.granted_by:
            raise ValueError("GovernanceOverride: granted_by must be a non-empty string")
        if self.expires_at is not None:
            if not isinstance(self.expires_at, datetime):
                raise ValueError("GovernanceOverride: expires_at must be a datetime instance")
            if self.expires_at.tzinfo is None:
                raise ValueError("GovernanceOverride: expires_at must be timezone-aware")

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class ModuleManifest:
    """Verification record for a loadable module."""
    module_id: str
    file_path: str
    sha256_hash: str
    allowed: bool = True
    max_safety_level: SafetyLevel = SafetyLevel.MODERATE

    # Max file size for hashing (100 MB) — prevents DoS via multi-GB files
    MAX_HASH_FILE_SIZE = 100 * 1024 * 1024

    @staticmethod
    def compute_hash(file_path: str, max_size: int = 0) -> str:
        if max_size <= 0:
            max_size = ModuleManifest.MAX_HASH_FILE_SIZE
        h = hashlib.sha256()
        bytes_read = 0
        with open(file_path, 'rb') as f:
            # Use fstat on the open fd (not os.path.getsize) to prevent
            # TOCTOU: file could be swapped between getsize and open.
            import stat as _stat
            fd_stat = os.fstat(f.fileno())
            # Reject non-regular files (FIFO, device, socket — could block
            # or produce infinite data, e.g. /dev/random)
            if not _stat.S_ISREG(fd_stat.st_mode):
                raise ValueError(
                    f"Cannot hash non-regular file (mode={oct(fd_stat.st_mode)})"
                )
            file_size = fd_stat.st_size
            if file_size > max_size:
                raise ValueError(
                    f"File too large for hashing ({file_size:,} bytes, "
                    f"limit {max_size:,})"
                )
            for chunk in iter(lambda: f.read(8192), b''):
                bytes_read += len(chunk)
                if bytes_read > max_size:
                    raise ValueError(
                        f"File grew during hashing ({bytes_read:,} bytes read, "
                        f"limit {max_size:,}) — possible TOCTOU"
                    )
                h.update(chunk)
        return h.hexdigest()

    def verify(self) -> bool:
        if not re.match(r'^[0-9a-f]{64}$', self.sha256_hash):
            return False  # Malformed expected hash
        actual = self.compute_hash(self.file_path)
        return hmac.compare_digest(actual, self.sha256_hash)


@dataclass
class PolicyChangeEvent:
    """Audit record for policy mutations."""
    old_mode: PolicyMode
    new_mode: PolicyMode
    changed_by: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""


@dataclass
class PluginDescriptor:
    """Descriptor for an out-of-process plugin subprocess.

    All third-party plugins run as separate MCP servers in subprocesses.
    Bond communicates via newline-delimited JSON-RPC over stdin/stdout.
    No in-process promotion — subprocess isolation is the only execution model.
    """
    name: str                       # Unique identifier, [a-z0-9-]+
    version: str                    # Semver string (e.g. "1.0.0")
    command: str                    # Executable path or PATH name (e.g. "python")
    args: List[str]                 # Subprocess arguments (e.g. ["-u", "server.py"])

    # Environment control — allowlisted keys only
    env_allowlist: List[str] = field(default_factory=list)

    # Tool naming — all tools become "{prefix}_{tool_name}"
    tools_prefix: str = ""

    # Safety ceiling — plugin-declared levels are IGNORED, this ceiling is applied
    max_safety_level: SafetyLevel = SafetyLevel.MODERATE

    # Concurrency — max concurrent in-flight calls to this plugin
    max_inflight: int = 1

    # Timeouts
    timeout_seconds: float = 30.0   # Per-tool call timeout

    # Circuit breaker
    max_restarts: int = 3           # Before circuit breaker opens
    backoff_base: float = 5.0       # Seconds, multiplied 3x each restart
    backoff_cap: float = 300.0      # Maximum backoff (5 minutes)

    # Heartbeat
    heartbeat_interval: float = 30.0  # Seconds between idle ping probes

    # Integrity verification — SHA-256 of plugin CODE files (not interpreter)
    files_sha256: Dict[str, str] = field(default_factory=dict)

    # Windows Job Object — opt-in breakaway for CI/CD environments
    allow_breakaway: bool = False

    # Working directory — set during discovery
    working_dir: Optional[str] = None

    # Schema handling
    input_schema_mode: str = "passthrough"  # "passthrough" or "validate"

    def __post_init__(self):
        # Sanitize name: strip control characters (log injection defense)
        # before validation — attacker-controlled metadata must never inject
        # newlines/carriage returns into log streams
        if isinstance(self.name, str):
            self.name = re.sub(r'[\x00-\x1f\x7f]', '', self.name)

        # Validate name: lowercase alphanumeric + hyphens
        if not self.name or not re.match(r'^[a-z0-9][a-z0-9-]*$', self.name):
            raise ValueError(
                f"Plugin name '{self.name!r}' invalid: must be [a-z0-9-]+, "
                f"start with alphanumeric"
            )

        # Validate command exists on PATH or is absolute, then resolve
        # to absolute path. Storing the absolute prevents hijack when the
        # subprocess env has a different PATH (shutil.which uses current
        # PATH at validation time, but spawn uses the sanitized env).
        # Sanitize command for control chars (prevents CR/LF in error messages)
        if isinstance(self.command, str):
            self.command = re.sub(r'[\x00-\x1f\x7f]', '', self.command)
        if not self.command:
            raise ValueError("Plugin command cannot be empty")
        if os.path.isabs(self.command):
            if not os.path.isfile(self.command):
                raise ValueError(f"Plugin command not found: {self.command}")
        else:
            resolved = shutil.which(self.command)
            if resolved is None:
                raise ValueError(
                    f"Plugin command '{self.command}' not found on PATH"
                )
            self.command = os.path.realpath(resolved)

        # Sanitize version: strip control characters (log injection defense)
        if isinstance(self.version, str):
            self.version = re.sub(r'[\x00-\x1f\x7f]', '', self.version)

        # Validate args: must be a list of non-empty strings, no null bytes
        if not isinstance(self.args, list):
            raise ValueError("Plugin args must be a list")
        sanitized_args = []
        for i, arg in enumerate(self.args):
            if not isinstance(arg, str):
                raise ValueError(
                    f"Plugin args[{i}] must be a string, got {type(arg).__name__}"
                )
            # Strip null bytes (can cause argument truncation/injection on POSIX)
            clean = arg.replace('\x00', '')
            if clean != arg:
                _logger.warning(
                    "Plugin '%s': null byte stripped from args[%d]",
                    self.name, i,
                )
            sanitized_args.append(clean)
        self.args = sanitized_args

        # Validate version: basic semver (major.minor.patch)
        if not re.match(r'^\d+\.\d+\.\d+([a-zA-Z0-9._+-]*)$', self.version):
            raise ValueError(
                f"Plugin version '{self.version!r}' invalid: must be semver "
                f"(e.g. 1.0.0)"
            )

        # Default tools_prefix to name with hyphens replaced by underscores
        if not self.tools_prefix:
            self.tools_prefix = self.name.replace('-', '_')
        # Always validate (whether derived or explicit) — name can start
        # with a digit but tools_prefix must start with a letter
        if not re.match(r'^[a-z][a-z0-9_]*$', self.tools_prefix):
            raise ValueError(
                f"tools_prefix {self.tools_prefix!r} invalid: must start with "
                f"a letter and contain only [a-z0-9_]"
            )

        # Validate numeric fields — explicit type + finiteness checks
        # (NaN bypasses all comparisons; Infinity bypasses upper bounds)
        if not isinstance(self.max_inflight, int) or isinstance(self.max_inflight, bool):
            raise ValueError("max_inflight must be an integer")
        if self.max_inflight < 1 or self.max_inflight > 100:
            raise ValueError("max_inflight must be 1-100")

        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool):
            raise ValueError("timeout_seconds must be a number")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a finite positive number")
        if self.timeout_seconds > 3600:
            raise ValueError("timeout_seconds must be <= 3600 (1 hour)")

        if not isinstance(self.max_restarts, int) or isinstance(self.max_restarts, bool):
            raise ValueError("max_restarts must be an integer")
        if self.max_restarts < 0 or self.max_restarts > 100:
            raise ValueError("max_restarts must be 0-100")

        if not isinstance(self.backoff_base, (int, float)) or isinstance(self.backoff_base, bool):
            raise ValueError("backoff_base must be a number")
        if not math.isfinite(self.backoff_base) or self.backoff_base <= 0:
            raise ValueError("backoff_base must be a finite positive number")

        if not isinstance(self.backoff_cap, (int, float)) or isinstance(self.backoff_cap, bool):
            raise ValueError("backoff_cap must be a number")
        if not math.isfinite(self.backoff_cap) or self.backoff_cap <= 0:
            raise ValueError("backoff_cap must be a finite positive number")
        if self.backoff_cap > 3600:
            raise ValueError("backoff_cap must be <= 3600 (1 hour)")

        if not isinstance(self.heartbeat_interval, (int, float)) or isinstance(self.heartbeat_interval, bool):
            raise ValueError("heartbeat_interval must be a number")
        if not math.isfinite(self.heartbeat_interval) or self.heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be a finite positive number")
        if self.heartbeat_interval > 300:
            raise ValueError("heartbeat_interval must be <= 300 (5 minutes)")

        # Validate input_schema_mode
        if self.input_schema_mode not in ("passthrough", "validate"):
            raise ValueError(
                f"input_schema_mode must be 'passthrough' or 'validate', "
                f"got '{self.input_schema_mode}'"
            )

    @classmethod
    def from_json(cls, manifest_path: str) -> PluginDescriptor:
        """Load a PluginDescriptor from a bond-plugin.json manifest file.

        Expected JSON format:
        {
            "name": "my-plugin",
            "version": "1.0.0",
            "command": "python",
            "args": ["-u", "server.py"],
            "env_allowlist": ["MY_API_KEY"],
            "max_safety_level": "moderate",
            "max_inflight": 1,
            "timeout_seconds": 30,
            "files_sha256": {"server.py": "hex-digest"}
        }
        """
        # Size cap: reject manifest files > 2 MB to prevent memory/CPU DoS
        _MAX_MANIFEST_BYTES = 2 * 1024 * 1024
        with open(manifest_path, 'rb') as f_raw:
            import stat as _stat_mod
            _fd_stat = os.fstat(f_raw.fileno())
            # Reject non-regular files on the OPEN fd (no TOCTOU gap)
            if not _stat_mod.S_ISREG(_fd_stat.st_mode):
                raise ValueError(
                    f"Plugin manifest is not a regular file "
                    f"(mode={oct(_fd_stat.st_mode)})"
                )
            file_size = _fd_stat.st_size
            if file_size > _MAX_MANIFEST_BYTES:
                raise ValueError(
                    f"Plugin manifest too large ({file_size:,} bytes, "
                    f"limit {_MAX_MANIFEST_BYTES:,})"
                )
            raw = f_raw.read(_MAX_MANIFEST_BYTES + 1)
            if len(raw) > _MAX_MANIFEST_BYTES:
                raise ValueError(
                    f"Plugin manifest grew during read (possible TOCTOU)"
                )
        try:
            data = json.loads(raw.decode('utf-8'))
        except RecursionError:
            raise ValueError(
                f"Recursion bomb in plugin manifest {manifest_path!r} "
                f"(deeply nested JSON)"
            )
        except UnicodeDecodeError:
            raise ValueError(
                f"Plugin manifest is not valid UTF-8: {manifest_path!r}"
            )

        # Top-level type check (json.loads can return list, int, etc.)
        if not isinstance(data, dict):
            raise ValueError(
                f"Plugin manifest must be a JSON object, got {type(data).__name__}"
            )

        # Required fields
        for key in ('name', 'version', 'command', 'args'):
            if key not in data:
                raise ValueError(
                    f"Missing required field {key!r} in {manifest_path!r}"
                )

        # Type-check required string fields (JSON can have "name": 123 or "name": null)
        for str_key in ('name', 'version', 'command'):
            if not isinstance(data[str_key], str) or not data[str_key].strip():
                raise ValueError(
                    f"Field '{str_key}' must be a non-empty string, "
                    f"got {type(data[str_key]).__name__}"
                )

        # Type-check optional fields before passing to constructor
        # (prevents e.g. env_allowlist="not-a-list" → iterating over chars)
        raw_env_allowlist = data.get('env_allowlist', [])
        if not isinstance(raw_env_allowlist, list):
            raise ValueError(
                f"env_allowlist must be a list, got {type(raw_env_allowlist).__name__}"
            )
        raw_args = data.get('args', [])
        if not isinstance(raw_args, list):
            raise ValueError(
                f"args must be a list, got {type(raw_args).__name__}"
            )

        # Cap files_sha256 entries (prevent DoS via heavy hash workload)
        _MAX_FILES_SHA256 = 500
        files_dict = data.get('files_sha256', {})
        if not isinstance(files_dict, dict):
            raise ValueError(
                f"files_sha256 must be an object, got {type(files_dict).__name__}"
            )
        if len(files_dict) > _MAX_FILES_SHA256:
            raise ValueError(
                f"Too many files_sha256 entries ({len(files_dict)}, "
                f"limit {_MAX_FILES_SHA256})"
            )
        # Validate all keys and values are strings (JSON can have int/null keys)
        for fk, fv in files_dict.items():
            if not isinstance(fk, str) or not fk.strip():
                raise ValueError(
                    f"files_sha256 key must be a non-empty string, "
                    f"got {type(fk).__name__}"
                )
            if not isinstance(fv, str) or not fv.strip():
                raise ValueError(
                    f"files_sha256 value for '{fk}' must be a non-empty string, "
                    f"got {type(fv).__name__}"
                )

        # Convert safety level string to enum (type-check first)
        raw_safety = data.get('max_safety_level', 'MODERATE')
        if not isinstance(raw_safety, str):
            raise ValueError(
                f"max_safety_level must be a string, got {type(raw_safety).__name__}"
            )
        safety_str = raw_safety.upper()
        try:
            safety = SafetyLevel(safety_str)
        except ValueError:
            raise ValueError(
                f"Invalid max_safety_level {safety_str!r} in {manifest_path!r}. "
                f"Valid values: {[s.value for s in SafetyLevel]}"
            )

        return cls(
            name=data['name'],
            version=data['version'],
            command=data['command'],
            args=data['args'],
            env_allowlist=data.get('env_allowlist', []),
            tools_prefix=data.get('tools_prefix', ''),
            max_safety_level=safety,
            max_inflight=data.get('max_inflight', 1),
            timeout_seconds=data.get('timeout_seconds', 30.0),
            max_restarts=data.get('max_restarts', 3),
            backoff_base=data.get('backoff_base', 5.0),
            backoff_cap=data.get('backoff_cap', 300.0),
            heartbeat_interval=data.get('heartbeat_interval', 30.0),
            files_sha256=data.get('files_sha256', {}),
            allow_breakaway=data.get('allow_breakaway', False),
            input_schema_mode=data.get('input_schema_mode', 'passthrough'),
            working_dir=os.path.dirname(os.path.abspath(manifest_path)),
        )

    # Env vars that are NEVER forwarded to plugin subprocesses,
    # even if explicitly listed in env_allowlist. These allow code injection
    # via library preloading or interpreter manipulation.
    _ENV_DENYLIST = frozenset({
        # POSIX library injection
        'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT',
        # macOS library injection
        'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
        'DYLD_FRAMEWORK_PATH', 'DYLD_FALLBACK_LIBRARY_PATH',
        # Python manipulation
        'PYTHONSTARTUP', 'PYTHONPATH',
        # Node.js manipulation
        'NODE_OPTIONS',
        # Java manipulation
        'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'JAVA_OPTS',
        # Ruby manipulation
        'RUBYOPT', 'RUBYLIB',
        # Perl manipulation
        'PERL5OPT', 'PERL5LIB', 'PERLLIB',
        # Go manipulation
        'GOFLAGS',
        # .NET manipulation
        'DOTNET_STARTUP_HOOKS', 'COR_PROFILER', 'COR_PROFILER_PATH',
        # Shell startup injection
        'BASH_ENV', 'ENV', 'CDPATH',
        # General
        'LD_DEBUG', 'LD_PROFILE',
    })

    def build_subprocess_env(self) -> Dict[str, str]:
        """Build a minimal, secure environment for the plugin subprocess.

        Starts from empty dict (NOT os.environ copy).
        Adds only: PATH + Windows essentials + allowlisted keys.
        Denylisted keys are NEVER forwarded, even if allowlisted.
        """
        env: Dict[str, str] = {}

        # PATH is always required for subprocess to find executables
        if 'PATH' in os.environ:
            env['PATH'] = os.environ['PATH']

        # Windows requires these for Python/Node to function
        if os.name == 'nt':
            for key in ('SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE',
                        'COMSPEC', 'PATHEXT'):
                if key in os.environ:
                    env[key] = os.environ[key]

        # Copy only allowlisted keys from Bond's environment
        # (denylist overrides allowlist — security-critical)
        for key in self.env_allowlist:
            # Validate type + sanitize control characters (log injection defense)
            if not isinstance(key, str):
                _logger.warning(
                    "Plugin '%s': non-string env_allowlist entry skipped (type %s)",
                    self.name, type(key).__name__,
                )
                continue
            key = re.sub(r'[\x00-\x1f\x7f]', '', key)
            if not key:
                continue  # Was entirely control characters
            if key.upper() in self._ENV_DENYLIST:
                _logger.warning(
                    "Plugin '%s': env key '%s' blocked by denylist "
                    "(security-critical — cannot be forwarded to subprocess)",
                    self.name, key,
                )
                continue
            if key in os.environ:
                env[key] = os.environ[key]

        return env

    # Aggregate hash workload cap (prevents 500 × 100MB = 50GB DoS)
    _MAX_TOTAL_HASH_BYTES = 500 * 1024 * 1024  # 500 MB total

    def verify_plugin_files(self) -> bool:
        """Verify SHA-256 hashes of plugin code files against manifest.

        Returns True if all files match (or no hashes specified).
        Raises ValueError with details on mismatch.
        """
        if not self.files_sha256:
            return True  # No verification in development mode

        if not self.working_dir:
            raise ValueError("Cannot verify files: working_dir not set")

        total_bytes_hashed = 0

        for rel_path, expected_hash in self.files_sha256.items():
            # Sanitize rel_path for error messages (strip control chars
            # that could inject fake log lines via CRLF)
            safe_rel = re.sub(r'[\x00-\x1f\x7f]', '_', str(rel_path))[:200]

            # Validate hash format before any filesystem work
            if not isinstance(expected_hash, str) or not re.match(r'^[0-9a-f]{64}$', expected_hash):
                raise ValueError(
                    f"Invalid SHA-256 hash format for '{safe_rel}'"
                )
            abs_path = os.path.normpath(
                os.path.join(self.working_dir, rel_path)
            )

            # Security: ensure resolved path is within working_dir
            real_path = unicodedata.normalize('NFC', os.path.realpath(abs_path))
            real_working = unicodedata.normalize('NFC', os.path.realpath(self.working_dir))
            try:
                common = os.path.commonpath([
                    os.path.normcase(real_working),
                    os.path.normcase(real_path),
                ])
            except ValueError:
                raise ValueError(
                    f"Plugin file '{safe_rel}' resolves outside working dir"
                )
            if common != os.path.normcase(real_working):
                raise ValueError(
                    f"Plugin file '{safe_rel}' resolves outside working dir"
                )

            # TOCTOU-safe: open with O_NOFOLLOW, fstat on the fd, then
            # hash from the same fd — prevents symlink swap between check
            # and read (same pattern as plugin_bridge._copy_to_cache)
            import stat as _stat
            open_flags = os.O_RDONLY
            if hasattr(os, 'O_NOFOLLOW'):
                open_flags |= os.O_NOFOLLOW
            else:
                # Without O_NOFOLLOW there is a TOCTOU gap where an attacker
                # can swap a file for a symlink between realpath check and open.
                # Refuse to verify hashes on platforms lacking O_NOFOLLOW.
                raise RuntimeError(
                    "Platform lacks os.O_NOFOLLOW — cannot safely verify "
                    "plugin file hashes (symlink TOCTOU risk)"
                )
            try:
                fd = os.open(real_path, open_flags)
            except OSError as e:
                if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                    raise ValueError(
                        f"Symlink not allowed in plugin files: {safe_rel}"
                    )
                raise ValueError(f"Plugin file '{safe_rel}' not accessible")

            fd_owned = True
            try:
                # Post-open verification: ensure fd actually points inside
                # working_dir (closes intermediate directory TOCTOU gap —
                # O_NOFOLLOW only protects the final path component).
                _verify_fd_path_in_container(fd, self.working_dir)

                fd_stat = os.fstat(fd)
                if not _stat.S_ISREG(fd_stat.st_mode):
                    raise ValueError(
                        f"Plugin file '{safe_rel}' is not a regular file"
                    )
                file_size = fd_stat.st_size
                if file_size > ModuleManifest.MAX_HASH_FILE_SIZE:
                    raise ValueError(
                        f"Plugin file '{safe_rel}' too large for hashing "
                        f"({file_size:,} bytes, limit "
                        f"{ModuleManifest.MAX_HASH_FILE_SIZE:,})"
                    )
                # Hash from open fd (no re-open gap)
                # Track actual bytes read (not st_size) for the aggregate cap,
                # preventing a TOCTOU where files grow after fstat.
                h = hashlib.sha256()
                bytes_read = 0
                with os.fdopen(fd, 'rb') as f:
                    fd_owned = False
                    for chunk in iter(lambda: f.read(8192), b''):
                        bytes_read += len(chunk)
                        if bytes_read > ModuleManifest.MAX_HASH_FILE_SIZE:
                            raise ValueError(
                                f"Plugin file '{safe_rel}' grew during hashing"
                            )
                        total_bytes_hashed += len(chunk)
                        if total_bytes_hashed > self._MAX_TOTAL_HASH_BYTES:
                            raise ValueError(
                                f"Aggregate hash workload exceeded "
                                f"({total_bytes_hashed:,} bytes, "
                                f"limit {self._MAX_TOTAL_HASH_BYTES:,})"
                            )
                        h.update(chunk)
                actual_hash = h.hexdigest()
            finally:
                if fd_owned:
                    os.close(fd)

            if not hmac.compare_digest(actual_hash, expected_hash):
                raise ValueError(
                    f"Hash mismatch for '{safe_rel}': "
                    f"expected {expected_hash[:16]}..., "
                    f"got {actual_hash[:16]}..."
                )

        return True
