"""Bond MCP Server — Filesystem Module (Hardened)

Security-hardened filesystem module. Replaces the original insecure version.

Key properties:
- MANDATORY sandbox root (fail-closed: no sandbox = no file ops)
- Symlink escape prevention
- File read/write size limits
- Path traversal protection
- Binary file detection
- Atomic writes (temp + rename)
- Blocked path patterns (.ssh, .env, secrets)
- Windows-safe: case-insensitive containment, device name blocking, ADS blocking
- No absolute path leakage (returns sandbox-relative paths only)
"""

from __future__ import annotations
import os
import re
import glob as globmod
import tempfile
import logging
from typing import List, Optional

from core.module_loader import BondModule
from core.fs_utils import win_get_final_path
from models.models import Tool, SafetyLevel

logger = logging.getLogger("bond.filesystem")

# Defaults
DEFAULT_MAX_READ_BYTES = 16 * 1024 * 1024  # 16 MB
DEFAULT_MAX_WRITE_BYTES = 16 * 1024 * 1024  # 16 MB
DEFAULT_MAX_LIST_ENTRIES = 10_000

# Paths that should never be accessible even within sandbox
BLOCKED_PATTERNS = [
    ".ssh", ".gnupg", ".env", ".git/config",
    "id_rsa", "id_ed25519", ".pem", ".key",
    "shadow", "passwd", ".bashrc", ".profile",
]

# Windows reserved device names
_WIN_DEVICE_NAME_RE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)", re.IGNORECASE
)


class SandboxViolation(Exception):
    """Raised when a path operation would escape the sandbox."""
    pass


class SandboxNotConfigured(Exception):
    """Raised when sandbox root is not set (fail-closed)."""
    pass


class FilesystemModule(BondModule):
    module_id = "filesystem"

    def __init__(
        self,
        sandbox_root: Optional[str] = None,
        max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
        max_write_bytes: int = DEFAULT_MAX_WRITE_BYTES,
        max_list_entries: int = DEFAULT_MAX_LIST_ENTRIES,
        blocked_patterns: Optional[List[str]] = None,
    ):
        # Resolve sandbox root: constructor arg > env var > FAIL CLOSED
        raw_root = sandbox_root or os.environ.get("BOND_SANDBOX_ROOT")
        if raw_root:
            self.sandbox_root = os.path.realpath(raw_root)
        else:
            self.sandbox_root = None  # Will fail-closed on any tool call

        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes
        self.max_list_entries = max_list_entries
        self.blocked_patterns = blocked_patterns or BLOCKED_PATTERNS

    def initialize(self, core):
        self.core = core
        if self.sandbox_root:
            os.makedirs(self.sandbox_root, exist_ok=True)
            logger.info("Filesystem module initialized: sandbox=%s", self.sandbox_root)
        else:
            logger.warning(
                "Filesystem module initialized WITHOUT sandbox root. "
                "All file operations will be REFUSED. "
                "Set BOND_SANDBOX_ROOT env var or pass sandbox_root to constructor."
            )

    def shutdown(self):
        pass

    def _require_sandbox(self) -> str:
        """Return sandbox root or raise if not configured (fail-closed)."""
        if not self.sandbox_root:
            raise SandboxNotConfigured(
                "Sandbox root is not configured. Set BOND_SANDBOX_ROOT environment "
                "variable or pass sandbox_root to FilesystemModule constructor. "
                "File operations are disabled without a sandbox."
            )
        return self.sandbox_root

    def _resolve_safe_path(self, path: str) -> str:
        """Resolve a path and ensure it's within the sandbox."""
        sandbox_root = self._require_sandbox()

        if os.name == "nt":
            if path.startswith("\\\\.\\") or path.startswith("\\\\?\\"):
                raise SandboxViolation("Windows device paths are not allowed")

        if not os.path.isabs(path):
            path = os.path.join(sandbox_root, path)

        resolved = os.path.realpath(path)

        if os.name == "nt" and _WIN_DEVICE_NAME_RE.match(os.path.basename(resolved)):
            raise SandboxViolation("Windows reserved device names are not allowed")

        # Case-insensitive containment check (Windows-safe via normcase)
        sandbox_norm = os.path.normcase(sandbox_root)
        resolved_norm = os.path.normcase(resolved)
        if not resolved_norm.startswith(sandbox_norm + os.sep) and resolved_norm != sandbox_norm:
            logger.warning("Sandbox escape attempt: '%s' resolves outside sandbox", path)
            raise SandboxViolation("Path is outside the sandbox")

        # Block NTFS Alternate Data Streams
        if os.name == "nt" and ":" in os.path.splitdrive(resolved)[1]:
            raise SandboxViolation("Alternate Data Streams are not allowed")

        lower_resolved = resolved.lower()
        for pattern in self.blocked_patterns:
            if pattern.lower() in lower_resolved:
                raise SandboxViolation(f"Path contains blocked pattern '{pattern}'")

        return resolved

    def _verify_fd_in_sandbox(self, fd: int, resolved: str) -> None:
        """Post-open verification: ensure fd actually points inside sandbox."""
        sandbox_root = self._require_sandbox()
        actual = None

        # Windows: GetFinalPathNameByHandleW for authoritative fd→path mapping
        if os.name == "nt":
            actual = win_get_final_path(fd)

        # Linux: /proc/self/fd/{fd}
        if actual is None:
            proc_path = f"/proc/self/fd/{fd}"
            if hasattr(os, "readlink") and os.path.exists(proc_path):
                try:
                    actual = os.readlink(proc_path)
                except OSError:
                    pass

        if actual is None:
            actual = os.path.realpath(resolved)

        actual_norm = os.path.normcase(actual)
        sandbox_norm = os.path.normcase(sandbox_root)
        if not actual_norm.startswith(sandbox_norm + os.sep) and actual_norm != sandbox_norm:
            os.close(fd)
            raise SandboxViolation("TOCTOU detected: fd resolves outside sandbox")

    def register_tools(self):
        return [
            Tool(
                name="read_file",
                description="Reads contents of a file (within sandbox)",
                parameters={
                    "path": {"type": "string", "description": "File path to read (relative to sandbox or absolute within sandbox)"},
                },
                handler=self.read_file,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
                redact_result=True,
            ),
            Tool(
                name="write_file",
                description="Writes content to a file (within sandbox)",
                parameters={
                    "path": {"type": "string", "description": "File path to write"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                handler=self.write_file,
                safety_level=SafetyLevel.MODERATE,
                module_id=self.module_id,
                redact_params=["content"],
            ),
            Tool(
                name="list_directory",
                description="Lists contents of a directory (within sandbox)",
                parameters={
                    "path": {"type": "string", "description": "Directory path"},
                },
                handler=self.list_directory,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
            Tool(
                name="search_files",
                description="Searches for files matching a glob pattern (within sandbox)",
                parameters={
                    "pattern": {"type": "string", "description": "Glob pattern"},
                    "directory": {"type": "string", "description": "Directory to search in"},
                },
                handler=self.search_files,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
            Tool(
                name="file_info",
                description="Gets metadata about a file (size, modified time, type)",
                parameters={
                    "path": {"type": "string", "description": "File path"},
                },
                handler=self.file_info,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
        ]

    def read_file(self, path: str) -> str:
        resolved = self._resolve_safe_path(path)

        if not os.path.isfile(resolved):
            raise FileNotFoundError(f"Not a file: {path}")

        try:
            flags = os.O_RDONLY
            has_nofollow = hasattr(os, "O_NOFOLLOW")
            if has_nofollow:
                flags |= os.O_NOFOLLOW
            fd = os.open(resolved, flags)
            self._verify_fd_in_sandbox(fd, resolved)
            if not has_nofollow and os.path.islink(resolved):
                os.close(fd)
                raise SandboxViolation(f"Refusing to follow symlink: {path}")
            try:
                with os.fdopen(fd, "rb") as f:
                    data = bytearray()
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > self.max_read_bytes:
                            raise ValueError(
                                f"File too large: exceeds {self.max_read_bytes:,} bytes"
                            )
                try:
                    content = data.decode("utf-8")
                except UnicodeDecodeError:
                    raise ValueError(
                        "File appears to be binary. Use a binary-aware tool instead."
                    )
            except ValueError:
                raise
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
        except OSError as e:
            if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                raise SandboxViolation(f"Refusing to follow symlink: {path}")
            raise

        logger.info("read_file: %s (%s bytes)", resolved, f"{len(data):,}")
        return content

    def write_file(self, path: str, content: str) -> dict:
        resolved = self._resolve_safe_path(path)

        content_bytes = len(content.encode("utf-8"))
        if content_bytes > self.max_write_bytes:
            raise ValueError(
                f"Content too large: {content_bytes:,} bytes "
                f"(limit: {self.max_write_bytes:,} bytes)"
            )

        parent = os.path.dirname(resolved)
        os.makedirs(parent, exist_ok=True)

        if os.path.lexists(resolved) and os.path.islink(resolved):
            raise SandboxViolation("Refusing to write to symlink path")

        sandbox_root = self._require_sandbox()
        actual_parent = os.path.realpath(parent)
        parent_norm = os.path.normcase(actual_parent)
        sandbox_norm = os.path.normcase(sandbox_root)
        if not parent_norm.startswith(sandbox_norm + os.sep) and parent_norm != sandbox_norm:
            raise SandboxViolation("Parent directory changed during write (TOCTOU)")

        fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".bond_write_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            if os.path.islink(resolved):
                raise SandboxViolation("Refusing to write to symlink path (race detected)")
            resolved_recheck = os.path.realpath(resolved)
            recheck_norm = os.path.normcase(resolved_recheck)
            if not recheck_norm.startswith(sandbox_norm + os.sep) and recheck_norm != sandbox_norm:
                raise SandboxViolation("Path escaped sandbox during write (race detected)")
            os.replace(tmp_path, resolved_recheck)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        logger.info("write_file: %s (%s bytes)", resolved, f"{content_bytes:,}")
        return {"path": path, "bytes_written": content_bytes}

    def list_directory(self, path: str) -> list:
        resolved = self._resolve_safe_path(path)

        if not os.path.isdir(resolved):
            raise NotADirectoryError(f"Not a directory: {path}")

        sandbox_root = self._require_sandbox()
        actual_dir = os.path.realpath(resolved)
        dir_norm = os.path.normcase(actual_dir)
        sandbox_norm = os.path.normcase(sandbox_root)
        if not dir_norm.startswith(sandbox_norm + os.sep) and dir_norm != sandbox_norm:
            raise SandboxViolation("Directory changed during list (TOCTOU)")

        entries = []
        for i, entry in enumerate(os.scandir(resolved)):
            if i >= self.max_list_entries:
                entries.append(f"... truncated at {self.max_list_entries} entries")
                break
            try:
                entry_real = os.path.realpath(entry.path)
                entry_norm = os.path.normcase(entry_real)
                if not entry_norm.startswith(sandbox_norm + os.sep) and entry_norm != sandbox_norm:
                    continue
            except OSError:
                continue
            if entry.is_symlink():
                entry_type = "symlink"
            else:
                entry_type = "dir" if entry.is_dir(follow_symlinks=False) else "file"
            entries.append({"name": entry.name, "type": entry_type})

        logger.info("list_directory: %s (%d entries)", resolved, len(entries))
        return entries

    def search_files(self, pattern: str, directory: str) -> list:
        resolved_dir = self._resolve_safe_path(directory)

        if not os.path.isdir(resolved_dir):
            raise NotADirectoryError(f"Not a directory: {directory}")

        if "**" in pattern:
            raise ValueError("Recursive glob '**' is disabled for safety")
        if pattern.count("/") + pattern.count("\\") > 3:
            raise ValueError("Glob pattern exceeds maximum directory depth of 3")
        if (os.path.isabs(pattern)
                or (len(pattern) >= 2 and pattern[1] == ':')
                or pattern.startswith("//") or pattern.startswith("\\\\")):
            raise ValueError("Glob pattern must be relative, not absolute")
        pattern_parts = pattern.replace("\\", "/").split("/")
        if ".." in pattern_parts:
            raise ValueError("Glob pattern must not contain '..' components")

        sandbox_root = self._require_sandbox()
        full_pattern = os.path.join(resolved_dir, pattern)
        sandbox_norm = os.path.normcase(sandbox_root)
        safe_results = []
        for r in globmod.iglob(full_pattern):
            real_r = os.path.realpath(r)
            real_r_norm = os.path.normcase(real_r)
            if real_r_norm.startswith(sandbox_norm + os.sep) or real_r_norm == sandbox_norm:
                try:
                    rel = os.path.relpath(real_r, sandbox_root)
                    safe_results.append(rel)
                except ValueError:
                    logger.warning("search_files: skipping result with unrelativizable path")
                    continue

            if len(safe_results) >= self.max_list_entries:
                safe_results.append(f"... truncated at {self.max_list_entries}")
                break

        logger.info("search_files: %s in %s (%d matches)", pattern, resolved_dir, len(safe_results))
        return safe_results

    def file_info(self, path: str) -> dict:
        resolved = self._resolve_safe_path(path)

        if not os.path.exists(resolved):
            raise FileNotFoundError(f"Path not found: {path}")

        # Use lstat exclusively to avoid following symlinks for all checks
        stat_result = os.lstat(resolved)
        is_link = os.path.islink(resolved)
        import stat as stat_mod
        is_file = not is_link and stat_mod.S_ISREG(stat_result.st_mode)
        is_dir = not is_link and stat_mod.S_ISDIR(stat_result.st_mode)
        return {
            "path": path,
            "exists": True,
            "is_file": is_file,
            "is_dir": is_dir,
            "is_symlink": is_link,
            "size_bytes": stat_result.st_size,
            "modified": stat_result.st_mtime,
            "created": stat_result.st_ctime,
        }
