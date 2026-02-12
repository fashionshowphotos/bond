"""Bond MCP Server — Filesystem Module (Hardened)

Changes from original:
- CRITICAL: Sandbox root enforcement — all paths resolved and checked
- Symlink escape prevention
- File read size limits (prevent OOM)
- File write size limits (prevent disk fill)
- Path traversal protection (../../ blocked)
- Binary file detection
- Atomic writes (write to temp then rename)
- Blocked path patterns (e.g., .ssh, .env, secrets)
"""

from __future__ import annotations
import os
import re
import glob as globmod
import tempfile
import logging
from typing import List, Optional

from core.module_loader import BondModule
from models.models import Tool, SafetyLevel

logger = logging.getLogger("bond.filesystem")

# Defaults
DEFAULT_SANDBOX_ROOT = os.path.expanduser("~/bond-workspace")
DEFAULT_MAX_READ_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_WRITE_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_LIST_ENTRIES = 10_000

# Paths that should never be accessible even within sandbox
BLOCKED_PATTERNS = [
    ".ssh", ".gnupg", ".env", ".git/config",
    "id_rsa", "id_ed25519", ".pem", ".key",
    "shadow", "passwd", ".bashrc", ".profile",
]

# Windows reserved device names — can cause hangs (CON) or unexpected I/O (COM/LPT)
_WIN_DEVICE_NAME_RE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)", re.IGNORECASE
)


class SandboxViolation(Exception):
    """Raised when a path operation would escape the sandbox."""
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
        self.sandbox_root = os.path.realpath(sandbox_root or DEFAULT_SANDBOX_ROOT)
        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes
        self.max_list_entries = max_list_entries
        self.blocked_patterns = blocked_patterns or BLOCKED_PATTERNS

    def initialize(self, core):
        self.core = core
        os.makedirs(self.sandbox_root, exist_ok=True)
        logger.info(f"Filesystem module initialized: sandbox={self.sandbox_root}")

    def shutdown(self):
        pass

    def _resolve_safe_path(self, path: str) -> str:
        """Resolve a path and ensure it's within the sandbox.

        Defence layers:
        1. Resolve relative paths against sandbox root
        2. Normalize with realpath (follows symlinks, resolves ..)
        3. Verify resolved path starts with sandbox root
        4. Check against blocked patterns
        """
        # Block Windows device paths (\\.\, \\?\) before any resolution
        if os.name == "nt":
            if path.startswith("\\\\.\\") or path.startswith("\\\\?\\"):
                raise SandboxViolation("Windows device paths are not allowed")

        # If relative, resolve against sandbox
        if not os.path.isabs(path):
            path = os.path.join(self.sandbox_root, path)

        # Resolve to real path (follows symlinks, normalizes)
        resolved = os.path.realpath(path)

        # Block Windows reserved device names (CON, PRN, NUL, COM1-9, LPT1-9)
        # These can cause hangs or unexpected I/O even inside the sandbox
        if os.name == "nt" and _WIN_DEVICE_NAME_RE.match(os.path.basename(resolved)):
            raise SandboxViolation("Windows reserved device names are not allowed")

        # Sandbox check (case-insensitive on Windows via normcase)
        sandbox_norm = os.path.normcase(self.sandbox_root)
        resolved_norm = os.path.normcase(resolved)
        if not resolved_norm.startswith(sandbox_norm + os.sep) and resolved_norm != sandbox_norm:
            logger.warning(
                f"Sandbox escape attempt: '{path}' resolves to '{resolved}' "
                f"outside sandbox '{self.sandbox_root}'"
            )
            raise SandboxViolation("Path is outside the sandbox")

        # Block NTFS Alternate Data Streams (Windows)
        if os.name == "nt" and ":" in os.path.splitdrive(resolved)[1]:
            raise SandboxViolation("Alternate Data Streams are not allowed")

        # Blocked pattern check
        lower_resolved = resolved.lower()
        for pattern in self.blocked_patterns:
            if pattern.lower() in lower_resolved:
                raise SandboxViolation(
                    f"Path contains blocked pattern '{pattern}'"
                )

        return resolved

    def _verify_fd_in_sandbox(self, fd: int, resolved: str) -> None:
        """Post-open verification: ensure fd actually points inside sandbox.

        Catches intermediate-directory symlink TOCTOU where O_NOFOLLOW
        only protects the final path component.
        On Linux, uses /proc/self/fd/{fd} for authoritative check.
        On other platforms, re-resolves the path as a weaker fallback.
        """
        actual = None
        proc_path = f"/proc/self/fd/{fd}"
        if hasattr(os, "readlink") and os.path.exists(proc_path):
            try:
                actual = os.readlink(proc_path)
            except OSError:
                pass

        if actual is None:
            # Fallback: re-resolve and compare (narrows TOCTOU window)
            actual = os.path.realpath(resolved)

        actual_norm = os.path.normcase(actual)
        sandbox_norm = os.path.normcase(self.sandbox_root)
        if not actual_norm.startswith(sandbox_norm + os.sep) and actual_norm != sandbox_norm:
            os.close(fd)
            raise SandboxViolation(
                f"TOCTOU detected: fd resolves outside sandbox"
            )

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
                redact_result=True,  # file contents should not appear in full in logs
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
                redact_params=["content"],  # don't log full content
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

        # Open with O_NOFOLLOW where available (TOCTOU mitigation)
        # On Windows (no O_NOFOLLOW), re-check realpath after open to detect symlink swap
        # Chunked read with hard cap to prevent OOM even if file grows after open
        try:
            flags = os.O_RDONLY
            has_nofollow = hasattr(os, "O_NOFOLLOW")
            if has_nofollow:
                flags |= os.O_NOFOLLOW
            fd = os.open(resolved, flags)
            # Verify fd actually points inside sandbox (catches intermediate symlink TOCTOU)
            self._verify_fd_in_sandbox(fd, resolved)
            # Windows TOCTOU mitigation: re-verify path hasn't become a symlink
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
            if "symbolic link" in str(e).lower() or e.errno == 40:  # ELOOP
                raise SandboxViolation(f"Refusing to follow symlink: {path}")
            raise

        logger.info(f"read_file: {resolved} ({len(data):,} bytes)")
        return content

    def write_file(self, path: str, content: str) -> dict:
        resolved = self._resolve_safe_path(path)

        content_bytes = len(content.encode("utf-8"))
        if content_bytes > self.max_write_bytes:
            raise ValueError(
                f"Content too large: {content_bytes:,} bytes "
                f"(limit: {self.max_write_bytes:,} bytes)"
            )

        # Ensure parent directory exists
        parent = os.path.dirname(resolved)
        os.makedirs(parent, exist_ok=True)

        # Refuse to overwrite symlink targets (prevents link-swap attacks)
        if os.path.lexists(resolved) and os.path.islink(resolved):
            raise SandboxViolation("Refusing to write to symlink path")

        # Re-verify parent is still inside sandbox (intermediate symlink TOCTOU)
        actual_parent = os.path.realpath(parent)
        parent_norm = os.path.normcase(actual_parent)
        sandbox_norm = os.path.normcase(self.sandbox_root)
        if not parent_norm.startswith(sandbox_norm + os.sep) and parent_norm != sandbox_norm:
            raise SandboxViolation("Parent directory changed during write (TOCTOU)")

        # Atomic write: write to temp file then rename
        fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".bond_write_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            # Re-check symlink right before replace (TOCTOU mitigation)
            # Note: os.replace on Linux actually replaces the symlink directory entry
            # itself (not the target), but we still block it to prevent confusion
            if os.path.islink(resolved):
                raise SandboxViolation("Refusing to write to symlink path (race detected)")
            os.replace(tmp_path, resolved)
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        logger.info(f"write_file: {resolved} ({content_bytes:,} bytes)")
        return {"path": path, "bytes_written": content_bytes}

    def list_directory(self, path: str) -> list:
        resolved = self._resolve_safe_path(path)

        if not os.path.isdir(resolved):
            raise NotADirectoryError(f"Not a directory: {path}")

        # Re-verify directory hasn't been swapped (intermediate symlink TOCTOU)
        actual_dir = os.path.realpath(resolved)
        dir_norm = os.path.normcase(actual_dir)
        sandbox_norm = os.path.normcase(self.sandbox_root)
        if not dir_norm.startswith(sandbox_norm + os.sep) and dir_norm != sandbox_norm:
            raise SandboxViolation("Directory changed during list (TOCTOU)")

        entries = []
        for i, entry in enumerate(os.scandir(resolved)):
            if i >= self.max_list_entries:
                entries.append(f"... truncated at {self.max_list_entries} entries")
                break
            # Re-verify each entry's real path is inside sandbox
            try:
                entry_real = os.path.realpath(entry.path)
                entry_norm = os.path.normcase(entry_real)
                if not entry_norm.startswith(sandbox_norm + os.sep) and entry_norm != sandbox_norm:
                    continue  # skip escaped entry silently
            except OSError:
                continue
            if entry.is_symlink():
                entry_type = "symlink"
            else:
                entry_type = "dir" if entry.is_dir(follow_symlinks=False) else "file"
            entries.append({"name": entry.name, "type": entry_type})

        logger.info(f"list_directory: {resolved} ({len(entries)} entries)")
        return entries

    def search_files(self, pattern: str, directory: str) -> list:
        resolved_dir = self._resolve_safe_path(directory)

        if not os.path.isdir(resolved_dir):
            raise NotADirectoryError(f"Not a directory: {directory}")

        # Block recursive glob and deep nesting to prevent DoS via directory traversal
        if "**" in pattern:
            raise ValueError("Recursive glob '**' is disabled for safety")
        # Limit directory depth in pattern (e.g. */*/*/*/* is depth 5 — cap at 3)
        if pattern.count("/") + pattern.count("\\") > 3:
            raise ValueError("Glob pattern exceeds maximum directory depth of 3")
        # Block absolute paths, drive letters, and UNC paths in pattern
        if (os.path.isabs(pattern)
                or (len(pattern) >= 2 and pattern[1] == ':')
                or pattern.startswith("//") or pattern.startswith("\\\\")):
            raise ValueError("Glob pattern must be relative, not absolute")

        # Block parent directory traversal in glob patterns
        pattern_parts = pattern.replace("\\", "/").split("/")
        if ".." in pattern_parts:
            raise ValueError("Glob pattern must not contain '..' components")

        full_pattern = os.path.join(resolved_dir, pattern)

        # Use iglob to avoid building full list in memory (prevents DoS)
        sandbox_norm = os.path.normcase(self.sandbox_root)
        safe_results = []
        for r in globmod.iglob(full_pattern):
            real_r = os.path.realpath(r)
            real_r_norm = os.path.normcase(real_r)
            if real_r_norm.startswith(sandbox_norm + os.sep) or real_r_norm == sandbox_norm:
                try:
                    rel = os.path.relpath(real_r, self.sandbox_root)
                    safe_results.append(rel)
                except ValueError:
                    # relpath failed (cross-drive on Windows) — skip rather than
                    # exposing the absolute path to the client
                    logger.warning("search_files: skipping result with unrelativizable path")
                    continue

            if len(safe_results) >= self.max_list_entries:
                safe_results.append(f"... truncated at {self.max_list_entries}")
                break

        logger.info(f"search_files: {pattern} in {resolved_dir} ({len(safe_results)} matches)")
        return safe_results

    def file_info(self, path: str) -> dict:
        resolved = self._resolve_safe_path(path)

        if not os.path.exists(resolved):
            raise FileNotFoundError(f"Path not found: {path}")

        # Use lstat to avoid following final-component symlinks (prevents metadata leak)
        stat = os.lstat(resolved)
        is_link = os.path.islink(resolved)
        return {
            "path": path,
            "exists": True,
            "is_file": not is_link and os.path.isfile(resolved),
            "is_dir": not is_link and os.path.isdir(resolved),
            "is_symlink": is_link,
            "size_bytes": stat.st_size,
            "modified": stat.st_mtime,
            "created": stat.st_ctime,
        }
