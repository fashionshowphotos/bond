"""
Bond Module: Orchestrator (formerly Antigravity)

Task orchestration with status tracking and audit ledger.

Security properties:
- Configurable data root (fail-closed: no data root = no file ops)
- Path containment: all file I/O verified within data root
- Symlink-aware: refuses to write through symlinks
- Sanitized error messages (no internal path leakage)
- Size caps on reads/writes
- TOCTOU protection via O_NOFOLLOW + fd verification

Tools (4):
  get_status     — Read current orchestrator status
  update_status  — Update runtime status snapshot
  append_ledger  — Append entry to audit ledger (JSONL)
  read_ledger    — Read recent ledger entries
"""

import os
import json
import time
import logging
from collections import deque
from typing import Optional

from core.module_loader import BondModule
from core.fs_utils import win_get_final_path
from models.models import Tool, SafetyLevel

logger = logging.getLogger("bond.orchestrator")

# Safety limits
MAX_LEDGER_READ_BYTES = 10 * 1024 * 1024   # 10 MB
MAX_LEDGER_LINES_CAP = 1000
MAX_LEDGER_ENTRY_BYTES = 64 * 1024          # 64 KB per ledger entry
MAX_LEDGER_FILE_BYTES = 100 * 1024 * 1024   # 100 MB ledger file cap
MAX_STATUS_SUMMARY_LEN = 4096


class OrchestratorModule(BondModule):
    module_id = "orchestrator"

    def __init__(
        self,
        data_root: Optional[str] = None,
    ):
        # Resolve data root: constructor arg > env vars > sandbox subdir > FAIL CLOSED
        raw_root = (
            data_root
            or os.environ.get("ORCHESTRATOR_DATA_ROOT")
            or os.environ.get("ANTIGRAVITY_DATA_ROOT")  # backward compat
            or self._derive_from_sandbox()
        )
        if raw_root:
            self.data_root = os.path.realpath(raw_root)
            # Pin data_root identity by inode/device to detect symlink swaps.
            # If the directory doesn't exist yet, pinning happens in initialize().
            self._data_root_identity: Optional[tuple] = None
            if os.path.isdir(self.data_root):
                st = os.stat(self.data_root)
                self._data_root_identity = (st.st_dev, st.st_ino)
        else:
            self.data_root = None  # Will fail-closed on any file operation
            self._data_root_identity = None

    @staticmethod
    def _derive_from_sandbox() -> Optional[str]:
        """Try to derive data root from Bond sandbox root."""
        sandbox = os.environ.get("BOND_SANDBOX_ROOT")
        if sandbox:
            return os.path.join(sandbox, "orchestrator_state")
        return None

    def _verify_data_root_identity(self):
        """Verify data_root hasn't been replaced by a symlink since init."""
        if self.data_root and self._data_root_identity:
            try:
                st = os.stat(self.data_root)
                current = (st.st_dev, st.st_ino)
                if current != self._data_root_identity:
                    raise ValueError(
                        "data_root identity changed (possible symlink swap): "
                        f"expected {self._data_root_identity}, got {current}"
                    )
            except FileNotFoundError:
                raise ValueError("data_root no longer exists")

    def initialize(self, core):
        self.core = core
        if self.data_root:
            # mode=0o750: owner rwx, group rx, others none (audit data protection)
            os.makedirs(os.path.dirname(self._runtime_file), mode=0o750, exist_ok=True)
            os.makedirs(os.path.dirname(self._ledger_file), mode=0o750, exist_ok=True)
            # Pin data_root identity after creation if not already pinned
            if self._data_root_identity is None:
                st = os.stat(self.data_root)
                self._data_root_identity = (st.st_dev, st.st_ino)
            logger.info("Orchestrator module initialized: data_root=%r", self.data_root)
        else:
            logger.warning(
                "Orchestrator module initialized WITHOUT data root. "
                "All file operations will be REFUSED. "
                "Set ORCHESTRATOR_DATA_ROOT or BOND_SANDBOX_ROOT env var."
            )

    def shutdown(self):
        pass

    # -- Derived Paths -------------------------------------------------------

    @property
    def _runtime_file(self) -> str:
        return os.path.join(self._require_data_root(), "runtime.json")

    @property
    def _ledger_file(self) -> str:
        return os.path.join(self._require_data_root(), "ledger.jsonl")

    # -- Safety Helpers -------------------------------------------------------

    def _require_data_root(self) -> str:
        """Return data root or raise if not configured (fail-closed).

        Also verifies the data root hasn't been replaced by a symlink
        since initialization (inode/device identity check).
        """
        if not self.data_root:
            raise RuntimeError(
                "Orchestrator data root is not configured. "
                "Set ORCHESTRATOR_DATA_ROOT or BOND_SANDBOX_ROOT environment variable. "
                "File operations are disabled without a data root."
            )
        self._verify_data_root_identity()
        return self.data_root

    def _verify_within(self, path: str, container: str) -> str:
        """Resolve path and verify it stays within container directory.

        Returns the resolved (real) path. Raises ValueError if containment
        is violated. Uses normcase for Windows case-insensitive comparison.
        Also checks the original (unresolved) path for symlinks — realpath
        silently resolves symlinks, which could mask a symlink-based attack.
        """
        # Check original path for symlinks BEFORE realpath strips them
        if os.path.islink(path):
            logger.warning("Path containment: symlink detected at original path %r", path)
            raise ValueError("Refusing to follow symlink")

        resolved = os.path.realpath(path)
        container_real = os.path.realpath(container)
        # Use commonpath + normcase for robust containment (handles Windows
        # case-insensitivity, UNC paths, Unicode equivalence — matches the
        # pattern used in models.py and plugin_bridge.py)
        r_norm = os.path.normcase(resolved)
        c_norm = os.path.normcase(container_real)
        try:
            common = os.path.commonpath([r_norm, c_norm])
        except ValueError:
            # Different drives on Windows, or path error
            logger.warning("Path containment violation: resolved %r escapes container", path)
            raise ValueError("Path is outside the allowed directory")
        if common != c_norm:
            logger.warning("Path containment violation: resolved %r escapes container", path)
            raise ValueError("Path is outside the allowed directory")
        return resolved

    def _verify_fd_in_container(self, fd: int, container: str,
                               symlink_protected: bool = True) -> None:
        """Post-open verification: ensure fd actually points inside container.

        Uses GetFinalPathNameByHandleW on Windows, /proc/self/fd on Linux,
        fcntl.F_GETPATH on macOS. Closes fd and raises on violation.

        If symlink_protected is False (O_NOFOLLOW unavailable) AND fd
        verification is also unavailable, raises instead of silently
        returning — fail-closed when no symlink protection exists.
        """
        actual = None

        if os.name == "nt":
            actual = win_get_final_path(fd)

        if actual is None:
            proc_path = f"/proc/self/fd/{fd}"
            if hasattr(os, "readlink") and os.path.exists(proc_path):
                try:
                    actual = os.readlink(proc_path)
                except OSError:
                    pass

        # macOS: use fcntl.F_GETPATH to get filesystem path from open fd
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
            if not symlink_protected:
                # No O_NOFOLLOW AND no fd verification — zero symlink
                # protection.  Fail closed rather than silently proceeding.
                os.close(fd)
                raise ValueError(
                    "fd verification unavailable and O_NOFOLLOW not supported — "
                    "refusing to proceed without symlink protection"
                )
            logger.debug(
                "fd verification unavailable on this platform — relying on O_NOFOLLOW"
            )
            return  # O_NOFOLLOW provides symlink protection; fd check is belt-and-suspenders

        actual_norm = os.path.normcase(actual)
        container_norm = os.path.normcase(os.path.realpath(container))
        if not actual_norm.startswith(container_norm + os.sep) and actual_norm != container_norm:
            os.close(fd)
            raise ValueError("TOCTOU detected: fd resolves outside container")

    # Default read cap when max_bytes is 0 / unspecified (10 MB).
    # Prevents unbounded memory allocation from a corrupted or malicious file.
    _DEFAULT_READ_CAP = 10 * 1024 * 1024

    def _safe_read_file(self, path: str, container: str, max_bytes: int = 0) -> str:
        """Open a file for reading with TOCTOU protection.

        Uses O_NOFOLLOW where available, verifies fd resolves inside container.
        Returns file content as string.

        If max_bytes is 0 or negative, applies _DEFAULT_READ_CAP (10 MB)
        to prevent unbounded reads.
        """
        self._verify_data_root_identity()
        if max_bytes <= 0:
            max_bytes = self._DEFAULT_READ_CAP

        resolved = self._verify_within(path, container)

        flags = os.O_RDONLY
        has_nofollow = hasattr(os, "O_NOFOLLOW")
        if has_nofollow:
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(resolved, flags)
        except OSError as e:
            if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                raise ValueError("Refusing to follow symlink")
            raise

        fd_owned = True  # Track whether we still own the fd
        try:
            self._verify_fd_in_container(fd, container, symlink_protected=has_nofollow)
            # Reject non-regular files (FIFO, device nodes) and hardlinks
            import stat as _stat_mod
            fd_stat = os.fstat(fd)
            if not _stat_mod.S_ISREG(fd_stat.st_mode):
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to read non-regular file (FIFO/device)")
            if fd_stat.st_nlink > 1:
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to read hard-linked file (nlink > 1)")
            if not has_nofollow and os.path.islink(path):
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to follow symlink")
            with os.fdopen(fd, "rb") as f:
                fd_owned = False  # os.fdopen took ownership
                # Read in binary mode and enforce BYTE cap (text mode
                # .read(n) reads n CHARS, not bytes — multibyte UTF-8
                # could read up to 4x more bytes than intended)
                raw = f.read(max_bytes)
                return raw.decode("utf-8", errors="replace")
        except Exception:
            if fd_owned:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def _safe_read_file_binary(
        self, path: str, container: str, seek_offset: int = 0,
        max_bytes: int = 0,
    ) -> bytes:
        """Open a file for binary reading with TOCTOU protection.

        If max_bytes is 0 or negative, applies _DEFAULT_READ_CAP to prevent
        unbounded memory allocation from corrupted or malicious files.
        """
        self._verify_data_root_identity()
        if max_bytes <= 0:
            max_bytes = self._DEFAULT_READ_CAP

        resolved = self._verify_within(path, container)

        flags = os.O_RDONLY
        has_nofollow = hasattr(os, "O_NOFOLLOW")
        if has_nofollow:
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(resolved, flags)
        except OSError as e:
            if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                raise ValueError("Refusing to follow symlink")
            raise

        fd_owned = True
        try:
            self._verify_fd_in_container(fd, container, symlink_protected=has_nofollow)
            # Reject non-regular files (FIFO, device nodes) and hardlinks
            import stat as _stat_mod
            fd_stat = os.fstat(fd)
            if not _stat_mod.S_ISREG(fd_stat.st_mode):
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to read non-regular file (FIFO/device)")
            if fd_stat.st_nlink > 1:
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to read hard-linked file (nlink > 1)")
            if not has_nofollow and os.path.islink(path):
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to follow symlink")
            with os.fdopen(fd, "rb") as f:
                fd_owned = False  # os.fdopen took ownership
                if seek_offset > 0:
                    f.seek(seek_offset)
                return f.read(max_bytes)
        except Exception:
            if fd_owned:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def _safe_write_file(self, path: str, container: str, content: str) -> None:
        """Atomic write with TOCTOU protection (temp+replace).

        Symlink defense: the target path is opened with O_NOFOLLOW (where
        available) AFTER the temp file is written, so we verify it's a
        regular file at the exact moment of replacement — not earlier.
        """
        self._verify_data_root_identity()
        import tempfile
        resolved = self._verify_within(path, container)

        if os.path.lexists(resolved) and os.path.islink(resolved):
            raise ValueError("Refusing to write to symlink")

        parent = os.path.dirname(resolved)

        # Verify parent directory is within container (defense against
        # parent-dir symlink attacks)
        self._verify_within(parent, container)

        # Preserve original file permissions if it exists (mkstemp defaults to 0o600)
        # Also check for hard links (nlink > 1) — os.replace on a hard-linked
        # target only replaces the directory entry, but the old inode persists
        # via other links, so this is a write-through risk.
        # Use lstat (not stat) to detect symlinks at this point too.
        original_mode = None
        if os.path.lexists(resolved):
            try:
                lst = os.lstat(resolved)
                if os.path.islink(resolved):
                    raise ValueError("Refusing to write to symlink")
                original_mode = lst.st_mode
                if lst.st_nlink > 1:
                    raise ValueError("Refusing to replace hard-linked file (nlink > 1)")
            except OSError:
                pass

        fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".orch_write_")
        try:
            if original_mode is not None:
                os.fchmod(fd, original_mode) if hasattr(os, 'fchmod') else os.chmod(tmp_path, original_mode)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            # Re-verify immediately before replace: use lstat to catch
            # symlinks that appeared during the write (race window defense).
            # This is the critical TOCTOU close — we check the exact path
            # that os.replace will target.
            if os.path.lexists(resolved):
                final_lstat = os.lstat(resolved)
                if os.path.islink(resolved):
                    raise ValueError("Symlink appeared during write (race)")
                if final_lstat.st_nlink > 1:
                    raise ValueError("Hard link appeared during write (race)")
            self._verify_within(resolved, container)
            os.replace(tmp_path, resolved)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _safe_append_file(
        self, path: str, container: str, line: str,
        max_file_bytes: int = 0,
    ) -> None:
        """Append a line with TOCTOU protection (O_NOFOLLOW + fd verify + advisory lock + hard-link check).

        If max_file_bytes > 0, the file size is checked AFTER acquiring the
        advisory lock (using fstat on the open fd) so concurrent appenders
        cannot all pass the check simultaneously.
        """
        self._verify_data_root_identity()
        resolved = self._verify_within(path, container)

        if os.path.lexists(resolved) and os.path.islink(resolved):
            raise ValueError("Refusing to append to symlink")

        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        has_nofollow = hasattr(os, "O_NOFOLLOW")
        if has_nofollow:
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(resolved, flags, 0o644)
        except OSError as e:
            if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                raise ValueError("Refusing to follow symlink")
            raise

        fd_owned = True  # Track whether we still own the fd
        try:
            self._verify_fd_in_container(fd, container, symlink_protected=has_nofollow)
            # Reject non-regular files (FIFO, device nodes) and hard links
            import stat as _stat_mod
            fd_stat = os.fstat(fd)
            if not _stat_mod.S_ISREG(fd_stat.st_mode):
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to append to non-regular file (FIFO/device)")
            if fd_stat.st_nlink > 1:
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to write to hard-linked file (nlink > 1)")
            if not has_nofollow and os.path.islink(resolved):
                os.close(fd)
                fd_owned = False
                raise ValueError("Refusing to follow symlink")
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                fd_owned = False  # os.fdopen took ownership
                # Advisory lock to prevent interleaved appends from concurrent processes.
                # Fail-closed: if lock cannot be acquired, reject the append.
                # This prevents concurrent appenders from bypassing the size cap.
                locked = self._advisory_lock(f)
                if not locked:
                    raise ValueError(
                        "Could not acquire advisory lock for append — "
                        "another process holds the lock. Retry later."
                    )
                try:
                    # Size check INSIDE lock: fstat on open fd is atomic and
                    # serialized by the advisory lock, closing the TOCTOU gap
                    # where concurrent appenders all pass an external size check.
                    if max_file_bytes > 0:
                        current_size = os.fstat(f.fileno()).st_size
                        if current_size >= max_file_bytes:
                            raise ValueError(
                                f"File too large ({current_size:,} bytes, "
                                f"limit {max_file_bytes:,}). "
                                f"Archive or truncate before appending."
                            )
                    f.write(line)
                finally:
                    self._advisory_unlock(f)
        except Exception:
            if fd_owned:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    # Lock region size for Windows advisory locking.
    # msvcrt.locking locks a byte range — 1 byte is useless for mutual exclusion.
    # Use 1 MB sentinel region at offset 0 so concurrent writers always contend
    # on the same range regardless of file size.
    _LOCK_REGION_SIZE = 1024 * 1024

    @staticmethod
    def _advisory_lock(f) -> bool:
        """Acquire advisory write lock (non-blocking, best-effort).

        Returns True if lock acquired, False otherwise.
        Both platforms use non-blocking mode for consistent behavior.
        """
        try:
            if os.name == 'nt':
                import msvcrt
                # Seek to offset 0 to lock a consistent region.
                # NOTE: file was opened with O_APPEND, so these seeks only affect
                # the locking operation — O_APPEND means the OS atomically seeks
                # to EOF before each write regardless of file position. Even if
                # an exception occurs between seek(0) and seek(pos), subsequent
                # writes still append correctly. This is safe.
                pos = f.tell()
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, OrchestratorModule._LOCK_REGION_SIZE)
                f.seek(pos)
                return True
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
        except (ImportError, OSError) as e:
            logger.warning("Advisory lock failed (best-effort): %s", e)
            return False

    @staticmethod
    def _advisory_unlock(f) -> None:
        """Release advisory write lock."""
        try:
            if os.name == 'nt':
                import msvcrt
                pos = f.tell()
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, OrchestratorModule._LOCK_REGION_SIZE)
                f.seek(pos)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):
            pass

    # -- Tool Registration ----------------------------------------------------

    def register_tools(self):
        return [
            Tool(
                name="get_status",
                description="Get current task orchestrator status (mode, active jobs, last update).",
                parameters={},
                handler=self.get_status,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
            Tool(
                name="update_status",
                description="Update the runtime status snapshot (mode, summary, active job).",
                parameters={
                    "mode": {
                        "type": "string",
                        "description": "Current mode: IDLE, RUNNING, WAITING, ERROR",
                    },
                    "summary": {
                        "type": "string",
                        "description": "Short text summary of current state",
                    },
                    "job_id": {
                        "type": "string",
                        "description": "Current job ID if running (optional)",
                        "optional": True,
                    },
                },
                handler=self.update_status,
                safety_level=SafetyLevel.MODERATE,
                module_id=self.module_id,
            ),
            Tool(
                name="append_ledger",
                description="Append an entry to the job ledger (JSONL audit trail).",
                parameters={
                    "entry": {
                        "type": "object",
                        "description": "JSON object to append (type, jobId, details, etc.)",
                    }
                },
                handler=self.append_ledger,
                safety_level=SafetyLevel.MODERATE,
                module_id=self.module_id,
            ),
            Tool(
                name="read_ledger",
                description="Read recent entries from the job ledger.",
                parameters={
                    "lines": {
                        "type": "integer",
                        "description": "Number of recent entries to return (default: 20, max: 1000)",
                        "optional": True,
                    }
                },
                handler=self.read_ledger,
                safety_level=SafetyLevel.SAFE,
                module_id=self.module_id,
            ),
        ]

    # -- Runtime Status -------------------------------------------------------

    def get_status(self):
        runtime_file = self._runtime_file
        data_root = self._require_data_root()

        if not os.path.exists(runtime_file):
            return {"mode": "UNKNOWN", "summary": "No runtime snapshot found"}

        try:
            content = self._safe_read_file(runtime_file, data_root)
            return json.loads(content)
        except ValueError as e:
            logger.warning("Runtime status read blocked: %s", e)
            return {"mode": "ERROR", "summary": "Runtime file access denied"}
        except Exception:
            logger.error("Failed to read runtime status", exc_info=True)
            return {"mode": "ERROR", "summary": "Failed to read runtime status"}

    def update_status(self, mode="IDLE", summary="", job_id=None):
        data_root = self._require_data_root()
        runtime_file = self._runtime_file

        # Input validation
        if not isinstance(mode, str) or mode not in ("IDLE", "RUNNING", "WAITING", "ERROR"):
            raise ValueError("mode must be one of: IDLE, RUNNING, WAITING, ERROR")
        if not isinstance(summary, str):
            raise ValueError("summary must be a string")
        if job_id is not None and not isinstance(job_id, str):
            raise ValueError("job_id must be a string or null")
        if isinstance(job_id, str) and len(job_id) > 256:
            raise ValueError("job_id too long (max 256 characters)")
        summary = summary[:MAX_STATUS_SUMMARY_LEN]

        snapshot = {
            "mode": mode,
            "summary": summary,
            "job_id": job_id,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ts": int(time.time() * 1000),
            "pid": os.getpid(),
        }

        # Atomic write with symlink + containment protection
        try:
            self._safe_write_file(runtime_file, data_root, json.dumps(snapshot, indent=2))
        except OSError as e:
            logger.error("Status update failed: %s", e)
            raise ValueError("Failed to write runtime status") from None
        return snapshot

    # -- Ledger ---------------------------------------------------------------

    # Max total elements (keys + values + list items) before bailing.
    # Prevents breadth-based DoS: a flat dict with 100K keys is depth-1
    # but still causes O(N) traversal and a huge serialization.
    _MAX_ESTIMATE_ELEMENTS = 10_000

    @staticmethod
    def _estimate_json_size(
        obj, depth: int = 0, _max_depth: int = 20,
        _counter: Optional[list] = None,
    ) -> int:
        """Estimate serialized JSON size without full serialization.

        Walks the structure up to _max_depth. Returns approximate byte count.
        Raises ValueError if depth or element count is excessive.
        _counter is a mutable single-element list [count] shared across the
        recursive traversal for global element counting.
        """
        if _counter is None:
            _counter = [0]
        if depth > _max_depth:
            raise ValueError("Ledger entry too deeply nested (max depth 20)")
        _counter[0] += 1
        if _counter[0] > OrchestratorModule._MAX_ESTIMATE_ELEMENTS:
            raise ValueError(
                f"Ledger entry too many elements (>{OrchestratorModule._MAX_ESTIMATE_ELEMENTS})"
            )
        if isinstance(obj, dict):
            total = 2  # {}
            for k, v in obj.items():
                _counter[0] += 1
                if _counter[0] > OrchestratorModule._MAX_ESTIMATE_ELEMENTS:
                    raise ValueError(
                        f"Ledger entry too many elements (>{OrchestratorModule._MAX_ESTIMATE_ELEMENTS})"
                    )
                total += len(str(k)) + 4  # key + quotes + colon + comma
                total += OrchestratorModule._estimate_json_size(v, depth + 1, _max_depth, _counter)
            return total
        if isinstance(obj, (list, tuple)):
            total = 2  # []
            for item in obj:
                total += OrchestratorModule._estimate_json_size(item, depth + 1, _max_depth, _counter) + 1
            return total
        if isinstance(obj, str):
            return len(obj) + 2  # quotes
        if isinstance(obj, bool):
            return 5  # "false"
        if isinstance(obj, (int, float)):
            return 20  # conservative
        if obj is None:
            return 4  # "null"
        return len(str(obj)) + 2

    def append_ledger(self, entry):
        if not isinstance(entry, dict):
            raise ValueError("entry must be a JSON object")
        data_root = self._require_data_root()
        ledger_file = self._ledger_file

        # Pre-serialization size/depth check — prevents json.dumps from
        # allocating unbounded memory on huge/deep attacker-controlled input
        try:
            est_size = self._estimate_json_size(entry)
        except ValueError:
            raise  # depth exceeded
        if est_size > MAX_LEDGER_ENTRY_BYTES:
            raise ValueError(
                f"Ledger entry too large (estimated {est_size:,} bytes, "
                f"limit {MAX_LEDGER_ENTRY_BYTES:,})"
            )

        # Work on a copy to avoid mutating the caller's dict
        entry = {
            **entry,
            "ts": int(time.time() * 1000),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        try:
            line = json.dumps(entry)
        except RecursionError:
            raise ValueError("Ledger entry too deeply nested (recursion limit)")
        if len(line.encode("utf-8")) > MAX_LEDGER_ENTRY_BYTES:
            raise ValueError(
                f"Ledger entry too large (limit: {MAX_LEDGER_ENTRY_BYTES:,} bytes)"
            )

        # Append with O_NOFOLLOW + fd verification + size check INSIDE lock
        # (closes TOCTOU gap where concurrent appenders all pass external size check)
        try:
            self._safe_append_file(
                ledger_file, data_root, line + "\n",
                max_file_bytes=MAX_LEDGER_FILE_BYTES,
            )
        except OSError as e:
            logger.error("Ledger append failed: %s", e)
            raise ValueError("Failed to write to ledger file") from None
        return {"appended": True}

    def read_ledger(self, lines=20):
        data_root = self._require_data_root()
        ledger_file = self._ledger_file

        if not os.path.exists(ledger_file):
            return {"entries": [], "count": 0}

        # Cap requested lines (guard against float('inf') → OverflowError)
        try:
            lines = min(max(1, int(lines)), MAX_LEDGER_LINES_CAP)
        except (OverflowError, TypeError, ValueError):
            lines = MAX_LEDGER_LINES_CAP

        try:
            # Re-verify data_root identity immediately before fs operation
            self._verify_data_root_identity()
            # Open file once with TOCTOU protection, fstat for size, then
            # read from the same fd (eliminates getsize TOCTOU gap)
            resolved = self._verify_within(ledger_file, data_root)

            flags = os.O_RDONLY
            has_nofollow = hasattr(os, "O_NOFOLLOW")
            if has_nofollow:
                flags |= os.O_NOFOLLOW

            try:
                fd = os.open(resolved, flags)
            except OSError as e:
                if "symbolic link" in str(e).lower() or getattr(e, "errno", 0) == 40:
                    raise ValueError("Refusing to follow symlink")
                raise

            fd_owned = True
            try:
                self._verify_fd_in_container(fd, data_root, symlink_protected=has_nofollow)
                if not has_nofollow and os.path.islink(ledger_file):
                    os.close(fd)
                    fd_owned = False
                    raise ValueError("Refusing to follow symlink")

                # Use fstat on open fd — atomic checks for file type, links, and size
                import stat as _stat_mod
                _fd_stat = os.fstat(fd)
                if not _stat_mod.S_ISREG(_fd_stat.st_mode):
                    os.close(fd)
                    fd_owned = False
                    raise ValueError("Refusing to read non-regular ledger file (FIFO/device)")
                if _fd_stat.st_nlink > 1:
                    os.close(fd)
                    fd_owned = False
                    raise ValueError("Refusing to read hard-linked ledger file (nlink > 1)")
                file_size = _fd_stat.st_size

                if file_size > MAX_LEDGER_READ_BYTES:
                    logger.warning(
                        "Ledger file too large (%s bytes), reading tail only", file_size
                    )
                    # Seek one byte before the intended offset so we can detect
                    # whether we land exactly on a line boundary (the extra byte
                    # is either \n = boundary, or part of a partial line to discard)
                    seek = max(0, file_size - MAX_LEDGER_READ_BYTES)
                    if seek > 0:
                        seek = max(0, seek - 1)
                    with os.fdopen(fd, "rb") as f:
                        fd_owned = False
                        if seek > 0:
                            f.seek(seek)
                        # Cap read to MAX_LEDGER_READ_BYTES — file could have
                        # grown between fstat and read (other processes appending
                        # to the same inode are visible to existing fds on Linux)
                        raw_bytes = f.read(MAX_LEDGER_READ_BYTES)
                    raw = raw_bytes.decode("utf-8", errors="replace")
                    # Use deque + io.StringIO to iterate lines lazily,
                    # avoiding a full list allocation from split().
                    # (10MB of short lines → millions of entries with split)
                    import io as _io
                    tail = deque(maxlen=lines)
                    # Only discard the first line if the extra leading byte
                    # is NOT a newline — if it IS '\n', we landed exactly on
                    # a line boundary and the first line is complete.
                    skip_first = (
                        seek > 0
                        and raw_bytes
                        and raw_bytes[0:1] != b'\n'
                    )
                    first = True
                    for ln in _io.StringIO(raw):
                        if first and skip_first:
                            first = False
                            continue  # drop partial first line
                        first = False
                        tail.append(ln.rstrip('\n\r'))
                    all_lines = list(tail)
                else:
                    # Full read with same fd — use binary mode + decode for
                    # consistency with tail-read path (text mode normalizes
                    # \r\n on Windows and raises UnicodeDecodeError on invalid
                    # UTF-8; binary + errors="replace" is more resilient)
                    with os.fdopen(fd, "rb") as f:
                        fd_owned = False
                        raw_bytes = f.read(MAX_LEDGER_READ_BYTES)
                    raw = raw_bytes.decode("utf-8", errors="replace").strip()
                    # Use deque + io.StringIO for lazy line iteration
                    import io as _io
                    tail = deque(maxlen=lines)
                    for ln in _io.StringIO(raw):
                        tail.append(ln.rstrip('\n\r'))
                    all_lines = list(tail)
            except Exception:
                if fd_owned:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                raise

            entries = []
            for line in all_lines:
                line = line.strip()
                if not line:
                    continue
                # Per-line byte cap: a poisoned ledger could have lines with
                # multi-MB JSON objects. Skip lines exceeding the entry limit
                # to prevent memory exhaustion when parsing 1000 such lines.
                if len(line) > MAX_LEDGER_ENTRY_BYTES:
                    continue
                try:
                    entries.append(json.loads(line))
                except (json.JSONDecodeError, RecursionError):
                    continue
            return {"entries": entries, "count": len(entries)}
        except ValueError as e:
            logger.warning("Ledger read blocked: %s", e)
            return {"error": "Ledger file access denied"}
        except Exception:
            logger.error("Failed to read ledger", exc_info=True)
            return {"error": "Failed to read ledger"}
