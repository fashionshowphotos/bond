"""Shared filesystem utilities for Bond modules.

Provides platform-specific helpers used across multiple modules
(filesystem, orchestrator) to avoid code duplication.
"""

from __future__ import annotations
from typing import Optional


def win_get_final_path(fd: int) -> Optional[str]:
    """Use Win32 GetFinalPathNameByHandleW to get canonical path of an open fd.

    Returns the resolved path string, or None if unavailable.
    """
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
            return final_path
    except Exception:
        pass
    return None
