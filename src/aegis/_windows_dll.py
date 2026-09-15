"""Work around a Windows C++ runtime collision between PyArrow and onnxruntime.

THE FAILURE
-----------
On Windows, once PyArrow is imported, importing onnxruntime fails with:

    ImportError: DLL load failed while importing onnxruntime_pybind11_state:
    A dynamic link library (DLL) initialization routine failed.

This broke `aegis ml embed` - and it was invisible in a standalone test that
happened not to import PyArrow first.

THE CAUSE (measured on the development machine)
-----------------------------------------------
    site-packages/pyarrow/msvcp140.dll     14.28.29334   bundled, old
    C:/Windows/System32/msvcp140.dll       14.40.33810   system, newer
    onnxruntime                            bundles no copy of its own

PyArrow ships its own copy of the Microsoft C++ runtime under the plain file
name `msvcp140.dll`. Windows keeps one module per file name in a process, so
once PyArrow has loaded its old 14.28 copy, onnxruntime is handed that same
copy - which is too old for it. (numpy ships the runtime under a hash-suffixed
name, which is why numpy never collides.)

A bisect of 13 libraries imported before onnxruntime isolated PyArrow as the
only trigger; MLflow failed only because it imports PyArrow.

THE FIX
-------
Load the system's newer copy first. Every later request for `msvcp140.dll` in
the process then resolves to it, and both libraries run on 14.40. Verified with
real inference, not just an import.

The Microsoft C++ runtime is backward compatible - binaries built against an
older version run on a newer one - but not forward compatible. So the system
copy is preloaded only when it is at least as new as the copy PyArrow bundles.
Preloading an older system copy would trade onnxruntime's failure for PyArrow's.

This module must never raise: it runs on every `aegis` import, and a command
that has nothing to do with ML must not fail because of it. Every outcome is
reported as a status string instead.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

Version = tuple[int, int, int, int]


def _format(version: Version | None) -> str:
    return ".".join(str(part) for part in version) if version else "unknown"


def file_version(path: Path) -> Version | None:
    """Read a Windows DLL's file version from its version resource."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        api = ctypes.WinDLL("version.dll")
        api.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        api.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        api.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        api.GetFileVersionInfoW.restype = wintypes.BOOL
        api.VerQueryValueW.argtypes = [
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        api.VerQueryValueW.restype = wintypes.BOOL

        size = api.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not api.GetFileVersionInfoW(str(path), 0, size, buffer):
            return None

        class FixedFileInfo(ctypes.Structure):
            _fields_ = [
                ("signature", wintypes.DWORD),
                ("struct_version", wintypes.DWORD),
                ("file_version_ms", wintypes.DWORD),
                ("file_version_ls", wintypes.DWORD),
            ]

        pointer = ctypes.c_void_p()
        length = wintypes.UINT()
        if not api.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            return None
        info = ctypes.cast(pointer, ctypes.POINTER(FixedFileInfo)).contents
        ms, ls = info.file_version_ms, info.file_version_ls
        return (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
    except Exception:
        return None


def pyarrow_bundled_runtime() -> Path | None:
    """PyArrow's bundled msvcp140.dll, located WITHOUT importing PyArrow.

    Importing PyArrow to find the file would load the old DLL - the very thing
    this module exists to prevent. find_spec locates a package without running it.
    """
    try:
        spec = importlib.util.find_spec("pyarrow")
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.submodule_search_locations:
        return None
    candidate = Path(next(iter(spec.submodule_search_locations))) / "msvcp140.dll"
    return candidate if candidate.exists() else None


def system_runtime() -> Path:
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "msvcp140.dll"


def _load_library(path: Path) -> None:
    """Separated out so tests can prove when a load does or does not happen."""
    if sys.platform == "win32":
        import ctypes

        ctypes.WinDLL(str(path))


def _on_windows() -> bool:
    return sys.platform == "win32"


def _pyarrow_already_imported() -> bool:
    return "pyarrow" in sys.modules


def preload_msvc_runtime() -> str | None:
    """Preload the system C++ runtime when PyArrow bundles an older one.

    Returns None on non-Windows platforms, otherwise a short status string.
    """
    # Platform and module checks go through small functions so tests can
    # replace them. Patching the real sys.platform or sys.modules inside a
    # test would affect every import in the test process.
    if not _on_windows():
        return None
    try:
        if _pyarrow_already_imported():
            return "too late: pyarrow was imported before aegis"

        bundled = pyarrow_bundled_runtime()
        if bundled is None:
            return "not needed: pyarrow bundles no msvcp140.dll"

        system = system_runtime()
        if not system.exists():
            return "not possible: no system msvcp140.dll (install the VC++ redistributable)"

        system_version = file_version(system)
        bundled_version = file_version(bundled)
        if system_version is None or bundled_version is None:
            return "skipped: could not read DLL versions"
        if system_version < bundled_version:
            return (
                f"skipped: system runtime {_format(system_version)} is older than "
                f"pyarrow's {_format(bundled_version)}"
            )

        _load_library(system)
        return (
            f"preloaded system runtime {_format(system_version)} "
            f"(pyarrow bundles {_format(bundled_version)})"
        )
    except Exception as exc:
        return f"error: {type(exc).__name__}: {exc}"
