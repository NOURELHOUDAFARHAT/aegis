"""Regression tests for the PyArrow / onnxruntime C++ runtime collision on Windows.

The decisive test runs in a FRESH process, because the failure depends on
import order and a process can only load a DLL once. Testing it inside pytest's
own process - which has long since imported PyArrow - would prove nothing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from aegis import _windows_dll

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestPlatformGuard:
    def test_does_nothing_off_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_windows_dll, "_on_windows", lambda: False)
        assert _windows_dll.preload_msvc_runtime() is None

    def test_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It runs on every `aegis` import; an exception here would break every command."""

        def boom() -> None:
            raise RuntimeError("unexpected")

        monkeypatch.setattr(_windows_dll, "_on_windows", lambda: True)
        monkeypatch.setattr(_windows_dll, "_pyarrow_already_imported", lambda: False)
        monkeypatch.setattr(_windows_dll, "pyarrow_bundled_runtime", boom)
        status = _windows_dll.preload_msvc_runtime()
        assert status is not None
        assert status.startswith("error:")


class TestVersionGuard:
    """The runtime is backward compatible, not forward compatible."""

    @pytest.fixture
    def windows(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, list[Path]]:
        bundled = tmp_path / "pyarrow" / "msvcp140.dll"
        system = tmp_path / "System32" / "msvcp140.dll"
        for f in (bundled, system):
            f.parent.mkdir(parents=True)
            f.write_bytes(b"")
        loaded: list[Path] = []
        monkeypatch.setattr(_windows_dll, "_on_windows", lambda: True)
        monkeypatch.setattr(_windows_dll, "_pyarrow_already_imported", lambda: False)
        monkeypatch.setattr(_windows_dll, "pyarrow_bundled_runtime", lambda: bundled)
        monkeypatch.setattr(_windows_dll, "system_runtime", lambda: system)
        monkeypatch.setattr(_windows_dll, "_load_library", loaded.append)
        return {"loaded": loaded, "paths": [bundled, system]}

    def test_preloads_when_the_system_copy_is_newer(
        self, windows: dict[str, list[Path]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundled, system = windows["paths"]
        versions = {bundled: (14, 28, 29334, 0), system: (14, 40, 33810, 0)}
        monkeypatch.setattr(_windows_dll, "file_version", versions.get)

        status = _windows_dll.preload_msvc_runtime()

        assert windows["loaded"] == [system]
        assert status is not None and status.startswith("preloaded")

    def test_refuses_to_force_an_older_system_copy_on_pyarrow(
        self, windows: dict[str, list[Path]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Preloading an older runtime would trade onnxruntime's failure for PyArrow's."""
        bundled, system = windows["paths"]
        versions = {bundled: (14, 40, 0, 0), system: (14, 28, 0, 0)}
        monkeypatch.setattr(_windows_dll, "file_version", versions.get)

        status = _windows_dll.preload_msvc_runtime()

        assert windows["loaded"] == []
        assert status is not None and status.startswith("skipped")

    def test_too_late_if_pyarrow_is_already_imported(
        self, windows: dict[str, list[Path]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_windows_dll, "_pyarrow_already_imported", lambda: True)
        status = _windows_dll.preload_msvc_runtime()
        assert windows["loaded"] == []
        assert status is not None and status.startswith("too late")


@pytest.mark.skipif(sys.platform != "win32", reason="the collision is Windows-specific")
class TestRealProcess:
    def test_reads_real_dll_versions(self) -> None:
        version = _windows_dll.file_version(_windows_dll.system_runtime())
        assert version is not None
        assert version[0] == 14  # the Visual C++ 2015-2022 runtime family

    def test_aegis_then_pyarrow_then_onnxruntime_imports_cleanly(self) -> None:
        """THE REGRESSION TEST. Without the preload this fails with
        'DLL load failed while importing onnxruntime_pybind11_state'."""
        pytest.importorskip("onnxruntime")
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import aegis, pyarrow, onnxruntime; print(aegis.MSVC_RUNTIME_STATUS)",
            ],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=REPO_ROOT,
            check=False,
        )
        assert result.returncode == 0, result.stderr[-800:]
