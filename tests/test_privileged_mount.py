"""Tests for the closed privileged-helper protocol and broker boundary."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from mulder.execution import mount_helper
from mulder.execution.policy import NetworkClass, PathAccess, PathArgument
from mulder.execution.privileged import SubprocessMountBroker
from mulder.execution.runner import ExecutionStatus
from mulder.server.extract_helpers import _MountCache


def test_broker_uses_fixed_module_and_typed_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")
    mount_point = tmp_path / "mount"
    mount_point.mkdir()
    captured: list[object] = []

    def fake_run(_self: object, request: object) -> object:
        captured.append(request)
        return SimpleNamespace(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout=b'{"ok": true}\n',
        )

    monkeypatch.setattr("mulder.execution.privileged.CommandRunner.run", fake_run)

    assert SubprocessMountBroker().mount_read_only(image, mount_point)
    request = captured[0]
    assert request.network_class is NetworkClass.NONE
    arguments = request.arguments
    assert arguments[:4] == ("-I", "-m", "mulder.execution.mount_helper", "mount")
    assert arguments[4] == PathArgument(image, PathAccess.READ)
    assert arguments[5] == PathArgument(mount_point, PathAccess.WRITE)


def test_broker_fails_closed_on_invalid_helper_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mount_point = tmp_path / "mount"
    mount_point.mkdir()

    monkeypatch.setattr(
        "mulder.execution.privileged.CommandRunner.run",
        lambda _self, _request: SimpleNamespace(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout=b"not-json",
        ),
    )

    assert not SubprocessMountBroker().unmount(mount_point)


def test_helper_rejects_paths_outside_closed_protocol(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        mount_helper.perform("mount", "relative.raw", str(tmp_path))
    with pytest.raises(ValueError, match="unsupported"):
        mount_helper.perform("run", str(tmp_path))


def test_raw_mount_argv_is_read_only_and_non_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")
    mount_point = tmp_path / "mount"
    mount_point.mkdir()
    calls: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name == "mount" else None

    def fake_run(argv: list[str], _timeout: float) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(mount_helper.shutil, "which", fake_which)
    monkeypatch.setattr(mount_helper, "_run", fake_run)

    assert mount_helper.perform("mount", str(image), str(mount_point))
    assert calls == [
        [
            "/usr/bin/mount",
            "-o",
            "ro,loop,noexec,nodev,nosuid",
            str(image),
            str(mount_point),
        ]
    ]


def test_mount_cache_uses_injected_broker(tmp_path: Path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class FakeBroker:
        def __init__(self) -> None:
            self.mounted: list[tuple[Path, Path]] = []
            self.unmounted: list[Path] = []

        def mount_read_only(self, image_path: Path, mount_point: Path) -> bool:
            self.mounted.append((image_path, mount_point))
            return True

        def unmount(self, mount_point: Path) -> bool:
            self.unmounted.append(mount_point)
            return True

    broker = FakeBroker()
    cache = _MountCache(broker)
    with cache.acquire(str(image)) as mounted:
        assert Path(mounted).is_dir()

    assert len(broker.mounted) == 1
    assert len(broker.unmounted) == 1
