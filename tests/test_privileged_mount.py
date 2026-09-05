"""Tests for the closed privileged-helper protocol and broker boundary."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from mulder.execution import mount_helper
from mulder.execution.mount_protocol import (
    canonical_mount_path,
    mount_request_payload,
    mount_response_payload,
)
from mulder.execution.policy import NetworkClass, PathAccess, PathArgument
from mulder.execution.privileged import SubprocessMountBroker
from mulder.execution.runner import ExecutionStatus, UnshareNetworkIsolationBackend
from mulder.server.extract_helpers import _MountCache


def test_broker_uses_fixed_module_and_typed_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")
    mount_point = tmp_path / "mount"
    mount_point.mkdir()
    captured: list[object] = []
    runners: list[object] = []

    def fake_run(_self: object, request: object) -> object:
        runners.append(_self)
        captured.append(request)
        arguments = request.arguments
        nonce = arguments[5]
        request_digest = arguments[7]
        payload = mount_request_payload(
            "mount",
            nonce,
            canonical_mount_path(mount_point, directory=True),
            canonical_mount_path(image, directory=False),
        )
        return SimpleNamespace(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout=json.dumps(
                mount_response_payload(payload, request_digest, ok=True),
                sort_keys=True,
            ).encode(),
        )

    monkeypatch.setattr("mulder.execution.privileged.CommandRunner.run", fake_run)
    monkeypatch.setattr("mulder.execution.privileged._verified_mount_state", lambda *_: True)

    assert SubprocessMountBroker().mount_read_only(image, mount_point)
    request = captured[0]
    assert request.network_class is NetworkClass.NONE
    arguments = request.arguments
    assert arguments[:4] == ("-I", "-m", "mulder.execution.mount_helper", "mount")
    assert arguments[4] == "--nonce"
    assert arguments[6] == "--request-digest"
    assert arguments[8] == PathArgument(image, PathAccess.READ)
    assert arguments[9] == PathArgument(mount_point, PathAccess.WRITE)
    assert isinstance(runners[0]._network_isolation, UnshareNetworkIsolationBackend)


def test_broker_rejects_unbound_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")
    mount_point = tmp_path / "mount"
    mount_point.mkdir()
    monkeypatch.setattr(
        "mulder.execution.privileged.CommandRunner.run",
        lambda *_: SimpleNamespace(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout=b'{"ok": true}\n',
        ),
    )
    assert not SubprocessMountBroker().mount_read_only(image, mount_point)


def test_broker_rolls_back_a_live_mount_when_verification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")
    mount_point = tmp_path / "mount"
    mount_point.mkdir()
    actions: list[str] = []

    def bound_response(_self: object, request: object) -> object:
        arguments = request.arguments
        action = arguments[3]
        actions.append(action)
        if action == "mount":
            payload = mount_request_payload(
                "mount",
                arguments[5],
                canonical_mount_path(mount_point, directory=True),
                canonical_mount_path(image, directory=False),
            )
        else:
            payload = mount_request_payload(
                "unmount",
                arguments[5],
                canonical_mount_path(mount_point, directory=True),
            )
        return SimpleNamespace(
            status=ExecutionStatus.COMPLETED,
            returncode=0,
            stdout=json.dumps(
                mount_response_payload(payload, arguments[7], ok=True),
                sort_keys=True,
            ).encode(),
        )

    unmounted_states = iter((True, False, True, True))
    monkeypatch.setattr("mulder.execution.privileged.CommandRunner.run", bound_response)
    monkeypatch.setattr("mulder.execution.privileged._verified_mount_state", lambda *_: False)
    monkeypatch.setattr(
        "mulder.execution.privileged._verified_unmounted",
        lambda *_: next(unmounted_states),
    )

    assert not SubprocessMountBroker().mount_read_only(image, mount_point)
    assert actions == ["mount", "unmount"]


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


def test_helper_entrypoint_requires_exact_descriptor_paths(tmp_path: Path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")
    mount_point = tmp_path / "mount"
    mount_point.mkdir()

    status = mount_helper.main(
        [
            "mount",
            "--nonce",
            "0" * 64,
            "--request-digest",
            "sha256:" + "0" * 64,
            str(image),
            str(mount_point),
        ]
    )

    assert status == 2


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
    assert not broker.mounted[0][1].exists()


def test_mount_cache_preserves_nonempty_directory_after_verified_unmount(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class InsertionBroker:
        mount_point: Path | None = None

        def mount_read_only(self, _image_path: Path, mount_point: Path) -> bool:
            self.mount_point = mount_point
            return True

        def unmount(self, mount_point: Path) -> bool:
            (mount_point / "late.txt").write_text("preserve")
            return True

    broker = InsertionBroker()
    cache = _MountCache(broker)
    with cache.acquire(str(image)):
        pass

    assert broker.mount_point is not None
    assert (broker.mount_point / "late.txt").read_text() == "preserve"


def test_mount_cache_preserves_replaced_directory_after_verified_unmount(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class ReplacementBroker:
        mount_point: Path | None = None

        def mount_read_only(self, _image_path: Path, mount_point: Path) -> bool:
            self.mount_point = mount_point
            return True

        def unmount(self, mount_point: Path) -> bool:
            mount_point.rmdir()
            mount_point.mkdir()
            return True

    broker = ReplacementBroker()
    cache = _MountCache(broker)
    with cache.acquire(str(image)):
        pass

    assert broker.mount_point is not None
    assert broker.mount_point.is_dir()


def test_mount_cache_preserves_directory_when_unmount_is_unverified(tmp_path: Path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class UnverifiableUnmountBroker:
        mount_point: Path | None = None

        def mount_read_only(self, _image_path: Path, mount_point: Path) -> bool:
            self.mount_point = mount_point
            return True

        def unmount(self, _mount_point: Path) -> bool:
            return False

    broker = UnverifiableUnmountBroker()
    cache = _MountCache(broker)
    with cache.acquire(str(image)):
        pass

    assert broker.mount_point is not None
    assert broker.mount_point.exists()


def test_mount_cache_rolls_back_ambiguous_failed_mount(tmp_path: Path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class SideEffectingBroker:
        mount_point: Path | None = None
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, mount_point: Path) -> bool:
            self.mount_point = mount_point
            return False

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return False

    broker = SideEffectingBroker()
    cache = _MountCache(broker)

    with pytest.raises(RuntimeError, match="Failed to mount"), cache.acquire(str(image)):
        pytest.fail("failed mount must not be yielded")

    assert broker.unmount_calls == 1
    assert broker.mount_point is not None
    assert broker.mount_point.exists()
