"""Tests for the closed privileged-helper protocol and broker boundary."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
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
    assert broker.mounted[0][1].is_dir()


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


def test_mount_cache_rolls_back_base_exception_and_evicts_entry(tmp_path: Path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class InterruptingBroker:
        mount_point: Path | None = None
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, mount_point: Path) -> bool:
            self.mount_point = mount_point
            raise KeyboardInterrupt

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return True

    broker = InterruptingBroker()
    cache = _MountCache(broker)

    with pytest.raises(KeyboardInterrupt), cache.acquire(str(image)):
        pytest.fail("interrupted mount must not be yielded")

    assert cache._entries == {}
    assert broker.unmount_calls == 1
    assert broker.mount_point is not None
    assert broker.mount_point.is_dir()


def test_mount_cache_interrupted_waiter_releases_its_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class SuccessfulBroker:
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, _mount_point: Path) -> bool:
            return True

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return True

    broker = SuccessfulBroker()
    cache = _MountCache(broker)
    owner = cache.acquire(str(image))
    owner.__enter__()
    entry = next(iter(cache._entries.values()))

    def interrupt_wait() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(entry.ready, "wait", interrupt_wait)
    with pytest.raises(KeyboardInterrupt), cache.acquire(str(image)):
        pytest.fail("interrupted waiter must not be yielded")

    assert entry.refcount == 1
    owner.__exit__(None, None, None)
    assert cache._entries == {}
    assert broker.unmount_calls == 1


def test_mount_cache_retries_cancellation_before_release_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class SuccessfulBroker:
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, _mount_point: Path) -> bool:
            return True

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return True

    broker = SuccessfulBroker()
    cache = _MountCache(broker)
    acquisition = cache.acquire(str(image))
    acquisition.__enter__()
    release = cache._release
    attempts = 0

    def interrupt_first_release(*args: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt
        release(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(cache, "_release", interrupt_first_release)
    with pytest.raises(KeyboardInterrupt):
        acquisition.__exit__(None, None, None)

    assert attempts == 2
    assert broker.unmount_calls == 1
    assert cache._entries == {}


def test_mount_cache_retries_trace_cancellation_on_finally_entry(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class SuccessfulBroker:
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, _mount_point: Path) -> bool:
            return True

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return True

    broker = SuccessfulBroker()
    cache = _MountCache(broker)
    acquisition = cache.acquire(str(image))
    acquisition.__enter__()
    generator_frame = acquisition.gen.gi_frame
    fired = False

    def interrupt_first_resumed_line(
        frame: object, event: str, _arg: object
    ) -> object:
        nonlocal fired
        if not fired and frame is generator_frame and event == "line":
            fired = True
            raise KeyboardInterrupt
        return interrupt_first_resumed_line

    sys.settrace(interrupt_first_resumed_line)
    try:
        with pytest.raises(KeyboardInterrupt):
            acquisition.__exit__(None, None, None)
    finally:
        sys.settrace(None)

    assert fired
    assert broker.unmount_calls == 1
    assert cache._entries == {}


def test_mount_cache_retries_cancellation_in_release_prologue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class SuccessfulBroker:
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, _mount_point: Path) -> bool:
            return True

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return True

    broker = SuccessfulBroker()
    cache = _MountCache(broker)
    acquisition = cache.acquire(str(image))
    acquisition.__enter__()
    release_once = cache._release_once
    attempts = 0

    def interrupt_first_attempt(*args: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt
        release_once(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(cache, "_release_once", interrupt_first_attempt)
    with pytest.raises(KeyboardInterrupt):
        acquisition.__exit__(None, None, None)

    assert attempts >= 2
    assert broker.unmount_calls == 1
    assert cache._entries == {}


def test_mount_cache_does_not_repeat_interrupted_unmount_on_replacement(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class RemountedBroker:
        unmount_calls = 0
        replacement_live = False

        def mount_read_only(self, _image_path: Path, _mount_point: Path) -> bool:
            return True

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            if self.unmount_calls == 1:
                self.replacement_live = True
                raise KeyboardInterrupt
            self.replacement_live = False
            return True

        def is_unmounted(self, _mount_point: Path) -> bool:
            return not self.replacement_live

    broker = RemountedBroker()
    cache = _MountCache(broker)
    acquisition = cache.acquire(str(image))
    acquisition.__enter__()

    with pytest.raises(KeyboardInterrupt):
        acquisition.__exit__(None, None, None)

    assert broker.unmount_calls == 1
    assert broker.replacement_live
    assert cache._entries == {}


def test_mount_cache_retries_eviction_after_interrupted_close_signal(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class SuccessfulBroker:
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, _mount_point: Path) -> bool:
            return True

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return True

    class InterruptingClose:
        def __init__(self) -> None:
            self._event = threading.Event()
            self.calls = 0

        def set(self) -> None:
            self.calls += 1
            self._event.set()
            if self.calls == 1:
                raise KeyboardInterrupt

        def wait(self) -> None:
            self._event.wait()

        def is_set(self) -> bool:
            return self._event.is_set()

    broker = SuccessfulBroker()
    cache = _MountCache(broker)
    acquisition = cache.acquire(str(image))
    acquisition.__enter__()
    entry = next(iter(cache._entries.values()))
    close_signal = InterruptingClose()
    entry.closed = close_signal  # type: ignore[assignment]

    with pytest.raises(KeyboardInterrupt):
        acquisition.__exit__(None, None, None)

    assert close_signal.calls == 2
    assert broker.unmount_calls == 1
    assert cache._entries == {}


def test_mount_cache_signals_close_before_new_owner_can_overtake(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"image")

    class SuccessfulBroker:
        mount_calls = 0
        unmount_calls = 0

        def mount_read_only(self, _image_path: Path, _mount_point: Path) -> bool:
            self.mount_calls += 1
            return True

        def unmount(self, _mount_point: Path) -> bool:
            self.unmount_calls += 1
            return True

    class GatedClose:
        def __init__(self) -> None:
            self._event = threading.Event()
            self.called = threading.Event()
            self.allow = threading.Event()

        def set(self) -> None:
            self.called.set()
            assert self.allow.wait(timeout=5)
            self._event.set()

        def wait(self) -> None:
            self._event.wait()

        def is_set(self) -> bool:
            return self._event.is_set()

    broker = SuccessfulBroker()
    cache = _MountCache(broker)
    first = cache.acquire(str(image))
    first.__enter__()
    entry = next(iter(cache._entries.values()))
    gated_close = GatedClose()
    entry.closed = gated_close  # type: ignore[assignment]

    close_thread = threading.Thread(target=lambda: first.__exit__(None, None, None))
    close_thread.start()
    assert gated_close.called.wait(timeout=5)

    second_entered = threading.Event()

    def acquire_again() -> None:
        with cache.acquire(str(image)):
            second_entered.set()

    second_thread = threading.Thread(target=acquire_again)
    second_thread.start()
    assert not second_entered.wait(timeout=0.05)
    assert broker.mount_calls == 1

    gated_close.allow.set()
    close_thread.join(timeout=5)
    second_thread.join(timeout=5)
    assert not close_thread.is_alive()
    assert not second_thread.is_alive()
    assert second_entered.is_set()
    assert broker.mount_calls == 2
    assert broker.unmount_calls == 2
