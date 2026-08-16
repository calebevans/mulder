"""Tests for ``mulder setup``'s planning and provisioning.

Offline by construction, in three independent layers:

1. ``provision(..., fetch=...)`` takes the downloader as a parameter and every
   test here passes a local one;
2. ``mulder.assets.manifest`` is inert data whose only I/O is one package-data
   read;
3. ``tests/conftest.py`` patches ``socket.connect`` and ``httpx`` send to raise,
   so a regression that bypasses the injected fetcher fails loudly instead of
   downloading a gigabyte in CI.
"""

from __future__ import annotations

import json
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.assets import install as install_mod
from mulder.assets.fetch import FetchError, FetchResult, sha256_file
from mulder.assets.install import Plan, PlanError, SetupOptions, build_plan, provision
from mulder.assets.manifest import ASSETS_BY_KEY
from mulder.assets.state import AssetState


class RecordingFetcher:
    """A fetcher that synthesises the right shape for each manifest row."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.urls: list[str] = []
        self.fail: set[str] = set()
        self.corrupt: set[str] = set()

    def head(self, url: str) -> int | None:
        raise AssertionError("--dry-run must issue no requests at all")

    def __call__(self, url: str, dest: Path, *, resume: bool = False) -> FetchResult:
        self.urls.append(url)
        name = url.rsplit("/", 1)[-1]
        if name in self.fail:
            raise FetchError("404 Not Found")
        if name.endswith(".json"):
            body = b'{"objects": []}' if name not in self.corrupt else b'{"objec'
            dest.write_bytes(body)
        elif name.endswith(".tar.gz"):
            _write_tarball(dest, name)
        else:
            _write_zip(dest, name)
        return FetchResult(dest, dest.stat().st_size, sha256_file(dest))


def _write_tarball(dest: Path, name: str) -> None:
    staging = dest.parent / "tar-src" / "prefix"
    (staging / "rules" / "windows").mkdir(parents=True, exist_ok=True)
    (staging / "rules" / "windows" / "rule.yml").write_text("title: test\n")
    (staging / "rules" / "linux").mkdir(parents=True, exist_ok=True)
    (staging / "rules" / "linux" / "rule.yml").write_text("title: test\n")
    (staging / "chainsaw").write_text("#!/bin/sh\n")
    with tarfile.open(dest, "w:gz") as tf:
        tf.add(staging, arcname="prefix")


def _write_zip(dest: Path, name: str) -> None:
    stem = name.removesuffix(".zip")
    with zipfile.ZipFile(dest, "w") as zf:
        zf.writestr("capa", "#!/bin/sh\n")
        zf.writestr(f"{stem}.dll", "binary")
        zf.writestr("hayabusa-3.8.1-lin-x64-musl", "#!/bin/sh\n")


@pytest.fixture()
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A pinned write root and shim directory, with git and root faked out."""
    from mulder.assets import paths

    root = tmp_path / "assets"
    root.mkdir()
    bin_dir = tmp_path / "bin"
    monkeypatch.setenv("MULDER_ASSET_ROOT", str(root))
    monkeypatch.setattr(install_mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(install_mod, "_geteuid", lambda: 1000)
    paths.reset_asset_caches()
    return root, bin_dir


def _plan(
    roots: tuple[Path, Path], keys: set[str] | None = None, **kwargs: Any
) -> tuple[Plan, SetupOptions]:
    """Build a plan, optionally narrowed to *keys*.

    `mulder setup` deliberately has no --only/--tier any more: it installs
    everything.  Tests still need to exercise one row at a time, so the
    narrowing lives here rather than as production CLI surface.
    """
    options = SetupOptions(**kwargs)
    plan = build_plan(options, roots[0], roots[1])
    if keys is not None:
        plan.selected = [a for a in plan.selected if a.key in keys]
    return plan, options


def _run(
    roots: tuple[Path, Path],
    fetcher: RecordingFetcher | Any,
    keys: set[str] | None = None,
    **kwargs: Any,
) -> Any:
    plan, options = _plan(roots, keys, **kwargs)
    install_mod.preflight(plan, options)
    return provision(plan, options, fetch=fetcher)


def _by_key(result: Any) -> dict[str, Any]:
    return {outcome.key: outcome for outcome in result.outcomes}


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


class TestPlanning:
    def test_every_manifest_row_appears_in_the_summary(self, roots: tuple[Path, Path]) -> None:
        """A silent partial install must be structurally impossible."""
        result = _run(roots, RecordingFetcher(roots[0]), dry_run=True)

        assert set(_by_key(result)) == set(ASSETS_BY_KEY)

    def test_requirements_are_provisioned_before_their_dependants(
        self, roots: tuple[Path, Path]
    ) -> None:
        """Ordering is implicit in manifest order; pin it so a reorder fails here.

        ``_seed_zircolite_rules`` reads the *installed* sigma-rules tree, so
        zircolite must never be provisioned first.
        """
        plan, _ = _plan(roots)
        order = [a.key for a in plan.selected]

        assert order.index("sigma-rules") < order.index("zircolite")

    def test_pinnable_row_without_a_digest_is_fatal(
        self, roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Never a silent downgrade to an unverified download."""
        import dataclasses

        stripped = dataclasses.replace(ASSETS_BY_KEY["chainsaw"], digests={})
        monkeypatch.setattr(
            install_mod,
            "ASSETS",
            tuple(stripped if a.key == "chainsaw" else a for a in install_mod.ASSETS),
        )
        with pytest.raises(PlanError) as exc:
            _plan(roots, {"chainsaw"})

        assert exc.value.exit_code == 1
        assert "make assets-lock" in str(exc.value)


class TestPreflight:
    def test_missing_git_is_fatal_before_any_fetch(
        self, roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(install_mod.shutil, "which", lambda _name: None)
        plan, options = _plan(roots)

        with pytest.raises(PlanError) as exc:
            install_mod.preflight(plan, options)

        assert exc.value.exit_code == 1
        assert "sudo apt install git" in str(exc.value)

    def test_running_as_root_is_a_usage_error(
        self, roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(install_mod, "_geteuid", lambda: 0)
        plan, options = _plan(roots)

        with pytest.raises(PlanError) as exc:
            install_mod.preflight(plan, options)

        assert exc.value.exit_code == 2
        assert "Refusing to run as root" in str(exc.value)

    def test_unwritable_write_root_is_fatal_before_any_fetch(
        self, roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        plan, options = _plan(roots)
        monkeypatch.setattr(
            Path, "write_bytes", lambda *_a, **_k: (_ for _ in ()).throw(OSError("EROFS"))
        )

        with pytest.raises(PlanError) as exc:
            install_mod.preflight(plan, options)

        assert exc.value.exit_code == 1
        assert "MULDER_ASSET_ROOT" in str(exc.value)


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------


class TestProvisioning:
    def test_dry_run_writes_nothing_and_requests_nothing(self, roots: tuple[Path, Path]) -> None:
        fetcher = RecordingFetcher(roots[0])
        result = _run(roots, fetcher, dry_run=True)

        assert fetcher.urls == []
        assert list(roots[0].iterdir()) == []
        assert result.exit_code == 0

    def test_fresh_install_then_idempotent_rerun(self, roots: tuple[Path, Path]) -> None:
        fetcher = RecordingFetcher(roots[0])
        first = _run(roots, fetcher, {"attack"})
        assert _by_key(first)["attack"].status == "installed"
        assert (roots[0] / "attack" / "enterprise-attack.json").exists()

        fetched = len(fetcher.urls)
        second = _run(roots, fetcher, {"attack"})

        assert _by_key(second)["attack"].status == "up-to-date"
        assert len(fetcher.urls) == fetched

    def test_a_failed_fetch_leaves_the_previous_good_copy_intact(
        self, roots: tuple[Path, Path]
    ) -> None:
        """The whole point of staging: a bad download never reaches the reader."""
        fetcher = RecordingFetcher(roots[0])
        _run(roots, fetcher, {"attack"})
        good = (roots[0] / "attack" / "enterprise-attack.json").read_bytes()

        fetcher.corrupt.add("enterprise-attack.json")
        # A re-fetch now happens only because the recorded version no longer
        # matches the manifest -- the same path a real upgrade takes.
        state = AssetState.load(roots[0])
        state.assets["attack"].version = "stale"
        state.save(roots[0])
        result = _run(roots, fetcher, {"attack"})

        assert _by_key(result)["attack"].failed
        assert result.exit_code == 3
        assert (roots[0] / "attack" / "enterprise-attack.json").read_bytes() == good
        assert json.loads(good)["objects"] == []

    def test_checksum_mismatch_is_a_failure(self, roots: tuple[Path, Path]) -> None:
        fetcher = RecordingFetcher(roots[0])
        result = _run(roots, fetcher, {"capa"})

        assert "checksum mismatch" in _by_key(result)["capa"].status
        assert not (roots[0] / "capa").exists()

    def test_shims_are_linked_into_bin_dir(self, roots: tuple[Path, Path]) -> None:
        import dataclasses

        from mulder.assets import manifest as manifest_mod

        unpinned = dataclasses.replace(ASSETS_BY_KEY["capa"], pinnable=False, digests={})
        patched = tuple(unpinned if a.key == "capa" else a for a in manifest_mod.ASSETS)
        with (
            patch.dict(manifest_mod.ASSETS_BY_KEY, {"capa": unpinned}),
            patch.object(install_mod, "ASSETS", patched),
            patch.object(manifest_mod, "ASSETS", patched),
        ):
            _run(roots, RecordingFetcher(roots[0]), {"capa"})

        assert (roots[1] / "capa").is_symlink()
        assert (roots[1] / "capa").resolve() == (roots[0] / "capa" / "capa").resolve()


class TestVerify:
    def test_verify_reports_missing_and_exits_4(self, roots: tuple[Path, Path]) -> None:
        from mulder.assets.fetch import OfflineFetcher

        plan, options = _plan(roots, verify=True)
        result = provision(plan, options, fetch=OfflineFetcher())

        assert _by_key(result)["attack"].status == "missing"
        assert result.exit_code == 4

    def test_verify_exits_0_when_everything_is_present(self, roots: tuple[Path, Path]) -> None:
        from mulder.assets.fetch import OfflineFetcher

        _run(roots, RecordingFetcher(roots[0]), {"attack"})
        plan, options = _plan(roots, {"attack"}, verify=True)
        result = provision(plan, options, fetch=OfflineFetcher())

        assert result.exit_code == 0


class TestShadowing:
    def test_a_higher_priority_copy_is_reported_not_hidden(
        self, roots: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The SIFT case: a hand-made /opt copy outranks what setup just wrote.

        Without this, setup prints "All N assets present" while every read still
        resolves to the older -- possibly truncated -- copy.
        """
        from mulder.assets import paths

        write_root, bin_dir = roots
        _run(roots, RecordingFetcher(write_root), {"attack"})

        stale = tmp_path / "opt"
        (stale / "attack").mkdir(parents=True)
        (stale / "attack" / "enterprise-attack.json").write_text('{"objects": []}')
        monkeypatch.delenv("MULDER_ASSET_ROOT")
        monkeypatch.setattr(paths, "SYSTEM_ROOT", stale)
        monkeypatch.setattr(Path, "home", lambda: write_root.parent / "fake-home")
        monkeypatch.setattr(paths, "user_root", lambda: write_root)
        paths.reset_asset_caches()

        options = SetupOptions(verify=True)
        plan = build_plan(options, write_root, bin_dir)
        plan.selected = [a for a in plan.selected if a.key == "attack"]
        from mulder.assets.fetch import OfflineFetcher

        result = provision(plan, options, fetch=OfflineFetcher())

        assert _by_key(result)["attack"].shadowed_by == str(stale / "attack")
        assert result.exit_code == 4
        assert "shadowed" in result.remedies[0]

    def test_verify_accepts_an_asset_provided_only_by_a_higher_priority_root(
        self, roots: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stock SIFT box, which SPEC 1.6 promises is unaffected.

        A hand-made /opt clone and no 'mulder setup' run is a working install.
        Deciding presence from the write root alone reported it 'missing' with
        exit 4, sending the user looking for a problem that is not there.
        """
        from mulder.assets import paths
        from mulder.assets.fetch import OfflineFetcher

        write_root, bin_dir = roots
        theirs = tmp_path / "opt"
        (theirs / "attack").mkdir(parents=True)
        (theirs / "attack" / "enterprise-attack.json").write_text('{"objects": []}')

        monkeypatch.delenv("MULDER_ASSET_ROOT")
        monkeypatch.setattr(paths, "SYSTEM_ROOT", theirs)
        monkeypatch.setattr(Path, "home", lambda: write_root.parent / "fake-home")
        monkeypatch.setattr(paths, "user_root", lambda: write_root)
        paths.reset_asset_caches()

        options = SetupOptions(verify=True)
        plan = build_plan(options, write_root, bin_dir)
        plan.selected = [a for a in plan.selected if a.key == "attack"]
        result = provision(plan, options, fetch=OfflineFetcher())

        attack = _by_key(result)["attack"]
        assert attack.status == "up-to-date (unmanaged)"
        assert not attack.missing
        assert str(theirs / "attack") in attack.detail
        assert result.exit_code == 0


class TestEzTools:
    def test_only_missing_dlls_are_fetched(self, roots: tuple[Path, Path]) -> None:
        """On SIFT that is PECmd alone -- 20 MB rather than shadowing five DLLs."""
        write_root = roots[0]
        platform_copy = write_root / "zimmermantools" / "net6"
        platform_copy.mkdir(parents=True)
        for tool in ("AmcacheParser", "AppCompatCacheParser", "MFTECmd", "EvtxECmd", "RECmd"):
            (platform_copy / f"{tool}.dll").write_text("")
        AssetState(assets={"eztools": _record(write_root)}).save(write_root)

        fetcher = RecordingFetcher(write_root)
        result = _run(roots, fetcher, {"eztools"})

        assert [u.rsplit("/", 1)[-1] for u in fetcher.urls] == ["PECmd.zip"]
        assert "fetched PECmd" in _by_key(result)["eztools"].detail

    def test_an_unmanaged_copy_is_never_written_into(self, roots: tuple[Path, Path]) -> None:
        """Even with --force: mixing net9 DLLs into SIFT's net6 tree is the bug."""
        write_root = roots[0]
        (write_root / "zimmermantools").mkdir()

        fetcher = RecordingFetcher(write_root)
        result = _run(roots, fetcher, {"eztools"})

        assert fetcher.urls == []
        assert "unmanaged copy" in _by_key(result)["eztools"].status


def _record(root: Path) -> Any:
    from mulder.assets.state import AssetRecord

    return AssetRecord(version="net9", url="x", dest=str(root / "zimmermantools"))


class TestArchiveSafety:
    def test_a_tar_member_escaping_the_destination_is_rejected(self, tmp_path: Path) -> None:
        archive = tmp_path / "evil.tar.gz"
        payload = tmp_path / "payload"
        payload.write_text("pwned")
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(payload, arcname="../../escaped")

        with pytest.raises(FetchError, match="escapes destination"):
            install_mod.extract_archive(archive, tmp_path / "dest")

        assert not (tmp_path.parent / "escaped").exists()

    def test_absolute_member_paths_are_rejected(self, tmp_path: Path) -> None:
        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("/etc/passwd", "pwned")

        with pytest.raises(FetchError, match="escapes destination"):
            install_mod.extract_archive(archive, tmp_path / "dest")


def test_zircolite_reports_when_its_linux_rules_could_not_be_seeded(
    roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty rules/linux is silent at analysis time, so say so at install time.

    Zircolite ships no Linux Sigma rules; mulder copies them across from
    sigma-rules.  When that fetch failed, Zircolite still installs and still
    runs -- it simply detects nothing, forever, with no error.
    """

    def _fake_git(cmd: list[str], **_kwargs: Any) -> Any:
        import subprocess

        if cmd[1] == "clone":
            target = Path(cmd[-1])
            (target / ".git").mkdir(parents=True)
            (target / "zircolite.py").write_text("#!/usr/bin/env python3\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")

    monkeypatch.setattr(install_mod.subprocess, "run", _fake_git)
    fetcher = RecordingFetcher(roots[0])
    fetcher.fail.add("r2024-09-02.tar.gz")  # the sigma-rules tarball
    result = _run(roots, fetcher, {"zircolite", "sigma-rules"})

    outcomes = _by_key(result)
    assert outcomes["sigma-rules"].failed
    assert outcomes["zircolite"].status == "installed"
    assert "linux rules skipped" in outcomes["zircolite"].detail
    assert result.exit_code == 3


def test_volatility_symbols_bypass_the_asset_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-rooting them would orphan them from the ``vol`` on $PATH."""
    from mulder.assets.manifest import volatility_cache_dir

    monkeypatch.setenv("MULDER_ASSET_ROOT", "/somewhere/else")
    monkeypatch.setenv("XDG_CACHE_HOME", "/tmp/xdg")

    assert volatility_cache_dir() == Path("/tmp/xdg/volatility3/symbols")
    assert "/somewhere/else" not in str(volatility_cache_dir())


def test_setup_never_shells_out_to_a_package_manager(
    roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    forbidden = {"apt", "apt-get", "dpkg", "sudo", "snap", "brew", "npm", "pipx"}
    seen: list[str] = []

    def _record(cmd: list[str], **_kwargs: Any) -> Any:
        import subprocess

        seen.append(os.path.basename(cmd[0]))
        target = Path(cmd[-1])
        if cmd[1] == "clone":
            (target / ".git").mkdir(parents=True)
            (target / "yara").mkdir()
            (target / "pdfid.py").write_text("")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")

    monkeypatch.setattr(install_mod.subprocess, "run", _record)
    _run(roots, RecordingFetcher(roots[0]))

    assert forbidden.isdisjoint(seen)


class TestSummaryLine:
    """The last line is the one a human actually reads."""

    def _render(
        self, roots: tuple[Path, Path], keys: set[str] | None = None, **kwargs: Any
    ) -> str:
        from io import StringIO

        from rich.console import Console

        from mulder.assets.fetch import OfflineFetcher
        from mulder.cli import _print_summary

        plan, options = _plan(roots, keys, **kwargs)
        result = provision(plan, options, fetch=OfflineFetcher())
        buffer = StringIO()
        _print_summary(Console(file=buffer, width=200, no_color=True), result, plan, options)
        return buffer.getvalue()

    def test_a_verify_run_that_found_nothing_does_not_claim_everything_is_present(
        self, roots: tuple[Path, Path]
    ) -> None:
        """It used to print 'All 8 selected assets present.' under a table of
        eight 'missing' rows and a Consequences block listing what broke."""
        output = self._render(roots, verify=True)

        assert "missing - run 'mulder setup' to install them" in output
        assert "selected assets present" not in output


def test_a_corrupt_zip_is_reported_not_raised(roots: tuple[Path, Path]) -> None:
    """BadZipFile is not an OSError, so it used to escape as a traceback."""
    from mulder.assets.fetch import OfflineFetcher
    from mulder.assets.manifest import volatility_cache_dir

    cache = volatility_cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "linux.zip").write_bytes(b"not a zip at all")

    plan, options = _plan(roots, {"vol-symbols-linux"}, verify=True)
    result = provision(plan, options, fetch=OfflineFetcher())

    assert _by_key(result)["vol-symbols-linux"].status == "invalid"
    assert result.exit_code == 4
