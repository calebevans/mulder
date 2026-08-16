"""Tests for the asset-root resolver.

The read-root / write-root split is the highest-risk decision in the asset
work: a single writability-tested resolver breaks the container, where ``/opt``
is ``root:root 0755`` and the server runs as ``mulder``.  These tests pin both
halves and the display helpers built on them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mulder.assets import paths


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start each test from an unset variable and a cold cache."""
    monkeypatch.delenv(paths.ENV_ASSET_ROOT, raising=False)
    paths.reset_asset_caches()


def _fake_opt(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, exists: bool = True) -> Path:
    """Point ``SYSTEM_ROOT`` at a tmp dir standing in for ``/opt``."""
    opt = tmp_path / "opt"
    if exists:
        opt.mkdir()
    monkeypatch.setattr(paths, "SYSTEM_ROOT", opt)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    paths.reset_asset_caches()
    return opt


class TestReadRoots:
    def test_env_var_is_exclusive(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A set MULDER_ASSET_ROOT is the *only* root, /opt included."""
        _fake_opt(monkeypatch, tmp_path)
        monkeypatch.setenv(paths.ENV_ASSET_ROOT, str(tmp_path / "pinned"))
        paths.reset_asset_caches()

        assert paths.asset_roots() == (tmp_path / "pinned",)

    def test_opt_first_then_user_root(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        opt = _fake_opt(monkeypatch, tmp_path)

        assert paths.asset_roots() == (opt, paths.user_root())

    def test_user_root_only_when_opt_absent(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _fake_opt(monkeypatch, tmp_path, exists=False)

        assert paths.asset_roots() == (paths.user_root(),)

    def test_env_change_takes_effect_without_a_flush(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The lru_cache key covers the variable, so tests need no bookkeeping."""
        monkeypatch.setenv(paths.ENV_ASSET_ROOT, str(tmp_path / "a"))
        assert paths.asset_roots() == (tmp_path / "a",)

        monkeypatch.setenv(paths.ENV_ASSET_ROOT, str(tmp_path / "b"))
        assert paths.asset_roots() == (tmp_path / "b",)


class TestLookups:
    def test_asset_path_returns_first_existing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        opt = _fake_opt(monkeypatch, tmp_path)
        (opt / "attack").mkdir()
        (opt / "attack" / "enterprise-attack.json").write_text("{}")
        user = paths.user_root() / "attack"
        user.mkdir(parents=True)
        (user / "enterprise-attack.json").write_text("{}")

        assert paths.asset_path("attack", "enterprise-attack.json") == (
            opt / "attack" / "enterprise-attack.json"
        )

    def test_asset_path_is_none_when_nothing_exists(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _fake_opt(monkeypatch, tmp_path)

        assert paths.asset_path("attack", "enterprise-attack.json") is None

    def test_search_summary_lists_every_candidate_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        opt = _fake_opt(monkeypatch, tmp_path)
        summary = paths.asset_search_summary("zimmermantools")

        assert summary == f"{opt / 'zimmermantools'}, {paths.user_root() / 'zimmermantools'}"


class TestDisplayPath:
    def test_falls_back_to_the_write_root_not_the_first_read_root(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Regression guard: naming ``/opt/...`` in a message is a lie.

        ``/opt`` exists on essentially every Linux host, so it is always read
        root #1 -- but with it unwritable, ``mulder setup`` provisions the user
        root instead.  A message (or a copy-pasteable ``pipx inject`` line)
        built from ``asset_roots()[0]`` names a path that will never exist.
        """
        opt = _fake_opt(monkeypatch, tmp_path)
        monkeypatch.setattr(paths.os, "access", lambda *_a, **_k: False)

        shown = paths.asset_display_path("aleapp", "requirements.txt")

        assert shown == paths.user_root() / "aleapp" / "requirements.txt"
        assert str(opt) not in str(shown)

    def test_prefers_an_installed_copy(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        opt = _fake_opt(monkeypatch, tmp_path)
        (opt / "aleapp").mkdir()
        (opt / "aleapp" / "aleapp.py").write_text("")

        assert paths.asset_display_path("aleapp", "aleapp.py") == opt / "aleapp" / "aleapp.py"


class TestWriteRoot:
    def test_env_wins_even_when_unwritable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Better to fail loudly than to write where the reader will not look."""
        monkeypatch.setenv(paths.ENV_ASSET_ROOT, "/definitely/not/writable")

        assert paths.asset_write_root() == Path("/definitely/not/writable")

    def test_opt_chosen_only_when_writable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        opt = _fake_opt(monkeypatch, tmp_path)
        monkeypatch.setattr(paths.os, "access", lambda *_a, **_k: True)
        assert paths.asset_write_root() == opt

        monkeypatch.setattr(paths.os, "access", lambda *_a, **_k: False)
        assert paths.asset_write_root() == paths.user_root()


class TestCacheClearing:
    def test_reset_clears_every_registered_consumer(self) -> None:
        """All four root-dependent caches must be flushed by one call."""
        from mulder.server.tools.attack import _load_attack_data  # noqa: F401
        from mulder.server.tools.extract.misc import _dotnet_major, _find_ez_tool
        from mulder.server.tools.phone import _find_leapp_cmd

        calls: list[str] = []
        paths.register_cache_clear(lambda: calls.append("probe"))
        paths.reset_asset_caches()

        assert calls == ["probe"]
        assert _find_ez_tool.cache_info().currsize == 0
        assert _find_leapp_cmd.cache_info().currsize == 0
        assert _dotnet_major.cache_info().currsize == 0

    def test_attack_cache_is_reset(self) -> None:
        import mulder.server.tools.attack as attack

        attack._attack_techniques = {"T1059": {}}
        paths.reset_asset_caches()

        assert attack._attack_techniques is None

    def test_yara_update_flag_is_rearmed(self) -> None:
        """A setup run that *creates* signature-base must allow a pull."""
        import mulder.server.tools.yara as yara

        yara._rules_updated = True
        paths.reset_asset_caches()

        assert yara._rules_updated is False


def test_no_module_outside_paths_uses_the_first_read_root() -> None:
    """``asset_roots()[0]`` is how the display-path bug was written.

    Every user-visible path comes from ``asset_display_path`` (one location) or
    ``asset_search_summary`` (a failed search); indexing the read roots
    directly reintroduces the ``/opt``-that-will-never-exist message.
    """
    src = Path(__file__).resolve().parents[1] / "src" / "mulder"
    pattern = re.compile(r"asset_roots\(\)\s*\[")
    offenders = [
        str(path.relative_to(src))
        for path in src.rglob("*.py")
        if path.name != "paths.py" and pattern.search(path.read_text(encoding="utf-8"))
    ]

    assert offenders == []
