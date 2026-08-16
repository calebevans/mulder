"""EZ Tools DLL selection.

Three defects lived in four lines: ``rglob`` order is filesystem order (so the
choice between ``net6/`` and ``net9/`` copies was nondeterministic), the
runtime that can actually *run* the DLL was never consulted (a net9 DLL under
net8 fails as "produced no CSV output", not as a version mismatch), and a
single root meant mulder's downloads could shadow SIFT's version-matched copies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mulder.assets import paths
from mulder.server.tools.extract.misc import _find_ez_tool, _framework_rank


@pytest.fixture(autouse=True)
def _cold_caches() -> None:
    paths.reset_asset_caches()


def _place(root: Path, *relative: str) -> Path:
    target = root.joinpath(*relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("")
    return target


@pytest.mark.parametrize(
    ("installed_dotnet", "layout", "expected"),
    [
        # net9 cannot run on dotnet 8; roll-forward covers net6, so it wins.
        (8, ("net6/PECmd.dll", "net9/PECmd.dll"), "net6/PECmd.dll"),
        (9, ("net6/PECmd.dll", "net9/PECmd.dll"), "net9/PECmd.dll"),
        # No ceiling to apply: degrade to highest-netN.
        (None, ("net6/PECmd.dll", "net9/PECmd.dll"), "net9/PECmd.dll"),
        # The container's flat layout: one candidate, no netN component.
        (9, ("PECmd.dll",), "PECmd.dll"),
        # Nothing runnable; return what there is and let doctor explain.
        (8, ("net9/PECmd.dll",), "net9/PECmd.dll"),
    ],
)
def test_selection_matrix(
    asset_root: Path, installed_dotnet: int | None, layout: tuple[str, ...], expected: str
) -> None:
    for relative in layout:
        _place(asset_root, "zimmermantools", *relative.split("/"))

    with patch("mulder.server.tools.extract.misc._dotnet_major", return_value=installed_dotnet):
        selected = _find_ez_tool("PECmd.dll")

    assert selected == str(asset_root / "zimmermantools" / expected)


def test_selection_is_stable_against_filesystem_ordering(asset_root: Path) -> None:
    """``rglob`` yields in ``os.scandir`` order; ``sorted()`` is the guard."""
    for relative in ("net6/PECmd.dll", "net8/PECmd.dll", "net9/PECmd.dll"):
        _place(asset_root, "zimmermantools", *relative.split("/"))

    real_rglob = Path.rglob

    def _make_shuffled(reverse: bool) -> Any:
        def _shuffled(self: Path, pattern: str) -> list[Path]:
            return sorted(real_rglob(self, pattern), reverse=reverse)

        return _shuffled

    results = []
    for reverse in (False, True):
        with (
            patch("mulder.server.tools.extract.misc._dotnet_major", return_value=9),
            patch.object(Path, "rglob", _make_shuffled(reverse)),
        ):
            _find_ez_tool.cache_clear()
            results.append(_find_ez_tool("PECmd.dll"))

    assert results[0] == results[1] == str(asset_root / "zimmermantools" / "net9" / "PECmd.dll")


def test_platform_root_is_searched_before_mulder_s_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SIFT's DLLs are version-matched to SIFT's dotnet; never shadow them."""
    platform_root = tmp_path / "opt"
    user_root = tmp_path / "home-assets"
    _place(platform_root, "zimmermantools", "net6", "PECmd.dll")
    _place(user_root, "zimmermantools", "net9", "PECmd.dll")

    monkeypatch.delenv(paths.ENV_ASSET_ROOT, raising=False)
    monkeypatch.setattr(paths, "SYSTEM_ROOT", platform_root)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "fake-home")
    monkeypatch.setattr(paths, "user_root", lambda: user_root)
    paths.reset_asset_caches()

    with patch("mulder.server.tools.extract.misc._dotnet_major", return_value=9):
        selected = _find_ez_tool("PECmd.dll")

    assert selected == str(platform_root / "zimmermantools" / "net6" / "PECmd.dll")


def test_a_flat_dll_always_counts_as_runnable() -> None:
    """No netN component means no claim about the runtime it needs."""
    runnable, best, _ = _framework_rank(Path("/opt/zimmermantools/PECmd.dll"), ceiling=6)

    assert (runnable, best) == (1, -1)


def test_error_names_every_root_that_was_searched(asset_root: Path) -> None:
    from mulder.server.tools.extract.misc import _run_ez_tool

    with patch("mulder.server.tools.extract.misc.require_binary", return_value="/usr/bin/dotnet"):
        result = _run_ez_tool("PECmd.dll", [], "ez.prefetch", "/evidence", "tc", "t", {}, 0.0)

    assert result["error_type"] == "binary_missing"
    assert str(asset_root / "zimmermantools") in str(result["error_message"])
    assert "mulder setup" in str(result["error_message"])
