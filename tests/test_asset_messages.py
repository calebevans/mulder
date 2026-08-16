"""Every user-facing path in an error must be one that can actually exist.

``/opt`` is a directory on essentially every Linux host, so it is always read
root #1 -- but on a rootless install ``mulder setup`` provisions
``~/.local/share/mulder/assets``.  A message (or worse, a copy-pasteable
``pipx inject --requirements ...`` line) built from the first *read* root names
a path that will never exist.  These tests pin the write root as the fallback.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest

from mulder.assets import paths


@pytest.fixture()
def unwritable_opt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """``/opt`` exists but cannot be written, and nothing is installed."""
    opt = tmp_path / "opt"
    opt.mkdir()
    home = tmp_path / "home"
    home.mkdir()

    monkeypatch.delenv(paths.ENV_ASSET_ROOT, raising=False)
    monkeypatch.setattr(paths, "SYSTEM_ROOT", opt)
    # The user read root is derived from $HOME inside the resolver, so patching
    # ``user_root`` alone would leave the second candidate pointing at the
    # developer's real home directory.
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(paths.os, "access", lambda *_a, **_k: False)
    paths.reset_asset_caches()
    yield opt
    paths.reset_asset_caches()


def _text(result: dict[str, object]) -> str:
    return f"{result.get('error_message', '')} {result.get('suggestion', '')}"


def test_attack_points_at_the_write_root_and_at_setup(unwritable_opt: Path) -> None:
    from mulder.server.tools.attack import lookup_attack_technique

    result = lookup_attack_technique.__wrapped__("T1059")  # type: ignore[attr-defined]
    message = _text(result)

    assert result["error_type"] == "file_not_found"
    assert str(paths.user_root() / "attack") in message
    assert "mulder setup" in message
    # The old text told the user to give up and use the container.
    assert "run inside the container" not in message


def test_zircolite_no_longer_tells_the_user_to_clone_into_opt(unwritable_opt: Path) -> None:
    from mulder.server.tools.zircolite import run_zircolite

    with (
        patch("mulder.server.tools.zircolite.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.zircolite.importlib.util.find_spec", return_value=object()),
    ):
        result = run_zircolite.__wrapped__("/fake/audit.log")  # type: ignore[attr-defined]
    message = _text(result)

    assert "git clone" not in message
    assert "mulder setup" in message
    assert str(paths.user_root() / "zircolite") in message


def test_chainsaw_names_both_searched_roots(unwritable_opt: Path) -> None:
    from mulder.server.tools.chainsaw import run_chainsaw

    with (
        patch("mulder.server.tools.chainsaw.sources_already_indexed", return_value=[]),
        patch("mulder.server.helpers.shutil.which", return_value=None),
    ):
        result = run_chainsaw.__wrapped__("/fake/evtx")  # type: ignore[attr-defined]
    message = _text(result)

    assert str(unwritable_opt / "chainsaw") in message
    assert str(paths.user_root() / "chainsaw") in message
    assert "mulder setup" in message


def test_hayabusa_names_both_searched_roots(unwritable_opt: Path) -> None:
    from mulder.server.tools.hayabusa import run_hayabusa

    with (
        patch("mulder.server.tools.hayabusa.sources_already_indexed", return_value=[]),
        patch("mulder.server.tools.hayabusa.shutil.which", return_value=None),
    ):
        result = run_hayabusa.__wrapped__(evtx_dir="/fake/evtx")  # type: ignore[attr-defined]
    message = _text(result)

    assert str(paths.user_root() / "hayabusa") in message
    assert "mulder setup" in message


def test_documents_no_longer_hardcodes_the_didier_stevens_path(
    unwritable_opt: Path, tmp_path: Path
) -> None:
    from mulder.server.tools.documents import analyze_pdf

    with patch("mulder.server.tools.documents.require_binary", return_value=None):
        result = analyze_pdf.__wrapped__("case", str(tmp_path / "x.pdf"))  # type: ignore[attr-defined]
    message = _text(result)

    assert str(paths.user_root() / "didier-stevens") in message
    assert "mulder setup" in message


def test_eztools_error_lists_every_root(unwritable_opt: Path) -> None:
    from mulder.server.tools.extract.misc import _run_ez_tool

    with patch("mulder.server.tools.extract.misc.require_binary", return_value="/usr/bin/dotnet"):
        result = _run_ez_tool("PECmd.dll", [], "ez.prefetch", "/e", "tc", "t", {}, 0.0)
    message = _text(result)

    assert str(unwritable_opt / "zimmermantools") in message
    assert str(paths.user_root() / "zimmermantools") in message


def test_aleapp_suggests_an_injectable_requirements_path(unwritable_opt: Path) -> None:
    """The exact string the first-read-root fallback would have got wrong.

    ``pipx inject mulder-dfir --requirements /opt/aleapp/requirements.txt`` is
    copy-pasteable and cannot work: nothing will ever create ``/opt/aleapp``
    on a rootless install.
    """
    from mulder.server.tools.phone import run_aleapp

    with (
        patch("mulder.server.tools.phone.require_binary", return_value="/usr/bin/aleapp"),
        patch("mulder.server.tools.phone._find_leapp_cmd", return_value=None),
    ):
        result = run_aleapp.__wrapped__(str(unwritable_opt))  # type: ignore[attr-defined]
    message = _text(result)

    assert str(paths.user_root() / "aleapp" / "requirements.txt") in message
    assert "/opt/aleapp/requirements.txt" not in message
    assert "mulder setup --full --inject-deps" in message


def test_ileapp_suggests_an_injectable_requirements_path(unwritable_opt: Path) -> None:
    from mulder.server.tools.phone import run_ileapp

    with (
        patch("mulder.server.tools.phone.require_binary", return_value="/usr/bin/ileapp"),
        patch("mulder.server.tools.phone._find_leapp_cmd", return_value=None),
    ):
        result = run_ileapp.__wrapped__(str(unwritable_opt))  # type: ignore[attr-defined]
    message = _text(result)

    assert str(paths.user_root() / "ileapp" / "requirements.txt") in message
    assert "/opt/ileapp/requirements.txt" not in message


def test_yara_names_setup_when_no_rules_are_installed() -> None:
    from mulder.server.tools.yara import _ERR_NO_RULES

    assert "mulder setup" in _ERR_NO_RULES


#: The nine directories mulder itself owns.  ``/opt/zeek/bin/zeek`` and
#: ``/opt/chainsaw`` are deliberately absent: those are platform install
#: prefixes the container puts on ``PATH``, not paths mulder provisions.
_MULDER_OWNED = (
    "/opt/attack",
    "/opt/aleapp",
    "/opt/didier-stevens",
    "/opt/hayabusa",
    "/opt/ileapp",
    "/opt/sigma-rules",
    "/opt/signature-base",
    "/opt/zimmermantools",
    "/opt/zircolite",
)


def test_no_source_file_hardcodes_a_mulder_owned_opt_path() -> None:
    """The manual-provisioning instructions are gone, not merely supplemented."""
    src = Path(__file__).resolve().parents[1] / "src" / "mulder"
    offenders = [
        f"{path.relative_to(src)}: {literal}"
        for path in src.rglob("*.py")
        for literal in _MULDER_OWNED
        if literal in path.read_text(encoding="utf-8")
    ]

    assert offenders == []
