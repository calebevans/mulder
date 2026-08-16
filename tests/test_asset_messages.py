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


#: /opt paths mulder used to hardcode. Each must now go through
#: ``mulder.assets.paths``; a literal here means a rootless install cannot see it.
_MULDER_OWNED = (
    "/opt/attack",
    "/opt/sigma-rules",
    "/opt/signature-base",
    "/opt/zircolite",
    "/opt/chainsaw",
    "/opt/hayabusa",
    "/opt/didier-stevens",
    "/opt/aleapp",
    "/opt/ileapp",
    "/opt/zimmermantools",
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
