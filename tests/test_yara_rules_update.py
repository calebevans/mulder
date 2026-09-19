"""The YARA community-rule refresh must not try to pull into a clone it cannot write."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import pytest

from mulder.server.tools import yara


@pytest.fixture
def clone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "signature-base"
    (base / ".git").mkdir(parents=True)
    monkeypatch.setattr(yara, "_signature_base_dir", lambda: base)
    yara._reset_rules_updated()
    return base


def test_read_only_clone_skips_the_pull_with_one_info_line(
    clone: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("mulder.server.tools.yara.os.access", lambda *_: False)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "mulder.server.tools.yara.subprocess.run", lambda cmd, **_: calls.append(cmd)
    )

    with caplog.at_level(logging.INFO, logger=yara.logger.name):
        yara._update_community_rules()
        yara._update_community_rules()

    assert calls == []
    infos = [r for r in caplog.records if "using the installed checkout" in r.message]
    assert [r.levelno for r in infos] == [logging.INFO]


def test_writable_clone_still_pulls(clone: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("mulder.server.tools.yara.subprocess.run", fake_run)
    yara._update_community_rules()

    assert calls == [["git", "-C", str(clone), "pull", "--ff-only", "-q"]]
