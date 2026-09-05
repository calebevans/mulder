"""Archive extraction trusted both the archive and the caller.

Four boundaries were missing or wrong.

**The destination.** ``extract_archive`` accepted an arbitrary ``extract_to``,
expanded it and used it verbatim, contradicting its own docstring ("creates a
directory under the mulder cases dir"). A malicious archive plus a steered
destination writes attacker-chosen files anywhere the process can reach --
and both the archive and the steer can come from the evidence tree, which
``scan_evidence`` renders back into the agent's context.

**The default destination.** ``<db_dir>/extracted/<archive.stem>`` ignores
where the archive came from. A case holding ``/evidence/host1/logs.zip`` and
``/evidence/host2/logs.zip`` gives both the same directory, so the second call
finds it populated and returns **host 1's files** as ``already_extracted``,
with a message telling the agent to analyse them. In a triage case that is the
normal shape of the evidence, not an edge case.

**The member filter.** ``member.startswith("/") or ".." in member`` answers a
question about substrings, not about where the member lands. It drops
``logs/app..2024-03-01.log`` and ``Users/j..smith/NTUSER.DAT`` -- ordinary
evidence -- and reports success with a file list that never contained them, so
the caller cannot tell anything was lost.

**Resource limits.** There were none: no cap on uncompressed size, member
count or compression ratio, and no timeout at all on the Python paths. The
tool's own ``scan_evidence`` message tells the agent to extract any archive it
finds, so a 42.zip in the evidence fills the filesystem holding the live case
database.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from mulder.server.tools.case import (
    MAX_COMPRESSION_RATIO,
    ArchiveLimitError,
    _archive_slot,
    _extract_tar,
    _extract_zip,
    _is_contained,
    _safe_tar_filter,
)


class TestContainment:
    @pytest.mark.parametrize(
        "name",
        ["../../etc/passwd", "a/../../b", "/etc/passwd", "\\\\windows\\\\system32", "", "a\x00b"],
    )
    def test_rejected(self, tmp_path: Path, name: str) -> None:
        assert _is_contained(tmp_path, name) is False

    @pytest.mark.parametrize(
        "name",
        [
            "normal.txt",
            "sub/dir/file.txt",
            "invoice..pdf",
            "logs/app..2024-03-01.log",
            "Users/j..smith/NTUSER.DAT",
            "v1..2/config",
        ],
    )
    def test_accepted(self, tmp_path: Path, name: str) -> None:
        """Every one of these was dropped by the substring check."""
        assert _is_contained(tmp_path, name) is True


class TestZipExtraction:
    @staticmethod
    def _archive(tmp_path: Path, names: dict[str, str]) -> Path:
        path = tmp_path / "a.zip"
        with zipfile.ZipFile(path, "w") as z:
            for name, content in names.items():
                z.writestr(name, content)
        return path

    def test_a_traversing_member_is_not_written(self, tmp_path: Path) -> None:
        archive = self._archive(tmp_path, {"../../escaped.txt": "pwned", "normal.txt": "ok"})
        dest = tmp_path / "out"
        dest.mkdir()

        files, skipped = _extract_zip(archive, dest)

        assert files == ["normal.txt"]
        assert skipped == ["../../escaped.txt"]
        assert not (tmp_path.parent / "escaped.txt").exists()

    def test_legitimately_named_evidence_is_kept(self, tmp_path: Path) -> None:
        """The names the old filter silently discarded."""
        archive = self._archive(
            tmp_path,
            {
                "logs/app..2024-03-01.log": "evidence",
                "Users/j..smith/NTUSER.DAT": "evidence",
            },
        )
        dest = tmp_path / "out"
        dest.mkdir()

        files, skipped = _extract_zip(archive, dest)

        assert sorted(files) == [
            "Users/j..smith/NTUSER.DAT",
            "logs/app..2024-03-01.log",
        ]
        assert skipped == []

    def test_a_bomb_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "bomb.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("big", b"\0" * (50 * 1024 * 1024))

        info = zipfile.ZipFile(path).infolist()[0]
        ratio = info.file_size / info.compress_size
        assert ratio > MAX_COMPRESSION_RATIO, "the fixture must actually be a bomb"

        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(ArchiveLimitError, match="ratio limit"):
            _extract_zip(path, dest)

    def test_ordinary_compression_is_not_refused(self, tmp_path: Path) -> None:
        """Logs compress well; the limit must leave room for real evidence."""
        path = tmp_path / "logs.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("auth.log", "Failed password for root from 10.0.0.1\n" * 20_000)

        dest = tmp_path / "out"
        dest.mkdir()
        files, _ = _extract_zip(path, dest)
        assert files == ["auth.log"]


class TestTarExtraction:
    def test_a_traversing_member_is_skipped(self, tmp_path: Path) -> None:
        payload = tmp_path / "payload"
        payload.write_text("pwned")
        archive = tmp_path / "a.tar"
        with tarfile.open(archive, "w") as tf:
            tf.add(payload, arcname="../../escaped.txt")
            tf.add(payload, arcname="normal.txt")

        dest = tmp_path / "out"
        dest.mkdir()
        files, skipped = _extract_tar(archive, dest)

        assert files == ["normal.txt"]
        assert skipped == ["../../escaped.txt"]

    def test_a_symlink_out_of_the_tree_is_skipped(self, tmp_path: Path) -> None:
        archive = tmp_path / "a.tar"
        with tarfile.open(archive, "w") as tf:
            member = tarfile.TarInfo("link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../../../etc/shadow"
            tf.addfile(member)

        dest = tmp_path / "out"
        dest.mkdir()
        files, skipped = _extract_tar(archive, dest)

        assert files == []
        assert skipped == ["link"]

    def test_the_filter_still_relativises_an_absolute_link(self, tmp_path: Path) -> None:
        member = tarfile.TarInfo("link.txt")
        member.type = tarfile.SYMTYPE
        member.linkname = "/usr/lib/libfoo.so"

        result = _safe_tar_filter(member, str(tmp_path))

        assert result is not None
        assert result.linkname == "usr/lib/libfoo.so"


class TestTheDestinationName:
    def test_two_hosts_do_not_collide(self) -> None:
        """The whole reason the idempotency check returned the wrong host."""
        one = _archive_slot(Path("/evidence/host1/logs.zip"))
        two = _archive_slot(Path("/evidence/host2/logs.zip"))
        assert one != two

    def test_it_is_a_single_path_segment(self) -> None:
        slot = _archive_slot(Path("/evidence/host 1/My Logs (final).zip"))
        assert "/" not in slot
        assert ".." not in slot

    def test_it_is_stable(self) -> None:
        """Idempotency depends on the same archive producing the same slot."""
        assert _archive_slot(Path("/evidence/host1/logs.zip")) == _archive_slot(
            Path("/evidence/host1/logs.zip")
        )

    def test_the_archive_name_is_still_readable_in_it(self) -> None:
        assert _archive_slot(Path("/evidence/host1/logs.zip")).startswith("logs-")
