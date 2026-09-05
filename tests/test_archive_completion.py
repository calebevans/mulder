"""Two ways ``extract_archive`` reported the wrong files.

**A partial extraction read as a finished one.** The idempotency check was
``dest.exists() and any(dest.iterdir())``. A run that hit the 600 s timeout
after writing 40 of 900 files leaves a non-empty directory behind; the retry
saw it, returned ``status: already_extracted`` with those 40 files and a
message telling the agent to proceed with analysis, and the other 860 were
never mentioned again. Completion is now recorded explicitly and read back.

**Plain compressed files were routed to tarfile.** The dispatch sent any
``.gz``/``.bz2`` whose name did not contain ``.tar`` to ``_extract_tar``::

    or (ext in (".gz", ".bz2") and ".tar" not in name_lower)

``auth.log.gz`` is a gzip stream, not a tar, so ``tarfile.open(..., "r:*")``
raises ``ReadError: file could not be opened successfully`` and the log --
which ``scan_evidence`` had classified as evidence and told the agent to
extract -- never reached the case. Compressed single-file logs are most of the
Linux evidence in a triage collection.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
import zipfile
from pathlib import Path

import pytest

from mulder.server.tools.case import (
    _COMPLETION_MARKER,
    ArchiveLimitError,
    _extract_single_file,
    _extract_tar,
    _extraction_is_complete,
    _listing,
    _mark_extraction_complete,
)


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "triage.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.txt", "one")
    return path


class TestCompletionIsRecordedNotInferred:
    def test_a_fresh_directory_is_not_complete(self, tmp_path: Path, archive: Path) -> None:
        dest = tmp_path / "out"
        dest.mkdir()
        assert _extraction_is_complete(dest, archive) is False

    def test_a_partial_extraction_is_not_complete(self, tmp_path: Path, archive: Path) -> None:
        """The bug: files on disk from a run that never finished."""
        dest = tmp_path / "out"
        dest.mkdir()
        (dest / "partial-1.evtx").write_text("x")
        (dest / "partial-2.evtx").write_text("x")

        assert any(dest.iterdir()), "the old check would have said yes here"
        assert _extraction_is_complete(dest, archive) is False

    def test_a_finished_extraction_is_complete(self, tmp_path: Path, archive: Path) -> None:
        dest = tmp_path / "out"
        dest.mkdir()
        (dest / "a.txt").write_text("one")
        _mark_extraction_complete(dest, archive, 1)

        assert _extraction_is_complete(dest, archive) is True

    def test_a_marker_for_a_different_archive_does_not_count(
        self, tmp_path: Path, archive: Path
    ) -> None:
        other = tmp_path / "other.zip"
        with zipfile.ZipFile(other, "w") as z:
            z.writestr("b.txt", "two")

        dest = tmp_path / "out"
        dest.mkdir()
        _mark_extraction_complete(dest, other, 1)

        assert _extraction_is_complete(dest, archive) is False

    def test_a_changed_archive_invalidates_the_marker(self, tmp_path: Path, archive: Path) -> None:
        """Re-collected evidence under the same name must not be skipped."""
        dest = tmp_path / "out"
        dest.mkdir()
        _mark_extraction_complete(dest, archive, 1)

        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("a.txt", "one")
            z.writestr("b.txt", "a second file, so the size differs")

        assert _extraction_is_complete(dest, archive) is False

    def test_a_corrupt_marker_is_not_trusted(self, tmp_path: Path, archive: Path) -> None:
        dest = tmp_path / "out"
        dest.mkdir()
        (dest / _COMPLETION_MARKER).write_text("{not json")

        assert _extraction_is_complete(dest, archive) is False

    def test_the_marker_is_not_reported_as_evidence(self, tmp_path: Path, archive: Path) -> None:
        """It is mulder's bookkeeping, not a file that came out of the archive."""
        dest = tmp_path / "out"
        dest.mkdir()
        (dest / "a.txt").write_text("one")
        _mark_extraction_complete(dest, archive, 1)

        assert _listing(dest) == ["a.txt"]


class TestSingleFileDecompression:
    def test_a_plain_gzip_log_is_extracted(self, tmp_path: Path) -> None:
        content = "Failed password for root from 10.0.0.1\n" * 100
        path = tmp_path / "auth.log.gz"
        with gzip.open(path, "wt") as fh:
            fh.write(content)

        dest = tmp_path / "out"
        dest.mkdir()
        files, skipped = _extract_single_file(path, dest)

        assert files == ["auth.log"]
        assert skipped == []
        assert (dest / "auth.log").read_text() == content

    def test_tarfile_really_cannot_read_it(self, tmp_path: Path) -> None:
        """Pin the premise: this is what the old dispatch did with it."""
        path = tmp_path / "auth.log.gz"
        with gzip.open(path, "wt") as fh:
            fh.write("some log line\n")

        dest = tmp_path / "out"
        dest.mkdir()
        with pytest.raises(tarfile.ReadError):
            _extract_tar(path, dest)

    def test_bzip2_and_xz_are_handled(self, tmp_path: Path) -> None:
        for name, opener in (("a.log.bz2", bz2.open), ("b.log.xz", lzma.open)):
            path = tmp_path / name
            with opener(path, "wt") as fh:  # type: ignore[operator]
                fh.write("line\n")
            dest = tmp_path / f"out-{name}"
            dest.mkdir()
            files, _ = _extract_single_file(path, dest)
            assert files == [name.rsplit(".", 1)[0]]

    def test_a_decompression_bomb_is_refused(self, tmp_path: Path) -> None:
        """A .gz of zeroes expands without limit; the cap must still apply."""
        from mulder.server.tools import case as case_module

        path = tmp_path / "bomb.log.gz"
        with gzip.open(path, "wb") as fh:
            fh.write(b"\0" * (8 * 1024 * 1024))

        dest = tmp_path / "out"
        dest.mkdir()
        original = case_module.MAX_EXTRACT_BYTES
        case_module.MAX_EXTRACT_BYTES = 1024
        try:
            with pytest.raises(ArchiveLimitError):
                _extract_single_file(path, dest)
        finally:
            case_module.MAX_EXTRACT_BYTES = original

        assert _listing(dest) == [], "the partial output must not be left behind"

    def test_a_tar_gz_is_still_a_tar(self, tmp_path: Path) -> None:
        """The dispatch must not send .tar.gz down the single-file path."""
        member = tmp_path / "inside.txt"
        member.write_text("evidence")
        path = tmp_path / "bundle.tar.gz"
        with tarfile.open(path, "w:gz") as tf:
            tf.add(member, arcname="inside.txt")

        dest = tmp_path / "out"
        dest.mkdir()
        files, _ = _extract_tar(path, dest)
        assert files == ["inside.txt"]
