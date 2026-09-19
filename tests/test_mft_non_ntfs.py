"""run_mft_parser must not try icat/mount on a volume that has no $MFT."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

_MISC = "mulder.server.tools.extract.misc"


@patch(f"{_MISC}.mount_disk_image")
@patch(f"{_MISC}.subprocess.run")
@patch(f"{_MISC}._detect_filesystem_type", return_value="exfat")
@patch(f"{_MISC}._resolve_partition_offset", return_value=0)
@patch(f"{_MISC}.sources_already_indexed", return_value=[])
def test_non_ntfs_is_skipped_before_icat_or_mount(
    mock_sources: MagicMock,
    mock_offset: MagicMock,
    mock_fs: MagicMock,
    mock_run: MagicMock,
    mock_mount: MagicMock,
) -> None:
    from mulder.server.tools.extract.misc import run_mft_parser

    result = run_mft_parser.__wrapped__("/fake/rm1.E01")  # type: ignore[attr-defined]

    assert result["status"] == "success"
    assert result["source"] == "ez.mft"
    assert '"status": "skipped"' in result["preview"]
    assert "filesystem is exfat" in result["preview"]
    mock_fs.assert_called_once_with("/fake/rm1.E01", 0)
    mock_run.assert_not_called()
    mock_mount.assert_not_called()


@patch(f"{_MISC}.mount_disk_image", side_effect=RuntimeError("no mount"))
@patch(f"{_MISC}.require_binary", return_value=None)
@patch(f"{_MISC}._detect_filesystem_type", return_value=None)
@patch(f"{_MISC}._resolve_partition_offset", return_value=0)
@patch(f"{_MISC}.sources_already_indexed", return_value=[])
def test_unknown_filesystem_still_attempts_extraction(
    mock_sources: MagicMock,
    mock_offset: MagicMock,
    mock_fs: MagicMock,
    mock_req: MagicMock,
    mock_mount: MagicMock,
) -> None:
    from mulder.server.tools.extract.misc import run_mft_parser

    result = run_mft_parser.__wrapped__("/fake/disk.E01")  # type: ignore[attr-defined]

    assert result["status"] == "error"
    assert "$MFT not found" in result["error_message"]
    mock_mount.assert_called_once()
