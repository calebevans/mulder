"""Tests for security hardening: SQL authorizer, path validation, archive filters."""

from __future__ import annotations

import sqlite3
import tarfile

import pytest

from mulder.server.tools.artifacts import _readonly_authorizer
from mulder.server.tools.case import _safe_tar_filter


class TestSqliteAuthorizer:
    """Test the read-only SQLite authorizer."""

    def test_allows_select(self) -> None:
        result = _readonly_authorizer(sqlite3.SQLITE_SELECT, None, None, None, None)
        assert result == sqlite3.SQLITE_OK

    def test_allows_read(self) -> None:
        result = _readonly_authorizer(sqlite3.SQLITE_READ, None, None, None, None)
        assert result == sqlite3.SQLITE_OK

    def test_allows_function(self) -> None:
        result = _readonly_authorizer(sqlite3.SQLITE_FUNCTION, None, None, None, None)
        assert result == sqlite3.SQLITE_OK

    @pytest.mark.parametrize(
        "action",
        [
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_INSERT,
            sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_UPDATE,
            sqlite3.SQLITE_DROP_TABLE,
        ],
    )
    def test_blocks_write_operations(self, action: int) -> None:
        result = _readonly_authorizer(action, None, None, None, None)
        assert result == sqlite3.SQLITE_DENY


class TestSafeTarFilter:
    """Test the tar extraction path traversal filter."""

    def test_blocks_dotdot_in_name(self) -> None:
        member = tarfile.TarInfo("../../etc/passwd")
        result = _safe_tar_filter(member, "/tmp/dest")
        assert result is None

    def test_blocks_absolute_path(self) -> None:
        member = tarfile.TarInfo("/etc/passwd")
        result = _safe_tar_filter(member, "/tmp/dest")
        assert result is None

    def test_blocks_dotdot_in_linkname(self) -> None:
        member = tarfile.TarInfo("safe_name.txt")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../etc/shadow"
        result = _safe_tar_filter(member, "/tmp/dest")
        assert result is None

    def test_allows_safe_entry(self) -> None:
        member = tarfile.TarInfo("subdir/file.txt")
        result = _safe_tar_filter(member, "/tmp/dest")
        assert result is not None
        assert result.name == "subdir/file.txt"

    def test_strips_absolute_symlink_target(self) -> None:
        member = tarfile.TarInfo("link.txt")
        member.type = tarfile.SYMTYPE
        member.linkname = "/usr/lib/libfoo.so"
        result = _safe_tar_filter(member, "/tmp/dest")
        assert result is not None
        assert not result.linkname.startswith("/")

    def test_allows_relative_symlink(self) -> None:
        member = tarfile.TarInfo("link.txt")
        member.type = tarfile.SYMTYPE
        member.linkname = "target.txt"
        result = _safe_tar_filter(member, "/tmp/dest")
        assert result is not None
        assert result.linkname == "target.txt"

    def test_symlink_resolving_outside_target_blocked(self) -> None:
        """Symlink whose relative target resolves outside extraction root is blocked."""
        member = tarfile.TarInfo("subdir/escape_link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../etc/shadow"
        result = _safe_tar_filter(member, "/tmp/dest")
        assert result is None
