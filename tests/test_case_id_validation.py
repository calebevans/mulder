"""A case ID becomes a filesystem path, so it has to be a path segment.

``scan_evidence`` slugifies ``case_id`` only when it derives one itself::

    elif case_id is None:
        case_id = slugify(ev_path.name)

An ID supplied by an agent skipped that and went to the filesystem verbatim,
as ``db_dir / f"{case_id}.db"`` and every sidecar path beside it::

    db_dir  = /home/analyst/.mulder/cases
    case_id = "../../../../home/analyst/cases/CASE-2024-007"
    ->        /home/analyst/cases/CASE-2024-007.db

``open_case`` had the same hole and one more: ``scan_evidence`` and
``create_case`` both refuse to work on a case other than ``MULDER_CASE_ID``
when it is set, and ``open_case`` did not consult it at all. An agent pinned
to CASE-A could call ``open_case("CASE-B")``, and every subsequent finding,
note and export would be written to CASE-B.

The evidence tree is attacker-influenced -- ``scan_evidence`` renders file and
directory names back into the agent's context -- so "an agent would not do
that" is not a control.

The check is containment only. A case ID that contains no path separator is
exactly one component once a suffix is appended, and one component cannot be
``.`` or ``..``, so it cannot leave ``db_dir``. IDs that mulder accepted before
and that do not escape -- spaces, accents, leading dashes, embedded ``..`` --
still work, and the tests below pin that as hard as they pin the traversal.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mulder.server.app import slugify, validate_case_id


class TestWhatAValidIdLooksLike:
    @pytest.mark.parametrize(
        "case_id",
        [
            "CASE-2024-007",
            "case1",
            "a",
            "host_1.image",
            "0",
            # Accepted by mulder's CLI today, and none of them escape db_dir.
            "Incident 2026",
            "café",
            "-case",
            "case..2026",
            ".hidden",
            "中文",
            # A suffix is always appended, so even these stay one component:
            # db_dir / "..db", db_dir / "...db".
            ".",
            "..",
            "A" * 200,
        ],
    )
    def test_accepted(self, case_id: str) -> None:
        assert validate_case_id(case_id) == case_id

    @pytest.mark.parametrize(
        "case_id",
        [
            "../../../../home/analyst/cases/CASE-2024-007",
            "../shared/cases/CASE-B",
            "a/b",
            "/etc/passwd",
            "CASE-2024-007/",
            "",
        ],
    )
    def test_a_separator_is_rejected(self, case_id: str) -> None:
        with pytest.raises(ValueError, match="case_id"):
            validate_case_id(case_id)

    def test_the_platform_separator_is_rejected(self) -> None:
        """On Windows a backslash separates; on POSIX it is an ordinary character."""
        with pytest.raises(ValueError, match="case_id"):
            validate_case_id(f"a{os.sep}b")

    @pytest.mark.parametrize("case_id", ["case\x00id", "case\n", "\ncase", "case\x7f", "a\tb"])
    def test_a_control_character_is_rejected(self, case_id: str) -> None:
        """A NUL truncates the name under open(); the rest corrupt the audit log.

        A trailing newline is the one that a `$`-anchored regex would have let
        through, so it is pinned explicitly rather than left to the class.
        """
        with pytest.raises(ValueError, match="case_id"):
            validate_case_id(case_id)

    def test_slugify_output_is_always_valid(self) -> None:
        """The two functions must agree, or derived IDs would be refused."""
        for name in ("Evidence 2024/03", "../../etc", "!!!", "Host A"):
            assert validate_case_id(slugify(name))


class TestTheTraversalItWasBlocking:
    """The security boundary, asserted without assuming a filesystem layout."""

    def test_the_path_really_did_escape(self, tmp_path: Path) -> None:
        """Pin the premise rather than describing it."""
        db_dir = (tmp_path / "cases").resolve()
        db_dir.mkdir()
        escaping = "../../../../analyst/cases/CASE-2024-007"

        target = (db_dir / f"{escaping}.db").resolve()

        assert db_dir not in target.parents, "the premise: this ID left db_dir"
        with pytest.raises(ValueError, match="case_id"):
            validate_case_id(escaping)

    @pytest.mark.parametrize(
        "case_id", ["CASE-2024-007", "Incident 2026", "café", "-case", "case..2026", ".", ".."]
    )
    def test_an_accepted_id_stays_inside(self, tmp_path: Path, case_id: str) -> None:
        """Every ID the validator accepts must land directly in db_dir."""
        db_dir = (tmp_path / "cases").resolve()
        db_dir.mkdir()

        target = (db_dir / f"{validate_case_id(case_id)}.db").resolve()

        assert target.parent == db_dir

    def test_every_sidecar_suffix_stays_inside_too(self, tmp_path: Path) -> None:
        """The .db path is not the only one an ID is interpolated into."""
        db_dir = (tmp_path / "cases").resolve()
        db_dir.mkdir()
        case_id = validate_case_id("case..2026")

        for suffix in (".db", ".audit.jsonl", ".report.md", ".plaso", ".iocs.stix.json"):
            assert (db_dir / f"{case_id}{suffix}").resolve().parent == db_dir


@pytest.fixture
def initialised_server(tmp_path: Path) -> None:
    """open_case reaches get_cfg() only after the enforcement checks pass."""
    from mulder.server.app import init_server

    init_server(db_dir=tmp_path)


class TestOpenCaseHonoursTheEnforcedCase:
    def test_a_different_case_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, initialised_server: None
    ) -> None:
        from mulder.server.tools.case import open_case

        monkeypatch.setenv("MULDER_CASE_ID", "CASE-A")
        result = open_case.__wrapped__("CASE-B")  # type: ignore[attr-defined]
        assert result["status"] == "error"
        assert result["error_type"] == "forbidden"
        assert "CASE-A" in str(result["error_message"])

    def test_the_enforced_case_is_still_reachable(
        self, monkeypatch: pytest.MonkeyPatch, initialised_server: None
    ) -> None:
        """The guard must not block the case the agent is pinned to."""
        from mulder.server.tools.case import open_case

        monkeypatch.setenv("MULDER_CASE_ID", "CASE-A")
        result = open_case.__wrapped__("CASE-A")  # type: ignore[attr-defined]
        # It gets past the guard; the case does not exist in this environment.
        assert result["error_type"] == "not_found"

    def test_a_traversal_is_refused_before_anything_else(
        self, monkeypatch: pytest.MonkeyPatch, initialised_server: None
    ) -> None:
        from mulder.server.tools.case import open_case

        monkeypatch.delenv("MULDER_CASE_ID", raising=False)
        result = open_case.__wrapped__("../../shared/cases/CASE-B")  # type: ignore[attr-defined]
        assert result["error_type"] == "invalid_input"

    def test_no_enforcement_leaves_ordinary_use_alone(
        self, monkeypatch: pytest.MonkeyPatch, initialised_server: None
    ) -> None:
        from mulder.server.tools.case import open_case

        monkeypatch.delenv("MULDER_CASE_ID", raising=False)
        result = open_case.__wrapped__("CASE-B")  # type: ignore[attr-defined]
        assert result["error_type"] == "not_found"
