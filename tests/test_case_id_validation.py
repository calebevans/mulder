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
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mulder.server.app import slugify, validate_case_id


class TestWhatAValidIdLooksLike:
    @pytest.mark.parametrize(
        "case_id",
        ["CASE-2024-007", "case1", "a", "host_1.image", "0", "A" * 128],
    )
    def test_accepted(self, case_id: str) -> None:
        assert validate_case_id(case_id) == case_id

    @pytest.mark.parametrize(
        "case_id",
        [
            "../../../../home/analyst/cases/CASE-2024-007",
            "../shared/cases/CASE-B",
            "..",
            "a/b",
            "a\\b",
            "/etc/passwd",
            ".hidden",
            "-leading-dash",
            "",
            "a" * 129,
            "case\x00id",
            "case id",
        ],
    )
    def test_rejected(self, case_id: str) -> None:
        with pytest.raises(ValueError, match="case_id"):
            validate_case_id(case_id)

    def test_slugify_output_is_always_valid(self) -> None:
        """The two functions must agree, or derived IDs would be refused."""
        for name in ("Evidence 2024/03", "../../etc", "!!!", "Host A"):
            assert validate_case_id(slugify(name))


class TestTheTraversalItWasBlocking:
    def test_the_path_really_did_escape(self) -> None:
        """Pin the premise rather than describing it."""
        db_dir = Path("/home/analyst/.mulder/cases")
        target = (db_dir / "../../../../home/analyst/cases/CASE-2024-007.db").resolve()
        assert target == Path("/home/analyst/cases/CASE-2024-007.db")
        assert db_dir.resolve() not in target.parents

    def test_a_valid_id_stays_inside(self) -> None:
        db_dir = Path("/home/analyst/.mulder/cases")
        target = (db_dir / f"{validate_case_id('CASE-2024-007')}.db").resolve()
        assert target.parent == db_dir.resolve()


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
