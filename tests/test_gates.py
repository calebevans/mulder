"""Tests for mulder.orchestrator.gates -- quality gate validation functions."""

from __future__ import annotations

from pathlib import Path

from mulder.orchestrator.gates import (
    validate_catalog,
    validate_cross_system,
    validate_extraction,
    validate_narrative,
    validate_report,
)


class TestValidateReport:
    """The report gate keys on the report file, not on the tool having been called (#211)."""

    def test_passes_when_report_exists(self, tmp_path: Path) -> None:
        report = tmp_path / "case.report.md"
        report.write_text("# Report")
        assert validate_report(["open_case", "finalize_report"], report).passed

    def test_fails_when_called_but_refused(self, tmp_path: Path) -> None:
        """The benchmark defect: finalize_report called, readiness refused, no file."""
        readiness = {
            "ready_to_finalize": False,
            "gates": [
                {"name": "minimum_findings", "passed": True, "detail": "ok"},
                {"name": "source_coverage", "passed": False, "detail": "cited 3 of 40 sources"},
            ],
        }
        result = validate_report(["finalize_report"], tmp_path / "case.report.md", readiness)
        assert not result.passed
        assert "source_coverage: cited 3 of 40 sources" in result.gaps[0]
        assert "minimum_findings" not in result.gaps[0]

    def test_refused_without_readiness_points_at_check(self, tmp_path: Path) -> None:
        result = validate_report(["finalize_report"], tmp_path / "case.report.md", None)
        assert not result.passed
        assert "check_finalize_readiness" in result.gaps[0]

    def test_fails_when_finalize_report_never_called(self, tmp_path: Path) -> None:
        result = validate_report(["open_case"], tmp_path / "case.report.md")
        assert not result.passed
        assert result.gaps == [
            "The report was not finalized. Call finalize_report to generate it."
        ]

    def test_stale_report_from_an_earlier_run_does_not_count(self, tmp_path: Path) -> None:
        report = tmp_path / "case.report.md"
        report.write_text("# Old")
        old = report.stat().st_mtime
        assert not validate_report(["finalize_report"], report, started_at=old + 60).passed


class TestValidateCatalog:
    """Tests for validate_catalog gate function."""

    def test_passes_with_complete_json(self) -> None:
        """Catalog JSON with case_id, evidence_root, and systems passes."""
        catalog_json = {
            "case_id": "incident-42",
            "evidence_root": "/evidence",
            "systems": [{"name": "host-a", "type": "Linux", "evidence": ["disk_image"]}],
        }
        result = validate_catalog(catalog_json)
        assert result.passed

    def test_fails_when_case_id_none(self) -> None:
        """JSON with case_id=None fails the case_created check."""
        catalog_json = {
            "case_id": None,
            "evidence_root": "/evidence",
            "systems": [{"name": "host-a"}],
        }
        result = validate_catalog(catalog_json)
        assert not result.passed

    def test_fails_on_empty_dict(self) -> None:
        """Empty dict fails all checks."""
        result = validate_catalog({})
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "case_created" in check_names
        assert "systems_identified" in check_names

    def test_fails_on_empty_systems(self) -> None:
        """Empty systems array fails the systems_identified check."""
        catalog_json = {
            "case_id": "test",
            "evidence_root": "/evidence",
            "systems": [],
        }
        result = validate_catalog(catalog_json)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "systems_identified" in check_names

    def test_fails_on_missing_evidence_root(self) -> None:
        """Missing evidence_root fails that specific check."""
        catalog_json = {
            "case_id": "test",
            "systems": [{"name": "host-a"}],
        }
        result = validate_catalog(catalog_json)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "evidence_discovered" in check_names


def _catalog(*names: str) -> dict[str, object]:
    return {
        "case_id": "ndlc",
        "evidence_root": "/evidence",
        "systems": [{"name": n, "evidence": ["disk_image"]} for n in names],
    }


def _touch(root: Path, *names: str) -> None:
    for n in names:
        (root / n).write_bytes(b"x")


class TestValidateCatalogImageCount:
    """One system per distinct disk image, or the gate fails (#237)."""

    def test_fewer_systems_than_images_fails_listing_images(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pc.E01", "pc.E02", "rm1.E01", "rm2.E01", "rm3.E01")
        result = validate_catalog(_catalog("cfreds_2015_data_leakage"), str(tmp_path))
        assert not result.passed
        assert [c.name for c in result.checks if not c.passed] == ["images_covered"]
        gap = result.gaps[0]
        assert "1 system(s)" in gap and "4 disk image(s)" in gap
        for name in ("pc.E01", "rm1.E01", "rm2.E01", "rm3.E01"):
            assert name in gap
        assert "pc.E02" not in gap

    def test_one_system_per_image_passes(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pc.E01", "rm1.E01", "rm2.E01", "rm3.E01")
        result = validate_catalog(_catalog("pc", "rm1", "rm2", "rm3"), str(tmp_path))
        assert result.passed

    def test_ewf_segments_count_as_one_image(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pc.E01", "pc.E02")
        assert validate_catalog(_catalog("pc"), str(tmp_path)).passed

    def test_memory_dump_is_not_a_system(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pc.E01", "pc-memory.mem", "capture.pcap", "notes.7z.001")
        assert validate_catalog(_catalog("pc"), str(tmp_path)).passed

    def test_unreadable_evidence_warns_instead_of_failing(self, tmp_path: Path) -> None:
        result = validate_catalog(_catalog("pc"), str(tmp_path / "missing"))
        assert result.passed
        check = next(c for c in result.checks if c.name == "images_covered")
        assert "not verified" in check.detail


class TestValidateCrossSystemWithData:
    """Tests for validate_cross_system with realistic data."""

    def test_passes_with_findings_and_mitre(self) -> None:
        """Summary with findings and mitre mappings passes both checks."""
        summary = {"findings_submitted": 5, "findings_with_mitre_ids": 3}
        result = validate_cross_system(summary)
        assert result.passed

    def test_fails_zero_findings(self) -> None:
        """Zero findings_submitted fails cross_system_findings check."""
        summary = {"findings_submitted": 0, "findings_with_mitre_ids": 0}
        result = validate_cross_system(summary)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "cross_system_findings" in check_names

    def test_fails_zero_mitre(self) -> None:
        """Zero findings_with_mitre_ids fails mitre_mapping check."""
        summary = {"findings_submitted": 3, "findings_with_mitre_ids": 0}
        result = validate_cross_system(summary)
        assert not result.passed
        check_names = [c.name for c in result.checks if not c.passed]
        assert "mitre_mapping" in check_names


class TestValidateNarrativeDeferral:
    """Tests for validate_narrative narrative_submitted deferral logic."""

    def test_narrative_submitted_false_still_passes(self) -> None:
        """narrative_submitted gate failing is deferred to report phase."""
        readiness = {
            "gates": [
                {"name": "minimum_findings", "passed": True, "detail": "3 findings"},
                {"name": "narrative_submitted", "passed": False, "detail": "not yet"},
            ]
        }
        result = validate_narrative(summary={"remaining_work": []}, readiness=readiness)
        assert result.passed

    def test_other_gate_failing_blocks(self) -> None:
        """A non-narrative failing gate causes overall failure."""
        readiness = {
            "gates": [
                {"name": "minimum_findings", "passed": False, "detail": "0 findings"},
                {"name": "narrative_submitted", "passed": False, "detail": "not yet"},
            ]
        }
        result = validate_narrative(summary={"remaining_work": []}, readiness=readiness)
        assert not result.passed

    def test_advisory_gate_passes_without_gaps(self) -> None:
        """An advisory readiness gate is logged, never a gap, so no retry follows."""
        readiness = {
            "gates": [
                {"name": "minimum_findings", "passed": True, "detail": "3 findings"},
                {
                    "name": "evidence_citation_coverage",
                    "passed": True,
                    "advisory": True,
                    "detail": "Advisory: 18.8% of evidence sources cited (3/16 distinct names)",
                },
            ]
        }
        result = validate_narrative(summary={"remaining_work": []}, readiness=readiness)
        assert result.passed
        assert result.gaps == []
        check = next(c for c in result.checks if c.name == "evidence_citation_coverage")
        assert check.passed
        assert "18.8%" in check.detail


class TestExtractionRetryFailure:
    """Tests for validate_extraction retry-aware failure tracking."""

    def test_first_none_passes_with_advisory(self) -> None:
        """First None summary passes with an advisory gap."""
        result = validate_extraction(None)
        assert result.passed
        assert any("ADVISORY" in g for g in result.gaps)

    def test_second_none_fails(self) -> None:
        """Consecutive None summaries fail the gate."""
        validate_extraction(None)
        result = validate_extraction(None)
        assert not result.passed
        assert any("retry" in g for g in result.gaps)

    def test_success_resets_counter(self) -> None:
        """A successful summary resets the failure counter."""
        validate_extraction(None)
        validate_extraction({"sources_indexed": 3})
        result = validate_extraction(None)
        assert result.passed

    def test_passes_with_sources(self) -> None:
        """Non-None summary with sources passes normally."""
        result = validate_extraction({"sources_indexed": 5})
        assert result.passed


class TestCrossSystemRetryFailure:
    """Tests for validate_cross_system retry-aware failure tracking."""

    def test_first_none_passes_with_advisory(self) -> None:
        """First None summary passes with an advisory gap."""
        result = validate_cross_system(None)
        assert result.passed
        assert any("ADVISORY" in g for g in result.gaps)

    def test_second_none_fails(self) -> None:
        """Consecutive None summaries fail the gate."""
        validate_cross_system(None)
        result = validate_cross_system(None)
        assert not result.passed
        assert any("retry" in g for g in result.gaps)

    def test_success_resets_counter(self) -> None:
        """A successful summary resets the failure counter."""
        validate_cross_system(None)
        validate_cross_system({"findings_submitted": 2, "findings_with_mitre_ids": 1})
        result = validate_cross_system(None)
        assert result.passed
