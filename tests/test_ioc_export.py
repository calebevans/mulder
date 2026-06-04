"""Tests for STIX 2.1 IOC export and CSV export format."""

from __future__ import annotations

import csv
import io
from typing import Any

from mulder.models import Finding
from mulder.report.ioc_export import (
    _ioc_to_stix_pattern,
    build_csv,
    build_stix_bundle,
)


def _make_finding(
    description: str,
    mitre_ids: list[str] | None = None,
) -> Finding:
    """Create a minimal Finding for IOC extraction tests."""
    return Finding(
        finding_id="f-test-001",
        case_id="test-case",
        title="Test Finding",
        description=description,
        severity="high",
        confidence="confirmed",
        evidence_refs=["tc_aabbccdd"],
        sources=["volatility.pslist"],
        mitre_attack_ids=mitre_ids or [],
        event_time_start="2025-01-15T08:00:00Z",
        submitted_at="2025-01-15T12:00:00Z",
    )


class TestIocToStixPattern:
    """Tests for individual IOC-to-STIX pattern conversion."""

    def test_ip_to_stix_pattern(self) -> None:
        """IP IOC produces valid STIX 2.1 indicator pattern."""
        ioc = {"type": "External IP", "value": "192.168.1.10", "context": "test"}
        pattern = _ioc_to_stix_pattern(ioc)
        assert pattern is not None
        assert pattern == "[ipv4-addr:value = '192.168.1.10']"

    def test_domain_to_stix_pattern(self) -> None:
        """Domain IOC produces valid STIX pattern."""
        ioc = {"type": "domain", "value": "evil.example.com", "context": "test"}
        pattern = _ioc_to_stix_pattern(ioc)
        assert pattern is not None
        assert pattern == "[domain-name:value = 'evil.example.com']"

    def test_sha256_to_stix_pattern(self) -> None:
        """SHA-256 hash IOC produces valid STIX file hash pattern."""
        hash_val = "a" * 64
        ioc = {"type": "sha256", "value": hash_val, "context": "test"}
        pattern = _ioc_to_stix_pattern(ioc)
        assert pattern is not None
        assert "SHA-256" in pattern
        assert hash_val in pattern

    def test_unknown_type_returns_none(self) -> None:
        """Unmapped IOC type returns None."""
        ioc = {"type": "unknown_type", "value": "foo", "context": "test"}
        pattern = _ioc_to_stix_pattern(ioc)
        assert pattern is None


class TestBuildStixBundle:
    """Tests for STIX bundle construction (manual fallback path)."""

    def test_bundle_has_required_structure(self) -> None:
        """STIX bundle contains required top-level keys and identity object."""
        findings = [
            _make_finding(
                description="Connection to 192.168.1.10:4444 from cmd.exe",
                mitre_ids=["T1059.001"],
            )
        ]
        iocs = {
            "network": [{"type": "External IP", "value": "192.168.1.10", "context": "test"}],
            "file": [],
            "email": [],
        }

        bundle = build_stix_bundle("test-case", findings, iocs)

        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert bundle["id"].startswith("bundle--")
        assert "objects" in bundle
        assert len(bundle["objects"]) > 0

        identity = bundle["objects"][0]
        assert identity["type"] == "identity"
        assert "Mulder Investigation" in identity["name"]

    def test_bundle_contains_indicator(self) -> None:
        """STIX bundle contains an indicator for the provided IOC."""
        iocs = {
            "network": [{"type": "domain", "value": "evil.example.com", "context": "c2"}],
            "file": [],
            "email": [],
        }
        findings = [_make_finding("C2 beacon to evil.example.com")]
        bundle = build_stix_bundle("test-case", findings, iocs)

        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) >= 1
        assert any("evil.example.com" in i["pattern"] for i in indicators)

    def test_bundle_contains_attack_pattern(self) -> None:
        """STIX bundle includes attack-pattern objects for MITRE IDs."""
        findings = [_make_finding("PowerShell execution", mitre_ids=["T1059.001"])]
        iocs: dict[str, list[Any]] = {"network": [], "file": [], "email": []}
        bundle = build_stix_bundle("test-case", findings, iocs)

        attack_patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        assert len(attack_patterns) >= 1
        ext_refs = attack_patterns[0]["external_references"]
        assert any(r["external_id"] == "T1059.001" for r in ext_refs)


class TestCsvExport:
    """Tests for CSV export format."""

    def test_csv_export_format(self) -> None:
        """CSV export has correct headers and row format."""
        iocs = {
            "network": [
                {
                    "type": "External IP",
                    "value": "10.0.0.1",
                    "context": "suspicious",
                    "severity": "high",
                }
            ],
            "file": [{"type": "sha256", "value": "abc123", "context": "malware"}],
            "email": [],
        }

        csv_text = build_csv(iocs)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)

        assert reader.fieldnames == ["type", "value", "context", "severity"]
        assert len(rows) == 2
        assert rows[0]["value"] == "10.0.0.1"
        assert rows[1]["value"] == "abc123"

    def test_csv_empty_iocs(self) -> None:
        """CSV export with no IOCs produces header-only output."""
        iocs: dict[str, list[Any]] = {"network": [], "file": [], "email": []}
        csv_text = build_csv(iocs)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) == 0
        assert reader.fieldnames == ["type", "value", "context", "severity"]
