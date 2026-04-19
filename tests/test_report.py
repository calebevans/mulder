"""Tests for mulder.report.renderer -- IOC extraction, provenance, rendering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mulder.models import AuditSummary, CaseMetadataRow, Finding
from mulder.report.renderer import (
    ReportRenderer,
    _attack_id_to_url,
    _build_mitre_techniques,
    _build_provenance_chains,
    _build_related_findings,
    _compute_integrity_status,
    _extract_iocs,
    _format_duration,
    _is_external_ip,
)


def _make_finding(**overrides: Any) -> Finding:
    base: dict[str, Any] = dict(
        finding_id="f-1",
        case_id="c",
        title="Test",
        description="desc",
        severity="high",
        confidence="confirmed",
        evidence_refs=["tc_1"],
        sources=["src"],
        submitted_at="2025-01-01T00:00:00Z",
    )
    base.update(overrides)
    return Finding(**base)


class TestExtractIocs:
    def test_extracts_external_ip(self) -> None:
        f = _make_finding(description="Connection to 8.8.8.8 detected")
        net, _, _ = _extract_iocs([f])
        ips = [i for i in net if i["type"] == "External IP"]
        assert len(ips) == 1
        assert ips[0]["value"] == "8.8.8.8"

    def test_extracts_internal_ip(self) -> None:
        f = _make_finding(description="Lateral movement to 192.168.1.50")
        net, _, _ = _extract_iocs([f])
        ips = [i for i in net if i["type"] == "Internal IP"]
        assert len(ips) == 1

    def test_skips_loopback(self) -> None:
        f = _make_finding(description="Listening on 127.0.0.1 and 0.0.0.0")
        net, _, _ = _extract_iocs([f])
        assert all(i["value"] not in ("127.0.0.1", "0.0.0.0") for i in net)

    def test_extracts_ip_with_port(self) -> None:
        f = _make_finding(description="C2 beacon to 10.0.0.5:4444")
        net, _, _ = _extract_iocs([f])
        ports = [i for i in net if i["type"] == "Port"]
        assert any(p["value"] == "TCP 4444" for p in ports)

    def test_extracts_path(self) -> None:
        f = _make_finding(description=r"Dropped C:\Windows\Temp\malware.exe on disk")
        _, files, _ = _extract_iocs([f])
        assert any("malware" in i["value"] for i in files)

    def test_extracts_hash(self) -> None:
        sha = "a" * 64
        f = _make_finding(description=f"SHA256: {sha}")
        _, files, _ = _extract_iocs([f])
        hashes = [i for i in files if i["type"] == "SHA256"]
        assert len(hashes) == 1
        assert hashes[0]["value"] == sha

    def test_extracts_email(self) -> None:
        f = _make_finding(description="Phishing from attacker@evil.com observed")
        _, _, emails = _extract_iocs([f])
        assert len(emails) == 1
        assert emails[0]["value"] == "attacker@evil.com"

    def test_deduplicates_across_findings(self) -> None:
        f1 = _make_finding(finding_id="f-1", description="IP 8.8.8.8 seen")
        f2 = _make_finding(finding_id="f-2", description="Also 8.8.8.8 here")
        net, _, _ = _extract_iocs([f1, f2])
        ips = [i for i in net if i["value"] == "8.8.8.8"]
        assert len(ips) == 1


class TestBuildProvenanceChains:
    def test_resolves_refs(self) -> None:
        f = _make_finding(evidence_refs=["tc_a", "tc_b"])
        entries = [
            {
                "type": "tool_call",
                "tool_call_id": "tc_a",
                "tool_name": "search",
                "timestamp": "t1",
                "duration_ms": 10,
                "params": {},
                "output_hash": "h",
            },
            {
                "type": "tool_call",
                "tool_call_id": "tc_b",
                "tool_name": "correlate",
                "timestamp": "t2",
                "duration_ms": 20,
                "params": {},
                "output_hash": "h",
            },
        ]
        chains = _build_provenance_chains([f], entries)
        assert len(chains) == 1
        assert len(chains[0]["evidence"]) == 2
        assert chains[0]["evidence"][0]["tool_name"] == "search"

    def test_unresolved_refs_get_unknown(self) -> None:
        f = _make_finding(evidence_refs=["tc_missing"])
        chains = _build_provenance_chains([f], [])
        assert chains[0]["evidence"][0]["tool_name"] == "unknown"


class TestBuildRelatedFindings:
    def test_links_shared_refs(self) -> None:
        f1 = _make_finding(finding_id="f-1", evidence_refs=["tc_shared"])
        f2 = _make_finding(finding_id="f-2", evidence_refs=["tc_shared"])
        related = _build_related_findings([f1, f2])
        assert "f-2" in related.get("f-1", [])
        assert "f-1" in related.get("f-2", [])

    def test_no_shared_refs(self) -> None:
        f1 = _make_finding(finding_id="f-1", evidence_refs=["tc_a"])
        f2 = _make_finding(finding_id="f-2", evidence_refs=["tc_b"])
        related = _build_related_findings([f1, f2])
        assert related == {}


class TestBuildMitreTechniques:
    def test_aggregates_techniques(self) -> None:
        f1 = _make_finding(finding_id="f-1", mitre_attack_ids=["T1059", "T1059.001"])
        f2 = _make_finding(finding_id="f-2", mitre_attack_ids=["T1059"])
        techs = _build_mitre_techniques([f1, f2])
        t1059 = next(t for t in techs if t["id"] == "T1059")
        assert t1059["finding_count"] == 2


class TestFormatDuration:
    def test_minutes(self) -> None:
        assert _format_duration(300_000) == "5 minutes"

    def test_hours(self) -> None:
        assert "hour" in _format_duration(7_200_000)


class TestAttackIdToUrl:
    def test_base_technique(self) -> None:
        assert _attack_id_to_url("T1059") == "https://attack.mitre.org/techniques/T1059/"

    def test_subtechnique(self) -> None:
        assert _attack_id_to_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"


class TestIsExternalIp:
    def test_public(self) -> None:
        assert _is_external_ip("8.8.8.8")

    def test_private_10(self) -> None:
        assert not _is_external_ip("10.0.0.1")

    def test_private_172(self) -> None:
        assert not _is_external_ip("172.16.0.1")

    def test_private_192(self) -> None:
        assert not _is_external_ip("192.168.1.1")


class TestComputeIntegrityStatus:
    def test_empty_returns_no_evidence(self) -> None:
        assert _compute_integrity_status(None) == "no_evidence_registered"
        assert _compute_integrity_status([]) == "no_evidence_registered"

    def test_populated_returns_hashes_recorded(self) -> None:
        assert _compute_integrity_status([{"file_path": "/a"}]) == "hashes_recorded"


class TestRenderSmoke:
    def test_render_produces_markdown(self, tmp_path: Path) -> None:
        renderer = ReportRenderer()
        meta = CaseMetadataRow(
            case_id="smoke",
            ingested_at="2025-01-01T00:00:00Z",
            evidence_root="/evidence",
            extractor_versions={},
        )
        finding = _make_finding(
            description="Found malware at C:\\Windows\\Temp\\bad.exe from 8.8.8.8:443"
        )
        summary = AuditSummary(
            total_tool_calls=5,
            total_findings=1,
            tool_call_counts={"search": 3, "correlate": 2},
            total_duration_ms=60_000,
            first_timestamp="2025-01-01T00:00:00Z",
            last_timestamp="2025-01-01T00:05:00Z",
        )
        audit_path = tmp_path / "audit.jsonl"
        audit_path.write_text("")
        result = renderer.render(meta, [finding], summary, audit_path)
        assert len(result) > 0
        assert "smoke" in result
