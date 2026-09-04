"""Interface-level tests for the EVTX, Kubernetes, and CloudTrail pilots."""

from __future__ import annotations

import gzip
import inspect
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.extractors.classifier import ClassifierConfig, EvidenceClassifier
from mulder.models import ToolOutcomeStatus, WindowRow
from mulder.packs import (
    DomainPackRegistry,
    LocalEvidenceDocument,
    PackRuntimeInventory,
    PilotAnalysisResult,
    analyze_cloudtrail_documents,
    analyze_evtx_documents,
    analyze_kubernetes_documents,
    pilot_fixture_root,
    register_builtin_packs,
)
from mulder.packs.builtin import (
    AWS_CLOUDTRAIL_PACK,
    KUBERNETES_SECURITY_PACK,
    WINDOWS_EVTX_PACK,
)
from mulder.packs.pilot_analysis import DocumentMediaType
from mulder.security.evidence_envelope import EvidenceFlag
from mulder.server.app import _tool_dispatch_sync
from mulder.server.tools.domain_pilots import (
    analyze_cloudtrail_pack,
    analyze_evtx_pack,
    analyze_kubernetes_pack,
)


def _fixture_document(domain: str, name: str) -> LocalEvidenceDocument:
    path = pilot_fixture_root() / domain / name
    media_type: DocumentMediaType
    if path.suffix == ".csv":
        media_type = "text/csv"
    elif domain == "evtx":
        media_type = "application/x-evtx-lines"
    elif path.suffix in {".yaml", ".yml"}:
        media_type = "application/yaml"
    else:
        media_type = "application/json"
    return LocalEvidenceDocument(
        source_id=f"fixture-{domain}",
        source_name=name,
        media_type=media_type,
        content=path.read_bytes(),
    )


def test_all_pilot_packs_preflight_together_with_existing_registry() -> None:
    registry = DomainPackRegistry()
    register_builtin_packs(registry)

    result = registry.enable(
        ["windows.evtx", "kubernetes.security", "cloud.aws-cloudtrail"],
        PackRuntimeInventory(
            available_capabilities=("forensic.local-read",),
            parser_versions={
                "evtx-pilot": "1",
                "kubernetes-pilot": "1",
                "aws-cloudtrail-export": "1",
            },
            fixture_root=pilot_fixture_root(),
        ),
    )

    assert result.ready
    assert result.activation is not None
    assert [pack.pack_id for pack in result.activation.manifests] == [
        "cloud.aws-cloudtrail",
        "kubernetes.security",
        "windows.evtx",
    ]
    assert [step.phase.name for step in result.activation.workflow_steps] == [
        "pack.cloud.aws-cloudtrail.cloudtrail-control-plane",
        "pack.kubernetes.security.kubernetes-security",
        "pack.windows.evtx.evtx-structural-detections",
    ]
    assert [len(pack.fixture_digests) for pack in result.activation.receipt.packs] == [
        5,
        5,
        6,
    ]


def test_pilot_classifiers_are_added_without_central_classifier_edits(tmp_path: Path) -> None:
    cloud_dir = tmp_path / "AWSLogs" / "1" / "CloudTrail" / "us-east-1"
    cloud_dir.mkdir(parents=True)
    (cloud_dir / "trail.json.gz").write_bytes(b"gzip")
    kubernetes_dir = tmp_path / "kubernetes" / "manifests"
    kubernetes_dir.mkdir(parents=True)
    (kubernetes_dir / "pod.yaml").write_text("kind: Pod\n", encoding="utf-8")
    (tmp_path / "Security.evtx").write_bytes(b"evtx")
    rules = tuple(
        rule
        for pack in (AWS_CLOUDTRAIL_PACK, KUBERNETES_SECURITY_PACK, WINDOWS_EVTX_PACK)
        for rule in pack.classifiers
    )

    classified = EvidenceClassifier(ClassifierConfig(pack_rules=rules)).classify(tmp_path)

    observed = {item.path.name: item.artifact_type for item in classified}
    assert observed == {
        "Security.evtx": "evtx",
        "pod.yaml": "kubernetes",
        "trail.json.gz": "aws_cloudtrail",
    }


@pytest.mark.parametrize(
    ("domain", "name", "expected"),
    [
        ("evtx", "clean.csv", ToolOutcomeStatus.SUCCESS_EMPTY),
        ("evtx", "malicious.csv", ToolOutcomeStatus.SUCCESS_NONEMPTY),
        ("evtx", "prompt-injected.csv", ToolOutcomeStatus.SUCCESS_EMPTY),
        ("evtx", "schema-drift.csv", ToolOutcomeStatus.UNSUPPORTED_VERSION),
        ("evtx", "partial.log", ToolOutcomeStatus.PARTIAL),
        ("evtx", "bom-renamed.csv", ToolOutcomeStatus.PARTIAL),
        ("kubernetes", "clean.yaml", ToolOutcomeStatus.SUCCESS_EMPTY),
        ("kubernetes", "malicious.yaml", ToolOutcomeStatus.SUCCESS_NONEMPTY),
        ("kubernetes", "prompt-injected.yaml", ToolOutcomeStatus.SUCCESS_EMPTY),
        ("kubernetes", "schema-drift.yaml", ToolOutcomeStatus.UNSUPPORTED_VERSION),
        ("kubernetes", "partial.yaml", ToolOutcomeStatus.PARTIAL),
        ("cloudtrail", "clean.json", ToolOutcomeStatus.SUCCESS_EMPTY),
        ("cloudtrail", "malicious.json", ToolOutcomeStatus.SUCCESS_NONEMPTY),
        ("cloudtrail", "prompt-injected.json", ToolOutcomeStatus.SUCCESS_EMPTY),
        ("cloudtrail", "schema-drift.json", ToolOutcomeStatus.UNSUPPORTED_VERSION),
        ("cloudtrail", "partial.json", ToolOutcomeStatus.PARTIAL),
    ],
)
def test_fixture_result_matrix(domain: str, name: str, expected: ToolOutcomeStatus) -> None:
    document = _fixture_document(domain, name)
    analyzer = {
        "evtx": analyze_evtx_documents,
        "kubernetes": analyze_kubernetes_documents,
        "cloudtrail": analyze_cloudtrail_documents,
    }[domain]

    result = analyzer((document,))

    assert result.outcome.status is expected
    pack = {
        "evtx": WINDOWS_EVTX_PACK,
        "kubernetes": KUBERNETES_SECURITY_PACK,
        "cloudtrail": AWS_CLOUDTRAIL_PACK,
    }[domain]
    expectation = next(
        item for item in pack.benchmark_expectations if item.fixture_id == Path(name).stem
    )
    assert expected in expectation.acceptable_statuses


def test_evtx_proofs_retain_actual_record_fields_and_rule_hashes() -> None:
    result = analyze_evtx_documents((_fixture_document("evtx", "malicious.csv"),))

    assert {finding.finding_type for finding in result.findings} == {
        "log_clear",
        "encoded_powershell",
        "service_install",
    }
    for finding in result.findings:
        assert finding.rule_hash == result.rule_hashes[finding.rule_id]
        assert finding.proofs[0].record_selector.startswith("csv:row=")
        assert all(
            selector.startswith("csv:row=") for selector in finding.proofs[0].field_selectors
        )
    log_clear = next(item for item in result.findings if item.finding_type == "log_clear")
    assert "csv:row=2;field=EventId" in log_clear.proofs[0].field_selectors
    assert "csv:row=2;field=RecordNumber" in log_clear.proofs[0].field_selectors
    assert (
        result.ruleset_hash
        == analyze_evtx_documents((_fixture_document("evtx", "malicious.csv"),)).ruleset_hash
    )


def test_evtx_bom_and_exporter_header_aliases_preserve_exact_names() -> None:
    result = analyze_evtx_documents((_fixture_document("evtx", "bom-renamed.csv"),))

    assert result.outcome.status is ToolOutcomeStatus.PARTIAL
    observation = result.observations[0]
    assert observation.attributes["event_id"] == 4624
    assert "csv:row=2;field=Event ID" in observation.proof.field_selectors
    assert "csv:row=2;field=Record ID" in observation.proof.field_selectors


@pytest.mark.parametrize(
    ("domain", "name", "analyzer"),
    [
        ("evtx", "prompt-injected.csv", analyze_evtx_documents),
        ("kubernetes", "prompt-injected.yaml", analyze_kubernetes_documents),
        ("cloudtrail", "prompt-injected.json", analyze_cloudtrail_documents),
    ],
)
def test_prompt_injected_fields_are_inert_but_flagged(
    domain: str,
    name: str,
    analyzer: Callable[[Sequence[LocalEvidenceDocument]], PilotAnalysisResult],
) -> None:
    result = analyzer((_fixture_document(domain, name),))

    assert result.outcome.status is ToolOutcomeStatus.SUCCESS_EMPTY
    assert result.findings == ()
    assert EvidenceFlag.INSTRUCTION_SHAPED in result.observations[0].proof.evidence_flags


def test_kubernetes_pack_covers_each_family_and_emits_egress_relationships() -> None:
    result = analyze_kubernetes_documents((_fixture_document("kubernetes", "malicious.yaml"),))

    assert {cell.family for cell in result.coverage} == {
        "audit",
        "events",
        "manifests",
        "rbac",
        "images",
        "egress",
    }
    assert all(
        cell.outcome.status is ToolOutcomeStatus.SUCCESS_NONEMPTY for cell in result.coverage
    )
    assert {finding.finding_type for finding in result.findings} == {
        "sensitive_api_action",
        "privileged_workload",
        "cluster_admin_binding",
        "rbac_wildcard",
        "mutable_image",
        "allow_all_egress",
    }
    predicates = {relationship.predicate for relationship in result.relationships}
    assert {
        "performs_k8s_action",
        "uses_container_image",
        "bound_to_k8s_role",
    } <= predicates
    egress = next(item for item in result.findings if item.finding_type == "allow_all_egress")
    assert egress.proofs[0].field_selectors == ("document[5].spec.egress[0].to",)


def test_cloudtrail_pilot_uses_documented_records_and_exact_proof_paths() -> None:
    result = analyze_cloudtrail_documents((_fixture_document("cloudtrail", "malicious.json"),))

    assert {finding.finding_type for finding in result.findings} == {
        "trail_integrity_change",
        "iam_policy_change",
        "root_login_without_mfa",
        "public_security_group_ingress",
    }
    trail = next(item for item in result.findings if item.finding_type == "trail_integrity_change")
    assert trail.proofs[0].record_selector == "Records[0]"
    assert "Records[0].eventName" in trail.proofs[0].field_selectors
    assert "Records[0].userIdentity" in trail.proofs[0].field_selectors
    assert {item.predicate for item in result.relationships} >= {
        "calls_aws_control_plane",
        "originates_aws_action_by",
    }


def test_cloudtrail_gzip_is_local_and_commits_transport_and_content() -> None:
    raw = (pilot_fixture_root() / "cloudtrail" / "clean.json").read_bytes()
    compressed = gzip.compress(raw, mtime=0)
    document = LocalEvidenceDocument(
        source_id="gzip-fixture",
        source_name="AWSLogs/CloudTrail/clean.json.gz",
        media_type="application/json",
        compression="gzip",
        content=compressed,
    )

    result = analyze_cloudtrail_documents((document,))

    assert result.outcome.status is ToolOutcomeStatus.SUCCESS_EMPTY
    proof = result.observations[0].proof
    assert proof.source_digest != proof.content_digest


def test_missing_artifacts_are_partial_and_never_clean() -> None:
    for analyzer in (
        analyze_evtx_documents,
        analyze_kubernetes_documents,
        analyze_cloudtrail_documents,
    ):
        result = analyzer(())
        assert result.outcome.status is ToolOutcomeStatus.PARTIAL
        assert all(
            cell.outcome.status is ToolOutcomeStatus.UNAVAILABLE for cell in result.coverage
        )


def _register_evtx_source(db: CaseDB) -> None:
    raw = (pilot_fixture_root() / "evtx" / "malicious.csv").read_text(encoding="utf-8")
    source_id = db.register_source(
        source_name="evtx.security",
        source_path="/evidence/Security.evtx",
        source_hash="sha256:" + "1" * 64,
        extractor="eztools",
        line_count=len(raw.splitlines()),
    )
    db.insert_windows(
        source_id,
        [
            WindowRow(
                source_id=source_id,
                line_start=0,
                line_end=len(raw),
                event_time=None,
                raw_text=raw,
            )
        ],
    )


def test_mcp_adapters_are_fixed_offline_operations(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    kube_dir = evidence / "kubernetes"
    cloud_dir = evidence / "AWSLogs" / "1" / "CloudTrail" / "us-east-1"
    kube_dir.mkdir(parents=True)
    cloud_dir.mkdir(parents=True)
    shutil.copyfile(pilot_fixture_root() / "kubernetes" / "malicious.yaml", kube_dir / "case.yaml")
    shutil.copyfile(
        pilot_fixture_root() / "cloudtrail" / "malicious.json", cloud_dir / "case.json"
    )
    db = CaseDB.create(case_id="pilot-case", evidence_root=str(evidence), db_dir=tmp_path)
    audit = AuditLog(tmp_path / "pilot.audit.jsonl")
    try:
        _register_evtx_source(db)
        context = MagicMock(db=db, audit=audit)
        with (
            patch("mulder.server.tools.domain_pilots.get_ctx", return_value=context),
            patch("socket.create_connection", side_effect=AssertionError("network attempted")),
        ):
            evtx = _tool_dispatch_sync["analyze_evtx_pack"]()
            kubernetes = _tool_dispatch_sync["analyze_kubernetes_pack"]()
            cloudtrail = _tool_dispatch_sync["analyze_cloudtrail_pack"]()

        assert evtx["outcome"]["status"] == "SUCCESS_NONEMPTY"
        assert kubernetes["outcome"]["status"] == "SUCCESS_NONEMPTY"
        assert cloudtrail["outcome"]["status"] == "SUCCESS_NONEMPTY"
    finally:
        db.close()


def test_mcp_pilot_tools_expose_no_query_or_remote_parameters() -> None:
    for tool in (analyze_evtx_pack, analyze_kubernetes_pack, analyze_cloudtrail_pack):
        wrapped = tool.__wrapped__  # type: ignore[attr-defined]
        assert inspect.signature(wrapped).parameters == {}
