"""Immutable collector-intake adapters."""

from mulder.adapters.intake import (
    ExaminerAssertion,
    IntakeError,
    IntakeLimits,
    IntakeManifest,
    IntakeResult,
    ingest_collection,
    load_intake_manifest,
    materialize_intake,
    prepare_evidence_case,
    read_intake_member,
    scan_collection,
    verify_intake_source,
)

__all__ = [
    "ExaminerAssertion",
    "IntakeError",
    "IntakeLimits",
    "IntakeManifest",
    "IntakeResult",
    "ingest_collection",
    "load_intake_manifest",
    "materialize_intake",
    "prepare_evidence_case",
    "read_intake_member",
    "scan_collection",
    "verify_intake_source",
]
