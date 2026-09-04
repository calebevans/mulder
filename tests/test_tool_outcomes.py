"""Tests for precise, backwards-compatible forensic tool outcomes."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mulder.models import (
    CoverageMetadata,
    FallbackAttempt,
    ToolOutcome,
    ToolOutcomeStatus,
)
from mulder.server.helpers import error_response, tool_response, windowed_response


def test_all_outcome_states_serialize_as_stable_strings() -> None:
    """Every universal status is JSON-safe and round-trips through the schema."""
    expected = {
        "SUCCESS_NONEMPTY",
        "SUCCESS_EMPTY",
        "NOT_APPLICABLE",
        "UNAVAILABLE",
        "UNSUPPORTED_VERSION",
        "FAILED",
        "TIMED_OUT",
        "PARTIAL",
        "SAMPLED",
        "NOT_RUN",
    }
    assert {status.value for status in ToolOutcomeStatus} == expected

    for status in ToolOutcomeStatus:
        coverage = CoverageMetadata(
            sample_reason="bounded fixture" if status is ToolOutcomeStatus.SAMPLED else None
        )
        original = ToolOutcome(status=status, coverage=coverage)
        encoded = json.dumps(original.model_dump(mode="json"))
        assert ToolOutcome.model_validate_json(encoded) == original


def test_json_schema_exposes_status_and_coverage_contract() -> None:
    """Generated schemas let MCP clients validate the additive envelope."""
    schema = ToolOutcome.model_json_schema()

    assert set(schema["$defs"]["ToolOutcomeStatus"]["enum"]) == {
        status.value for status in ToolOutcomeStatus
    }
    coverage_properties = schema["$defs"]["CoverageMetadata"]["properties"]
    assert {
        "bytes_examined",
        "bytes_total",
        "rows_examined",
        "rows_total",
        "truncation_reason",
        "sample_reason",
        "tool_version",
        "parser_version",
        "fallback_lineage",
    } <= coverage_properties.keys()


def test_coverage_serializes_fallback_lineage_and_versions() -> None:
    """Fallback provenance remains structured instead of becoming prose."""
    outcome = ToolOutcome(
        status=ToolOutcomeStatus.SUCCESS_NONEMPTY,
        coverage=CoverageMetadata(
            bytes_examined=512,
            bytes_total=512,
            rows_examined=8,
            rows_total=8,
            tool_version="2.4.1",
            parser_version="evtx-0.8.1",
            fallback_lineage=[
                FallbackAttempt(
                    adapter="primary-evtx-parser",
                    status=ToolOutcomeStatus.UNSUPPORTED_VERSION,
                    reason="unknown chunk format",
                    parser_version="evtx-0.7.4",
                )
            ],
        ),
    )

    wire = outcome.model_dump(mode="json")
    assert wire["schema_version"] == 1
    assert wire["coverage"]["fallback_lineage"][0]["status"] == "UNSUPPORTED_VERSION"
    assert wire["coverage"]["parser_version"] == "evtx-0.8.1"


@pytest.mark.parametrize(
    ("field_values", "message"),
    [
        ({"bytes_examined": 2, "bytes_total": 1}, "bytes_examined"),
        ({"rows_examined": 2, "rows_total": 1}, "rows_examined"),
    ],
)
def test_coverage_rejects_impossible_scope(field_values: dict[str, int], message: str) -> None:
    """An adapter cannot claim to examine more than its known input scope."""
    with pytest.raises(ValidationError, match=message):
        CoverageMetadata(**field_values)


def test_sampled_outcome_requires_a_machine_visible_reason() -> None:
    """A sampled result cannot masquerade as an unexplained complete result."""
    with pytest.raises(ValidationError, match="sample_reason"):
        ToolOutcome(status=ToolOutcomeStatus.SAMPLED)


def test_parser_failure_is_not_serialized_as_successful_empty() -> None:
    """A parser crash stays FAILED even when it produced no rows."""
    response = error_response(
        "tc_parser",
        "parse_fixture",
        {},
        "malformed record at offset 42",
        error_type="parse_error",
        coverage=CoverageMetadata(bytes_examined=42, bytes_total=100),
    )

    assert response["status"] == "error"
    assert response["outcome"]["status"] == "FAILED"
    assert response["outcome"]["status"] != "SUCCESS_EMPTY"
    assert response["outcome"]["coverage"]["bytes_examined"] == 42
    assert response["outcome"]["coverage"]["bytes_total"] == 100
    assert response["outcome"]["execution"]["output_digest"].startswith("blake2b:")
    assert response["outcome"]["legacy_mapping"] is None


def test_timeout_gets_a_distinct_outcome_without_breaking_legacy_status() -> None:
    response = error_response(
        "tc_timeout",
        "slow_parser",
        {},
        "timed out",
        error_type="timeout",
    )

    assert response["status"] == "error"
    assert response["outcome"]["status"] == "TIMED_OUT"


def test_success_helper_preserves_legacy_shape_and_accepts_precise_scope() -> None:
    response = tool_response(
        "tc_partial",
        "bounded_parser",
        {},
        {"records": [1, 2]},
        outcome=ToolOutcome(
            status=ToolOutcomeStatus.PARTIAL,
            coverage=CoverageMetadata(
                rows_examined=2,
                rows_total=9,
                truncation_reason="parser stopped at corrupt record",
            ),
        ),
    )

    assert response["status"] == "success"
    assert response["results"] == {"records": [1, 2]}
    assert response["outcome"]["status"] == "PARTIAL"
    assert response["outcome"]["coverage"]["rows_total"] == 9


def test_windowed_response_distinguishes_empty_and_sampled_scope() -> None:
    empty = windowed_response("tc_empty", [], "source", "search", {}, 0)
    assert empty["status"] == "success"
    assert empty["outcome"]["status"] == "SUCCESS_EMPTY"

    sampled = windowed_response(
        "tc_sampled",
        [{"raw_text": str(index)} for index in range(3)],
        "source",
        "search",
        {},
        0,
        cap=2,
    )
    assert sampled["outcome"]["status"] == "SAMPLED"
    assert sampled["outcome"]["coverage"]["rows_examined"] == 2
    assert sampled["outcome"]["coverage"]["rows_total"] == 3
    assert sampled["outcome"]["execution"]["source_ids"] == ["source"]


def test_omitted_outcome_is_derived_and_full_content_is_committed() -> None:
    empty = tool_response("tc_empty", "query", {}, [])
    explicit_count = tool_response("tc_count", "query", {}, {"result_count": 1})
    ambiguous = tool_response("tc_ambiguous", "query", {}, {"completed": True})
    first = windowed_response("tc_first", [{"raw_text": "alpha"}], "source", "search", {}, 0)
    second = windowed_response("tc_second", [{"raw_text": "bravo"}], "source", "search", {}, 0)

    assert empty["outcome"]["status"] == "SUCCESS_EMPTY"
    assert explicit_count["outcome"]["status"] == "SUCCESS_NONEMPTY"
    assert ambiguous["outcome"]["status"] == "PARTIAL"
    assert "cardinality" in ambiguous["outcome"]["reason"]
    assert (
        first["outcome"]["execution"]["output_digest"]
        != second["outcome"]["execution"]["output_digest"]
    )
