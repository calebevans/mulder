"""Reproducible, non-production harness for the PR 8.2 code-mode spike.

This module deliberately lives outside ``src/``.  It evaluates only a tiny JSON
assertion language; it never evaluates Python or JavaScript source and it does
not launch a guest runtime.  Runtime cases without an implemented, reviewed
adapter are reported as NOT_RUN so they fail the readiness gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import cast

SCHEMA_VERSION = "mulder.code-mode-spike.v1"
DEFAULT_SUITE = Path(__file__).with_name("fixtures") / "abuse-cases.json"


class Truth(str, Enum):
    """Three-valued result for a forensic assertion."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    INCONCLUSIVE = "INCONCLUSIVE"


class CaseStatus(str, Enum):
    """Observable status of one escape/abuse case."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"


class CandidateStatus(str, Enum):
    """Readiness state derived from hard-gate results."""

    READY = "READY"
    NOT_READY = "NOT_READY"
    REJECTED_BY_DESIGN = "REJECTED_BY_DESIGN"


class DslStatus(str, Enum):
    """Outcome at the assertion-language interface."""

    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class DslLimits:
    """Budgets applied before and during assertion evaluation."""

    max_program_bytes: int = 16_384
    max_evidence_bytes: int = 1_048_576
    max_nodes: int = 256
    max_depth: int = 20
    max_collection_items: int = 4_096
    max_string_bytes: int = 65_536


@dataclass(frozen=True)
class DslRun:
    """Content-addressed result containing no raw evidence values."""

    schema_version: str
    status: DslStatus
    truth: Truth | None
    reason_code: str
    program_sha256: str
    evidence_sha256: str
    result_sha256: str
    nodes_evaluated: int


@dataclass(frozen=True)
class CaseResult:
    """One expected-vs-observed harness result."""

    case_id: str
    candidate: str
    gate: str
    status: CaseStatus
    reason_code: str
    fixture_sha256: str | None = None


@dataclass(frozen=True)
class CandidateResult:
    """Candidate readiness derived solely from declared hard gates."""

    candidate: str
    status: CandidateStatus
    passed_gates: tuple[str, ...]
    missing_gates: tuple[str, ...]
    failed_gates: tuple[str, ...]


@dataclass(frozen=True)
class SpikeReport:
    """Deterministic architecture-spike result."""

    schema_version: str
    suite_sha256: str
    recommendation: str
    reason_code: str
    cases: tuple[CaseResult, ...]
    candidates: tuple[CandidateResult, ...]
    rejected_architectures: tuple[str, ...]

    def to_json(self) -> str:
        """Return stable JSON suitable for review or a CI artifact."""

        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"


class DslRejected(ValueError):
    """A fail-closed assertion-language rejection with a stable reason."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _Missing:
    pass


MISSING = _Missing()
Scalar = str | int | float | bool | None
Value = Scalar | list[object] | Mapping[str, object] | _Missing


@dataclass
class _Budget:
    limits: DslLimits
    nodes: int = 0

    def visit(self, depth: int) -> None:
        if depth > self.limits.max_depth:
            raise DslRejected("MAX_DEPTH_EXCEEDED")
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            raise DslRejected("MAX_NODES_EXCEEDED")


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise DslRejected("NON_JSON_INPUT") from exc
    return rendered.encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_json_shape(value: object, limits: DslLimits, *, max_bytes: int) -> bytes:
    """Validate bounded JSON without invoking user-defined behavior."""

    stack: list[tuple[object, int]] = [(value, 0)]
    collection_items = 0
    while stack:
        current, depth = stack.pop()
        if depth > limits.max_depth:
            raise DslRejected("MAX_DEPTH_EXCEEDED")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > limits.max_string_bytes:
                raise DslRejected("MAX_STRING_BYTES_EXCEEDED")
        elif isinstance(current, bool) or current is None or isinstance(current, int):
            pass
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise DslRejected("NON_JSON_INPUT")
        elif isinstance(current, list):
            collection_items += len(current)
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, dict):
            if not all(isinstance(key, str) for key in current):
                raise DslRejected("NON_STRING_KEY")
            collection_items += len(current)
            stack.extend((item, depth + 1) for item in current.values())
        else:
            raise DslRejected("NON_JSON_INPUT")
        if collection_items > limits.max_collection_items:
            raise DslRejected("MAX_COLLECTION_ITEMS_EXCEEDED")

    payload = _canonical_json(value)
    if len(payload) > max_bytes:
        raise DslRejected("MAX_BYTES_EXCEEDED")
    return payload


def _keys(
    expression: Mapping[str, object],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    actual = frozenset(expression)
    if not required.issubset(actual):
        raise DslRejected("MISSING_OPERATOR_FIELD")
    if not actual.issubset(required | optional):
        raise DslRejected("UNKNOWN_OPERATOR_FIELD")


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise DslRejected("INVALID_JSON_POINTER")
    tokens: list[str] = []
    for raw in pointer[1:].split("/"):
        index = 0
        decoded: list[str] = []
        while index < len(raw):
            if raw[index] != "~":
                decoded.append(raw[index])
                index += 1
                continue
            if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                raise DslRejected("INVALID_JSON_POINTER")
            decoded.append("~" if raw[index + 1] == "0" else "/")
            index += 2
        tokens.append("".join(decoded))
    return tuple(tokens)


def _resolve_pointer(evidence: object, pointer: str) -> Value:
    current = evidence
    for token in _pointer_tokens(pointer):
        if isinstance(current, dict):
            if token not in current:
                return MISSING
            current = current[token]
        elif isinstance(current, list):
            if not token.isascii() or not token.isdigit():
                return MISSING
            index = int(token)
            if index >= len(current):
                return MISSING
            current = current[index]
        else:
            return MISSING
    return cast(Value, current)


def _truth(value: Value) -> Truth:
    if isinstance(value, Truth):
        return value
    raise DslRejected("ROOT_NOT_ASSERTION")


def _compare(op: str, left: Value, right: Value) -> Truth:
    if left is MISSING or right is MISSING:
        return Truth.INCONCLUSIVE
    both_bool = isinstance(left, bool) and isinstance(right, bool)
    both_str = isinstance(left, str) and isinstance(right, str)
    both_number = (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and isinstance(right, (int, float))
        and not isinstance(right, bool)
    )
    if op in {"eq", "ne"}:
        if not (both_bool or both_str or both_number):
            return Truth.INCONCLUSIVE
        equal = left == right
        return Truth.TRUE if equal is (op == "eq") else Truth.FALSE
    if isinstance(left, str) and isinstance(right, str):
        operations = {
            "lt": left < right,
            "lte": left <= right,
            "gt": left > right,
            "gte": left >= right,
        }
        return Truth.TRUE if operations[op] else Truth.FALSE
    if (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and isinstance(right, (int, float))
        and not isinstance(right, bool)
    ):
        numeric_left = float(left)
        numeric_right = float(right)
        numeric_operations = {
            "lt": numeric_left < numeric_right,
            "lte": numeric_left <= numeric_right,
            "gt": numeric_left > numeric_right,
            "gte": numeric_left >= numeric_right,
        }
        return Truth.TRUE if numeric_operations[op] else Truth.FALSE
    return Truth.INCONCLUSIVE


def _evaluate(expression: object, evidence: object, budget: _Budget, depth: int = 0) -> Value:
    budget.visit(depth)
    if not isinstance(expression, dict):
        raise DslRejected("EXPRESSION_NOT_OBJECT")
    raw_op = expression.get("op")
    if not isinstance(raw_op, str):
        raise DslRejected("MISSING_OPERATOR")

    if raw_op == "literal":
        _keys(expression, required=frozenset({"op", "value"}))
        value = expression["value"]
        if isinstance(value, (dict, list)):
            raise DslRejected("LITERAL_NOT_SCALAR")
        return cast(Scalar, value)

    if raw_op == "field":
        _keys(expression, required=frozenset({"op", "path"}))
        pointer = expression["path"]
        if not isinstance(pointer, str):
            raise DslRejected("INVALID_JSON_POINTER")
        return _resolve_pointer(evidence, pointer)

    if raw_op == "length":
        _keys(expression, required=frozenset({"op", "value"}))
        value = _evaluate(expression["value"], evidence, budget, depth + 1)
        if value is MISSING:
            return MISSING
        if isinstance(value, (str, list, dict)):
            return len(value)
        return MISSING

    if raw_op == "exists":
        _keys(expression, required=frozenset({"op", "value"}))
        value = _evaluate(expression["value"], evidence, budget, depth + 1)
        return Truth.FALSE if value is MISSING else Truth.TRUE

    if raw_op in {"eq", "ne", "lt", "lte", "gt", "gte"}:
        _keys(expression, required=frozenset({"op", "left", "right"}))
        left = _evaluate(expression["left"], evidence, budget, depth + 1)
        right = _evaluate(expression["right"], evidence, budget, depth + 1)
        return _compare(raw_op, left, right)

    if raw_op == "contains":
        _keys(expression, required=frozenset({"op", "container", "item"}))
        container = _evaluate(expression["container"], evidence, budget, depth + 1)
        item = _evaluate(expression["item"], evidence, budget, depth + 1)
        if container is MISSING or item is MISSING:
            return Truth.INCONCLUSIVE
        if isinstance(container, str) and isinstance(item, str):
            return Truth.TRUE if item in container else Truth.FALSE
        if isinstance(container, list) and not isinstance(item, (list, dict, _Missing)):
            return Truth.TRUE if item in container else Truth.FALSE
        return Truth.INCONCLUSIVE

    if raw_op == "not":
        _keys(expression, required=frozenset({"op", "arg"}))
        arg = _truth(_evaluate(expression["arg"], evidence, budget, depth + 1))
        if arg is Truth.INCONCLUSIVE:
            return arg
        return Truth.FALSE if arg is Truth.TRUE else Truth.TRUE

    if raw_op in {"all", "any"}:
        _keys(expression, required=frozenset({"op", "args"}))
        args = expression["args"]
        if not isinstance(args, list) or not args:
            raise DslRejected("ASSERTION_ARGS_INVALID")
        truths = [_truth(_evaluate(arg, evidence, budget, depth + 1)) for arg in args]
        if raw_op == "all":
            if Truth.FALSE in truths:
                return Truth.FALSE
            return Truth.INCONCLUSIVE if Truth.INCONCLUSIVE in truths else Truth.TRUE
        if Truth.TRUE in truths:
            return Truth.TRUE
        return Truth.INCONCLUSIVE if Truth.INCONCLUSIVE in truths else Truth.FALSE

    raise DslRejected("UNKNOWN_OPERATOR")


def _result_digest(status: DslStatus, truth: Truth | None, reason_code: str) -> str:
    result = {
        "reason_code": reason_code,
        "status": status.value,
        "truth": truth.value if truth else None,
    }
    return _sha256(_canonical_json(result))


def execute_dsl(
    program: object,
    evidence: object,
    limits: DslLimits | None = None,
) -> DslRun:
    """Evaluate the bounded assertion DSL and return a content-addressed receipt.

    Missing evidence yields ``INCONCLUSIVE``. Unknown syntax, exceeded budgets,
    and non-JSON inputs are rejected. Raw evidence is never copied to the result.
    """

    selected_limits = limits or DslLimits()
    program_payload = _canonical_json(program)
    evidence_payload = _canonical_json(evidence)
    program_digest = _sha256(program_payload)
    evidence_digest = _sha256(evidence_payload)
    budget = _Budget(selected_limits)
    try:
        _validate_json_shape(
            program,
            selected_limits,
            max_bytes=selected_limits.max_program_bytes,
        )
        _validate_json_shape(
            evidence,
            selected_limits,
            max_bytes=selected_limits.max_evidence_bytes,
        )
        truth = _truth(_evaluate(program, evidence, budget))
    except DslRejected as exc:
        return DslRun(
            schema_version=SCHEMA_VERSION,
            status=DslStatus.REJECTED,
            truth=None,
            reason_code=exc.reason_code,
            program_sha256=program_digest,
            evidence_sha256=evidence_digest,
            result_sha256=_result_digest(DslStatus.REJECTED, None, exc.reason_code),
            nodes_evaluated=budget.nodes,
        )
    return DslRun(
        schema_version=SCHEMA_VERSION,
        status=DslStatus.COMPLETED,
        truth=truth,
        reason_code="ASSERTION_EVALUATED",
        program_sha256=program_digest,
        evidence_sha256=evidence_digest,
        result_sha256=_result_digest(DslStatus.COMPLETED, truth, "ASSERTION_EVALUATED"),
        nodes_evaluated=budget.nodes,
    )


def _load_object(path: Path) -> tuple[Mapping[str, object], bytes]:
    payload = path.read_bytes()
    loaded = json.loads(payload)
    if not isinstance(loaded, dict):
        raise ValueError(f"fixture must contain an object: {path}")
    return cast(Mapping[str, object], loaded), payload


def _string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return tuple(cast(list[str], value))


def _run_dsl_case(raw: object) -> CaseResult:
    if not isinstance(raw, dict):
        raise ValueError("DSL case must be an object")
    case_id = raw.get("id")
    gate = raw.get("gate")
    if not isinstance(case_id, str) or not isinstance(gate, str):
        raise ValueError("DSL case id and gate must be strings")
    limits = DslLimits()
    raw_limits = raw.get("limits")
    if raw_limits is not None:
        if not isinstance(raw_limits, dict):
            raise ValueError("DSL case limits must be an object")
        max_evidence_bytes = raw_limits.get("max_evidence_bytes", limits.max_evidence_bytes)
        max_string_bytes = raw_limits.get("max_string_bytes", limits.max_string_bytes)
        if not isinstance(max_evidence_bytes, int) or not isinstance(max_string_bytes, int):
            raise ValueError("DSL case limits must be integers")
        limits = DslLimits(
            max_evidence_bytes=max_evidence_bytes,
            max_string_bytes=max_string_bytes,
        )
    run = execute_dsl(raw.get("program"), raw.get("evidence"), limits)
    expected_status = raw.get("expected_status")
    expected_truth = raw.get("expected_truth")
    matched = run.status.value == expected_status
    if expected_truth is not None:
        matched = matched and run.truth is not None and run.truth.value == expected_truth
    expected_reason = raw.get("expected_reason")
    if expected_reason is not None:
        matched = matched and run.reason_code == expected_reason
    expected_schema = raw.get("expected_schema")
    if expected_schema is not None:
        matched = matched and run.schema_version == expected_schema
    receipt_json = json.dumps(asdict(run), sort_keys=True, default=str)
    excluded_values = raw.get("receipt_must_exclude", [])
    if not isinstance(excluded_values, list) or not all(
        isinstance(value, str) for value in excluded_values
    ):
        raise ValueError("receipt_must_exclude must be a list of strings")
    matched = matched and all(value not in receipt_json for value in excluded_values)
    expected_max_receipt_bytes = raw.get("expected_max_receipt_bytes")
    if expected_max_receipt_bytes is not None:
        if not isinstance(expected_max_receipt_bytes, int):
            raise ValueError("expected_max_receipt_bytes must be an integer")
        matched = matched and len(receipt_json.encode("utf-8")) <= expected_max_receipt_bytes
    return CaseResult(
        case_id=case_id,
        candidate="constrained_assertion_dsl",
        gate=gate,
        status=CaseStatus.PASS if matched else CaseStatus.FAIL,
        reason_code="EXPECTED_OUTCOME_OBSERVED" if matched else "OUTCOME_MISMATCH",
    )


def _runtime_case(raw: object, fixture_root: Path) -> CaseResult:
    if not isinstance(raw, dict):
        raise ValueError("runtime case must be an object")
    case_id = raw.get("id")
    candidate = raw.get("candidate")
    gate = raw.get("gate")
    fixture_name = raw.get("fixture")
    if not all(isinstance(value, str) for value in (case_id, candidate, gate, fixture_name)):
        raise ValueError("runtime case fields must be strings")
    fixture_path = (fixture_root / cast(str, fixture_name)).resolve()
    if not fixture_path.is_relative_to(fixture_root.resolve()) or not fixture_path.is_file():
        raise ValueError(f"missing or escaped runtime fixture: {fixture_name}")
    return CaseResult(
        case_id=cast(str, case_id),
        candidate=cast(str, candidate),
        gate=cast(str, gate),
        status=CaseStatus.NOT_RUN,
        reason_code="REVIEWED_RUNTIME_ADAPTER_NOT_IMPLEMENTED",
        fixture_sha256=_sha256(fixture_path.read_bytes()),
    )


def _candidate_result(
    candidate: str,
    required_gates: Sequence[str],
    cases: Sequence[CaseResult],
) -> CandidateResult:
    relevant = [case for case in cases if case.candidate == candidate]
    passed = {
        case.gate
        for case in relevant
        if case.status is CaseStatus.PASS
        and not any(
            other.gate == case.gate and other.status is not CaseStatus.PASS for other in relevant
        )
    }
    failed = {
        case.gate for case in relevant if case.status in {CaseStatus.FAIL, CaseStatus.NOT_RUN}
    }
    missing = set(required_gates) - passed - failed
    ready = not failed and not missing
    return CandidateResult(
        candidate=candidate,
        status=CandidateStatus.READY if ready else CandidateStatus.NOT_READY,
        passed_gates=tuple(sorted(passed)),
        missing_gates=tuple(sorted(missing)),
        failed_gates=tuple(sorted(failed)),
    )


def run_suite(path: Path = DEFAULT_SUITE) -> SpikeReport:
    """Run the fixture suite and derive the PR 8.3 recommendation."""

    suite, payload = _load_object(path)
    if suite.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported spike fixture schema")
    required_gates = _string_list(suite.get("required_gates"), "required_gates")
    candidates = _string_list(suite.get("candidates"), "candidates")
    dsl_cases = suite.get("dsl_cases")
    runtime_cases = suite.get("runtime_cases")
    if not isinstance(dsl_cases, list) or not isinstance(runtime_cases, list):
        raise ValueError("dsl_cases and runtime_cases must be lists")

    results = [_run_dsl_case(case) for case in dsl_cases]
    results.extend(_runtime_case(case, path.parent) for case in runtime_cases)
    results.sort(key=lambda result: result.case_id)
    candidate_results = tuple(
        _candidate_result(candidate, required_gates, results) for candidate in candidates
    )
    recommendation = (
        "GO"
        if any(result.status is CandidateStatus.READY for result in candidate_results)
        else "NO_GO"
    )
    return SpikeReport(
        schema_version=SCHEMA_VERSION,
        suite_sha256=_sha256(payload),
        recommendation=recommendation,
        reason_code=(
            "AT_LEAST_ONE_CANDIDATE_PASSED_ALL_HARD_GATES"
            if recommendation == "GO"
            else "NO_CANDIDATE_PASSED_ALL_HARD_GATES"
        ),
        cases=tuple(results),
        candidates=candidate_results,
        rejected_architectures=("in_process_javascript", "in_process_python"),
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        type=Path,
        default=DEFAULT_SUITE,
        help="path to a versioned abuse-case fixture",
    )
    return parser.parse_args()


def main() -> int:
    """Print the deterministic report; NO_GO is a valid spike outcome."""

    args = _parse_args()
    print(run_suite(args.suite).to_json(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
