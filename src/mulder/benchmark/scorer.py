"""Deterministic benchmark scoring over normalized, committed result objects."""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import Counter
from collections.abc import Hashable, Iterable
from dataclasses import dataclass
from typing import Literal, TypeAlias, TypeVar

from mulder.benchmark.models import (
    AggregateScore,
    BenchmarkCase,
    BenchmarkManifest,
    BenchmarkRunResult,
    BenchmarkScoreDocument,
    CaseRunResult,
    CaseScore,
    CitationScore,
    CoverageExpectation,
    CoverageScore,
    EpistemicScore,
    ExpectedClaim,
    MetricDistribution,
    ObservedClaim,
    RunScore,
    ScoreSlice,
    SetScore,
    VerdictScore,
)
from mulder.models import JsonScalar, ToolOutcomeStatus

ScalarKey: TypeAlias = tuple[str, str]
ClaimKey: TypeAlias = tuple[str, str, ScalarKey, tuple[tuple[str, ScalarKey], ...]]
SetKeyT = TypeVar("SetKeyT", bound=Hashable)


def _document_hash(document: BenchmarkManifest | BenchmarkRunResult) -> str:
    """Hash canonical semantic JSON, independent of input syntax or whitespace."""
    payload = json.dumps(
        document.model_dump(mode="json"),
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalized_scalar(value: JsonScalar) -> ScalarKey:
    """Return a type-sensitive canonical scalar suitable for set comparison."""
    if value is None:
        return ("null", "null")
    if isinstance(value, bool):
        return ("boolean", "true" if value else "false")
    if isinstance(value, int):
        return ("integer", str(value))
    if isinstance(value, float):
        return ("number", json.dumps(value, allow_nan=False, separators=(",", ":")))
    return ("string", value.strip().casefold())


def _claim_key(claim: ExpectedClaim | ObservedClaim) -> ClaimKey:
    qualifiers = tuple(
        sorted(
            (key.strip().casefold(), _normalized_scalar(value))
            for key, value in claim.qualifiers.items()
        )
    )
    return (
        claim.subject.strip().casefold(),
        claim.predicate.strip().casefold(),
        _normalized_scalar(claim.object_value),
        qualifiers,
    )


def _entity_key(claim: ExpectedClaim | ObservedClaim) -> str:
    return claim.subject.strip().casefold()


def _predicate_key(claim: ExpectedClaim | ObservedClaim) -> tuple[str, str]:
    return (_entity_key(claim), claim.predicate.strip().casefold())


def _rate(numerator: int, denominator: int, *, empty: float = 0.0) -> float:
    if denominator == 0:
        return empty
    return round(numerator / denominator, 6)


def _set_score(expected: set[SetKeyT], observed: set[SetKeyT]) -> SetScore:
    tp = len(expected & observed)
    fp = len(observed - expected)
    fn = len(expected - observed)
    precision = _rate(tp, tp + fp, empty=1.0 if not expected else 0.0)
    recall = _rate(tp, tp + fn, empty=1.0)
    f1 = (
        0.0 if precision + recall == 0 else round(2 * precision * recall / (precision + recall), 6)
    )
    return SetScore(
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def _coverage_satisfied(expectation: CoverageExpectation, status: ToolOutcomeStatus) -> bool:
    return status in expectation.acceptable_statuses


def _coverage_complete(expectation: CoverageExpectation, status: ToolOutcomeStatus) -> bool:
    """Return whether an applicable domain was fully and correctly examined."""
    if expectation.applicability == "not_applicable":
        return status is ToolOutcomeStatus.NOT_APPLICABLE
    if expectation.expected_content == "empty":
        return status is ToolOutcomeStatus.SUCCESS_EMPTY
    if expectation.expected_content == "nonempty":
        return status is ToolOutcomeStatus.SUCCESS_NONEMPTY
    return status in {ToolOutcomeStatus.SUCCESS_EMPTY, ToolOutcomeStatus.SUCCESS_NONEMPTY}


@dataclass(frozen=True)
class _RawCaseScore:
    """Additive counters retained until one or more cases are aggregated."""

    case_id: str
    ground_truth_label: Literal["clean", "nonempty"]
    expected_claims: frozenset[ClaimKey]
    observed_claims: frozenset[ClaimKey]
    expected_entities: frozenset[str]
    observed_entities: frozenset[str]
    expected_predicates: frozenset[tuple[str, str]]
    observed_predicates: frozenset[tuple[str, str]]
    citation_total: int
    citation_resolved: int
    citation_valid: int
    verified_claims: int
    claims_with_valid_citation: int
    uncited_verified_claims: int
    state_counts: Counter[str]
    expected_domains: int
    matched_expected_outcomes: int
    required_domains: int
    completed_required_domains: int
    unexpected_domains: int
    verdict_correct: int
    no_verdict: int
    expected_no_verdict: int
    correct_no_verdict: int
    unsafe_clean_verdicts: int
    completed_cases: int
    failed_cases: int
    duplicate_claims: int
    duplicate_citations: int


def _score_case(manifest_case: BenchmarkCase, run_case: CaseRunResult) -> _RawCaseScore:
    expected_by_key = {_claim_key(claim): claim for claim in manifest_case.expected_claims}
    expected_claims = set(expected_by_key)
    asserted = [claim for claim in run_case.claims if claim.verification_state == "verified"]
    asserted_keys = [_claim_key(claim) for claim in asserted]
    observed_claims = set(asserted_keys)
    duplicate_claims = len(asserted_keys) - len(observed_claims)

    expected_entities = {_entity_key(claim) for claim in manifest_case.expected_claims}
    observed_entities = {_entity_key(claim) for claim in asserted}
    expected_predicates = {_predicate_key(claim) for claim in manifest_case.expected_claims}
    observed_predicates = {_predicate_key(claim) for claim in asserted}

    anchors = {anchor.anchor_id: anchor for anchor in manifest_case.anchors}
    citation_total = citation_resolved = citation_valid = 0
    claims_with_valid_citation = uncited_verified_claims = duplicate_citations = 0
    for claim in asserted:
        unique_citations = set(claim.citations)
        duplicate_citations += len(claim.citations) - len(unique_citations)
        if not unique_citations:
            uncited_verified_claims += 1
        expected = expected_by_key.get(_claim_key(claim))
        claim_has_valid_citation = False
        for anchor_id in unique_citations:
            citation_total += 1
            anchor = anchors.get(anchor_id)
            if anchor is None:
                continue
            citation_resolved += 1
            if expected is not None and expected.claim_id in anchor.supports_claim_ids:
                citation_valid += 1
                claim_has_valid_citation = True
        claims_with_valid_citation += int(claim_has_valid_citation)

    state_counts: Counter[str] = Counter(claim.verification_state for claim in run_case.claims)
    expected_coverage = {item.domain: item for item in manifest_case.coverage}
    observed_coverage = {item.domain: item.status for item in run_case.coverage}
    matched_expected_outcomes = 0
    required_domains = 0
    completed_required_domains = 0
    for domain, expectation in expected_coverage.items():
        matched = domain in observed_coverage and _coverage_satisfied(
            expectation, observed_coverage[domain]
        )
        matched_expected_outcomes += int(matched)
        if expectation.required:
            required_domains += 1
            complete = domain in observed_coverage and _coverage_complete(
                expectation, observed_coverage[domain]
            )
            completed_required_domains += int(complete)

    # An infrastructure failure is never a correct analytical abstention, even
    # when the answer key itself expects no_verdict.
    verdict_correct = int(
        run_case.cell_status != "failed" and run_case.verdict == manifest_case.expected_verdict
    )
    no_verdict = int(run_case.verdict == "no_verdict")
    expected_no_verdict = int(manifest_case.expected_verdict == "no_verdict")
    correct_no_verdict = int(
        run_case.cell_status != "failed" and no_verdict and expected_no_verdict
    )
    required_complete = completed_required_domains == required_domains
    unsafe_clean_verdicts = int(
        run_case.verdict == "no_evil_within_coverage"
        and (manifest_case.ground_truth_label == "nonempty" or not required_complete)
    )

    return _RawCaseScore(
        case_id=manifest_case.case_id,
        ground_truth_label=manifest_case.ground_truth_label,
        expected_claims=frozenset(expected_claims),
        observed_claims=frozenset(observed_claims),
        expected_entities=frozenset(expected_entities),
        observed_entities=frozenset(observed_entities),
        expected_predicates=frozenset(expected_predicates),
        observed_predicates=frozenset(observed_predicates),
        citation_total=citation_total,
        citation_resolved=citation_resolved,
        citation_valid=citation_valid,
        verified_claims=len(asserted),
        claims_with_valid_citation=claims_with_valid_citation,
        uncited_verified_claims=uncited_verified_claims,
        state_counts=state_counts,
        expected_domains=len(expected_coverage),
        matched_expected_outcomes=matched_expected_outcomes,
        required_domains=required_domains,
        completed_required_domains=completed_required_domains,
        unexpected_domains=len(set(observed_coverage) - set(expected_coverage)),
        verdict_correct=verdict_correct,
        no_verdict=no_verdict,
        expected_no_verdict=expected_no_verdict,
        correct_no_verdict=correct_no_verdict,
        unsafe_clean_verdicts=unsafe_clean_verdicts,
        completed_cases=int(run_case.cell_status == "completed"),
        failed_cases=int(run_case.cell_status == "failed"),
        duplicate_claims=duplicate_claims,
        duplicate_citations=duplicate_citations,
    )


def _tagged(values: Iterable[object], case_id: str) -> set[tuple[str, object]]:
    """Keep equal propositions in separate cases distinct during micro averaging."""
    return {(case_id, value) for value in values}


def _aggregate(raw_scores: list[_RawCaseScore]) -> ScoreSlice:
    expected_claims: set[tuple[str, object]] = set()
    observed_claims: set[tuple[str, object]] = set()
    expected_entities: set[tuple[str, object]] = set()
    observed_entities: set[tuple[str, object]] = set()
    expected_predicates: set[tuple[str, object]] = set()
    observed_predicates: set[tuple[str, object]] = set()
    states: Counter[str] = Counter()
    for score in raw_scores:
        expected_claims |= _tagged(score.expected_claims, score.case_id)
        observed_claims |= _tagged(score.observed_claims, score.case_id)
        expected_entities |= _tagged(score.expected_entities, score.case_id)
        observed_entities |= _tagged(score.observed_entities, score.case_id)
        expected_predicates |= _tagged(score.expected_predicates, score.case_id)
        observed_predicates |= _tagged(score.observed_predicates, score.case_id)
        states.update(score.state_counts)

    citation_total = sum(score.citation_total for score in raw_scores)
    citation_resolved = sum(score.citation_resolved for score in raw_scores)
    citation_valid = sum(score.citation_valid for score in raw_scores)
    verified_claims = sum(score.verified_claims for score in raw_scores)
    claims_with_valid_citation = sum(score.claims_with_valid_citation for score in raw_scores)
    total_claims = sum(states.values())
    expected_domains = sum(score.expected_domains for score in raw_scores)
    matched_expected_outcomes = sum(score.matched_expected_outcomes for score in raw_scores)
    required_domains = sum(score.required_domains for score in raw_scores)
    completed_required = sum(score.completed_required_domains for score in raw_scores)
    total_cases = len(raw_scores)
    verdict_correct = sum(score.verdict_correct for score in raw_scores)
    no_verdict = sum(score.no_verdict for score in raw_scores)
    expected_no_verdict = sum(score.expected_no_verdict for score in raw_scores)

    return ScoreSlice(
        case_count=total_cases,
        atomic_claims=_set_score(expected_claims, observed_claims),
        entities=_set_score(expected_entities, observed_entities),
        predicates=_set_score(expected_predicates, observed_predicates),
        citations=CitationScore(
            total=citation_total,
            resolved=citation_resolved,
            valid=citation_valid,
            unresolved=citation_total - citation_resolved,
            verified_claims=verified_claims,
            claims_with_valid_citation=claims_with_valid_citation,
            uncited_verified_claims=sum(score.uncited_verified_claims for score in raw_scores),
            resolution_rate=_rate(citation_resolved, citation_total, empty=1.0),
            validity_rate=_rate(citation_valid, citation_total, empty=1.0),
            claim_citation_rate=_rate(claims_with_valid_citation, verified_claims, empty=1.0),
        ),
        epistemic=EpistemicScore(
            total_claims=total_claims,
            verified=states["verified"],
            contradicted=states["contradicted"],
            inconclusive=states["inconclusive"],
            unsupported=states["unsupported"],
            unverified=states["unverified"],
            contradicted_rate=_rate(states["contradicted"], total_claims),
            inconclusive_rate=_rate(states["inconclusive"], total_claims),
            unsupported_rate=_rate(states["unsupported"], total_claims),
        ),
        coverage=CoverageScore(
            expected_domains=expected_domains,
            matched_expected_outcomes=matched_expected_outcomes,
            required_domains=required_domains,
            completed_required_domains=completed_required,
            unexpected_domains=sum(score.unexpected_domains for score in raw_scores),
            expectation_accuracy=_rate(matched_expected_outcomes, expected_domains, empty=1.0),
            required_completeness=_rate(completed_required, required_domains, empty=1.0),
        ),
        verdicts=VerdictScore(
            total_cases=total_cases,
            completed_cases=sum(score.completed_cases for score in raw_scores),
            failed_cases=sum(score.failed_cases for score in raw_scores),
            correct=verdict_correct,
            no_verdict=no_verdict,
            expected_no_verdict=expected_no_verdict,
            correct_no_verdict=sum(score.correct_no_verdict for score in raw_scores),
            unsafe_clean_verdicts=sum(score.unsafe_clean_verdicts for score in raw_scores),
            accuracy=_rate(verdict_correct, total_cases, empty=1.0),
            no_verdict_rate=_rate(no_verdict, total_cases),
            no_verdict_recall=_rate(
                sum(score.correct_no_verdict for score in raw_scores),
                expected_no_verdict,
                empty=1.0,
            ),
        ),
        duplicate_claims=sum(score.duplicate_claims for score in raw_scores),
        duplicate_citations=sum(score.duplicate_citations for score in raw_scores),
    )


def _distribution(values: Iterable[int | float | None]) -> MetricDistribution:
    """Build stable population statistics, retaining an explicit zero count."""
    samples = [float(value) for value in values if value is not None]
    if not samples:
        return MetricDistribution(count=0)
    mean = round(statistics.fmean(samples), 6)
    variance = round(statistics.pvariance(samples), 6)
    stddev = round(statistics.pstdev(samples), 6)
    return MetricDistribution(
        count=len(samples),
        mean=mean,
        population_variance=variance,
        population_stddev=stddev,
        minimum=round(min(samples), 6),
        maximum=round(max(samples), 6),
    )


def _aggregate_repeats(runs: list[RunScore]) -> list[AggregateScore]:
    by_cell: dict[str, list[RunScore]] = {}
    for run in runs:
        cell = (
            run.identity.matrix_cell
            if run.identity is not None
            else f"{run.system_name}@{run.system_version}"
        )
        by_cell.setdefault(cell, []).append(run)

    aggregates: list[AggregateScore] = []
    for cell, cell_runs in sorted(by_cell.items()):
        cell_runs.sort(key=lambda run: run.run_id)
        metrics = {
            "atomic_claims.precision": _distribution(
                run.overall.atomic_claims.precision for run in cell_runs
            ),
            "atomic_claims.recall": _distribution(
                run.overall.atomic_claims.recall for run in cell_runs
            ),
            "atomic_claims.f1": _distribution(run.overall.atomic_claims.f1 for run in cell_runs),
            "entities.f1": _distribution(run.overall.entities.f1 for run in cell_runs),
            "predicates.f1": _distribution(run.overall.predicates.f1 for run in cell_runs),
            "citations.validity_rate": _distribution(
                run.overall.citations.validity_rate for run in cell_runs
            ),
            "citations.claim_citation_rate": _distribution(
                run.overall.citations.claim_citation_rate for run in cell_runs
            ),
            "coverage.expectation_accuracy": _distribution(
                run.overall.coverage.expectation_accuracy for run in cell_runs
            ),
            "coverage.required_completeness": _distribution(
                run.overall.coverage.required_completeness for run in cell_runs
            ),
            "verdicts.accuracy": _distribution(run.overall.verdicts.accuracy for run in cell_runs),
            "verdicts.no_verdict_rate": _distribution(
                run.overall.verdicts.no_verdict_rate for run in cell_runs
            ),
            "verdicts.failed_cases": _distribution(
                run.overall.verdicts.failed_cases for run in cell_runs
            ),
            "verdicts.failed_rate": _distribution(
                _rate(run.overall.verdicts.failed_cases, run.overall.case_count)
                for run in cell_runs
            ),
            "verdicts.completed_rate": _distribution(
                _rate(run.overall.verdicts.completed_cases, run.overall.case_count)
                for run in cell_runs
            ),
            "epistemic.unsupported_rate": _distribution(
                run.overall.epistemic.unsupported_rate for run in cell_runs
            ),
            "epistemic.contradicted_rate": _distribution(
                run.overall.epistemic.contradicted_rate for run in cell_runs
            ),
            "epistemic.inconclusive_rate": _distribution(
                run.overall.epistemic.inconclusive_rate for run in cell_runs
            ),
            "resources.runtime_ms": _distribution(run.resources.runtime_ms for run in cell_runs),
            "resources.total_tokens": _distribution(
                run.resources.total_tokens for run in cell_runs
            ),
            "resources.cost_usd": _distribution(run.resources.cost_usd for run in cell_runs),
        }
        aggregates.append(
            AggregateScore(
                matrix_cell=cell,
                run_ids=[run.run_id for run in cell_runs],
                repeat_count=len(cell_runs),
                metrics=metrics,
            )
        )
    return aggregates


def _matrix_identity_key(run: BenchmarkRunResult) -> tuple[object, ...] | None:
    """Return cell-invariant provenance, excluding repeat index and seed."""
    identity = run.identity
    if identity is None:
        return None
    return (
        run.system_name,
        run.system_version,
        tuple(sorted(identity.models.items())),
        identity.prompt_set_sha256,
        identity.toolset_sha256,
        identity.orchestrator_version,
        identity.methodology_version,
        tuple(sorted(identity.ablations)),
    )


def _case_score(raw: _RawCaseScore) -> CaseScore:
    score = _aggregate([raw])
    return CaseScore(
        **score.model_dump(),
        case_id=raw.case_id,
        ground_truth_label=raw.ground_truth_label,
    )


def score_benchmark(
    manifest: BenchmarkManifest, results: Iterable[BenchmarkRunResult]
) -> BenchmarkScoreDocument:
    """Score complete result objects, rejecting incomparable case sets."""
    manifest_cases = {case.case_id: case for case in manifest.cases}
    expected_case_ids = set(manifest_cases)
    run_scores: list[RunScore] = []
    seen_run_ids: set[str] = set()
    seen_repeats: set[tuple[str, int]] = set()
    matrix_identities: dict[str, tuple[object, ...]] = {}
    for result in results:
        if result.benchmark_id != manifest.benchmark_id:
            raise ValueError(
                f"run {result.run_id!r} benchmark_id {result.benchmark_id!r} does not match "
                f"manifest {manifest.benchmark_id!r}"
            )
        if result.run_id in seen_run_ids:
            raise ValueError(f"duplicate run_id: {result.run_id!r}")
        seen_run_ids.add(result.run_id)
        if result.identity is not None:
            if result.identity.methodology_version != manifest.methodology_version:
                raise ValueError(
                    f"run {result.run_id!r} methodology version "
                    f"{result.identity.methodology_version!r} does not match manifest "
                    f"{manifest.methodology_version!r}"
                )
            repeat = (result.identity.matrix_cell, result.identity.repeat_index)
            if repeat in seen_repeats:
                raise ValueError(
                    f"duplicate repeat_index {repeat[1]} for matrix cell {repeat[0]!r}"
                )
            seen_repeats.add(repeat)
            identity_key = _matrix_identity_key(result)
            assert identity_key is not None
            earlier_identity = matrix_identities.setdefault(
                result.identity.matrix_cell, identity_key
            )
            if identity_key != earlier_identity:
                raise ValueError(
                    f"matrix cell {result.identity.matrix_cell!r} has inconsistent "
                    "system/model/prompt/tool/orchestrator/methodology/ablation identity"
                )
        result_cases = {case.case_id: case for case in result.cases}
        if set(result_cases) != expected_case_ids:
            missing = sorted(expected_case_ids - set(result_cases))
            unexpected = sorted(set(result_cases) - expected_case_ids)
            raise ValueError(
                f"run {result.run_id!r} has an incomparable case set; "
                f"missing={missing!r}, unexpected={unexpected!r}"
            )
        raw = [
            _score_case(manifest_case, result_cases[case_id])
            for case_id, manifest_case in sorted(manifest_cases.items())
        ]
        clean = [score for score in raw if score.ground_truth_label == "clean"]
        nonempty = [score for score in raw if score.ground_truth_label == "nonempty"]
        run_scores.append(
            RunScore(
                run_id=result.run_id,
                system_name=result.system_name,
                system_version=result.system_version,
                identity=result.identity,
                result_sha256=_document_hash(result),
                overall=_aggregate(raw),
                clean=_aggregate(clean),
                nonempty=_aggregate(nonempty),
                cases=[_case_score(score) for score in raw],
                resources=result.resources,
            )
        )

    if not run_scores:
        raise ValueError("at least one benchmark result is required")
    run_scores.sort(key=lambda score: score.run_id)
    return BenchmarkScoreDocument(
        benchmark_id=manifest.benchmark_id,
        manifest_sha256=_document_hash(manifest),
        methodology_version=manifest.methodology_version,
        runs=run_scores,
        aggregates=_aggregate_repeats(run_scores),
    )
