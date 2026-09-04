"""Deterministic duplicate-candidate policy shared by production and benchmarks."""

from __future__ import annotations

import re

from mulder.models import Finding

_IOC_PATTERN = re.compile(
    r"\b(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|[a-fA-F0-9]{32,64}"
    r"|(?:[a-z0-9-]+\.)+[a-z]{2,}"
    r")\b"
)


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 0.0
    return len(left & right) / len(left | right)


def _tokenize(text: str) -> set[str]:
    return {word.lower().strip(".,;:!?()[]") for word in text.split() if len(word) > 2}


def _time_windows_overlap(left: Finding, right: Finding) -> float:
    if not left.event_time_start or not right.event_time_start:
        return 0.0
    left_end = left.event_time_end or left.event_time_start
    right_end = right.event_time_end or right.event_time_start
    return float(left.event_time_start <= right_end and right.event_time_start <= left_end)


def finding_similarity(left: Finding, right: Finding) -> float:
    """Apply the production six-signal duplicate-candidate calculation."""
    return (
        0.20 * _jaccard(_tokenize(left.title), _tokenize(right.title))
        + 0.15 * _jaccard(set(left.mitre_attack_ids), set(right.mitre_attack_ids))
        + 0.15
        * _jaccard(
            set(_IOC_PATTERN.findall(left.description.lower())),
            set(_IOC_PATTERN.findall(right.description.lower())),
        )
        + 0.25 * _jaccard(set(left.evidence_refs), set(right.evidence_refs))
        + 0.15 * _jaccard(set(left.sources), set(right.sources))
        + 0.10 * _time_windows_overlap(left, right)
    )


def group_duplicate_findings(findings: list[Finding], threshold: float) -> list[list[Finding]]:
    """Group duplicate candidates using the exact production policy."""
    if threshold < 0 or threshold > 1:
        raise ValueError("similarity threshold must be between zero and one")
    groups: list[list[Finding]] = []
    assigned: set[str] = set()
    for finding in findings:
        if finding.finding_id in assigned:
            continue
        group = [finding]
        assigned.add(finding.finding_id)
        for candidate in findings:
            if candidate.finding_id in assigned:
                continue
            if any(finding_similarity(member, candidate) >= threshold for member in group):
                group.append(candidate)
                assigned.add(candidate.finding_id)
        groups.append(group)
    return groups


def representative_finding(group: list[Finding]) -> Finding:
    """Choose the same longest-description representative as production consolidation."""
    if not group:
        raise ValueError("duplicate group cannot be empty")
    return max(group, key=lambda finding: len(finding.description))
