#!/usr/bin/env python3
"""Reproducibly normalize the checked-in NDLC adjudication; performs no I/O off disk."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "examples" / "ndlc" / "ACCURACY-REPORT.md"
OUTPUT_DIR = Path(__file__).resolve().parent

ARTIFACTS = (
    (
        "pc-archive-part",
        "pc.7z.001",
        "7409b09714121f56be88f161450ebad92e194ff0554462be3187525eb76aa695",
    ),
    ("pc-e01", "pc.E01", "e6365e44f1004252171acb73e6779be05277cbd57d09d7febed22d2463a956a9"),
    ("rm1-e01", "rm1.E01", "a14150a21bc1e3700b51912c2ab20cd9587ad3e27ee67475af64508a7e760121"),
    ("rm2-archive", "rm2.7z", "ade9fb60ba1f700b93c6b8b1f538c72000411e5b30037dc95c300c5a0aeafd65"),
    ("rm2-e01", "rm2.E01", "25215f9bcb51ceee9147886ed3f5c13ef148de634fc5114491e0f8dad8b15696"),
    (
        "rm3-type1-archive",
        "rm3_type1.7z",
        "f30f3408bf1a0eec5a34851c66a711634618430ac1794b24afa917b3b2c729e1",
    ),
    (
        "rm3-type2-archive",
        "rm3_type2.7z",
        "9e6137a9b101ef7ff7e12fcf8740a83a559179d0d3d75daedf4b1c40e98a8fef",
    ),
    (
        "rm3-type3-e01",
        "rm3_type3.E01",
        "336e1307721ef5f63679379961d1716b74f986e69df8c40117d9cea7858d512b",
    ),
)


def _rows(text: str) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for line in text.splitlines():
        if not re.match(r"^\| \d+ \|", line):
            continue
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        if len(cells) != 4:
            raise ValueError(f"unexpected NDLC adjudication row: {line}")
        rows.append(cells)
    if [int(row[0]) for row in rows] != list(range(1, 21)):
        raise ValueError("expected the unchanged 20-row NDLC adjudication")
    return rows


def _reported_counts(text: str) -> dict[str, int]:
    scorecard = text.split("## Scorecard", 1)[1].split("## Ground Truth", 1)[0]
    counts = {
        status: int(count)
        for status, count in re.findall(
            r"^\| (FOUND|PARTIAL|MISSED|FALSE POSITIVE) \| (\d+) \|",
            scorecard,
            flags=re.MULTILINE,
        )
    }
    if set(counts) != {"FOUND", "PARTIAL", "MISSED", "FALSE POSITIVE"}:
        raise ValueError("could not parse the NDLC scorecard")
    return counts


def _evidence() -> list[dict[str, object]]:
    return [
        {
            "artifact_id": artifact_id,
            "path": f"downloads/{filename}",
            "sha256": digest,
            "origin": "real",
            "redistribution": "manifest_only",
            "license": {
                "name": "NIST CFReDS published dataset terms (verify at source)",
                "url": "https://cfreds-archive.nist.gov/",
            },
            "source_url": "https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html",
        }
        for artifact_id, filename, digest in ARTIFACTS
    ]


def main() -> None:
    source_bytes = SOURCE.read_bytes()
    text = source_bytes.decode("utf-8")
    rows = _rows(text)
    reported_counts = _reported_counts(text)
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()

    expected_claims = [
        {
            "claim_id": f"ndlc-{int(item_id):02d}",
            "subject": f"ndlc:answer-key-item:{int(item_id):02d}",
            "predicate": "historical_full_match",
            "object_value": ground_truth,
        }
        for item_id, ground_truth, _status, _observed in rows
    ]
    manifest = {
        "schema_version": 1,
        "benchmark_id": "nist-cfreds-ndlc-2015-historical",
        "title": "NIST CFReDS Data Leakage Case 2015 — historical Mulder run",
        "description": (
            "A normalization of examples/ndlc/ACCURACY-REPORT.md. The answer-key "
            "items and human labels are preserved; this does not re-run the case."
        ),
        "methodology_version": "1.0",
        "cases": [
            {
                "case_id": "ndlc-2015",
                "title": "NIST CFReDS Data Leakage Case 2015",
                "ground_truth_label": "nonempty",
                "applicability": ["real:disk-images", "forensics:data-leakage"],
                "expected_verdict": "positive",
                "evidence": _evidence(),
                "coverage": [
                    {
                        "domain": "legacy/human-adjudication",
                        "applicability": "applicable",
                        "expected_content": "nonempty",
                        "acceptable_statuses": ["PARTIAL"],
                    }
                ],
                "expected_claims": expected_claims,
                "anchors": [],
            }
        ],
    }

    state_by_status = {
        "FOUND": "verified",
        "PARTIAL": "inconclusive",
        "FALSE POSITIVE": "contradicted",
    }
    claims = [
        {
            "claim_id": f"historical-{int(item_id):02d}",
            "subject": f"ndlc:answer-key-item:{int(item_id):02d}",
            "predicate": "historical_full_match",
            "object_value": ground_truth if status == "FOUND" else observed,
            "verification_state": state_by_status[status],
            "citations": [],
        }
        for item_id, ground_truth, status, observed in rows
        if status != "MISSED"
    ]
    result = {
        "schema_version": 1,
        "benchmark_id": manifest["benchmark_id"],
        "run_id": "mulder-ndlc-historical-2026-06-06",
        "system_name": "mulder",
        "system_version": "historical-unrecorded",
        "identity": {
            "matrix_cell": "historical/ndlc/claude-opus-4-6",
            "models": {
                "analyst": "claude-opus-4-6",
                "orchestrator": "claude-sonnet-4-5@20250929",
            },
            "orchestrator_version": "historical-unrecorded",
            "methodology_version": "1.0",
            "repeat_index": 0,
            "ablations": [],
        },
        "cases": [
            {
                "case_id": "ndlc-2015",
                "verdict": "positive",
                "cell_status": "completed",
                "claims": claims,
                "coverage": [{"domain": "legacy/human-adjudication", "status": "PARTIAL"}],
            }
        ],
        "resources": {
            "runtime_ms": 6_120_000,
            "unattributed_tokens": 330_300,
        },
        "source_adjudication": {
            "scheme": "FOUND/PARTIAL/MISSED/FALSE POSITIVE",
            "source_path": "examples/ndlc/ACCURACY-REPORT.md",
            "source_sha256": source_sha256,
            "reported_counts": reported_counts,
            "items": [
                {
                    "item_id": item_id,
                    "status": status,
                    "ground_truth": ground_truth,
                    "observed": observed,
                }
                for item_id, ground_truth, status, observed in rows
            ],
            "count_mismatch_note": (
                "The source scorecard reports 12 FOUND and 6 PARTIAL, while its "
                "20 item rows contain 11 FOUND and 7 PARTIAL. Both are retained "
                "verbatim; this import does not re-adjudicate the historical run."
            ),
            "note": (
                "FOUND rows become verified exact claims. PARTIAL rows remain "
                "inconclusive, FALSE POSITIVE remains contradicted, and MISSED has "
                "no observed claim. No atomic evidence anchors were recorded in the "
                "historical report, so citation scores are intentionally zero."
            ),
        },
    }

    for filename, document in (
        ("manifest-v1.json", manifest),
        ("result-historical.json", result),
    ):
        (OUTPUT_DIR / filename).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
