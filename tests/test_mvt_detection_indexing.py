"""Every MVT detection that is counted must also reach the case index.

``_collect_mvt_results`` reported ``module_counts[module] = len(data)`` -- the
number the analyst is shown as "detections" -- but only serialised the first
100 records, and only those that happened to be dicts. A device with 250
Pegasus-related hits was reported as 250 detections while ``search()`` over the
case could surface at most 100 of them, with nothing in the response saying the
rest had been dropped. The count promised evidence the case DB did not hold.

The asymmetry that gives this away: the timeline CSVs in the same function are
indexed in full, uncapped. The 100-record ceiling applied only to the detection
records -- the part that matters most.
"""

from __future__ import annotations

import json
from pathlib import Path

from mulder.server.tools.mvt import _collect_mvt_results


def _write_module(output_dir: Path, name: str, records: object) -> None:
    """Write one MVT module result file: a list of records, or a bare object."""
    (output_dir / f"{name}.json").write_text(json.dumps(records))


def test_every_counted_detection_is_indexed(tmp_path: Path) -> None:
    """250 detections counted must be 250 detections indexed."""
    records: list[object] = [
        {"file": f"/private/var/mobile/evidence_{i}.db", "matched_indicator": f"ioc-{i}"}
        for i in range(250)
    ]
    _write_module(tmp_path, "sms_detected", records)

    raw_output, module_counts = _collect_mvt_results(str(tmp_path))

    assert module_counts["sms_detected"] == 250
    indexed = raw_output.splitlines()
    assert len(indexed) == 250, (
        f"module_counts claims 250 detections but only {len(indexed)} reached the index"
    )


def test_a_detection_past_the_old_cap_is_searchable(tmp_path: Path) -> None:
    """The specific harm: detection 101 exists, is counted, and was unfindable."""
    records: list[object] = [{"matched_indicator": f"ioc-{i}"} for i in range(150)]
    records[130] = {"matched_indicator": "pegasus-c2-domain", "file": "/var/db/late.db"}
    _write_module(tmp_path, "whatsapp_detected", records)

    raw_output, _counts = _collect_mvt_results(str(tmp_path))

    assert "pegasus-c2-domain" in raw_output, (
        "a detection past the 100-record cap never reached the case DB"
    )


def test_a_counted_non_dict_record_is_also_indexed(tmp_path: Path) -> None:
    """The second way a counted record went missing: it was not a dict.

    ``module_counts`` counted every element, but only dicts were serialised, so
    a module emitting bare strings inflated the count over what was searchable.
    """
    records: list[object] = ["/var/mobile/suspicious_path", {"matched_indicator": "x"}]
    _write_module(tmp_path, "backup_detected", records)

    raw_output, module_counts = _collect_mvt_results(str(tmp_path))

    assert module_counts["backup_detected"] == 2
    assert len(raw_output.splitlines()) == 2
    assert "suspicious_path" in raw_output


def test_the_count_and_the_index_agree_across_several_modules(tmp_path: Path) -> None:
    """The invariant, stated directly: sum(counts) == indexed record lines."""
    _write_module(tmp_path, "sms_detected", [{"i": i} for i in range(120)])
    _write_module(tmp_path, "calls_detected", [{"i": i} for i in range(30)])
    _write_module(tmp_path, "config", {"single": "object"})

    raw_output, module_counts = _collect_mvt_results(str(tmp_path))

    assert sum(module_counts.values()) == len(raw_output.splitlines())


# --- narrowness: the fix must not change anything else -----------------------


def test_a_clean_device_still_produces_no_output(tmp_path: Path) -> None:
    """An empty result set stays empty -- no placeholder rows invented."""
    _write_module(tmp_path, "sms_detected", [])

    raw_output, module_counts = _collect_mvt_results(str(tmp_path))

    assert module_counts["sms_detected"] == 0
    assert raw_output == ""


def test_timeline_csvs_are_still_indexed_whole(tmp_path: Path) -> None:
    """Pins the untouched path: CSV timelines were and remain uncapped."""
    (tmp_path / "timeline.csv").write_text("ts,event\n1,a\n2,b\n")

    raw_output, _counts = _collect_mvt_results(str(tmp_path))

    assert "=== timeline.csv ===" in raw_output
    assert "1,a" in raw_output and "2,b" in raw_output


def test_a_malformed_module_file_is_still_skipped(tmp_path: Path) -> None:
    """Pins the untouched error path: bad JSON is suppressed, not raised."""
    (tmp_path / "broken.json").write_text("{not json")
    _write_module(tmp_path, "sms_detected", [{"matched_indicator": "ok"}])

    raw_output, module_counts = _collect_mvt_results(str(tmp_path))

    assert "broken" not in module_counts
    assert "ok" in raw_output


def test_one_record_per_line_so_none_is_split_across_windows(tmp_path: Path) -> None:
    """Records must stay line-delimited; a newline inside a value must not split one."""
    records: list[object] = [
        {"matched_indicator": "first"},
        {"note": "line one\nline two"},
        {"matched_indicator": "last"},
    ]
    _write_module(tmp_path, "sms_detected", records)

    raw_output, _counts = _collect_mvt_results(str(tmp_path))

    lines = raw_output.splitlines()
    assert len(lines) == 3, "an embedded newline broke a record across lines"
    for line in lines:
        json.loads(line)
