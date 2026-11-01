"""Every NetFlow source records a windows hash that ``verify_evidence_integrity`` confirms."""

from __future__ import annotations

from mulder.db import WINDOWS_HASH_PENDING
from tests.conftest import Env


def _netflow_results(nf_env: Env) -> list[dict[str, object]]:
    return [
        r
        for r in nf_env.db.verify_evidence_integrity()
        if str(r["source_name"]).startswith("netflow.")
    ]


def test_analysis_sources_verify(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_analysis", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    results = _netflow_results(nf_env)
    names = {str(r["source_name"]) for r in results}
    # the summary, the completion marker and the progress record (header plus footer)
    assert any(n.startswith("netflow.analysis.") for n in names)
    assert any(n.startswith("netflow.complete.") for n in names)
    assert any(n.startswith("netflow.progress.") for n in names)
    assert {r["status"] for r in results} == {"verified"}, results


def test_pivot_source_verifies_and_detects_a_modified_row(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    (result,) = _netflow_results(nf_env)
    assert result["status"] == "verified" and result["window_count"] == resp["row_count"] + 1

    with nf_env.db._engine.begin() as conn:  # noqa: SLF001 - tamper with a stored row
        conn.exec_driver_sql(
            "UPDATE windows SET raw_text = raw_text || ' x' WHERE window_id = "
            "(SELECT MAX(window_id) FROM windows)"
        )
    (result,) = _netflow_results(nf_env)
    assert result["status"] == "modified"


def test_a_source_cut_short_verifies_as_incomplete(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    (source,) = [s for s in nf_env.db.get_sources() if s.source_name.startswith("netflow.")]
    nf_env.db.set_windows_hash(source.source_id, WINDOWS_HASH_PENDING)
    (result,) = _netflow_results(nf_env)
    assert result["status"] == "incomplete"
