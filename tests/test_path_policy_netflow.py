"""evidence_path goes through mulder.path_policy: only the evidence root and the case DB dir.

What: ``/etc`` and a relative path are ``invalid_argument``; a symlink inside the root that points
outside is denied after resolution; a path under ``cfg.db_dir`` is allowed (also when the case
metadata has no evidence_root, and ``Path("")`` never becomes a root); a NUL byte is an audited
``invalid_argument`` instead of an escaping ``ValueError``; the response and the registered
``source_path`` carry the resolved path (``..`` collapsed); a symlinked nfcapd file inside the
root is excluded with ``reason: symlink``; missing paths and directories without nfcapd files are
``file_not_found``; no open case is ``no_case_loaded``.
When: hermetic (fake subprocess, tmp roots: evidence root ``tmp/evidence``, db dir ``tmp/db``).
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from mulder.server.tools.netflow import tools
from tests.netflow_harness import NETFLOW_TOOLS, Env, make_tree, nfcapd


def _invalid(resp: dict[str, object]) -> None:
    assert resp["status"] == "error", resp
    assert resp["error_type"] == "invalid_argument"
    assert "nfdump_argv" not in resp


def test_etc_outside_every_root(nf_env: Env) -> None:
    resp = nf_env.call("run_netflow_query", evidence_path="/etc")
    _invalid(resp)
    assert "inside the case evidence root" in str(resp["suggestion"])
    assert nf_env.fake.calls == []
    assert nf_env.db.get_sources() == []


def test_relative_path(nf_env: Env) -> None:
    nf_env.tree(days=range(63, 64), strays=False)
    resp = nf_env.call("run_netflow_top", evidence_path="netflow/edge-router/2001/02")
    _invalid(resp)
    assert "absolute" in str(resp["error_message"])
    resp = nf_env.call("run_netflow_top", evidence_path="")
    _invalid(resp)


def test_symlink_inside_root_pointing_outside(
    nf_env: Env, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("outside")
    make_tree(outside, days=range(63, 64), strays=False)
    link = nf_env.evidence_root / "linked"
    link.symlink_to(outside / "netflow" / "edge-router")
    resp = nf_env.call("run_netflow_query", evidence_path=str(link / "2001" / "02"))
    _invalid(resp)
    assert nf_env.fake.calls == []


def test_dotdot_escape_is_denied(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    escaped = day_dir / ".." / ".." / ".." / ".." / ".."  # -> tmp_path: neither root
    assert escaped.resolve() == nf_env.tmp_path
    _invalid(nf_env.call("run_netflow_query", evidence_path=str(escaped)))
    _invalid(nf_env.call("run_netflow_query", evidence_path=str(nf_env.tmp_path)))
    _invalid(nf_env.call("run_netflow_query", evidence_path=str(nf_env.evidence_root.parent)))


def test_path_under_db_dir_is_allowed(nf_env: Env) -> None:
    d = nf_env.db_dir / "nf"
    nfcapd(d, day="20010304")
    resp = nf_env.call("run_netflow_top", evidence_path=str(d))
    assert resp["status"] == "success"
    assert resp["evidence_path"] == str(d.resolve())


def test_resolved_path_in_response_and_source_path(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    dotted = day_dir / ".." / "02" / "."
    resp = nf_env.call("run_netflow_query", evidence_path=str(dotted))
    assert resp["status"] == "success"
    assert resp["evidence_path"] == str(day_dir)
    src = nf_env.db.get_sources()[0]
    assert src.source_path == str(day_dir)
    header = nf_env.db.get_windows_page(resp["source_name"])[0][0].raw_text
    assert f" evidence_path={day_dir} " in header
    assert "/../" not in header and "/./" not in header


def test_symlink_inside_root_to_a_dir_inside_root_is_followed(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    alias = nf_env.evidence_root / "alias"
    alias.symlink_to(day_dir)
    resp = nf_env.call("run_netflow_query", evidence_path=str(alias))
    assert resp["status"] == "success"
    assert resp["evidence_path"] == str(day_dir)  # the resolved target, never the alias
    assert nf_env.fake.last.read_args == ["-r", str(day_dir / "nfcapd.200103040000")]


def test_symlinked_nfcapd_inside_root_is_excluded(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    os.symlink(day_dir / "nfcapd.200103040000", day_dir / "nfcapd.200103050000")
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    assert resp["files_scanned"] == 1
    assert resp["files_excluded"] == [
        {"path": str(day_dir / "nfcapd.200103050000"), "reason": "symlink"}
    ]
    assert nf_env.fake.last.read_args == ["-r", str(day_dir / "nfcapd.200103040000")]


def test_single_file_evidence_path_uses_dash_r(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 65), strays=False)
    f = day_dir / "nfcapd.200103040000"
    resp = nf_env.call("run_netflow_query", evidence_path=str(f))
    assert resp["status"] == "success" and resp["files_scanned"] == 1
    assert resp["file_range"] == ["nfcapd.200103040000", "nfcapd.200103040000"]
    assert resp["evidence_path"] == str(f)
    assert nf_env.fake.last.read_args == ["-r", str(f)]
    assert nf_env.db.get_sources()[0].source_path == str(f)


def test_missing_and_empty_targets_are_file_not_found(nf_env: Env) -> None:
    day_dir = nf_env.tree()
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir / "nfcapd.200103320000"))
    assert resp["status"] == "error" and resp["error_type"] == "file_not_found"
    stray = day_dir.parent.parent / "zero-length"
    resp = nf_env.call("run_netflow_query", evidence_path=str(stray))
    assert resp["status"] == "error" and resp["error_type"] == "file_not_found"
    assert resp["files_excluded"] == [{"path": str(stray), "reason": "empty"}]
    assert resp["evidence_path"] == str(stray)
    text = day_dir / "nfcapd.200103035555"
    resp = nf_env.call("run_netflow_query", evidence_path=str(text))
    assert resp["error_type"] == "file_not_found"
    assert resp["files_excluded"] == [{"path": str(text), "reason": "no nfdump magic"}]
    empty_dir = nf_env.evidence_root / "docs"
    empty_dir.mkdir()
    (empty_dir / "README.md").write_text("no flows here\n")
    resp = nf_env.call("run_netflow_query", evidence_path=str(empty_dir))
    assert resp["error_type"] == "file_not_found"
    assert "no nfcapd files under" in resp["error_message"] and resp["files_excluded"] == []
    assert nf_env.fake.calls == []


def test_no_case_loaded(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    nf_env.monkeypatch.setattr(tools, "has_ctx", lambda: False)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "no_case_loaded"
    assert nf_env.fake.calls == []


def test_evidence_root_missing_metadata_root_still_uses_db_dir(nf_env: Env) -> None:
    """A case whose evidence_root is empty still allows paths under db_dir (artifacts.py parity),
    and the empty string never becomes ``Path("")`` == the working directory as a root."""
    real = nf_env.ctx.db.get_case_metadata()
    assert real is not None and real.evidence_root  # the fixture sets it: empty it explicitly
    empty = (
        dataclasses.replace(real, evidence_root="")
        if dataclasses.is_dataclass(real)
        else real.model_copy(update={"evidence_root": ""})
    )
    nf_env.monkeypatch.setattr(nf_env.ctx.db, "get_case_metadata", lambda: empty)
    nf_env.monkeypatch.chdir(nf_env.tmp_path)
    d = nf_env.db_dir / "nf"
    nfcapd(d, day="20010304")
    resolved = tools._resolve_evidence(str(d))
    assert resolved == d.resolve()
    with pytest.raises(Exception, match="outside allowed"):
        tools._resolve_evidence("/etc")
    with pytest.raises(Exception, match="absolute"):
        tools._resolve_evidence("relative")
    assert Path(str(resolved)).is_absolute()
    # the (now unlisted) evidence root is outside every root: a bare Path("") would have
    # admitted the cwd and everything under it
    with pytest.raises(Exception, match="outside allowed"):
        tools._resolve_evidence(str(nf_env.evidence_root))
    with pytest.raises(Exception, match="outside allowed"):
        tools._resolve_evidence(str(nf_env.tmp_path / "evidence"))


@pytest.mark.parametrize("tool", NETFLOW_TOOLS)
def test_nul_byte_in_evidence_path_is_audited_invalid_argument(nf_env: Env, tool: str) -> None:
    """An embedded NUL (``Path.resolve`` raises ValueError on it) becomes an audited
    ``invalid_argument`` in every tool."""
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    required = {
        "run_netflow_host_profile": {"host": "192.0.2.99"},
        "run_netflow_pair_timeline": {"src": "192.0.2.99", "dst": "192.0.2.98"},
    }.get(tool, {})
    for bad in (f"{day_dir}\x00", "/x\x00", "\x00", f"{day_dir}/nfcapd.2001\x0003040000"):
        resp = nf_env.call(tool, evidence_path=bad, **required)
        _invalid(resp)
        assert "NUL" in resp["error_message"]
        assert resp["tool"] == tool and resp["tool_call_id"].startswith("tc_")
        entry = nf_env.audit_entry(resp["tool_call_id"])
        assert entry["tool_name"] == tool and "source" not in entry["params"]
    assert nf_env.fake.calls == [] and nf_env.db.get_sources() == []
