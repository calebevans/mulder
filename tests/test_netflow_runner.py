"""The nfdump runner: semaphore, slot-wait budget, prlimit prefix, stderr classifier, exit codes.

What: at most two ``subprocess.run`` calls are ever in flight (the third waits and reports
``slot_wait_s``); a call that cannot get a slot within its budget is ``error_type="timeout"``
without touching nfdump; ``RLIMIT_AS`` (and ``RLIMIT_CORE=0``) are applied by the
``prlimit --as=4294967296 --core=0 --`` argv prefix (instead of ``preexec_fn``) and a missing
``prlimit`` refuses to run nfdump; ANY stderr line at rc 0 that is not in the (empty) benign
allowlist is ``tool_failed`` and nothing is registered (nfdump 1.7.10 stops a ``-R`` walk silently
on a truncated or block-corrupt file); rc 254 is ``invalid_argument`` with nfdump's message;
rc 255, death by SIGABRT (rc -6 / 134) and allocation messages carry the memory suggestion;
identical concurrent calls register one source; the staging directory is removed even when the
subprocess raises.
When: hermetic (fake subprocess).
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from mulder.server.tools.netflow import core, tools
from mulder.server.tools.netflow.tools import NfFailure, NfRun
from tests.netflow_harness import PRLIMIT_PREFIX, Env, fixture_text

_READ = ["-r", "/evidence/nfcapd.200103040000"]


def _run(timeout: int = 30) -> NfRun | NfFailure:
    return tools._run_nfdump(_READ, ["-s", "ip/flows", "-n", "5"], core.STAT_FMT, "any", timeout)


def _single(nf_env: Env) -> Path:
    return nf_env.tree(days=range(63, 64), strays=False)


# ---------------------------------------------------------------------------
# semaphore
# ---------------------------------------------------------------------------


def test_never_more_than_two_nfdump_processes(nf_env: Env) -> None:
    lock = threading.Lock()
    state = {"inside": 0, "peak": 0}
    entered = threading.Semaphore(0)
    release = threading.Event()

    def hook(_argv: list[str]) -> None:
        with lock:
            state["inside"] += 1
            state["peak"] = max(state["peak"], state["inside"])
        entered.release()
        assert release.wait(10)
        with lock:
            state["inside"] -= 1

    nf_env.fake.hook = hook
    results: list[NfRun | NfFailure] = []
    threads = [threading.Thread(target=lambda: results.append(_run())) for _ in range(3)]
    for t in threads:
        t.start()
    assert entered.acquire(timeout=5) and entered.acquire(timeout=5)
    time.sleep(0.4)
    with lock:
        assert state["inside"] == 2  # the third call is waiting for a slot, not running
    assert len(nf_env.fake.calls) == 2
    release.set()
    for t in threads:
        t.join(timeout=10)
    assert state["peak"] == 2
    assert len(results) == 3 and all(isinstance(r, NfRun) for r in results)
    waits = sorted(r.slot_wait_s for r in results)
    assert waits[0] < 0.2 and waits[-1] >= 0.3


def test_slot_wait_timeout_is_error_type_timeout(nf_env: Env) -> None:
    assert tools._NFDUMP_SLOTS.acquire(timeout=1) and tools._NFDUMP_SLOTS.acquire(timeout=1)
    try:
        res = _run(timeout=1)
    finally:
        tools._NFDUMP_SLOTS.release()
        tools._NFDUMP_SLOTS.release()
    assert isinstance(res, NfFailure)
    assert res.error_type == "timeout"
    assert "slot" in res.error and "2 per server" in res.error
    assert res.slot_wait_s >= 0.9
    assert res.argv[: len(PRLIMIT_PREFIX)] == PRLIMIT_PREFIX
    assert nf_env.fake.calls == []


def test_slot_wait_timeout_through_a_tool(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.monkeypatch.setattr(core, "timeout_for", lambda selected: 1)
    assert tools._NFDUMP_SLOTS.acquire(timeout=1) and tools._NFDUMP_SLOTS.acquire(timeout=1)
    try:
        resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    finally:
        tools._NFDUMP_SLOTS.release()
        tools._NFDUMP_SLOTS.release()
    assert resp["status"] == "error" and resp["error_type"] == "timeout"
    assert resp["slot_wait_s"] >= 0.9
    assert "retry" in resp["suggestion"]
    assert resp["nfdump_argv"][: len(PRLIMIT_PREFIX)] == PRLIMIT_PREFIX
    assert nf_env.fake.calls == []
    assert nf_env.db.get_sources() == []
    entry = nf_env.audit_entry(resp["tool_call_id"])
    assert "source" not in entry["params"]


def test_slot_is_released_after_failure_and_exception(nf_env: Env) -> None:
    nf_env.fake.raise_exc = OSError("boom")
    assert isinstance(_run(), NfFailure)
    nf_env.fake.raise_exc = subprocess.TimeoutExpired(cmd="nfdump", timeout=1)
    assert isinstance(_run(), NfFailure)
    nf_env.fake.raise_exc = None
    nf_env.fake.returncode = 1
    assert isinstance(_run(), NfFailure)
    # both slots are free again: two acquires succeed without waiting
    assert tools._NFDUMP_SLOTS.acquire(timeout=0.1) and tools._NFDUMP_SLOTS.acquire(timeout=0.1)
    tools._NFDUMP_SLOTS.release()
    tools._NFDUMP_SLOTS.release()


# ---------------------------------------------------------------------------
# RLIMIT_AS via a prlimit argv prefix (instead of preexec_fn)
# ---------------------------------------------------------------------------


def test_rlimit_as_is_a_prlimit_argv_prefix_not_preexec_fn(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    call = nf_env.fake.last
    assert call.cmd[:5] == [
        "/usr/bin/prlimit", "--as=4294967296", "--core=0", "--", core.NFDUMP_BINARY,
    ]  # fmt: skip
    assert core.NFDUMP_RLIMIT_AS == 4 << 30 == 4294967296
    assert core.NFDUMP_RLIMIT_CORE == 0  # an abort under the cap never writes a multi-GiB core
    assert "preexec_fn" not in call.kwargs
    assert resp["nfdump_argv"] == call.cmd


def test_missing_prlimit_refuses_to_run_nfdump(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.monkeypatch.setattr(
        tools, "require_binary", lambda name: name if name == core.NFDUMP_BINARY else None
    )
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "binary_missing"
    assert "prlimit" in resp["error_message"]
    assert nf_env.fake.calls == []
    assert nf_env.db.get_sources() == []


def test_missing_nfdump_is_binary_missing(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.monkeypatch.setattr(tools, "require_binary", lambda name: None)
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "binary_missing"
    assert "nfdump" in resp["error_message"]
    assert nf_env.fake.calls == []


def test_nfdump_fallback_to_path_lookup(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    which = {"nfdump": "/usr/local/bin/nfdump", "prlimit": "/usr/bin/prlimit"}
    nf_env.monkeypatch.setattr(tools, "require_binary", lambda name: which.get(name))
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "success"
    assert nf_env.fake.last.cmd[:5] == ["/usr/bin/prlimit", "--as=4294967296", "--core=0", "--",
                                        "/usr/local/bin/nfdump"]  # fmt: skip


# ---------------------------------------------------------------------------
# stderr / exit-code classification
# ---------------------------------------------------------------------------


def _register_spy(nf_env: Env) -> list[str]:
    registered: list[str] = []
    real = nf_env.db.register_source

    def spy(*args: Any, **kwargs: Any) -> int:
        registered.append(str(args[0] if args else kwargs.get("source_name")))
        return int(real(*args, **kwargs))

    nf_env.monkeypatch.setattr(nf_env.db, "register_source", spy)
    return registered


@pytest.mark.parametrize(
    "stderr",
    [
        "Short read from file: /tmp/nfsel_k3j2/000001\n",
        "read() error in nffile.c line 786: Success\n",
        "stat() error for file 000000: No such file or directory\n",
        "Error open file: /tmp/nfsel_x/000000\n",
        "bad magic: 0x1234\n",
        "bad version: 3\n",
        "malloc() error in nfx.c: Cannot allocate memory\n",
        "pthread_create() error in nfdump.c line 636: Resource temporarily unavailable\n",
        # the messages nfdump 1.7.10 prints at rc 0 for truncated / block-corrupt files
        "Open file /tmp/nfsel_x/000001: appendix offset error\n",
        "Unknown block type 99. Skip block\n",
        "Corrupt data file: Error buffer size 2147483647\n",
        "DataBlock count error\nDataBlock: count: 100, size: 1048576. Found: 50\n",
        "Can't process block type 7. Skip block\n",
        "Corrupt extension 42. Skip record\n",
        "Warn: something\nShort read from file: x\nother\n",
    ],
)
def test_failing_stderr_at_rc0_is_tool_failed_and_never_indexed(nf_env: Env, stderr: str) -> None:
    day_dir = nf_env.tree(days=range(62, 65), strays=False)
    registered = _register_spy(nf_env)
    nf_env.fake.stderr = stderr
    nf_env.fake.returncode = 0
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert resp["status"] == "error", resp
    assert resp["error_type"] == "tool_failed"
    assert resp["error_message"].startswith("nfdump reported a damaged or unreadable input file: ")
    assert core.STDERR_FAIL_RE.search(resp["error_message"])
    assert "Warn: something" not in resp["error_message"]
    assert "truncated, block-corrupt or unreadable" in resp["suggestion"]
    for key in ("nfdump_argv", "slot_wait_s", "elapsed_s", "evidence_path", "files_scanned",
                "file_range", "files_excluded"):  # fmt: skip
        assert key in resp, key
    assert resp["files_scanned"] == 3
    assert registered == []
    assert nf_env.db.get_sources() == []
    assert nf_env.audit_entry(resp["tool_call_id"])["tool_name"] == "run_netflow_query"


def test_rc255_is_tool_failed_with_memory_suggestion(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.returncode = 255
    nf_env.fake.stderr = (
        "pthread_create() error in nfdump.c line 636: Resource temporarily unavailable\n"
    )
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes")
    assert resp["status"] == "error" and resp["error_type"] == "tool_failed"
    assert "pthread_create() error" in resp["error_message"]
    assert "4 GiB memory limit" in resp["suggestion"]
    assert nf_env.db.get_sources() == []


_ASSERTION = (
    "nfdump: nflowcache.c:395: flowHash_resize: Assertion `newFlags && newCells && newRecords' "
    "failed.\n"
)


def test_sigabrt_under_rlimit_is_tool_failed_with_memory_suggestion(nf_env: Env) -> None:
    """nfdump can abort (SIGABRT, rc -6) under the 4 GiB cap; it is classified like rc 255."""
    day_dir = _single(nf_env)
    nf_env.fake.returncode = -6
    nf_env.fake.stderr = _ASSERTION
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes",
                       filter="ipv4")  # fmt: skip
    assert resp["status"] == "error" and resp["error_type"] == "tool_failed"
    assert resp["error_message"].startswith("nfdump killed by SIGABRT (likely hit its 4 GiB")
    assert "flowHash_resize" in resp["error_message"]
    assert "4 GiB memory limit" in resp["suggestion"] and "'src ip'" in resp["suggestion"]
    assert nf_env.db.get_sources() == []
    # a shell-style 134, and an allocation message at any other rc, get the same treatment
    nf_env.fake.returncode = 134
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes",
                       filter="proto tcp")  # fmt: skip
    assert resp["error_type"] == "tool_failed" and "4 GiB memory limit" in resp["suggestion"]
    assert resp["error_message"].startswith("nfdump aborted (SIGABRT")
    nf_env.fake.returncode = 1
    nf_env.fake.stderr = "Memory allocation error in nflowcache.c line 200\n"
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes",
                       filter="proto udp")  # fmt: skip
    assert resp["error_type"] == "tool_failed" and "4 GiB memory limit" in resp["suggestion"]
    assert resp["error_message"].startswith("nfdump exited 1: Memory allocation error")
    # an unknown signal number still produces a structured response
    nf_env.fake.returncode = -200
    nf_env.fake.stderr = ""
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir), order="bytes",
                       filter="proto icmp")  # fmt: skip
    assert resp["error_type"] == "tool_failed"
    assert resp["error_message"].startswith("nfdump killed by signal 200")


def test_rc254_is_invalid_argument_with_nfdump_message(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.returncode = 254
    nf_env.fake.stdout = fixture_text("exit254.txt")
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), filter="src ip 192.0.2.99 and"
    )
    assert resp["status"] == "error" and resp["error_type"] == "invalid_argument"
    assert "syntax error" in resp["error_message"]
    assert "Line 1" in resp["error_message"]
    assert core.EXAMPLE_FILTERS[0] in resp["suggestion"]
    assert resp["nfdump_argv"][-1] == "src ip 192.0.2.99 and"
    assert nf_env.db.get_sources() == []


def test_rc1_flg_misuse_is_tool_failed(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.returncode = 1
    nf_env.fake.stdout = ""
    nf_env.fake.stderr = fixture_text("flg_stderr.txt")
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), aggregate=["srcip", "dstip"]
    )
    assert resp["status"] == "error" and resp["error_type"] == "tool_failed"
    assert resp["error_message"].startswith("nfdump exited 1: Output token %flg")


def test_any_stderr_at_rc0_is_tool_failed_unless_allowlisted(nf_env: Env) -> None:
    """A healthy nfdump 1.7.10 run prints nothing on stderr; an unknown message is a failure, not
    a warning, because a damaged file makes nfdump stop its walk with rc 0."""
    day_dir = _single(nf_env)
    registered = _register_spy(nf_env)
    nf_env.fake.stderr = "Notice: one\nNotice: two\n"
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "tool_failed"
    assert resp["error_message"] == (
        "nfdump reported a damaged or unreadable input file: Notice: one\nNotice: two"
    )
    assert registered == [] and nf_env.db.get_sources() == []
    assert core.STDERR_BENIGN_PREFIXES == ()  # no message is known to be benign: keep it empty
    nf_env.monkeypatch.setattr(core, "STDERR_BENIGN_PREFIXES", ("Notice: ",))
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "success" and resp["warnings"] == []
    assert resp["row_count"] == 5
    nf_env.fake.stderr = "   \n\n"  # whitespace-only stderr is not a message
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir), n=6)
    assert resp["status"] == "success"


def test_dash_i_stderr_at_rc0_excludes_the_file_from_inventory(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(62, 65), strays=False)
    bad = str(day_dir / "nfcapd.200103040000")
    real_call = nf_env.fake.__call__

    def dash_i_warns(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        proc = real_call(cmd, **kwargs)
        if "-I" in cmd and cmd[-1] == bad:
            return subprocess.CompletedProcess(
                cmd, 0, stdout=proc.stdout, stderr="Unknown block type 99. Skip block\n"
            )
        return proc

    nf_env.monkeypatch.setattr(subprocess, "run", dash_i_warns)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "success", resp
    assert resp["files_scanned"] == 2 and resp["summary"]["flows"] == 2 * 197
    (entry,) = [e for e in resp["files_excluded"] if e["path"] == bad]
    assert entry["reason"] == (
        "nfdump -I failed: nfdump reported a damaged or unreadable input file: "
        "Unknown block type 99. Skip block"
    )


def test_undecodable_nfdump_output_never_raises(nf_env: Env) -> None:
    """subprocess.run is called with errors="replace": nfdump echoes the offending filter bytes
    on stdout at rc 254, and decoding must never raise."""
    day_dir = _single(nf_env)
    nf_env.fake.returncode = 254
    nf_env.fake.stdout = "Line 1: syntax error at '\ufffd'\n"  # what errors="replace" yields
    resp = nf_env.call(
        "run_netflow_query", evidence_path=str(day_dir), filter="src ip 192.0.2.99 and"
    )
    assert resp["status"] == "error" and resp["error_type"] == "invalid_argument"
    assert "syntax error" in resp["error_message"]
    assert nf_env.fake.last.kwargs["errors"] == "replace"


def test_stdout_too_large_is_tool_failed(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.monkeypatch.setattr(core, "MAX_STDOUT_BYTES", 10)
    resp = nf_env.call("run_netflow_top", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "tool_failed"
    assert "output too large" in resp["error_message"]
    assert nf_env.db.get_sources() == []


def test_timeout_expired_is_deferrable_timeout(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.raise_exc = subprocess.TimeoutExpired(cmd="nfdump", timeout=150)
    resp = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "timeout"
    assert "150" in resp["error_message"]
    assert "narrow" in resp["suggestion"] and "2 slots" in resp["suggestion"]
    assert resp["nfdump_argv"][: len(PRLIMIT_PREFIX)] == PRLIMIT_PREFIX
    assert nf_env.db.get_sources() == []


def test_os_error_is_os_error(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.raise_exc = PermissionError(13, "Permission denied")
    resp = nf_env.call("run_netflow_pair_timeline", evidence_path=str(day_dir), src="192.0.2.99",
                       dst="192.0.2.98")  # fmt: skip
    assert resp["status"] == "error" and resp["error_type"] == "os_error"
    assert "Permission denied" in resp["error_message"]


def test_staging_dir_removed_when_subprocess_raises(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(62, 65), strays=False)
    seen: list[Path] = []

    def hook(argv: list[str]) -> None:
        tmp = Path(argv[argv.index("-R") + 1])
        assert tmp.is_dir() and sorted(p.name for p in tmp.iterdir()) == ["000000", "000001",
                                                                          "000002"]  # fmt: skip
        seen.append(tmp)
        raise OSError("exec failed")

    nf_env.fake.hook = hook
    resp = nf_env.call("run_netflow_query", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "os_error"
    assert len(seen) == 1 and not seen[0].exists()


def test_inventory_drops_files_whose_dash_i_fails(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(62, 65), strays=False)
    bad = str(day_dir / "nfcapd.200103040000")
    real_call = nf_env.fake.__call__

    def dash_i_fails(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        proc = real_call(cmd, **kwargs)
        if "-I" in cmd and cmd[-1] == bad:
            return subprocess.CompletedProcess(cmd, 250, stdout="", stderr="Error open file: x\n")
        return proc

    nf_env.monkeypatch.setattr(subprocess, "run", dash_i_fails)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "success", resp
    assert resp["files_scanned"] == 2
    assert resp["file_range"] == ["nfcapd.200103030000", "nfcapd.200103050000"]
    assert [e for e in resp["files_excluded"] if e["path"] == bad][0]["reason"].startswith(
        "nfdump -I failed: nfdump exited 250"
    )
    staged = nf_env.fake.calls[-1]
    tmp_links = [c for c in nf_env.fake.calls if c.read_args[0] == "-R"]
    assert staged.read_args[0] == "-R" and len(tmp_links) == 2
    assert resp["summary"]["files"] == 2 and resp["summary"]["flows"] == 2 * 197


def test_inventory_all_dash_i_failed_is_file_not_found(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.returncode = 250
    nf_env.fake.stderr = "Error open file: x\n"
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "file_not_found"
    assert resp["files_excluded"][0]["reason"].startswith("nfdump -I failed")
    assert nf_env.db.get_sources() == []


def test_inventory_pass_timeout_is_timeout(nf_env: Env) -> None:
    day_dir = _single(nf_env)
    nf_env.fake.raise_exc = subprocess.TimeoutExpired(cmd="nfdump", timeout=150)
    resp = nf_env.call("run_netflow_inventory", evidence_path=str(day_dir))
    assert resp["status"] == "error" and resp["error_type"] == "timeout"
    assert resp["nfdump_argv"][len(PRLIMIT_PREFIX) : len(PRLIMIT_PREFIX) + 2] == [
        core.NFDUMP_BINARY, "-I",
    ]  # fmt: skip


def test_run_nfdump_bare_mode_for_dash_i(nf_env: Env) -> None:
    res = tools._run_nfdump(["-I", "-r", "/evidence/nfcapd.200103040000"], [], None, None, 5)
    assert isinstance(res, NfRun)
    assert res.argv == [*PRLIMIT_PREFIX, core.NFDUMP_BINARY, "-I", "-r",
                        "/evidence/nfcapd.200103040000"]  # fmt: skip
    assert "-N" not in res.argv and "--" not in res.argv[len(PRLIMIT_PREFIX) :]
    assert res.stdout.startswith("Ident: edge-router")
    assert res.returncode == 0 and res.warnings == []


# ---------------------------------------------------------------------------
# identical concurrent calls register one source (per-name lock)
# ---------------------------------------------------------------------------


def _concurrent_calls(nf_env: Env, tool: str, n: int, **kwargs: Any) -> list[dict[str, Any]]:
    """Run ``n`` identical calls on threads while the fake nfdump blocks until all have started."""
    started = threading.Semaphore(0)
    release = threading.Event()

    def hook(_argv: list[str]) -> None:
        started.release()
        assert release.wait(10)

    nf_env.fake.hook = hook
    results: list[dict[str, Any]] = []
    lock = threading.Lock()

    def worker() -> None:
        resp = nf_env.call(tool, **kwargs)
        with lock:
            results.append(resp)

    before = len(nf_env.fake.calls)
    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    try:
        assert started.acquire(timeout=5)  # exactly one call reaches nfdump ...
        time.sleep(0.4)
        assert len(nf_env.fake.calls) == before + 1  # ... the others wait on the name lock
    finally:
        release.set()  # never leave a worker blocked past the fixture's teardown
        for t in threads:
            t.join(timeout=15)
    assert len(results) == n
    return results


def test_identical_concurrent_calls_register_one_source(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    registered = _register_spy(nf_env)
    results = _concurrent_calls(
        nf_env,
        "run_netflow_query",
        3,
        evidence_path=str(day_dir),
        filter="src ip 10.0.3.44",
        limit=5,
    )
    statuses = sorted(r["status"] for r in results)
    assert statuses == ["skipped", "skipped", "success"], statuses
    names = {r["source_name"] for r in results}
    assert len(names) == 1
    (name,) = names
    assert registered == [name]
    assert [s.source_name for s in nf_env.db.get_sources()] == [name]
    assert len(nf_env.fake.calls) == 1  # the duplicates never spent an nfdump slot
    rows, total = nf_env.db.get_windows_page(name, limit=1000)
    assert total == 6  # header + 5 rows, once
    for r in results:
        if r["status"] == "skipped":
            assert r["line_count"] == 6 and r["existing_sources"] == [name]
            assert nf_env.audit_entry(r["tool_call_id"])["params"]["source"] == name


def test_identical_concurrent_forced_calls_get_distinct_rerun_names(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    first = nf_env.call("run_netflow_sweep", evidence_path=str(day_dir), ports=[445, 3389])
    base = first["source_name"]
    results = _concurrent_calls(
        nf_env, "run_netflow_sweep", 2, evidence_path=str(day_dir), ports=[445, 3389], force=True
    )
    assert sorted(r["status"] for r in results) == ["success", "success"]
    assert sorted(r["source_name"] for r in results) == [f"{base}-r1", f"{base}-r2"]
    names = [s.source_name for s in nf_env.db.get_sources()]
    assert names == [base, f"{base}-r1", f"{base}-r2"]


def test_different_parameter_sets_still_run_in_parallel(nf_env: Env) -> None:
    day_dir = nf_env.tree(days=range(63, 64), strays=False)
    entered = threading.Semaphore(0)
    release = threading.Event()

    def hook(_argv: list[str]) -> None:
        entered.release()
        assert release.wait(10)

    nf_env.fake.hook = hook
    threads = [
        threading.Thread(
            target=lambda n=n: nf_env.call("run_netflow_top", evidence_path=str(day_dir), n=n)
        )
        for n in (5, 6)
    ]
    for t in threads:
        t.start()
    assert entered.acquire(timeout=5) and entered.acquire(timeout=5)  # both inside nfdump at once
    release.set()
    for t in threads:
        t.join(timeout=10)
    assert len(nf_env.db.get_sources()) == 2
