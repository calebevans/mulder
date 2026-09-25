"""Hermetic test harness for the NetFlow (nfdump) tools.

A real ``CaseDB`` on ``tmp_path`` plus an ``AuditLog``, wired into a ``ServerContext`` /
``ServerConfig`` the way ``mulder.server.app`` does it; ``get_ctx``/``get_cfg``/``has_ctx`` are
patched on the netflow tools module (the plaso-test pattern) and the same objects are installed
as ``app._ctx``/``app._cfg`` so ``helpers.sources_already_indexed``, ``error_response`` and
``extract_and_index`` (which import ``get_ctx`` from ``app``) see the same case.
``subprocess.run`` is replaced by :class:`FakeNfdump`, which records every
``cmd``/``env``/``timeout`` and answers with captured nfdump stdout from
``tests/fixtures/netflow/nfdump_stdout``; ``require_binary`` is faked so the nfdump and prlimit
binaries "exist" although the base image has neither.

The ``nf_env`` fixture in ``tests/conftest.py`` builds an :class:`Env` through :func:`make_env`;
tools are always called through ``app._tool_dispatch_sync`` (the JobStore path).
"""

from __future__ import annotations

import json
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

import mulder.server.app as app  # noqa: F401  (imports mulder.server.tools -> registers tools)
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.index.correlator import Correlator
from mulder.server.app import ServerConfig, ServerContext, _tool_dispatch_sync
from mulder.server.tools.netflow import core, tools

FIXTURES = Path(__file__).resolve().parent / "fixtures"
STDOUT_FIXTURES = FIXTURES / "netflow" / "nfdump_stdout"
FIXTURE_TREE = FIXTURES / "netflow" / "edge-router"  # synthetic nfcapd files + two strays

MAGIC = b"\x0c\xa5\x02\x00"
PRLIMIT_PREFIX = [
    core.PRLIMIT_BINARY,
    f"--as={core.NFDUMP_RLIMIT_AS}",
    f"--core={core.NFDUMP_RLIMIT_CORE}",
    "--",
]
NETFLOW_TOOLS = (
    "run_netflow_inventory",
    "run_netflow_top",
    "run_netflow_host_profile",
    "run_netflow_sweep",
    "run_netflow_pair_timeline",
    "run_netflow_query",
)


def fixture_text(name: str) -> str:
    """Return one captured nfdump stdout fixture."""
    return (STDOUT_FIXTURES / name).read_text()


def _first_stat_table(text: str) -> str:
    """The first ``ts,te,...`` table of a multi-table STAT capture."""
    head, sep, _rest = text.partition("\nts,te,")
    return head + "\n" if sep else text


# Composite STAT captures in the exact table order the tools request.
STAT_IP = fixture_text("stat_ip.txt")
STAT_PORT_P = fixture_text("stat_port_p.txt")
STAT_SRCIP_BYTES = _first_stat_table(fixture_text("stat_multi.txt"))
INVENTORY_STAT = (
    STAT_IP + STAT_PORT_P + STAT_SRCIP_BYTES + STAT_IP
)  # ip, dstport:p, srcip/b, dstip/b
# 4-table host-profile captures for 10.0.2.37 over the synthetic day-1 file: the exact
# <host>/flows table first, then dstport:p/flows, <peer>/flows, <peer>/bytes.
PROFILE_OUT = fixture_text("profile_out.txt")
PROFILE_IN = fixture_text("profile_in.txt")


def yday(day_of_year: int) -> str:
    """``YYYYMMDD`` of one day of the year 2001 (1 = 2001-01-01; not a leap year)."""
    return (date(2001, 1, 1) + timedelta(days=day_of_year - 1)).strftime("%Y%m%d")


def nfcapd(directory: Path, name: str | None = None, day: str | None = None) -> Path:
    """Write a magic-valid nfcapd file (4 magic bytes + padding) and return its path.

    ``name`` is the full file name; when omitted ``day`` (``YYYYMMDD``) names it
    ``nfcapd.<day>0000``.
    """
    if name is None:
        if day is None:
            raise ValueError("nfcapd() needs a name or a day")
        name = f"nfcapd.{day}0000"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(MAGIC + b"\x00" * 60)
    return path


def make_tree(root: Path, days: range = range(48, 76), strays: bool = True) -> Path:
    """``<root>/netflow/edge-router/2001/02`` with one magic file per day of the year in
    ``days`` (+ two strays)."""
    exporter = root / "netflow" / "edge-router"
    day_dir = exporter / "2001" / "02"
    day_dir.mkdir(parents=True, exist_ok=True)
    for d in days:
        nfcapd(day_dir, day=yday(d))
    if strays:
        (exporter / "zero-length").write_bytes(b"")
        (day_dir / "nfcapd.200103035555").write_text("not a netflow file\n")
    return day_dir


def default_stdout(cmd: list[str]) -> str:
    """Pick the captured stdout that matches the argv shape nfdump was given."""
    if "-I" in cmd:
        return fixture_text("dash_I.txt")
    stats = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-s"]
    if "192.0.2.99" in cmd[-1] or "192.0.2.98" in cmd[-1]:  # addresses no fixture flow carries
        # nfdump 1.7.10 prints ONLY the sentinel (no header) for -A and -s record/* modes, the
        # sentinel then a header for other -s modes, and a header then the sentinel for RAW -c.
        if "-A" in cmd or (stats and stats[0].startswith("record/")):
            return fixture_text("no_match_agg.txt")
        if stats:
            return fixture_text("no_match_stat.txt")
        return fixture_text("no_match.txt")
    if "-A" in cmd:
        keys = cmd[cmd.index("-A") + 1]
        if "flags" in keys:
            return fixture_text("sweep.txt")
        if "/" in keys:
            return fixture_text("seg24.txt")
        return fixture_text("agg_plain.txt")
    if stats:
        if stats[0].startswith("record/"):
            return fixture_text("raw.txt")
        if stats[0] == "ip/flows" and len(stats) == 4:
            return INVENTORY_STAT
        if stats[0] in ("srcip/flows", "dstip/flows") and len(stats) == 4:
            return PROFILE_OUT if stats[0] == "srcip/flows" else PROFILE_IN
        key = stats[0].split("/", 1)[0]  # "dstip:p/flows" -> "dstip:p"
        return STAT_IP if core.stat_ip_valued(key) else STAT_PORT_P
    if "-c" in cmd:
        if "192.0.2.150" in cmd[-1]:  # the SYN-only retry pair
            return fixture_text("pair_retries.txt")
        if "203.0.113.77" in cmd[-1]:  # the long session's pair
            if "src port 40519" in cmd[-1]:
                return fixture_text("pair_session_both.txt")
            return fixture_text("pair_session.txt")
        return fixture_text("raw.txt")
    return fixture_text("no_match.txt")


@dataclass
class FakeCall:
    """One recorded ``subprocess.run`` invocation."""

    cmd: list[str]
    kwargs: dict[str, Any]

    @property
    def env(self) -> dict[str, str]:
        """The ``env`` mapping passed to ``subprocess.run``."""
        env = self.kwargs.get("env")
        assert isinstance(env, dict)
        return env

    @property
    def timeout(self) -> float:
        """The ``timeout`` passed to ``subprocess.run``."""
        return float(self.kwargs["timeout"])

    @property
    def nfdump_argv(self) -> list[str]:
        """argv after the prlimit prefix (``nfdump ...``)."""
        assert self.cmd[: len(PRLIMIT_PREFIX)] == PRLIMIT_PREFIX, self.cmd
        return self.cmd[len(PRLIMIT_PREFIX) :]

    @property
    def read_args(self) -> list[str]:
        """``["-r", file]`` or ``["-R", tmpdir]``."""
        argv = self.nfdump_argv
        for flag in ("-r", "-R"):
            if flag in argv:
                i = argv.index(flag)
                return argv[i : i + 2]
        raise AssertionError(f"no -r/-R in {argv}")


class FakeNfdump:
    """``subprocess.run`` stand-in: records calls, answers with fixture stdout.

    ``stdout`` forces one answer for every call; ``responder`` maps argv to an
    answer; otherwise :func:`default_stdout` picks by argv shape.  ``hook`` runs
    inside the call (blocking/threading tests); ``raise_exc`` is raised instead
    of returning.
    """

    def __init__(self) -> None:
        self.calls: list[FakeCall] = []
        self.stdout: str | None = None
        self.stderr: str = ""
        self.returncode: int = 0
        self.raise_exc: BaseException | None = None
        self.hook: Callable[[list[str]], None] | None = None
        self.responder: Callable[[list[str]], str | None] | None = None

    def __call__(self, cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        argv = list(cmd)
        self.calls.append(FakeCall(cmd=argv, kwargs=dict(kwargs)))
        if self.hook is not None:
            self.hook(argv)
        if self.raise_exc is not None:
            raise self.raise_exc
        out = self.stdout
        if out is None and self.responder is not None:
            out = self.responder(argv)
        if out is None:
            out = default_stdout(argv)
        return subprocess.CompletedProcess(argv, self.returncode, stdout=out, stderr=self.stderr)

    @property
    def last(self) -> FakeCall:
        """The most recent call."""
        assert self.calls, "nfdump was never run"
        return self.calls[-1]


def fake_which(name: str) -> str | None:
    """``require_binary`` stand-in: only the configured nfdump and prlimit exist."""
    if name in (core.NFDUMP_BINARY, core.PRLIMIT_BINARY):
        return name
    return None


@dataclass
class Env:
    """Everything a tool test needs: the case, the fake nfdump and a tree helper."""

    tmp_path: Path
    db_dir: Path
    evidence_root: Path
    db: CaseDB
    audit: AuditLog
    audit_path: Path
    ctx: ServerContext
    cfg: ServerConfig
    fake: FakeNfdump
    monkeypatch: pytest.MonkeyPatch
    _trees: dict[str, Path] = field(default_factory=dict)

    def call(self, tool: str, **kwargs: Any) -> dict[str, Any]:
        """Call a registered tool the way the JobStore does (sync dispatch table)."""
        result: dict[str, Any] = _tool_dispatch_sync[tool](**kwargs)
        return result

    def tree(self, days: range = range(48, 76), strays: bool = True) -> Path:
        """Create (once) the default day tree under the evidence root; return the day dir."""
        key = f"{days.start}-{days.stop}-{strays}"
        if key not in self._trees:
            self._trees[key] = make_tree(self.evidence_root, days, strays)
        return self._trees[key]

    def audit_entries(self, tool: str | None = None) -> list[dict[str, Any]]:
        """Tool-call entries from the JSONL audit log (optionally one tool)."""
        out: list[dict[str, Any]] = []
        for line in self.audit_path.read_text().splitlines():
            entry = json.loads(line)
            if entry.get("type") != "tool_call":
                continue
            if tool is None or entry.get("tool_name") == tool:
                out.append(entry)
        return out

    def audit_entry(self, tool_call_id: str) -> dict[str, Any]:
        """The audit entry for one tool_call_id."""
        for entry in self.audit_entries():
            if entry.get("tool_call_id") == tool_call_id:
                return entry
        raise AssertionError(f"no audit entry for {tool_call_id}")


def make_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    """Real CaseDB + AuditLog + ServerContext; patched ctx accessors, binaries and subprocess.

    The caller owns ``env.db`` and closes it when the test ends (see ``nf_env`` in
    ``tests/conftest.py``).
    """
    db_dir = tmp_path / "db"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    db = CaseDB.create(case_id="nf-test", evidence_root=str(evidence_root), db_dir=db_dir)
    audit_path = db_dir / "nf-test.audit.jsonl"
    audit = AuditLog(audit_path)
    ctx = ServerContext(case_id="nf-test", db=db, correlator=Correlator(db=db), audit=audit)
    cfg = ServerConfig(db_dir=db_dir)
    fake = FakeNfdump()

    monkeypatch.setattr(tools, "get_ctx", lambda: ctx)
    monkeypatch.setattr(tools, "get_cfg", lambda: cfg)
    monkeypatch.setattr(tools, "has_ctx", lambda: True)
    # helpers / extract_helpers read app's globals through app.get_ctx / app.has_ctx
    monkeypatch.setattr(app, "_ctx", ctx)
    monkeypatch.setattr(app, "_cfg", cfg)
    monkeypatch.setattr(tools, "require_binary", fake_which)
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(tools, "_NFDUMP_SLOTS", threading.BoundedSemaphore(core.NFDUMP_SLOT_COUNT))
    env = Env(
        tmp_path=tmp_path,
        db_dir=db_dir,
        evidence_root=evidence_root,
        db=db,
        audit=audit,
        audit_path=audit_path,
        ctx=ctx,
        cfg=cfg,
        fake=fake,
        monkeypatch=monkeypatch,
    )
    return env
