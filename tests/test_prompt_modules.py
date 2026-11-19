"""A session's system prompt is a core plus the modules for the evidence it works on.

Guidance for one kind of evidence is a marked block in its role's prompt
file. A session is sent the core and the blocks of the modules its system
(extraction) or the case (the later phases) needs, chosen from the catalog's
evidence types and the sources indexed so far. Text is only ever left out,
never changed or moved, and when what a system holds cannot be determined
the session gets every module.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import mulder.server.app as server_app
from mulder.db import CaseDB
from mulder.extractors import classifier
from mulder.orchestrator import prompts
from mulder.orchestrator.evidence import EvidenceContext
from mulder.orchestrator.phases import ALTERNATIVE_NARRATIVE, CROSS_SYSTEM, EXTRACTION, PhaseConfig
from mulder.orchestrator.prompts import MODULES, assemble, modules_for
from mulder.orchestrator.runner import Orchestrator
from mulder.orchestrator.types import ExecutionResults, PhaseResult, Plan
from mulder.server import source_names
from mulder.server.helpers import TOOL_SOURCE_PREFIXES
from mulder.server.tools import case as case_tools
from mulder.server.tools import review

CASE = "case-1"
ALL = frozenset(name for names in MODULES.values() for name in names)
_DIR = Path(prompts.__file__).parent
_MARKER = re.compile(r"<!-- (?:module: [a-z ]+|/module) -->")

#: Every role prompt, by file stem.
PROMPTS = {
    name.removesuffix("_PROMPT").lower(): getattr(prompts, name)
    for name in dir(prompts)
    if name.endswith("_PROMPT")
}
#: The ones that have modules.
MODULAR = (
    "extract_planner",
    "extract_analyst",
    "cross_system_planner",
    "cross_system_analyst",
    "narrative_analyst",
)

#: A Windows disk image once extraction has run on it.
DISK_SOURCES = ["tsk.filelist", "ez.mft", "evtx.security", "registry.system", "hayabusa.alerts"]


def _blocks(stem: str) -> list[tuple[frozenset[str] | None, list[str]]]:
    """A prompt file as (module names or None for the core, its lines), in order."""
    blocks: list[tuple[frozenset[str] | None, list[str]]] = [(None, [])]
    for line in (_DIR / f"{stem}.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("<!-- module: "):
            blocks.append((frozenset(line[13:-4].split()), []))
        elif line == "<!-- /module -->":
            blocks.append((None, []))
        else:
            blocks[-1][1].append(line)
    return blocks


# ---------------------------------------------------------------------------
# The text: moved, not rewritten
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stem", sorted(PROMPTS))
def test_a_prompt_is_its_file_with_the_marker_lines_taken_out(stem: str) -> None:
    """Nothing else is done to the text, so with every module a prompt is what
    its file says, in the order the file says it."""
    raw = (_DIR / f"{stem}.md").read_text(encoding="utf-8")
    kept = [line for line in raw.splitlines() if not _MARKER.fullmatch(line)]

    assert PROMPTS[stem] == "\n".join(kept).strip()
    assert "<!--" not in PROMPTS[stem] and "/module" not in PROMPTS[stem]


@pytest.mark.parametrize("stem", sorted(PROMPTS))
def test_a_case_holding_every_kind_of_evidence_gets_the_whole_prompt(stem: str) -> None:
    types = [t for t in MODULES if not t.endswith(".")]
    sources = [f"{prefix}x" for prefix in MODULES if prefix.endswith(".")]

    assert modules_for(types, sources) == ALL
    assert assemble(PROMPTS[stem], ALL) == PROMPTS[stem]
    assert assemble(PROMPTS[stem], None) == PROMPTS[stem]


def test_only_the_prompts_with_evidence_sections_have_modules() -> None:
    with_blocks = {stem for stem in PROMPTS if any(names for names, _ in _blocks(stem))}

    assert with_blocks == set(MODULAR)
    # The catalog runs before the kinds are known; executors and the report
    # have no section about one kind of evidence.
    for stem in set(PROMPTS) - with_blocks:
        assert assemble(PROMPTS[stem], frozenset()) == PROMPTS[stem]


@pytest.mark.parametrize("stem", MODULAR)
def test_a_windows_disk_only_system_gets_no_line_of_another_module(stem: str) -> None:
    modules = modules_for(["disk_image"], DISK_SOURCES)
    assert modules == frozenset({"disk"})
    sent = assemble(PROMPTS[stem], modules).splitlines()

    blocks = _blocks(stem)
    kept = [line for names, lines in blocks if names is None or "disk" in names for line in lines]
    dropped = [
        line for names, lines in blocks if names and "disk" not in names for line in lines if line
    ]
    # Exactly the core and the disk blocks, in the file's order.
    assert sent == "\n".join(kept).strip().splitlines()
    assert dropped, "this prompt has blocks a disk-only system does not get"
    for line in dropped:
        if line not in kept:  # a line two blocks share word for word stays with the kept one
            assert line not in sent, line


def test_the_headings_of_other_kinds_are_absent_for_a_disk_only_system() -> None:
    modules = modules_for(["disk_image"], DISK_SOURCES)
    planner = assemble(prompts.EXTRACT_PLANNER_PROMPT, modules)
    analyst = assemble(prompts.EXTRACT_ANALYST_PROMPT, modules)

    for heading in (
        "When the evidence includes a MEMORY DUMP",
        "When the evidence includes NETWORK CAPTURES",
        "When the evidence includes NETFLOW",
        "CLOUD AUDIT LOGS, REPOSITORY CHECKOUTS",
        "LOG DIRECTORIES, LOOSE LOG FILES",
        "TRIAGE COLLECTIONS (type",
        "When the evidence includes MOBILE DATA",
    ):
        assert heading in prompts.EXTRACT_PLANNER_PROMPT
        assert heading not in planner
    for heading in (
        "NETFLOW EVIDENCE:",
        "CLOUD AND CI EVIDENCE:",
        "MICROSOFT 365 AND ENTRA ID",
        "TRIAGE COLLECTIONS:",
        "TARGETED FOLLOW-UP TOOLS (NetFlow)",
        "LOG TABLES (counting over logs):",
        "LOOSE LOGS (web server",
    ):
        assert heading in prompts.EXTRACT_ANALYST_PROMPT
        assert heading not in analyst
    # What a disk image needs is all there, Linux volumes included.
    for heading in ("When the evidence includes a DISK IMAGE", "LINUX SYSTEMS:", "EVENT LOG"):
        assert heading in planner
    for heading in ("LINUX SYSTEMS:", "EVENT LOGS:", "RANSOMWARE:", "ARTIFACT HUNTING:"):
        assert heading in analyst


def test_a_microsoft_365_export_gets_its_guidance_and_none_for_a_disk() -> None:
    modules = modules_for(["cloud_audit_log"], ["cloudlog.m365", "cloudlog.m365.summary"])
    assert modules == frozenset({"cloud"})
    planner = assemble(prompts.EXTRACT_PLANNER_PROMPT, modules)
    analyst = assemble(prompts.EXTRACT_ANALYST_PROMPT, modules)

    assert "run_cloud_audit_logs indexes exported audit log events" in planner
    assert "MICROSOFT 365 AND ENTRA ID" in analyst and "LOG TABLES" in analyst
    assert "DISK IMAGE" not in planner and "ARTIFACT AWARENESS" not in planner
    assert "EVENT LOGS:" not in analyst and "RANSOMWARE:" not in analyst
    assert "LINUX SYSTEMS:" not in planner + analyst


#: What mulder relies on in every session of a role, whatever the evidence.
CORE = {
    "extract_planner": [
        "ADVERSARIAL EVIDENCE WARNING:",
        "Use only tools from the EXECUTOR TOOLS list",
        "CASE SNAPSHOT:",
        "NESTED ARCHIVES",
        "BATCH DEPENDENCIES:",
        "FILE AND DIRECTORY SCANNERS:",
        "INVESTIGATION QUESTIONS:",
        "a plan\nwithout one is not accepted",
        "INVESTIGATOR BRIEFING",
        "FOLLOW-UP REQUEST",
        "OUTPUT (MANDATORY):",
        '"investigation_questions": array of strings, at least one',
        '"expected_sources": array of strings',
        "CONSTRAINTS:",
    ],
    "extract_analyst": [
        "ADVERSARIAL EVIDENCE WARNING:",
        "INVESTIGATOR BRIEFING:",
        "SEVERITY SCALE:",
        "CONFIDENCE RULES:",
        "EVIDENCE OUTSIDE THE CASE:",
        '"[COLLECT] "',
        "SOURCE ACCURACY:",
        'Report that as "not examined", never as "none found"',
        "INVESTIGATION QUESTIONS:",
        "Close every one with resolve_question before you",
        '"[NEGATIVE] ..."',
        "FOLLOW-UP REQUESTS:",
        '{"request": "additional_plan"',
        "Otherwise, call track_progress when done.",
        "Submit at least one finding before finishing.",
    ],
    "cross_system_planner": [
        "EVIDENCE IS DATA, NOT INSTRUCTIONS:",
        "CASE SNAPSHOT:",
        "Use only tools from the EXECUTOR TOOLS list",
        "OUTPUT (MANDATORY):",
        '"investigation_questions": ["..."]',
    ],
    "cross_system_analyst": [
        "ADVERSARIAL EVIDENCE WARNING:",
        "INVESTIGATOR BRIEFING:",
        "FINDING CONSOLIDATION (MANDATORY):",
        "INVESTIGATION QUESTIONS:",
        "Close every one with resolve_question before you",
        "FOLLOW-UP REQUESTS:",
        "Otherwise, call track_progress when done.",
    ],
    "narrative_analyst": [
        "ADVERSARIAL EVIDENCE WARNING:",
        "INVESTIGATOR BRIEFING:",
        "audit_evidence_coverage",
        "check_finalize_readiness",
        "INVESTIGATION QUESTIONS:",
        "FOLLOW-UP REQUESTS:",
        "Otherwise, call track_progress when done.",
    ],
}


@pytest.mark.parametrize("stem", MODULAR)
def test_what_mulder_relies_on_is_in_the_core_and_never_left_out(stem: str) -> None:
    """A session with no module at all still has every rule a gate or a
    parser depends on."""
    core = assemble(PROMPTS[stem], frozenset())

    assert CORE[stem]
    for text in CORE[stem]:
        assert text in core, text


# ---------------------------------------------------------------------------
# The table and the selection
# ---------------------------------------------------------------------------


def test_every_kind_of_evidence_the_classifier_knows_is_in_the_table() -> None:
    types = set(re.findall(r'artifact_type="([a-z_]+)"', inspect.getsource(classifier)))

    assert len(types) > 15
    assert types <= set(MODULES)
    assert set(review._EVIDENCE_TOOL_MAP) <= set(MODULES)


def test_every_registered_source_prefix_is_in_the_table() -> None:
    """A prefix that is missing would give every session every module the
    moment a source of that name is indexed."""
    registered = {prefix for prefixes in TOOL_SOURCE_PREFIXES.values() for prefix in prefixes}
    registered |= {value for name, value in vars(source_names).items() if name.startswith("SRC_")}

    assert len(registered) > 40
    for source in sorted(registered):
        assert source.split(".", 1)[0] + "." in MODULES, source


def test_the_blocks_name_only_modules_the_table_can_select() -> None:
    named = {name for stem in MODULAR for names, _ in _blocks(stem) if names for name in names}

    assert named == ALL


@pytest.mark.parametrize(
    ("types", "sources", "expected"),
    [
        (["disk_image"], [], {"disk"}),
        (["Disk Image", "memory-dump"], [], {"disk", "memory"}),
        (["triage_collection"], [], {"triage", "disk"}),
        (["disk_image"], ["netflow.inventory.abc"], {"disk", "netflow"}),
        (["disk_image"], ["pst.emails", "pcap.dns"], {"disk", "cloud", "pcap"}),
        (["cloud_audit_log"], ["logtable.cloudlog.m365", "enrichment.iocs"], {"cloud"}),
        (["log_directory", "esxi_bundle"], ["logs.esxi"], {"logs"}),
        (["phone_dump"], [], {"mobile", "disk"}),
        (["compressed_archive", "memory_dump"], ["binary.triage"], {"memory"}),
    ],
)
def test_types_and_sources_select_modules(
    types: list[str], sources: list[str], expected: set[str]
) -> None:
    assert modules_for(types, sources) == frozenset(expected)


@pytest.mark.parametrize(
    ("types", "sources"),
    [
        (None, []),  # no catalog entry
        ([], []),  # an entry that lists no evidence
        (["disk_image", "quantum_storage"], []),  # a type the table does not know
        (["disk_image", "other"], []),
        (["disk_image"], ["tsk.filelist", "newtool.output"]),  # a prefix nothing maps
        (["disk_image"], ["nodot"]),
        (["disk_image"], None),  # the database could not be read
        # Loose files only: nothing says what guidance they need.
        (["sqlite_database", "compressed_archive"], ["binary.triage"]),
    ],
)
def test_what_cannot_be_determined_selects_every_module(
    types: list[str] | None, sources: list[str] | None
) -> None:
    assert modules_for(types, sources) is None
    for stem in MODULAR:
        assert assemble(PROMPTS[stem], modules_for(types, sources)) == PROMPTS[stem]


def test_a_prompt_that_is_not_one_of_the_constants_is_returned_as_it_is() -> None:
    assert assemble("You fix malformed JSON.", {"disk"}) == "You fix malformed JSON."


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("a\n<!-- module: disk -->\nb\n", "not closed"),
        ("a\n<!-- /module -->\nb\n", "not balanced"),
        ("a\n<!-- module: disk -->\n<!-- module: memory -->\nb\n<!-- /module -->\n", "balanced"),
        ("a\n<!-- module: floppy -->\nb\n<!-- /module -->\n", "unknown module"),
    ],
)
def test_a_prompt_file_with_broken_markers_does_not_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str, error: str
) -> None:
    (tmp_path / "bad.md").write_text(text, encoding="utf-8")
    monkeypatch.setattr(prompts, "_DIR", tmp_path)
    monkeypatch.setattr(prompts, "_BLOCKS", {})

    with pytest.raises(ValueError, match=error):
        prompts._load("bad.md")


# ---------------------------------------------------------------------------
# What a system holds
# ---------------------------------------------------------------------------


def _catalog(evidence: EvidenceContext, **systems: Any) -> None:
    evidence._catalog_systems = {
        name.lower(): {"name": name, "type": "Windows", "evidence": types}
        for name, types in systems.items()
    }


def test_the_types_are_the_catalogs_plus_what_the_evidence_context_listed(
    tmp_path: Path,
) -> None:
    """The catalog is a model's output: a type it left out still counts when
    the planner was shown evidence of it."""
    root = tmp_path / "evidence"
    (root / "host-a").mkdir(parents=True)
    (root / "host-a" / "memory.vmem").write_bytes(b"\0" * 64)
    evidence = EvidenceContext(str(root), tmp_path / "extracted")
    _catalog(evidence, **{"host-a": ["disk_image"], "host-b": ["network_capture"]})

    assert evidence.evidence_types("host-a") == {"disk_image"}
    assert "memory.vmem" in evidence.build_evidence_context("host-a")
    assert evidence.evidence_types("host-a") == {"disk_image", "memory_dump"}
    assert evidence.evidence_types("HOST-B") == {"network_capture"}
    # A group of systems and the whole case hold what their members hold.
    assert evidence.evidence_types("host-a, host-b") == {
        "disk_image",
        "memory_dump",
        "network_capture",
    }
    assert evidence.evidence_types() == evidence.evidence_types("host-a, host-b")


@pytest.mark.parametrize("entry", [None, {}, {"evidence": []}, {"evidence": "disk_image"}])
def test_a_system_the_catalog_cannot_describe_has_no_known_types(
    tmp_path: Path, entry: dict[str, Any] | None
) -> None:
    evidence = EvidenceContext(str(tmp_path), tmp_path / "extracted")
    _catalog(evidence, **{"host-a": ["disk_image"]})
    if entry is not None:
        evidence._catalog_systems["host-b"] = {"name": "host-b", **entry}

    assert evidence.evidence_types("host-b") is None
    assert evidence.evidence_types("host-a, host-b") is None
    if entry is not None:  # one system of the case that is not known is enough
        assert evidence.evidence_types() is None


def test_a_system_with_an_archive_nothing_has_unpacked_has_no_known_types(
    tmp_path: Path,
) -> None:
    """What is inside can be any kind of evidence, whatever the catalog says."""
    root, extracted = tmp_path / "evidence", tmp_path / "extracted"
    (root / "host-a").mkdir(parents=True)
    archive = root / "host-a" / "host-a-memory.7z"
    archive.write_bytes(b"7z")
    evidence = EvidenceContext(str(root), extracted)
    _catalog(evidence, **{"host-a": ["compressed_archive", "disk_image"]})

    assert "NESTED ARCHIVES" in evidence.build_evidence_context("host-a")
    assert evidence.evidence_types("host-a") is None
    assert evidence.evidence_types() is None

    # Once extract_archive has unpacked it, what it held is listed by type.
    slot = extracted / case_tools._archive_slot(archive.resolve())
    slot.mkdir(parents=True)
    (slot / "memory.vmem").write_bytes(b"\0" * 64)
    case_tools._mark_extraction_complete(slot, archive.resolve(), 1)
    evidence.build_evidence_context("host-a")

    assert evidence.evidence_types("host-a") == {"compressed_archive", "disk_image", "memory_dump"}
    assert modules_for(evidence.evidence_types("host-a"), []) == frozenset({"disk", "memory"})


def test_before_the_catalog_nothing_is_known(tmp_path: Path) -> None:
    evidence = EvidenceContext(str(tmp_path), tmp_path / "extracted")

    assert evidence.evidence_types() is None
    assert evidence.evidence_types("host-a") is None


def test_a_source_counts_for_the_system_its_path_names_or_for_every_system(
    tmp_path: Path,
) -> None:
    evidence = EvidenceContext("/evidence", tmp_path / "extracted")
    _catalog(evidence, **{"host-a": ["disk_image"], "host-b": ["disk_image"]})

    assert evidence.owns("host-a", "/evidence/host-a/disk.E01")
    assert not evidence.owns("host-b", "/evidence/host-a/disk.E01")
    assert evidence.owns("host-a, host-b", "/evidence/HOST-B/disk.E01")
    assert evidence.owns("host-b", str(tmp_path / "extracted" / "host-b-1a2b" / "mem.raw"))
    # Nobody's name is in the path: it cannot be shown to be another system's.
    assert evidence.owns("host-a", "/evidence/flows/nfcapd.2026")
    assert evidence.owns("host-b", "/evidence/flows/nfcapd.2026")
    # A name in the path to the evidence itself claims nothing.
    named_root = EvidenceContext("/cases/host-a/evidence", tmp_path / "extracted")
    _catalog(named_root, **{"host-a": ["disk_image"], "host-b": ["disk_image"]})
    assert not named_root.owns("host-a", "/cases/host-a/evidence/host-b/disk.E01")


# ---------------------------------------------------------------------------
# What a session is sent
# ---------------------------------------------------------------------------

SYSTEM = "host-a"
IMAGE = "/evidence/host-a/disk.E01"
PLAN = Plan("p", [{"tool": "run_mmls", "args": {}, "purpose": "x"}], ["What ran?"], [], "", 1)


@pytest.fixture()
def db_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A case database the orchestrator's ``ServerBridge`` reads for real."""
    CaseDB.create(case_id=CASE, evidence_root="/evidence", db_dir=tmp_path).close()
    monkeypatch.setattr(server_app, "_cfg", None)
    yield tmp_path
    server_app._close_current_ctx()


def _index(db_dir: Path, name: str, path: str = IMAGE) -> None:
    """What a tool that indexed a source leaves in the database."""
    with CaseDB.open(CASE, db_dir) as db:
        db.register_source(name, path, "h", "test", 10)


def _orchestrator(db_dir: Path, **systems: Any) -> Orchestrator:
    with patch("mulder.orchestrator.runner.InvestigationDashboard"):
        orch = Orchestrator("/evidence", case_id=CASE, db_dir=db_dir)
    _catalog(orch._evidence, **(systems or {SYSTEM: ["disk_image"], "edge": ["netflow_capture"]}))
    return orch


class _Sessions:
    """Fake ``SessionExecutor.execute`` that keeps every call."""

    def __init__(self, *messages: str) -> None:
        self.messages = list(messages) or ["done"]
        self.calls: list[dict[str, Any]] = []

    async def execute(self, **kwargs: Any) -> PhaseResult:
        self.calls.append(kwargs)
        return PhaseResult("query", messages=self.messages, turns_used=1, session_id="s")

    def sent(self, phase: PhaseConfig, role: str) -> list[str]:
        """The system prompts sent to *role* sessions, by their first line."""
        first = getattr(phase, f"{role}_system_prompt").split("\n", 1)[0]
        return [c["system_prompt"] for c in self.calls if c["system_prompt"].startswith(first)]


async def _run_roles(orch: Orchestrator, phase: PhaseConfig, system: str = SYSTEM) -> _Sessions:
    """One planner, one executor and the analyst step of *phase*."""
    plan = (
        '{"tasks": [{"tool": "search", "args": {}, "purpose": "p"}],'
        ' "investigation_questions": ["What ran?"]}'
    )
    sessions = _Sessions(plan)
    variables = {
        "case_id": CASE,
        "system_name": system,
        "evidence_path": "/evidence",
        "evidence_context": "",
        "case_briefing": "",
        "consistency_report": "",
    }
    with patch.object(orch._session, "execute", side_effect=sessions.execute):
        assert await orch._roles.run_planner(phase, variables) is not None
        await orch._roles.run_executor(phase, PLAN, task_system=system)
        await orch._roles.run_analyst(
            phase, PLAN, ExecutionResults("p", [], 0, False), variables, task_system=system
        )
    return sessions


@pytest.mark.asyncio()
async def test_each_extraction_role_is_sent_the_modules_for_its_system(db_dir: Path) -> None:
    orch = _orchestrator(db_dir)
    for name in DISK_SOURCES:
        _index(db_dir, name)
    # Another system's NetFlow is indexed too: it is not this system's.
    _index(db_dir, "netflow.inventory.abc", "/evidence/edge")

    sessions = await _run_roles(orch, EXTRACTION)

    assert sessions.sent(EXTRACTION, "planner") == [
        assemble(EXTRACTION.planner_system_prompt, {"disk"})
    ]
    analysts = sessions.sent(EXTRACTION, "analyst")
    assert len(analysts) == 2  # the question session and the consolidation
    for sent in analysts:
        assert sent.startswith(assemble(EXTRACTION.analyst_system_prompt, {"disk"}))
        assert "NETFLOW EVIDENCE:" not in sent and "MICROSOFT 365" not in sent
        assert "EVENT LOGS:" in sent
    # Executor prompts have no modules: an executor gets all of its prompt.
    (executor,) = sessions.sent(EXTRACTION, "executor")
    assert executor.startswith(EXTRACTION.executor_system_prompt)


@pytest.mark.asyncio()
async def test_a_source_indexed_for_the_system_brings_its_module(db_dir: Path) -> None:
    """A capture found inside the image is not in the catalog entry."""
    orch = _orchestrator(db_dir)
    _index(db_dir, "tsk.filelist")
    _index(db_dir, "pcap.dns")

    sessions = await _run_roles(orch, EXTRACTION)

    assert sessions.sent(EXTRACTION, "planner") == [
        assemble(EXTRACTION.planner_system_prompt, {"disk", "pcap"})
    ]


@pytest.mark.asyncio()
@pytest.mark.parametrize("phase", [CROSS_SYSTEM, ALTERNATIVE_NARRATIVE], ids=lambda p: p.name)
async def test_the_later_phases_are_sent_the_modules_for_the_whole_case(
    db_dir: Path, phase: PhaseConfig
) -> None:
    orch = _orchestrator(db_dir)
    _index(db_dir, "tsk.filelist")
    _index(db_dir, "netflow.inventory.abc", "/evidence/edge")

    sessions = await _run_roles(orch, phase, system="")

    whole = {"disk", "netflow"}
    assert sessions.sent(phase, "planner") == [assemble(phase.planner_system_prompt, whole)]
    assert sessions.sent(phase, "analyst") == [assemble(phase.analyst_system_prompt, whole)]
    if phase is CROSS_SYSTEM:
        (analyst,) = sessions.sent(phase, "analyst")
        assert "NETFLOW EVIDENCE:" in analyst and "RANSOMWARE:" in analyst
        (planner,) = sessions.sent(phase, "planner")
        assert "For NetFlow evidence" in planner and "cloudlog.m365" not in planner


@pytest.mark.asyncio()
@pytest.mark.parametrize(
    "case",
    ["no catalog entry", "unknown type", "unknown source prefix", "no catalog", "no database"],
)
async def test_a_session_gets_every_module_when_the_kinds_cannot_be_determined(
    db_dir: Path, case: str
) -> None:
    orch = _orchestrator(db_dir)
    _index(db_dir, "tsk.filelist")
    system = SYSTEM
    if case == "no catalog entry":
        system = "host-z"
    elif case == "unknown type":
        orch._evidence._catalog_systems[SYSTEM]["evidence"] = ["disk_image", "tape_archive"]
    elif case == "unknown source prefix":
        _index(db_dir, "newtool.output")
    elif case == "no catalog":
        orch._evidence._catalog_systems = {}
    else:
        (db_dir / f"{CASE}.db").unlink()

    sessions = await _run_roles(orch, EXTRACTION, system)

    assert sessions.sent(EXTRACTION, "planner") == [EXTRACTION.planner_system_prompt]
    for sent in sessions.sent(EXTRACTION, "analyst"):
        assert sent.startswith(EXTRACTION.analyst_system_prompt)
