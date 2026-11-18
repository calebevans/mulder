"""Triage collections through the tools: a directory read where a disk image is read.

Every test uses a real case database; only the external parsers are stood in for.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mulder import dirroot
from mulder.audit import AuditLog
from mulder.db import CaseDB
from mulder.dirroot import LISTING_EXTRACTOR
from mulder.server import app
from mulder.server.app import _tool_dispatch_sync
from mulder.server.extract_helpers import extract_and_index, mount_disk_image
from mulder.server.helpers import TOOL_SOURCE_PREFIXES, tool_already_indexed
from mulder.server.tools import triage
from mulder.server.tools.extract import evtx, misc, registry, tsk
from tests.triage_trees import BODY, kape, snapshot, uac, velociraptor, windows_volume, write


@pytest.fixture
def case(
    tmp_case_db: CaseDB, tmp_audit_log: AuditLog, monkeypatch: pytest.MonkeyPatch
) -> Iterator[CaseDB]:
    """A real case database behind the server context, so indexing is not mocked."""
    ctx = app.ServerContext(
        case_id="test-case", db=tmp_case_db, correlator=MagicMock(), audit=tmp_audit_log
    )
    monkeypatch.setattr(app, "_ctx", ctx)
    dirroot._build.cache_clear()
    yield tmp_case_db
    dirroot._build.cache_clear()


def _call(tool: str, **kwargs: object) -> dict[str, Any]:
    return dict(_tool_dispatch_sync[tool](**kwargs))


def _text(db: CaseDB, source: str) -> str:
    return "".join(w.raw_text for w in db.get_windows_by_source(source))


def _sources(db: CaseDB) -> dict[str, str]:
    return {s.source_name: s.extractor for s in db.get_sources()}


# --- the listing -----------------------------------------------------------


def test_run_fls_lists_a_collection_and_says_what_the_listing_is(
    case: CaseDB, tmp_path: Path
) -> None:
    root = kape(tmp_path / "k")

    result = _call("run_fls", image_path=str(root))

    assert result["status"] == "success" and result["source"] == "tsk.filelist"
    assert "not a disk image" in result["preview"]
    assert _sources(case) == {"tsk.filelist": LISTING_EXTRACTOR}
    listing = _text(case, "tsk.filelist")
    assert "r/r 0:\t$MFT\n" in listing
    assert "\tWindows/System32/config/SYSTEM\n" in listing
    # Run again, it is skipped like any indexed listing.
    assert _call("run_fls", image_path=str(root))["preview"].startswith('{"status": "skipped"')


def test_a_directory_listing_is_never_read_as_an_images(case: CaseDB, tmp_path: Path) -> None:
    """Its inode column holds row numbers; icat on an image would read other files."""
    root = kape(tmp_path / "k")
    _call("run_fls", image_path=str(root))
    extract_and_index(
        "r/r 4242-128-1:\tWindows/System32/config/SYSTEM", "tsk.filelist", "/e/d.E01", "sleuthkit"
    )

    with patch.object(tsk, "require_binary", return_value=None):
        image_rows = tsk._collect_fls_chunks("/e/d.E01")
    directory_rows = tsk._collect_fls_chunks(str(root))

    assert [chunks for chunks, _ in image_rows] == [
        ["r/r 4242-128-1:\tWindows/System32/config/SYSTEM"]
    ]
    assert "4242" not in directory_rows[0][0][0] and "\t$MFT" in directory_rows[0][0][0]


def test_the_listing_is_indexed_once_when_two_tools_reach_it_together(
    case: CaseDB, tmp_path: Path
) -> None:
    """run_fls and index_triage_collection in one batch both pass their own check first."""
    root = str(kape(tmp_path / "k"))

    first, second = tsk._index_dir_listing(root), tsk._index_dir_listing(root)

    assert first is not None and first["files_listed"] == 9
    assert second is not None and second["status"] == "skipped"
    assert [s.source_name for s in case.get_sources()] == ["tsk.filelist"]


def _row(root: Path, name: str) -> int:
    """The row number the listing gives the file whose path ends in *name*."""
    listing = dirroot.dir_root(str(root))
    assert listing is not None
    return next(
        row
        for row, (original, _) in enumerate(listing.files, listing.first_inode)
        if original.endswith(name)
    )


def test_a_collections_row_number_is_never_read_from_a_disk_image(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Row 9 of a collection is inode 9 of the image beside it: some other file's content."""
    monkeypatch.setattr("mulder.server.tools.tsk._cached_image_info", {})
    root = kape(tmp_path / "k")
    row = _row(root, "app.ini")
    _call("run_fls", image_path=str(root))

    with (
        patch("mulder.server.tools.tsk.subprocess.run") as run,
        patch("mulder.server.tools.tsk.shutil.which", return_value="/usr/bin/icat"),
        patch("mulder.server.tools.tsk._detect_filesystem_type", return_value=None),
    ):
        alone = _call("extract_file_by_inode", inode=row)  # the case's only listing
        extract_and_index("r/r 9:\tsecret.txt", "tsk.filelist", "/e/dc01.dd", "sleuthkit")
        unnamed = _call("extract_file_by_inode", inode=row)
        metadata = _call("get_file_metadata", inode=row)
        named = _call("extract_file_by_inode", inode=row, image_path=str(root))
        no_metadata = _call("get_file_metadata", inode=row, image_path=str(root))
        unknown = [
            _call(tool, inode=row, image_path="/e/other.dd")
            for tool in ("extract_file_by_inode", "get_file_metadata")
        ]
        run.assert_not_called()  # neither icat nor istat has run on the image
        # Asked for by name, the image is read: it has a listing and no partition table.
        _call("extract_file_by_inode", inode=9, image_path="/e/dc01.dd")

    assert run.call_args.args[0] == ["icat", "/e/dc01.dd", "9"]
    assert alone["status"] == named["status"] == "success"
    assert _text(case, f"tsk.extracted.{row}").count("host=10.0.0.5") == 2
    assert unnamed["error_type"] == metadata["error_type"] == "image_path_required"
    assert str(root) in unnamed["error_message"] and "/e/dc01.dd" in unnamed["error_message"]
    assert no_metadata["error_type"] == "not_applicable"
    assert "those of the copy" in no_metadata["error_message"]
    # An image the case has no listing of was an uncaught ValueError.
    assert [r["error_type"] for r in unknown] == ["image_not_found"] * 2


def test_a_database_in_a_collection_is_queried_by_row_number(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("mulder.server.tools.tsk._cached_image_info", {})
    root = kape(tmp_path / "k")
    history = root / "C/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History"
    history.parent.mkdir(parents=True)
    with sqlite3.connect(history) as db:
        db.execute("CREATE TABLE urls (url)")
        db.execute("INSERT INTO urls VALUES ('https://files.example/x.zip')")
    row = _row(root, "Default/History")
    _call("run_fls", image_path=str(root))
    extract_and_index("r/r 9:\tsecret.txt", "tsk.filelist", "/e/dc01.dd", "sleuthkit")

    failed = subprocess.CompletedProcess([], 1, b"", b"")
    with (
        patch("mulder.server.tools.artifacts.shutil.which", return_value="/usr/bin/icat"),
        patch("mulder.server.tools.tsk._detect_filesystem_type", return_value=None),
        patch("mulder.dirroot.subprocess.run", return_value=failed) as run,
    ):
        unnamed = _call("query_sqlite_from_image", inode=row, query="SELECT url FROM urls")
        named = _call(
            "query_sqlite_from_image",
            inode=row,
            query="SELECT url FROM urls",
            image_path=str(root),
        )
        run.assert_not_called()
        # Named, the image is what icat reads, whichever listing was indexed first.
        _call("query_sqlite_from_image", inode=9, query="SELECT 1", image_path="/e/dc01.dd")

    assert run.call_args.args[0] == ["icat", "/e/dc01.dd", "9"]
    assert unnamed["status"] == "error" and "pass image_path" in unnamed["error_message"]
    assert named["result_count"] == 1
    assert "https://files.example/x.zip" in _text(case, f"sqlite.inode_{row}")


# --- reading files ---------------------------------------------------------


def test_files_are_copied_out_and_the_collection_is_left_alone(
    case: CaseDB, tmp_path: Path
) -> None:
    root = kape(tmp_path / "k")
    before = snapshot(root)

    extracted = tsk._tsk_extract_files(str(root), ["config/SYSTEM", "Amcache.hve"])

    assert {rel: p.read_bytes() for rel, p in extracted} == {
        "Windows/System32/config/SYSTEM": b"regf-system",
        "Windows/AppCompat/Programs/Amcache.hve": b"regf-amcache",
    }
    work = extracted[0][1].parent
    assert not work.is_relative_to(root)
    tsk._cleanup_tsk_extract_dir(str(work))  # what every caller does afterwards
    assert not work.exists() and snapshot(root) == before


def test_the_live_hive_comes_before_an_old_installations_or_a_shadow_copys(
    case: CaseDB, tmp_path: Path
) -> None:
    """The shimcache, Amcache and registry value tools read the first match.

    KAPE collects Windows.old; sorted as whole strings it came before Windows.
    """
    root = kape(tmp_path / "k")
    hive = "Windows/System32/config/SYSTEM"
    write(
        root,
        {
            f"C/Windows.old/{hive}": b"regf-old",
            f"D/{hive}": b"regf-second-volume",
            f"VSS1/{hive}": b"regf-shadow",
        },
    )

    extracted = tsk._tsk_extract_files(str(root), ["config/SYSTEM"])

    assert [rel for rel, _ in extracted] == [
        hive,
        f"Windows.old/{hive}",
        f"D/{hive}",
        f"VSS1/{hive}",
    ]
    assert extracted[0][1].read_bytes() == b"regf-system"
    tsk._cleanup_tsk_extract_dir(str(extracted[0][1].parent))


def test_the_registry_parser_gets_system_and_user_hives(case: CaseDB, tmp_path: Path) -> None:
    root = velociraptor(tmp_path / "v")
    seen: dict[str, bytes] = {}

    def parse(hive: Path, source: str, image_path: str, plugins: object = None) -> dict[str, Any]:
        seen[source] = hive.read_bytes()
        assert not hive.is_relative_to(root) and image_path == str(root)
        return {"source_name": source, "status": "parsed"}

    with patch.object(registry, "_parse_single_hive", side_effect=parse):
        result = _call("run_registry_parser", image_path=str(root), hive="SYSTEM")
        users = registry._parse_all_user_hives(str(root))

    assert result["status"] == "success"
    assert seen["registry.system"] == b"regf-system"  # from uploads/auto/C%3A
    assert seen["registry.ntuser.bob"] == b"regf-bob"
    assert [u["source_name"] for u in users] == ["registry.ntuser.bob"]


def test_the_ez_tool_parsers_are_handed_the_collected_file(case: CaseDB, tmp_path: Path) -> None:
    root = kape(tmp_path / "k")
    handed: dict[str, bytes] = {}

    def run_ez(dll: str, args: list[str], *rest: object) -> dict[str, object]:
        handed[dll] = Path(args[1]).read_bytes()
        return {"status": "success"}

    with (
        patch.object(misc, "_run_ez_tool", side_effect=run_ez),
        patch.object(misc, "require_binary", return_value="/usr/bin/icat"),
        patch.object(misc, "_detect_filesystem_type", return_value=None),
        patch.object(tsk, "require_binary", return_value=None),
    ):
        _call("run_amcache_parser", image_path=str(root))
        _call("run_shimcache_parser", image_path=str(root))
        _call("run_mft_parser", image_path=str(root))

    assert handed == {
        "AmcacheParser.dll": b"regf-amcache",
        "AppCompatCacheParser.dll": b"regf-system",
        "MFTECmd.dll": b"FILE0-mft",  # inode 0 of the listing
    }


def test_an_artifact_that_was_not_collected_is_not_found_and_nothing_is_mounted(
    case: CaseDB, tmp_path: Path
) -> None:
    root = windows_volume(tmp_path / "w")  # no Prefetch, no $MFT

    with patch("mulder.server.extract_helpers._mount_image", return_value=False) as mount:
        prefetch = _call("run_prefetch_parser", image_path=str(root))
        with pytest.raises(RuntimeError, match="Not a disk image"), mount_disk_image(str(root)):
            pass
        mount.assert_not_called()
        on_image = _call("run_prefetch_parser", image_path=str(tmp_path / "disk.E01"))

    assert prefetch["status"] == "error" and "No Prefetch files found" in prefetch["error_message"]
    # Said in the result itself: a missing artifact is not a clean system.
    assert "was not collected" in prefetch["suggestion"]
    assert "does not show it was absent" in prefetch["suggestion"]
    assert "suggestion" not in on_image  # an image's error is what it always was


def test_a_registry_value_query_finds_the_hive(case: CaseDB, tmp_path: Path) -> None:
    root = kape(tmp_path / "k")
    opened: list[bytes] = []

    def open_hive(path: str) -> None:
        opened.append(Path(path).read_bytes())
        raise ValueError("the fixture hive is not a real one")

    with patch(
        "mulder.server.tools.extract.registry_query.Registry.Registry", side_effect=open_hive
    ):
        result = _call(
            "query_registry_value",
            case_id="test-case",
            image_path=str(root),
            hive="system",
            key_path="ControlSet001\\Control",
        )

    assert opened == [b"regf-system"]
    assert result["error_type"] == "hive_unreadable"  # found and handed to the parser


def test_application_files_are_indexed_from_a_collection(case: CaseDB, tmp_path: Path) -> None:
    root = kape(tmp_path / "k")

    with patch("mulder.server.tools.extract.app_files.shutil.which", return_value="/usr/bin/icat"):
        result = _call(
            "index_app_files",
            case_id="test-case",
            image_path=str(root),
            directory_pattern="Program Files/App",
        )

    assert result["results"]["files_indexed"] == 1
    assert "host=10.0.0.5" in _text(case, "appfiles.program_files.app.app.ini")


def test_browser_history_is_read_from_a_collection(case: CaseDB, tmp_path: Path) -> None:
    root = kape(tmp_path / "k")
    history = root / "C/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History"
    history.parent.mkdir(parents=True)
    with sqlite3.connect(history) as db:
        db.execute("CREATE TABLE urls (url, title, visit_count, last_visit_time)")
        db.execute("INSERT INTO urls VALUES ('https://files.example/x.zip', 'x', 3, 1)")
    _call("run_fls", image_path=str(root))

    with patch("mulder.server.tools.artifacts.shutil.which", return_value="/usr/bin/icat"):
        result = _call("parse_browser_history")

    assert result["result_count"] == 1
    assert "https://files.example/x.zip" in _text(case, "browser.history")


def test_event_logs_of_a_collection_get_a_manifest_like_an_images(
    case: CaseDB, tmp_path: Path
) -> None:
    root = kape(tmp_path / "k")

    result = _call("run_evtx_parser", evtx_path=str(root))

    assert result["source"] == "evtx.manifest"
    assert "Windows_System32_winevt_logs_Security.evtx" in _text(case, "evtx.manifest")
    work = Path(case.get_kv(f"evtx_extract_dir:{root}") or "")
    assert not work.is_relative_to(root)
    copy = work / "Windows_System32_winevt_logs_Security.evtx"
    assert copy.read_bytes() == b"ElfFile-security"


def test_a_plain_directory_of_event_logs_is_still_parsed_at_once(
    case: CaseDB, tmp_path: Path
) -> None:
    logs = write(tmp_path / "logs", {"Security.evtx": b"ElfFile"})

    with patch.object(evtx, "_parse_evtx_with_eztools", return_value={"line_count": 1}) as ez:
        result = _call("run_evtx_parser", evtx_path=str(logs))

    ez.assert_called_once_with(str(logs), str(logs))
    assert result["source"] == "ez.evtx"


# --- timeline --------------------------------------------------------------


def test_mactime_runs_on_the_body_file_a_uac_collection_carries(
    case: CaseDB, tmp_path: Path
) -> None:
    root = uac(tmp_path)
    header = "Date,Size,Type,Mode,UID,GID,Meta,File Name\n"
    done = subprocess.CompletedProcess(
        [], 0, header + "Tue Jan 02 2024 03:04:05,1024,macb,r/rrw-r--r--,0,0,131,/etc/passwd\n", ""
    )
    nothing = subprocess.CompletedProcess([], 0, header, "")  # mactime exits 0 all the same

    with (
        patch.object(tsk, "require_binary", return_value="/usr/bin/mactime"),
        patch(
            "mulder.server.tools.extract.tsk.subprocess.run", side_effect=[done, nothing]
        ) as run,
    ):
        result = _call("run_mactime", image_path=str(root), time_range="2024-01-01..2024-01-03")
        # The range becomes an argument: anything that is not a date or two is refused.
        refused = [
            _call("run_mactime", image_path=str(root), time_range=bad)
            for bad in ("-b..//etc/shadow", "2024-01-01..2024-01-02..2024-01-03")
        ]
        empty = _call("run_mactime", image_path=str(root), time_range="2024-13-45")

    # One argument: given the two dates apart, mactime ignores the second.
    assert [c.args[0] for c in run.call_args_list] == [
        ["mactime", "-b", "-", "-d", "2024-01-01..2024-01-03"],
        ["mactime", "-b", "-", "-d", "2024-13-45"],
    ]
    assert run.call_args.kwargs["input"] == BODY
    assert result["source"] == "tsk.timeline" and "/etc/passwd" in _text(case, "tsk.timeline")
    assert '"body_rows": 1, "timeline_rows": 1' in result["preview"]
    assert [r["error_type"] for r in refused] == ["invalid_input"] * 2
    # A header and nothing under it is not a timeline.
    assert empty["error_type"] == "no_rows" and "rows read: 1" in empty["error_message"]


def test_mactime_on_a_collection_without_a_body_file_says_why(
    case: CaseDB, tmp_path: Path
) -> None:
    root = kape(tmp_path / "k")

    with patch("mulder.server.tools.extract.tsk.subprocess.run") as run:
        result = _call("run_mactime", image_path=str(root))

    run.assert_not_called()
    assert result["error_type"] == "not_applicable"
    assert "those of the copy" in result["error_message"]
    assert "run_mft_parser" in result["suggestion"]


# --- index_triage_collection -----------------------------------------------


def test_a_kape_collection_is_indexed_with_its_copy_log(case: CaseDB, tmp_path: Path) -> None:
    root = kape(tmp_path / "k")
    before = snapshot(root)

    result = _call("index_triage_collection", evidence_path=str(root))["results"]

    assert (result["layout"], result["host"]) == ("KAPE target output", "WS-01")
    assert result["files_collected"] == 9 and result["listing_truncated"] is False
    assert {"registry hives", "event logs", "$MFT", "USN journal"} <= set(result["collected"])
    assert {"Prefetch", "SRUM", "browser history", "memory and crash dumps"} <= set(
        result["not_collected"]
    )
    assert result["sources"] == [
        "tsk.filelist",
        "triage.kape.copylog",
        "triage.kape.skiplog",
        "triage.summary",
    ]
    assert "not thereby absent" in result["note"]

    copylog = _text(case, "triage.kape.copylog")
    # The file as it was on the source: path, hash and times, not when KAPE copied it.
    assert (
        "C:\\Windows\\System32\\config\\SYSTEM\tsha1=C70BFFF0A559AF8CB76AD80A504DD55BD6CC484D\t"
        "size=11\tcreated=2021-09-15 16:02:35.2937725\tmodified=2023-03-15 06:17:16.6838553"
    ) in copylog
    assert "2023-03-24 12:39:26" not in copylog and "C:\\out" not in copylog
    assert "Empty.evtx\tsha1=C70BFFF0A559AF8CB76AD80A504DD55BD6CC484D\treason=Deduped" in _text(
        case, "triage.kape.skiplog"
    )
    assert "not_collected: Prefetch" in _text(case, "triage.summary")
    assert _sources(case)["tsk.filelist"] == LISTING_EXTRACTOR
    assert snapshot(root) == before


def test_a_second_call_is_skipped_and_the_batch_check_sees_it(
    case: CaseDB, tmp_path: Path
) -> None:
    root, other = kape(tmp_path / "k"), windows_volume(tmp_path / "w")
    _call("index_triage_collection", evidence_path=str(root))

    again = _call("index_triage_collection", evidence_path=str(root))["results"]

    assert again["status"] == "skipped"
    assert TOOL_SOURCE_PREFIXES["index_triage_collection"] == ["triage."]
    assert tool_already_indexed("index_triage_collection", evidence_path=str(root))
    # A second collection in the same case is not taken for done.
    assert not tool_already_indexed("index_triage_collection", evidence_path=str(other))
    assert [s.source_name for s in case.get_sources()].count("tsk.filelist") == 1


def test_velociraptor_query_results_become_searchable_sources(
    case: CaseDB, tmp_path: Path
) -> None:
    root = velociraptor(tmp_path / "v")

    result = _call("index_triage_collection", evidence_path=str(root))["results"]

    source = "triage.velociraptor.windows.kapefiles.targets.uploads"
    assert result["layout"] == "Velociraptor offline collection"
    assert result["host"] == "DESKTOP-9" and source in result["sources"]
    assert len(result["volumes"]) == 3  # C twice (ntfs, auto) and D
    row = json.loads(_text(case, source))
    assert row["SourceFile"] == "C:\\Users\\bob\\NTUSER.DAT"  # original path and times
    assert not any(".index" in s for s in _sources(case))


def test_a_huge_or_planted_result_file_is_bounded(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = velociraptor(tmp_path / "v")
    (tmp_path / "secret.json").write_text('{"password": "hunter2"}\n')
    rows = "".join(json.dumps({"n": i, "pad": "x" * 40}) + "\n" for i in range(2000))
    write(root, {"results/Big.json": rows, "results/OneLine.json": '{"k": "' + "v" * 9000})
    (root / "results" / "Planted.json").symlink_to(tmp_path / "secret.json")
    monkeypatch.setattr(triage, "_MAX_SOURCE_BYTES", 4096)

    result = _call("index_triage_collection", evidence_path=str(root))["results"]

    big = _text(case, "triage.velociraptor.big")
    assert len(big) < 4096 + 200 and big.rstrip().endswith("bytes were indexed]")
    assert json.loads(big.splitlines()[-3])["n"] < 100  # cut at a row boundary
    assert "triage.velociraptor.big: only the first 4096 bytes indexed" in result["not_indexed"]
    # No line end to cut at: what was read is indexed, as the result says it was.
    assert _text(case, "triage.velociraptor.oneline").count("v") == 4096 - len('{"k": "')
    assert "triage.velociraptor.planted" not in _sources(case)
    assert "hunter2" not in "".join(_text(case, s) for s in _sources(case))


def test_uac_command_output_is_indexed_per_category(case: CaseDB, tmp_path: Path) -> None:
    root = uac(tmp_path)

    result = _call("index_triage_collection", evidence_path=str(root))["results"]

    assert (result["layout"], result["host"]) == ("UAC collection", "web01")
    assert result["collected"] == ["[root]", "bodyfile", "live_response"]
    assert result["not_collected"] == []  # the Windows artifact list does not apply
    process = _text(case, "triage.uac.process")
    assert process.startswith("=== live_response/process/ps_auxwww.txt ===\n")
    assert "/tmp/.x/miner" in process and "ps: warning" not in process  # .stderr left out
    assert "0.0.0.0:4444" in _text(case, "triage.uac.network")
    assert "etc/passwd" in _text(case, "tsk.filelist")


def test_uac_output_that_is_cut_or_left_out_is_named(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = uac(tmp_path)
    write(
        root,
        {
            "live_response/process/big.txt": "line\n" * 200,
            "live_response/process/oneline.txt": "x" * 2000,
            "live_response/system/lsmod": "ext4 1 0\n",
        },
    )
    monkeypatch.setattr(triage, "_MAX_OUTPUT_BYTES", 512)

    result = _call("index_triage_collection", evidence_path=str(root))["results"]

    process = _text(case, "triage.uac.process")
    # A long single line is cut where reading stopped, not dropped.
    assert f"=== live_response/process/oneline.txt ===\n{'x' * 512}\n[cut at 512 bytes]" in process
    other = "files that are not .txt command output (stderr and others) were not indexed"
    assert result["not_indexed"] == [
        "triage.uac.process: only the first 512 bytes indexed of "
        "process/big.txt, process/oneline.txt",
        f"triage.uac.process: 1 {other}",  # ps_auxwww.txt.stderr
        f"triage.uac.system: 1 {other}",  # lsmod
    ]
    assert "triage.uac.system" not in _sources(case)


def test_a_cut_listing_is_not_reported_as_not_collected(
    case: CaseDB, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What is past the cut was collected all the same."""
    root = velociraptor(tmp_path / "v")
    write(root, {f"uploads/auto/C%3A/Users/bob/Downloads/f{i}": "x" for i in range(30)})
    monkeypatch.setattr(dirroot, "MAX_ENTRIES", 12)

    result = _call("index_triage_collection", evidence_path=str(root))["results"]
    with patch("mulder.server.extract_helpers._mount_image", return_value=False):
        prefetch = _call("run_prefetch_parser", image_path=str(root))

    assert result["listing_truncated"] is True and "not_collected" not in result
    assert "$MFT" in result["collected"]  # at the top of the volume walked last
    assert "Prefetch" in result["not_seen_in_cut_listing"]
    assert "may still be in the collection" in result["note"]
    assert "not_seen_in_cut_listing: " in _text(case, "triage.summary")
    assert "listing was cut" in prefetch["suggestion"]


def test_event_logs_that_were_not_collected_are_not_looked_for_by_carving(
    case: CaseDB, tmp_path: Path
) -> None:
    root = uac(tmp_path)

    result = _call("run_evtx_parser", evtx_path=str(root))

    assert result["status"] == "error" and "No event logs" in result["error_message"]
    assert "disk image" not in result["error_message"]
    assert "run_bulk_extractor" not in result["error_message"]
    assert "was not collected" in result["suggestion"]


def test_anything_else_is_refused_with_a_reason(case: CaseDB, tmp_path: Path) -> None:
    plain = write(tmp_path / "plain", {"notes.txt": "x"})

    not_one = _call("index_triage_collection", evidence_path=str(plain))
    missing = _call("index_triage_collection", evidence_path=str(tmp_path / "nope"))

    assert (not_one["status"], not_one["error_type"]) == ("error", "not_a_collection")
    assert (missing["status"], missing["error_type"]) == ("error", "file_not_found")
    assert _sources(case) == {}
