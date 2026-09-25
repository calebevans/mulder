"""Classifier patch: nfcapd files become ``netflow_capture`` by 4-byte magic, never by name.

What: a rotation-named file with magic classifies, the same name with text does not, a renamed
extension-less file classifies only beside a rotation-named sibling (and is not even opened when
alone), ``nfcapd.current.<pid>`` with magic classifies, layout byte 3 / a short header / a symlink
fail the magic check, the 0-byte ``zero-length`` stray and ``nfcapd.txt`` stay unclassified,
``readme.txt`` is still skipped, the fixture tree scans to exactly three ``netflow_capture``
items and ``_manifest_entry`` adds ``size_human``.
When: hermetic (tmp trees + the synthetic ``tests/fixtures/netflow/edge-router`` tree).
Returns: nothing; pytest assertions.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

import mulder.extractors.classifier as classifier_mod
from mulder.extractors.classifier import (
    ClassifiedEvidence,
    EvidenceClassifier,
    _dir_has_named_nfcapd,
    has_nfdump_magic,
    is_nfcapd,
)
from mulder.server.tools.case import _manifest_entry
from tests.netflow_harness import FIXTURE_TREE, MAGIC, nfcapd, yday


@pytest.fixture(autouse=True)
def _clear_listdir_cache() -> None:
    _dir_has_named_nfcapd.cache_clear()


def _classify(path: Path) -> str | None:
    result = EvidenceClassifier()._classify_file(path)
    return result.artifact_type if result else None


def test_rotation_name_with_magic(tmp_path: Path) -> None:
    f = nfcapd(tmp_path, "nfcapd.200103040000")
    assert has_nfdump_magic(f) and is_nfcapd(f)
    assert _classify(f) == "netflow_capture"


def test_rotation_name_with_text_content(tmp_path: Path) -> None:
    f = tmp_path / "nfcapd.200103040000"
    f.write_text("not a netflow file\n")
    assert not has_nfdump_magic(f) and not is_nfcapd(f)
    assert _classify(f) is None
    f2 = tmp_path / "nfcapd.200103035555"
    f2.write_text("not a netflow file\n")
    assert _classify(f2) is None


def test_fourteen_digit_rotation_name(tmp_path: Path) -> None:
    f = nfcapd(tmp_path, "nfcapd.20010304000000")
    assert _classify(f) == "netflow_capture"
    assert _classify(nfcapd(tmp_path, "NFCAPD.20010304000000")) == "netflow_capture"


def test_renamed_file_beside_rotation_named_sibling(tmp_path: Path) -> None:
    nfcapd(tmp_path, "nfcapd.200103040000")
    renamed = nfcapd(tmp_path, "exported-flows")
    assert is_nfcapd(renamed)
    assert _classify(renamed) == "netflow_capture"
    digit_suffix = nfcapd(tmp_path, "flows.001")
    assert _classify(digit_suffix) == "netflow_capture"


def test_renamed_file_alone_is_not_sniffed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alone = nfcapd(tmp_path / "alone", "exported-flows")

    def never(_path: Path) -> bool:
        raise AssertionError("has_nfdump_magic must not be called for a lone renamed file")

    monkeypatch.setattr(classifier_mod, "has_nfdump_magic", never)
    assert not is_nfcapd(alone)
    assert _classify(alone) is None


def test_live_collector_temp_file(tmp_path: Path) -> None:
    nfcapd(tmp_path, "nfcapd.200103040000")
    current = nfcapd(tmp_path, "nfcapd.current.1234")
    assert _classify(current) == "netflow_capture"
    nfcapd(tmp_path / "solo", "nfcapd.current.1234")
    assert _classify(tmp_path / "solo" / "nfcapd.current.1234") is None  # no sibling: not sniffed


@pytest.mark.parametrize(
    "head, expected",
    [
        (b"\x0c\xa5\x02\x00", True),
        (b"\x0c\xa5\x01\x00", True),  # nfdump 1.6 layout
        (b"\x0c\xa5\x03\x00", False),
        (b"\x0c\xa5\x02\x01", False),
        (b"\xa5\x0c\x02\x00", False),  # wrong endianness
        (b"\x0c\xa5\x02", False),  # short
        (b"", False),
        (b"\xd4\xc3\xb2\xa1", False),  # pcap
    ],
)
def test_has_nfdump_magic_header_bytes(tmp_path: Path, head: bytes, expected: bool) -> None:
    f = tmp_path / "nfcapd.200103040000"
    f.write_bytes(head + b"\x00" * 60 if len(head) == 4 else head)
    assert has_nfdump_magic(f) is expected
    assert is_nfcapd(f) is expected


def test_symlink_and_unreadable_fail_magic(tmp_path: Path) -> None:
    real = nfcapd(tmp_path, "nfcapd.200103040000")
    link = tmp_path / "nfcapd.200103050000"
    link.symlink_to(real)
    assert not has_nfdump_magic(link) and not is_nfcapd(link)
    assert not has_nfdump_magic(tmp_path / "missing")
    assert not has_nfdump_magic(tmp_path)  # a directory


def test_strays_stay_unclassified(tmp_path: Path) -> None:
    exporter = tmp_path / "edge-router"
    day_dir = exporter / "2001" / "02"
    nfcapd(day_dir, "nfcapd.200103040000")
    stray = exporter / "zero-length"
    stray.write_bytes(b"")
    assert _classify(stray) is None  # rule (b): edge-router/ has no rotation-named file
    txt = nfcapd(day_dir, "nfcapd.txt")
    assert not is_nfcapd(txt)  # non-digit suffix: never sniffed ...
    assert _classify(txt) == "log_file"  # ... so the pristine .txt rule still applies
    bak = nfcapd(day_dir, "nfcapd.200103040000.bak")
    assert _classify(bak) is None
    readme = day_dir / "readme.txt"
    readme.write_text("notes\n")
    assert _classify(readme) is None
    (day_dir / "auth.log").write_text("Mar  4 12:38:02 sshd\n")
    assert _classify(day_dir / "auth.log") == "log_file"
    (day_dir / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    assert _classify(day_dir / "capture.pcap") == "network_capture"
    assert Path("nfcapd.200103040000").suffix == ".200103040000"


def test_fixture_tree_scans_to_three_items() -> None:
    assert FIXTURE_TREE.is_dir(), f"missing fixture tree {FIXTURE_TREE}"
    items = EvidenceClassifier().classify(FIXTURE_TREE)
    assert Counter(i.artifact_type for i in items) == {"netflow_capture": 3}
    assert sorted(i.path.name for i in items) == [
        "nfcapd.200102030000", "nfcapd.200102040000", "nfcapd.200102100600",
    ]  # fmt: skip
    for item in items:
        assert item.path.stat().st_size > 0 and has_nfdump_magic(item.path)
        assert item.path.read_bytes()[:4] == MAGIC
    assert (FIXTURE_TREE / "zero-length").stat().st_size == 0
    assert (FIXTURE_TREE / "2001" / "02" / "nfcapd.200102035555").read_text() == (
        "not a netflow file\n"
    )


def test_manifest_entry_adds_size_human() -> None:
    path = (FIXTURE_TREE / "2001" / "02" / "nfcapd.200102030000").resolve()
    entry = _manifest_entry(ClassifiedEvidence(path=path, artifact_type="netflow_capture"))
    assert entry["artifact_type"] == "netflow_capture" and entry["path"] == str(path)
    assert entry["size_bytes"] == path.stat().st_size == 20780
    assert isinstance(entry["size_human"], str) and entry["size_human"].endswith("KB")
    assert "media" not in entry


def test_single_file_classify_and_daily_tree(tmp_path: Path) -> None:
    day_dir = tmp_path / "netflow" / "edge-router" / "2001" / "02"
    for day in range(48, 76):
        nfcapd(day_dir, day=yday(day))
    (tmp_path / "netflow" / "edge-router" / "zero-length").write_bytes(b"")
    (day_dir / "nfcapd.200103035555").write_text("not a netflow file\n")
    items = EvidenceClassifier().classify(tmp_path)
    assert Counter(i.artifact_type for i in items) == {"netflow_capture": 28}
    single = EvidenceClassifier().classify(day_dir / "nfcapd.200103040000")
    assert [i.artifact_type for i in single] == ["netflow_capture"]


def test_classify_resniffs_after_a_rotation_named_file_appears(tmp_path: Path) -> None:
    """``_dir_has_named_nfcapd`` is an lru_cache keyed on the directory only; ``classify()``
    clears it per walk so a directory that gains a rotation-named file after its first walk in
    this process is re-sniffed instead of keeping a stale False."""
    day_dir = tmp_path / "flows"
    nfcapd(day_dir, "nfcapd.current.4242")
    nfcapd(day_dir, "exported-flows")
    first = EvidenceClassifier().classify(tmp_path)
    assert first == []  # rule (b): no rotation-named sibling yet
    assert _dir_has_named_nfcapd(str(day_dir)) is False  # the cached answer
    nfcapd(day_dir, "nfcapd.200103040000")
    again = EvidenceClassifier().classify(tmp_path)  # same process, new walk
    assert sorted(i.path.name for i in again) == [
        "exported-flows", "nfcapd.200103040000", "nfcapd.current.4242",
    ]  # fmt: skip
    assert all(i.artifact_type == "netflow_capture" for i in again)
