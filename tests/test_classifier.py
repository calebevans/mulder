"""Tests for mulder.extractors.classifier -- evidence classification."""

from __future__ import annotations

from pathlib import Path

import pytest

from mulder.extractors.classifier import (
    ClassifierConfig,
    EvidenceClassifier,
    _is_evidence_sidecar,
    _is_hidden,
)


@pytest.fixture()
def classifier() -> EvidenceClassifier:
    return EvidenceClassifier()


class TestExtensionMapping:
    @pytest.mark.parametrize(
        "filename, expected_type",
        [
            ("memdump.mem", "memory_dump"),
            ("image.vmem", "memory_dump"),
            ("crash.dmp", "memory_dump"),
            ("dump.raw", "memory_dump"),
            ("disk.e01", "disk_image"),
            ("disk.dd", "disk_image"),
            ("disk.img", "disk_image"),
            ("capture.pcap", "network_capture"),
            ("capture.pcapng", "network_capture"),
            ("Security.evtx", "evtx"),
            ("rules.yar", "yara_rules"),
            ("archive.zip", "compressed_archive"),
            ("backup.tar.gz", "compressed_archive"),
            ("index.dat", "browser_history"),
            ("contacts2.db", "phone_database"),
            ("manifest.db", "phone_database"),
            ("unknown.sqlite", "sqlite_database"),
            ("server.log", "log_file"),
            ("output.txt", "log_file"),
        ],
    )
    def test_known_extensions(
        self, classifier: EvidenceClassifier, tmp_path: Path, filename: str, expected_type: str
    ) -> None:
        f = tmp_path / filename
        f.write_text("data")
        results = classifier.classify(f)
        assert len(results) == 1
        assert results[0].artifact_type == expected_type

    def test_single_file_classification(
        self, classifier: EvidenceClassifier, tmp_path: Path
    ) -> None:
        f = tmp_path / "evidence.e01"
        f.write_text("data")
        results = classifier.classify(f)
        assert len(results) == 1
        assert results[0].path == f


class TestSkipRules:
    @pytest.mark.parametrize("filename", ["readme.txt", "LICENSE", ".gitignore", "Makefile"])
    def test_skip_filenames(
        self, classifier: EvidenceClassifier, tmp_path: Path, filename: str
    ) -> None:
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / filename).write_text("ignored")
        results = classifier.classify(evidence_dir)
        assert results == []

    @pytest.mark.parametrize("filename", ["script.py", "notes.md", "style.css", "data.json"])
    def test_skip_extensions(
        self, classifier: EvidenceClassifier, tmp_path: Path, filename: str
    ) -> None:
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / filename).write_text("ignored")
        results = classifier.classify(evidence_dir)
        assert results == []


class TestHiddenFiles:
    def test_hidden_files_excluded(self, classifier: EvidenceClassifier, tmp_path: Path) -> None:
        evidence_dir = tmp_path / "evidence"
        hidden_dir = evidence_dir / ".hidden"
        hidden_dir.mkdir(parents=True)
        (hidden_dir / "memdump.mem").write_text("data")
        results = classifier.classify(evidence_dir)
        assert results == []


class TestExcludePatterns:
    def test_glob_exclude(self, tmp_path: Path) -> None:
        config = ClassifierConfig(exclude_patterns=["*.mem"])
        clf = EvidenceClassifier(config)
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / "dump.mem").write_text("data")
        (evidence_dir / "disk.e01").write_text("data")
        results = clf.classify(evidence_dir)
        assert len(results) == 1
        assert results[0].artifact_type == "disk_image"


class TestEvidenceSidecar:
    def test_e01_txt_is_sidecar(self) -> None:
        assert _is_evidence_sidecar(Path("evidence.E01.txt"))

    def test_raw_suffix_is_sidecar(self) -> None:
        assert _is_evidence_sidecar(Path("win7-memory-raw.txt"))

    def test_normal_log_is_not_sidecar(self) -> None:
        assert not _is_evidence_sidecar(Path("server.log.txt"))


class TestLogDirectoryDetection:
    def test_name_based(self, classifier: EvidenceClassifier, tmp_path: Path) -> None:
        evidence_dir = tmp_path / "evidence"
        log_dir = evidence_dir / "logs"
        log_dir.mkdir(parents=True)
        (log_dir / "auth.log").write_text("data")
        results = classifier.classify(evidence_dir)
        types = {r.artifact_type for r in results}
        assert "log_directory" in types

    def test_var_log_path(self, classifier: EvidenceClassifier, tmp_path: Path) -> None:
        evidence_dir = tmp_path / "evidence"
        var_log = evidence_dir / "var" / "log"
        var_log.mkdir(parents=True)
        (var_log / "syslog.log").write_text("data")
        results = classifier.classify(evidence_dir)
        types = {r.artifact_type for r in results}
        assert "log_directory" in types


class TestPhoneDumpSizeThreshold:
    def test_small_bin_not_classified(
        self, classifier: EvidenceClassifier, tmp_path: Path
    ) -> None:
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        small = evidence_dir / "small.bin"
        small.write_bytes(b"\x00" * 100)
        results = classifier.classify(evidence_dir)
        assert results == []


class TestNonexistentPath:
    def test_raises_file_not_found(self, classifier: EvidenceClassifier) -> None:
        with pytest.raises(FileNotFoundError, match="does not exist"):
            classifier.classify(Path("/nonexistent/evidence"))


class TestIsHidden:
    def test_dot_prefixed_component(self) -> None:
        assert _is_hidden(Path("/a/.hidden/file.txt"))

    def test_normal_path_not_hidden(self) -> None:
        assert not _is_hidden(Path("/a/b/file.txt"))


class TestAutoExcludeDirs:
    def test_precooked_excluded(self, classifier: EvidenceClassifier, tmp_path: Path) -> None:
        evidence_dir = tmp_path / "evidence"
        precooked = evidence_dir / "precooked"
        precooked.mkdir(parents=True)
        (precooked / "dump.mem").write_text("data")
        (evidence_dir / "real.mem").write_text("data")
        results = classifier.classify(evidence_dir)
        assert len(results) == 1
        assert results[0].path == evidence_dir / "real.mem"


class TestDiskImageExts:
    def test_disk_image_exts_defined(self) -> None:
        from mulder.extractors import DISK_IMAGE_EXTS

        assert ".e01" in DISK_IMAGE_EXTS
        assert ".dd" in DISK_IMAGE_EXTS
        assert ".img" in DISK_IMAGE_EXTS
        assert isinstance(DISK_IMAGE_EXTS, frozenset)
