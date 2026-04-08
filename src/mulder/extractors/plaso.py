"""Plaso/log2timeline disk-image and filesystem extractor.

Runs ``log2timeline.py`` to build a Plaso storage file, then ``psort.py``
to export the super-timeline as L2T CSV text.  The resulting timeline is
returned as an :class:`ExtractionResult` for windowing and embedding.

When ``plaso_dir`` is configured, the ``.plaso`` storage file is persisted
alongside the case database so that query-time tools (``tools_plaso.py``)
can run ad-hoc ``psort.py`` queries against it.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from mulder.extractors.base import ExtractionResult

logger = logging.getLogger(__name__)

_DISK_IMAGE_EXTS = frozenset({".e01", ".dd", ".img"})
_LOG2TIMELINE_BIN = "log2timeline.py"
_PSORT_BIN = "psort.py"
_PINFO_BIN = "pinfo.py"
_LOG2TIMELINE_TIMEOUT = 1800  # 30 minutes
_PSORT_TIMEOUT = 600  # 10 minutes
_PINFO_TIMEOUT = 60

_EVTX_EXTS = frozenset({".evtx"})
_REGISTRY_HIVE_NAMES = frozenset(
    {
        "sam",
        "system",
        "software",
        "security",
        "ntuser.dat",
        "usrclass.dat",
        "default",
        "amcache.hve",
    }
)
_PREFETCH_EXTS = frozenset({".pf"})

_TARGETED_PARSER_MAP: dict[str, str] = {
    "evtx": "winevtx",
    "registry": "winreg",
    "prefetch": "prefetch",
}


def _looks_like_mounted_fs(path: Path) -> bool:
    """Heuristic: a directory that contains ``Windows/`` or ``var/log/``."""
    if not path.is_dir():
        return False
    return (path / "Windows").is_dir() or (path / "var" / "log").is_dir()


def _detect_os(path: Path) -> str | None:
    """Detect the OS type from evidence structure.

    Returns ``"windows"``, ``"linux"``, or ``None`` when the OS cannot be
    determined (e.g. raw disk images where Plaso auto-detects internally).
    """
    if not path.is_dir():
        return None
    if (path / "Windows").is_dir():
        return "windows"
    if (path / "var" / "log").is_dir():
        return "linux"
    return None


def _detect_targeted_parser(path: Path) -> str | None:
    """Return a narrow parser string when evidence is a single artifact type.

    For example, a directory containing only ``.evtx`` files should use
    ``--parsers winevtx`` instead of the full parser set.
    """
    if not path.is_dir():
        return None

    children = list(path.iterdir())
    if not children:
        return None

    suffixes = {c.suffix.lower() for c in children if c.is_file()}
    names = {c.name.lower() for c in children if c.is_file()}

    if suffixes and suffixes <= _EVTX_EXTS:
        return _TARGETED_PARSER_MAP["evtx"]

    if names and names <= _REGISTRY_HIVE_NAMES:
        return _TARGETED_PARSER_MAP["registry"]

    if suffixes and suffixes <= _PREFETCH_EXTS:
        return _TARGETED_PARSER_MAP["prefetch"]

    return None


class PlasoExtractor:
    """Runs Plaso/log2timeline against a disk image or mounted filesystem.

    Set :attr:`plaso_dir` to a directory path (typically the case ``db_dir``)
    to persist the ``.plaso`` storage file for query-time tools.
    """

    name: str = "plaso"

    def __init__(self) -> None:
        self._cached_version: str | None = None
        self.plaso_dir: Path | None = None

    def can_handle(self, path: Path) -> bool:
        if path.suffix.lower() in _DISK_IMAGE_EXTS:
            return True
        return _looks_like_mounted_fs(path)

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        if not shutil.which(_LOG2TIMELINE_BIN):
            logger.warning("%s not found on $PATH -- skipping Plaso extraction", _LOG2TIMELINE_BIN)
            return []
        if not shutil.which(_PSORT_BIN):
            logger.warning("%s not found on $PATH -- skipping Plaso extraction", _PSORT_BIN)
            return []

        plaso_path, is_persistent = self._resolve_plaso_path(case_id)
        try:
            l2t_ok = self._run_log2timeline(path, plaso_path)
            if not l2t_ok:
                return []

            results: list[ExtractionResult] = []

            timeline_result = self._run_psort_export(path, plaso_path)
            if timeline_result:
                results.append(timeline_result)

            stats_result = self._run_pinfo(plaso_path)
            if stats_result:
                results.append(stats_result)

            return results

        except subprocess.TimeoutExpired as exc:
            logger.error("Plaso timed out on %s: %s", path, exc)
            return []
        finally:
            if not is_persistent:
                with contextlib.suppress(OSError):
                    Path(plaso_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_plaso_path(self, case_id: str) -> tuple[str, bool]:
        """Return ``(plaso_file_path, is_persistent)``.

        When :attr:`plaso_dir` is set the file lives alongside the case DB
        and is kept after extraction so query-time tools can use it.
        """
        if self.plaso_dir is not None:
            plaso_dir = Path(self.plaso_dir).expanduser()
            plaso_dir.mkdir(parents=True, exist_ok=True)
            return str(plaso_dir / f"{case_id}.plaso"), True

        fd, tmp_path = tempfile.mkstemp(prefix=f"{case_id}_plaso_", suffix=".dump")
        os.close(fd)
        return tmp_path, False

    def _build_l2t_cmd(self, path: Path, plaso_path: str) -> list[str]:
        """Assemble the ``log2timeline.py`` command with optimal flags."""
        cmd: list[str] = [_LOG2TIMELINE_BIN]

        cmd.extend(["--hashers", "md5,sha256"])

        targeted = _detect_targeted_parser(path)
        if targeted:
            cmd.extend(["--parsers", targeted])
        else:
            detected_os = _detect_os(path)
            if detected_os == "windows":
                cmd.extend(["--parsers", "win10"])
            elif detected_os == "linux":
                cmd.extend(["--parsers", "linux"])

        is_disk_image = path.is_file() and path.suffix.lower() in _DISK_IMAGE_EXTS
        if is_disk_image:
            cmd.extend(["--vss-stores", "all"])

        cmd.extend(["--storage-file", plaso_path, str(path)])
        return cmd

    def _run_log2timeline(self, path: Path, plaso_path: str) -> bool:
        """Run ``log2timeline.py`` and return True on success."""
        cmd = self._build_l2t_cmd(path, plaso_path)
        logger.info("Running log2timeline on %s (this may take a while) ...", path)
        logger.debug("log2timeline command: %s", " ".join(cmd))

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_LOG2TIMELINE_TIMEOUT,
            check=False,
        )
        if proc.returncode != 0:
            stderr_preview = (proc.stderr or "")[:500]
            logger.warning(
                "log2timeline exited %d on %s: %s",
                proc.returncode,
                path,
                stderr_preview,
            )
            return False
        return True

    def _run_psort_export(self, path: Path, plaso_path: str) -> ExtractionResult | None:
        """Export the full timeline via ``psort.py -o l2tcsv``."""
        logger.info("Running psort to export L2T CSV ...")
        proc = subprocess.run(
            [_PSORT_BIN, "-o", "l2tcsv", plaso_path],
            capture_output=True,
            text=True,
            timeout=_PSORT_TIMEOUT,
            check=False,
        )
        if proc.returncode != 0:
            stderr_preview = (proc.stderr or "")[:500]
            logger.warning("psort exited %d: %s", proc.returncode, stderr_preview)
            return None

        output = proc.stdout.strip()
        if not output:
            logger.debug("Plaso produced no timeline output for %s", path)
            return None

        return ExtractionResult(
            source_name="plaso.timeline",
            source_path=str(path),
            extractor="plaso",
            text_output=output,
            line_count=output.count("\n") + 1,
        )

    def _run_pinfo(self, plaso_path: str) -> ExtractionResult | None:
        """Run ``pinfo.py -v`` and return parser statistics as an extraction result.

        The ``source_path`` is set to the ``.plaso`` file so query-time tools
        can locate it from the sources table.
        """
        if not shutil.which(_PINFO_BIN):
            logger.debug("pinfo.py not found on $PATH -- skipping stats collection")
            return None

        logger.info("Running pinfo to collect parser statistics ...")
        proc = subprocess.run(
            [_PINFO_BIN, "-v", plaso_path],
            capture_output=True,
            text=True,
            timeout=_PINFO_TIMEOUT,
            check=False,
        )
        if proc.returncode != 0:
            stderr_preview = (proc.stderr or "")[:500]
            logger.warning("pinfo exited %d: %s", proc.returncode, stderr_preview)
            return None

        output = proc.stdout.strip()
        if not output:
            return None

        return ExtractionResult(
            source_name="plaso.stats",
            source_path=plaso_path,
            extractor="plaso",
            text_output=output,
            line_count=output.count("\n") + 1,
        )

    # ------------------------------------------------------------------
    # Version
    # ------------------------------------------------------------------

    def version(self) -> str:
        if self._cached_version is not None:
            return self._cached_version

        if not shutil.which(_LOG2TIMELINE_BIN):
            self._cached_version = "plaso (not installed)"
            return self._cached_version

        try:
            proc = subprocess.run(
                [_LOG2TIMELINE_BIN, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            first_line = (proc.stdout or proc.stderr or "").split("\n", 1)[0]
            self._cached_version = first_line.strip() or "plaso (unknown version)"
        except (subprocess.TimeoutExpired, OSError):
            self._cached_version = "plaso (unknown version)"
        return self._cached_version
