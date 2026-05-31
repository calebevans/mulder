"""Sleuth Kit (TSK) filesystem forensics extractor.

Runs TSK command-line tools (mmls, fls, mactime, fsstat) against disk
images at ingest time to produce filesystem listing, timeline, and
partition metadata.  Query-time tools (icat, istat) are exposed via
the MCP tool layer in ``tools_tsk.py``.
"""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import subprocess
from pathlib import Path

from mulder.extractors import DISK_IMAGE_EXTS
from mulder.extractors.base import ExtractionResult

logger = logging.getLogger(__name__)

_MMLS_TIMEOUT = 60
_FLS_TIMEOUT = 600
_MACTIME_TIMEOUT = 300
_FSSTAT_TIMEOUT = 60

# Matches mmls output rows:  000:002   0000002048   0001023999   0001021952   NTFS / exFAT (0x07)
_MMLS_ROW_RE = re.compile(
    r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$",
    re.MULTILINE,
)

_NTFS_INDICATORS = ("ntfs", "exfat", "0x07", "win95 fat", "0x0b", "0x0c")
_LINUX_INDICATORS = ("linux", "0x83", "ext", "0x8e")


def _tsk_available() -> bool:
    """Return True if The Sleuth Kit is installed (``fls`` on $PATH)."""
    return shutil.which("fls") is not None


def _parse_partition_offset(mmls_output: str) -> int:
    """Parse mmls output to find the best partition offset (in sectors).

    Prefers NTFS/Linux partitions; falls back to the largest partition.
    """
    rows: list[tuple[int, int, str]] = []
    for m in _MMLS_ROW_RE.finditer(mmls_output):
        start_sector = int(m.group(1))
        length = int(m.group(2))
        desc = m.group(3).strip()
        rows.append((start_sector, length, desc))

    if not rows:
        return 0

    annotated = [(s, sz, d.lower()) for s, sz, d in rows]

    for start, length, dl in annotated:
        if any(ind in dl for ind in _NTFS_INDICATORS) and length > 0:
            return start

    for start, length, dl in annotated:
        if any(ind in dl for ind in _LINUX_INDICATORS) and length > 0:
            return start

    biggest = max(annotated, key=lambda t: t[1])
    if biggest[1] > 0:
        return biggest[0]

    return 0


class SleuthKitExtractor:
    """Extracts filesystem metadata from disk images using TSK tools."""

    name: str = "sleuthkit"

    def can_handle(self, path: Path) -> bool:
        """Return True for disk image files (.e01/.dd/.img)."""
        return path.suffix.lower() in DISK_IMAGE_EXTS

    def extract(self, path: Path, _case_id: str) -> list[ExtractionResult]:
        """Run TSK tools (mmls, fls, mactime, fsstat) and return filesystem metadata."""
        if not _tsk_available():
            logger.info("Sleuth Kit not installed (fls not on PATH), skipping %s", path)
            return []

        results: list[ExtractionResult] = []
        image = str(path)

        mmls_text, offset = self._run_mmls(image)
        if mmls_text:
            results.append(
                ExtractionResult(
                    source_name="tsk.partitions",
                    source_path=image,
                    extractor="sleuthkit-mmls",
                    text_output=mmls_text,
                    line_count=mmls_text.count("\n") + 1,
                )
            )

        filelist = self._run_fls_listing(image, offset)
        if filelist:
            results.append(
                ExtractionResult(
                    source_name="tsk.filelist",
                    source_path=image,
                    extractor="sleuthkit-fls",
                    text_output=filelist,
                    line_count=filelist.count("\n") + 1,
                )
            )

        timeline = self._run_fls_timeline(image, offset)
        if timeline:
            results.append(
                ExtractionResult(
                    source_name="tsk.timeline",
                    source_path=image,
                    extractor="sleuthkit-mactime",
                    text_output=timeline,
                    line_count=timeline.count("\n") + 1,
                )
            )

        fsstat_text = self._run_fsstat(image, offset)
        if fsstat_text:
            results.append(
                ExtractionResult(
                    source_name="tsk.fsstat",
                    source_path=image,
                    extractor="sleuthkit-fsstat",
                    text_output=fsstat_text,
                    line_count=fsstat_text.count("\n") + 1,
                )
            )

        logger.info(
            "SleuthKit produced %d source(s) for %s (offset=%d)",
            len(results),
            path,
            offset,
        )
        return results

    def version(self) -> str:
        """Return the Sleuth Kit version string from ``fls -V``."""
        if not _tsk_available():
            return "sleuthkit (not installed)"
        try:
            proc = subprocess.run(
                ["fls", "-V"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            line = (proc.stdout or proc.stderr or "").strip().split("\n", 1)[0]
            return line or "sleuthkit (unknown version)"
        except (subprocess.TimeoutExpired, OSError):
            return "sleuthkit (unknown version)"

    def _run_mmls(self, image: str) -> tuple[str, int]:
        """Run mmls and return (output_text, partition_offset_sectors).

        Returns ("", 0) if mmls fails (e.g. raw filesystem with no
        partition table).
        """
        try:
            proc = subprocess.run(
                ["mmls", image],
                capture_output=True,
                text=True,
                timeout=_MMLS_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error("mmls timed out on %s", image)
            return "", 0

        if proc.returncode != 0 or not proc.stdout.strip():
            logger.info(
                "mmls returned no partition table for %s (rc=%d); using offset 0",
                image,
                proc.returncode,
            )
            return "", 0

        text = proc.stdout.strip()
        offset = _parse_partition_offset(text)
        logger.info("Parsed partition offset %d sectors from mmls for %s", offset, image)
        return text, offset

    def _run_fls_listing(self, image: str, offset: int) -> str:
        """Run ``fls -r -p`` for a recursive file listing including deleted files."""
        cmd = ["fls", "-r", "-p"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(image)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_FLS_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error("fls -r -p timed out on %s", image)
            return ""

        if proc.returncode != 0:
            logger.warning(
                "fls -r -p exited %d on %s: %s", proc.returncode, image, (proc.stderr or "")[:300]
            )
            return ""

        return proc.stdout.strip()

    def _run_fls_timeline(self, image: str, offset: int) -> str:
        """Run ``fls -r -m /`` piped to ``mactime -b - -z UTC`` for a filesystem timeline."""
        if not shutil.which("mactime"):
            logger.info("mactime not on PATH, skipping timeline generation")
            return ""

        fls_cmd = ["fls", "-r", "-m", "/"]
        if offset > 0:
            fls_cmd.extend(["-o", str(offset)])
        fls_cmd.append(image)

        try:
            fls_proc = subprocess.Popen(
                fls_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            mac_proc = subprocess.Popen(
                ["mactime", "-b", "-", "-z", "UTC"],
                stdin=fls_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Allow fls to receive SIGPIPE if mactime exits
            if fls_proc.stdout:
                fls_proc.stdout.close()

            mac_stdout, mac_stderr = mac_proc.communicate(timeout=_FLS_TIMEOUT + _MACTIME_TIMEOUT)
            fls_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            logger.error("fls|mactime pipeline timed out on %s", image)
            for p in (fls_proc, mac_proc):
                with contextlib.suppress(OSError):
                    p.kill()
                with contextlib.suppress(OSError):
                    p.wait(timeout=5)
            return ""
        except OSError as exc:
            logger.error("fls|mactime pipeline failed on %s: %s", image, exc)
            for p in (fls_proc, mac_proc):
                with contextlib.suppress(OSError):
                    p.kill()
                with contextlib.suppress(OSError):
                    p.wait(timeout=5)
            return ""

        if mac_proc.returncode != 0:
            logger.warning(
                "mactime exited %d on %s: %s",
                mac_proc.returncode,
                image,
                (mac_stderr or "")[:300],
            )

        return (mac_stdout or "").strip()

    def _run_fsstat(self, image: str, offset: int) -> str:
        """Run ``fsstat`` for filesystem metadata."""
        cmd = ["fsstat"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(image)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_FSSTAT_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error("fsstat timed out on %s", image)
            return ""

        if proc.returncode != 0:
            logger.warning(
                "fsstat exited %d on %s: %s", proc.returncode, image, (proc.stderr or "")[:300]
            )
            return ""

        return proc.stdout.strip()
