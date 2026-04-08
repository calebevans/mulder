"""Eric Zimmerman Tools extractor for structured Windows artifact parsing.

Runs EZ Tools (PECmd, AmcacheParser, MFTECmd, etc.) against mounted disk
images at ingest time.  Each tool produces CSV output which is parsed into
text for windowing and embedding.  Tools live at ``/opt/zimmermantools/``
on a SIFT workstation and are invoked via ``dotnet``.

Query-time MCP tools are exposed in ``tools_eztools.py``.
"""

from __future__ import annotations

import contextlib
import csv
import io
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from mulder.extractors.base import ExtractionResult
from mulder.extractors.disk import _mount_image, _unmount_image

logger = logging.getLogger(__name__)

_DISK_IMAGE_EXTS = frozenset({".e01", ".dd", ".img"})
_EZ_TOOLS_DIR = Path("/opt/zimmermantools")

_TOOL_TIMEOUT = 600
_ICAT_TIMEOUT = 120

_MMLS_ROW_RE = re.compile(
    r"^\d+:\d+\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$",
    re.MULTILINE,
)
_NTFS_INDICATORS = ("ntfs", "exfat", "0x07", "win95 fat", "0x0b", "0x0c")


@dataclass(frozen=True)
class _ArtifactJob:
    """Describes one EZ tool invocation."""

    tool_dll: str
    source_name: str
    input_path: Path
    use_dir_flag: bool


def _ez_available() -> bool:
    return shutil.which("dotnet") is not None and _EZ_TOOLS_DIR.is_dir()


def _run_ez_tool(
    tool_dll: str,
    input_path: Path,
    csv_dir: Path,
    csv_filename: str,
    *,
    use_dir_flag: bool = False,
    extra_args: list[str] | None = None,
) -> str:
    """Invoke an EZ tool and return the CSV text output, or empty string on failure."""
    dll_path = _EZ_TOOLS_DIR / tool_dll
    if not dll_path.exists():
        logger.info("EZ tool not found: %s -- skipping", dll_path)
        return ""

    flag = "-d" if use_dir_flag else "-f"
    cmd = [
        "dotnet",
        str(dll_path),
        flag,
        str(input_path),
        "--csv",
        str(csv_dir),
        "--csvf",
        csv_filename,
    ]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("%s timed out after %ds on %s", tool_dll, _TOOL_TIMEOUT, input_path)
        return ""

    if proc.returncode != 0:
        logger.warning(
            "%s exited %d on %s: %s",
            tool_dll,
            proc.returncode,
            input_path,
            (proc.stderr or "")[:300],
        )

    csv_path = csv_dir / csv_filename
    if not csv_path.exists():
        for candidate in csv_dir.glob("*.csv"):
            csv_path = candidate
            break
        else:
            logger.info("%s produced no CSV output for %s", tool_dll, input_path)
            return ""

    return csv_path.read_text(encoding="utf-8", errors="replace")


def _csv_to_text(csv_content: str) -> str:
    """Convert CSV content to tab-separated key=value lines for embedding."""
    if not csv_content.strip():
        return ""

    lines: list[str] = []
    reader = csv.DictReader(io.StringIO(csv_content))
    for row in reader:
        parts = [f"{k}={v}" for k, v in row.items() if v]
        if parts:
            lines.append("\t".join(parts))

    return "\n".join(lines)


def _resolve_partition_offset(image: str) -> int:
    """Run mmls to find the NTFS partition offset, reusing sleuthkit logic."""
    if not shutil.which("mmls"):
        return 0
    try:
        proc = subprocess.run(
            ["mmls", image],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 0

    if proc.returncode != 0 or not proc.stdout.strip():
        return 0

    for m in _MMLS_ROW_RE.finditer(proc.stdout):
        start = int(m.group(1))
        length = int(m.group(2))
        desc = m.group(3).strip().lower()
        if any(ind in desc for ind in _NTFS_INDICATORS) and length > 0:
            return start
    return 0


def _extract_via_icat(image: str, inode: int, dest: Path, offset: int) -> bool:
    """Use icat to extract a file by inode number. Returns True on success."""
    if not shutil.which("icat"):
        return False
    cmd = ["icat"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image, str(inode)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_ICAT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("icat timed out extracting inode %d from %s", inode, image)
        return False

    if proc.returncode != 0 or not proc.stdout:
        return False

    dest.write_bytes(proc.stdout)
    return True


def _find_case_insensitive(root: Path, *segments: str) -> Path | None:
    """Walk path segments case-insensitively under root."""
    current = root
    for seg in segments:
        seg_lower = seg.lower()
        match = next(
            (child for child in current.iterdir() if child.name.lower() == seg_lower),
            None,
        )
        if match is None:
            return None
        current = match
    return current


def _find_all_case_insensitive(root: Path, *segments: str) -> list[Path]:
    """Like _find_case_insensitive but globs the last segment."""
    if len(segments) < 2:
        pattern = segments[0] if segments else "*"
        return sorted(root.glob(pattern))

    parent = _find_case_insensitive(root, *segments[:-1])
    if parent is None or not parent.is_dir():
        return []
    return sorted(parent.glob(segments[-1]))


class EZToolsExtractor:
    """Extracts Windows artifacts from disk images using Eric Zimmerman Tools."""

    name: str = "eztools"

    def can_handle(self, path: Path) -> bool:
        return path.suffix.lower() in _DISK_IMAGE_EXTS

    def extract(self, path: Path, case_id: str) -> list[ExtractionResult]:
        if not _ez_available():
            logger.info(
                "EZ Tools not available (need dotnet + %s) -- skipping %s",
                _EZ_TOOLS_DIR,
                path,
            )
            return []

        mount_point = Path(tempfile.mkdtemp(prefix=f"mulder_{case_id}_ez_"))
        mounted = False

        try:
            mounted = _mount_image(path, mount_point)
            if not mounted:
                logger.error("Cannot mount %s for EZ Tools extraction", path)
                return []

            results: list[ExtractionResult] = []
            image = str(path)

            results.extend(self._run_prefetch(mount_point, image))
            results.extend(self._run_amcache(mount_point, image))
            results.extend(self._run_shimcache(mount_point, image))
            results.extend(self._run_mft(mount_point, image))
            results.extend(self._run_usnjrnl(mount_point, image))
            results.extend(self._run_evtx(mount_point, image))
            results.extend(self._run_registry(mount_point, image))
            results.extend(self._run_jumplists(mount_point, image))
            results.extend(self._run_lnkfiles(mount_point, image))
            results.extend(self._run_shellbags(mount_point, image))
            results.extend(self._run_recyclebin(mount_point, image))
            results.extend(self._run_srum(mount_point, image))

            logger.info("EZ Tools produced %d source(s) for %s", len(results), path)
            return results
        finally:
            if mounted:
                _unmount_image(mount_point)
            with contextlib.suppress(OSError):
                mount_point.rmdir()

    def version(self) -> str:
        if not _ez_available():
            return "eztools (not available)"
        try:
            proc = subprocess.run(
                ["dotnet", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            dotnet_ver = (proc.stdout or "").strip()
            return f"eztools (dotnet {dotnet_ver})"
        except (subprocess.TimeoutExpired, OSError):
            return "eztools (dotnet unknown version)"

    # ------------------------------------------------------------------
    # Individual tool runners
    # ------------------------------------------------------------------

    def _make_result(
        self, source_name: str, source_path: str, text: str
    ) -> list[ExtractionResult]:
        if not text.strip():
            return []
        return [
            ExtractionResult(
                source_name=source_name,
                source_path=source_path,
                extractor=f"eztools-{source_name.split('.', 1)[-1]}",
                text_output=text,
                line_count=text.count("\n") + 1,
            )
        ]

    def _run_tool_and_parse(
        self,
        tool_dll: str,
        input_path: Path,
        csv_filename: str,
        *,
        use_dir_flag: bool = False,
        extra_args: list[str] | None = None,
    ) -> str:
        """Run an EZ tool and return parsed text output."""
        with tempfile.TemporaryDirectory(prefix="mulder_ez_csv_") as csv_dir:
            raw_csv = _run_ez_tool(
                tool_dll,
                input_path,
                Path(csv_dir),
                csv_filename,
                use_dir_flag=use_dir_flag,
                extra_args=extra_args,
            )
            return _csv_to_text(raw_csv)

    def _run_prefetch(self, root: Path, image: str) -> list[ExtractionResult]:
        pf_dir = _find_case_insensitive(root, "Windows", "Prefetch")
        if pf_dir is None or not pf_dir.is_dir():
            return []
        text = self._run_tool_and_parse("PECmd.dll", pf_dir, "prefetch.csv", use_dir_flag=True)
        return self._make_result("ez.prefetch", image, text)

    def _run_amcache(self, root: Path, image: str) -> list[ExtractionResult]:
        amcache = _find_case_insensitive(root, "Windows", "appcompat", "Programs", "Amcache.hve")
        if amcache is None or not amcache.is_file():
            return []
        text = self._run_tool_and_parse("AmcacheParser.dll", amcache, "amcache.csv")
        return self._make_result("ez.amcache", image, text)

    def _run_shimcache(self, root: Path, image: str) -> list[ExtractionResult]:
        system_hive = _find_case_insensitive(root, "Windows", "System32", "config", "SYSTEM")
        if system_hive is None or not system_hive.is_file():
            return []
        text = self._run_tool_and_parse("AppCompatCacheParser.dll", system_hive, "shimcache.csv")
        return self._make_result("ez.shimcache", image, text)

    def _run_mft(self, root: Path, image: str) -> list[ExtractionResult]:
        with tempfile.TemporaryDirectory(prefix="mulder_ez_mft_") as tmp:
            mft_path = Path(tmp) / "$MFT"
            offset = _resolve_partition_offset(image)
            extracted = _extract_via_icat(image, 0, mft_path, offset)

            if not extracted:
                mft_path_mounted = _find_case_insensitive(root, "$MFT")
                if mft_path_mounted is not None and mft_path_mounted.is_file():
                    mft_path = mft_path_mounted
                else:
                    logger.info("Cannot access $MFT for EZ Tools -- skipping MFTECmd")
                    return []

            text = self._run_tool_and_parse("MFTECmd.dll", mft_path, "mft.csv")
            return self._make_result("ez.mft", image, text)

    def _run_usnjrnl(self, root: Path, image: str) -> list[ExtractionResult]:
        with tempfile.TemporaryDirectory(prefix="mulder_ez_usn_") as tmp:
            usn_path = Path(tmp) / "$J"
            offset = _resolve_partition_offset(image)

            usn_inode = self._find_usnjrnl_inode(image, offset)
            if usn_inode is not None:
                extracted = _extract_via_icat(image, usn_inode, usn_path, offset)
            else:
                extracted = False

            if not extracted:
                logger.info("Cannot extract $UsnJrnl:$J -- skipping")
                return []

            text = self._run_tool_and_parse("MFTECmd.dll", usn_path, "usnjrnl.csv")
            return self._make_result("ez.usnjrnl", image, text)

    def _find_usnjrnl_inode(self, image: str, offset: int) -> int | None:
        """Use fls to find the inode number of $UsnJrnl:$J."""
        if not shutil.which("fls"):
            return None
        cmd = ["fls", "-r", "-p"]
        if offset > 0:
            cmd.extend(["-o", str(offset)])
        cmd.append(image)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode != 0:
            return None
        for line in proc.stdout.splitlines():
            if "$UsnJrnl" in line and "$J" in line:
                m = re.search(r"(\d+)(?:-\d+)?(?:-\d+)?:", line)
                if m:
                    return int(m.group(1))
        return None

    def _run_evtx(self, root: Path, image: str) -> list[ExtractionResult]:
        evtx_dir = _find_case_insensitive(root, "Windows", "System32", "winevt", "Logs")
        if evtx_dir is None or not evtx_dir.is_dir():
            return []

        results: list[ExtractionResult] = []
        with tempfile.TemporaryDirectory(prefix="mulder_ez_evtx_") as csv_dir:
            raw_csv = _run_ez_tool(
                "EvtxECmd.dll",
                evtx_dir,
                Path(csv_dir),
                "evtx_all.csv",
                use_dir_flag=True,
            )
            if not raw_csv.strip():
                return []

            channel_rows: dict[str, list[dict[str, str]]] = {}
            reader = csv.DictReader(io.StringIO(raw_csv))
            for row in reader:
                channel = (row.get("Channel") or row.get("channel") or "unknown").lower()
                channel = re.sub(r"[^a-z0-9\-]", "-", channel)
                channel = re.sub(r"-+", "-", channel).strip("-")
                channel_rows.setdefault(channel, []).append(row)

            for channel, rows in channel_rows.items():
                lines = []
                for row in rows:
                    parts = [f"{k}={v}" for k, v in row.items() if v]
                    if parts:
                        lines.append("\t".join(parts))
                text = "\n".join(lines)
                results.extend(self._make_result(f"ez.evtx.{channel}", image, text))

        return results

    def _run_registry(self, root: Path, image: str) -> list[ExtractionResult]:
        config_dir = _find_case_insensitive(root, "Windows", "System32", "config")
        if config_dir is None or not config_dir.is_dir():
            return []

        hive_names = {"system", "software", "sam", "security", "default"}
        results: list[ExtractionResult] = []

        for child in config_dir.iterdir():
            if child.name.lower() not in hive_names or not child.is_file():
                continue
            label = child.name.lower()
            batch_file = _EZ_TOOLS_DIR / "BatchExamples" / "RECmd_Batch_MC.reb"
            extra = ["--bn", str(batch_file)] if batch_file.exists() else None
            text = self._run_tool_and_parse(
                "RECmd.dll", child, f"registry_{label}.csv", extra_args=extra
            )
            results.extend(self._make_result(f"ez.registry.{label}", image, text))

        return results

    def _run_jumplists(self, root: Path, image: str) -> list[ExtractionResult]:
        users_dir = _find_case_insensitive(root, "Users")
        if users_dir is None or not users_dir.is_dir():
            return []

        all_text: list[str] = []
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            jl_dir = _find_case_insensitive(
                user_dir,
                "AppData",
                "Roaming",
                "Microsoft",
                "Windows",
                "Recent",
                "AutomaticDestinations",
            )
            if jl_dir is not None and jl_dir.is_dir():
                text = self._run_tool_and_parse(
                    "JLECmd.dll", jl_dir, "jumplists.csv", use_dir_flag=True
                )
                if text:
                    all_text.append(text)

        return self._make_result("ez.jumplists", image, "\n".join(all_text))

    def _run_lnkfiles(self, root: Path, image: str) -> list[ExtractionResult]:
        users_dir = _find_case_insensitive(root, "Users")
        if users_dir is None or not users_dir.is_dir():
            return []

        all_text: list[str] = []
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            recent_dir = _find_case_insensitive(
                user_dir,
                "AppData",
                "Roaming",
                "Microsoft",
                "Windows",
                "Recent",
            )
            if recent_dir is not None and recent_dir.is_dir():
                text = self._run_tool_and_parse(
                    "LECmd.dll", recent_dir, "lnkfiles.csv", use_dir_flag=True
                )
                if text:
                    all_text.append(text)

        return self._make_result("ez.lnkfiles", image, "\n".join(all_text))

    def _run_shellbags(self, root: Path, image: str) -> list[ExtractionResult]:
        users_dir = _find_case_insensitive(root, "Users")
        if users_dir is None or not users_dir.is_dir():
            return []

        all_text: list[str] = []
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            usrclass = _find_case_insensitive(
                user_dir,
                "AppData",
                "Local",
                "Microsoft",
                "Windows",
                "UsrClass.dat",
            )
            if usrclass is not None and usrclass.is_file():
                text = self._run_tool_and_parse("SBECmd.dll", usrclass, "shellbags.csv")
                if text:
                    all_text.append(text)

        return self._make_result("ez.shellbags", image, "\n".join(all_text))

    def _run_recyclebin(self, root: Path, image: str) -> list[ExtractionResult]:
        rb_dir = _find_case_insensitive(root, "$Recycle.Bin")
        if rb_dir is None or not rb_dir.is_dir():
            return []
        text = self._run_tool_and_parse("RBCmd.dll", rb_dir, "recyclebin.csv", use_dir_flag=True)
        return self._make_result("ez.recyclebin", image, text)

    def _run_srum(self, root: Path, image: str) -> list[ExtractionResult]:
        srudb = _find_case_insensitive(root, "Windows", "System32", "sru", "SRUDB.dat")
        if srudb is None or not srudb.is_file():
            return []
        text = self._run_tool_and_parse("SrumECmd.dll", srudb, "srum.csv")
        return self._make_result("ez.srum", image, text)
