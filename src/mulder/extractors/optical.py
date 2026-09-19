"""Optical media (UDF and ISO 9660) reader for disc images.

Sleuth Kit has no UDF or ISO 9660 support (``fls`` reports "Possible
encryption detected (High entropy)" on a CD-R image), the FUSE mount chain
has no UDF driver, and no packaged userland tool (p7zip, 7-Zip 26, pycdlib,
udfclient) can open a Windows "Live File System" CD-R: those discs are UDF
2.01 with a Virtual Allocation Table, which only the Linux kernel driver
understands.  This module is a small pure-Python reader that covers what
forensic disc images actually contain:

- UDF 1.02-2.01, including write-once media with a VAT.  Every earlier
  VAT generation is walked too, so files deleted or renamed by a later
  session are listed (marked ``*``) and can still be extracted, because a
  write-once disc never overwrites their data.
- ISO 9660 with Joliet names.

Raw (``.dd``/``.iso``/``.bin``) images are read directly; EWF images are
exposed as a flat file with ``xmount`` (see :func:`raw_image`).
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO

from mulder.extractors.disk import (
    _EWF_FIRST_SEGMENT,
    _ewf_segments,
    _run,
    _unmount_path,
)

logger = logging.getLogger(__name__)

SECTOR = 2048
_VRS_START = 16
_VRS_END = 32
_MAX_VAT_GENERATIONS = 64
_VAT_SEARCH_SECTORS = 1024
_MAX_ENTRIES = 200_000

_TAG_PVD, _TAG_AVDP, _TAG_PD, _TAG_LVD, _TAG_TD = 1, 2, 5, 6, 8
_TAG_FSD, _TAG_FID, _TAG_FE, _TAG_EFE = 256, 257, 261, 266
_FILE_TYPE_VAT = 248
_FID_DIRECTORY, _FID_DELETED, _FID_PARENT = 0x02, 0x04, 0x08


class OpticalError(RuntimeError):
    """The image is not a readable UDF/ISO 9660 disc."""


@dataclass
class _FileEntry:
    """The parts of a UDF (Extended) File Entry the walker needs."""

    file_type: int
    size: int
    mtime: str
    ctime: str
    extents: list[tuple[int, int]]  # (byte offset, length)
    embedded: bytes | None


@dataclass
class OpticalEntry:
    """One file or directory on the disc."""

    path: str
    is_dir: bool
    size: int
    mtime: str
    ctime: str
    deleted: bool
    generation: int
    extents: list[tuple[int, int]] = field(default_factory=list)  # (byte offset, length)
    location: str = ""


@dataclass
class OpticalListing:
    """Volume metadata plus every entry found on the disc."""

    fs_type: str
    volume_label: str
    sectors: int
    generations: int
    entries: list[OpticalEntry]

    def to_text(self) -> str:
        """fls-like tab-separated text: one header line, one line per entry."""
        lines = [
            f"Optical media: {self.fs_type}\tvolume label: {self.volume_label!r}"
            f"\tsectors: {self.sectors}\tsessions (VAT generations): {self.generations}"
        ]
        for e in self.entries:
            kind = "d/d" if e.is_dir else "r/r"
            flag = "* " if e.deleted else ""
            state = "deleted" if e.deleted else "present"
            lines.append(
                f"{flag}{kind} {e.location}:\t{e.path}\tsize={e.size}"
                f"\tmodified={e.mtime}\tcreated={e.ctime}\t{state} (session {e.generation})"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Signature probing
# ---------------------------------------------------------------------------


def signature_from_vrs(vrs: bytes) -> str | None:
    """Classify a Volume Recognition Sequence (sectors 16-31) as ``udf``/``iso9660``."""
    idents = {vrs[i + 1 : i + 6] for i in range(0, len(vrs) - 6, SECTOR)}
    if idents & {b"BEA01", b"NSR02", b"NSR03"}:
        return "udf"
    if b"CD001" in idents:
        return "iso9660"
    return None


def probe_optical(image_path: str) -> str | None:
    """Return ``udf``/``iso9660`` when *image_path* carries an optical signature.

    Cheap enough for catalog time: raw images are read directly; EWF images
    go through TSK ``img_cat`` (which decompresses just the needed chunk), so
    no mount is involved.
    """
    path = Path(image_path)
    try:
        if _EWF_FIRST_SEGMENT.search(path.name):
            if not shutil.which("img_cat"):
                return None
            proc = subprocess.run(
                ["img_cat", "-b", str(SECTOR), "-s", str(_VRS_START), "-e", str(_VRS_END - 1)]
                + [str(path)],
                capture_output=True,
                timeout=60,
                check=False,
            )
            vrs = proc.stdout if proc.returncode == 0 else b""
        else:
            with open(path, "rb") as fh:
                fh.seek(_VRS_START * SECTOR)
                vrs = fh.read((_VRS_END - _VRS_START) * SECTOR)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return signature_from_vrs(vrs)


@contextmanager
def raw_image(image_path: str) -> Iterator[Path]:
    """Yield a flat, seekable path for *image_path*, xmounting EWF images."""
    path = Path(image_path)
    if not _EWF_FIRST_SEGMENT.search(path.name):
        yield path
        return
    if not shutil.which("xmount"):
        raise OpticalError("xmount not found; cannot read an E01 disc image")
    raw_dir = Path(tempfile.mkdtemp(prefix="mulder_optical_"))
    cmd = ["xmount", "--in", "ewf", *map(str, _ewf_segments(path)), "--out", "raw", str(raw_dir)]
    if not _run(cmd, timeout=120):
        shutil.rmtree(raw_dir, ignore_errors=True)
        raise OpticalError(f"xmount could not expose {path.name}")
    try:
        raw = next(raw_dir.glob("*.dd"), None)
        if raw is None:
            raise OpticalError(f"xmount exposed no .dd file for {path.name}")
        yield raw
    finally:
        _unmount_path(raw_dir, lazy=True)
        shutil.rmtree(raw_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Shared decoding helpers
# ---------------------------------------------------------------------------


def _u16(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", b, off)[0])


def _u32(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", b, off)[0])


def _dstring(b: bytes) -> str:
    """Decode an OSTA compressed-unicode string (first byte is the width)."""
    if not b:
        return ""
    width, body = b[0], b[1:]
    if width in (8, 254):
        return body.decode("latin-1")
    if width in (16, 255):
        return body[: len(body) & ~1].decode("utf-16-be", errors="replace")
    return body.decode("latin-1", errors="replace")


def _fixed_dstring(b: bytes) -> str:
    """A fixed-width dstring keeps its byte length in the last byte."""
    n = b[-1]
    return _dstring(b[:n]).rstrip("\0") if 0 < n < len(b) else ""


def _udf_timestamp(b: bytes) -> str:
    type_tz = _u16(b, 0)
    year = struct.unpack_from("<h", b, 2)[0]
    tz = type_tz & 0x0FFF
    if tz & 0x800:
        tz -= 0x1000
    try:
        dt = datetime(year, b[4], b[5], b[6], b[7], b[8])
    except ValueError:
        return ""
    if tz != -2048:  # -2048 means "no timezone recorded"
        dt = dt.replace(tzinfo=timezone(timedelta(minutes=tz)))
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ" if dt.tzinfo else "%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------------------
# UDF
# ---------------------------------------------------------------------------


class _Udf:
    """A minimal UDF volume: physical + virtual (VAT) partition maps."""

    def __init__(self, fh: BinaryIO, size: int) -> None:
        self.fh = fh
        self.sectors = size // SECTOR
        self.part_start: dict[int, int] = {}  # partition number -> start sector
        self.maps: list[tuple[str, int]] = []  # (kind, partition number) by map index
        self.vat: list[int] | None = None
        self.label = ""
        self.fsd_ad = b""
        self._parse_vds()

    def sector(self, n: int, count: int = 1) -> bytes:
        self.fh.seek(n * SECTOR)
        return self.fh.read(count * SECTOR)

    def _parse_vds(self) -> None:
        candidates = (256, self.sectors - 257, self.sectors - 1)
        avdp = next((s for s in candidates if self._tag(s) == _TAG_AVDP), None)
        if avdp is None:
            raise OpticalError("UDF anchor volume descriptor pointer not found")
        b = self.sector(avdp)
        length, loc = _u32(b, 16), _u32(b, 20)
        for i in range(max(1, length // SECTOR)):
            d = self.sector(loc + i)
            tag = _u16(d, 0)
            if tag == _TAG_TD or tag == 0:
                break
            if tag == _TAG_PD:
                self.part_start[_u16(d, 22)] = _u32(d, 188)
            elif tag == _TAG_LVD:
                self.label = _fixed_dstring(d[84:212])
                self.fsd_ad = d[248:264]
                off = 440
                for _ in range(_u32(d, 268)):
                    kind, mlen = d[off], d[off + 1]
                    if kind == 1:
                        self.maps.append(("physical", _u16(d, off + 4)))
                    else:
                        ident = d[off + 5 : off + 27]
                        if ident.startswith(b"*UDF Virtual Partition"):
                            self.maps.append(("virtual", _u16(d, off + 38)))
                        elif ident.startswith(b"*UDF Sparable Partition"):
                            # ponytail: sparing-table remaps ignored; CD-RW only
                            self.maps.append(("physical", _u16(d, off + 38)))
                        else:
                            raise OpticalError(f"unsupported UDF partition map {ident!r}")
                    off += mlen
        if not self.maps or not self.part_start:
            raise OpticalError("UDF logical volume or partition descriptor missing")

    def _tag(self, sector: int) -> int:
        if sector < 0 or sector >= self.sectors:
            return -1
        b = self.sector(sector)
        if len(b) < 16 or (sum(b[:4]) + sum(b[5:16])) & 0xFF != b[4]:
            return -1
        return _u16(b, 0)

    def physical(self, part_ref: int, lb: int) -> int:
        """Map a (partition reference, logical block) to a physical sector."""
        kind, num = self.maps[part_ref]
        if kind == "virtual":
            if self.vat is None or lb >= len(self.vat):
                raise OpticalError(f"virtual block {lb} outside the VAT")
            lb = self.vat[lb]
        return self.part_start[num] + lb

    # -- file entries -------------------------------------------------------

    def read_fe(self, part_ref: int, lb: int) -> _FileEntry | None:
        """Parse a (Extended) File Entry into type, size, times and extents."""
        try:
            sec = self.physical(part_ref, lb)
        except (OpticalError, KeyError):
            return None
        b = self.sector(sec)
        tag = _u16(b, 0)
        if tag not in (_TAG_FE, _TAG_EFE) or (sum(b[:4]) + sum(b[5:16])) & 0xFF != b[4]:
            return None
        efe = tag == _TAG_EFE
        file_type = b[27]
        ad_type = _u16(b, 34) & 7
        size = struct.unpack_from("<Q", b, 56)[0]
        # FE: access@72 modification@84; EFE: access@80 modification@92 creation@104
        mtime = _udf_timestamp(b[92:104] if efe else b[84:96])
        ctime = _udf_timestamp(b[104:116] if efe else b[84:96])
        l_ea, l_ad = (_u32(b, 208), _u32(b, 212)) if efe else (_u32(b, 168), _u32(b, 172))
        ads = b[(216 if efe else 176) + l_ea :][:l_ad]
        extents: list[tuple[int, int]] = []
        embedded: bytes | None = None
        if ad_type == 3:
            embedded = ads[:size]
        else:
            step = 8 if ad_type == 0 else 16
            for off in range(0, len(ads) - step + 1, step):
                raw_len = _u32(ads, off)
                ext_type, ext_len = raw_len >> 30, raw_len & 0x3FFFFFFF
                if ext_len == 0:
                    break
                if ext_type == 3:  # continuation pointer to another AD block
                    break  # ponytail: multi-block AD chains unsupported
                ref = part_ref if step == 8 else _u16(ads, off + 8)
                try:
                    phys = self.physical(ref, _u32(ads, off + 4))
                except (OpticalError, KeyError):
                    return None
                if ext_type == 0:
                    extents.append((phys * SECTOR, ext_len))
        return _FileEntry(file_type, size, mtime, ctime, extents, embedded)

    def read_data(self, fe: _FileEntry, limit: int | None = None) -> bytes:
        if fe.embedded is not None:
            return fe.embedded[:limit]
        out = bytearray()
        for off, length in fe.extents:
            self.fh.seek(off)
            out += self.fh.read(length)
            if limit is not None and len(out) >= limit:
                break
        return bytes(out[:limit])

    # -- VAT ----------------------------------------------------------------

    def find_vat(self, at_or_before: int) -> tuple[int, list[int], int | None] | None:
        """Locate the VAT ICB at or before sector *at_or_before*.

        Returns ``(icb sector, table, previous VAT ICB sector)``.
        """
        if not any(k == "virtual" for k, _ in self.maps):
            return None
        phys_num = next(num for k, num in self.maps if k == "physical")
        start = self.part_start[phys_num]
        low = max(start, at_or_before - _VAT_SEARCH_SECTORS)
        for sec in range(at_or_before, low - 1, -1):
            if self._tag(sec) not in (_TAG_FE, _TAG_EFE):
                continue
            self.vat = None
            fe = self.read_fe(0, sec - start)
            if fe is None:
                continue
            data = self.read_data(fe)
            if fe.file_type == _FILE_TYPE_VAT:  # UDF 2.x: header then entries
                hdr = _u16(data, 0)
                prev = _u32(data, 132)
                table = list(struct.unpack_from(f"<{(len(data) - hdr) // 4}I", data, hdr))
            elif fe.file_type == 0 and b"*UDF Virtual Alloc Tbl" in data[-36:]:
                prev = _u32(data, len(data) - 4)  # UDF 1.50: entries then trailer
                table = list(struct.unpack_from(f"<{(len(data) - 36) // 4}I", data, 0))
            else:
                continue
            return sec, table, None if prev == 0xFFFFFFFF else start + prev
        return None

    # -- directory walk -----------------------------------------------------

    def walk(self, generation: int) -> list[OpticalEntry]:
        fsd_sec = self.physical(_u16(self.fsd_ad, 8), _u32(self.fsd_ad, 4))
        fsd = self.sector(fsd_sec)
        if _u16(fsd, 0) != _TAG_FSD:
            raise OpticalError("UDF file set descriptor not found")
        root = fsd[400:416]
        entries: list[OpticalEntry] = []
        self._walk_dir(_u16(root, 8), _u32(root, 4), "", generation, entries, set())
        return entries

    def _walk_dir(
        self,
        part_ref: int,
        lb: int,
        prefix: str,
        generation: int,
        out: list[OpticalEntry],
        seen: set[tuple[int, int]],
    ) -> None:
        if (part_ref, lb) in seen or len(out) >= _MAX_ENTRIES:
            return
        seen.add((part_ref, lb))
        fe = self.read_fe(part_ref, lb)
        if fe is None:
            return
        data = self.read_data(fe)
        off = 0
        while off + 38 <= len(data):
            if _u16(data, off) != _TAG_FID:
                break
            chars, l_fi, l_iu = data[off + 18], data[off + 19], _u16(data, off + 36)
            icb = data[off + 20 : off + 36]
            name = _dstring(data[off + 38 + l_iu : off + 38 + l_iu + l_fi])
            off += (38 + l_fi + l_iu + 3) & ~3
            if chars & _FID_PARENT or not name:
                continue
            child_ref, child_lb = _u16(icb, 8), _u32(icb, 4)
            path = f"{prefix}/{name}"
            # A deleted FID keeps its name but zeroes its ICB; block 0 is not it.
            child = self.read_fe(child_ref, child_lb) if _u32(icb, 0) else None
            is_dir = bool(chars & _FID_DIRECTORY)
            out.append(
                OpticalEntry(
                    path=path,
                    is_dir=is_dir,
                    size=child.size if child and not is_dir else 0,
                    mtime=child.mtime if child else "",
                    ctime=child.ctime if child else "",
                    deleted=bool(chars & _FID_DELETED),
                    generation=generation,
                    extents=list(child.extents) if child else [],
                    location=f"{child_ref}:{child_lb}",
                )
            )
            if is_dir and child is not None:
                self._walk_dir(child_ref, child_lb, path, generation, out, seen)


def _list_udf(fh: BinaryIO, size: int) -> OpticalListing:
    udf = _Udf(fh, size)
    generations: list[list[OpticalEntry]] = []
    vat = udf.find_vat(udf.sectors - 1)
    if vat is None:
        generations.append(udf.walk(0))
    else:
        seen_icbs: set[int] = set()
        while vat is not None and len(generations) < _MAX_VAT_GENERATIONS:
            icb, table, prev = vat
            if icb in seen_icbs:
                break
            seen_icbs.add(icb)
            udf.vat = table
            try:
                generations.append(udf.walk(-len(generations)))
            except OpticalError:
                logger.debug("UDF VAT generation at sector %d unreadable", icb, exc_info=True)
            vat = udf.find_vat(prev) if prev is not None else None

    # The newest generation is authoritative; older ones only contribute
    # entries (path + ICB) it no longer has, which are reported as deleted.
    entries: list[OpticalEntry] = []
    known: set[tuple[str, str]] = set()
    for gen_entries in generations:
        for e in gen_entries:
            key = (e.path, e.location)
            if key in known:
                continue
            known.add(key)
            if e.generation != 0:
                e.deleted = True
            entries.append(e)
    return OpticalListing(
        fs_type="UDF" + (" (write-once, VAT)" if vat is not None or udf.vat else ""),
        volume_label=udf.label,
        sectors=udf.sectors,
        generations=max(1, len(generations)),
        entries=entries,
    )


# ---------------------------------------------------------------------------
# ISO 9660
# ---------------------------------------------------------------------------


def _iso_timestamp(b: bytes) -> str:
    try:
        dt = datetime(1900 + b[0], b[1], b[2], b[3], b[4], b[5])
    except ValueError:
        return ""
    tz = struct.unpack_from("<b", b, 6)[0] * 15
    return (
        dt.replace(tzinfo=timezone(timedelta(minutes=tz)))
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _list_iso(fh: BinaryIO, size: int) -> OpticalListing:
    pvd: bytes | None = None
    svd: bytes | None = None
    for n in range(_VRS_START, _VRS_END):
        fh.seek(n * SECTOR)
        d = fh.read(SECTOR)
        if d[1:6] != b"CD001":
            break
        if d[0] == 1 and pvd is None:
            pvd = d
        elif d[0] == 2 and b"%/" in d[88:91]:  # Joliet escape sequences %/@ %/C %/E
            svd = d
        elif d[0] == 255:
            break
    if pvd is None:
        raise OpticalError("ISO 9660 primary volume descriptor not found")
    joliet = svd is not None
    vd = svd if svd is not None else pvd
    label = (vd[40:72].decode("utf-16-be" if joliet else "latin-1", errors="replace")).strip(" \0")
    entries: list[OpticalEntry] = []

    def name_of(raw: bytes) -> str:
        n = raw.decode("utf-16-be" if joliet else "latin-1", errors="replace")
        return n.split(";")[0].rstrip(".")

    def walk(extent: int, length: int, prefix: str, seen: set[int]) -> None:
        if extent in seen or len(entries) >= _MAX_ENTRIES:
            return
        seen.add(extent)
        fh.seek(extent * SECTOR)
        data = fh.read(length)
        off = 0
        while off < len(data):
            rec_len = data[off]
            if rec_len == 0:  # records never span sectors; skip padding
                off = (off // SECTOR + 1) * SECTOR
                continue
            rec = data[off : off + rec_len]
            off += rec_len
            ext, ext_len, flags, l_fi = _u32(rec, 2), _u32(rec, 10), rec[25], rec[32]
            raw_name = rec[33 : 33 + l_fi]
            if raw_name in (b"\x00", b"\x01"):
                continue
            name = name_of(raw_name)
            is_dir = bool(flags & 2)
            path = f"{prefix}/{name}"
            ts = _iso_timestamp(rec[18:25])
            entries.append(
                OpticalEntry(
                    path=path,
                    is_dir=is_dir,
                    size=0 if is_dir else ext_len,
                    mtime=ts,
                    ctime=ts,
                    deleted=False,
                    generation=0,
                    extents=[] if is_dir else [(ext * SECTOR, ext_len)],
                    location=str(ext),
                )
            )
            if is_dir:
                walk(ext, ext_len, path, seen)

    root = vd[156:190]
    walk(_u32(root, 2), _u32(root, 10), "", set())
    return OpticalListing(
        fs_type="ISO 9660" + (" + Joliet" if joliet else ""),
        volume_label=label,
        sectors=size // SECTOR,
        generations=1,
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Public entry points (operate on a flat image file)
# ---------------------------------------------------------------------------


def list_optical(raw_path: Path) -> OpticalListing:
    """List every entry on the disc at *raw_path* (a flat image file)."""
    size = os.path.getsize(raw_path)
    with open(raw_path, "rb") as fh:
        fh.seek(_VRS_START * SECTOR)
        sig = signature_from_vrs(fh.read((_VRS_END - _VRS_START) * SECTOR))
        if sig == "udf":
            return _list_udf(fh, size)
        if sig == "iso9660":
            return _list_iso(fh, size)
    raise OpticalError("no UDF or ISO 9660 signature in sectors 16-31")


def extract_optical(raw_path: Path, entry: OpticalEntry, dest: Path) -> int:
    """Copy *entry*'s data from the disc at *raw_path* to *dest*; returns bytes written."""
    written = 0
    remaining = entry.size
    with open(raw_path, "rb") as fh, open(dest, "wb") as out:
        for off, length in entry.extents:
            fh.seek(off)
            chunk = fh.read(min(length, remaining))
            out.write(chunk)
            written += len(chunk)
            remaining -= len(chunk)
            if remaining <= 0:
                break
    return written
