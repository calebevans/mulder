"""The inert description of everything ``mulder setup`` may provision.

Every version here is pinned to the literal the Dockerfile uses, so a native
install and the container image resolve the same tool at the same version;
``tests/test_manifest_parity.py`` fails the build if the two drift apart.

Nothing in this module opens a socket or touches the filesystem at import
beyond the single ``assets.lock`` package-data read.
"""

from __future__ import annotations

import json
import os
import platform
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

Kind = Literal["file", "archive", "git", "eztools"]
Validation = Literal["archive", "stix-json", "sigma-tree", "git", "none"]


ANY_ARCH = "any"


@dataclass(frozen=True)
class Asset:
    """One provisionable artifact.

    Attributes:
        key: Stable name used by ``--only`` / ``--skip`` and by the state file.
        version: Pinned upstream version, or a branch/"HEAD" marker.
        kind: How it is fetched and published.
        urls: Architecture -> URL. ``ANY_ARCH`` for arch-independent rows.
        dest: Destination directory, relative to the asset root.
        sentinel: Path relative to *dest* whose presence means "installed".
        pinnable: True when ``assets.lock`` MUST carry a SHA-256 for it.
        size_estimate: Space the asset occupies on disk once installed, in
            bytes, measured against upstream on 2026-08-16 (release assets by
            Content-Length, clones by ``du`` of a ``--depth 1`` working tree).
            For clones this deliberately exceeds the bytes transferred -- a
            shallow iLEAPP clone is ~830 MB on disk against a ~225 MB
            download -- because disk is what runs out.  Drives ``--dry-run``
            and the first-pass total only; a live run refines the file and
            archive rows from Content-Length.
        filename: For ``kind="file"``, the basename written under *dest*.
        siblings: Further ``(basename, url)`` files written into the same dest.
        strip_components: Leading archive path components to drop.
        chmod_x: Files under *dest* to mark executable after extraction.
        symlinks: ``(link_name, target_name)`` pairs created under *dest*.
        shims: Basenames under *dest* to link into ``bin_dir()``.
        requires: HARD dependencies; ``--only`` pulls these in transitively.
        arch_only: Non-empty restricts the row to those architectures.
        substitute: What to do instead on an unsupported architecture.
        git_ref: For ``kind="git"``, the tag or branch to clone.
        supplement_url: A second git repo whose *supplement_paths* are copied
            into *dest* after the primary artifact lands (Chainsaw's mappings
            and rules, which upstream ships only in the source tree).
        validate: Shape check applied before publishing.
        cache_dest: Non-empty routes the row outside the asset root; only
            ``"vol-symbols"`` exists, for the reason in ``volatility_cache_dir``.
        members: For ``kind="eztools"``, the DLL basenames mulder invokes.
        note: Extra text for the ``--list`` table.
    """

    key: str
    version: str
    kind: Kind
    urls: Mapping[str, str]
    dest: tuple[str, ...]
    sentinel: tuple[str, ...]
    pinnable: bool
    size_estimate: int
    filename: str = ""
    siblings: tuple[tuple[str, str], ...] = ()
    strip_components: int = 0
    chmod_x: tuple[str, ...] = ()
    symlinks: tuple[tuple[str, str], ...] = ()
    shims: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    arch_only: tuple[str, ...] = ()
    substitute: str = ""
    git_ref: str = ""
    supplement_url: str = ""
    supplement_paths: tuple[str, ...] = ()
    validate: Validation = "archive"
    cache_dest: str = ""
    members: tuple[str, ...] = ()
    note: str = ""
    #: Populated from ``assets.lock`` at import; never edited by hand.
    digests: Mapping[str, str] = field(default_factory=dict)

    def url_for(self, arch: str) -> str | None:
        """The download URL for *arch*, or None when upstream ships none."""
        if self.arch_only and arch not in self.arch_only:
            return None
        return self.urls.get(arch) or self.urls.get(ANY_ARCH)


_MB = 1024 * 1024

_RAW_ATTACK = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
_GH = "https://github.com"

#: Pinned versions, each matching a Dockerfile ``ARG``/literal.
CHAINSAW_VERSION = "2.16.0"
HAYABUSA_VERSION = "3.8.1"
CAPA_VERSION = "9.4.0"
FLOSS_VERSION = "3.1.0"
ZIRCOLITE_VERSION = "2.20.0"
SIGMA_VERSION = "r2024-09-02"

_ASSETS: tuple[Asset, ...] = (
    Asset(
        key="attack",
        version="master",
        kind="file",
        urls={ANY_ARCH: f"{_RAW_ATTACK}/enterprise-attack/enterprise-attack.json"},
        filename="enterprise-attack.json",
        siblings=(("ics-attack.json", f"{_RAW_ATTACK}/ics-attack/ics-attack.json"),),
        dest=("attack",),
        sentinel=("enterprise-attack.json",),
        pinnable=False,
        size_estimate=58 * _MB,
        validate="stix-json",
        note="MITRE ATT&CK Enterprise + ICS STIX bundles (tracks master)",
    ),
    Asset(
        key="sigma-rules",
        version=SIGMA_VERSION,
        kind="archive",
        urls={ANY_ARCH: f"{_GH}/SigmaHQ/sigma/archive/refs/tags/{SIGMA_VERSION}.tar.gz"},
        dest=("sigma-rules",),
        sentinel=("rules",),
        # GitHub regenerates tag tarballs, so their gzip bytes are not stable
        # even for a fixed tag; shape validation is the only honest check.
        pinnable=False,
        size_estimate=6 * _MB,
        strip_components=1,
        validate="sigma-tree",
        note="Sigma rules for Chainsaw",
    ),
    Asset(
        key="signature-base",
        version="HEAD",
        kind="git",
        urls={ANY_ARCH: f"{_GH}/Neo23x0/signature-base.git"},
        dest=("signature-base",),
        sentinel=("yara",),
        pinnable=False,
        size_estimate=12 * _MB,
        validate="git",
        note="YARA community rules; keeps its .git so mulder can pull updates",
    ),
    Asset(
        key="didier-stevens",
        version="HEAD",
        kind="git",
        urls={ANY_ARCH: f"{_GH}/DidierStevens/DidierStevensSuite.git"},
        dest=("didier-stevens",),
        sentinel=("pdfid.py",),
        pinnable=False,
        size_estimate=47 * _MB,
        chmod_x=("pdfid.py", "pdf-parser.py"),
        validate="git",
        note="pdfid.py / pdf-parser.py for analyze_pdf",
    ),
    Asset(
        key="chainsaw",
        version=CHAINSAW_VERSION,
        kind="archive",
        urls={
            "amd64": (
                f"{_GH}/WithSecureLabs/chainsaw/releases/download/v{CHAINSAW_VERSION}"
                "/chainsaw_x86_64-unknown-linux-gnu.tar.gz"
            ),
            "arm64": (
                f"{_GH}/WithSecureLabs/chainsaw/releases/download/v{CHAINSAW_VERSION}"
                "/chainsaw_aarch64-unknown-linux-gnu.tar.gz"
            ),
        },
        dest=("chainsaw",),
        sentinel=("chainsaw",),
        pinnable=True,
        size_estimate=96 * _MB,
        strip_components=1,
        chmod_x=("chainsaw",),
        shims=("chainsaw",),
        supplement_url=f"{_GH}/WithSecureLabs/chainsaw.git",
        supplement_paths=("mappings", "rules"),
        note="Sigma/EVTX hunting engine",
    ),
    Asset(
        key="hayabusa",
        version=HAYABUSA_VERSION,
        kind="archive",
        urls={
            "amd64": (
                f"{_GH}/Yamato-Security/hayabusa/releases/download/v{HAYABUSA_VERSION}"
                f"/hayabusa-{HAYABUSA_VERSION}-lin-x64-musl.zip"
            )
        },
        dest=("hayabusa",),
        sentinel=("hayabusa",),
        pinnable=True,
        size_estimate=45 * _MB,
        chmod_x=(f"hayabusa-{HAYABUSA_VERSION}-lin-x64-musl",),
        symlinks=(("hayabusa", f"hayabusa-{HAYABUSA_VERSION}-lin-x64-musl"),),
        shims=("hayabusa",),
        arch_only=("amd64",),
        substitute=(
            "upstream's aarch64-gnu build needs GLIBC >= 2.38; build from source "
            "per Dockerfile:135-146"
        ),
        note="Windows EVTX Sigma engine",
    ),
    Asset(
        key="zircolite",
        version=ZIRCOLITE_VERSION,
        kind="git",
        urls={ANY_ARCH: f"{_GH}/wagga40/Zircolite.git"},
        git_ref=ZIRCOLITE_VERSION,
        dest=("zircolite",),
        sentinel=("zircolite.py",),
        pinnable=False,
        size_estimate=75 * _MB,
        chmod_x=("zircolite.py",),
        # Zircolite ships no Linux Sigma rules of its own; without sigma-rules
        # run_zircolite dies on its first call because rules/linux is empty.
        requires=("sigma-rules",),
        validate="git",
        note="Linux Sigma detection (auditd / Sysmon-for-Linux)",
    ),
    Asset(
        key="capa",
        version=CAPA_VERSION,
        kind="archive",
        urls={
            "amd64": (
                f"{_GH}/mandiant/capa/releases/download/v{CAPA_VERSION}"
                f"/capa-v{CAPA_VERSION}-linux.zip"
            ),
            "arm64": (
                f"{_GH}/mandiant/capa/releases/download/v{CAPA_VERSION}"
                f"/capa-v{CAPA_VERSION}-linux-arm64.zip"
            ),
        },
        dest=("capa",),
        sentinel=("capa",),
        pinnable=True,
        size_estimate=48 * _MB,
        chmod_x=("capa",),
        shims=("capa",),
        note="capability detection for binaries",
    ),
    Asset(
        key="eztools",
        version="net9",
        kind="eztools",
        urls={ANY_ARCH: "https://download.ericzimmermanstools.com/net9"},
        dest=("zimmermantools",),
        sentinel=("PECmd.dll",),
        # The vendor URL carries no version at all, so there is nothing stable
        # to pin; it always serves the current build.
        pinnable=False,
        size_estimate=20 * _MB,
        members=(
            "PECmd",
            "AmcacheParser",
            "AppCompatCacheParser",
            "MFTECmd",
            "EvtxECmd",
            "RECmd",
        ),
        # SPEC §2.4 rule 3: --force means "re-fetch what mulder installed", not
        # "install on top of the platform's version-matched copies".
        note="the six EZ Tools DLLs mulder invokes (needs dotnet at runtime)",
    ),
    Asset(
        key="floss",
        version=FLOSS_VERSION,
        kind="archive",
        urls={
            "amd64": (
                f"{_GH}/mandiant/flare-floss/releases/download/v{FLOSS_VERSION}"
                f"/floss-v{FLOSS_VERSION}-linux.zip"
            )
        },
        dest=("floss",),
        sentinel=("floss",),
        pinnable=True,
        size_estimate=41 * _MB,
        chmod_x=("floss",),
        shims=("floss",),
        arch_only=("amd64",),
        substitute="pipx inject mulder-dfir flare-floss",
        note="obfuscated string extraction",
    ),
    Asset(
        key="aleapp",
        version="HEAD",
        kind="git",
        urls={ANY_ARCH: f"{_GH}/abrignoni/ALEAPP.git"},
        dest=("aleapp",),
        sentinel=("aleapp.py",),
        pinnable=False,
        size_estimate=24 * _MB,
        validate="git",
        note="Android logs/events parser; needs --inject-deps for its requirements",
    ),
    Asset(
        key="ileapp",
        version="HEAD",
        kind="git",
        urls={ANY_ARCH: f"{_GH}/abrignoni/iLEAPP.git"},
        dest=("ileapp",),
        sentinel=("ileapp.py",),
        pinnable=False,
        size_estimate=829 * _MB,
        validate="git",
        note="iOS logs/events parser; needs --inject-deps for its requirements",
    ),
    Asset(
        key="vol-symbols-linux",
        version="latest",
        kind="file",
        urls={
            ANY_ARCH: "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"
        },
        filename="linux.zip",
        dest=(),
        sentinel=("linux.zip",),
        pinnable=False,
        size_estimate=3 * _MB,
        cache_dest="vol-symbols",
        validate="archive",
        note="Volatility 3 Linux ISF packs (left zipped; volatility reads zips)",
    ),
    Asset(
        key="vol-symbols-windows",
        version="latest",
        kind="file",
        urls={
            ANY_ARCH: "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
        },
        filename="windows.zip",
        dest=(),
        sentinel=("windows.zip",),
        pinnable=False,
        size_estimate=840 * _MB,
        cache_dest="vol-symbols",
        validate="archive",
        note="Volatility 3 Windows ISF packs (the largest single asset)",
    ),
)


def _load_lock() -> dict[str, dict[str, object]]:
    """Read the checked-in digests.

    Kept as package data rather than a Python literal so ``make assets-lock``
    can rewrite it without touching source.
    """
    lock_file = Path(__file__).with_name("assets.lock")
    try:
        raw = json.loads(lock_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entries = raw.get("entries")
    return entries if isinstance(entries, dict) else {}


LOCK: Mapping[str, dict[str, object]] = _load_lock()


def _with_digests(asset: Asset) -> Asset:
    """Attach the locked SHA-256 for each architecture of *asset*."""
    if not asset.pinnable:
        return asset
    digests = {
        arch: str(entry["sha256"])
        for arch in asset.urls
        if (entry := LOCK.get(f"{asset.key}:{arch}")) and entry.get("sha256")
    }
    return replace(asset, digests=digests)


ASSETS: tuple[Asset, ...] = tuple(_with_digests(a) for a in _ASSETS)
ASSETS_BY_KEY: Mapping[str, Asset] = {a.key: a for a in ASSETS}


def detect_arch() -> str:
    """Map ``platform.machine()`` onto the Dockerfile's ``TARGETARCH`` values."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


def volatility_cache_dir() -> Path:
    """Where volatility3 itself looks for ISF symbol packs.

    Copied from ``volatility3.framework.constants`` rather than imported: that
    import has the side effect of creating the cache directory, and the *system*
    ``vol`` mulder prefers is a different install of the same package computing
    the same env-derived path.  ``MULDER_ASSET_ROOT`` deliberately does not
    affect this -- re-rooting the symbols would orphan them from the ``vol`` on
    ``$PATH``.
    """
    cache_home = os.environ.get("XDG_CACHE_HOME")
    base = Path(cache_home) if cache_home else Path.home() / ".cache"
    return base / "volatility3" / "symbols"


def expand_requires(keys: set[str]) -> set[str]:
    """Close *keys* transitively over ``Asset.requires``."""
    out = set(keys)
    pending = list(keys)
    while pending:
        current = ASSETS_BY_KEY.get(pending.pop())
        if current is None:
            continue
        for dep in current.requires:
            if dep not in out:
                out.add(dep)
                pending.append(dep)
    return out
