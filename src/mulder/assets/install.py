"""Planning and provisioning for ``mulder setup``.

Everything here is structured around one rule: **a partially written asset is
never visible where mulder would parse it.**  Downloads land in a staging
directory on the destination filesystem, are validated there, and are swapped
into place with ``os.replace``.  A truncated ``enterprise-attack.json`` would
otherwise break ``lookup_attack_technique`` on every call forever, because the
parse failure is never cached and so never self-heals.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import shutil
import tarfile
import zipfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mulder.assets.fetch import FetchError, FetchResult
from mulder.assets.manifest import (
    ANY_ARCH,
    ASSETS,
    Asset,
    detect_arch,
    volatility_cache_dir,
)
from mulder.assets.paths import asset_path, reset_asset_caches
from mulder.assets.state import AssetRecord, AssetState
from mulder.execution import safe_subprocess as subprocess

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows; mulder is Linux-first
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

STAGING_DIRNAME = ".mulder-staging"
LOCK_FILENAME = ".mulder-setup.lock"

#: A lock sentinel from a run that died without releasing it.
_STALE_LOCK_AGE = 6 * 60 * 60

#: ``(key, message)`` progress callback.
EventHook = Callable[[str, str], None]


class PlanError(Exception):
    """A fatal problem found before anything was fetched.

    Attributes:
        exit_code: The process exit code this maps to (SPEC §3.9).
    """

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class SetupOptions:
    """The flags ``mulder setup`` was invoked with."""

    verify: bool = False
    dry_run: bool = False


@dataclass
class Outcome:
    """What happened to one manifest row, selected or not."""

    key: str
    status: str
    selected: bool = False
    detail: str = ""
    size: int = 0
    shadowed_by: str = ""

    @property
    def failed(self) -> bool:
        return self.status.startswith("failed")

    @property
    def missing(self) -> bool:
        """True when ``--offline`` / ``--verify`` found nothing usable."""
        return self.status in ("missing", "invalid") or self.status.startswith("skipped (offline)")


@dataclass
class Plan:
    """A resolved, not-yet-executed provisioning plan."""

    write_root: Path
    bin_dir: Path
    arch: str
    selected: list[Asset] = field(default_factory=list)
    pulled_in: dict[str, str] = field(default_factory=dict)
    excluded: dict[str, str] = field(default_factory=dict)

    @property
    def total_bytes(self) -> int:
        return sum(a.size_estimate for a in self.selected)


@dataclass
class Result:
    """The outcome of a whole run, one row per manifest asset."""

    outcomes: list[Outcome] = field(default_factory=list)
    remedies: list[str] = field(default_factory=list)
    exit_code: int = 0


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


def build_plan(options: SetupOptions, write_root: Path, bin_dir: Path) -> Plan:
    """Resolve the full asset set to provision.

    ``setup`` installs everything mulder owns; there is no tier or subset to
    select, so the only thing that removes a row is having no artifact for this
    architecture.

    Raises:
        PlanError: On a missing digest (exit 1).
    """
    arch = detect_arch()
    plan = Plan(write_root=write_root, bin_dir=bin_dir, arch=arch)

    for asset in ASSETS:
        if asset.url_for(arch) is None:
            reason = f"skipped (arch: {'/'.join(asset.arch_only)} only)"
            if asset.substitute:
                reason += f" - {asset.substitute}"
            plan.excluded[asset.key] = reason
            continue
        plan.selected.append(asset)

    _require_digests(plan)
    return plan


def _require_digests(plan: Plan) -> None:
    """A pinnable row with no ``assets.lock`` entry is fatal, never a downgrade."""
    missing = [a.key for a in plan.selected if a.pinnable and not a.digests.get(plan.arch)]
    if missing:
        raise PlanError(
            f"No SHA-256 in assets.lock for: {', '.join(missing)} ({plan.arch}). "
            "Refusing to download a pinnable asset unverified - run 'make assets-lock'.",
            exit_code=1,
        )


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def preflight(plan: Plan, options: SetupOptions) -> None:
    """Every check that must happen before the first byte moves.

    Raises:
        PlanError: With the graded exit code for the failure found.
    """
    needs_git = any(a.kind == "git" or a.supplement_url for a in plan.selected)
    if needs_git and shutil.which("git") is None:
        raise PlanError(
            "git is required: "
            + ", ".join(a.key for a in plan.selected if a.kind == "git" or a.supplement_url)
            + " are git clones.\n"
            "  Install it with: sudo apt install git\n"
            "  signature-base cannot use a tarball instead - mulder keeps its .git so "
            "it can refresh the YARA rules with 'git pull --ff-only'.",
            exit_code=1,
        )

    if _geteuid() == 0:
        raise PlanError(
            "Refusing to run as root.\n"
            f"  As root the asset root resolves to {plan.write_root}, and the clones "
            "would be owned by root.\n"
            "  git then refuses to operate on them as your normal user "
            "('detected dubious ownership'), so YARA community-rule updates stop "
            "permanently and silently.\n"
            "  Run 'mulder setup' as the user who will run mulder.",
            exit_code=2,
        )

    if options.dry_run or options.verify:
        return

    _write_probe(plan.write_root)


def _write_probe(root: Path) -> None:
    """Actually create a file under *root*.

    ``os.access`` answers with the real uid and lies on read-only mounts, NFS
    root-squash and some ACL setups, so resolution's cheap test is not enough
    once a download is about to start.
    """
    probe = root / f".mulder-write-probe.{os.getpid()}"
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"\0")
    except OSError as exc:
        raise PlanError(
            f"Asset root {root} is not writable: {exc}\n"
            "  mulder picks the asset root in this order:\n"
            "    1. $MULDER_ASSET_ROOT, if set (wins outright)\n"
            "    2. /opt, if it exists and is writable\n"
            "    3. ~/.local/share/mulder/assets\n"
            "  Point it somewhere you can write with: "
            "export MULDER_ASSET_ROOT=~/.local/share/mulder/assets",
            exit_code=1,
        ) from exc
    finally:
        probe.unlink(missing_ok=True)


def _geteuid() -> int:
    """``os.geteuid`` where it exists, else a non-root sentinel."""
    getter = getattr(os, "geteuid", None)
    return getter() if getter is not None else 1000


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------


def _safe_target(root: Path, member_name: str, strip: int) -> Path | None:
    """Resolve an archive member under *root*, or None when it escapes.

    Python's ``tarfile`` extraction filters differ across 3.10-3.13, so the
    containment check is done here rather than delegated to ``filter="data"``.
    """
    parts = [p for p in Path(member_name).parts if p not in ("", ".")]
    if strip:
        parts = parts[strip:]
    if not parts:
        return None
    if any(p == ".." for p in parts) or Path(member_name).is_absolute():
        return None
    target = root.joinpath(*parts)
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return target


def extract_archive(archive: Path, dest: Path, strip: int = 0) -> None:
    """Extract *archive* into *dest*, rejecting any member that escapes it."""
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            bad = zf.testzip()
            if bad is not None:
                raise FetchError(f"corrupt zip member: {bad}")
            for info in zf.infolist():
                target = _safe_target(dest, info.filename, strip)
                if target is None:
                    if info.filename.endswith("/"):
                        continue
                    raise FetchError(f"archive member escapes destination: {info.filename}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out)
                if info.external_attr >> 16 & 0o111:
                    target.chmod(target.stat().st_mode | 0o111)
        return

    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            if member.issym() or member.islnk():
                # A link can point outside the tree even when its own name is
                # clean, and nothing mulder fetches needs one.
                continue
            target = _safe_target(dest, member.name, strip)
            if target is None:
                if member.isdir():
                    continue
                raise FetchError(f"archive member escapes destination: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            with extracted, target.open("wb") as out:
                shutil.copyfileobj(extracted, out)
            if member.mode & 0o111:
                target.chmod(target.stat().st_mode | 0o111)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_tree(asset: Asset, root: Path) -> None:
    """Shape-check a published (or about-to-be-published) tree.

    Nine of the fifteen manifest rows cannot be digest-pinned, so this is the
    only integrity signal they have beyond TLS.

    Raises:
        FetchError: When the tree is not what the asset is supposed to be.
    """
    if asset.validate == "stix-json":
        target = root / asset.filename if asset.filename else root
        doc = json.loads(target.read_text(encoding="utf-8"))
        if "objects" not in doc:
            raise FetchError(f"{target.name}: no 'objects' key; not a STIX bundle")
        return
    if asset.validate == "sigma-tree":
        if next(root.rglob("*.yml"), None) is None:
            raise FetchError("Sigma tree contains no .yml rules")
        return
    if asset.validate == "git":
        if not (root / ".git").is_dir():
            raise FetchError("clone has no .git directory")
        return
    if asset.validate == "archive" and asset.kind == "file":
        target = root / asset.filename if asset.filename else root
        if target.suffix == ".zip":
            # BadZipFile is not an OSError, so letting it escape crashes
            # `setup --verify` with a traceback instead of reporting the row
            # as invalid -- which is precisely what a corrupt symbol pack does.
            try:
                with zipfile.ZipFile(target) as zf:
                    if zf.testzip() is not None:
                        raise FetchError(f"{target.name}: corrupt zip")
            except zipfile.BadZipFile as exc:
                raise FetchError(f"{target.name}: not a zip file ({exc})") from exc


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------


def _publish_dir(staged: Path, dest: Path) -> None:
    """Swap *staged* into *dest*, keeping the old copy until the swap lands."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    old = dest.with_name(dest.name + ".old")
    if old.exists():
        shutil.rmtree(old, ignore_errors=True)
    if dest.exists():
        os.replace(dest, old)
    os.replace(staged, dest)
    if old.exists():
        shutil.rmtree(old, ignore_errors=True)


class _suppress_oserror:
    """``contextlib.suppress(OSError)`` without the import."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: type[BaseException] | None, *_rest: object) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


def sweep_staging(root: Path) -> None:
    """Remove staging directories and swap leftovers from a killed run."""
    staging = root / STAGING_DIRNAME
    if staging.is_dir():
        shutil.rmtree(staging, ignore_errors=True)
    for orphan in list(root.glob("*.new")) + list(root.glob("*.old")):
        shutil.rmtree(orphan, ignore_errors=True) if orphan.is_dir() else orphan.unlink(
            missing_ok=True
        )


def provision(
    plan: Plan,
    options: SetupOptions,
    *,
    fetch: Callable[..., FetchResult],
    on_event: EventHook | None = None,
) -> Result:
    """Execute *plan*, returning one outcome per manifest row.

    Args:
        plan: The resolved plan from :func:`build_plan`.
        options: The flags the run was invoked with.
        fetch: The downloader.  Injected so tests never open a socket.
        on_event: Optional ``(asset key, message)`` progress callback.

    Returns:
        A :class:`Result` whose ``outcomes`` cover *every* manifest asset,
        selected or not -- a silent partial install is structurally impossible
        because nothing is ever omitted from the report.
    """
    emit: EventHook = on_event or (lambda _key, _msg: None)
    state = AssetState.load(plan.write_root)
    outcomes: dict[str, Outcome] = {
        key: Outcome(key=key, status=reason) for key, reason in plan.excluded.items()
    }

    if options.dry_run:
        for asset in plan.selected:
            outcomes[asset.key] = Outcome(
                key=asset.key,
                status="would install",
                selected=True,
                size=asset.size_estimate,
                detail=_pulled_in_detail(plan, asset.key),
            )
        return Result(outcomes=_ordered(outcomes), exit_code=0)

    if not options.verify:
        sweep_staging(plan.write_root)

    staging = plan.write_root / STAGING_DIRNAME

    for asset in plan.selected:
        outcomes[asset.key] = _provision_one(asset, plan, options, state, staging, fetch, emit)

    if not options.verify:
        state.mulder_version = _mulder_version()
        state.root = str(plan.write_root)
        state.euid = _geteuid()
        state.owner_uid = _geteuid()
        state.save(plan.write_root)
        shutil.rmtree(staging, ignore_errors=True)
        reset_asset_caches()

    result = Result(outcomes=_ordered(outcomes))
    result.exit_code = _exit_code(result.outcomes, options)
    result.remedies = _remedies(result.outcomes)
    return result


def _ordered(outcomes: dict[str, Outcome]) -> list[Outcome]:
    """Manifest order, so the summary reads the same way every run."""
    return [outcomes[a.key] for a in ASSETS if a.key in outcomes]


def _pulled_in_detail(plan: Plan, key: str) -> str:
    origin = plan.pulled_in.get(key)
    return f"pulled in by --only {origin}" if origin else ""


def _provision_one(
    asset: Asset,
    plan: Plan,
    options: SetupOptions,
    state: AssetState,
    staging: Path,
    fetch: Callable[..., FetchResult],
    emit: EventHook,
) -> Outcome:
    """Provision (or verify) a single asset."""
    dest = _dest_for(asset, plan.write_root)
    detail = _pulled_in_detail(plan, asset.key)
    record = state.assets.get(asset.key)

    if asset.key == "eztools":
        return _provision_eztools(asset, plan, options, state, staging, fetch, emit)

    installed = (dest / Path(*asset.sentinel)).exists() if asset.sentinel else dest.exists()
    current = installed and record is not None and record.version == asset.version

    if options.verify:
        return _verify_one(asset, plan, dest, installed, current, record, detail)

    if current:
        return _shadow_check(
            asset, plan, Outcome(asset.key, "up-to-date", selected=True, detail=detail)
        )

    status = "stale -> updated" if installed and not current else "installed"
    try:
        emit(asset.key, f"{asset.key} {asset.version}: fetching")
        fetched = _fetch_asset(asset, plan, staging, fetch)
        _publish(asset, fetched, dest)
    except (FetchError, OSError, subprocess.SubprocessError, ValueError) as exc:
        logger.debug("Provisioning %s failed", asset.key, exc_info=True)
        return Outcome(asset.key, f"failed ({exc})", selected=True, detail=detail)

    _install_shims(asset, dest, plan.bin_dir, emit)
    state.assets[asset.key] = AssetRecord(
        version=asset.version,
        url=asset.url_for(plan.arch) or "",
        sha256=asset.digests.get(plan.arch),
        commit=fetched.commit,
        arch=plan.arch if asset.arch_only or len(asset.urls) > 1 else ANY_ARCH,
        dest=str(dest),
        bytes=fetched.size,
        fetched_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        status="installed",
        shims=list(asset.shims),
    )
    if fetched.note:
        detail = f"{detail}; {fetched.note}" if detail else fetched.note
    outcome = Outcome(asset.key, status, selected=True, detail=detail, size=fetched.size)
    return _shadow_check(asset, plan, outcome)


def _verify_one(
    asset: Asset,
    plan: Plan,
    dest: Path,
    installed: bool,
    current: bool,
    record: AssetRecord | None,
    detail: str,
) -> Outcome:
    """Validate what is present without fetching anything.

    Presence is decided by the path reads actually resolve to, not by the write
    root alone.  A SIFT box with a hand-made ``/opt`` clone and no ``mulder
    setup`` run is fully functional; calling that "missing" is a false alarm
    that sends the user looking for a problem that is not there.
    """
    if not installed:
        elsewhere = (
            asset_path(*asset.dest, *asset.sentinel)
            if asset.sentinel and not asset.cache_dest
            else None
        )
        if elsewhere is None:
            return Outcome(asset.key, "missing", selected=True, detail=detail)
        try:
            validate_tree(asset, elsewhere.parent)
        except (FetchError, OSError, ValueError) as exc:
            return Outcome(asset.key, "invalid", selected=True, detail=str(exc))
        note = f"provided by {elsewhere.parent}"
        return Outcome(
            asset.key,
            "up-to-date (unmanaged)",
            selected=True,
            detail=f"{detail}; {note}" if detail else note,
        )
    try:
        validate_tree(asset, dest)
    except (FetchError, OSError, ValueError) as exc:
        return Outcome(asset.key, "invalid", selected=True, detail=str(exc))
    if current:
        status = "up-to-date"
    elif record is None:
        # Present and structurally valid, but mulder never installed it, so
        # there is no recorded version to compare against.  Calling that
        # "stale" asserts it is out of date on no evidence -- and it is the
        # normal case for the container, whose /opt is provisioned by the
        # Dockerfile at these exact versions, and for a hand-made /opt on SIFT.
        status = "up-to-date (unmanaged)"
    else:
        status = "stale"
    return _shadow_check(asset, plan, Outcome(asset.key, status, selected=True, detail=detail))


def _shadow_check(asset: Asset, plan: Plan, outcome: Outcome) -> Outcome:
    """Flag an asset that mulder reads from somewhere other than the write root.

    A user who followed the old guide has hand-made ATT&CK data under ``/opt``,
    which is the first read root -- so ``setup`` can install a perfect copy into
    ``~/.local/share`` and every read still resolves to the stale one.  The
    shape validation deliberately runs against the *resolved* path so a
    truncated ``/opt`` copy is detected rather than masked.
    """
    if asset.cache_dest or not asset.sentinel:
        return outcome
    effective = asset_path(*asset.dest, *asset.sentinel)
    mine = plan.write_root.joinpath(*asset.dest, *asset.sentinel)
    if effective is None or effective == mine:
        return outcome
    outcome.shadowed_by = str(effective.parent)
    try:
        validate_tree(asset, effective.parent)
    except (FetchError, OSError, ValueError) as exc:
        outcome.detail = f"the shadowing copy is also invalid: {exc}"
    return outcome


# ---------------------------------------------------------------------------
# Per-kind fetching
# ---------------------------------------------------------------------------


@dataclass
class _Fetched:
    """A validated tree or file in staging, ready to be published."""

    staged: Path
    size: int = 0
    commit: str | None = None
    #: A degradation worth reporting even though the install itself succeeded.
    note: str = ""


def _dest_for(asset: Asset, write_root: Path) -> Path:
    """Where *asset* is published.

    ``vol-symbols-*`` deliberately bypass the asset root: volatility3 computes
    its cache path from ``XDG_CACHE_HOME``/``$HOME`` and mulder never passes
    ``-s``, so re-rooting the packs would orphan them from the ``vol`` on PATH.
    """
    if asset.cache_dest == "vol-symbols":
        return volatility_cache_dir()
    return write_root.joinpath(*asset.dest)


def _fetch_asset(
    asset: Asset, plan: Plan, staging: Path, fetch: Callable[..., FetchResult]
) -> _Fetched:
    """Download and validate *asset* into a staging directory."""
    work = staging / f"{asset.key}.{os.getpid()}"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    url = asset.url_for(plan.arch)
    if url is None:  # pragma: no cover - build_plan filters these out
        raise FetchError(f"no URL for arch {plan.arch}")

    if asset.kind == "git":
        return _fetch_git(asset, url, work)

    staged = work / "tree"
    staged.mkdir()

    if asset.kind == "file":
        total = 0
        for name, file_url in ((asset.filename, url), *asset.siblings):
            result = fetch(file_url, staged / name)
            _check_digest(asset, plan.arch, result, primary=file_url == url)
            total += result.bytes_written
        validate_tree(asset, staged)
        return _Fetched(staged=staged, size=total)

    archive = work / "download"
    result = fetch(url, archive)
    _check_digest(asset, plan.arch, result, primary=True)
    extract_archive(archive, staged, asset.strip_components)
    archive.unlink(missing_ok=True)
    _post_process(asset, staged)
    validate_tree(asset, staged)
    if asset.supplement_url:
        _add_supplement(asset, staged, work)
    return _Fetched(staged=staged, size=result.bytes_written)


def _check_digest(asset: Asset, arch: str, result: FetchResult, *, primary: bool) -> None:
    """Compare a download against ``assets.lock``.

    Only the primary URL of a pinnable row is locked; the siblings (ICS ATT&CK)
    belong to unpinnable rows by construction.
    """
    if not (asset.pinnable and primary):
        return
    expected = asset.digests.get(arch)
    if expected and result.sha256 != expected:
        raise FetchError(
            f"checksum mismatch: expected {expected[:16]}…, got {result.sha256[:16]}…"
        )


def _post_process(asset: Asset, staged: Path) -> None:
    """Apply chmod/symlink post-processing to a staged tree."""
    for name in asset.chmod_x:
        target = staged / name
        if target.exists():
            target.chmod(target.stat().st_mode | 0o111)
    for link_name, target_name in asset.symlinks:
        link = staged / link_name
        link.unlink(missing_ok=True)
        link.symlink_to(target_name)


def _fetch_git(asset: Asset, url: str, work: Path) -> _Fetched:
    """Clone *asset* into staging and record the resolved commit."""
    staged = work / "tree"
    cmd = ["git", "clone", "--depth", "1"]
    if asset.git_ref:
        cmd += ["--branch", asset.git_ref]
    cmd += [url, str(staged)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
    if proc.returncode != 0:
        raise FetchError(f"git clone failed: {(proc.stderr or '').strip()[:200]}")
    commit = subprocess.run(
        ["git", "-C", str(staged), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if commit.returncode != 0:
        raise FetchError("git rev-parse HEAD failed on the fresh clone")
    _post_process(asset, staged)
    validate_tree(asset, staged)
    note = _seed_zircolite_rules(staged) if asset.key == "zircolite" else ""
    return _Fetched(
        staged=staged,
        size=asset.size_estimate,
        commit=commit.stdout.strip(),
        note=note,
    )


def _seed_zircolite_rules(staged: Path) -> str:
    """Copy the Linux Sigma rules in beside Zircolite.

    Upstream ships none, and ``run_zircolite`` detects nothing at all with an
    empty ``rules/linux`` -- the Dockerfile does the same copy at build time.

    Returns:
        A degradation note when the rules could not be seeded, else "".  An
        empty ``rules/linux`` is silent at analysis time, so the one chance to
        tell the user is this run's summary.
    """
    source = asset_path("sigma-rules", "rules", "linux")
    target = staged / "rules" / "linux"
    target.mkdir(parents=True, exist_ok=True)
    if source is None or not source.is_dir():
        return "linux rules skipped - sigma-rules is not installed"
    for entry in source.iterdir():
        destination = target / entry.name
        if entry.is_dir():
            shutil.copytree(entry, destination, dirs_exist_ok=True)
        else:
            shutil.copyfile(entry, destination)
    return ""


def _add_supplement(asset: Asset, staged: Path, work: Path) -> None:
    """Copy extra directories from a source clone into a release tree.

    Chainsaw's release tarball carries the binary only; its ``mappings/`` and
    ``rules/`` live in the tagged source tree, which is why the Dockerfile
    clones the tag as well.
    """
    clone = work / "supplement"
    proc = subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            f"v{asset.version}",
            asset.supplement_url,
            str(clone),
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if proc.returncode != 0:
        raise FetchError(f"git clone (mappings/rules) failed: {(proc.stderr or '').strip()[:200]}")
    for name in asset.supplement_paths:
        source = clone / name
        if source.is_dir():
            shutil.copytree(source, staged / name, dirs_exist_ok=True)
    shutil.rmtree(clone, ignore_errors=True)


def _publish(asset: Asset, fetched: _Fetched, dest: Path) -> None:
    """Move a staged tree into place.

    ``vol-symbols-*`` publish per file rather than per directory: the cache is
    shared with whatever else volatility3 has downloaded and must not be
    replaced wholesale.
    """
    if asset.cache_dest == "vol-symbols":
        dest.mkdir(parents=True, exist_ok=True)
        for entry in fetched.staged.iterdir():
            _replace_across_devices(entry, dest / entry.name)
        shutil.rmtree(fetched.staged, ignore_errors=True)
        return
    _publish_dir(fetched.staged, dest)


def _replace_across_devices(source: Path, dest: Path) -> None:
    """``os.replace`` that survives a staging area on another filesystem.

    Symbol packs stage under the write root but publish into the Volatility
    cache under ``$HOME``.  With a writable ``/opt`` write root and ``/home`` on
    its own partition -- a very common SIFT/Ubuntu layout -- those are different
    devices and ``os.replace`` raises ``EXDEV`` after an 840 MB download.
    """
    try:
        os.replace(source, dest)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        shutil.move(str(source), str(dest))


def _install_shims(asset: Asset, dest: Path, bin_dir: Path, emit: EventHook) -> None:
    """Link an asset's executables into ``bin_dir()`` and check reachability."""
    if not asset.shims:
        return
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in asset.shims:
        target = dest / name
        link = bin_dir / name
        if not target.exists():
            continue
        link.unlink(missing_ok=True)
        link.symlink_to(target)
        if shutil.which(name) is None:
            emit(
                asset.key,
                f"warning: {link} is not on $PATH, so '{name}' stays invisible to mulder "
                f'-- add it with: export PATH="{bin_dir}:$PATH"',
            )


# ---------------------------------------------------------------------------
# EZ Tools
# ---------------------------------------------------------------------------


def ez_dll_installed(dll_name: str) -> Path | None:
    """Find an EZ Tools DLL across every read root.

    Deliberately not ``mulder.server.tools.extract.misc._find_ez_tool``:
    importing that module builds the whole MCP server, which ``mulder setup``
    has no use for.  Only presence matters here -- framework ranking is the
    tool call's problem.
    """
    from mulder.assets.paths import asset_candidates

    for root in asset_candidates("zimmermantools"):
        if not root.is_dir():
            continue
        hit = next(iter(sorted(root.rglob(dll_name))), None)
        if hit is not None:
            return hit
    return None


def _provision_eztools(
    asset: Asset,
    plan: Plan,
    options: SetupOptions,
    state: AssetState,
    staging: Path,
    fetch: Callable[..., FetchResult],
    emit: EventHook,
) -> Outcome:
    """Fetch only the EZ Tools DLLs that resolve nowhere.

    On SIFT that is normally ``PECmd`` alone: SIFT ships the rest, its copies
    are version-matched to its own ``dotnet``, and shadowing them with mulder's
    ``net9`` downloads is a regression rather than an upgrade.  ``--force`` does
    not override that, and a root already holding an unmanaged copy is left
    entirely alone.
    """
    dest = _dest_for(asset, plan.write_root)
    record = state.assets.get(asset.key)

    if options.verify:
        missing = [m for m in asset.members if ez_dll_installed(f"{m}.dll") is None]
        if missing:
            return Outcome(asset.key, "missing", selected=True, detail=", ".join(missing))
        return Outcome(asset.key, "up-to-date", selected=True)

    if dest.exists() and record is None:
        return Outcome(
            asset.key,
            f"skipped (unmanaged copy at {dest})",
            selected=True,
        )

    wanted: list[str] = []
    provided: list[str] = []
    for member in asset.members:
        hit = ez_dll_installed(f"{member}.dll")
        if hit is None:
            wanted.append(member)
        else:
            provided.append(f"{member} ({hit.parent})")

    if not wanted:
        return Outcome(
            asset.key,
            "up-to-date",
            selected=True,
            detail=f"provided by the platform: {', '.join(provided)}" if provided else "",
        )

    work = staging / f"{asset.key}.{os.getpid()}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    staged = work / "tree"
    staged.mkdir()
    if dest.is_dir():
        # Additive: the row installs individual DLLs, so an existing managed
        # copy of the other five must survive the swap.
        shutil.copytree(dest, staged, dirs_exist_ok=True)

    base = asset.url_for(plan.arch) or ""
    total = 0
    try:
        for member in wanted:
            emit(asset.key, f"eztools: fetching {member}")
            archive = work / f"{member}.zip"
            result = fetch(f"{base}/{member}.zip", archive)
            extract_archive(archive, staged)
            archive.unlink(missing_ok=True)
            total += result.bytes_written
        _publish_dir(staged, dest)
    except (FetchError, OSError) as exc:
        return Outcome(asset.key, f"failed ({exc})", selected=True)

    state.assets[asset.key] = AssetRecord(
        version=asset.version,
        url=base,
        arch=ANY_ARCH,
        dest=str(dest),
        bytes=total,
        fetched_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        status="installed",
    )
    detail = f"fetched {', '.join(wanted)}"
    if provided:
        detail += f"; skipped (provided by the platform): {', '.join(provided)}"
    return Outcome(asset.key, "installed", selected=True, detail=detail, size=total)


def _under(path: Path, root: Path) -> bool:
    """True when *path* sits inside *root*."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------


def _exit_code(outcomes: Sequence[Outcome], options: SetupOptions) -> int:
    """Grade a finished run (SPEC §3.9)."""
    if any(o.failed for o in outcomes):
        return 3
    if options.verify:
        if any(o.missing or o.status == "invalid" for o in outcomes):
            return 4
        if any(o.shadowed_by for o in outcomes):
            return 4
    return 0


def _remedies(outcomes: Iterable[Outcome]) -> list[str]:
    """The one-off remediation text a run has earned."""
    out: list[str] = []
    if any(o.shadowed_by for o in outcomes):
        out.append(
            "Some assets are shadowed: mulder reads an older copy from a "
            "higher-priority root. Either delete that copy, or run "
            "'sudo mulder setup --system' to refresh it in place, or pin the "
            "resolver with 'export MULDER_ASSET_ROOT=<write root>' (which "
            "disables the /opt search entirely)."
        )
    return out


def capability_gaps(outcomes: Iterable[Outcome]) -> list[str]:
    """Translate missing assets into the MCP tools they disable."""
    by_key = {o.key: o for o in outcomes}
    gaps: list[str] = []

    def absent(key: str) -> bool:
        outcome = by_key.get(key)
        return outcome is None or outcome.status.startswith(("skipped", "failed", "missing"))

    if absent("signature-base"):
        gaps.append("signature-base missing -> run_yara returns 'No YARA rules available'")
    if absent("attack"):
        gaps.append("attack missing -> lookup_attack_technique fails")
    if absent("eztools"):
        gaps.append(
            "zimmermantools missing -> run_prefetch_parser / run_amcache_parser / "
            "run_shimcache_parser / run_mft_parser / run_evtx_parser / run_registry_parser "
            "unavailable"
        )
    if absent("sigma-rules"):
        gaps.append("sigma-rules missing -> run_chainsaw hunt mode has no rules to apply")
    if shutil.which("dotnet") is None and not absent("eztools"):
        gaps.append("dotnet missing -> EZ Tools are present but unusable")
    return gaps


def _mulder_version() -> str:
    from mulder import __version__

    return __version__
