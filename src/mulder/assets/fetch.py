"""The injectable downloader used by ``mulder setup``.

``provision`` takes a ``Fetcher`` as a parameter so the test suite can hand it
a local one; nothing else in ``mulder.assets`` opens a socket.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

#: Read size for hashing and for streaming a body to disk.
_CHUNK = 1024 * 256


@dataclass(frozen=True)
class FetchResult:
    """Outcome of one download."""

    path: Path
    bytes_written: int
    sha256: str
    from_cache: bool = False


class FetchError(RuntimeError):
    """A download failed in a way that leaves nothing publishable."""


class OfflineFetcher:
    """A fetcher that refuses every request, for ``--offline`` / ``--verify``."""

    def head(self, url: str) -> int | None:
        """Report an unknown size; ``--offline`` never issues requests."""
        return None

    def __call__(self, url: str, dest: Path) -> FetchResult:
        raise FetchError("offline: refusing to download")


class HttpFetcher:
    """Streaming ``httpx`` downloader."""

    def __init__(self, *, timeout: float = 60.0, progress: ProgressHook | None = None) -> None:
        self._timeout = timeout
        self._progress = progress

    def head(self, url: str) -> int | None:
        """Content-Length for *url*, or None when the server will not say.

        ``Accept-Encoding: identity`` is required for the answer to be useful:
        ATT&CK's raw JSON is served gzipped, and its compressed Content-Length
        understates the real download by a factor of nine.  Used only to refine
        the plan total before the >1 GB confirmation, so a failure is not an
        error.
        """
        import httpx

        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                response = client.head(url, headers={"Accept-Encoding": "identity"})
                response.raise_for_status()
                if response.headers.get("content-encoding"):
                    return None
                length = response.headers.get("content-length")
                return int(length) if length else None
        except Exception:
            logger.debug("HEAD failed for %s", url, exc_info=True)
            return None

    def __call__(self, url: str, dest: Path) -> FetchResult:
        """Download *url* to *dest*, returning its size and digest.

        The body lands in ``<dest>.part`` and is renamed only once the whole
        response has been read, so a truncated file is never left where the
        caller would validate it.  An interrupted download is simply redone;
        mulder has no resume, because a half-file that is never trusted costs
        only bandwidth.
        """
        import httpx

        part = dest.with_name(dest.name + ".part")
        digest = hashlib.sha256()
        written = 0
        try:
            with (
                httpx.Client(timeout=self._timeout, follow_redirects=True) as client,
                client.stream("GET", url) as response,
            ):
                response.raise_for_status()
                total = _total_bytes(response)
                with part.open("wb") as out:
                    for chunk in response.iter_bytes(_CHUNK):
                        out.write(chunk)
                        digest.update(chunk)
                        written += len(chunk)
                        if self._progress is not None:
                            self._progress(written, total)
        except httpx.HTTPError as exc:
            raise FetchError(f"{type(exc).__name__}: {exc}") from exc

        part.replace(dest)
        return FetchResult(path=dest, bytes_written=written, sha256=digest.hexdigest())


#: ``(bytes_done, bytes_total_or_None) -> None``
ProgressHook = Callable[[int, "int | None"], None]

#: What ``provision`` calls to obtain bytes.  ``head`` is optional; duck-typed
#: so a test fake need only be callable.
Fetcher = Callable[..., FetchResult]


def _total_bytes(response: object) -> int | None:
    """Total size of the response body, when the server declares one."""
    headers = getattr(response, "headers", {})
    length = headers.get("content-length")
    if not length:
        return None
    try:
        return int(length)
    except ValueError:
        return None


def sha256_file(path: Path) -> str:
    """SHA-256 of *path*, streamed."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_fetcher(source_dir: Path) -> Fetcher:
    """A ``Fetcher`` that copies from *source_dir* instead of downloading.

    Used by the test suite: the fixture directory is keyed by URL basename.
    """

    def _fetch(url: str, dest: Path) -> FetchResult:
        src = source_dir / url.rsplit("/", 1)[-1]
        if not src.exists():
            raise FetchError(f"404 (fixture missing): {url}")
        shutil.copyfile(src, dest)
        return FetchResult(path=dest, bytes_written=dest.stat().st_size, sha256=sha256_file(dest))

    return _fetch
