"""``.mulder-assets.json`` -- what ``mulder setup`` installed, and where.

The state file is what makes three otherwise-unanswerable questions decidable:
is this copy of an asset one mulder owns (SPEC §2.4 rule 3), is mulder reading
its own copy or somebody else's (§3.10), and which ``bin_dir()`` entries are
shims mulder wrote (§4.2).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_FILENAME = ".mulder-assets.json"
SCHEMA_VERSION = 1


@dataclass
class AssetRecord:
    """One installed asset, as recorded after a successful publish."""

    version: str
    url: str
    sha256: str | None = None
    commit: str | None = None
    arch: str = "any"
    dest: str = ""
    bytes: int = 0
    fetched_at: str = ""
    status: str = "installed"
    shims: list[str] = field(default_factory=list)


@dataclass
class AssetState:
    """The whole state document for one write root."""

    schema: int = SCHEMA_VERSION
    mulder_version: str = ""
    root: str = ""
    euid: int = 0
    owner_uid: int = 0
    assets: dict[str, AssetRecord] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path) -> AssetState:
        """Read the state file under *root*, or return an empty document."""
        path = root / STATE_FILENAME
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls(root=str(root))
        assets = {
            key: AssetRecord(
                **{k: v for k, v in value.items() if k in AssetRecord.__annotations__}
            )
            for key, value in (raw.get("assets") or {}).items()
            if isinstance(value, dict)
        }
        return cls(
            schema=int(raw.get("schema", SCHEMA_VERSION)),
            mulder_version=str(raw.get("mulder_version", "")),
            root=str(raw.get("root", root)),
            euid=int(raw.get("euid", 0)),
            owner_uid=int(raw.get("owner_uid", 0)),
            assets=assets,
        )

    def save(self, root: Path) -> None:
        """Write the state file atomically.

        Same stage-then-``os.replace`` dance as the assets themselves: a crash
        mid-write must not leave a half-parsed document that makes every
        installed asset look unmanaged.
        """
        path = root / STATE_FILENAME
        payload = {
            "schema": self.schema,
            "mulder_version": self.mulder_version,
            "root": str(root),
            "euid": self.euid,
            "owner_uid": self.owner_uid,
            "assets": {key: asdict(record) for key, record in sorted(self.assets.items())},
        }
        root.mkdir(parents=True, exist_ok=True)
        handle, tmp_name = tempfile.mkstemp(dir=str(root), prefix=".mulder-assets.", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                json.dump(payload, out, indent=2, sort_keys=False)
                out.write("\n")
            os.replace(tmp_name, path)
        except OSError:
            Path(tmp_name).unlink(missing_ok=True)
            raise

    def installed_shims(self) -> dict[str, str]:
        """Map shim basename -> the asset key that installed it."""
        return {name: key for key, record in self.assets.items() for name in record.shims}
