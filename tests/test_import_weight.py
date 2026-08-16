"""``mulder.assets.paths`` is on every MCP tool's import path.

It is imported by ``attack``, ``yara``, ``chainsaw``, ``hayabusa``,
``zircolite``, ``documents``, ``phone`` and ``extract/misc``, all of which load
on every ``mulder serve`` start.  Dragging ``click``, ``rich``, ``httpx`` or the
asset manifest in behind it would put that cost on every server start for no
benefit.
"""

from __future__ import annotations

import subprocess
import sys

_HEAVY = ("click", "rich", "httpx", "mulder.assets.manifest", "mulder.assets.install")


def test_importing_the_resolver_pulls_in_nothing_heavy() -> None:
    """Run in a fresh interpreter: pytest itself has already imported all of them."""
    script = (
        "import sys, json; import mulder.assets.paths; "
        f"print(json.dumps([m for m in {_HEAVY!r} if m in sys.modules]))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )

    assert proc.stdout.strip() == "[]"


def test_the_cli_does_not_import_the_asset_machinery_at_module_scope() -> None:
    """``mulder serve`` must not pay for ``setup``'s dependencies."""
    script = (
        "import sys, json; import mulder.cli; "
        "print(json.dumps([m for m in "
        "('mulder.assets.install', 'mulder.assets.manifest', 'mulder.doctor.probes') "
        "if m in sys.modules]))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )

    assert proc.stdout.strip() == "[]"
