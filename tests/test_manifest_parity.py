"""The manifest and the Dockerfile must pin the same versions.

A native install that resolves a different Chainsaw than the image is a support
nightmare, and the drift is invisible without a check: nothing else reads both
files.  This is what makes the "bump the Dockerfile, bump manifest.py, re-run
``make assets-lock``" chore enforceable rather than aspirational.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mulder.assets.manifest import ASSETS, ASSETS_BY_KEY

_DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"

#: ``asset key -> the Dockerfile ARG that pins it``.
_ARGS = {
    "chainsaw": "CHAINSAW_VERSION",
    "hayabusa": "HAYABUSA_VERSION",
    "capa": "CAPA_VERSION",
    "floss": "FLOSS_VERSION",
    "sigma-rules": "SIGMA_VERSION",
}


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return _DOCKERFILE.read_text(encoding="utf-8")


@pytest.mark.parametrize(("key", "arg"), sorted(_ARGS.items()))
def test_pinned_version_matches_the_dockerfile_arg(key: str, arg: str, dockerfile: str) -> None:
    match = re.search(rf"^ARG {arg}=(\S+)$", dockerfile, re.MULTILINE)

    assert match is not None, f"Dockerfile no longer declares ARG {arg}"
    assert ASSETS_BY_KEY[key].version == match.group(1)


def test_zircolite_tag_matches_the_dockerfile_clone(dockerfile: str) -> None:
    """Zircolite is pinned inline rather than through an ARG."""
    match = re.search(
        r"git clone --depth 1 --branch (\S+) \\\n\s+https://github.com/wagga40/Zircolite",
        dockerfile,
    )

    assert match is not None
    assert ASSETS_BY_KEY["zircolite"].version == match.group(1)


def test_every_manifest_url_host_appears_in_the_dockerfile(dockerfile: str) -> None:
    """The manifest must not invent a source the image does not use."""
    unknown = []
    for asset in ASSETS:
        for url in asset.urls.values():
            host = url.split("/")[2]
            if host not in dockerfile:
                unknown.append(f"{asset.key}: {host}")

    assert unknown == []


def test_the_eztools_member_list_is_a_subset_of_the_dockerfile_s(dockerfile: str) -> None:
    """mulder invokes six of the eleven DLLs the image unzips."""
    match = re.search(r"for tool in ([\w ]+); do", dockerfile)

    assert match is not None
    assert set(ASSETS_BY_KEY["eztools"].members) <= set(match.group(1).split())


def test_every_asset_key_is_unique_and_flag_safe() -> None:
    """``--only <key>`` has to be typeable and unambiguous."""
    keys = [asset.key for asset in ASSETS]

    assert len(keys) == len(set(keys))
    assert all(re.fullmatch(r"[a-z0-9-]+", key) for key in keys)


def test_requires_only_names_real_assets() -> None:
    for asset in ASSETS:
        assert set(asset.requires) <= set(ASSETS_BY_KEY), asset.key


def test_sentinels_are_declared_for_every_asset() -> None:
    """Without one, "already installed" is not decidable."""
    assert all(asset.sentinel for asset in ASSETS)
