"""The binary parsers must read the keys capa and FLOSS actually emit.

FLOSS 3.1.0's ResultDocument is ``{metadata, analysis, strings}``. All four
string lists live under ``strings``, and the decoded one is named
``decoded_strings``. ``_parse_floss_output`` read ``decoded``,
``stack_strings``, ``tight_strings`` and ``static_strings`` from the *top
level*, where none of them exist -- so every sample produced four empty lists
and the tool reported that no obfuscated strings were recovered. Analysis time
was read from ``metadata.elapsed_time``, which does not exist either; FLOSS
records ``metadata.runtime.total``.

capa 9.4.0's ``AttackSpec`` is ``(parts, tactic, technique, subtechnique, id)``.
There is no ``subtechnique_id``, so that field was always ``None``.

The FLOSS fixture below is a real document emitted by the pinned release
(floss v3.1.0-0-gdb9af41), not a hand-written guess.
"""

from __future__ import annotations

from typing import Any

from mulder.server.tools.binary import _parse_capa_output, _parse_floss_output

# Captured verbatim from `floss --json --format sc32 --minimum-length 4`
# against a 64-byte NOP sled containing one ASCII string.
_REAL_FLOSS_DOC: dict[str, Any] = {
    "metadata": {
        "file_path": "sc.bin",
        "min_length": 4,
        "runtime": {
            "decoded_strings": 0.084,
            "find_features": 0.1069,
            "language_strings": 0,
            "stack_strings": 0.1072,
            "start_date": "2026-09-08T06:09:20.037682Z",
            "static_strings": 0.0008,
            "tight_strings": 0.0018,
            "total": 21.27,
            "vivisect": 20.9608,
        },
        "version": "3.1.0",
    },
    "analysis": {},
    "strings": {
        "decoded_strings": [
            {"string": "http://evil.example/c2", "address": 4198400, "encoding": "ASCII"}
        ],
        "language_strings": [],
        "language_strings_missed": [],
        "stack_strings": [{"string": "cmd.exe /c", "encoding": "ASCII"}],
        "static_strings": [{"encoding": "ASCII", "offset": 64, "string": "Hello decoded world"}],
        "tight_strings": [{"string": "VirtualAllocEx", "encoding": "ASCII"}],
    },
}


def test_floss_strings_are_read_from_the_strings_section() -> None:
    """The whole point: a document with strings must not parse as empty.

    Reading the top level found nothing, and "nothing recovered" is exactly
    what an analyst would have been told about a sample that FLOSS had in fact
    decoded a C2 URL out of.
    """
    parsed = _parse_floss_output(_REAL_FLOSS_DOC, "/evidence/sample.exe")

    assert len(parsed["decoded_strings"]) == 1  # type: ignore[arg-type]
    assert len(parsed["stack_strings"]) == 1  # type: ignore[arg-type]
    assert len(parsed["tight_strings"]) == 1  # type: ignore[arg-type]
    assert len(parsed["static_strings"]) == 1  # type: ignore[arg-type]
    assert parsed["total_decoded"] == 3


def test_the_decoded_c2_url_actually_reaches_the_caller() -> None:
    """Not just a count -- the recovered value has to be present."""
    parsed = _parse_floss_output(_REAL_FLOSS_DOC, "/evidence/sample.exe")

    decoded: list[dict[str, object]] = parsed["decoded_strings"]  # type: ignore[assignment]
    assert decoded[0]["value"] == "http://evil.example/c2"


def test_analysis_time_comes_from_metadata_runtime_total() -> None:
    """FLOSS records `metadata.runtime.total`; `elapsed_time` does not exist."""
    parsed = _parse_floss_output(_REAL_FLOSS_DOC, "/evidence/sample.exe")

    assert parsed["analysis_time_seconds"] == 21.27


def test_a_genuinely_empty_result_still_parses_as_empty() -> None:
    """Narrowness guard: a sample with no strings must stay at zero.

    The fix must not manufacture findings, only stop discarding them.
    """
    empty = {
        "metadata": {"runtime": {"total": 1.5}},
        "strings": {
            "decoded_strings": [],
            "stack_strings": [],
            "tight_strings": [],
            "static_strings": [],
        },
    }

    parsed = _parse_floss_output(empty, "/evidence/clean.exe")

    assert parsed["total_decoded"] == 0
    assert parsed["analysis_time_seconds"] == 1.5


def test_a_malformed_document_does_not_raise() -> None:
    """Narrowness guard: FLOSS output that is not shaped as expected."""
    malformed: list[dict[str, Any]] = [
        {},
        {"strings": None},
        {"strings": []},
        {"metadata": "nope"},
    ]
    for bad in malformed:
        parsed = _parse_floss_output(bad, "/evidence/x.exe")
        assert parsed["total_decoded"] == 0
        assert parsed["analysis_time_seconds"] == 0.0


def test_capa_subtechnique_is_read_by_its_real_name() -> None:
    """capa's AttackSpec field is `subtechnique`, and it holds a name."""
    raw = {
        "rules": {
            "encrypt data using AES": {
                "meta": {
                    "namespace": "data-manipulation/encryption/aes",
                    "attack": [
                        {
                            "parts": ["Execution", "Command and Scripting Interpreter", "Python"],
                            "tactic": "Execution",
                            "technique": "Command and Scripting Interpreter",
                            "subtechnique": "Python",
                            "id": "T1059.006",
                        }
                    ],
                },
                "matches": {"0x401000": {}},
            }
        }
    }

    parsed = _parse_capa_output(raw, "/evidence/sample.exe")

    caps: list[dict[str, Any]] = parsed["capabilities"]  # type: ignore[assignment]
    mapping = caps[0]["attack"][0]
    assert mapping["subtechnique"] == "Python"
    assert "subtechnique_id" not in mapping, "capa emits no such field"
    assert mapping["technique_id"] == "T1059.006"

    summary: dict[str, list[str]] = parsed["mitre_summary"]  # type: ignore[assignment]
    assert summary["Execution"] == ["T1059.006: Command and Scripting Interpreter::Python"]


def test_capa_technique_without_a_subtechnique_is_unchanged() -> None:
    """Narrowness guard: no trailing separator when there is no sub-technique."""
    raw = {
        "rules": {
            "r": {
                "meta": {
                    "namespace": "n",
                    "attack": [
                        {
                            "parts": ["Execution", "Native API"],
                            "tactic": "Execution",
                            "technique": "Native API",
                            "subtechnique": "",
                            "id": "T1106",
                        }
                    ],
                },
                "matches": {},
            }
        }
    }

    parsed = _parse_capa_output(raw, "/evidence/sample.exe")

    summary: dict[str, list[str]] = parsed["mitre_summary"]  # type: ignore[assignment]
    assert summary["Execution"] == ["T1106: Native API"]
