"""The binary parsers read keys their tools never emit.

Three wrapped tools, one failure: the parser looks for a shape the tool does
not produce, finds nothing, and the nothing is reported as a clean result.

* **FLOSS.** ``_parse_floss_output`` read ``raw["decoded"]``,
  ``raw["stack_strings"]``, ``raw["tight_strings"]`` and
  ``raw["static_strings"]`` at the top level. FLOSS's ``ResultDocument`` is
  ``{metadata, analysis, strings}`` and nests all four under ``strings`` --
  and the decoded one is ``decoded_strings``, not ``decoded``. Every lookup
  returned ``[]``, so a sample with dozens of XOR-decoded C2 URLs was reported
  as ``total_decoded: 0`` with ``status: success``. Schema read from
  ``floss/results.py`` in flare-floss 3.1.1.

* **Detect It Easy.** ``_parse_die_output`` read ``type``/``name`` off each
  ``detects[]`` entry and compared the type against lowercase literals. DIE
  nests the records under ``detects[].values[]`` and capitalises the type on
  output: a rule declaring ``init("packer", "UPX")`` is emitted as
  ``"type": "Packer"``. Both halves independently defeat the classification,
  so every detection came out ``{"type": "unknown", "name": ""}`` and
  ``is_packed`` was always ``False`` -- a packed sample reported as unpacked,
  with no error. Verified by running Detect It Easy 3.09 against real ELF
  binaries; the fixture below is its actual output with a packer record in the
  shape DIE emits for one.

* **capa.** ``_parse_capa_output`` read ``ref["subtechnique_id"]``. capa's
  ``AttackSpec`` fields are ``parts``/``tactic``/``technique``/
  ``subtechnique``/``id``, so the value was always ``None``. Read from
  ``capa/render/result_document.py`` in flare-capa 9.4.0.
"""

from __future__ import annotations

import json
from typing import Any

from mulder.server.tools.binary import (
    _parse_capa_output,
    _parse_die_output,
    _parse_floss_output,
)

# Verbatim Detect It Easy 3.09 output for /bin/ls, plus a UPX record in the
# shape DIE emits for init("packer", "UPX").
DIE_OUTPUT: dict[str, Any] = json.loads(
    """
{"detects": [{"filetype": "ELF64", "info": "", "offset": "0",
  "parentfilepart": "Header", "size": "11352352",
  "values": [
    {"info": "DYN AMD64-64", "name": "GLIBC",
     "string": "Library: GLIBC(2.9)[DYN AMD64-64]", "type": "Library",
     "version": "2.9"},
    {"info": "", "name": "GCC", "string": "Compiler: GCC(3.X)",
     "type": "Compiler", "version": "3.X"},
    {"info": "NRV,brute", "name": "UPX", "string": "Packer: UPX(3.96)",
     "type": "Packer", "version": "3.96"}
  ]}]}
"""
)

# The pre-3.x flat shape, still accepted.
DIE_FLAT: dict[str, Any] = {
    "filetype": "PE32",
    "detects": [{"type": "packer", "name": "UPX", "version": "3.96"}],
}

FLOSS_OUTPUT: dict[str, Any] = {
    "metadata": {
        "file_path": "/evidence/sample.exe",
        "version": "3.1.1",
        "runtime": {"total": 12.5},
    },
    "analysis": {"enable_decoded_strings": True},
    "strings": {
        "decoded_strings": [
            {
                "address": 4210688,
                "address_type": "GLOBAL",
                "string": "http://c2.example/gate.php",
                "encoding": "ASCII",
                "decoded_at": 4198400,
                "decoding_routine": 4198656,
            }
        ],
        "stack_strings": [
            {
                "function": 4198400,
                "string": "cmd.exe /c",
                "encoding": "ASCII",
                "program_counter": 4198420,
                "stack_pointer": 100,
                "original_stack_pointer": 120,
                "offset": 8,
                "frame_offset": 16,
            }
        ],
        "tight_strings": [],
        "static_strings": [{"string": "KERNEL32.dll", "offset": 1024, "encoding": "ASCII"}],
    },
}

CAPA_OUTPUT: dict[str, Any] = {
    "meta": {"version": "9.4.0", "analysis": {"time": 3.5}},
    "rules": {
        "inject code via process hollowing": {
            "meta": {
                "name": "inject code via process hollowing",
                "namespace": "host-interaction/process/inject",
                "attack": [
                    {
                        "parts": ["Defense Evasion", "Process Injection", "Process Hollowing"],
                        "tactic": "Defense Evasion",
                        "technique": "Process Injection",
                        "subtechnique": "Process Hollowing",
                        "id": "T1055.012",
                    }
                ],
            },
            "matches": [[{"type": "absolute", "value": 4198400}, {}]],
        }
    },
}


class TestFlossStringsAreFound:
    def test_the_old_top_level_keys_do_not_exist(self) -> None:
        """Pin the premise: this is why every lookup returned an empty list."""
        assert "decoded" not in FLOSS_OUTPUT
        assert "stack_strings" not in FLOSS_OUTPUT
        assert "static_strings" not in FLOSS_OUTPUT
        assert set(FLOSS_OUTPUT) == {"metadata", "analysis", "strings"}

    def test_decoded_strings_are_recovered(self) -> None:
        result = _parse_floss_output(FLOSS_OUTPUT, "/evidence/sample.exe")
        values = [s["value"] for s in result["decoded_strings"]]  # type: ignore[union-attr]
        assert values == ["http://c2.example/gate.php"]

    def test_the_c2_url_is_categorised(self) -> None:
        """The whole point of running FLOSS on a packed sample."""
        result = _parse_floss_output(FLOSS_OUTPUT, "/evidence/sample.exe")
        assert result["decoded_strings"][0]["category"] == "url"  # type: ignore[index]

    def test_stack_and_static_strings_are_recovered(self) -> None:
        result = _parse_floss_output(FLOSS_OUTPUT, "/evidence/sample.exe")
        assert [s["value"] for s in result["stack_strings"]] == ["cmd.exe /c"]  # type: ignore[union-attr]
        assert [s["value"] for s in result["static_strings"]] == ["KERNEL32.dll"]  # type: ignore[union-attr]

    def test_the_total_counts_the_obfuscated_strings_only(self) -> None:
        """static strings are not obfuscated, so they are not "decoded"."""
        result = _parse_floss_output(FLOSS_OUTPUT, "/evidence/sample.exe")
        assert result["total_decoded"] == 2

    def test_a_decoded_string_carries_its_address_not_an_offset(self) -> None:
        """It never existed in the file, so it has no file offset."""
        entry = _parse_floss_output(FLOSS_OUTPUT, "/e")["decoded_strings"][0]  # type: ignore[index]
        assert entry["offset"] is None
        assert entry["address"] == 4210688
        assert entry["decoding_routine_address"] == 4198656

    def test_the_runtime_is_read_from_where_floss_records_it(self) -> None:
        assert _parse_floss_output(FLOSS_OUTPUT, "/e")["analysis_time_seconds"] == 12.5

    def test_an_empty_document_does_not_explode(self) -> None:
        result = _parse_floss_output({"metadata": {}}, "/e")
        assert result["total_decoded"] == 0
        assert result["analysis_time_seconds"] == 0.0


class TestDieDetectionsAreClassified:
    def test_the_records_are_not_on_the_detects_entry(self) -> None:
        """Pin the premise: the entry itself carries no type or name."""
        entry = DIE_OUTPUT["detects"][0]
        assert "type" not in entry
        assert "name" not in entry
        assert "values" in entry

    def test_a_packed_sample_is_reported_as_packed(self) -> None:
        result = _parse_die_output(DIE_OUTPUT, "/evidence/sample")
        assert result["is_packed"] is True
        assert result["packer_name"] == "UPX"

    def test_the_capitalised_type_still_classifies(self) -> None:
        """DIE emits "Packer" for a rule that declares init("packer", ...)."""
        assert DIE_OUTPUT["detects"][0]["values"][2]["type"] == "Packer"
        result = _parse_die_output(DIE_OUTPUT, "/evidence/sample")
        assert [p["name"] for p in result["packers"]] == ["UPX"]  # type: ignore[union-attr]
        assert [c["name"] for c in result["compilers"]] == ["GCC"]  # type: ignore[union-attr]

    def test_every_detection_is_named(self) -> None:
        result = _parse_die_output(DIE_OUTPUT, "/evidence/sample")
        names = [d["name"] for d in result["detections"]]  # type: ignore[union-attr]
        assert names == ["GLIBC", "GCC", "UPX"]
        assert all(d["type"] != "unknown" for d in result["detections"])  # type: ignore[union-attr]

    def test_the_file_type_comes_from_the_detection_entry(self) -> None:
        """There is no top-level filetype in DIE 3.x output."""
        assert "filetype" not in DIE_OUTPUT
        assert _parse_die_output(DIE_OUTPUT, "/e")["file_type"] == "ELF64"

    def test_the_flat_shape_is_still_accepted(self) -> None:
        result = _parse_die_output(DIE_FLAT, "/e")
        assert result["is_packed"] is True
        assert result["packer_name"] == "UPX"
        assert result["file_type"] == "PE32"

    def test_a_clean_binary_is_not_reported_as_packed(self) -> None:
        clean = {
            "detects": [{"filetype": "ELF64", "values": [DIE_OUTPUT["detects"][0]["values"][1]]}]
        }
        result = _parse_die_output(clean, "/e")
        assert result["is_packed"] is False
        assert result["packer_name"] is None

    def test_no_detections_does_not_explode(self) -> None:
        assert _parse_die_output({}, "/e")["file_type"] == "unknown"


class TestCapaSubtechnique:
    def test_the_field_capa_emits_is_read(self) -> None:
        assert (
            "subtechnique_id"
            not in CAPA_OUTPUT["rules"]["inject code via process hollowing"]["meta"]["attack"][0]
        )

        result = _parse_capa_output(CAPA_OUTPUT, "/e/sample.exe")
        mapping = result["capabilities"][0]["attack"][0]  # type: ignore[index]
        assert mapping["subtechnique"] == "Process Hollowing"

    def test_the_technique_id_already_carries_the_subtechnique(self) -> None:
        """capa's `id` is the full identifier, so granularity was never lost."""
        result = _parse_capa_output(CAPA_OUTPUT, "/e/sample.exe")
        mapping = result["capabilities"][0]["attack"][0]  # type: ignore[index]
        assert mapping["technique_id"] == "T1055.012"

    def test_the_summary_names_the_subtechnique(self) -> None:
        result = _parse_capa_output(CAPA_OUTPUT, "/e/sample.exe")
        assert result["mitre_summary"] == {
            "Defense Evasion": ["T1055.012: Process Injection::Process Hollowing"]
        }
