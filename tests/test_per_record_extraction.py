"""A window holds many records; the extractors used to read exactly one.

``extract_pids_from_windows`` and ``extract_module_names`` ran ``re.search``
over the whole window text, so a window of forty processes contributed one
PID and the other thirty-nine were invisible to every correlation built on
top of them.
"""

from __future__ import annotations

from mulder.models import WindowRow
from mulder.server.helpers import (
    extract_module_names,
    extract_pid,
    extract_pids,
    extract_pids_from_windows,
    window_has_pid,
)


def _window(text: str, source_id: int = 1) -> WindowRow:
    return WindowRow(source_id=source_id, line_start=1, line_end=1, event_time=None, raw_text=text)


PSLIST = "\n".join(
    f"{pid}\t{pid - 4}\tsvchost{i}.exe\t0x{pid:012x}\t12\t340\t0\tFalse\tN/A"
    for i, pid in enumerate(range(4, 4 * 41, 4), start=1)
)

MODULES = "\n".join(
    f"driver{i}.sys\t0x{i:08x}\t\\SystemRoot\\System32\\drivers\\driver{i}.sys"
    for i in range(1, 21)
)


class TestExtractPids:
    def test_every_pid_in_a_multi_record_window(self) -> None:
        assert extract_pids(PSLIST) == list(range(4, 4 * 41, 4))

    def test_first_pid_is_unchanged(self) -> None:
        assert extract_pid(PSLIST) == 4

    def test_duplicates_collapse_but_order_is_kept(self) -> None:
        assert extract_pids("9\t0\ta\n4\t0\tb\n9\t0\tc") == [9, 4]

    def test_zero_is_not_a_pid(self) -> None:
        assert extract_pids("0\t0\tidle") == []

    def test_no_records(self) -> None:
        assert extract_pids("no numeric pid here") == []
        assert extract_pids("") == []

    def test_the_per_line_match_is_unchanged(self) -> None:
        """Which column holds the PID varies by plugin; only the line count changed."""
        # windows.netscan puts the PID eighth; the historical match takes the
        # first tab-delimited number on the line either way.
        assert extract_pids("svchost.exe\t1234\t456\t...") == [1234]


class TestExtractPidsFromWindows:
    def test_all_forty_processes_are_grouped(self) -> None:
        mapping = extract_pids_from_windows([_window(PSLIST)])
        assert set(mapping) == set(range(4, 4 * 41, 4))

    def test_a_pid_spanning_two_windows_maps_to_both(self) -> None:
        mapping = extract_pids_from_windows([_window("7\t0\ta"), _window("7\t0\tb\n9\t0\tc")])
        assert len(mapping[7]) == 2
        assert len(mapping[9]) == 1

    def test_empty_input(self) -> None:
        assert extract_pids_from_windows([]) == {}


class TestWindowHasPid:
    def test_finds_a_pid_that_is_not_the_first(self) -> None:
        assert window_has_pid(PSLIST, 160) is True

    def test_absent_pid(self) -> None:
        assert window_has_pid(PSLIST, 999999) is False


class TestExtractModuleNames:
    def test_all_modules_in_one_window(self) -> None:
        mapping = extract_module_names([_window(MODULES)])
        assert set(mapping) == {f"driver{i}.sys" for i in range(1, 21)}

    def test_only_the_first_column_is_a_module_name(self) -> None:
        """A .sys path in a later column is the same module, not a second one."""
        mapping = extract_module_names([_window("tcpip.sys\t0x1\t\\SystemRoot\\other.sys")])
        assert set(mapping) == {"tcpip.sys"}

    def test_a_module_in_two_windows_maps_to_both(self) -> None:
        mapping = extract_module_names([_window("a.sys\t1"), _window("a.sys\t2\nb.sys\t3")])
        assert len(mapping["a.sys"]) == 2
        assert len(mapping["b.sys"]) == 1
