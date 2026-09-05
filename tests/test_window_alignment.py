"""Windows must never cut a record in half.

The store used to slice ``raw_output[offset : offset + 4096]`` at absolute
character offsets. Around twenty callers read one record per window, so a
severed row does not merely lose data -- it yields a *wrong* value: a
truncated PID that still parses as an integer, or a process name from one
row paired with the PID from another.
"""

from __future__ import annotations

from mulder.server.extract_helpers import _WINDOW_CHAR_BUDGET, _line_aligned_windows


def _pslist(rows: int = 200) -> str:
    """Realistically shaped ``windows.pslist`` output, wide enough to straddle."""
    header = (
        "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\t"
        "Wow64\tCreateTime\tExitTime\tFile output\n"
    )
    lines = [header]
    for i in range(1, rows + 1):
        lines.append(
            f"{i * 4}\t{i * 4 - 4}\tsvchost{i}.exe\t0x{i:012x}\t"
            f"{i % 40}\t{i * 3}\t0\tFalse\t"
            f"2024-03-0{i % 9 + 1} 10:{i % 60:02d}:00.000000 UTC\tN/A\tDisabled\n"
        )
    return "".join(lines)


class TestLineAlignedWindows:
    def test_no_window_starts_or_ends_mid_record(self) -> None:
        text = _pslist()
        for window, _, _ in _line_aligned_windows(text):
            for line in window.splitlines():
                # Every real row has exactly ten tabs; a severed one does not.
                assert line.count("\t") == 10, f"severed row: {line!r}"

    def test_every_row_survives_exactly_once(self) -> None:
        text = _pslist()
        recovered = [
            line for window, _, _ in _line_aligned_windows(text) for line in window.splitlines()
        ]
        assert recovered == text.splitlines()

    def test_every_pid_is_recoverable(self) -> None:
        """The failure this prevents: 40 processes indexed, 39 readable."""
        text = _pslist(rows=200)
        pids = {
            int(line.split("\t")[0])
            for window, _, _ in _line_aligned_windows(text)
            for line in window.splitlines()
            if line.split("\t")[0].isdigit()
        }
        assert pids == {i * 4 for i in range(1, 201)}

    def test_line_numbers_are_contiguous_and_one_based(self) -> None:
        windows = list(_line_aligned_windows(_pslist()))
        assert windows[0][1] == 1
        for (_, _, prev_end), (_, next_start, _) in zip(windows, windows[1:], strict=False):
            assert next_start == prev_end + 1

    def test_line_numbers_cover_the_whole_output(self) -> None:
        text = _pslist()
        windows = list(_line_aligned_windows(text))
        assert windows[-1][2] == len(text.splitlines())

    def test_windows_respect_the_budget(self) -> None:
        for window, _, _ in _line_aligned_windows(_pslist()):
            assert len(window) <= _WINDOW_CHAR_BUDGET

    def test_a_single_overlong_line_is_still_split(self) -> None:
        blob = "A" * (_WINDOW_CHAR_BUDGET * 3 + 17) + "\n"
        windows = list(_line_aligned_windows(blob))
        assert len(windows) == 4
        assert "".join(w for w, _, _ in windows) == blob
        assert all(s == 1 and e == 1 for _, s, e in windows)

    def test_blank_only_windows_are_dropped(self) -> None:
        assert list(_line_aligned_windows("\n\n   \n\n")) == []

    def test_empty_input(self) -> None:
        assert list(_line_aligned_windows("")) == []

    def test_output_without_a_trailing_newline(self) -> None:
        text = "a\nb\nc"
        windows = list(_line_aligned_windows(text))
        assert "".join(w for w, _, _ in windows) == text
        assert windows[-1][2] == 3
