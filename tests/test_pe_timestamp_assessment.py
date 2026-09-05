"""A valid PE compilation timestamp was asserted to be forensically impossible.

``_assess_timestamp`` did ``int(raw_ts)`` and, on ValueError, returned
``validity: "impossible"``, which ``_compute_verdict`` scores **+5** -- past
the threshold of 4 on its own, so a clean binary with no other signal was
classified ``suspicious_indicators``.

rabin2 does not emit an epoch integer. It formats the PE TimeDateStamp with
ctime first. Running radare2 6.0.7 against a PE built with a known
``TimeDateStamp`` of ``1741772463``::

    "compiled": "Wed Mar 12 09:41:03 2025"
    "bintype":  "pe"

The complementary half hits every non-Windows binary: ELF and Mach-O carry no
compilation timestamp at all, rabin2 reports ``compiled: ""`` for them, and the
missing-timestamp branch scored **+2** for a field the format never had.
``rabin2 -Ij /bin/ls`` confirms ``compiled: ''``.

The zeroed timestamp -- an actual malware evasion -- was reported as
impossible before this change and still is, but now because it parses to 1970
rather than because it failed to parse at all.
"""

from __future__ import annotations

from mulder.server.tools.binary import _assess_timestamp, _compute_verdict


class TestRabin2FormatsTheTimestamp:
    def test_the_real_rabin2_value_is_valid(self) -> None:
        """Verbatim `compiled` from radare2 6.0.7 on TimeDateStamp 1741772463."""
        result = _assess_timestamp("Wed Mar 12 09:41:03 2025", "pe")
        assert result["validity"] == "valid"
        assert result["parsed_utc"] == "2025-03-12T09:41:03+00:00"

    def test_int_really_does_reject_that_value(self) -> None:
        """Pin the premise rather than trusting the description of the bug."""
        import pytest

        with pytest.raises(ValueError):
            int("Wed Mar 12 09:41:03 2025")

    def test_a_single_digit_day_is_parsed(self) -> None:
        """ctime pads with a second space: `Jan  1`, not `Jan 01`."""
        result = _assess_timestamp("Thu Jan  1 00:00:00 1970", "pe")
        assert result["parsed_utc"] == "1970-01-01T00:00:00+00:00"

    def test_a_bare_epoch_integer_is_still_accepted(self) -> None:
        result = _assess_timestamp("1741772463", "pe")
        assert result["validity"] == "valid"
        assert result["parsed_utc"] == "2025-03-12T09:41:03+00:00"

    def test_genuine_garbage_is_still_impossible(self) -> None:
        result = _assess_timestamp("not a date at all", "pe")
        assert result["validity"] == "impossible"


class TestTheVerdictNoLongerPunishesACleanBinary:
    def test_a_clean_pe_scores_nothing(self) -> None:
        ts = _assess_timestamp("Wed Mar 12 09:41:03 2025", "pe")
        verdict = _compute_verdict([], {}, ts, [])
        assert verdict["classification"] == "benign_indicators"
        assert verdict["reasons"] == []

    def test_the_old_behaviour_would_have_crossed_the_threshold(self) -> None:
        """+5 for an impossible timestamp, against a threshold of 4."""
        impossible = {"validity": "impossible", "reason": "Cannot parse timestamp value"}
        verdict = _compute_verdict([], {}, impossible, [])
        assert verdict["classification"] == "suspicious_indicators"


class TestFormatsWithoutATimestamp:
    def test_an_elf_is_not_penalised(self) -> None:
        """rabin2 reports compiled: '' for ELF; the format has no such field."""
        result = _assess_timestamp(None, "elf")
        assert result["validity"] == "not_applicable"
        assert _compute_verdict([], {}, result, [])["reasons"] == []

    def test_a_macho_is_not_penalised(self) -> None:
        assert _assess_timestamp(None, "mach0")["validity"] == "not_applicable"

    def test_a_pe_with_no_timestamp_is_still_suspicious(self) -> None:
        """A PE header always has the field, so a missing value is an anomaly."""
        result = _assess_timestamp(None, "pe")
        assert result["validity"] == "suspicious"
        assert _compute_verdict([], {}, result, [])["reasons"] == [
            "Missing or suspicious timestamp"
        ]

    def test_an_unknown_format_keeps_the_old_conservative_reading(self) -> None:
        assert _assess_timestamp(None, "")["validity"] == "suspicious"


class TestTheEvasionIsStillCaught:
    def test_a_zeroed_timestamp_is_impossible(self) -> None:
        """The real signal this check exists for, preserved."""
        result = _assess_timestamp("Thu Jan  1 00:00:00 1970", "pe")
        assert result["validity"] == "impossible"
        assert "predates" in str(result["reason"])

    def test_a_future_timestamp_is_impossible(self) -> None:
        result = _assess_timestamp("Sat Jan  1 00:00:00 2400", "pe")
        assert result["validity"] == "impossible"
        assert "future" in str(result["reason"])
