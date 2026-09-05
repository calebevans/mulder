"""``binary.py`` re-declared IP and path regexes instead of using the shared ones.

``mulder.patterns`` exists so one parser is fixed once -- the same reason the
``mmls`` and ``fls`` parsers were consolidated. ``binary.py`` kept private
copies, and they had drifted:

===================  ==========================================
shared               ``/(?:usr|var|etc|home|tmp|opt|root|proc|sys|run|mnt|media)``
local (was)          ``/(?:usr|etc|tmp|var)/``
===================  ==========================================

So ``_categorize_string`` returned ``None`` for exactly the paths a malware
triage cares about -- ``/root/.bash_history``, ``/home/victim/.ssh/id_rsa``,
``/opt/...``, ``/proc/self/maps``, ``/run/...``, ``/mnt/...`` -- and those
strings were dropped from the categorised output rather than surfaced as
``filepath``.

The IP copy was byte-identical to ``patterns.IP_RE``, so nothing changes there;
it is removed because the next drift is the problem.
"""

from __future__ import annotations

import pytest

from mulder.patterns import IP_RE, UNIX_PATH_RE, WIN_PATH_RE
from mulder.server.tools.binary import _categorize_string


class TestPathsTheLocalCopyMissed:
    @pytest.mark.parametrize(
        "value",
        [
            "/root/.bash_history",
            "/home/victim/.ssh/id_rsa",
            "/opt/implant/payload",
            "/proc/self/maps",
            "/run/user/1000/keyring",
            "/mnt/exfil/staging.tar",
            "/media/usb0/dump.bin",
            "/sys/class/net/eth0/address",
        ],
    )
    def test_it_is_now_a_filepath(self, value: str) -> None:
        assert _categorize_string(value) == "filepath"

    def test_the_old_pattern_really_did_miss_them(self) -> None:
        """Pin the premise rather than describing it."""
        import re

        old = re.compile(r"[A-Z]:\\[^\s\"]+|/(?:usr|etc|tmp|var)/[^\s\"]+")

        assert old.search("/root/.bash_history") is None
        assert old.search("/home/victim/.ssh/id_rsa") is None


class TestUnchangedBehaviour:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (r"C:\Windows\System32\svchost.exe", "filepath"),
            (r"C:\Users\victim\AppData\Roaming\update.exe", "filepath"),
            ("/usr/bin/curl", "filepath"),
            ("/etc/passwd", "filepath"),
            ("/tmp/.X11-unix/x0", "filepath"),
            ("/var/log/auth.log", "filepath"),
            ("http://evil.example/payload", "url"),
            ("192.168.1.50", "ip"),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "registry"),
        ],
    )
    def test_still_classified_the_same(self, value: str, expected: str) -> None:
        assert _categorize_string(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "GET /index.html HTTP/1.1",
            "Mozilla/5.0 compatible",
            "/dev/null",
            "just some text",
        ],
    )
    def test_still_uncategorised(self, value: str) -> None:
        assert _categorize_string(value) is None


class TestTheSharedPatternsAreTheOnesUsed:
    def test_no_private_copies_remain(self) -> None:
        """A re-declared copy here is what drifted last time."""
        from mulder.server.tools import binary

        assert not hasattr(binary, "_IPV4_RE")
        assert not hasattr(binary, "_FILEPATH_RE")

    def test_the_module_imports_the_shared_ones(self) -> None:
        from mulder.server.tools import binary

        assert binary.IP_RE is IP_RE
        assert binary.WIN_PATH_RE is WIN_PATH_RE
        assert binary.UNIX_PATH_RE is UNIX_PATH_RE
