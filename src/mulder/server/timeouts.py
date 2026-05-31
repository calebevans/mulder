"""Shared timeout computation and deferral decision logic.

When a forensic tool times out, the system checks whether resource
contention (high CPU, concurrent batch jobs) caused the timeout.  If
so, the job is deferred for retry once resources free up rather than
being marked as permanently failed.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_CPU_LOAD_THRESHOLD = 70.0


def _get_cpu_percent() -> float:
    """Return current system-wide CPU usage as a 0-100 float.

    Falls back to ``/proc/loadavg`` on systems without *psutil*.
    Returns ``-1.0`` if CPU usage cannot be determined.
    """
    try:
        import psutil

        return float(psutil.cpu_percent(interval=None))
    except (ImportError, AttributeError):
        pass
    try:
        import os

        with open("/proc/loadavg") as f:
            load1 = float(f.read().split()[0])
            ncpu = os.cpu_count() or 1
            return min(100.0, 100.0 * load1 / ncpu)
    except OSError:
        return -1.0


def is_system_under_load(cpu_threshold: float = _CPU_LOAD_THRESHOLD) -> bool:
    """Return True if system CPU usage exceeds *cpu_threshold*.

    Args:
        cpu_threshold: CPU usage percentage above which the system
            is considered under load.

    Returns:
        True if system is under heavy CPU load.  Returns False when
        CPU metrics are unavailable (assumes low load).
    """
    cpu = _get_cpu_percent()
    if cpu < 0:
        return False
    return cpu > cpu_threshold


def should_defer(
    other_running_in_batch: int,
    cpu_threshold: float = _CPU_LOAD_THRESHOLD,
) -> bool:
    """Decide whether a timed-out job should be deferred for retry.

    A job is deferred (rather than permanently failed) when either:

    - Other jobs in the same batch are still running (resource
      contention), OR
    - System CPU load exceeds *cpu_threshold*.

    Args:
        other_running_in_batch: Count of other concurrently running
            jobs in the same batch.
        cpu_threshold: CPU usage percentage above which the system
            is considered under load.

    Returns:
        True if the job should be deferred for later retry.
    """
    if other_running_in_batch > 0:
        return True
    return is_system_under_load(cpu_threshold)
