"""Background log file monitoring for job completion events.

Tails ``mulder.log`` for structured ``[JOB_COMPLETE]`` markers emitted
by the MCP server when background jobs finish, and pushes real-time
status updates to the investigation dashboard.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path

from mulder.orchestrator.display import InvestigationDashboard

logger = logging.getLogger(__name__)

_SUCCESS_STATUSES: frozenset[str] = frozenset(("completed", "ok", "success"))


class LogTailer:
    """Tails mulder.log for job completion markers and updates the dashboard.

    Runs a daemon thread that polls the log file for new lines containing
    ``[JOB_COMPLETE]`` markers. Each marker triggers a dashboard task
    panel update so the user sees real-time progress during extraction.
    """

    def __init__(
        self,
        dashboard: InvestigationDashboard,
        log_path: Path,
    ) -> None:
        """Initialize the log tailer.

        Args:
            dashboard: Dashboard instance for real-time task panel updates.
            log_path: Path to the mulder.log file to tail.
        """
        self._dashboard = dashboard
        self._log_path = log_path

    def start(self, is_running: Callable[[], bool]) -> None:
        """Start a daemon thread that tails the log file for job completions.

        The thread polls the log file for new ``[JOB_COMPLETE]`` lines and
        updates the dashboard task panel in real time. The thread exits
        when ``is_running`` returns False.

        Args:
            is_running: Callable that returns True while the orchestrator
                is active. The tailer thread exits when this returns False.
        """
        if not self._log_path.exists():
            logger.debug("mulder.log not found at %s; tailer will wait", self._log_path)

        def _tail() -> None:
            while is_running():
                if not self._log_path.exists():
                    time.sleep(1.0)
                    continue
                try:
                    with open(self._log_path, encoding="utf-8", errors="replace") as f:
                        f.seek(0, 2)
                        while is_running():
                            line = f.readline()
                            if not line:
                                time.sleep(0.5)
                                continue
                            if "[JOB_COMPLETE]" in line:
                                self._handle_job_completion(line)
                except OSError:
                    logger.debug("Log tailer encountered IO error", exc_info=True)
                    time.sleep(1.0)

        thread = threading.Thread(target=_tail, daemon=True, name="log-tailer")
        thread.start()

    def _handle_job_completion(self, line: str) -> None:
        """Parse a job completion log line and update the dashboard task panel.

        Expected format after the marker::

            [JOB_COMPLETE] tool_name|status|error_or_empty

        The marker does not carry a system identifier, so we delegate to
        ``complete_one_running_task`` which updates exactly one task in
        ``running`` state per event.

        Args:
            line: Full log line containing the JOB_COMPLETE marker.
        """
        marker = "[JOB_COMPLETE] "
        try:
            idx = line.index(marker) + len(marker)
        except ValueError:
            return

        parts = line[idx:].strip().split("|", 2)
        if len(parts) < 2:
            return

        tool_name = parts[0]
        status = parts[1]
        error = parts[2] if len(parts) > 2 and parts[2] else None

        if status in _SUCCESS_STATUSES:
            self._dashboard.complete_one_running_task(tool_name, "done")
        elif status == "failed":
            self._dashboard.complete_one_running_task(tool_name, "failed", error=error)
