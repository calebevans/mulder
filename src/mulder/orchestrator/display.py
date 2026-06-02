"""Rich Live dashboard for investigation progress display.

Provides a split-screen terminal UI with a fixed stats header and a
scrolling log panel. Uses Rich's Live display to manage all terminal
rendering, preventing corruption from the SDK subprocess.
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from collections import deque
from dataclasses import dataclass
from itertools import islice
from typing import TYPE_CHECKING, Any, Literal

import psutil

if TYPE_CHECKING:
    from mulder.orchestrator.types import InvestigationResult
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mulder.patterns import format_token_count

logger = logging.getLogger(__name__)

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "bold cyan",
    "low": "cyan",
    "informational": "dim white",
    "info": "dim white",
}

_SEVERITY_DOTS: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
    "info": "⚪",
}

_SYSTEM_COLORS: list[str] = [
    "bright_cyan",
    "bright_green",
    "bright_magenta",
    "bright_yellow",
    "bright_blue",
    "bright_red",
    "cyan",
    "green",
    "magenta",
    "yellow",
]

_SYSTEM_PREFIX_RE: re.Pattern[str] = re.compile(r"\[([^\]]+)\]\s*")

_SPINNER_FRAMES: str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


@dataclass
class TaskItem:
    """A single tool execution task displayed in the progress panel.

    Attributes:
        tool: Short tool name (e.g. ``extract_archive``).
        system: System this task belongs to (e.g. ``base-dc``).
        status: Current execution state.
        elapsed_seconds: Wall-clock seconds spent, set on completion.
        error: Error message when status is ``failed``.
    """

    tool: str
    system: str
    status: Literal["pending", "running", "done", "failed"] = "pending"
    elapsed_seconds: float | None = None
    error: str | None = None


def _format_elapsed(start: float) -> str:
    """Format elapsed time since start as HH:MM:SS or MM:SS.

    Args:
        start: Monotonic timestamp from time.monotonic().

    Returns:
        Formatted duration string.
    """
    elapsed = int(time.monotonic() - start)
    hours, remainder = divmod(elapsed, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    return f"{minutes}:{seconds:02d}"


class InvestigationDashboard:
    """Live terminal dashboard for forensic investigation progress.

    Renders a Rich Live display with two regions:
    - A fixed stats header showing phase, tokens, throughput, and findings.
    - A scrolling log panel showing assistant reasoning and tool calls.

    All output goes through Rich's console, which properly manages
    terminal cursor state and prevents corruption from the SDK
    subprocess writing its own ANSI sequences.
    """

    def __init__(self) -> None:
        """Initialize the dashboard."""
        self._console = Console(stderr=True)
        # Seed psutil so the first real call returns accurate data
        psutil.cpu_percent(interval=None)
        self._live: Live | None = None
        self._start_time = time.monotonic()

        self._phase_label = ""
        self._phase_num = 0
        self._total_phases = 0
        self._phase_model = ""
        self._phase_max_turns = 0
        self._tool_count = 0
        self._total_findings = 0
        self._severity_counts: dict[str, int] = {}
        self._input_tokens = 0
        self._output_tokens = 0
        self._model_tokens: dict[str, dict[str, int]] = {}

        self._log_lines: deque[Text] = deque(maxlen=500)

        self._tasks: list[TaskItem] = []
        self._tasks_active: bool = False
        self._spinner_frame: int = 0

        self._extraction_total: int = 0
        self._extraction_done: int = 0
        self._extraction_active: int = 0

        self._psutil_cache_time: float = 0.0
        self._psutil_cache: tuple[float, float, float] = (0.0, 0.0, 0.0)

        self._system_color_map: dict[str, str] = {}
        self._next_color_idx: int = 0

    def _get_system_color(self, system: str) -> str:
        """Return a consistent color for a system name.

        Assigns colors from a rotating palette so each system gets a
        unique, stable color across the entire dashboard lifetime.

        Args:
            system: System identifier string.

        Returns:
            Rich style color name.
        """
        if system not in self._system_color_map:
            color = _SYSTEM_COLORS[self._next_color_idx % len(_SYSTEM_COLORS)]
            self._system_color_map[system] = color
            self._next_color_idx += 1
        return self._system_color_map[system]

    def _log_and_display(self, text: str, style: str = "white") -> None:
        """Append styled text to the log panel and write to the file logger.

        Args:
            text: Display text (may include leading whitespace for indent).
            style: Rich style string applied to the entire line.
        """
        logger.info("[dashboard] %s", text.strip())
        styled = Text(text, style=style)
        self._log_lines.append(styled)

    def start(self) -> None:
        """Enter the Live display context."""
        self._live = Live(
            self._build_layout(),
            console=self._console,
            refresh_per_second=4,
            redirect_stdout=True,
            redirect_stderr=True,
            vertical_overflow="crop",
            get_renderable=self._build_layout,
        )
        self._live.start()

    def stop(self) -> None:
        """Exit the Live display context and restore the terminal."""
        if self._live is not None:
            self._live.stop()
            self._live = None

    def set_phase(
        self,
        label: str,
        phase_num: int,
        total_phases: int,
        model: str,
        max_turns: int,
    ) -> None:
        """Update the current phase in the stats header.

        Args:
            label: Human-readable phase label.
            phase_num: Current phase number (1-indexed).
            total_phases: Total number of phases.
            model: Model being used for this phase.
            max_turns: Maximum turns allowed for this phase.
        """
        self._phase_label = label
        self._phase_num = phase_num
        self._total_phases = total_phases
        self._phase_model = model
        self._phase_max_turns = max_turns

        logger.info(
            "[dashboard] Phase [%d/%d] %s (model=%s, max_turns=%d)",
            phase_num,
            total_phases,
            label,
            model,
            max_turns,
        )

        self._log_lines.append(Text())
        separator = Text(f"{'━' * 58}", style="dim")
        self._log_lines.append(separator)
        phase_line = Text(f"  [{phase_num}/{total_phases}] {label}", style="bold")
        self._log_lines.append(phase_line)
        detail = Text(f"  {model}", style="dim")
        self._log_lines.append(detail)
        self._log_lines.append(separator)

        self._refresh()

    def set_extraction_counts(self, total: int, done: int, active: int) -> None:
        """Update extraction progress counters for the phase header.

        Called from the rolling worker pool as systems start and finish.
        Updates the phase label to reflect current progress.

        Args:
            total: Total number of extraction groups.
            done: Number of groups completed so far.
            active: Number of groups currently running.
        """
        self._extraction_total = total
        self._extraction_done = done
        self._extraction_active = active
        self._phase_label = f"Phase 2: Extraction ({done}/{total} done, {active} active)"

    def log(self, text: str) -> None:
        """Append a line of assistant reasoning to the log panel.

        Detects ``[system-name]`` prefixes and colorizes them using
        the per-system color palette.

        Args:
            text: Raw text from an assistant TextBlock.
        """
        for line in text.strip().splitlines():
            stripped = line.strip()
            if stripped:
                logger.info("[dashboard] %s", stripped)
                match = _SYSTEM_PREFIX_RE.match(stripped)
                if match:
                    system = match.group(1)
                    color = self._get_system_color(system)
                    styled = Text("  ")
                    styled.append(f"[{system}]", style=color)
                    styled.append(f" {stripped[match.end() :]}", style="white")
                else:
                    styled = Text(f"  {stripped}", style="white")
                self._log_lines.append(styled)

    def log_tool(self, name: str) -> None:
        """Log a tool call in the scrolling panel.

        Args:
            name: MCP tool name (without mcp__mulder__ prefix).
        """
        self._tool_count += 1
        self._log_and_display(f"  ▸ {name}", style="dim green")

    def log_finding(self, severity: str, title: str) -> None:
        """Log a finding submission with color-coded severity.

        Args:
            severity: Severity level (critical, high, medium, low, informational).
            title: Finding title text.
        """
        self._total_findings += 1
        sev_lower = severity.lower()
        self._severity_counts[sev_lower] = self._severity_counts.get(sev_lower, 0) + 1
        logger.info("[dashboard] [%s] %s", severity.upper(), title)
        style = _SEVERITY_STYLES.get(sev_lower, "bold white")
        dot = _SEVERITY_DOTS.get(sev_lower, "⚪")
        label = severity.upper()
        line = Text()
        line.append(f"  {dot} [{label}] ", style=style)
        line.append(title)
        self._log_lines.append(line)

    def log_phase_done(self, tool_count: int, turns: int, tokens: int) -> None:
        """Log phase completion stats in the scrolling panel.

        Args:
            tool_count: Number of tool calls in the phase.
            turns: Number of turns consumed.
            tokens: Total tokens used in the phase.
        """
        msg = (
            f"  Done: {tool_count} tool calls, {turns} turns, {format_token_count(tokens)} tokens"
        )
        logger.info("[dashboard] %s", msg.strip())
        line = Text(msg, style="bold dim")
        self._log_lines.append(line)

    def log_gate_pass(self, label: str, turns: int) -> None:
        """Log a successful gate check.

        Args:
            label: Phase label.
            turns: Total turns for the phase.
        """
        self._log_and_display(f"  ✓ {label} ({turns} turns)", style="bold green")

    def log_gate_fail(self, message: str) -> None:
        """Log a failed gate check.

        Args:
            message: Failure description.
        """
        self._log_and_display(f"  ✗ {message}", style="bold red")

    def log_info(self, text: str) -> None:
        """Log an informational message (retries, limits, etc.).

        Args:
            text: Message to display.
        """
        self._log_and_display(f"  · {text}", style="dim yellow")

    def set_tasks(self, system: str, tools: list[str]) -> None:
        """Register pending tasks for a system in the progress panel.

        Called after the planner produces a plan for an extraction phase.
        Tasks are appended so multiple systems can coexist.

        Args:
            system: System identifier (e.g. ``base-dc``).
            tools: Ordered tool names from the plan.
        """
        for tool in tools:
            self._tasks.append(TaskItem(tool=tool, system=system))
        self._tasks_active = True

    def update_task(
        self,
        system: str,
        tool: str,
        status: Literal["pending", "running", "done", "failed"],
        elapsed: float | None = None,
        error: str | None = None,
    ) -> None:
        """Update status of a specific task, creating it if necessary.

        Uses upsert semantics: finds the first matching task that is not
        already ``done`` and applies the new status. If no matching task
        exists, a new ``TaskItem`` is created so the panel reactively
        reflects actual execution without requiring pre-population.

        Args:
            system: System identifier.
            tool: Tool name to update.
            status: New status value.
            elapsed: Elapsed seconds (typically set on completion).
            error: Error message (set when status is ``failed``).
        """
        for task in self._tasks:
            if task.system == system and task.tool == tool and task.status != "done":
                task.status = status
                task.elapsed_seconds = elapsed
                task.error = error
                return

        self._tasks.append(
            TaskItem(
                tool=tool,
                system=system,
                status=status,
                elapsed_seconds=elapsed,
                error=error,
            )
        )
        self._tasks_active = True

    def clear_tasks(self) -> None:
        """Remove all tasks and hide the progress panel."""
        self._tasks = []
        self._tasks_active = False

    def clear_system_tasks(self, system: str) -> None:
        """Remove all tasks for a specific system from the panel.

        Args:
            system: System identifier whose tasks should be removed.
        """
        self._tasks = [t for t in self._tasks if t.system != system]
        if not self._tasks:
            self._tasks_active = False

    def add_tokens(self, input_tokens: int, output_tokens: int) -> None:
        """Accumulate token usage.

        Accepts negative values for reconciliation corrections when the
        authoritative ResultMessage total is lower than the incremental
        sum (e.g. due to unexpected duplicate messages).

        Args:
            input_tokens: Input token delta (positive or negative).
            output_tokens: Output token delta (positive or negative).
        """
        self._input_tokens += input_tokens
        self._output_tokens += output_tokens
        logger.debug(
            "Dashboard tokens: +(%d in, %d out) -> total %d in, %d out",
            input_tokens,
            output_tokens,
            self._input_tokens,
            self._output_tokens,
        )

    def add_model_usage(self, model_usage: dict[str, Any]) -> None:
        """Accumulate per-model token usage from ResultMessage.model_usage.

        The model_usage dict maps model names to dicts with camelCase
        keys: inputTokens, outputTokens, cacheCreationInputTokens,
        cacheReadInputTokens.

        Args:
            model_usage: Per-model usage dict from the SDK.
        """
        for model_name, usage in model_usage.items():
            if not isinstance(usage, dict):
                logger.warning(
                    "Unexpected model_usage value for '%s': %s",
                    model_name,
                    type(usage).__name__,
                )
                continue
            if model_name not in self._model_tokens:
                self._model_tokens[model_name] = {"input": 0, "output": 0}
            tok_in = usage.get("inputTokens", 0) or 0
            tok_out = usage.get("outputTokens", 0) or 0
            self._model_tokens[model_name]["input"] += tok_in
            self._model_tokens[model_name]["output"] += tok_out
            logger.debug(
                "Model usage '%s': +(%d in, %d out)",
                model_name,
                tok_in,
                tok_out,
            )

    @property
    def total_findings(self) -> int:
        """Current total finding count."""
        return self._total_findings

    @property
    def input_tokens(self) -> int:
        """Cumulative input token count."""
        return self._input_tokens

    @property
    def output_tokens(self) -> int:
        """Cumulative output token count."""
        return self._output_tokens

    @property
    def start_time(self) -> float:
        """Monotonic start timestamp."""
        return self._start_time

    @property
    def model_tokens(self) -> dict[str, dict[str, int]]:
        """Per-model token usage accumulated during the investigation."""
        return self._model_tokens

    @staticmethod
    def suppress_stderr(_line: str) -> None:
        """No-op stderr callback for the Agent SDK.

        Suppresses all SDK subprocess stderr output to prevent
        terminal corruption. Passed as the ``stderr`` parameter
        to ``ClaudeAgentOptions``.
        """

    def _build_task_panel(self) -> Panel | None:
        """Build the extraction task progress panel.

        Prioritizes active (running/pending) systems when the terminal
        is too short to show everything. Fully completed systems are
        collapsed into a summary line at the bottom.

        Returns a Rich Panel with per-system task rows when tasks are
        active, or None when no tasks are registered.
        """
        if not self._tasks_active or not self._tasks:
            return None

        # Derive spinner frame from wall clock so it always animates
        # even when the panel isn't being rebuilt frequently
        spinner_idx = int(time.monotonic() * 8) % len(_SPINNER_FRAMES)
        spinner = _SPINNER_FRAMES[spinner_idx]

        terminal_height = shutil.get_terminal_size().lines
        # Panel border + title take ~3 lines; header takes ~8
        available_lines = max(6, terminal_height - 11)

        systems_ordered: list[str] = []
        system_tasks: dict[str, list[TaskItem]] = {}
        for task in self._tasks:
            if task.system not in system_tasks:
                system_tasks[task.system] = []
                systems_ordered.append(task.system)
            system_tasks[task.system].append(task)

        active_systems = [
            s
            for s in systems_ordered
            if any(t.status in ("running", "pending") for t in system_tasks[s])
        ]
        done_systems = [
            s
            for s in systems_ordered
            if all(t.status in ("done", "failed") for t in system_tasks[s])
        ]

        num_active = max(len(active_systems), 1)
        per_system_budget = max(4, (available_lines - num_active) // num_active)

        def _system_line_count(system: str) -> int:
            """Header line + visible tasks + overflow line + separator."""
            task_count = min(len(system_tasks[system]), per_system_budget)
            overflow = 1 if len(system_tasks[system]) > per_system_budget else 0
            return 1 + task_count + overflow + 1

        content = Text()
        lines_used = 0

        for system in active_systems:
            needed = _system_line_count(system)
            if lines_used + needed > available_lines and lines_used > 0:
                break
            self._append_system_block(
                content,
                system,
                system_tasks[system],
                spinner,
                per_system_budget,
            )
            lines_used += needed

        remaining_space = available_lines - lines_used
        shown_done = 0
        for system in done_systems:
            needed = _system_line_count(system)
            if remaining_space < needed + 1:
                break
            self._append_system_block(
                content,
                system,
                system_tasks[system],
                spinner,
                per_system_budget,
            )
            remaining_space -= needed
            shown_done += 1

        hidden_done = len(done_systems) - shown_done
        if hidden_done > 0:
            label = "system" if hidden_done == 1 else "systems"
            content.append(f"\n  ({hidden_done} {label} completed)", style="dim green")

        return Panel(content, title="🔍 Evidence Analysis", border_style="dim")

    def _append_system_block(
        self,
        content: Text,
        system: str,
        tasks: list[TaskItem],
        spinner: str,
        max_tasks: int = 8,
    ) -> None:
        """Append a system header and its task rows to the panel content.

        Args:
            content: Rich Text object to append to (mutated in place).
            system: System identifier.
            tasks: Task items belonging to this system.
            spinner: Current spinner character for running tasks.
            max_tasks: Maximum task rows to display for this system.
        """

        if content.plain:
            content.append("\n")
        system_color = self._get_system_color(system)
        content.append(f"  {system}\n", style=f"bold {system_color}")

        # Prioritize showing running/pending tasks over completed ones
        active_tasks = [t for t in tasks if t.status in ("running", "pending")]
        done_tasks = [t for t in tasks if t.status in ("done", "failed")]
        prioritized = active_tasks + done_tasks
        visible_tasks = prioritized[:max_tasks]
        hidden_count = len(prioritized) - max_tasks

        for task in visible_tasks:
            if task.status == "pending":
                icon = "○"
                style = "dim"
                suffix = ""
            elif task.status == "running":
                icon = spinner
                style = "yellow"
                suffix = "running..."
            elif task.status == "done":
                icon = "●"
                style = "green"
                suffix = (
                    f"done ({task.elapsed_seconds:.0f}s)"
                    if task.elapsed_seconds is not None
                    else "done"
                )
            else:
                icon = "✗"
                style = "red"
                suffix = task.error or "failed"

            line = f"    {icon} {task.tool:<28} {suffix}\n"
            content.append(line, style=style)

        if hidden_count > 0:
            content.append(f"    ... +{hidden_count} more\n", style="dim")

    def _build_layout(self) -> Layout:
        """Build the dashboard layout with optional side-by-side task panel.

        When tasks are active the body splits horizontally: the log
        panel takes 2/3 width on the left and the task panel takes 1/3
        on the right. Without tasks the log takes the full width.
        """
        header_size = 8
        layout = Layout()
        task_panel = self._build_task_panel()

        if task_panel:
            body = Layout(name="body")
            body.split_row(
                Layout(self._build_log_panel(), name="logs", ratio=2),
                Layout(task_panel, name="tasks", ratio=1),
            )
            layout.split_column(
                Layout(self._build_stats_panel(), name="header", size=header_size),
                body,
            )
        else:
            layout.split_column(
                Layout(self._build_stats_panel(), name="header", size=header_size),
                Layout(self._build_log_panel(), name="logs"),
            )

        return layout

    def _total_tokens_from_models(self) -> int:
        """Compute total tokens from per-model tracking.

        Returns the sum across all models, or 0 if no model data exists.
        """
        if not self._model_tokens:
            return 0
        return sum(c["input"] + c["output"] for c in self._model_tokens.values())

    def _effective_total_tokens(self) -> int:
        """Return the best available total token count.

        Prefers per-model data (populated via model_usage on Vertex)
        over the main accumulator (populated via usage, often empty
        on Vertex).
        """
        model_total = self._total_tokens_from_models()
        if model_total > 0:
            return model_total
        return self._input_tokens + self._output_tokens

    def _get_system_stats(self) -> tuple[float, float, float]:
        """Return cached (cpu_percent, mem_used_gb, mem_total_gb).

        Caches psutil calls with a 2-second TTL to avoid expensive
        system calls on every panel rebuild (4 Hz).
        """
        now = time.monotonic()
        if now - self._psutil_cache_time > 2.0:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            self._psutil_cache = (cpu, mem.used / (1024**3), mem.total / (1024**3))
            self._psutil_cache_time = now
        return self._psutil_cache

    def _build_stats_panel(self) -> Panel:
        """Build the fixed stats header panel with clean visual sections."""
        elapsed = _format_elapsed(self._start_time)
        total_tok = self._effective_total_tokens()
        elapsed_min = (time.monotonic() - self._start_time) / 60.0
        tpm = int(total_tok / elapsed_min) if elapsed_min > 0.1 else 0

        table = Table.grid(padding=(0, 3))
        table.add_column(justify="left")
        table.add_column(justify="left")
        table.add_column(justify="left")
        table.add_column(justify="left")

        phase_str = (
            f"[bold cyan][{self._phase_num}/{self._total_phases}] {self._phase_label}[/]"
            if self._phase_label
            else "[dim]Starting...[/]"
        )
        table.add_row(phase_str, "", "", "")

        model_str = self._phase_model or "pending"
        table.add_row(
            f"[dim]{model_str}[/]",
            "",
            "",
            "",
        )

        table.add_row(
            f"[green]Tools: {self._tool_count}[/]",
            f"[yellow]Findings: {self._total_findings}[/]",
            f"Tokens: {format_token_count(total_tok)}",
            f"{format_token_count(tpm)}/min",
        )

        cpu, mem_used_gb, mem_total_gb = self._get_system_stats()
        mem_pct = (mem_used_gb / mem_total_gb * 100.0) if mem_total_gb > 0 else 0.0
        table.add_row(
            f"[dim]CPU: {cpu:.0f}%[/]",
            f"[dim]MEM: {mem_used_gb:.1f}/{mem_total_gb:.0f} GB ({mem_pct:.0f}%)[/]",
            f"[dim]{elapsed}[/]",
            "",
        )

        return Panel(table, title="Mulder", border_style="blue")

    def _build_log_panel(self) -> Panel:
        """Build the scrolling log panel from the deque."""
        terminal_height = shutil.get_terminal_size().lines
        available = max(5, terminal_height - 8)

        skip = max(0, len(self._log_lines) - available)
        recent = list(islice(self._log_lines, skip, None))

        content = Text()
        for i, line in enumerate(recent):
            if i > 0:
                content.append("\n")
            content.append_text(line)

        return Panel(content, title="Investigation Log", border_style="dim")

    def _refresh(self) -> None:
        """Refresh the live display with updated content."""
        if self._live is None:
            return
        layout = self._build_layout()
        self._live.update(layout)

    def _format_findings_summary(self) -> str:
        """Format findings total with per-severity dot breakdown.

        Returns:
            String like ``23 (3🔴 8🟠 9🟡 3🔵)`` or just the count
            when no severity data is available.
        """
        if not self._severity_counts:
            return str(self._total_findings)

        order = ["critical", "high", "medium", "low", "informational", "info"]
        seen: set[str] = set()
        parts: list[str] = []
        for sev in order:
            if sev in seen:
                continue
            count = self._severity_counts.get(sev, 0)
            if count > 0:
                dot = _SEVERITY_DOTS.get(sev, "⚪")
                parts.append(f"{count}{dot}")
            if sev == "informational":
                seen.add("info")
            elif sev == "info":
                seen.add("informational")
            seen.add(sev)

        if parts:
            return f"{self._total_findings} ({' '.join(parts)})"
        return str(self._total_findings)

    def print_summary(self, result: InvestigationResult) -> None:
        """Print the final investigation summary after Live stops.

        Args:
            result: InvestigationResult with phase outcomes.
        """
        total_tok = self._effective_total_tokens()
        elapsed = time.monotonic() - self._start_time
        elapsed_min = elapsed / 60.0
        tpm = int(total_tok / elapsed_min) if elapsed_min > 0.1 else 0
        m, s = divmod(int(elapsed), 60)
        h, m = divmod(m, 60)
        elapsed_str = f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"

        # Derive in/out from model tokens if available
        if self._model_tokens:
            total_in = sum(c["input"] for c in self._model_tokens.values())
            total_out = sum(c["output"] for c in self._model_tokens.values())
        else:
            total_in = self._input_tokens
            total_out = self._output_tokens

        summary = Table(title="Investigation Complete", border_style="blue", show_header=False)
        summary.add_column("Metric", style="bold")
        summary.add_column("Value")
        summary.add_row("Turns", str(result.total_turns))
        summary.add_row(
            "Tokens",
            f"{format_token_count(total_tok)} "
            f"(in: {format_token_count(total_in)}, "
            f"out: {format_token_count(total_out)})",
        )
        summary.add_row("Throughput", f"{format_token_count(tpm)}/min")
        summary.add_row("Findings", self._format_findings_summary())
        summary.add_row("Elapsed", elapsed_str)

        # Per-model breakdown
        for model_name, counts in sorted(self._model_tokens.items()):
            m_in = counts["input"]
            m_out = counts["output"]
            m_total = m_in + m_out
            if m_total == 0:
                continue
            short_name = model_name.replace("claude-", "").replace("-2025", "")
            detail = (
                f"{format_token_count(m_in)} in / "
                f"{format_token_count(m_out)} out = "
                f"{format_token_count(m_total)}"
            )
            summary.add_row(f"  {short_name}", detail)

        self._console.print()
        self._console.print(summary)

        phases_table = Table(title="Phase Results", border_style="dim")
        phases_table.add_column("Phase")
        phases_table.add_column("Status")
        phases_table.add_column("Turns", justify="right")
        for phase in result.phases:
            status_style = "bold green" if phase.success else "bold red"
            status_text = "PASS" if phase.success else "FAIL"
            phases_table.add_row(
                phase.phase_name,
                Text(status_text, style=status_style),
                str(phase.turns_used),
            )

        self._console.print(phases_table)
