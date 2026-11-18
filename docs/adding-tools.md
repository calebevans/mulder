# Adding a New MCP Tool

This guide walks through adding a new tool to the Mulder MCP server, from function creation through registration and testing.

## 1. Create the Tool Function

### Where to Put It

Tool modules live under `src/mulder/server/tools/` (with the exception of `run_parallel`, which is defined in `src/mulder/server/app.py`). Choose a location based on the tool's purpose:

| Location | Purpose |
|----------|---------|
| `tools/extract/` | Extraction tools that run external binaries and index output (Volatility, TSK, Plaso, etc.) |
| `tools/composite/` | Cross-source analysis tools that combine data from multiple sources |
| `tools/core.py` | Query tools that read from the case database |
| `tools/<name>.py` | Standalone tool modules (e.g. `hayabusa.py`, `yara.py`, `bulk.py`) |

For a new extraction tool, add it to an existing file in `tools/extract/` or create a new module. For a new query tool, add it to `core.py` or a dedicated module.

### Required Decorators

Every tool needs two decorators, in this order:

```python
@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_my_tool(target_path: str, force: bool = False) -> dict[str, object]: ...
```

`@mcp.tool()` must come first (outermost) so MCPServer registers the function. `@tool_access(...)` must come second so it registers the unwrapped function name in the role registry before MCPServer wraps it.

Optionally, add `@audited_tool("tool_name")` as a third decorator to handle `tool_call_id` generation, timing, and audit logging automatically:

```python
@mcp.tool()
@tool_access(Role.EXTRACT_ANALYST | Role.CROSS_ANALYST)
@audited_tool("my_query_tool")
def my_query_tool(query: str) -> dict[str, object]: ...
```

When using `@audited_tool`, the wrapped function does not need to call `make_tool_call_id()`, measure elapsed time, or call `ctx.audit.log_tool_call()`. The decorator injects `tool_call_id` into the returned dict automatically.

### Function Signature

- Parameters should use plain types that MCPServer can serialize: `str`, `int`, `float`, `bool`, `list[str]`, `None`.
- The return type is always `dict[str, object]`.
- Use `| None` for optional parameters with a default of `None`.

### Docstring Contract

The first three sentences of the docstring form a contract that tells the agent **what** the tool does, **when** to call it, and **what it returns**:

```python
def run_my_tool(target_path: str) -> dict[str, object]:
    """Parse custom artifacts from a disk image using mytool.

    Call after evidence cataloging identifies files matching *.custom
    extension. Falls back to TSK extraction when FUSE mounting fails.

    Returns parsed artifact records indexed into the case database.

    Args:
        target_path: Path to the disk image (E01, dd, img).
    """
```

These three sentences are what the agent reads to decide whether and when to invoke the tool.

### Imports

Import the shared plumbing from the server package:

```python
from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    require_binary,
    run_subprocess,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access
```

## 2. Choose the Right Roles

The `Role` enum in [`src/mulder/server/tool_access.py`](../src/mulder/server/tool_access.py) declares which pipeline roles can call a tool. Each investigation phase uses a planner/executor/analyst split, and each role maps to a specific responsibility:

### Individual Roles

| Role | Phase | Responsibility |
|------|-------|----------------|
| `CATALOG` | Catalog | Evidence enumeration and classification |
| `EXTRACT_PLANNER` | Extraction | Decides which extraction tools to run |
| `EXTRACT_EXECUTOR` | Extraction | Calls extraction tools, manages retries |
| `EXTRACT_ANALYST` | Extraction | Queries indexed data, submits findings |
| `CROSS_PLANNER` | Cross-System | Plans cross-source correlation |
| `CROSS_EXECUTOR` | Cross-System | Runs correlation and enrichment tools |
| `CROSS_ANALYST` | Cross-System | Interprets correlated evidence |
| `NARRATIVE_PLANNER` | Alternative Narrative | Plans counter-evidence searches |
| `NARRATIVE_EXECUTOR` | Alternative Narrative | Executes additional evidence gathering |
| `NARRATIVE_ANALYST` | Alternative Narrative | Challenges findings, checks coverage |
| `REPORT` | Report | Generates final report |

### Semantic Shorthands

Combine roles with `|` or use the pre-defined shorthands:

| Shorthand | Expands To |
|-----------|------------|
| `PLANNERS` | `EXTRACT_PLANNER \| CROSS_PLANNER \| NARRATIVE_PLANNER` |
| `EXECUTORS` | `EXTRACT_EXECUTOR \| CROSS_EXECUTOR \| NARRATIVE_EXECUTOR` |
| `ANALYSTS` | `EXTRACT_ANALYST \| CROSS_ANALYST \| NARRATIVE_ANALYST` |
| `ALL_ROLES` | `CATALOG \| PLANNERS \| EXECUTORS \| ANALYSTS \| REPORT` |

### Guidelines

| Tool Type | Typical Roles |
|-----------|---------------|
| Extraction (runs a binary, indexes output) | `Role.EXTRACT_EXECUTOR` |
| Query (reads from case DB) | `Role.EXTRACT_ANALYST \| Role.CROSS_ANALYST` |
| Cross-source correlation | `Role.CROSS_EXECUTOR` |
| Enrichment (TI lookups, IOC matching) | `Role.CROSS_EXECUTOR` |
| Finding submission / management | `ANALYSTS` |
| Evidence browsing (list sources, stats) | Multiple phases as needed |

Start with the narrowest set of roles that makes sense. You can always expand later.

## 3. Index Output into the Database

### `extract_and_index()`

Use [`extract_and_index()`](../src/mulder/server/extract_helpers.py) for tools that produce searchable data. It splits raw output into fixed-size windows, extracts timestamps, hashes the content, and stores everything in the case database:

```python
from mulder.server.extract_helpers import extract_and_index

summary = extract_and_index(
    raw_output=proc.stdout.strip(),
    source_name="mytool.output",
    source_path=target_path,
    extractor_name="mytool",
)
```

The `source_name` is how agents reference this data later (e.g. `search(query, source="mytool.output")`). Use a dotted prefix convention: `toolname.artifact_type`.

### Log tables: `logtable.ingest()`

If the tool parses a log into events, also load them as rows, so the analyst can count with `log_top`, `log_histogram` and `log_rows` instead of paging through `search`. Index the text first, then pass the same events to [`ingest()`](../src/mulder/logtable.py) with the `source_id` that `extract_and_index()` returned:

```python
from mulder import logtable
from mulder.server.app import get_ctx

lines = [format_line(event) for event in events]  # one event per line
indexed = extract_and_index("\n".join(lines), "mylog.access", evidence_path, "mylog")


def rows():
    for number, event in enumerate(events, 1):
        if event is None:  # a record the parser could not read
            yield None
            continue
        yield {
            "event_time": event.time,  # ISO 8601, epoch seconds or ms, or a datetime
            "actor": event.user,
            "src_ip": event.client,
            "action": event.method,
            "target": event.path,
            "status": event.status,
            "user_agent": event.agent,
            "session_id": event.session,
            "bytes": event.size,
            "line": number,  # the event's line in the indexed text
            "extra": {"host": event.vhost},  # other fields worth counting on
        }


logtable.ingest(get_ctx().db, "mylog.access", int(str(indexed["source_id"])), rows())
```

- Every key is optional. Leave out what the log does not have rather than inventing a value; a field no row fills is not offered to the model.
- Name the table after the text source, so `list_sources` and `list_log_tables` agree.
- `extra` keys are constants you choose (`[a-z][a-z0-9_]*`), never names read from the evidence: they become fields the model may filter and group on. Keep them to a handful that answer counting questions.
- `rows` may be a generator; it is consumed in batches. Values are stored as one printable line of at most 512 characters, and a time `ingest()` cannot read is stored as no time and counted. A time without an offset is taken as UTC, so convert a local time or attach its offset first.
- Call `ingest()` once per source and table, with every row in the one iterable. It returns `{"rows", "rows_no_time", "rows_unparsed"}`. Running it again for a source of the same name and evidence path replaces the earlier rows. One source may feed more than one table.
- Yield `None` for whatever was not read: a record that did not parse, or a damaged or truncated stretch of the file. Every query result repeats the count, which is how the analyst learns that a count is over an incomplete log.
- If the tool reads a directory recursively, pass `nested=True`: one evidence path can then contain another, with the same events. A path inside one already loaded is not loaded again (the result carries `covered_by`, and `rows` is not read), and a directory replaces the rows of paths inside it. Without it, two overlapping paths are counted twice.
- A time before 1990 or after 2100 is stored as no time, so a zeroed or forged timestamp cannot become a first or last seen.

### `tool_response()` vs `@audited_tool()`

Use **one** of these two patterns for audit logging, not both:

- **`tool_response()`** for tools that manually manage `tool_call_id`, timing, and audit logging. Call `make_tool_call_id()` yourself, measure elapsed time, and pass everything to `tool_response()`:

```python
from mulder.server.helpers import tool_response

return tool_response(
    tc_id,
    "run_my_tool",
    params,
    summary,  # dict from extract_and_index or custom results
    "mytool.output",  # source name (or None if not indexed)
    elapsed,
)
```

- **`@audited_tool("tool_name")`** for tools that return a plain dict. The decorator handles `tool_call_id` generation, timing, and audit logging automatically. Do not call `make_tool_call_id()` or `tool_response()` inside the function.

**Truncation behavior:** When `source` is provided, `tool_response` returns only a preview of the output (first 500 chars). The full data lives in the database, accessible via `search()` or `get_raw_output()`. When `source` is `None`, the full results are returned in the response (appropriate for reference tools whose output is not indexed).

### `error_response()`

For error cases, use `error_response()` which logs the failure to the audit trail:

```python
from mulder.server.helpers import error_response

return error_response(
    tc_id,
    "run_my_tool",
    params,
    "mytool not found on PATH",
    error_type="binary_missing",
)
```

### Convenience: `run_cli_tool()`

For simple tools that run a binary and index its stdout, `run_cli_tool()` wraps the entire flow (binary check, subprocess execution, `extract_and_index`, `tool_response`) into a single call:

```python
from mulder.server.helpers import run_cli_tool

return run_cli_tool(
    binary="mytool",
    cmd=["mytool", "--json", target_path],
    tool_name="run_my_tool",
    params={"target_path": target_path},
    source_name="mytool.output",
    source_path=target_path,
    extractor_label="mytool",
    timeout=600,
)
```

## 4. Register the Module Import

After writing the tool module, import it in the appropriate `__init__.py` so the tool is registered at server startup.

For a top-level module (e.g. `tools/mytool.py`), add to [`src/mulder/server/tools/__init__.py`](../src/mulder/server/tools/__init__.py):

```python
from mulder.server.tools import (
    ...
    mytool,   # add alphabetically
    ...
)
```

For an extraction submodule (e.g. `tools/extract/mytool.py`), add to [`src/mulder/server/tools/extract/__init__.py`](../src/mulder/server/tools/extract/__init__.py):

```python
from mulder.server.tools.extract import (
    ...
    mytool,   # add alphabetically
    ...
)
```

The tool is automatically available to agents after import. No additional registration is needed since `@mcp.tool()` handles MCPServer registration and `@tool_access()` handles role registration at import time.

## 5. Add Skip Logic (Extraction Tools)

Extraction tools should be idempotent. If the data has already been indexed from a prior run, skip the extraction unless the caller explicitly requests a re-run.

### Check for Existing Sources

Use `sources_already_indexed()` at the top of the tool function:

```python
from mulder.server.helpers import sources_already_indexed, tool_response

if not force:
    existing = sources_already_indexed(
        ["mytool."],  # source name prefixes this tool produces
        evidence_path=target_path,  # scope check to this evidence file
    )
    if existing:
        return tool_response(
            tc_id,
            "run_my_tool",
            params,
            {
                "status": "skipped",
                "reason": "Sources already indexed from prior extraction",
                "existing_sources": existing,
            },
            "mytool.output",
            0.0,
        )
```

The `evidence_path` parameter ensures that running the same tool on a *different* evidence file is not blocked by results from a prior file.

### Register in `TOOL_SOURCE_PREFIXES`

Add your tool's source prefix mapping to `TOOL_SOURCE_PREFIXES` in [`src/mulder/server/helpers.py`](../src/mulder/server/helpers.py):

```python
TOOL_SOURCE_PREFIXES: dict[str, list[str]] = {
    ...
    "run_my_tool": ["mytool."],
    ...
}
```

This enables the orchestrator's batch submission logic to skip tools whose output already exists.

### Include the `force` Parameter

Always include `force: bool = False` so agents can explicitly re-run an extraction when needed:

```python
def run_my_tool(target_path: str, force: bool = False) -> dict[str, object]:
```

## 6. Test

### Verify the Tool Works

Confirm the tool registers correctly by running the test suite, which validates tool registration and role access:

```bash
pytest tests/ -k tool
```

For extraction tools, run a small test case. This requires a valid `.mcp.json` configuration in the working directory (or the container default) so the orchestrator can connect to the MCP server:

```bash
mulder investigate /path/to/test/evidence test-case
```

### Run Pre-commit and Pytest

```bash
pre-commit run --all-files
pytest
```

Pre-commit runs ruff (linting + formatting), mypy (strict type checking), and other checks. All code must pass before merging.

## Complete Example

Here is a minimal extraction tool that runs a hypothetical `custom-parser` binary on a disk image and indexes the output:

```python
"""Custom parser MCP tool for parsing proprietary log formats."""

from __future__ import annotations

import time

from mulder.server.app import mcp
from mulder.server.extract_helpers import extract_and_index
from mulder.server.helpers import (
    error_response,
    make_tool_call_id,
    require_binary,
    run_subprocess,
    sources_already_indexed,
    tool_response,
)
from mulder.server.tool_access import Role, tool_access


@mcp.tool()
@tool_access(Role.EXTRACT_EXECUTOR)
def run_custom_parser(
    target_path: str,
    log_format: str = "default",
    force: bool = False,
) -> dict[str, object]:
    """Parse proprietary log files using custom-parser.

    Call when evidence cataloging identifies .customlog files in the
    evidence directory. Extracts structured event records with timestamps
    and indexes them for cross-source correlation.

    Returns parsed event records indexed into the case database.

    Args:
        target_path: Path to the log file or directory containing logs.
        log_format: Parser format profile (default "default").
        force: Re-run extraction even if sources already exist.
    """
    tc_id = make_tool_call_id()
    t0 = time.monotonic()
    params: dict[str, object] = {
        "target_path": target_path,
        "log_format": log_format,
        "force": force,
    }

    # Skip if already indexed
    if not force:
        existing = sources_already_indexed(
            ["custom_parser."],
            evidence_path=target_path,
        )
        if existing:
            return tool_response(
                tc_id,
                "run_custom_parser",
                params,
                {
                    "status": "skipped",
                    "reason": "Sources already indexed from prior extraction",
                    "existing_sources": existing,
                },
                "custom_parser.events",
                0.0,
            )

    # Check binary availability
    if not require_binary("custom-parser"):
        return error_response(
            tc_id,
            "run_custom_parser",
            params,
            "custom-parser not found on PATH",
            error_type="binary_missing",
        )

    # Run the external tool
    result = run_subprocess(
        ["custom-parser", "--format", log_format, "--json", target_path],
        timeout=600,
    )
    if isinstance(result, str):
        return error_response(tc_id, "run_custom_parser", params, result, error_type="timeout")

    # Index output into the case database
    summary = extract_and_index(
        raw_output=result.stdout.strip(),
        source_name="custom_parser.events",
        source_path=target_path,
        extractor_name="custom_parser",
    )

    elapsed = (time.monotonic() - t0) * 1000
    return tool_response(
        tc_id, "run_custom_parser", params, summary, "custom_parser.events", elapsed
    )
```

After writing this module, you would:

1. Save it as `src/mulder/server/tools/extract/custom_parser.py`
2. Add `custom_parser,` to the imports in `src/mulder/server/tools/extract/__init__.py`
3. Add `"run_custom_parser": ["custom_parser."]` to `TOOL_SOURCE_PREFIXES` in `src/mulder/server/helpers.py`
4. Run `pre-commit run --all-files` and `pytest`
