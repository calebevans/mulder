# Mulder Architecture V2: Agent-Driven Lazy Extraction

## Problem with Current Architecture

The current `ingest_evidence` tool runs **every extractor against every evidence file up front**. For the SRL-2015 dataset (4 disk images + 4 memory dumps), this means:
- 24 extraction tasks (8 evidence files x 3+ extractors each)
- Plaso running for 30-60 minutes per E01 (even if the agent never queries the timeline)
- bulk_extractor carving IOCs from all 4 disk images (even if the agent only needs one)
- Total ingestion time: 1-3 hours before the agent can start investigating

A real analyst doesn't work this way. They orient first, form hypotheses, and run targeted tools based on what they find.

## New Architecture: Agent Drives Everything

Instead of pre-ingesting, the agent decides which tools to run, when, and against which evidence files. Each tool call runs the extraction on demand, indexes the results into the DB, and returns a summary. The agent builds the case incrementally.

```
User: "Investigate the evidence at /evidence/SRL-2015/"

Agent's thought process:
1. "Let me see what evidence files are available" → calls scan_evidence("/evidence/SRL-2015/")
2. "I see 4 disk images and 4 memory dumps. Let me start with memory -- faster results"
3. "Run process listing on the domain controller memory" → calls run_volatility("pslist", "/evidence/.../controller-memory-raw.001")
4. "I see suspicious process PID 1234. Let me check for injection" → calls run_volatility("malfind", "/evidence/.../controller-memory-raw.001")
5. "Found injected code. Let me check the disk for persistence" → calls run_sleuthkit("fls", "/evidence/.../controller-c-drive.E01")
6. "I see a suspicious file. Let me check the timeline around that timestamp" → calls run_plaso("/evidence/.../controller-c-drive.E01", time_range="2015-08-01/2015-08-05")
7. Submits findings as it goes
```

## MCP Tool Surface (Redesigned)

### Tier 1: Orientation (no extraction needed)

These tools help the agent understand what evidence is available before running anything.

| Tool | Purpose |
|------|---------|
| `scan_evidence(path)` | Walk the evidence directory, classify files by type (disk image, memory dump, EVTX, logs). Return a manifest of what's available with sizes. Does NOT extract or ingest anything. |
| `list_sources()` | List what has already been extracted and indexed in the current case DB. Initially empty -- grows as the agent runs tools. |
| `list_cases()` | List previously ingested cases. |
| `open_case(case_id)` | Switch to a previous case. |

### Tier 2: Extract-on-Demand Tools

Each of these runs a specific forensic tool against a specific evidence file, indexes the output into the DB, and returns a summary. The agent chooses which to run and in what order.

**Memory Analysis (Volatility)**

| Tool | Purpose |
|------|---------|
| `run_volatility(plugin, memory_path)` | Run a single Volatility 3 plugin (e.g., "pslist", "netscan", "malfind") against a memory dump. Indexes the output and returns a summary. |

The agent sees the available plugins and chooses which to run based on its investigation strategy. It doesn't need to run all 18 plugins -- maybe it only needs pslist, netscan, and malfind for a given memory dump.

**Filesystem Analysis (Sleuth Kit)**

| Tool | Purpose |
|------|---------|
| `run_fls(image_path)` | Run recursive file listing on a disk image. Indexes and returns summary. |
| `run_mactime(image_path, time_range?)` | Generate MAC timeline for a disk image, optionally filtered to a time range. |
| `get_deleted_files(image_path)` | Extract deleted file entries from a disk image. |
| `extract_file(image_path, inode)` | Extract a specific file by inode number. |

**Timeline (Plaso)**

| Tool | Purpose |
|------|---------|
| `run_plaso(evidence_path, parsers?, time_range?)` | Run log2timeline against a specific evidence file with optional parser and time filters. This is the expensive one -- but now the agent can choose to run it only on the most relevant evidence, or with targeted parsers instead of the full suite. |

**Windows Artifacts (EZ Tools)**

| Tool | Purpose |
|------|---------|
| `parse_prefetch(image_path)` | Parse prefetch files from a mounted disk image. |
| `parse_amcache(image_path)` | Parse Amcache from a disk image. |
| `parse_shimcache(image_path)` | Parse ShimCache from a disk image. |
| `parse_mft(image_path, time_range?)` | Parse $MFT with optional time filter. |
| `parse_evtx(evtx_path_or_dir)` | Parse Windows event logs. |
| `parse_registry(image_path, hive?)` | Parse registry hives. |

**IOC Hunting**

| Tool | Purpose |
|------|---------|
| `run_bulk_extractor(image_path, features?)` | Carve IOCs from a disk image. Optional feature filter (e.g., just URLs, just emails). |
| `run_yara(target_path, rules?)` | Scan files or memory with YARA rules. |

### Tier 3: Query Tools (same as current)

These query the DB for whatever has been indexed so far. They get richer as the agent runs more Tier 2 tools.

| Tool | Purpose |
|------|---------|
| `search(query, source?)` | Semantic search across all indexed data. |
| `get_anomalies_in_range(source, t_start, t_end)` | Anomaly-scored windows. |
| `correlate_across_sources(t_start, t_end)` | Cross-source correlation. |
| `baseline_for(source)` | Statistical baseline. |

### Tier 4: Findings (same as current)

| Tool | Purpose |
|------|---------|
| `submit_finding(...)` | Submit a validated finding with evidence refs. |
| `get_findings()` | List current findings. |
| `finalize_report()` | Generate the Markdown report. |

## How Extraction + Indexing Works

Each Tier 2 tool follows the same pattern:

```
1. Agent calls run_volatility("pslist", "/evidence/memory.001")
2. Tool runs: vol -f /evidence/memory.001 windows.pslist.PsList
3. Tool captures the text output
4. Tool windows + embeds the output (using the configured embedding backend)
5. Tool stores windows in the case DB as source "volatility.pslist"
6. Tool returns a summary to the agent: "Found 47 processes. Notable: cmd.exe (PID 1234), powershell.exe (PID 5678)"
7. The output is now searchable via search(), correlate_across_sources(), etc.
```

The case DB and embedding config are managed at the server level (same as current). The difference is that the DB starts empty and grows incrementally as the agent runs tools.

## What Changes from Current Architecture

### Remove
- `run_ingestion()` function in `cli.py` (the big batch pipeline)
- `ingest_evidence` MCP tool (replaced by scan_evidence + individual tool calls)
- `mulder ingest` CLI command (or keep as a convenience that runs all extractors)
- The parallel extraction Phase 1 / Phase 2 split

### Keep
- `ServerContext`, `ServerConfig`, `CaseDB`, `Embedder`, `QueryEngine`, `Correlator`, `OutputReducer`, `AuditLog` -- all the infrastructure stays
- The sqlite-vec index and embedding pipeline
- All Tier 3 query tools and Tier 4 finding tools
- The `.mcp.json`, Claude Code skill, slash command
- The Dockerfile with all forensic tools installed

### Add / Rewrite
- `scan_evidence` tool -- lightweight directory scan, no extraction
- Individual tool wrappers (Tier 2) that each run one extractor, index results, and return summaries
- A shared helper function: `_extract_and_index(tool_output_text, source_name, ...)` that handles windowing, embedding, and DB insertion (extracted from the current `run_ingestion` loop body)

### Modify
- `tools_core.py` -- the composite tools (`find_suspicious_processes`, etc.) should check what sources exist and suggest which Tier 2 tools to run if the needed sources aren't indexed yet
- The investigation skill (`.claude/skills/investigate.md`) -- update to teach the agent the new workflow: orient → hypothesize → targeted extraction → query → cross-verify → submit findings

## Benefits

1. **Faster time to first finding**: Agent can start investigating within seconds instead of waiting hours for full ingestion
2. **Agent-driven prioritization**: The agent decides what matters, not a hardcoded extraction order
3. **Resource efficiency**: Only extract what's needed. If the agent solves the case from memory analysis alone, disk images are never processed
4. **Better for the hackathon demo**: Shows genuine autonomous reasoning about tool selection, not just querying a pre-built index
5. **Matches how analysts actually work**: Orient, hypothesize, investigate, verify
6. **Directly addresses judging criterion #1**: "Does the agent reason about next steps?" -- yes, it reasons about which forensic tools to run

## Migration Path

This can be done incrementally:
1. Add `scan_evidence` tool (replaces the classification step)
2. Add `_extract_and_index` helper (factored out of current `run_ingestion`)
3. Add Tier 2 tool wrappers one at a time (Volatility first, then TSK, then Plaso, etc.)
4. Update the investigation skill
5. Keep `mulder ingest` CLI as an optional batch mode for users who prefer it
6. Remove `ingest_evidence` MCP tool (or keep it as "ingest everything" shortcut)

## Example Investigation Flow

```
Agent: scan_evidence("/evidence/SRL-2015-Compromised Enterprise Network/")
→ Returns: 4 disk images (E01), 4 memory dumps (.001), organized by host

Agent: run_volatility("pslist", "/evidence/.../win2008R2-controller-memory-raw.001")  
→ Returns: "72 processes found. source 'volatility.pslist.controller' indexed (247 windows)"

Agent: run_volatility("netscan", "/evidence/.../win2008R2-controller-memory-raw.001")
→ Returns: "34 network connections found. source 'volatility.netscan.controller' indexed (89 windows)"

Agent: search("suspicious outbound connection", source="volatility.netscan.controller")
→ Returns: connections to unusual external IPs

Agent: run_volatility("malfind", "/evidence/.../win2008R2-controller-memory-raw.001")
→ Returns: "3 processes with injected code found"

Agent: correlate_across_sources(t_start="2015-08-01", t_end="2015-08-05")
→ Cross-references pslist + netscan + malfind findings

Agent: submit_finding(title="Process injection in svchost.exe", ...)

Agent: "Now let me check the nromanoff workstation for lateral movement..."
Agent: run_volatility("pslist", "/evidence/.../win7-32-nromanoff-memory-raw.001")
→ And so on...
```

The agent never runs Plaso or bulk_extractor because it solved the case from memory analysis and targeted filesystem queries. Total investigation time: minutes instead of hours.
