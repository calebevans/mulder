# Mulder Implementation Roadmap: Full-Service SIFT Agent

This document breaks the improvement roadmap into **8 self-contained implementation units**. Each unit is scoped so it can be handed to a planning agent independently. Units are ordered by dependency -- later units may reference patterns established in earlier ones, but each is independently implementable.

---

## Architecture Context

Every unit must follow these patterns from the existing codebase:

- **Extractor protocol** (`src/mulder/extractors/base.py`): Classes implement `can_handle(path) -> bool`, `extract(path, case_id) -> list[ExtractionResult]`, `version() -> str`. Register in `default_registry()`.
- **MCP tools** (`src/mulder/server/tools_core.py`): Decorated with `@mcp.tool()`, return a dict with `tool_call_id`, `results`, `source`, `result_count`, `reduced`, `reduction_ratio`. Every call is logged to the JSONL audit trail.
- **Ingest-time extraction**: Heavy parsing runs during `mulder ingest`, producing `ExtractionResult` objects whose `text_output` gets windowed, embedded, and stored in sqlite-vec.
- **Query-time tools**: Lightweight MCP tools that query the sqlite-vec index or shell out to CLI tools on demand (hybrid model).
- **Audit logging**: Every tool call gets a `tool_call_id`, params, output_hash, and duration_ms written to the JSONL audit file.

Key files to understand before any unit:
- `src/mulder/extractors/base.py` -- Extractor protocol and registry
- `src/mulder/extractors/volatility.py` -- Example extractor (subprocess + parallel workers)
- `src/mulder/server/tools_core.py` -- Example MCP tools (ingest-time data)
- `src/mulder/server/tools_composite.py` -- Example composite tools (join multiple sources)
- `src/mulder/server/app.py` -- Server context and initialization
- `.claude/skills/investigate.md` -- Investigation strategy (Claude Code skill)

---

## Unit 1: Expand Volatility Plugins -- COMPLETE

**Goal**: Expand from 8 to ~20 Windows plugins, add Linux plugin support.

**Approach**: Ingest-time (existing pattern -- add plugins to `PLUGINS` list, everything else is automatic).

### Files to modify
- `src/mulder/extractors/volatility.py` -- Add plugins to `PLUGINS` list

### Windows plugins to add
```python
PLUGINS = [
    # Existing
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.malfind.Malfind",
    "windows.dlllist.DllList",
    "windows.svcscan.SvcScan",
    "windows.handles.Handles",
    # NEW -- Process analysis
    "windows.psscan.PsScan",        # Pool-tag scan (finds hidden/exited processes)
    "windows.envars.Envars",        # Environment variables per process
    "windows.privs.Privs",          # Token privileges (SeDebugPrivilege = red flag)
    "windows.getsids.GetSIDs",      # Process security context
    # NEW -- Network
    "windows.netstat.NetStat",      # Active connections at capture time
    # NEW -- Registry from memory
    "windows.registry.hivelist.HiveList",      # Loaded hive addresses
    "windows.registry.userassist.UserAssist",  # GUI execution evidence
    # NEW -- Files and modules
    "windows.filescan.FileScan",    # All files cached in memory
    "windows.modules.Modules",      # Kernel modules (linked list)
    "windows.modscan.ModScan",      # Kernel modules (pool scan -- finds hidden)
    # NEW -- Injection analysis
    "windows.vadinfo.VadInfo",      # VAD tree for detailed injection analysis
]
```

### Linux plugin support
- Add a detection mechanism: try `windows.info.Info` first; if it fails, try `linux.bash.Bash` to determine OS type
- Add Linux plugin list:
```python
LINUX_PLUGINS = [
    "linux.pslist.PsList",
    "linux.pstree.PsTree",
    "linux.bash.Bash",
    "linux.check_modules.Check_modules",
    "linux.lsmod.Lsmod",
    "linux.sockstat.Sockstat",
    "linux.lsof.Lsof",
    "linux.elfs.Elfs",
    "linux.tty_check.tty_check",
    "linux.proc.Maps",
]
```
- Source names: `volatility.pslist`, `volatility.bash`, etc. (keep the `volatility.` prefix, drop the OS namespace)

### New MCP tools to add in `tools_core.py`
- `scan_hidden_processes()` -- queries `volatility.psscan`, compares against `volatility.pslist` to find discrepancies
- `get_process_environment(pid: int)` -- filters `volatility.envars` windows by PID
- `get_process_privileges(pid: int)` -- filters `volatility.privs` windows by PID
- `scan_kernel_modules()` -- queries `volatility.modules` vs `volatility.modscan`, returns diff
- `get_userassist()` -- returns all windows from `volatility.userassist`
- `scan_files_in_memory()` -- returns all windows from `volatility.filescan`

### Composite tool updates in `tools_composite.py`
- `find_suspicious_processes` -- add psscan diff, envars check, privs check to the analysis
- Use `_source_exists()` helper (already added) to gracefully handle missing sources

### Acceptance criteria
- `mulder ingest` with a Windows memory dump produces sources for all new plugins
- `mulder ingest` with a Linux memory dump auto-detects OS and runs Linux plugins
- New MCP tools return results for the new sources
- Composite tools use the expanded data when available

---

## Unit 2: Sleuth Kit Filesystem Forensics -- COMPLETE

**Goal**: Add TSK-based filesystem analysis as both an extractor (ingest-time) and query-time MCP tools.

**Approach**: Hybrid -- extract filesystem listing and timeline at ingest time; expose `icat` (file extraction) and `mmls` (partition listing) as query-time tools.

### New files to create
- `src/mulder/extractors/sleuthkit.py` -- New extractor

### Extractor: `SleuthKitExtractor`
- **Handles**: `.e01`, `.dd`, `.img` (same as DiskImageExtractor, but runs TSK instead of mounting)
- **Ingest-time operations**:
  - `mmls <image>` -- partition table → source `tsk.partitions`
  - `fls -r -p <image>` -- recursive file listing with deleted files → source `tsk.filelist`
  - `fls -r -m / <image>` then `mactime -b - -z UTC` -- filesystem timeline → source `tsk.timeline`
  - `fsstat <image>` -- filesystem metadata → source `tsk.fsstat`
- **Produces**: `ExtractionResult` per output, text gets embedded for semantic search
- Uses `shutil.which("fls")` to check availability; skips gracefully if not installed
- Needs to handle partition offsets: run `mmls` first, parse the NTFS partition start sector, pass `-o <sector>` to subsequent commands

### New MCP tools (query-time) in new file `src/mulder/server/tools_tsk.py`
- `list_partitions()` -- returns `tsk.partitions` source windows
- `list_files(path_filter: str | None, include_deleted: bool)` -- returns `tsk.filelist` windows, optionally filtered
- `get_deleted_files()` -- filters `tsk.filelist` for entries starting with `*` (TSK deleted marker)
- `get_fs_timeline(t_start: str, t_end: str)` -- returns `tsk.timeline` windows in time range, Cordon-reduced
- `extract_file_by_inode(inode: int)` -- query-time: shells out to `icat` and returns file content as text (read-only, text files only; binary files return hash + metadata)
- `get_file_metadata(inode: int)` -- query-time: shells out to `istat` and returns MAC times, size, blocks

### Registration
- Add to `default_registry()` in `base.py` between Plaso and Disk extractors
- Import in `tools_tsk.py` same pattern as existing tool modules
- Add `import mulder.server.tools_tsk as _tools_tsk` to `app.py`

### Evidence path handling
- Store the original image path in case metadata or a server context field so query-time tools know where to run `icat`/`istat`
- Partition offset from `mmls` should be cached during ingest

---

## Unit 3: Eric Zimmerman Tools -- COMPLETE

**Goal**: Add structured parsing of Windows artifacts using EZ Tools available at `/opt/zimmermantools/` on SIFT.

**Approach**: Ingest-time extraction. EZ Tools produce CSV output which is far richer than the current RegRipper/stat-based approaches.

### New files to create
- `src/mulder/extractors/eztools.py` -- New extractor

### Extractor: `EZToolsExtractor`
- **Handles**: Runs against mounted disk images or extracted artifact files. Triggered when specific artifact paths are found.
- **Detection**: Check `shutil.which("dotnet")` and existence of `/opt/zimmermantools/`
- **Tools to integrate (ingest-time)**:

| Tool | Input | Source name | What it produces |
|------|-------|-------------|-----------------|
| PECmd | `./exports/prefetch/` or mounted Prefetch dir | `ez.prefetch` | Last 8 run times, referenced DLLs per executable |
| AmcacheParser | `Amcache.hve` | `ez.amcache` | Program execution with SHA1 hashes |
| AppCompatCacheParser | `SYSTEM` hive | `ez.shimcache` | File existence evidence (chronological on Win7) |
| MFTECmd | `$MFT` (inode 0) | `ez.mft` | Full MFT with timestamps, sizes, parent directories |
| MFTECmd | `$J` (UsnJrnl) | `ez.usnjrnl` | File system change journal |
| EvtxECmd | `.evtx` files | `ez.evtx.<channel>` | Structured event log parsing with maps |
| RECmd | Registry hives | `ez.registry.<hive>` | Batch registry analysis with predefined plugins |
| JLECmd | Jump lists | `ez.jumplists` | User file access history |
| LECmd | LNK files | `ez.lnkfiles` | Shortcut targets (execution evidence) |
| SBECmd | UsrClass.dat | `ez.shellbags` | Folder access history |
| RBCmd | $Recycle.Bin | `ez.recyclebin` | Deleted file metadata |
| SrumECmd | SRUDB.dat | `ez.srum` | Network, app, energy usage over 30-60 days |

- **CLI pattern**: `dotnet /opt/zimmermantools/<Tool>.dll -f <input> --csv <output_dir> --csvf <filename>`
- Parse CSV output into text for embedding (one line per row, or structured summary)

### New MCP tools in `src/mulder/server/tools_eztools.py`
- `parse_prefetch_detailed()` -- returns `ez.prefetch` windows
- `parse_amcache()` -- returns `ez.amcache` windows
- `parse_shimcache()` -- returns `ez.shimcache` windows
- `parse_mft(t_start, t_end)` -- returns `ez.mft` windows in time range, Cordon-reduced
- `parse_usn_journal(t_start, t_end)` -- returns `ez.usnjrnl` windows in time range, Cordon-reduced
- `parse_jump_lists()` -- returns `ez.jumplists` windows
- `parse_lnk_files()` -- returns `ez.lnkfiles` windows
- `parse_shellbags()` -- returns `ez.shellbags` windows
- `parse_srum()` -- returns `ez.srum` windows

### Dependency on Unit 2
- MFT extraction (`icat <image> 0`) comes from Sleuth Kit
- If Unit 2 is not yet implemented, fall back to extracting from mounted filesystem path

---

## Unit 4: YARA Threat Hunting -- COMPLETE

**Goal**: Add YARA scanning as query-time MCP tools.

**Approach**: Query-time only. YARA scans are targeted operations the agent requests against specific files or the memory image.

### New files to create
- `src/mulder/server/tools_yara.py` -- New MCP tools

### MCP tools
- `yara_scan_files(target_path: str, rules: str | None)` -- Scan files on a mounted filesystem or extracted directory. `rules` is a YARA rule string or path to a .yar file. Uses `/usr/local/bin/yara -r -s`.
- `yara_scan_memory(rules: str | None)` -- Scan the memory image. Target path comes from case metadata.
- `yara_scan_with_volatility(pid: int | None, rules: str | None)` -- Uses Volatility's `windows.vadyarascan` plugin to scan process memory.

### Built-in rule sets
- Ship a small set of detection rules in `src/mulder/yara_rules/` covering:
  - Common malware strings (mimikatz, cobalt strike beacons, meterpreter)
  - Suspicious PE characteristics (high entropy sections, no exports)
  - Known IOC patterns (encoded PowerShell, base64 blobs)
- If community rulesets exist on SIFT (`/opt/signature-base/`, `/opt/yara-rules/`), use those

### Security boundary
- YARA is read-only by design -- it only reads files, never modifies
- Rules can be agent-generated (string passed via MCP) or pre-built (path on disk)
- Output: list of matches with rule name, matched strings, file path, and offset

### Registration
- Add `import mulder.server.tools_yara as _tools_yara` to `app.py`

---

## Unit 5: Improved Plaso Integration -- COMPLETE

**Goal**: Upgrade Plaso from basic to production-quality.

**Approach**: Ingest-time improvements + new query-time filtering tools.

### Files to modify
- `src/mulder/extractors/plaso.py` -- Improve extraction

### Ingest-time improvements
- **Parser presets**: Add `--parsers win10` by default for Windows images, `--parsers linux` for Linux. Auto-detect from filesystem structure.
- **VSS support**: Add `--vss-stores all` flag when processing disk images
- **Hashing**: Add `--hashers md5,sha256` for file hashing during ingest
- **Targeted parsing**: If specific directories are passed (e.g., just EVTX dir), use appropriate parser (`--parsers winevtx`)
- **pinfo.py integration**: After ingest, run `pinfo.py -v` and store parser hit statistics as a source (`plaso.stats`)

### New MCP tools in `src/mulder/server/tools_plaso.py`
- `get_plaso_stats()` -- Returns parser hit statistics from `plaso.stats`
- `filter_timeline(t_start, t_end, keyword: str | None, parser: str | None)` -- Query-time: runs `psort.py` with filters against the stored `.plaso` file and returns results. Uses `--slice` for quick pivots.
- `export_timeline_slice(timestamp: str)` -- Query-time: runs `psort.py --slice <timestamp>` for 5-minute window around an event

### Plaso storage management
- Store the `.plaso` file path in case metadata so query-time tools can find it
- Keep the `.plaso` file alongside the `.db` file in `~/.mulder/cases/`

---

## Unit 6: Bulk Extractor Integration -- COMPLETE

**Goal**: Add `bulk_extractor` for IOC carving across disk images.

**Approach**: Ingest-time extraction with large output Cordon-reduced.

### New files to create
- `src/mulder/extractors/bulk.py` -- New extractor

### Extractor: `BulkExtractorExtractor`
- **Handles**: `.e01`, `.dd`, `.img` (runs in parallel with Plaso/TSK)
- **Runs**: `bulk_extractor -o <tmpdir> <image>`
- **Produces one source per feature file**:
  - `bulk.email` -- extracted email addresses
  - `bulk.url` -- extracted URLs
  - `bulk.domain` -- extracted domain names
  - `bulk.telephone` -- phone numbers
  - `bulk.ccn` -- credit card numbers (PII indicator)
  - `bulk.ip` -- IP addresses
  - `bulk.elf` / `bulk.exe` -- carved executables
- Each feature file is read and stored as a source; Cordon-reduced at query time if large

### New MCP tool
- `get_carved_iocs(feature: str | None)` -- Returns windows from `bulk.<feature>` sources. If no feature specified, returns summary counts for each feature type.

---

## Unit 7: Agent Prompt and Response Improvements -- COMPLETE

**Goal**: Update the system prompt to reference all new tools and fix the tool response format to prevent agent hallucination of errors.

**Approach**: Modify prompts and tool response formatting.

### Files to modify
- `.claude/skills/investigate.md` -- Investigation strategy skill (replaces agent/prompts.py)
- `src/mulder/server/tools_core.py` -- Response format improvements
- `src/mulder/server/tools_composite.py` -- Response format improvements

### Prompt changes
Update the investigation skill to include:

```
### Phase 2 -- Broad Sweep
- Run composite tools:
  - find_suspicious_processes() -- memory process anomalies
  - find_persistence_mechanisms() -- registry, services, startup, scheduled tasks
  - find_lateral_movement_indicators() -- logon events, network, RDP
- Run YARA sweep: yara_scan_files() with built-in detection rules
- Check execution evidence: parse_prefetch_detailed(), parse_amcache(), parse_shimcache()
- Check IOC indicators: get_carved_iocs() for bulk_extractor results

### Phase 3 -- Filesystem Analysis
- Use get_deleted_files() to check for deleted evidence
- Use get_fs_timeline() for filesystem-level timeline around events of interest
- Use parse_usn_journal() for file system change journal

### Phase 4 -- Deep Dive
(existing content plus):
- Use filter_timeline() for targeted Plaso queries
- Use extract_file_by_inode() to recover specific files
- Use scan_hidden_processes() to compare pslist vs psscan
- Use get_process_privileges() to check for privilege escalation
- Use scan_kernel_modules() for rootkit detection
```

### Response format improvements
Add explicit `"status": "success"` or `"status": "error"` to every tool response dict:
```python
return {
    "tool_call_id": tc_id,
    "status": "success",  # or "error" with "error_message"
    "results": results,
    "source": source,
    "result_count": len(results),
    "reduced": False,
    "reduction_ratio": None,
}
```

When a source doesn't exist, return:
```python
return {
    "tool_call_id": tc_id,
    "status": "success",
    "results": [],
    "result_count": 0,
    "note": "Source 'volatility.pslist' not found. This case may not include memory evidence.",
}
```

This prevents the agent from hallucinating "authentication errors" when tools return empty results.

### Investigation skill update
The `.claude/skills/investigate.md` file already includes: "If composite tools return empty results, check `list_sources` output to determine which artifact types are actually available and adapt your strategy. Empty results from memory tools mean no memory dump was ingested, not an error."

---

## Unit 8: Composite Tool Enhancements -- COMPLETE

**Goal**: Update composite tools to use expanded data sources and improve detection quality.

**Approach**: Modify existing composite tools and add new ones.

### Files to modify
- `src/mulder/server/tools_composite.py`

### `find_suspicious_processes` improvements
- Add psscan vs pslist comparison (hidden process detection)
- Add privilege checking (SeDebugPrivilege, SeTcbPrivilege)
- Add environment variable analysis (injected env indicators)
- Add DLL anomaly checking (DLLs loaded from unusual paths)
- Use `_source_exists()` for all source queries (already partially done)

### `find_persistence_mechanisms` improvements
- Query `ez.shimcache` for persistence-related executables
- Query `ez.amcache` for recently installed programs
- Query `ez.prefetch` for execution of persistence-related tools
- Query scheduled tasks from EZ Tools or EVTX
- Query `tsk.filelist` for files in startup directories

### `find_lateral_movement_indicators` improvements
- Query `ez.evtx.security` (structured) instead of raw EVTX
- Add RDP session analysis from EVTX and Plaso
- Add WinRM detection (Event IDs 91, 168, 169)
- Query `ez.srum` for network usage anomalies

### New composite tool: `find_data_exfiltration_indicators`
- Query `bulk.url` for external upload services
- Query `bulk.email` for data exfiltration via email
- Query `bulk.domain` for known C2 domains
- Query `volatility.netscan` for connections to high ports
- Query Plaso timeline for large file access patterns

### New composite tool: `find_execution_evidence`
- Join `ez.prefetch` + `ez.amcache` + `ez.shimcache` + `ez.jumplists` + `ez.lnkfiles`
- Cross-reference with process tree from memory
- Produce a unified execution timeline

### New composite tool: `find_defense_evasion`
- Check for timestomping (UsnJrnl vs MFT timestamp discrepancies)
- Check for log clearing (Event IDs 104, 1102)
- Check for hidden processes (psscan vs pslist diff)
- Check for hidden kernel modules (modscan vs modules diff)
- Check for disabled security (YARA rule for AV/EDR process termination patterns)

---

## Dependency Graph

```
Unit 1 (Volatility)     -- no dependencies
Unit 2 (Sleuth Kit)     -- no dependencies
Unit 3 (EZ Tools)       -- benefits from Unit 2 (icat for MFT extraction)
Unit 4 (YARA)           -- no dependencies
Unit 5 (Plaso)          -- no dependencies
Unit 6 (Bulk Extractor) -- no dependencies
Unit 7 (Prompts)        -- should run AFTER Units 1-6 to reference all new tools
Unit 8 (Composites)     -- should run AFTER Units 1-6 to use all new sources
```

Units 1-6 can be implemented in parallel. Units 7-8 should run last.

---

## Estimated Scope Per Unit

| Unit | New files | Modified files | New MCP tools | Complexity |
|------|-----------|---------------|---------------|------------|
| 1. Volatility | 0 | 3 | 6 | Medium |
| 2. Sleuth Kit | 2 | 2 | 6 | Medium |
| 3. EZ Tools | 2 | 2 | 9 | Large |
| 4. YARA | 1-2 | 1 | 3 | Small |
| 5. Plaso | 1 | 2 | 3 | Medium |
| 6. Bulk Extractor | 1 | 2 | 1 | Small |
| 7. Prompts | 0 | 3 | 0 | Small |
| 8. Composites | 0 | 1 | 3 | Large |

---

## Testing Strategy

Each unit should be tested with:
1. **EVTX-ATTACK-SAMPLES** -- EVTX-only dataset (already available at `~/cases/evtx-test`)
2. **A Windows memory dump** -- e.g., Volatility sample images (Units 1, 4)
3. **A Windows disk image** -- e.g., from DFRWS or CyberDefenders (Units 2, 3, 5, 6)
4. **Full SIFT OVA** -- validate all tools are on PATH and produce expected output
