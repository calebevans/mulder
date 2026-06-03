# Glossary

Project terminology and definitions for contributors and users of Mulder.

## Mulder Architecture

| Term | Definition |
|------|-----------|
| Analyst | The third agent role in a split-mode phase. Interprets execution results, queries indexed evidence, submits findings, and may request follow-up iterations. See `src/mulder/orchestrator/runner.py`. |
| Audit Log | Append-only JSONL file recording every MCP tool invocation with parameters, output hashes, durations, and timestamps. Enables provenance chain resolution from findings back to raw evidence. See `src/mulder/audit.py`. |
| Batch | A group of background extraction jobs submitted together via `start_extraction_batch`. Each batch has a unique ID (e.g. `bg_a1b2c3d4`) and can be polled with `check_extraction_status`. See `src/mulder/server/tools/jobs.py`. |
| Bookmark | A saved reference to an interesting evidence window with a note. Persists across context compaction so leads are not lost. Stored in the `bookmarks` table. |
| Case | A forensic investigation tracked by a unique `case_id`. Each case gets its own SQLite database file at `~/.mulder/cases/{case_id}.db` containing all indexed evidence, findings, and metadata. |
| CaseDB | The per-case SQLite database manager. Uses SQLAlchemy Core with WAL mode, FTS5 full-text search, and a single-writer thread queue to prevent BUSY errors under concurrent access. See `src/mulder/db.py`. |
| Compaction | The process of restarting an agent session when the context window is exhausted. The orchestrator spawns a continuation session with a prompt to recover state from the database, avoiding re-processing completed work. Limited to 3 compactions per role. See `_compaction_loop` in `src/mulder/orchestrator/runner.py`. |
| Composite Tool | A cross-source analysis tool that queries multiple indexed sources to detect patterns (persistence, lateral movement, exfiltration, etc.). Results are indexed as `composite.*` sources for subsequent phases. See `src/mulder/server/tools/composite/`. |
| Correlator | Engine that joins evidence windows from multiple sources within a time range, enabling cross-artifact analysis ("what did each source observe at time T?"). See `src/mulder/index/correlator.py`. |
| Evidence Context | A pre-built prompt string listing disk images, memory dumps, and nested archives for a specific system. Injected into the planner prompt so it can plan extraction without calling `list_directory`. Built by `_build_evidence_context` in the orchestrator. |
| Evidence Registry | Database table recording SHA-256 hashes and sizes of original evidence files for chain-of-custody verification. Populated during `scan_evidence`. |
| Executor | The second agent role in a split-mode phase. Receives a structured JSON plan from the planner and executes each tool call in sequence, reporting results. See `src/mulder/orchestrator/runner.py`. |
| Finding | A submitted investigation result backed by evidence references. Each finding has a severity (critical/high/medium/low/info), confidence level (confirmed/inference), MITRE ATT&CK mappings, evidence_refs (validated tool_call_ids), and source citations. See `src/mulder/models.py`. |
| Follow-up | An analyst-initiated request for additional investigation. The analyst emits a structured JSON follow-up that triggers a new planner/executor/analyst cycle within the same phase. Limited by `max_follow_ups` (default 2). |
| Gate / GateResult / GateCheck | Quality validation checkpoints between investigation phases. Each gate evaluates structured criteria (sources indexed, findings submitted, MITRE mappings present, etc.) and returns pass/fail with detailed gap descriptions. Failed gates trigger retries with increased budgets. See `src/mulder/orchestrator/gates.py`. |
| Investigation | A complete multi-phase forensic analysis run. Tracked by `InvestigationResult` which aggregates all phase results and total turn counts. |
| JobStore | In-process background job manager using a bounded thread pool. Decouples launching slow forensic tools from waiting for results. Supports deferred retry for timed-out jobs. See `src/mulder/server/jobs.py`. |
| MCP Server | The FastMCP server (`mulder serve`) exposing 140+ typed forensic tools over the Model Context Protocol via stdio or streamable-http transport. All tools are read-only with respect to evidence. See `src/mulder/server/app.py`. |
| Narrative | The long-form investigation report written as markdown with sections for Background, Incident Timeline, Key Findings, Impact Assessment, Recommendations, and Conclusion. Stored in the `case_metadata.narrative` column and rendered into the final report. |
| Orchestrator | The multi-phase investigation pipeline that sequences catalog, extraction, cross-system, alternative narrative, and report phases with quality gates. See `src/mulder/orchestrator/runner.py`. |
| Phase | A discrete stage of the investigation pipeline. Mulder uses five phases in sequence: Catalog, Extraction, Cross-System, Alternative Narrative, and Report. See `src/mulder/orchestrator/phases.py`. |
| Planner | The first agent role in a split-mode phase. Examines available evidence and outputs a structured JSON plan listing tool calls, investigation questions, and expected sources. See `src/mulder/orchestrator/runner.py`. |
| Provenance Chain | The full trace from a finding back to the original evidence files. Links finding_id to tool_call_ids (from the audit log) to source files (from registered sources via `db.get_sources()`). See `ProvenanceChain` in `src/mulder/models.py`. |
| Role | A `Flag` enum value declaring which pipeline stages may invoke a given MCP tool. Roles include CATALOG, EXTRACT_PLANNER, EXTRACT_EXECUTOR, EXTRACT_ANALYST, CROSS_PLANNER, CROSS_EXECUTOR, CROSS_ANALYST, NARRATIVE_PLANNER, NARRATIVE_EXECUTOR, NARRATIVE_ANALYST, and REPORT. See `src/mulder/server/tool_access.py`. |
| Single-mode Phase | A phase that runs one agent session for the entire task. Used by catalog (discovery) and report (generation) where the work is self-contained. Compare with split-mode. |
| Source | A named evidence stream in the case database. Each source has a unique hierarchical name (e.g. `volatility.pslist.host1`), a file hash, an extractor name, and a line count. Sources are registered via `register_source` and queried by name or prefix. |
| Split-mode Phase | A phase that decomposes work across three agent roles (planner, executor, analyst) running in separate SDK sessions. Used by extraction, cross-system, and alternative narrative phases. Compare with single-mode. |
| Tool Access | The declarative registry that maps MCP tools to the pipeline roles allowed to invoke them. Tools self-declare access via the `@tool_access` decorator placed below `@mcp.tool()`. See `src/mulder/server/tool_access.py`. |
| Window | The database unit of indexed evidence. Raw tool output is split into character-budget-limited chunks (default 4096 chars) with optional timestamp extraction. Stored in the `windows` table with FTS5 full-text indexing. See `extract_and_index` in `src/mulder/server/extract_helpers.py`. |

## Investigation Phases

| Term | Definition |
|------|-----------|
| Catalog Phase | Phase 1 (single-mode). Scans the evidence directory, creates the case database, identifies systems and evidence types, and outputs structured JSON listing all discovered systems. Validated by the catalog gate which checks for `case_id`, `evidence_root`, and a non-empty `systems` array. |
| Extraction Phase | Phase 2 (split-mode). Runs per-system with a rolling worker pool. The planner selects extraction tools, the executor runs them (with background batching), and the analyst reviews indexed evidence to submit findings. The gate requires at least one source to be indexed. |
| Cross-System Phase | Phase 3 (split-mode). Correlates evidence across all systems using composite tools and timeline analysis. The gate requires at least one finding with a MITRE ATT&CK technique mapping. |
| Alternative Narrative Phase | Phase 4 (split-mode). Challenges initial findings by seeking counter-evidence, deduplicates findings, runs audit tools, and ensures the investigation is ready for report generation. The gate checks finalize readiness. |
| Report Phase | Phase 5 (single-mode). Writes the investigation narrative via `submit_narrative` and generates the final HTML/Markdown report via `finalize_report`. The gate verifies that `finalize_report` was called. |
