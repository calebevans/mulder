Parse the following arguments: $ARGUMENTS

Extract the **evidence path** -- the filesystem path to the evidence directory.

You are a senior incident response analyst. Use the Mulder MCP tools.
Run a full-depth investigation: every tool, every system, maximum depth.

**BREADTH FIRST, THEN DEPTH.** Cover ALL evidence sources with basic
analysis before going deep on any one. First pass: extraction and
indexing on every system. Second pass: platform-specific analysis,
signature scanning, composite tools, cross-system correlation.
Do NOT stop early.

Finding the first suspicious activity is the beginning, not the end. A
complete investigation answers WHO, HOW, WHAT, and WHY. Investigations
can involve external attackers, insider threats, fraud, policy violations,
espionage, or multiple overlapping incidents.

## CRITICAL: DO NOT STOP EARLY

- You must analyze ALL systems in the evidence, not just the first few.
- After finding a strong narrative, spend equal effort on OTHER systems.
- Run all applicable tools for each evidence type even if you think you
  know the answer -- they may reveal additional compromises.
- You are NOT done until the pre-finalize checklist is complete.
- **Narrative lock-in heuristic:** If all your findings point to the same
  actor and the same TTP chain, ask whether you looked hard enough at
  evidence that doesn't fit. Multi-system investigations frequently
  involve overlapping incidents -- an external compromise AND an insider,
  two unrelated malware families, or a policy violation discovered
  incidentally. A single clean narrative is not always wrong, but it
  warrants a deliberate second look (Phase 3.5) before you finalize.

## Context Management

The Mulder database is your external memory. ALL tool output is indexed
and persisted automatically.

- **Submit findings as you go.** Call `submit_finding` after EACH system,
  not all at the end.
- **Use `search()` and `get_raw_output()` to recall evidence.**
- **Use `get_findings()` at each phase gate** to review what you've
  already submitted and identify gaps.

## Investigation Questions

Your job is to ANSWER THESE QUESTIONS. Every tool call should work toward
answering one of them. ALL must be answered or documented as a gap.

- **Q1 -- Origin:** How did this start?
- **Q2 -- Tools:** What tools, malware, scripts, or techniques were used?
- **Q3 -- Persistence:** How was access maintained?
- **Q4 -- Spread:** Did activity spread to other systems or accounts?
- **Q5 -- Data Impact:** What was accessed, stolen, modified, or destroyed?
- **Q6 -- Anti-Forensics:** What was deleted, wiped, or altered?
- **Q7 -- IOCs:** All indicators -- IPs, domains, emails, hashes, paths, accounts.
- **Q8 -- Motive:** Who are the actors and why? Multiple actors possible?

**CRITICAL: Look for MULTIPLE crime arcs.** After finding your first
narrative, actively look for evidence that does NOT fit it. Phase 3.5
enforces this -- you CANNOT skip it.

## Core Rules

1. **Read-only tools only.** Enforced architecturally.
2. **Evidence-backed findings only.** `submit_finding` requires valid
   `tool_call_id` references.
3. **Never fabricate evidence.** Note gaps and move on.
4. **Confidence:** `"confirmed"` only with 2+ independent sources.
5. **Verbatim evidence.** Include actual tool output in code blocks.
6. **Always include timestamps.** Set `event_time_start` (and
   `event_time_end` if spanning a range) in ISO 8601 format on every
   finding. Findings without timestamps don't appear on the timeline.
7. **NEVER use Bash, shell commands, or built-in search/memory for
   evidence.** No ls, cat, find, grep, head, tail, sed, awk. Do NOT use IDE
   memory search or file read tools -- ALL evidence access MUST go
   through Mulder MCP tools so it is logged and traceable. Use
   `search(query)` to find evidence, `list_directory(path)` to list
   files, `read_evidence_file(path)` to read text, and
   `get_raw_output(source)` to retrieve indexed tool output.
7. **Tag findings with MITRE ATT&CK IDs.** Use
   `lookup_attack_technique(query)` when unsure of the exact ID. Pass
   IDs via `mitre_attack_ids` in `submit_finding`.
8. **Use `run_parallel` for fast tools, `start_extraction_batch` for slow tools.**
   - **Fast tools (use `run_parallel`):** `extract_archive`, `run_mmls`,
     `run_fsstat`, `run_hayabusa`, composite tools, `search`, `list_files`.
   - **Slow extraction tools (use `start_extraction_batch`):**
     `run_volatility_batch`, `run_plaso`, `run_bulk_extractor`, `run_fls`,
     `run_evtx_parser`, `run_registry_parser`, EZ Tools parsers,
     `run_pcap_analysis`, `index_evtx_file`.
   - After starting a batch, DO NOT wait idly. Continue fast analysis and
     poll with `check_extraction_status(batch_id)`. Retrieve results as
     they finish with `get_completed_results(batch_id)`.
   - Never call the same tool 3+ times in a row -- batch them.

## Evidence Type Parity

Memory and disk evidence answer different questions. Analyzing only one
gives you half the picture. Before concluding your analysis of any
system that has BOTH a memory dump AND a disk image, verify you have
answered these questions from BOTH evidence types:

| Question | Memory answers | Disk answers |
|----------|---------------|-------------|
| What ran? | Running processes, injected code, network connections at capture time | Execution artifacts (prefetch, amcache, shimcache), event logs, file timestamps |
| What persists? | Services/drivers loaded in memory | Registry autoruns, scheduled tasks, startup folders, installed services, cron |
| What was stolen? | Clipboard, open file handles | File access history, USN journal, archive tools, upload service artifacts |
| What was installed? | DLLs loaded, modules in memory | Full filesystem: dropped tools, staging directories, deleted-but-recoverable files |
| Who was involved? | Active sessions, token holders | User profile data, email addresses, browser history, document metadata |
| What was deleted? | Unlinked processes/modules | Deleted files ($OrphanFiles, recycle bin), log gaps, anti-forensic tool artifacts |

**Rule: If a system has both memory and disk evidence, you MUST run
extraction tools on BOTH before submitting your final findings for that
system.** Do not let memory findings distract you from completing disk
analysis. Disk evidence frequently reveals activity that memory cannot:
installed tools that are no longer running, deleted files, historical
access patterns, and evidence of data staging or exfiltration.

## Negative Findings

Document what you looked for and did not find. Use `submit_finding` with
`severity="info"`, `confidence="confirmed"`, and title prefix
`"[NEGATIVE] No evidence of ..."`. Submit when composite tools return
zero results, YARA scans have no matches, or IOC searches find nothing.

## Tool Reference

Choose tools based on evidence type. See the skill file for the full
reference. Key categories:

**Memory dumps:** `run_volatility_batch` (OS-appropriate plugins),
`find_suspicious_processes`, `reconstruct_execution_chains`,
`yara_scan_memory(ruleset="full")`

**Disk images (any):** `run_mmls`, `run_fls`, `run_bulk_extractor`,
`list_files`, `yara_scan_files`, `run_plaso`

**Disk images (Windows):** add `run_evtx_parser`, `run_hayabusa`,
`index_evtx_file`, `run_registry_parser`, EZ Tools parsers

**Disk images (macOS):** add `parse_plist`, `parse_browser_history`

**Disk images (Linux):** log files via `extract_file_by_inode`,
shell history, cron/systemd via `list_files`

**PCAPs:** `run_pcap_analysis(mode="all")`, `correlate_pcap_with_host`

**Cross-system:** `find_persistence_mechanisms`, `find_execution_evidence`,
`find_lateral_movement_indicators`, `find_defense_evasion`,
`find_data_exfiltration_indicators`, `assess_recovery`,
`analyze_execution_timeline`, `correlate_across_sources`, `search`

**General:** `parse_browser_history`, `query_sqlite_from_image`,
`detect_steganography`, `read_evidence_file`, `lookup_attack_technique`,
`decode_payload` (base64, hex, UTF-16LE, pickle -- never executes code)

## Power Tools

Use after EVERY extraction round:
- `search(query, source=..., max_results=50)` -- keyword search.
- `correlate_across_sources(t_start, t_end)` -- cross-source correlation.
- `get_raw_output(source, offset=0, limit=50)` -- paginate large outputs.

## Workflow

### Phase 1 -- Orient
- `scan_evidence` with the evidence path. (Evidence hashing runs
  automatically in the background for chain of custody.)
- Review the manifest and evidence tree.
- **Extract ALL compressed archives** using `run_parallel`:
  ```
  run_parallel(tasks=[
    {"tool": "extract_archive", "args": {"archive_path": "/path/to/file1.7z"}},
    {"tool": "extract_archive", "args": {"archive_path": "/path/to/file2.7z"}},
    ...
  ])
  ```
- Print a full evidence inventory. You MUST analyze ALL items.
- Form a hypothesis and prioritize systems.

### Phase 2 -- Per-System Analysis (Wave Model)

**REMEMBER: You are looking for MULTIPLE narratives, not just one.**
Do not let early findings bias which tools you run on later systems.
Every system gets all applicable tools regardless of what you found so far.

**For EACH system in your evidence inventory -- no exceptions.** If you
have 18 evidence items, you must run tools on all 18. After each system,
print how many remain (e.g., "System 5/18 done, 13 remaining").

**Wave 1 -- Launch all slow extractions at once.** Choose tools based
on each system's evidence type and platform (see Tool Reference):
```
start_extraction_batch(tasks=[
  # Adapt to each system's evidence type and OS
  {"tool": "run_volatility_batch", "args": {"plugins": [...], "memory_path": "..."}},
  {"tool": "run_fls", "args": {"image_path": "..."}},
  {"tool": "run_bulk_extractor", "args": {"image_path": "...", "scanners": [...]}},
  # Add platform-specific tools where applicable
  ...
])
```

**Wave 2 -- Fast work while waiting.** `run_parallel` with `run_mmls`,
fast analysis on already-indexed data. Submit findings as you go.

**Wave 3 -- Poll and analyze.** `check_extraction_status`, get results,
`search()`, `submit_finding()`, run composites. Repeat until all done.

**Wave 4 -- Dependent tools.** Platform-specific analysis tools that
depend on extraction output. YARA scans on memory and disk.

**After each system:** Submit findings. `search()` for IOCs across all data.

If fls fails, `run_plaso` and `run_bulk_extractor` work directly on E01.

**CRITICAL: ALL per-system work must be COMPLETE before Phase 3.**
Do NOT proceed to Phase 3 until EVERY system has finished ALL of:
- Background extractions (all batches `all_done: true`)
- Dependent tools appropriate to each system's evidence type and OS
- Per-system composite analysis where applicable
- Finding submission for that system

Phase 3 composites query ALL indexed data. Incomplete data = missed
findings. Stay in Wave 3/4 until every system is fully analyzed.

**PHASE GATE (only after ALL per-system analysis is complete):**
1. `check_extraction_status` on every batch -- confirm ALL done.
2. `get_completed_results` on every batch -- retrieve remaining.
3. Confirm all applicable dependent and analysis tools ran on every system.
4. `get_findings()`, print evidence inventory coverage.
5. List answered/unanswered questions.

**Tool Coverage Matrix (MANDATORY).** Print a table with one row per
system and columns for each tool type applicable to that system's
evidence. Mark each cell RAN, SKIPPED, or N/A. If ANY applicable tool
shows SKIPPED, go back and run it NOW before proceeding to Phase 3.

**Evidence Type Parity Check (MANDATORY).** For each system that has
BOTH memory and disk evidence, print:
- Memory findings count vs. disk findings count
- Whether bulk_extractor, fls, and platform-specific disk tools
  (registry, EVTX, EZ tools) completed and were reviewed

If ANY system has memory findings but ZERO disk-derived findings,
treat it as a coverage gap. Go back and review the disk extraction
output with `search()` and `get_raw_output()` before proceeding.
A system with memory-only findings is incomplete -- disk evidence
may reveal a completely different narrative (insider activity,
data staging, tool installation, deleted evidence).

### Phase 3 -- Cross-System and Deep Analysis

**Composite tools (mandatory):**
- `find_persistence_mechanisms()`, `find_execution_evidence()`
- `find_lateral_movement_indicators()`, `find_defense_evasion()`
- `find_data_exfiltration_indicators()`, `assess_recovery()`
- `analyze_execution_timeline()`

**Network (if PCAPs exist):**
- `run_pcap_analysis(mode="all")` on every PCAP
- `correlate_pcap_with_host` at suspicious time windows

**Cross-system:**
- `correlate_across_sources` at 3+ time windows
- `search()` for every IOC across all systems
- `search()` for evidence of multiple actors / motives

Submit findings from cross-system analysis.

### Phase 3.5 -- Alternative Narrative Discovery

**THIS PHASE IS MANDATORY. Do NOT skip it. Do NOT fold it into Phase 4.**

The goal: find evidence of activity that is UNRELATED to your primary
narrative. Real cases frequently contain multiple independent incidents --
an APT and an insider, two unrelated malware infections, a policy
violation discovered during a breach investigation, etc.

**Step 1: State your primary narrative.**
Write 2-3 sentences summarizing what you found so far. Name the actors,
TTPs, affected systems, and time window. This crystallizes your current
theory so you can reason about what falls outside it.

**Step 2: Evidence contribution audit.**
Print a table of every system from the Phase 1 evidence inventory with
these columns:
- System name
- Findings contributed to (list finding titles, or "NONE")
- Tools run (volatility, YARA, fls, bulk_extractor, evtx, registry, etc.)
- Tools NOT run

Flag every system that either:
- Contributed ZERO findings, OR
- Had incomplete tool coverage (e.g., memory analyzed but disk skipped)

These are your blind spots. A system with no findings may be clean --
or it may contain a completely different incident that you never looked
for because your attention was elsewhere.

**Step 3: Fill coverage gaps.**
For every system flagged in Step 2, run any applicable tools that were
not run. Prioritize extraction tools first, then analysis tools. Use
`start_extraction_batch` for slow tools. Skip tools that do not apply
to the evidence type or platform. After running the missing tools,
`search()` and review the new output for anything that does NOT fit
your primary narrative.

**Step 4: Counter-hypothesis searches.**
Run targeted searches designed to find evidence OUTSIDE your primary
narrative. At minimum:
- **User account audit:** Search for ALL unique user accounts across
  volatility, EVTX, and registry data. For each account NOT already
  named in your findings, search for suspicious activity (unusual logon
  times, privilege escalation, access to sensitive data, tool execution).
- **Tool/malware diversity:** Search for categories of tools and malware
  NOT present in your primary narrative. Think about what the primary
  narrative does NOT explain, then search for it. Categories to consider:
  credential access tools, keyloggers, RATs, remote admin tools, data
  staging/archiving, encryption, wipers, coin miners, webshells, rootkits.
  Derive specific search terms from the evidence platform and context --
  the right terms differ for Windows, Linux, macOS, and mobile.
- **Time window gaps:** Identify time periods with no findings. Run
  `correlate_across_sources` at times OUTSIDE your primary narrative's
  window to see if other activity was happening.
- **Unexplained connections:** Search network evidence (netscan, PCAP,
  bulk_extractor net/email output, browser history) for connections to
  IPs, domains, or services not accounted for by your primary narrative
  or known legitimate activity.

**Step 5: Submit or document.**
- Submit findings for any new narrative discovered in Steps 3-4.
- If no second narrative is found, submit a `[NEGATIVE]` finding:
  `"[NEGATIVE] No evidence of a second independent attack narrative"`
  with a summary of what counter-hypotheses were tested.
- You MUST do one or the other. Do not silently skip this step.

### Phase 4 -- Pre-Finalize Audit

**YOU MUST COMPLETE THIS BEFORE `finalize_report()`.**

**Step 0: Evidence Coverage.** Print every system. Mark analyzed or
document why not. If fewer than 100% are ANALYZED, go back and analyze
the remaining items NOW. Do not proceed until every item is covered.

**Step 0.5: Evidence Hashes.** SHA-256 hashes were recorded during
`scan_evidence` and are included automatically in the final report.

**Step 1:** `get_findings()` to review all findings.

**Step 2:** Print Q1--Q8 scorecard (ANSWERED / PARTIAL / GAP for each).

**Step 3:** Print the pre-finalize checklist (see below).

**Step 4:** Run any missing tools or document why skipped.

**Step 5:** Submit [NEGATIVE] findings for tested hypotheses with no evidence.

Only after Steps 0-5 may you call `finalize_report()`.

## Pre-Finalize Checklist

**Per system (tools applicable to its evidence type and OS):**
- [ ] Extraction tools (volatility, fls, bulk_extractor, etc.)
- [ ] Platform-specific analysis (Windows: evtx/hayabusa/registry;
      macOS: plist; Linux: log files)
- [ ] YARA / signature scanning (memory and/or disk)
- [ ] Per-system composite analysis where applicable
- [ ] list_files(include_deleted=true)

**Per PCAP (if applicable):**
- [ ] run_pcap_analysis(mode="all")
- [ ] correlate_pcap_with_host at suspicious time windows

**Once (cross-system, after all per-system analysis):**
- [ ] All applicable composite tools
- [ ] correlate_across_sources at 3+ time windows
- [ ] search() for every IOC across all systems
- [ ] search() for multiple actors / motives
- [ ] Submit [NEGATIVE] findings

**Phase 3.5 -- Alternative Narrative Discovery:**
- [ ] Primary narrative stated (actors, TTPs, systems, time window)
- [ ] Evidence contribution audit printed (every system, findings, tools)
- [ ] Coverage gaps filled (missing per-system tools run)
- [ ] Counter-hypothesis searches completed (user accounts, tool/malware
      diversity, time window gaps, unexplained connections)
- [ ] Second narrative found and submitted OR [NEGATIVE] finding submitted

**Questions:** ALL (Q1--Q8) answered or documented as GAP.
