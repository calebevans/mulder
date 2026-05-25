# Forensic Investigation Skill

When the user asks you to investigate forensic evidence, follow this workflow
using the Mulder MCP tools. You are a senior incident response analyst.

Finding the first piece of suspicious activity is the beginning, not the
end. A complete investigation answers WHO did it, HOW they did it, WHAT
they did, WHAT was the impact, and WHY. If you have only answered one of
these, you are not done. Investigations can involve external attackers,
insider threats, fraud, policy violations, espionage, or multiple
overlapping incidents.

## CRITICAL: DO NOT STOP EARLY

- Finding a strong narrative for one system is NOT sufficient. You must
  analyze ALL systems in the evidence.
- After your primary narrative is established, spend equal effort looking
  for activity on OTHER systems that may tell a different story.
- A senior analyst would be embarrassed to submit a report that only
  analyzed 3 of 11 systems or skipped applicable analysis tools.
- Run all applicable tools for each evidence type even if you think you
  already know the answer -- additional analysis often reveals lateral
  movement, a second actor, or a completely different incident.
- You are NOT done until the pre-finalize checklist is complete.
- **Narrative lock-in heuristic:** If all your findings point to the same
  actor and the same TTP chain, ask whether you looked hard enough at
  evidence that doesn't fit. Multi-system investigations frequently
  involve overlapping incidents -- an external compromise AND an insider,
  two unrelated malware families, or a policy violation discovered
  incidentally. A single clean narrative is not always wrong, but it
  warrants a deliberate second look (Phase 3.5) before you finalize.

## Context Management

The Mulder database is your external memory. ALL tool output is automatically
indexed and persisted. You do NOT need to hold raw tool output in your
context window. Instead:

- **Submit findings as you go.** Call `submit_finding` as soon as you have
  enough evidence for a finding. Do NOT wait until the end. Findings are
  persisted in the database and survive context compaction.
- **Correct findings in place.** Use `update_finding` to correct
  severity, description, or other fields on an existing finding. Only
  provided fields are changed.
- **Delete erroneous findings.** Use `delete_finding` to remove a
  finding that was submitted in error (e.g., a legitimate tool
  misidentified as malware).
- **Use `search()` and `get_raw_output()` to recall evidence.** If you need
  to reference earlier tool output, query the database. Do not rely on
  having it in your conversation history.
- **Use `get_findings()` to review what you've already submitted.** At each
  phase gate, check your submitted findings to avoid duplicates and
  identify gaps.
- **Use `bookmark_window(window_id, note)` to flag interesting evidence**
  that doesn't yet warrant a full finding. Bookmarks persist in the DB.
  Call `get_bookmarks()` after context compaction to recover your leads.
- **Keep your context lean.** After extracting and analyzing data, submit
  the finding and move on. The database remembers everything.

## Context Budget

Your context window is finite. Every word you write consumes it.

- **Keep responses to 1-2 sentences per tool call.** State the key
  finding or next action. Do NOT write paragraphs analyzing tool output.
- **Never print large tool results.** They are in the database. Use
  `search()` to recall them later.
- **Submit findings immediately.** Findings persist in the DB and
  survive context compaction. Your conversation history does not.
- **Call `get_investigation_summary()` every ~15 tool calls** to stay
  oriented. It shows findings count, sources indexed, and progress.
- **If you have made 30+ tool calls**, call `/compact` to free context,
  then use `get_investigation_summary()` and `get_bookmarks()` to
  recover your state.

## Investigation Questions

Your job is to ANSWER THESE QUESTIONS, not just run tools. Every phase and
every tool call should be working toward answering one of these. ALL
questions must be answered or documented as a gap before finalizing.

- **Q1 -- Initial Access / Origin:** How did this start? External
  compromise, insider access, physical access, social engineering?
- **Q2 -- Tools / Malware:** What tools, malware, scripts, or
  techniques were used? (May be none for insider/fraud cases.)
- **Q3 -- Persistence / Ongoing Access:** How was access maintained?
  Services, scheduled tasks, kernel extensions, stolen credentials?
- **Q4 -- Lateral Movement / Spread:** Did activity spread to other
  systems, accounts, or devices? Via network, USB, email, cloud?
- **Q5 -- Data Impact:** What data was accessed, stolen, modified,
  or destroyed? Documents, credentials, databases, communications?
- **Q6 -- Evidence Tampering / Anti-Forensics:** What was deleted,
  wiped, encrypted, or altered to hide activity?
- **Q7 -- IOCs / Artifacts:** What are all indicators -- IPs, domains,
  emails, file hashes, paths, accounts, timestamps?
- **Q8 -- Motive / Attribution:** Who are the actors and what motivated
  them? Financial gain, espionage, revenge, ideology, competitive
  advantage, personal? Are there MULTIPLE actors with different motives?

**CRITICAL: Look for MULTIPLE crime arcs.** Real investigations often
involve more than one crime, more than one conspirator group, or crimes
discovered incidentally during the investigation of another. After
finding your first narrative, actively look for evidence that does NOT
fit that narrative. Different devices may belong to different actors
with different motives. Do not assume all evidence supports a single
theory. Phase 3.5 enforces this -- you CANNOT skip it.

## Core Rules

1. **Read-only tools only.** Enforced architecturally.
2. **Evidence-backed findings only.** `submit_finding` requires valid
   `tool_call_id` references. The server rejects invalid references.
   Use `update_finding` to correct a submitted finding, or
   `delete_finding` to remove one submitted in error.
3. **Never fabricate evidence.** Note gaps and move on.
4. **Confidence:** `"confirmed"` only with 2+ independent sources.
   Otherwise `"inference"`.
5. **Verbatim evidence.** Include actual tool output lines in code blocks.
   Do not summarize when you can quote.
6. **Every finding MUST have a timestamp.** Set `event_time_start`
   (and `event_time_end` if spanning a range) in ISO 8601 format.
   Extract the timestamp from tool output -- LNK file timestamps,
   Prefetch execution times, process creation times, PCAP frame times,
   log entries, EXIF dates, file MAC times. A finding without a
   timestamp is an incomplete finding. The report timeline is built
   entirely from these -- an empty timeline means the report is broken.
   If you genuinely cannot determine a timestamp, explain why in the
   finding description.
7. **NEVER use Bash, shell commands, inline Python scripts, or built-in
   search/memory for evidence.** This includes `python3 -c`, `bash -c`,
   ls, cat, find, grep, head, tail, sed, awk, and any other non-MCP
   method of reading or parsing evidence files. Do NOT use IDE memory
   search or file read tools. ALL evidence access MUST go through Mulder
   MCP tools so it is logged and traceable. Use only:
   - `search(query)` to find evidence across indexed data
   - `list_directory(path)` to list files in any directory
   - `read_evidence_file(path)` to read text files (including extracted logs)
   - `list_files(path_filter=...)` for disk image file listings
   - `get_raw_output(source)` to read tool output
   - `decode_payload(source=..., pattern=...)` to extract and decode
     encoded strings from indexed evidence
   If you find yourself writing a Python or shell one-liner to parse a
   file, STOP -- there is always an MCP tool that can do it.
7. **Tag findings with MITRE ATT&CK IDs.** Use
   `lookup_attack_technique(query)` when unsure of the exact ID. Pass
   IDs via `mitre_attack_ids` in `submit_finding`.
8. **Use `run_parallel` for fast tools, `start_extraction_batch` for slow tools.**
   - **Fast tools (use `run_parallel`):** `extract_archive`, `run_mmls`,
     `run_fsstat`, `run_hayabusa`, all composite tools (`find_suspicious_processes`,
     `find_persistence_mechanisms`, etc.), `search`, `correlate_across_sources`,
     `list_files`. These complete in seconds and `run_parallel` returns all
     results at once.
   - **Slow extraction tools (use `start_extraction_batch`):**
     `run_volatility_batch`, `run_volatility`, `run_plaso`, `run_bulk_extractor`,
     `run_fls`, `run_evtx_parser`, `run_registry_parser`, `run_prefetch_parser`,
     `run_amcache_parser`, `run_shimcache_parser`, `run_mft_parser`,
     `run_pcap_analysis`, `index_evtx_file`. These take minutes to hours.
     `start_extraction_batch` launches them in the background and returns
     immediately so you can keep working.
   - **After starting a batch, DO NOT wait idly.** Continue with fast analysis
     (search, correlate, submit_finding, composite tools) and poll progress
     with `check_extraction_status(batch_id)`. Retrieve results as they
     complete with `get_completed_results(batch_id)`.
   - Never call the same tool 3+ times in a row -- batch them.

## Evidence Type Parity

Memory and disk evidence answer different questions. Analyzing only one
gives you half the picture. Before concluding your analysis of any
system that has BOTH a memory dump AND a disk image, verify you have
answered these questions from BOTH evidence types: what ran, what
persists, what was stolen, what was installed, who was involved, and
what was deleted.

**Rule: If a system has both memory and disk evidence, you MUST run
extraction tools on BOTH before submitting your final findings for that
system.** Do not let memory findings distract you from completing disk
analysis. Disk evidence frequently reveals activity that memory cannot:
installed tools that are no longer running, deleted files, historical
access patterns, and evidence of data staging or exfiltration.

## Negative Findings

Document what you looked for and **did not find**. This is critical for
court reports and compliance -- proving absence is as important as
proving presence.

- Use `submit_finding` with `severity="info"` and `confidence="confirmed"`
- Title prefix: `"[NEGATIVE] No evidence of ..."` (the report uses this
  prefix to categorize negative findings separately)
- Submit a negative finding when:
  - A composite tool returns zero results after all prerequisite data is indexed
  - YARA scans complete with zero matches
  - Searching for a specific IOC or hypothesis across all sources yields no hits
  - A specific investigation question (Q1--Q8) has no supporting evidence
- Do NOT submit negatives for tools that failed due to missing data
- Do NOT submit trivial negatives -- only meaningful absences

## Tool Selection

Choose tools based on evidence type. The MCP tool descriptions contain
full documentation. Key mappings:

- **Memory dumps**: run_volatility_batch, find_suspicious_processes,
  reconstruct_execution_chains, yara_scan_memory
- **Disk images (all)**: run_fls, run_bulk_extractor, list_files,
  get_deleted_files, yara_scan_files, extract_file_by_inode
- **Disk images (Windows)**: run_evtx_parser, run_hayabusa,
  run_registry_parser, run_prefetch_parser, run_amcache_parser,
  run_shimcache_parser, run_mft_parser, parse_usn_journal
- **Disk images (macOS)**: parse_plist, parse_browser_history
- **Disk images (Linux)**: read_evidence_file for /var/log, extract_file_by_inode for crontabs/history
- **PCAPs**: run_pcap_analysis, correlate_pcap_with_host
- **Cross-system**: find_persistence_mechanisms, find_execution_evidence,
  find_lateral_movement_indicators, find_defense_evasion,
  find_data_exfiltration_indicators, assess_recovery,
  analyze_execution_timeline, correlate_across_sources
- **Self-correction**: audit_evidence_coverage, audit_tool_coverage

## Investigation Workflow

The key principle: **analyze each system fully, then correlate across systems.**
Submit findings incrementally -- do NOT batch them all at the end.

### Phase 1 -- Orient

- Call `scan_evidence` with the evidence path. (Evidence hashing for
  chain of custody runs automatically in the background.)
- Review the manifest and evidence tree: how many systems, disk images,
  memory dumps, PCAPs, archives?
- Call `list_sources` to see what has already been indexed.

**EVIDENCE INVENTORY -- CRITICAL.**
List EVERY system, device, and archive from the manifest. You MUST
analyze ALL of them before finalizing. Print this inventory now and
refer back to it throughout the investigation.

**EXTRACT ALL ARCHIVES using `run_parallel`:**
```
run_parallel(tasks=[
  {"tool": "extract_archive", "args": {"archive_path": "/path/to/file1.7z"}},
  {"tool": "extract_archive", "args": {"archive_path": "/path/to/file2.7z"}},
  ...
])
```
After extraction, call `scan_evidence` on the extracted directories
to classify the new files.

- Form an initial hypothesis and prioritize systems (start with the
  most suspicious or the primary workstation).

### Phase 2 -- Per-System Analysis (Wave Model)

**REMEMBER: You are looking for MULTIPLE narratives, not just one.**
Do not let early findings bias which tools you run on later systems.
Every system gets all applicable tools regardless of what you found so far.

**For EACH system in your evidence inventory -- no exceptions.** If you
have 18 evidence items, you must run tools on all 18. After each
system, print how many systems remain (e.g., "System 5/18 done,
13 remaining").

Phase 2 uses a **wave model** to maximize throughput. Launch all slow
extractions across ALL systems at once, then do fast analysis while
they run, and harvest results as they complete.

#### Wave 1 -- Launch All Slow Extractions

Review the evidence inventory from Phase 1. For each system, choose the
appropriate extraction tools based on evidence type and platform (see
Tool Reference). Submit ALL slow extractions as a single background batch:

```
start_extraction_batch(tasks=[
  # Adapt tools to each system's evidence type and OS
  # Memory dumps: run_volatility_batch with OS-appropriate plugins
  {"tool": "run_volatility_batch", "args": {"plugins": [...], "memory_path": "..."}},
  # Disk images: fls + bulk_extractor + platform-specific tools
  {"tool": "run_fls", "args": {"image_path": "..."}},
  {"tool": "run_bulk_extractor", "args": {"image_path": "...", "scanners": [...]}},
  # Windows disk images: add evtx_parser, registry_parser
  # PCAPs: add run_pcap_analysis
  # ... all systems at once ...
])
```

#### Wave 2 -- Fast Work While Waiting

While extractions run in the background, use `run_parallel` for fast
tools that complete in seconds:

- `run_mmls` on all disk images (partition info)
- Any fast analysis tools applicable to already-indexed data
- Submit findings for anything already discovered

#### Wave 3 -- Harvest and Analyze (Poll Loop)

Poll for completed extractions and analyze results as they arrive:

1. `check_extraction_status(batch_id)` -- see what's done
2. `get_completed_results(batch_id)` -- retrieve finished results
3. For each newly completed extraction:
   - `search()` across the new data for IOCs and suspicious patterns
   - `submit_finding()` for anything notable
   - Run composite tools if their prerequisite data is now indexed
4. Repeat until all extractions complete.

**GATE CHECK: Do NOT leave Wave 3 until:**
- `check_extraction_status` on EVERY batch_id reports `all_done: true`
- If ANY batch has running jobs, stay here. Do more search/analysis work.

**POLLING DISCIPLINE:**
- Do NOT poll `check_extraction_status` more than once every 5-10 tool
  calls. Between polls, do productive work: search for IOCs, analyze
  completed results, submit findings, run composite tools on available
  data.
- If extractions are taking a long time (20+ minutes), that is normal
  for large memory dumps. DO NOT give up. DO NOT print a summary to the
  conversation instead of finalizing through the MCP tools.
- If you have exhausted all productive work and batches are still
  running, call `wait(seconds=600)` to sleep for 10 minutes, then poll
  again. Sleeping is far better than burning context with repeated
  status checks.
- If your context is above 70%, call `/compact` and then use
  `get_investigation_summary()` and `get_findings()` to recover state.
  Then continue polling and analyzing.
- NEVER terminate the investigation while batches are running. The
  `finalize_report` tool will block you anyway. Wait for them.

#### Wave 4 -- Dependent Tools

Once primary extractions complete, launch tools that depend on their
output. Choose based on what applies to each system:

- After EVTX extraction: `run_hayabusa()`, then `index_evtx_file`
- After fls: platform-specific parsers (registry, plist, log files)
- YARA scans on memory dumps and extracted files
- Any other applicable tools from the Tool Reference

Use `start_extraction_batch` for these if there are multiple, or call
them directly if just one or two.

#### Per-System Tool Selection

Choose tools based on what evidence exists for each system. Use the
Tool Reference section above. Every system should get:

1. **Extraction tools** appropriate to its evidence type (memory analysis,
   file listing, artifact carving, log parsing)
2. **Platform-specific tools** appropriate to its OS (registry for Windows,
   plist for macOS, log files for Linux, etc.)
3. **YARA / signature scanning** on memory and/or disk
4. **Per-system composite analysis** once extraction data is indexed

**AFTER each system's analysis completes:**
- Submit findings for anything suspicious.
- `search()` for IOCs discovered so far across ALL indexed data.

**If fls fails on a disk image**, other tools still work independently:
- `run_plaso` works directly on E01 images (does NOT need fls)
- `run_bulk_extractor` also works directly on E01 images

**CRITICAL: ALL per-system work must be COMPLETE before Phase 3.**
Do NOT proceed to Phase 3 until EVERY system has finished ALL of:
- Background extractions (all batches report `all_done: true`)
- Dependent tools appropriate to each system's evidence type and OS
- Per-system composite analysis on each system with sufficient data
- Finding submission for that system

Phase 3 composite tools query ALL indexed data across ALL systems.
Running them on incomplete data produces incomplete results and will
miss findings. If ANY extraction batch is still running, or ANY system
still needs dependent tools or analysis, stay in Wave 3/4. Keep
polling with `check_extraction_status`, running dependent tools as
prerequisites complete, and analyzing results. Only proceed when
every system is fully analyzed.

**PHASE GATE (only after ALL per-system analysis is complete):**
1. Call `get_investigation_summary()` to check overall progress.
2. Call `check_extraction_status` on every batch -- confirm ALL done.
3. Call `get_completed_results` on every batch -- retrieve any remaining.
3. Confirm all dependent and platform-specific tools have been run on
   every applicable system.
4. Confirm per-system composite tools have run where applicable.
5. Call `get_findings()` to review all submitted findings.
6. Which investigation questions (Q1--Q8) can you already answer?
7. Which questions remain unanswered?
8. Print your evidence inventory and mark which systems are analyzed.
9. **Tool Coverage Matrix (MANDATORY).** Print a table with one row per
   system and columns for each tool type applicable to that system's
   evidence (e.g., a Windows disk image gets different columns than a
   Linux memory dump). Mark each cell RAN, SKIPPED, or N/A. If ANY
   applicable tool shows SKIPPED, go back and run it NOW before
   proceeding to Phase 3.
10. **Evidence Type Parity Check (MANDATORY).** For each system that has
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

Run these composite and cross-cutting tools AFTER all individual systems
have been analyzed:

**Composite detection tools:**
- `find_persistence_mechanisms()` (Q3)
- `find_execution_evidence()` (Q2)
- `find_lateral_movement_indicators()` (Q4)
- `find_defense_evasion()` (Q6)
- `find_data_exfiltration_indicators()` (Q5)
- `assess_recovery()` (Q5, Q6)
- `analyze_execution_timeline()` (Q2, Q3)

**Network analysis (if PCAPs exist):**
- `run_pcap_analysis(mode="all")` on every PCAP file
- `correlate_pcap_with_host(t_start, t_end)` at suspicious time windows

**Cross-system correlation:**
- `get_timeline(t_start, t_end)` for a unified chronological view
  across ALL sources at suspicious time windows
- `correlate_across_sources` at 3+ distinct time windows covering the
  key events in your timeline
- `get_ioc_summary()` to extract and deduplicate all IOCs from findings
  and bulk_extractor data, then search for each across ALL systems
- `search()` for evidence of multiple actors / motives / narratives

**YARA on disk (if not done per-system):**
- `yara_scan_files(target_path, ruleset="full")` on mounted/extracted evidence

**SUBMIT FINDINGS NOW.** Submit anything new from the cross-system analysis.

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
not run. Prioritize extraction tools first (fls, bulk_extractor,
volatility), then analysis tools (platform-specific parsers, YARA,
composite analysis). Use `start_extraction_batch` for slow tools.

Skip tools that do not apply to the evidence type or platform. After
running the missing tools, `search()` and review the new output for
anything that does NOT fit your primary narrative.

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

**YOU MUST COMPLETE THIS PHASE BEFORE CALLING `finalize_report()`.**

**Step 0: Evidence Coverage.**
Print every system/device/archive from your Phase 1 evidence inventory.
For each, mark:
- [x] ANALYZED -- list which tools were run on it
- [ ] NOT ANALYZED -- explain why (encrypted, unsupported format, etc.)

**Step 0.5: Evidence Hashes.**
SHA-256 hashes were recorded during `scan_evidence` and are included
automatically in the final report. Users can verify independently with
`sha256sum`.

If fewer than 100% of evidence items are marked ANALYZED, you MUST go
back and analyze the remaining items NOW. Do not proceed to
finalize_report until every item is covered. This is non-negotiable.

**Step 1: Review submitted findings.**
Call `get_findings()` to see everything submitted so far.

**Step 1.5: Timestamp audit.**
Print each finding title and its `event_time_start` value. If ANY
finding has a null timestamp, go back and fix it NOW by searching
the evidence for a timestamp to associate with that finding. Common
sources: Prefetch execution times, LNK file timestamps, process
creation times from volatility, PCAP frame times, log entry
timestamps, EXIF dates, file system MAC times. Only proceed after
every finding has a timestamp or an explicit documented reason why
one cannot be determined.

**Step 2: Print the investigation questions scorecard.**
For EVERY question Q1--Q8, print one of:
- ANSWERED: [brief summary of the answer]
- PARTIAL: [what you found, what's missing]
- GAP: [why you couldn't answer -- which tools returned nothing]

**Step 3: Print the tool checklist.**
Mark each item from the Pre-Finalize Checklist below:
- [x] if completed
- [ ] NOT RUN -- [reason]

**Step 4: Address gaps.**
For any unchecked checklist item, unanswered question, or unanalyzed
evidence item, either:
- Run the missing tool / analyze the missing evidence NOW, OR
- Document why it was skipped (tool not applicable, no evidence of that type)

**Step 5: Negative findings.**
Submit `[NEGATIVE]` findings for all tested hypotheses with no evidence.

Only after Steps 0-5 are complete may you proceed to Phase 4.5.

### Phase 4.5 -- Self-Correction Audit

**THIS PHASE IS MANDATORY. Do NOT skip it. Do NOT fold it into Phase 4.**

The goal: use server-side audit tools to detect blind spots that you
missed through manual review. These tools compare what you extracted
against what you explained, and what tools you could have run against
what you actually ran.

**Step 1: Run `audit_evidence_coverage()`.**
This returns every indexed source NOT cited by any finding, grouped by
extractor type, with content samples for non-empty sources.

For each uncited source with `line_count > 0`:
- Use `search(query, source=source_name)` to check for relevant evidence
- Pay special attention to uncited `bulk.email`, `bulk.url`, `bulk.rfc822`
  sources -- communication data is almost always investigatively relevant
- If the source contains relevant evidence, submit a finding
- If it does not, no action needed -- but note it for your own awareness

**Step 2: Run `audit_tool_coverage()`.**
This re-classifies the evidence and compares applicable tools for each
artifact type against the tools you actually invoked.

For each tool listed in `tools_not_run`:
- Run the tool now if it could yield new evidence (especially
  `detect_steganography` on disk images with suspicious media files,
  `yara_scan_files` on unscanned images, `run_pcap_analysis` on
  unanalyzed captures)
- Skip tools that are genuinely not applicable (e.g., Windows-specific
  tools on a macOS image) -- no documentation needed for obvious skips

**Step 3: Re-examine ruled-out hypotheses.**
For each `[NEGATIVE]` finding you submitted:
- Check whether the uncited evidence from Step 1 could change that
  conclusion
- If an email address, account name, or contact from a ruled-out
  finding appears in any uncited source content, investigate further
  before confirming the negative
- If the negative still holds after this review, leave it as-is

Only after Steps 1-3 are complete may you proceed to Phase 5.

### Phase 5 -- Write the Narrative Report

**THIS IS THE LAST STEP BEFORE `finalize_report()`.** All evidence must
be fully processed, all findings submitted, all self-correction gaps
closed, and all hypotheses tested before writing the narrative. The
narrative must reflect the COMPLETE investigation, not a partial view.

Call `submit_narrative()` with a long-form incident report in markdown.
Structure it with these sections:
- **Background:** What organization/systems are involved, what prompted
  the investigation
- **Incident Timeline:** Chronological narrative of what happened, told
  as a story with cause and effect
- **Key Findings:** Detailed discussion of each major finding and how
  they connect to each other
- **Impact Assessment:** What data was compromised, what systems were
  affected, business impact
- **Recommendations:** Specific actions to prevent recurrence (technical
  controls, policy changes, monitoring improvements)
- **Conclusion:** Summary of the investigation outcome

Write in full paragraphs. This is for executives and legal -- not a
technical audience. Do NOT repeat raw tool output. Synthesize findings
into a coherent narrative that tells the story of what happened and why.

After the narrative is submitted, call `finalize_report()`.

---

## Pre-Finalize Checklist

**Per system with a memory dump (if applicable):**
- [ ] run_volatility_batch with OS-appropriate plugins
- [ ] find_suspicious_processes (after volatility indexed)
- [ ] reconstruct_execution_chains (after volatility indexed)
- [ ] yara_scan_memory(ruleset="full")

**Per system with a disk image (if applicable):**
- [ ] run_mmls + run_fls
- [ ] run_bulk_extractor with appropriate scanners
- [ ] Platform-specific tools:
  - Windows: evtx_parser + hayabusa + index_evtx_file, registry_parser
  - macOS: parse_plist
  - Linux: log file extraction and analysis
- [ ] list_files(include_deleted=true)
- [ ] yara_scan_files if not covered by memory scan

**Per PCAP (if applicable):**
- [ ] run_pcap_analysis(mode="all")
- [ ] correlate_pcap_with_host at suspicious time windows

**Once (cross-system, after all per-system analysis):**
- [ ] All applicable composite tools (find_persistence_mechanisms,
      find_execution_evidence, find_lateral_movement_indicators,
      find_defense_evasion, find_data_exfiltration_indicators,
      assess_recovery, analyze_execution_timeline)
- [ ] correlate_across_sources at 3+ time windows
- [ ] search() for every IOC across all systems
- [ ] search() for evidence of multiple actors / motives / narratives
- [ ] Submit [NEGATIVE] findings for all tested hypotheses with no evidence

**Phase 3.5 -- Alternative Narrative Discovery:**
- [ ] Primary narrative stated (actors, TTPs, systems, time window)
- [ ] Evidence contribution audit printed (every system, findings, tools)
- [ ] Coverage gaps filled (missing per-system tools run)
- [ ] Counter-hypothesis searches completed (user accounts, tool/malware
      diversity, time window gaps, unexplained connections)
- [ ] Second narrative found and submitted OR [NEGATIVE] finding submitted

**Phase 4.5 -- Self-Correction Audit:**
- [ ] `audit_evidence_coverage()` -- all uncited sources with content reviewed
- [ ] `audit_tool_coverage()` -- all tool gaps addressed or skipped with reason
- [ ] Ruled-out hypotheses re-checked against uncited evidence

**Phase 5 -- Narrative Report (after ALL evidence processed and gaps closed):**
- [ ] `submit_narrative()` -- long-form investigation report written

**Timestamps:**
- [ ] Every finding has `event_time_start` set (or documented reason why not)

**Questions:** ALL (Q1--Q8) must be ANSWERED or documented as GAP.

---

## Async Extraction Reference

**Rule:** If a tool runs a subprocess or processes large evidence files,
use `start_extraction_batch`. If it queries the DB or runs fast analysis,
use `run_parallel`.

```
start_extraction_batch(tasks=[...])  # slow tools (volatility, plaso, fls, evtx, etc.)
run_parallel(tasks=[...])            # fast tools (extract_archive, search, composites, etc.)
```

Poll with `check_extraction_status(batch_id)`, harvest with
`get_completed_results(batch_id)`. Do NOT wait idly.

---

## FINAL RULES

These override everything above if there is a conflict.

1. **NEVER terminate while batches are running.** The `finalize_report`
   tool will block you. Do not print a summary to the conversation as
   a substitute. Wait for batches, analyze results, then finalize via
   the MCP tool.
2. **Do NOT poll in a tight loop.** Poll `check_extraction_status` once
   every 5-10 tool calls. Between polls, do productive analysis work.
3. Keep responses SHORT. 1-2 sentences per tool call. Submit findings
   to the DB, not to the conversation.
4. **If context is above 70%, `/compact` and continue.** Use
   `get_investigation_summary()` and `get_findings()` to recover state.
5. ALL 8 investigation questions (Q1-Q8) must be ANSWERED or documented
   as GAP before you may call `finalize_report`.
6. Use `bookmark_window()` for interesting evidence you are not ready to
   submit as a finding. Use `get_bookmarks()` after `/compact`.
