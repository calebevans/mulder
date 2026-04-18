# Mulder -- Test Case Matrix

This document defines the test cases for validating Mulder against forensic evidence
of varying types, complexity, and attack sophistication. Each case specifies the
dataset source, ground truth findings, difficulty rating, which Mulder capabilities
are exercised, and step-by-step instructions for execution and scoring.

---

## How to Use This Document

1. Work through cases in tier order (Tier 1 is mandatory for submission).
2. For each case, start Claude Code in the mulder project directory and ask it to investigate the evidence path.
3. After all runs, aggregate results into `docs/accuracy-report.md` and `docs/dataset.md`.

**Running a test case:** Start Claude Code (`claude`) in the mulder project directory, then ask:
```
Investigate the evidence at /path/to/evidence/
```
Claude Code will call `ingest_evidence`, run the full investigation, and produce a report.

---

## Baseline: EVTX-ATTACK-SAMPLES Full Run (Completed)

Before the tiered cases, here is the baseline from the initial test run for comparison.

| Metric | Value |
|--------|-------|
| Dataset | sbousseaden/EVTX-ATTACK-SAMPLES (all directories) |
| Evidence types | EVTX only (no memory, no disk image) |
| Sources ingested | 280 |
| Windows created | 19,813 |
| Ingestion time | 633s |
| Iterations used | 13 / 20 |
| Tool calls | 35 |
| Findings (confirmed) | 11 |
| Findings (inference) | 4 |
| Investigation time | 115.6s |
| Model | gemini/gemini-2.5-flash |
| Extractors fired | EVTX parser, Plaso |
| Tools returning 0 results | find_suspicious_processes, parse_prefetch_detailed, parse_amcache, parse_shimcache, yara_scan_files, get_carved_iocs |

### Baseline Findings

| # | Title | Severity | Confidence |
|---|-------|----------|------------|
| 1 | Suspicious Service Installation: cmd.exe as a service (spoolfool) | critical | confirmed |
| 2 | Credential Dumping Attempt: PowerShell accessing LSASS | critical | confirmed |
| 3 | Malicious Persistence: Atomic Red Team Run Key | critical | confirmed |
| 4 | Meterpreter MSI Package Execution | critical | confirmed |
| 5 | Timestomping: NvSmart.exe and NvSmartMax.dll | critical | confirmed |
| 6 | Timestomping: bs.ps1 Startup Script | critical | confirmed |
| 7 | Windows Defender Detections with Defense Evasion | critical | confirmed |
| 8 | Suspicious Service Installation: calc.exe as a service (remotesvc) | high | confirmed |
| 9 | Scheduled Task for Persistence: CYAlyNSS executing tasklist | high | confirmed |
| 10 | Persistence via Startup Script: bs.ps1 | high | confirmed |
| 11 | Security Event Log Cleared | high | confirmed |
| 12 | Remote Desktop Protocol (RDP) Activity Detected | medium | inference |
| 13 | WinRM Connection Detected | medium | inference |
| 14 | Suspicious Startup File Creation: onedrive.exe | medium | inference |
| 15 | Failed Interactive Logon via Chrome Process | medium | inference |

### Capability Gaps Identified

The baseline run exercised only ~30% of Mulder's 48 MCP tools. The following tool
categories returned zero results because the required evidence types were absent:

- **Volatility tools** (0/11 used): No memory dump ingested
- **Sleuth Kit tools** (0/6 used): No disk image ingested
- **EZ Tools** (0/9 used): No disk image or extracted artifact files
- **Bulk extractor** (0/1 used): No disk image ingested
- **YARA scanning** (0/3 used): No files or memory to scan

---

## Tier 1: Official Hackathon Starter Data

### Case 1 -- SANS Hackathon Starter Evidence

| Field | Value |
|-------|-------|
| Source | https://sansorg.egnyte.com/fl/HhH7crTYT4JK |
| Format | Unknown until downloaded (likely mixed: disk images, memory dumps, EVTX, logs) |
| Difficulty | **UNKNOWN** (likely MEDIUM-HIGH) |
| Priority | **MANDATORY** -- judges will expect this data to work |
| Reference | Hackathon Resources page; Valhuntir example submission used this data |

**Why this case matters:** This is the evidence the hackathon organizers curated for
participants. Judges may run submissions against this exact data. Any submission that
cannot handle it will fail Stage One evaluation.

**Mulder tools exercised:** Depends on contents. If the package contains disk images
and memory dumps alongside EVTX, this exercises the full pipeline.

**Ground truth:** May be provided with the download, or discoverable via the Protocol
SIFT NotebookLM notebook referenced on the Resources page.

#### Steps

```bash
# 1. Download the starter evidence package
#    Visit https://sansorg.egnyte.com/fl/HhH7crTYT4JK in a browser
#    Download all available files to ~/cases/hackathon-starter/

# 2. Inventory the evidence
ls -lR ~/cases/hackathon-starter/
file ~/cases/hackathon-starter/*

# 3. Identify evidence types
#    Look for: .evtx, .mem/.vmem/.raw/.dmp, .e01/.dd/.img, .log/.txt, .pcap

# 4. Ingest
mulder ingest ~/cases/hackathon-starter/ --case-id hackathon-starter

# 5. Record which extractors fired from the ingestion output:
#    - Volatility?  (memory dump present)
#    - Plaso?       (disk image or EVTX present)
#    - Sleuth Kit?  (disk image present)
#    - EZ Tools?    (disk image present)
#    - Bulk extractor? (disk image present)
#    - EVTX parser? (EVTX files present)
#    - Log reader?  (text logs present)

# 6. Investigate
mulder investigate --case-id hackathon-starter --model gemini/gemini-2.5-flash

# 7. Review outputs
cat ~/.mulder/cases/hackathon-starter.report.md
wc -l ~/.mulder/cases/hackathon-starter.audit.jsonl
```

#### Scoring

Record in the scoring table at the bottom of this document.
If ground truth is provided with the data, compute TP/FP/FN.

---

## Tier 2: Memory Forensics

These cases exercise the Volatility extractor pipeline and memory-focused MCP tools
that returned zero results in the baseline EVTX test.

### Case 2 -- CyberDefenders "DumpMe" (Meterpreter in Memory)

| Field | Value |
|-------|-------|
| Source | https://cyberdefenders.org -- search "DumpMe" |
| Download password | `cyberdefenders.org` |
| Format | Single file: `Triage-Memory.mem` (Windows 7 SP1 x64) |
| Size | ~1.5 GB |
| Difficulty | **LOW** |
| SHA1 | `C95E8CC8C946F95A109EA8E47A6800DE10A27ABD` |

**Why this case matters:** It is the simplest possible memory-only test with
fully documented ground truth. If Mulder's Volatility pipeline works, this case
will produce findings. If it does not, this case will surface the bug quickly.

#### Ground Truth

| # | Finding | Severity | Key Evidence |
|---|---------|----------|-------------|
| 1 | Malicious process `UWkpjFjDzM.exe` (PID 3496) running meterpreter reverse shell | critical | pslist, malfind, netscan |
| 2 | `wscript.exe` spawned malicious child process | high | pstree parent-child relationship |
| 3 | Attacker IP `10.0.0.106` communicating with victim `10.0.0.101` | high | netscan connection |
| 4 | VBS dropper `vhjReUDEuumrX.vbs` used for initial execution | high | cmdline arguments |
| 5 | VCRUNTIME140.dll loaded by 5 processes (potential DLL side-loading) | medium | dlllist |
| 6 | Bob's account credentials recoverable from memory | medium | hashdump |

#### Mulder Tools Exercised

| Tool | Expected Behavior |
|------|-------------------|
| `VolatilityExtractor` | All plugins fire: pslist, pstree, cmdline, netscan, malfind, dlllist, svcscan, handles, psscan, envars, privs, etc. |
| `find_suspicious_processes()` | Should flag PID 3496 via malfind + netscan anomalies |
| `scan_hidden_processes()` | psscan vs pslist diff (may or may not find hidden processes in this case) |
| `yara_scan_memory()` | Meterpreter YARA signatures should match |
| `search()` | Semantic queries for process names, IPs, script names |
| `get_process_tree()` | Should show wscript.exe -> UWkpjFjDzM.exe chain |
| `list_processes_from_memory()` | Full process listing |

#### Steps

```bash
# 1. Download from CyberDefenders
#    Navigate to cyberdefenders.org, search "DumpMe", download the zip
#    Extract with password: cyberdefenders.org
mkdir -p ~/cases/dumpme
cd ~/cases/dumpme
unzip /path/to/DumpMe.zip  # password: cyberdefenders.org

# 2. Verify integrity
sha1sum Triage-Memory.mem
# Expected: C95E8CC8C946F95A109EA8E47A6800DE10A27ABD

# 3. Ingest
mulder ingest ~/cases/dumpme/ --case-id dumpme

# 4. Verify Volatility ran -- check the ingestion output for sources like:
#    volatility.pslist, volatility.pstree, volatility.cmdline,
#    volatility.netscan, volatility.malfind, volatility.dlllist

# 5. Investigate
mulder investigate --case-id dumpme --model gemini/gemini-2.5-flash

# 6. Review report
cat ~/.mulder/cases/dumpme.report.md
```

#### Accuracy Scoring Checklist

| Ground Truth Item | Found? | Finding ID | Correct? | Notes |
|-------------------|--------|------------|----------|-------|
| PID 3496 as malicious | | | | |
| wscript.exe as parent | | | | |
| Attacker IP 10.0.0.106 | | | | |
| VBS dropper vhjReUDEuumrX | | | | |
| VCRUNTIME140.dll anomaly | | | | |
| Credential presence | | | | |
| **Hallucinated findings** | | | | Count FPs here |

---

### Case 3 -- Volatility Foundation "Cridex" Sample (Banking Trojan)

| Field | Value |
|-------|-------|
| Source | https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples |
| Direct download | http://files.sempersecurus.org/cridex_data.zip |
| Format | Single file: `cridex.vmem` (Windows XP SP2 x86) |
| Difficulty | **LOW-MEDIUM** |
| MD5 | `734aadd62d0662256a65510271d40048` |

**Why this case matters:** Tests Mulder against an older Windows version (XP).
Volatility 3 handles XP differently than Win7+. If the OS auto-detection and plugin
selection work, this surfaces banking trojan indicators. If they fail, it reveals
compatibility gaps in the Volatility extractor.

#### Ground Truth

| # | Finding | Severity | Key Evidence |
|---|---------|----------|-------------|
| 1 | Suspicious process `reader_sl.exe` (PID 1640) with injected code | critical | malfind, pslist |
| 2 | C2 connections to external IPs (41.168.5.140:8080, 125.19.103.198:8080) | critical | netscan/connscan |
| 3 | Injected code sections in explorer.exe | high | malfind VAD analysis |
| 4 | Suspicious DLL loaded from temp directories | medium | dlllist |

#### Steps

```bash
# 1. Download
mkdir -p ~/cases/cridex
cd ~/cases/cridex
wget http://files.sempersecurus.org/cridex_data.zip
unzip cridex_data.zip

# 2. Verify
md5sum cridex.vmem
# Expected: 734aadd62d0662256a65510271d40048

# 3. Ingest
mulder ingest ~/cases/cridex/ --case-id cridex

# 4. Check for XP compatibility -- if Volatility errors appear in output,
#    note the specific error for debugging

# 5. Investigate
mulder investigate --case-id cridex --model gemini/gemini-2.5-flash

# 6. Review
cat ~/.mulder/cases/cridex.report.md
```

#### Accuracy Scoring Checklist

| Ground Truth Item | Found? | Finding ID | Correct? | Notes |
|-------------------|--------|------------|----------|-------|
| PID 1640 injected code | | | | |
| C2 to 41.168.5.140 | | | | |
| C2 to 125.19.103.198 | | | | |
| explorer.exe injection | | | | |
| Suspicious DLLs | | | | |

---

### Case 4 -- Volatility Foundation "Stuxnet" Sample (Nation-State Rootkit)

| Field | Value |
|-------|-------|
| Source | https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples |
| Format | `stuxnet.vmem` (Windows XP SP3 x86) |
| Difficulty | **MEDIUM** |

**Why this case matters:** Stuxnet is a multi-component rootkit with hidden drivers,
process injection, and kernel-level evasion. This is the hardest memory-only case
and tests whether Mulder's agent can reason about rootkit behavior -- hidden processes
that only appear in psscan but not pslist, and kernel modules visible only via modscan.

#### Ground Truth

| # | Finding | Severity | Key Evidence |
|---|---------|----------|-------------|
| 1 | Hidden processes (present in psscan but absent from pslist) | critical | psscan vs pslist diff |
| 2 | Process injection via `lsass.exe` | critical | malfind, handles |
| 3 | Malicious kernel drivers loaded | critical | modules vs modscan diff |
| 4 | Suspicious DLLs in system directories | high | dlllist, filescan |
| 5 | Network connections to C2 infrastructure | high | netscan |

#### Mulder Tools Exercised

This case specifically tests tools that had no data in the baseline:

| Tool | What It Tests |
|------|---------------|
| `scan_hidden_processes()` | **Critical** -- must detect psscan/pslist discrepancy |
| `scan_kernel_modules()` | **Critical** -- must detect modscan/modules discrepancy |
| `yara_scan_memory()` | Stuxnet-specific signatures in built-in YARA rules |
| `find_defense_evasion()` | Rootkit indicator aggregation |
| `get_process_privileges()` | SeDebugPrivilege on injected processes |

#### Steps

```bash
# 1. Download stuxnet.vmem
#    Check Volatility wiki Memory Samples page for current mirror
#    Original source: malwarecookbook.googlecode.com (may need archive.org)
mkdir -p ~/cases/stuxnet
cd ~/cases/stuxnet
# wget <mirror-url>/stuxnet.vmem.zip
# unzip stuxnet.vmem.zip

# 2. Ingest
mulder ingest ~/cases/stuxnet/ --case-id stuxnet

# 3. Investigate
mulder investigate --case-id stuxnet --model gemini/gemini-2.5-flash

# 4. Key questions to answer from the report:
#    - Did scan_hidden_processes() find the rootkit processes?
#    - Did scan_kernel_modules() find the hidden drivers?
#    - Did the agent correlate hidden processes with kernel modules?
#    - Did YARA rules match Stuxnet signatures?

cat ~/.mulder/cases/stuxnet.report.md
```

#### Accuracy Scoring Checklist

| Ground Truth Item | Found? | Finding ID | Correct? | Notes |
|-------------------|--------|------------|----------|-------|
| Hidden processes (psscan diff) | | | | |
| lsass.exe injection | | | | |
| Malicious kernel drivers | | | | |
| Suspicious system DLLs | | | | |
| C2 network connections | | | | |

---

## Tier 3: EVTX Depth Testing

### Case 5 -- EVTX-ATTACK-SAMPLES Focused Subsets

| Field | Value |
|-------|-------|
| Source | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (already cloned) |
| Ground truth | `EVTX_ATT&CK_Metadata/` directory + `evtx_data.csv` in the repo |
| Difficulty | **LOW** (data already available) |

**Why this case matters:** The baseline run ingested all 280 EVTX files at once,
producing broad but shallow findings. Running focused subsets tests whether Mulder
produces more granular, technique-specific findings when the signal-to-noise ratio
is higher. This directly addresses the judging criterion "Depth on fewer types beats
shallow coverage of many."

#### Subset A: Lateral Movement

| Field | Value |
|-------|-------|
| Path | `EVTX-ATTACK-SAMPLES/Lateral Movement/` |
| Case ID | `evtx-latmov` |

**Expected findings:**
- WMI remote execution (Event ID 5857, 5860, 5861)
- PsExec service installation (Event ID 7045)
- RDP session initiation (Event ID 1149, 4624 Type 10)
- WinRM connection (Event ID 91, 168)
- DCOM lateral movement
- Pass-the-hash / pass-the-ticket indicators

#### Subset B: Credential Access

| Field | Value |
|-------|-------|
| Path | `EVTX-ATTACK-SAMPLES/Credential Access/` |
| Case ID | `evtx-creds` |

**Expected findings:**
- Mimikatz / LSASS memory access (Sysmon Event ID 10)
- Kerberoasting (Event ID 4769 with RC4 encryption)
- DCSync / DCShadow indicators
- SAM database access
- Credential dumping tool execution

#### Subset C: Persistence

| Field | Value |
|-------|-------|
| Path | `EVTX-ATTACK-SAMPLES/Persistence/` |
| Case ID | `evtx-persist` |

**Expected findings:**
- Registry Run/RunOnce key modification
- Service creation for persistence (Event ID 7045)
- Scheduled task creation (Event ID 4698)
- Startup folder manipulation
- WMI event subscription persistence

#### Steps (repeat for each subset)

```bash
# Using Lateral Movement as the example:

# 1. Ingest the subset
mulder ingest ~/cases/evtx-test/Lateral\ Movement/ --case-id evtx-latmov

# 2. Investigate
mulder investigate --case-id evtx-latmov --model gemini/gemini-2.5-flash

# 3. Review
cat ~/.mulder/cases/evtx-latmov.report.md

# 4. Compare with baseline:
#    - How many findings specific to lateral movement?
#    - Did it find techniques the full run missed?
#    - What is the confirmed vs inference ratio?

# Repeat for Credential Access and Persistence:
mulder ingest ~/cases/evtx-test/Credential\ Access/ --case-id evtx-creds
mulder investigate --case-id evtx-creds --model gemini/gemini-2.5-flash

mulder ingest ~/cases/evtx-test/Persistence/ --case-id evtx-persist
mulder investigate --case-id evtx-persist --model gemini/gemini-2.5-flash
```

#### Comparison Table

| Metric | Full Run (baseline) | Lateral Movement | Credential Access | Persistence |
|--------|--------------------:|:----------------:|:-----------------:|:-----------:|
| Sources ingested | 280 | | | |
| Findings (confirmed) | 11 | | | |
| Findings (inference) | 4 | | | |
| Technique-specific findings | N/A | | | |
| False positives | TBD | | | |

---

## Tier 4: Disk Image Analysis

These cases exercise Sleuth Kit, EZ Tools, Plaso super-timeline, and bulk_extractor
-- all of which returned zero results in the baseline.

### Case 6 -- Ali Hadi Challenge #1 (Web Server Compromise)

| Field | Value |
|-------|-------|
| Source | https://www.ashemery.com/dfir.html -- Challenge #1 |
| Mirrors | Archive.org primary, Mega.co.nz alternate |
| Format | Windows disk image + memory dump |
| Difficulty | **MEDIUM** |

**Why this case matters:** This is the first multi-source test case (disk + memory).
It exercises cross-source correlation -- the core differentiator described in the
Devpost writeup. It also activates the full extractor pipeline: Volatility for memory,
Plaso + TSK + EZ Tools for disk, and bulk_extractor for IOC carving.

#### Ground Truth

| # | Finding | Severity | Expected Sources |
|---|---------|----------|-----------------|
| 1 | PHP web shell uploaded to XAMPP web root | critical | tsk.filelist, plaso.timeline |
| 2 | SQL injection used for initial access | high | plaso.timeline, logs |
| 3 | Attacker process activity in memory | high | volatility.pslist, volatility.cmdline |
| 4 | Malicious files in web server directory | high | tsk.filelist, bulk.url |
| 5 | Timeline of intrusion events (initial access through persistence) | medium | plaso.timeline, tsk.timeline |
| 6 | Deleted evidence artifacts | medium | tsk.filelist (deleted markers) |

#### Mulder Tools Exercised

| Tool Category | Tools | What They Test |
|---------------|-------|----------------|
| Sleuth Kit | `list_files`, `get_deleted_files`, `get_fs_timeline`, `extract_file_by_inode` | Filesystem analysis |
| EZ Tools | `parse_prefetch_detailed`, `parse_amcache`, `parse_shimcache`, `parse_mft` | Windows artifact parsing |
| Plaso | `filter_timeline`, `export_timeline_slice`, `get_plaso_stats` | Super-timeline queries |
| Bulk extractor | `get_carved_iocs` | URL/IP/email carving |
| Volatility | All memory plugins | Process analysis |
| Composite | `find_execution_evidence`, `correlate_across_sources` | Cross-source joins |

#### Steps

```bash
# 1. Download from ashemery.com
#    Visit https://www.ashemery.com/dfir.html
#    Download Challenge #1 files (disk image + memory dump)
#    Alternative: check Archive.org mirror links on the page
mkdir -p ~/cases/ali-hadi-1
cd ~/cases/ali-hadi-1
# Download and extract image files here

# 2. Verify file types
file *

# 3. Ingest
mulder ingest ~/cases/ali-hadi-1/ --case-id ali-hadi-1

# 4. Verify all extractors fired:
#    Check output for: Volatility, Plaso, SleuthKit, EZTools, BulkExtractor, EVTX

# 5. Investigate
mulder investigate --case-id ali-hadi-1 --model gemini/gemini-2.5-flash

# 6. Review and score
cat ~/.mulder/cases/ali-hadi-1.report.md

# 7. Key questions:
#    - Did correlate_across_sources() join disk and memory findings?
#    - Did get_deleted_files() find evidence of cleanup?
#    - Did the Plaso timeline cover the full intrusion window?
#    - How many tools from each category were actually invoked?
```

#### Accuracy Scoring Checklist

| Ground Truth Item | Found? | Finding ID | Correct? | Notes |
|-------------------|--------|------------|----------|-------|
| PHP web shell | | | | |
| SQL injection initial access | | | | |
| Attacker process in memory | | | | |
| Malicious web root files | | | | |
| Intrusion timeline | | | | |
| Deleted evidence | | | | |

---

### Case 7 -- NIST CFReDS Windows Registry Dataset

| Field | Value |
|-------|-------|
| Source | https://cfreds-archive.nist.gov/winreg/cfreds-2017-winreg/cfreds-2017-winreg.html |
| Format | Registry hive files (SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat) with ground truth |
| Difficulty | **MEDIUM** |

**Why this case matters:** NIST provides exact ground truth for every registry key
value. This is the only dataset where accuracy can be measured to the individual
artifact level. It benchmarks Mulder's registry parsing (EZ Tools RECmd, RegRipper)
against a known-good standard.

#### Ground Truth

NIST provides complete documentation for:
- Installed software and versions
- User activity (UserAssist, RecentDocs, TypedPaths)
- System configuration (services, startup items, network)
- USB device history
- Shell bags (folder access history)

The ground truth document is available alongside the dataset download.

#### Steps

```bash
# 1. Download from NIST
#    Visit the CFReDS URL above
#    Download the Win10 registry dataset (7z archive)
mkdir -p ~/cases/nist-registry
cd ~/cases/nist-registry
# Extract registry hive files here

# 2. Ingest
mulder ingest ~/cases/nist-registry/ --case-id nist-registry

# 3. Investigate
mulder investigate --case-id nist-registry --model gemini/gemini-2.5-flash

# 4. Compare extracted persistence mechanisms against NIST ground truth
#    Focus on: Run keys, services, scheduled tasks, UserAssist entries
cat ~/.mulder/cases/nist-registry.report.md
```

---

## Tier 5: Combined / Stress Tests

These cases exercise the full pipeline with multiple evidence types and complex
attack chains requiring cross-source correlation.

### Case 8 -- CyberDefenders "Injector" (Disk + Memory)

| Field | Value |
|-------|-------|
| Source | https://cyberdefenders.org -- search "Injector" |
| Download password | `cyberdefenders.org` |
| Format | Disk image + memory dump (compromised web server) |
| Difficulty | **HIGH** |

**Why this case matters:** This is the most demanding test. It requires Mulder to
reconstruct a complete attack chain from initial web server compromise through
privilege escalation and command execution, using evidence from both disk and memory.
The cross-source correlation must work correctly for findings to be confirmed.

#### Ground Truth

| # | Finding | Severity | Expected Sources |
|---|---------|----------|-----------------|
| 1 | Web server initial compromise | critical | disk artifacts, logs |
| 2 | Privilege escalation method | critical | volatility (memory), event logs |
| 3 | Post-exploitation command execution | high | volatility.cmdline, event logs |
| 4 | Attacker tools and persistence | high | tsk.filelist, ez.prefetch |
| 5 | Data access / exfiltration indicators | medium | bulk extractor, netscan |

#### Steps

```bash
# 1. Download from CyberDefenders
mkdir -p ~/cases/injector
cd ~/cases/injector
# Download and extract with password: cyberdefenders.org

# 2. Ingest
mulder ingest ~/cases/injector/ --case-id injector

# 3. Investigate
mulder investigate --case-id injector --model gemini/gemini-2.5-flash

# 4. Evaluate
cat ~/.mulder/cases/injector.report.md

# Key evaluation criteria:
#   - Did the agent reconstruct the full attack chain (initial access -> privesc -> execution)?
#   - How many findings used correlate_across_sources()?
#   - Were disk and memory findings cross-referenced?
#   - Did the agent self-correct any findings?
```

---

### Case 9 -- CyberDefenders "DarkCrystal" (Endpoint Forensics)

| Field | Value |
|-------|-------|
| Source | https://cyberdefenders.org -- search "DarkCrystal" |
| Download password | `cyberdefenders.org` |
| Format | Memory dump + Windows event logs |
| Difficulty | **MEDIUM-HIGH** |

**Why this case matters:** This case combines memory forensics with EVTX analysis,
testing the specific combination that exercises both the Volatility and EVTX parsing
pipelines simultaneously. Unlike Case 6 (disk + memory), this omits disk images,
so the agent must correlate memory findings with event log evidence only.

#### Steps

```bash
# 1. Download from CyberDefenders
mkdir -p ~/cases/darkcrystal
cd ~/cases/darkcrystal
# Download and extract with password: cyberdefenders.org

# 2. Ingest
mulder ingest ~/cases/darkcrystal/ --case-id darkcrystal

# 3. Investigate
mulder investigate --case-id darkcrystal --model gemini/gemini-2.5-flash

# 4. Evaluate cross-source correlation quality
cat ~/.mulder/cases/darkcrystal.report.md

# Key questions:
#   - Did the agent correlate process findings (Volatility) with logon events (EVTX)?
#   - Were timestamps aligned across memory and event log sources?
#   - How many findings achieved "confirmed" via cross-source verification?
```

---

## Scoring Framework

### Per-Case Metrics Table

For each test case, fill in this table:

| Metric | Case 1 | Case 2 | Case 3 | Case 4 | Case 5a | Case 5b | Case 5c | Case 6 | Case 7 | Case 8 | Case 9 |
|--------|--------|--------|--------|--------|---------|---------|---------|--------|--------|--------|--------|
| Sources ingested | | | | | | | | | | | |
| Windows created | | | | | | | | | | | |
| Ingestion time (s) | | | | | | | | | | | |
| Iterations used | | | | | | | | | | | |
| Tool calls | | | | | | | | | | | |
| Findings (confirmed) | | | | | | | | | | | |
| Findings (inference) | | | | | | | | | | | |
| True positives | | | | | | | | | | | |
| False positives | | | | | | | | | | | |
| False negatives | | | | | | | | | | | |
| Self-corrections | | | | | | | | | | | |
| Hallucination rejections | | | | | | | | | | | |
| Investigation time (s) | | | | | | | | | | | |
| Extractors fired | | | | | | | | | | | |

### Aggregate Metrics (for accuracy-report.md)

After all runs, compute:

| Metric | Formula | Value |
|--------|---------|-------|
| **Overall precision** | TP / (TP + FP) across all cases | |
| **Overall recall** | TP / (TP + FN) across all cases | |
| **Confirmed precision** | TP_confirmed / total_confirmed | |
| **Inference precision** | TP_inference / total_inference | |
| **Hallucination rate** | rejected_findings / total_submit_attempts | |
| **Cross-source confirmation rate** | confirmed_with_2+_sources / total_confirmed | |
| **Average investigation time** | mean(investigation_time) across all cases | |
| **Tool utilization** | unique_tools_invoked / 48 across all cases | |

### Capability Coverage Matrix

Track which MCP tool categories are exercised across all cases:

| Tool Category | Case 1 | Case 2 | Case 3 | Case 4 | Case 5 | Case 6 | Case 7 | Case 8 | Case 9 |
|---------------|:------:|:------:|:------:|:------:|:------:|:------:|:------:|:------:|:------:|
| Core (17 tools) | | X | X | X | X | X | X | X | X |
| Volatility | | X | X | X | | X | | X | X |
| Sleuth Kit | | | | | | X | | X | |
| EZ Tools | | | | | | X | X | X | |
| Plaso | X | | | | X | X | | X | |
| YARA | | X | X | X | | X | | X | |
| Bulk extractor | | | | | | X | | X | |
| Composites | X | X | X | X | X | X | X | X | X |
| Findings | X | X | X | X | X | X | X | X | X |

---

## Priority Order for Testing

| Priority | Case | Rationale |
|----------|------|-----------|
| 1 | Case 1 (Hackathon starter) | Mandatory for submission; judges will test against this |
| 2 | Case 2 (DumpMe) | Validates Volatility pipeline; easy ground truth; quick to run |
| 3 | Case 5 (EVTX subsets) | Data already available; tests depth; populates accuracy metrics |
| 4 | Case 6 (Ali Hadi) | First multi-source test; exercises disk pipeline |
| 5 | Case 3 (Cridex) | Tests legacy OS compatibility; quick download |
| 6 | Case 9 (DarkCrystal) | Tests memory + EVTX correlation |
| 7 | Case 8 (Injector) | Full pipeline stress test |
| 8 | Case 4 (Stuxnet) | Rootkit detection edge case |
| 9 | Case 7 (NIST CFReDS) | Registry parsing benchmark |
