# Killjoy Demo Video Script

Target length: 5 minutes.

---

## 0:00 -- 0:30 | Introduction

**On screen:** Title card, then terminal on the SIFT Workstation.

**Narration:**

> Killjoy is a custom MCP server for forensic investigations on the SANS SIFT Workstation. It ingests evidence once, builds a semantic index, and then lets an autonomous AI agent investigate through typed, read-only tools. The agent cannot modify evidence because the API surface does not contain destructive operations.

**Key points to hit:**
- Custom MCP Server architecture (hackathon approach #2)
- Three-command UX: ingest, investigate, serve
- Evidence integrity enforced by API design, not prompts

---

## 0:30 -- 1:30 | Ingestion

**On screen:** Terminal running `killjoy ingest`.

```bash
killjoy ingest /cases/sample-case/ --case-id demo
```

**Show:**
- Evidence classification output (memory dump detected, EVTX files found, log directories scanned)
- Volatility plugins running against the memory dump (pslist, pstree, cmdline, netscan, malfind, dlllist, svcscan, handles)
- Windowing and embedding progress
- Final summary: N sources, M windows, elapsed time

**Narration:**

> Killjoy scans the evidence directory, classifies each file, and runs the appropriate extractor. Memory dumps go through Volatility 3, disk images through Plaso, event logs through our EVTX parser. Every piece of extracted text is split into windows, embedded with all-MiniLM-L6-v2, and stored in a per-case sqlite-vec database.

---

## 1:30 -- 4:00 | Autonomous Investigation

**On screen:** Terminal running `killjoy investigate`.

```bash
killjoy investigate --case-id demo --model claude-sonnet-4-20250514
```

**Show the real-time terminal output:**

1. Agent calls `list_sources` -- show the enumeration of available evidence
2. Agent calls `find_suspicious_processes` -- highlight the composite query joining malfind + cmdline + netscan + pstree
3. Agent calls `correlate_across_sources` for the suspicious time range
4. **Self-correction moment** (the tiebreaker):
   - Agent finds a process flagged by malfind
   - Cross-checks with event logs -- no corresponding service installation event
   - Demotes the finding from "confirmed" to "inference" and notes the gap
5. Agent calls `find_lateral_movement_indicators` -- show RDP logon correlation
6. Agent calls `submit_finding` -- show the Pydantic validation accepting the finding with evidence refs
7. Agent calls `finalize_report`

**Narration:**

> The agent follows a structured investigation strategy. It starts broad with composite tools, then cross-verifies every finding using correlate_across_sources. Watch here -- the agent found a suspicious process via malfind, but when it checked the event logs, there was no corroborating evidence. Instead of reporting a false positive, it demoted the finding to "inference" and noted the missing corroboration. This self-correction loop is what separates Killjoy from a simple prompt-and-pray approach.

---

## 4:00 -- 4:45 | Report and Audit Trail

**On screen:** The generated report in a Markdown viewer.

**Show:**
- Executive summary with finding counts (confirmed vs. inference)
- A specific finding: click through the evidence_refs to the audit log entries
- Show the JSONL audit log: tool_call_id -> tool_name -> params -> output_hash
- Trace a finding back to the original evidence file with its SHA-256 hash

**Narration:**

> Every finding in the report links to specific tool call IDs. Each tool call is logged with its parameters and an output hash. From any finding, a judge can trace the full provenance chain: finding, to tool call, to source, to original evidence file with its SHA-256 hash. This is the audit trail that criterion 5 demands.

---

## 4:45 -- 5:00 | Spoliation Test

**On screen:** Terminal showing the MCP tool list.

**Show:**
- Print the full list of registered MCP tools
- Highlight: every single tool is a query/read operation
- No `execute_shell`, no `write_file`, no `delete`, no `modify`

**Narration:**

> Finally, the spoliation test. Here is the complete MCP tool surface. Every tool is a read operation. There is no shell execution, no file writing, no evidence modification. The agent literally cannot spoliate evidence because the verbs do not exist. This is an architectural guardrail, not a prompt-based one.

---

## Recording Notes

- Record on the SIFT Workstation (or Docker container) for authenticity
- Use a dark terminal theme with large font for readability
- Color-coded agent output (THINK/TOOL/RESULT/FINDING/VERIFY prefixes) is built into `killjoy investigate --verbose`
- Keep the mouse cursor visible when clicking through the report for the audit trail walkthrough
- Target 720p or 1080p resolution
