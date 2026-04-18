# Mulder Demo Video Script

Target length: 5 minutes.

---

## 0:00 -- 0:30 | Introduction

**On screen:** Title card, then terminal on the SIFT Workstation.

**Narration:**

> Mulder is a custom MCP server for forensic investigations on the SANS SIFT Workstation. It gives Claude Code 50+ typed, read-only forensic tools. The agent ingests evidence, builds a semantic index, investigates autonomously, and produces a report -- all through MCP. The agent cannot modify evidence because the API surface does not contain destructive operations.

**Key points to hit:**
- Custom MCP Server architecture (hackathon approach #2)
- Claude Code as the agentic framework
- Evidence integrity enforced by API design, not prompts

---

## 0:30 -- 1:00 | Setup

**On screen:** Terminal showing the `.mcp.json` config and the skill file.

**Show:**
- The `.mcp.json` file: one MCP server entry, points to `mulder serve`
- The `.claude/skills/investigate.md` skill: phased investigation strategy
- Start Claude Code: `claude`

**Narration:**

> Setup is two files. The MCP config tells Claude Code how to launch the Mulder server. The skill file teaches Claude the investigation methodology -- how to sequence tools, when to cross-verify, and when to demote confidence. Let's start Claude Code and give it some evidence.

---

## 1:00 -- 1:30 | Ingestion

**On screen:** Claude Code calling `ingest_evidence`.

**Show:**
- User prompt: "Investigate the evidence at /cases/sample-case/"
- Claude calls `ingest_evidence("/cases/sample-case/")`
- Evidence classification output (memory dump detected, EVTX files found, log directories scanned)
- Extractors running (Volatility, Plaso, EVTX parser)
- Final summary: N sources, M windows, elapsed time

**Narration:**

> I ask Claude to investigate evidence. It calls `ingest_evidence`, which scans the directory, classifies each file, and runs the appropriate extractor. Memory dumps go through Volatility 3, disk images through Plaso and Sleuth Kit, event logs through our EVTX parser. Everything is embedded and stored in a per-case sqlite-vec database.

---

## 1:30 -- 4:00 | Autonomous Investigation

**On screen:** Claude Code calling forensic tools.

**Show the real-time tool calls:**

1. Claude calls `list_sources` -- show the enumeration of available evidence
2. Claude calls `find_suspicious_processes` -- highlight the composite query joining malfind + cmdline + netscan + pstree
3. Claude calls `correlate_across_sources` for the suspicious time range
4. **Self-correction moment** (the tiebreaker):
   - Claude finds a process flagged by malfind
   - Cross-checks with event logs -- no corresponding service installation event
   - Demotes the finding from "confirmed" to "inference" and notes the gap
5. Claude calls `find_lateral_movement_indicators` -- show RDP logon correlation
6. Claude calls `submit_finding` -- show the Pydantic validation accepting the finding with evidence refs
7. Claude calls `finalize_report`

**Narration:**

> Claude follows the investigation skill. It starts broad with composite tools, then cross-verifies every finding. Watch here -- Claude found a suspicious process via malfind, but when it checked the event logs, there was no corroborating evidence. Instead of reporting a false positive, it demoted the finding to "inference" and noted the missing corroboration. This self-correction loop is what separates Mulder from a simple prompt-and-pray approach.

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

**On screen:** The MCP tool list.

**Show:**
- List all registered MCP tools
- Highlight: every single tool is a query/read operation
- No `execute_shell`, no `write_file`, no `delete`, no `modify`

**Narration:**

> Finally, the spoliation test. Here is the complete MCP tool surface. Every tool is a read operation. There is no shell execution, no file writing, no evidence modification. The agent literally cannot spoliate evidence because the verbs do not exist. This is an architectural guardrail, not a prompt-based one.

---

## Recording Notes

- Record on the SIFT Workstation (or Docker container) for authenticity
- Use a dark terminal theme with large font for readability
- Claude Code's built-in tool-use display shows each MCP call clearly
- Keep the mouse cursor visible when clicking through the report for the audit trail walkthrough
- Target 720p or 1080p resolution
