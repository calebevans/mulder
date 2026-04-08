# Killjoy -- Devpost Writeup

## What It Does

Killjoy is a custom MCP server that turns the SANS SIFT Workstation into an autonomous forensic investigation platform. It ingests a forensic case (memory dumps, disk images, event logs, text logs), builds a per-case semantic index, and then lets an AI agent investigate through typed, read-only MCP tools.

The agent follows a structured investigation strategy: broad sweeps with composite tools (suspicious processes, persistence mechanisms, lateral movement), cross-verification across multiple artifact types, and self-correction when evidence conflicts. Every finding must pass Pydantic validation that rejects submissions missing evidence references or citing non-existent tool calls.

The result: a Markdown report where every finding traces back through the audit trail to the original evidence file with its SHA-256 hash.

## How We Built It

**Architectural approach:** Custom MCP Server (hackathon brief option #2). This was chosen over prompt-only approaches because it allows evidence integrity to be enforced at the API boundary rather than through prompt instructions.

**Key design decisions:**

- **Typed read-only MCP surface.** The tool list contains only query operations. There are no destructive verbs. The agent cannot spoliate evidence because the API does not allow it.
- **Pydantic validation on submit_finding.** Every finding must include `evidence_refs` pointing to real `tool_call_id` values from the audit log. The server rejects findings with empty or invalid references.
- **Selective Cordon usage.** Verbose artifacts (Plaso timelines, event logs) are reduced via Cordon's anomaly detection before being returned to the agent. Small structured artifacts (prefetch, registry, cmdline) are returned raw. A token budget planner decides per-source.
- **Per-case sqlite-vec databases.** Each case gets its own database file. No cross-case contamination. The semantic index is immutable after ingestion.

**Tech stack:**
- MCP server: `mcp` (FastMCP)
- Embeddings: `sentence-transformers` (all-MiniLM-L6-v2)
- Vector store: `sqlite-vec`
- Anomaly scoring: `cordon`
- LLM calls: `litellm`
- Findings validation: `pydantic`
- Report rendering: `jinja2`
- Secret redaction: `detect-secrets`
- CLI: `click`

## Challenges

- **Cordon baseline scope.** Per-source baselines produce much better anomaly scores than per-case baselines, because "normal" looks very different across artifact types (a normal pslist vs. a normal event log). We had to score anomalies within each source independently.
- **Timestamp parsing across formats.** ISO 8601, syslog (`MMM DD HH:MM:SS`), Windows event log, and Plaso L2T CSV all use different formats. The multi-format parser handles the common cases and falls back to `None` for unparseable timestamps.
- **Volatility output variability.** Different memory images produce wildly different output sizes. The malfind plugin can return nothing or thousands of lines. The token budget planner handles this dynamically.
- **Self-correction without over-correction.** The agent needs to cross-verify findings without falling into infinite re-query loops. The iteration cap (default 20) and the structured investigation strategy keep it focused.

## What We Learned

- API-level guardrails are stronger than prompt-level guardrails. An agent that has no `execute_shell` tool cannot run shell commands, regardless of how it is prompted.
- Semantic search over forensic artifacts is surprisingly effective. A query like "suspicious PowerShell execution" finds encoded command lines, invoke-expression patterns, and base64-encoded payloads across different evidence types.
- Cross-source correlation is the real differentiator. Any tool can find anomalies in one artifact type. Correlating across memory, event logs, and filesystem timelines at the same timestamp range is what produces high-confidence findings.

## What's Next

- **Live SOC mode.** Stream new evidence into the index as it arrives, rather than requiring batch ingestion.
- **Wider extractor coverage.** Add extractors for macOS/Linux memory (via Volatility Linux/Mac plugins), cloud logs (AWS CloudTrail, Azure Activity Log), and network captures (Zeek logs).
- **Cross-case baselines.** Maintain a baseline database across cases to detect patterns that repeat across incidents.
- **Interactive mode.** Let a human analyst ask follow-up questions via the MCP server while the agent is investigating.
