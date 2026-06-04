<div align="center">

# mulder

**MCP server and agentic orchestrator for digital forensics.**
**145+ typed forensic tools. No shell access. Fully autonomous investigations.**

</div>

Mulder takes a directory of forensic evidence (disk images, memory dumps, PCAPs, event logs) and runs a five-phase autonomous investigation with hard quality gates between each phase. It produces structured incident reports with MITRE ATT&CK mappings, IOC exports, and a full audit trail. An adversarial "Alternative Narrative" phase challenges every finding before the report is generated. All tool invocations go through typed MCP interfaces - never through a shell - and an append-only audit log validates every evidence citation at the API boundary, making hallucinated findings structurally impossible to submit.

## Results

Four autonomous investigations against real forensic datasets, unmodified from tool output:

| Case | Systems | Evidence | Sources | Tool Calls | Findings | Runtime | Tokens |
|------|---------|----------|---------|------------|----------|---------|--------|
| [Rocba](examples/rocba/) | 1 | ~8 GB | 85 | 396 | 15 (2 high) | 72 min | 104K |
| [SRL-2015](examples/srl-2015/) | 4 | ~30 GB | 154 | 614 | 28 (21 high) | 108 min | 216K |
| [SRL-2018](examples/srl-2018/) | 9 | ~120 GB | 365 | 1,060 | 50 (4 crit, 9 high) | 234 min | 301K |
| [Szechuan](examples/szechuan/) | 2 | ~13 GB | 115 | 412 | 18 (3 crit, 6 high) | 55 min | 134K |

The Szechuan case has a [detailed accuracy report](examples/szechuan/ACCURACY-REPORT.md) validated against [published ground truth](https://dfirmadness.com/the-stolen-szechuan-sauce/): 57% full match, 79% detection rate, 0% false positive rate. The Alternative Narrative phase caught and corrected two would-be false positives (a DCSync misclassification and an over-matching YARA rule) before they reached the final report.

## How It Works

Each investigation runs through five phases with quality gates between them. Phases 2-4 use a plan-and-execute pipeline with three specialized roles (planner, executor, analyst) that can optionally be assigned to different models for cost optimization.

1. **Catalog** - scan evidence directory, classify file types, identify distinct systems
2. **Extraction** - run applicable forensic tools per system, index results into FTS5 database
3. **Cross-System Analysis** - correlate events across systems, map MITRE ATT&CK techniques, deduplicate findings
4. **Alternative Narrative** - challenge the primary narrative with counter-evidence, test alternative hypotheses, audit for tool and evidence coverage gaps
5. **Report** - write the investigation narrative, generate Markdown/HTML reports, export IOCs and ATT&CK Navigator layers

Each gate validates structural criteria (minimum sources indexed, findings submitted, MITRE mappings present, audit tools invoked). Failed gates trigger retries with escalating turn budgets and gap-specific remediation instructions. See [Architecture](docs/architecture.md) for the full pipeline design.

## Key Design Decisions

**No shell access.** All 145+ tool invocations go through typed MCP interfaces with validated parameters. The agent never gets a shell. Every action is auditable and every parameter is constrained to its declared type.

**Anti-hallucination at the API boundary.** Every finding must cite `evidence_refs` that are real `tool_call_id` values from the append-only audit log. The MCP server validates these references at submission time and rejects findings that cite nonexistent tool calls. Timestamps are validated as ISO-8601 and auto-nullified when they appear fabricated. This is enforced architecturally, not by prompting.

**Adversarial self-review.** Phase 4 explicitly challenges the primary narrative before report generation. It formulates counter-hypotheses, searches for disconfirming evidence, and runs coverage audits to identify which tools were applicable but never invoked and which evidence sources were indexed but never cited. In the Szechuan case, this phase ran 28 structured challenge tasks in 10 minutes.

**Token efficiency.** The SRL-2018 investigation (9 systems, 120 GB, 1,060 tool calls across 234 minutes) consumed 301K tokens. For cost optimization, the three pipeline roles (planner, executor, analyst) can be assigned to different models - routing mechanical tool-calling to a cheaper model while preserving reasoning quality for analysis.

## Quick Start

```bash
docker pull ghcr.io/calebevans/mulder:1.1
```

```bash
mkdir -p ~/mulder-cases

docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  ghcr.io/calebevans/mulder:1.1
```

```bash
mulder investigate /evidence my-case-id
```

For Vertex AI, Amazon Bedrock, non-Anthropic models via LiteLLM, and full CLI options, see the [Usage Guide](docs/usage-guide.md).

## Forensic Tools

Mulder integrates 35+ open-source forensic tools exposed as 145+ typed MCP operations:

**Memory:** Volatility 3 (14 plugins) | **Disk:** Sleuthkit, Plaso, foremost, PhotoRec, Scalpel | **Windows artifacts:** EZ Tools (Prefetch, Amcache, ShimCache, MFT, USN Journal, Jump Lists, Shellbags, SRUM), RegRipper, Hayabusa (3,700+ Sigma rules), Chainsaw | **Event logs:** python-evtx, Zircolite | **Network:** tshark, Zeek, Suricata, tcpflow, tcpxtract | **Malware:** YARA, CAPA, FLOSS, Detect-It-Easy, ClamAV, radare2 | **Documents:** oletools, PDF tools, pst-utils | **Mobile:** ALEAPP, iLEAPP, MVT | **Other:** bulk_extractor, binwalk, ExifTool, ssdeep, hashdeep, steghide, Hindsight

Full API reference: [Tool Manifest](docs/tool-manifest.md)

## Output

Each investigation produces:

- **Markdown and HTML reports** - executive summary, attack timeline, findings with MITRE ATT&CK mappings, IOC tables, and audit trail
- **Per-case SQLite database** - FTS5 full-text search across all indexed evidence
- **Append-only audit log** - JSONL recording every tool invocation with BLAKE2b output hashes
- **Optional exports** - STIX 2.1 IOC bundle, CSV IOC list, and MITRE ATT&CK Navigator layer via `mulder export-iocs` and `mulder export-navigator`

## Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/usage-guide.md) | Installation, providers, CLI reference, Docker configuration |
| [Architecture](docs/architecture.md) | System design, pipeline phases, quality gates, data flow |
| [Tool Manifest](docs/tool-manifest.md) | API reference for all 146 MCP tools |
| [Adding Tools](docs/adding-tools.md) | Contributor guide for adding new forensic tools |
| [Glossary](docs/glossary.md) | Terminology and definitions |

## License

Apache-2.0
