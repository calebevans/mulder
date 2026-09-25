<div align="center">

# mulder
### 🏆 1st Place - SANS Institute [Find Evil Hackathon 2026](https://www.sans.org/press/announcements/sans-names-the-five-winners-of-find-evil-2026)
</div>

Mulder takes a directory of forensic evidence (disk images, memory dumps, PCAPs, event logs) and runs a five-phase autonomous investigation with hard quality gates between each phase. It produces structured incident reports with MITRE ATT&CK mappings, IOC exports, and a full audit trail. An adversarial "Alternative Narrative" phase challenges every finding before the report is generated. All tool invocations go through typed MCP interfaces - never through a shell - and an append-only audit log validates every evidence citation at the API boundary, making findings with fabricated evidence citations structurally impossible to submit.

## Results

Three models on the [NIST CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) on the v1.5.2 release image, with the same evidence, prompts and tools. Each is scored item by item against the [published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) (20 ground-truth items; **full match** = the exact fact stated, **detection** = at least related evidence found, **false positives** = claims the answer key contradicts). Every report, log and scorecard is in the repo, unmodified from tool output.

| Model | Full match | Detection | False positives | Runtime per run |
|-------|-----------:|----------:|----------------:|----------------:|
| Claude Opus 4.6 (Anthropic) | 45% (45–50) | 95% (90–95) | 10% (5–10) | 68–79 min |
| Kimi K3 (Bedrock, open weight) | 35% (35–50) | 90% (80–95) | 20% (20–25) | 52–70 min |
| GLM-5 (Bedrock, open weight) | 20% (20–25) | 75% (75–90) | 20% (10–25) | 60–63 min |

Reports and scorecards for every run:

| Model | Runs |
|-------|------|
| Claude Opus 4.6 | [run 1](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/opus-4.6-run1/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/opus-4.6-run1/ACCURACY-REPORT.md)) · [run 2](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/opus-4.6-run2/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/opus-4.6-run2/ACCURACY-REPORT.md)) · [run 3](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/opus-4.6-run3/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/opus-4.6-run3/ACCURACY-REPORT.md)) |
| Kimi K3 | [run 1](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/kimi-k3-run1/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/kimi-k3-run1/ACCURACY-REPORT.md)) · [run 2](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/kimi-k3-run2/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/kimi-k3-run2/ACCURACY-REPORT.md)) · [run 3](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/kimi-k3-run3/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/kimi-k3-run3/ACCURACY-REPORT.md)) |
| GLM-5 | [run 1](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/glm-5-run1/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/glm-5-run1/ACCURACY-REPORT.md)) · [run 2](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/glm-5-run2/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/glm-5-run2/ACCURACY-REPORT.md)) · [run 3](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/glm-5-run3/ndlc.report.html) ([scorecard](https://github.com/calebevans/mulder/blob/main/examples/ndlc-v1.5.2/glm-5-run3/ACCURACY-REPORT.md)) |

Claude Opus 4.6 ran with extended thinking; the open-weight models ran on Amazon Bedrock through Mulder's LiteLLM proxy (both with native reasoning; GLM-5 needs no per-model overrides). Each model was run three times and is shown as the median with the range in parentheses; every run is published. Models that were tried and are not recommended are left out of the table: MiniMax M2.5, DeepSeek V3.2 and Qwen3 235B (three runs each, at most 5% full match), and Mistral Large 3, Qwen3 Coder 480B, gpt-oss-120b, GLM-4.7, Kimi K2.5 and Kimi K2 Thinking (one or two runs each: no usable report, a collapsed catalog, or at or below 40% detection). Detection means the model surfaced the evidence; full match means it stated the exact serial, label, filename, timestamp or count the answer key lists. Older investigations of other datasets are still in the [examples directory](https://github.com/calebevans/mulder/blob/main/examples/README.md).

## How It Works

<p align="center">
<img src="https://raw.githubusercontent.com/calebevans/mulder/main/docs/images/diagram.png" alt="Mulder Architecture and Security Boundaries" width="420">
</p>

Each investigation runs through five phases with quality gates between them. Phases 2-4 use a plan-and-execute pipeline with three specialized roles (planner, executor, analyst) that can optionally be assigned to different models for cost optimization.

1. **Catalog** - scan evidence directory, classify file types, identify distinct systems
2. **Extraction** - run applicable forensic tools per system, index results into FTS5 database
3. **Cross-System Analysis** - correlate events across systems, map MITRE ATT&CK techniques, deduplicate findings
4. **Alternative Narrative** - challenge the primary narrative with counter-evidence, test alternative hypotheses, audit for tool and evidence coverage gaps
5. **Report** - write the investigation narrative, generate Markdown/HTML reports, export IOCs and ATT&CK Navigator layers

Each gate validates structural criteria (minimum sources indexed, findings submitted, MITRE mappings present, audit tools invoked). Failed gates trigger bounded phase retries; single-agent retries include gap-specific remediation instructions. See [Architecture](https://github.com/calebevans/mulder/blob/main/docs/architecture.md) for the full pipeline design.

## Key Design Decisions

**No shell access, no built-in tools.** All 140+ tool invocations go through typed MCP interfaces with validated parameters. Every Claude Code built-in tool (Bash, Read, Grep, Glob, Write, Edit, WebFetch, WebSearch, ...) is disabled for every agent session, so the agent never gets a shell, never reads evidence or writes the workspace outside the audit log, and never reaches the network. Every action is auditable and every parameter is constrained to its declared type.

**Anti-hallucination at the API boundary.** Every finding must cite `evidence_refs` that are real `tool_call_id` values from the append-only audit log. The MCP server validates these references at submission time and rejects findings that cite nonexistent tool calls. Timestamps are validated as ISO-8601 and auto-nullified when they appear fabricated. This is enforced architecturally, not by prompting.

**Adversarial self-review.** Phase 4 explicitly challenges the primary narrative before report generation. It formulates counter-hypotheses, searches for disconfirming evidence, and runs coverage audits to identify which tools were applicable but never invoked and which evidence sources were indexed but never cited.

**Token efficiency.** The SRL-2018 investigation (11 systems, 120 GB, 1,508 tool calls across 336 minutes) consumed 698K tokens. For cost optimization, the three pipeline roles (planner, executor, analyst) can be assigned to different models - routing mechanical tool-calling to a cheaper model while preserving reasoning quality for analysis.

## Quick Start

### Install natively (SIFT Workstation, Debian/Ubuntu)

```bash
sudo apt install git sleuthkit yara p7zip-full binutils
pipx install "mulder-dfir[forensics]"
mulder setup
mulder investigate /path/to/evidence my-case-id
```

`pipx` installs mulder into its own isolated virtualenv and puts the `mulder` command on your PATH; `uv tool install "mulder-dfir[forensics]"` works identically. The `forensics` extra pulls in Zircolite's runtime dependencies. If `mulder` is not found afterwards, open a new terminal — Ubuntu only adds `~/.local/bin` to `PATH` at login, and only if it already existed.

On first run mulder creates a working directory at `~/.mulder/workspace` (override with `--cwd` or `MULDER_CWD`) and writes a default `.mcp.json` into it. Case databases and reports go to `~/.mulder/cases` (override with `--db-dir`).

`mulder setup` downloads everything mulder owns - rule sets, signatures, and helper binaries - in one run (~2.2 GB, no `sudo`, refuses to run as root). It pins the same versions the container image uses. The rest of the forensic toolchain (Sleuth Kit, plaso, Zeek, `dotnet`) is your OS's job; SIFT already provides all of it except the `yara` binary above. See the [Usage Guide](https://github.com/calebevans/mulder/blob/main/docs/usage-guide.md#native-install) for the full picture. The container remains available if you would rather not install anything at all.

### Run with Docker (everything preinstalled)

```bash
docker pull ghcr.io/calebevans/mulder:1.5.2
```

```bash
mkdir -p ~/mulder-cases

docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  ghcr.io/calebevans/mulder:1.5.2
```

```bash
mulder investigate /evidence my-case-id
```

For Vertex AI, Amazon Bedrock, non-Anthropic models via LiteLLM, and full CLI options, see the [Usage Guide](https://github.com/calebevans/mulder/blob/main/docs/usage-guide.md).

### Use as an MCP server

Add to `claude_desktop_config.json` / `.mcp.json`:

```json
{
  "mcpServers": {
    "mulder": {
      "type": "stdio",
      "command": "mulder",
      "args": ["serve"]
    }
  }
}
```

Without installing first, `uvx mulder-dfir serve` works too.

### Case Briefing (Optional)

Drop a `MULDER.md` file in your evidence directory to provide case context:

```markdown
## What We Know
- The network was breached on March 15
- Suspect account: jsmith

## What We're Looking For
- How did the attacker gain initial access?
- Was data exfiltrated?
```

The briefing is injected into every investigation phase, guiding tool selection, analysis focus, and report framing. See the [Usage Guide](https://github.com/calebevans/mulder/blob/main/docs/usage-guide.md#case-briefing) for details.

## Forensic Tools

Mulder integrates 35+ open-source forensic tools exposed as 140+ typed MCP operations:

| Category | Tools |
|----------|-------|
| Memory | Volatility 3 (14 plugins) |
| Disk | Sleuthkit, Plaso, foremost, PhotoRec, Scalpel |
| Windows artifacts | EZ Tools (Prefetch, Amcache, ShimCache, MFT, USN Journal, Jump Lists, Shellbags, SRUM), RegRipper, Hayabusa (3,700+ Sigma rules), Chainsaw |
| Event logs | python-evtx, Zircolite |
| Network | tshark, Zeek, Suricata, tcpflow, tcpxtract, nfdump (NetFlow) |
| Malware | YARA, CAPA, FLOSS, ClamAV, radare2, Detect-It-Easy&nbsp;\* |
| Documents | oletools, PDF tools, pst-utils |
| Mobile | ALEAPP, iLEAPP, MVT |
| Other | bulk_extractor, binwalk, ExifTool, ssdeep, hashdeep, steghide, Hindsight |

\* Detect-It-Easy is supported but not bundled: its `.deb` pulls in ten `libqt5*` packages for a CLI that draws nothing. `run_detect_it_easy` uses it if `diec` is on `$PATH`, and reports it as missing otherwise. Packing is still flagged without it — `triage_binary` checks section entropy, RWX permissions, known packer section names and import-table shape.

Full API reference: [Tool Manifest](https://github.com/calebevans/mulder/blob/main/docs/tool-manifest.md)

## Output

Each investigation produces:

- **Markdown and HTML reports** - executive summary, attack timeline, findings with MITRE ATT&CK mappings, IOC tables, and audit trail ([example HTML reports](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/opus-4.6-run1/ndlc.report.html))
- **Per-case SQLite database** - FTS5 full-text search across all indexed evidence
- **Append-only audit log** - JSONL recording every tool invocation with BLAKE2b output hashes
- **Optional exports** - STIX 2.1 IOC bundle, CSV IOC list, and MITRE ATT&CK Navigator layer via `mulder export-iocs` and `mulder export-navigator`

## Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](https://github.com/calebevans/mulder/blob/main/docs/usage-guide.md) | Installation, providers, CLI reference, Docker configuration |
| [Architecture](https://github.com/calebevans/mulder/blob/main/docs/architecture.md) | System design, pipeline phases, quality gates, data flow |
| [Tool Manifest](https://github.com/calebevans/mulder/blob/main/docs/tool-manifest.md) | API reference for all MCP tools |
| [Adding Tools](https://github.com/calebevans/mulder/blob/main/docs/adding-tools.md) | Contributor guide for adding new forensic tools |
| [Glossary](https://github.com/calebevans/mulder/blob/main/docs/glossary.md) | Terminology and definitions |

## License

Apache-2.0
