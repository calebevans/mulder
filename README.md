<div align="center">

# mulder


</div>

Mulder is an [MCP](https://modelcontextprotocol.io/) server and SDK orchestrator for digital forensics. It exposes 110+ typed forensic tools (Volatility 3, Sleuthkit, Plaso, Hayabusa, YARA, and more) through the Model Context Protocol with no shell access, and includes a multi-phase SDK orchestrator that runs full investigations autonomously with quality gates between phases.

<p align="center">
  <img src="docs/photos/report-demo.gif" alt="Mulder report demo" width="800">
</p>

<p align="center">
  <b>Example reports:</b>&nbsp;
  <a href="https://calebevans.github.io/mulder/examples/nist-data-leakage/sonnet/nist-data-leakage.report.html">NIST Data Leakage</a> · <a href="https://calebevans.github.io/mulder/examples/ngdc/sonnet/ngdc.report.html">National Gallery DC</a>
</p>

## Features

- **MCP server** with 110+ typed forensic tools covering memory, disk, timeline, Windows event logs, YARA, network capture, mobile, steganography, and more
- **SDK orchestrator** that decomposes investigations into six phases (Catalog, Extraction, Cross-System Analysis, Alternative Narrative, Audit, Report) with hard quality gates between each phase
- **Per-case SQLite database** with FTS5 full-text search across all indexed evidence
- **Append-only audit log** that records every tool invocation; findings must cite real tool call IDs to prevent hallucinated evidence citations
- **Cross-source correlation** to join evidence from different artifact types within a time range
- **Rich Live dashboard** showing real-time investigation progress, per-model token usage, findings, and throughput
- **Report generation** producing both Markdown and styled HTML reports with IOC tables, MITRE ATT&CK coverage, and full audit trails
- **Resource throttling** with configurable memory and CPU limits so extractions do not overwhelm the host
- **Parallel extraction** with a configurable worker pool, background job management, and a `run_parallel` meta-tool for batch dispatch
- **Finding validator** that checks CRITICAL/HIGH findings against cited evidence in real time, rejecting unsupported claims and downgrading miscalibrated confidence
- **Auto-compaction** that detects context window exhaustion and restarts phases with a compact prompt, recovering state from the database
- **Per-model token tracking** with role-based model assignment (planner, executor, analyst) and per-role usage breakdowns

### Example Output

From the agent's live terminal during a [NIST insider threat investigation](examples/nist-data-leakage/):

```
BOMBSHELL: Informant's Downloads folder contains:
  - googledrivesync.exe + Zone.Identifier (downloaded from internet!)
  - icloudsetup.exe + Zone.Identifier (also downloaded from internet!)

  Multi-vector exfiltration: USB drives (x2), CD-R burn, Google Drive cloud
  sync, and possibly iCloud!

SMOKING GUN: Browser Search Queries Show Premeditation:
  search?q=anti-forensic+tools      (n=85)
  search?q=ccleaner                 (n=65)
  search?q=cd+burning+method        (n=64)
  search?q=external+device+forensics (n=65)
  search?q=DLP+DRM                  (n=90)
  search?q=e-mail+investigation     (n=88)

  The informant researched how to cover their tracks AND how forensic
  investigations work. This is deliberate, premeditated data theft.
```

From a single Sonnet run: 14 findings, 9 critical, 34 minutes. Report with narrative, IOCs, and MITRE ATT&CK mappings generated automatically.

See [examples/](examples/) for reports from multiple forensic datasets with ground truth comparisons, including runs on both Opus and Sonnet.

## Getting Started

### Docker/Podman

The container image comes with all forensic tools, dependencies, Claude Code, and the Mulder MCP server pre-installed. The SDK orchestrator runs inside the container, launching Claude Code sessions that connect to the MCP server automatically.

```bash
docker pull ghcr.io/calebevans/mulder:1.1
```

#### Running the Container

The container runs as a non-root `mulder` user for security. An entrypoint script handles credential copying and permission setup automatically.

The container expects three volume mounts:

| Mount | Purpose |
|-------|---------|
| `/evidence` | Your evidence directory (mount read-only with `:ro`) |
| `/home/mulder/.mulder/cases` | Case databases, audit logs, and generated reports (persisted to host) |
| `/home/mulder/.claude` | Claude Code configuration and session data |

**With an Anthropic API key:**

```bash
mkdir -p ~/mulder-cases

docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -v ~/.claude:/home/mulder/.claude \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  ghcr.io/calebevans/mulder:1.1
```

**With Google Cloud Vertex AI:**

```bash
mkdir -p ~/mulder-cases

docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -v ~/.claude:/home/mulder/.claude \
  -e CLAUDE_CODE_USE_VERTEX=1 \
  -e CLOUD_ML_REGION=us-east5 \
  -e ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project-id \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcloud-creds.json \
  -v ~/.config/gcloud/application_default_credentials.json:/tmp/gcloud-creds.json:ro \
  ghcr.io/calebevans/mulder:1.1
```

**With Amazon Bedrock:**

```bash
mkdir -p ~/mulder-cases

docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -v ~/.claude:/home/mulder/.claude \
  -e CLAUDE_CODE_USE_BEDROCK=1 \
  -e AWS_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  ghcr.io/calebevans/mulder:1.1
```

#### Starting an Investigation

Use the `mulder investigate` command to run a full autonomous investigation:

```bash
mulder investigate /evidence/case-2025-001
```

The orchestrator will:
1. Catalog all evidence files and classify their types
2. Run per-system extraction (memory analysis, disk forensics, log parsing)
3. Perform cross-system correlation and MITRE ATT&CK mapping
4. Challenge the primary narrative with alternative hypotheses
5. Audit for completeness and tool coverage gaps
6. Generate a comprehensive investigation report

Case databases and reports are written to the mounted `~/mulder-cases` directory on the host.

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | | API key for direct Anthropic access |
| `CLAUDE_CODE_USE_VERTEX` | | Set to `1` for Google Cloud Vertex AI |
| `CLAUDE_CODE_USE_BEDROCK` | | Set to `1` for Amazon Bedrock |
| `DISABLE_AUTOUPDATE` | `1` | Prevents Claude Code from auto-updating inside the container (set by default in the image) |

## Investigation Pipeline

Each phase (except catalog and report) uses a three-agent pipeline:

1. **Planner** (Sonnet): examines evidence, outputs a structured tool execution plan
2. **Executor** (Haiku): follows the plan, calls tools, reports results
3. **Analyst** (Sonnet): interprets results, submits findings

This reduces cost by ~40-60% versus running a single expensive model for the entire phase, while maintaining reasoning quality where it matters.

| Role | Default Model | Responsibility |
|------|--------------|----------------|
| Planner | Sonnet | Decides what tools to run, produces execution plans |
| Executor | Haiku | Calls tools mechanically, manages waits and retries |
| Analyst | Sonnet | Queries indexed data, reasons about evidence, submits findings |

### Phases

| Phase | Objective | Mode |
|-------|-----------|------|
| 1. Catalog | Enumerate and classify all evidence files, identify distinct systems | Single (Planner model) |
| 2. Extraction | Run all applicable forensic tools per system, submit findings | Split (per system) |
| 3. Cross-System | Correlate events across systems, map MITRE ATT&CK, consolidate findings | Split |
| 3.5 Alternative Narrative | Challenge primary narrative, search for counter-evidence | Split |
| 4. Audit | Verify completeness, fix timestamps, close coverage gaps | Split |
| 5. Report | Write investigation narrative and generate the final report | Single (Analyst model) |

Each phase passes through a quality gate before proceeding. Failed gates trigger retries with increased turn limits and gap-specific remediation instructions. The analyst can request follow-up cycles (capped at a maximum per phase) when it needs additional tool execution.

## CLI Reference

### `mulder investigate <evidence_path>`

Runs a full multi-phase forensic investigation using the SDK orchestrator.

| Option | Default | Description |
|--------|---------|-------------|
| `--model` | None | Fallback model for all roles |
| `--planner-model` | `claude-sonnet-4-6` | Model for planner agents (decides what tools to run) |
| `--executor-model` | `claude-haiku-4-5` | Model for executor agents (calls tools, manages waits) |
| `--analyst-model` | `claude-sonnet-4-6` | Model for analyst agents (interprets results, submits findings) |
| `--config` | None | YAML config file for models and settings |
| `--effort` | `max` | Effort level for Claude Code sessions (`max`, `xhigh`, `high`) |
| `--workers` | `3` | Maximum parallel extraction sessions |
| `--db-dir` | `~/.mulder/cases` | Case database directory |
| `--cwd` | `/mulder-investigation` | Working directory for Claude Code sessions |
| `--proxy-config` | None | LiteLLM config YAML for custom model routing |

**Cost-optimized (recommended):**

```bash
mulder investigate /evidence/case-2025-001 \
  --planner-model claude-sonnet-4-6 \
  --executor-model claude-haiku-4-5 \
  --analyst-model claude-sonnet-4-6
```

**Single model (simple):**

```bash
mulder investigate /evidence/case-2025-001 --model claude-sonnet-4-6
```

**Config file:**

```bash
mulder investigate /evidence/case-2025-001 --config investigation.yaml
```

All roles inherit from `--model` when not explicitly set, so a single `--model` flag is sufficient for providers that use a unified model identifier.

**Non-Claude models** (via built-in LiteLLM proxy, supports Bedrock, OpenAI, Vertex AI, Ollama):

```bash
# Use a Bedrock-hosted Llama model for all roles
mulder investigate /evidence/case-2025-001 \
  --model bedrock/meta.llama3-1-70b-instruct-v1:0

# Mix providers: Llama for execution, Claude for planning and analysis
mulder investigate /evidence/case-2025-001 \
  --executor-model bedrock/meta.llama3-1-70b-instruct-v1:0 \
  --planner-model claude-sonnet-4-6 \
  --analyst-model claude-sonnet-4-6

# Use a local Ollama model
mulder investigate /evidence/case-2025-001 \
  --model ollama/llama3.1:70b
```

When any model ID uses a provider prefix (`bedrock/`, `openai/`, `vertex_ai/`, `azure/`, `ollama/`), a local LiteLLM proxy is auto-started to translate between the Anthropic API format and the target provider. No manual proxy setup is required.

For advanced routing, pass a custom LiteLLM config:

```bash
mulder investigate /evidence/case-2025-001 \
  --proxy-config ./litellm_config.yaml \
  --model my-custom-deployment
```

| Option | Default | Description |
|--------|---------|-------------|
| `--proxy-config` | None | Path to a LiteLLM config YAML for custom model routing |

### `mulder serve`

Starts the MCP server. Normally invoked automatically by the orchestrator or MCP client configuration.

| Option | Default | Description |
|--------|---------|-------------|
| `--case-id` | None | Pre-load an existing case on startup |
| `--db-dir` | `~/.mulder/cases` | Directory for per-case databases and audit logs |
| `--transport` | `stdio` | MCP transport (`stdio` or `streamable-http`) |
| `--workers` | `8` | Number of parallel extraction workers |
| `--mem-limit` | `90` | Memory usage % threshold; tools wait when exceeded (0 to disable) |
| `--cpu-limit` | `90` | CPU usage % threshold; tools wait when exceeded (0 to disable) |

### `mulder report <case_id>`

Generates reports offline without starting the MCP server.

| Option | Default | Description |
|--------|---------|-------------|
| `--db-dir` | `~/.mulder/cases` | Directory containing case databases |

Reads `{case_id}.db` and `{case_id}.audit.jsonl` from the database directory and writes `{case_id}.report.md` and `{case_id}.report.html` alongside them.

## Supported Forensic Tools

| Tool | Description |
|------|-------------|
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Memory forensics framework for analyzing RAM dumps |
| [Sleuthkit](https://www.sleuthkit.org/) | Disk image analysis, filesystem listing, file extraction, and MAC timelines |
| [Plaso](https://github.com/log2timeline/plaso) | Super-timeline generation from disk images and log artifacts |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Windows event log threat hunting with Sigma rules |
| [YARA](https://virustotal.github.io/yara/) | Pattern matching across files, memory dumps, and Volatility output |
| [bulk_extractor](https://github.com/simsong/bulk_extractor) | Carves emails, URLs, credit card numbers, and other IOCs from raw data |
| [Eric Zimmerman tools](https://ericzimmerman.github.io/) | Windows artifact parsers (Prefetch, Amcache, ShimCache, Jump Lists, LNK, Shellbags, SRUM, MFT, USN Journal) |
| [RegRipper](https://github.com/keydet89/RegRipper3.0) | Windows registry hive parsing |
| [python-evtx](https://github.com/williballenthin/python-evtx) | Windows EVTX event log parsing and indexing |
| [foremost](https://foremost.sourceforge.net/) | File carving from disk images |
| [Scalpel](https://github.com/sleuthkit/scalpel) | File carving and recovery |
| [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) | File recovery from disk images |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Firmware and embedded file analysis |
| [ClamAV](https://www.clamav.net/) | Malware scanning |
| [ExifTool](https://exiftool.org/) | File metadata extraction |
| [ssdeep](https://ssdeep-project.github.io/ssdeep/) | Fuzzy hashing for file similarity |
| [hashdeep](https://github.com/jessek/hashdeep) | Recursive cryptographic hashing |
| [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) | Network capture (PCAP) analysis |
| [chkrootkit](http://www.chkrootkit.org/) | Rootkit detection |
| [steghide](https://steghide.sourceforge.net/) / stegdetect | Steganography detection and extraction |
| [strings](https://man7.org/linux/man-pages/man1/strings.1.html) | Extract printable strings from binary files |
| [pasco](https://www.mcafee.com/enterprise/en-us/downloads/free-tools.html) | Internet Explorer history parsing |
| [Hindsight](https://github.com/obsidianforensics/hindsight) | Chrome/Chromium browser forensics (history, cookies, downloads, cache) |
| [MVT](https://github.com/mvt-project/mvt) | Mobile Verification Toolkit for spyware detection (Pegasus, Predator) |
| [radare2](https://github.com/radareorg/radare2) | Binary analysis and reverse engineering for malware triage |
| [dislocker](https://github.com/Aorimn/dislocker) / [libbde](https://github.com/libyal/libbde) | BitLocker volume decryption and metadata extraction |
| [libfvde](https://github.com/libyal/libfvde) | Apple FileVault encryption metadata extraction |
| [tcpflow](https://github.com/simsong/tcpflow) / [tcpxtract](https://tcpxtract.sourceforge.net/) | TCP stream reconstruction and file extraction from PCAPs |

## Report Generation

Mulder generates two report formats from the case database and audit log:

- **Markdown** (`{case_id}.report.md`) for plain-text review and version control
- **HTML** (`{case_id}.report.html`) a self-contained styled page with dark/light theme, sidebar navigation, and interactive layout

Both formats include an executive summary, severity overview, evidence integrity hashes, attack timeline, detailed findings with MITRE ATT&CK mappings, IOC tables (network, file, email), audit metrics, and a sources appendix.

Reports can be generated in two ways:

1. **Automatically** by the SDK orchestrator at the end of a successful investigation
2. **CLI**: run `mulder report <case_id>` offline without starting the server

## Architecture

See [docs/architecture.md](docs/architecture.md) for a detailed technical overview of the server internals, SDK orchestrator pipeline, database schema, and security model.
