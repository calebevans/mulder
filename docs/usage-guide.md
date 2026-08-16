# Usage Guide

Try-it-out instructions for running Mulder, the forensic investigation platform.

## Table of Contents

- [Usage Guide](#usage-guide)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Pulling the Container Image](#pulling-the-container-image)
  - [Running a Container](#running-a-container)
    - [Volume Mounts](#volume-mounts)
    - [Privileged Access](#privileged-access)
    - [Using an Anthropic API Key](#using-an-anthropic-api-key)
    - [Using Google Cloud Vertex AI](#using-google-cloud-vertex-ai)
    - [Using Amazon Bedrock](#using-amazon-bedrock)
  - [Starting an Investigation](#starting-an-investigation)
  - [Using Non-Anthropic Models via LiteLLM](#using-non-anthropic-models-via-litellm)
    - [Provider Prefixes](#provider-prefixes)
    - [Mixing Providers Across Roles](#mixing-providers-across-roles)
    - [Local Models with Ollama](#local-models-with-ollama)
    - [Custom LiteLLM Configuration](#custom-litellm-configuration)
  - [Case Briefing](#case-briefing)
    - [What to Include](#what-to-include)
    - [How It Works](#how-it-works)
    - [Example](#example)
  - [Artifact Awareness](#artifact-awareness)
  - [CLI Reference](#cli-reference)
    - [`mulder investigate`](#mulder-investigate)
    - [`mulder serve`](#mulder-serve)
    - [`mulder report`](#mulder-report)
    - [`mulder export-iocs`](#mulder-export-iocs)
    - [`mulder export-navigator`](#mulder-export-navigator)
  - [Understanding the Output](#understanding-the-output)
    - [Case Artifacts](#case-artifacts)
    - [Reports](#reports)
    - [IOC Exports](#ioc-exports)
    - [Logs](#logs)
  - [Building the Image from Source](#building-the-image-from-source)

## Prerequisites

- **Docker or Podman** installed and running. All commands below use `docker`, but `podman` works as a drop-in replacement.

  If you are on a SANS SIFT Workstation, there is a second option: `sudo ./install.sh` installs Mulder natively into an isolated virtualenv at `/opt/mulder` and reuses the forensic tools SIFT already provides, so there is no container to pull. See the [SIFT Install Guide](sift-install.md). Everything below still applies, minus the `docker run` wrapper: set the same environment variables in your shell and run `mulder investigate` directly.
- **Evidence to analyze.** A directory containing disk images, memory dumps, event logs, or other forensic artifacts.
- **An LLM provider account.** One of the following:
  - An Anthropic API key
  - A Google Cloud project with Vertex AI enabled and Claude model access
  - An AWS account with Amazon Bedrock Claude model access
  - Any LiteLLM-supported provider (OpenAI, Ollama, Azure, etc.)
- **Disk space** for case output. Investigations produce databases, audit logs, and reports that are written to a host-mounted directory.

## Pulling the Container Image

The pre-built container image includes all forensic tools, dependencies, and the Mulder server:

```bash
docker pull ghcr.io/calebevans/mulder:1.3.2
```

## Running a Container

### Volume Mounts

Every `docker run` invocation requires two volume mounts:

| Mount Path | Purpose |
|------------|---------|
| `/evidence` | Your evidence directory (mount read-only with `:ro`) |
| `/home/mulder/.mulder/cases` | Case databases, audit logs, and reports (persisted to host) |

Create the cases directory on the host before your first run:

```bash
mkdir -p ~/mulder-cases
```

### Privileged Access

The `--privileged` flag is required for FUSE operations that several forensic tools depend on (`ewfmount` for E01 images, `guestmount` for VM disk images, etc.).

If `--privileged` is too permissive for your environment, use the narrower capability grant instead:

```bash
--cap-add SYS_ADMIN --device /dev/fuse
```

The container runs as a non-root `mulder` user. An entrypoint script handles credential copying and permission setup automatically.

### Using an Anthropic API Key

The simplest configuration passes your API key as an environment variable:

```bash
docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  ghcr.io/calebevans/mulder:1.3.2
```

### Using Google Cloud Vertex AI

To route requests through Vertex AI, mount your GCP credentials file into the container and set the Vertex environment variables:

```bash
docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e CLAUDE_CODE_USE_VERTEX=1 \
  -e CLOUD_ML_REGION=us-east5 \
  -e ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project-id \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcloud-creds.json \
  -v ~/.config/gcloud/application_default_credentials.json:/tmp/gcloud-creds.json:ro \
  ghcr.io/calebevans/mulder:1.3.2
```

Model IDs are passed through to the SDK exactly as specified, with no automatic translation or mapping. When using Vertex, you must provide the full Vertex model ID including the `@version` suffix (e.g. `--model claude-opus-4-6@20250514`). If you omit `--model`, the built-in defaults (`claude-opus-4-6` for planner/analyst, `claude-haiku-4-5` for executor) are used.

| Variable | Description |
|----------|-------------|
| `CLAUDE_CODE_USE_VERTEX` | Set to `1` to enable Vertex AI |
| `CLOUD_ML_REGION` | GCP region where Claude is enabled (e.g. `us-east5`) |
| `ANTHROPIC_VERTEX_PROJECT_ID` | Your GCP project ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path inside the container to the mounted credentials file |

If you use Application Default Credentials (ADC) from `gcloud auth application-default login`, the default host path is `~/.config/gcloud/application_default_credentials.json`.

### Using Amazon Bedrock

Pass your AWS credentials and region as environment variables:

```bash
docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e CLAUDE_CODE_USE_BEDROCK=1 \
  -e AWS_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  ghcr.io/calebevans/mulder:1.3.2
```

Model IDs are passed through to the SDK exactly as specified, with no automatic translation or mapping. When using Bedrock, you must provide the full Bedrock model ID with the `us.anthropic.` prefix (e.g. `--model us.anthropic.claude-opus-4-6`). If you omit `--model`, the built-in defaults (`claude-opus-4-6` for planner/analyst, `claude-haiku-4-5` for executor) are used.

| Variable | Description |
|----------|-------------|
| `CLAUDE_CODE_USE_BEDROCK` | Set to `1` to enable Bedrock |
| `AWS_REGION` | AWS region with Bedrock Claude model access |
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |

You can also mount `~/.aws/credentials` if you prefer file credentials over environment variables.

## Starting an Investigation

Once the container is running, launch a full autonomous investigation with `mulder investigate`. The command takes two positional arguments: the evidence path and a case ID:

```bash
mulder investigate /evidence my-case
```

The case ID names the output database and all derived artifacts. Choose something descriptive (e.g. the incident ticket number or a short codename).

The orchestrator runs five phases in sequence:

1. **Catalog** scans the evidence directory, classifies file types, and identifies distinct systems.
2. **Extraction** runs forensic tools per system (memory analysis, disk forensics, log parsing) and submits findings.
3. **Cross-System Analysis** correlates evidence across systems and maps findings to MITRE ATT&CK techniques.
4. **Alternative Narrative** challenges the primary hypothesis, searches for counter-evidence, and audits for completeness.
5. **Report** generates the investigation narrative and final report artifacts.

Each phase passes through a quality gate before proceeding. The investigation runs unattended from start to finish.

## Using Non-Anthropic Models via LiteLLM

Mulder includes a built-in LiteLLM proxy that enables any LiteLLM-supported model provider. No manual proxy setup is required.

### Provider Prefixes

When any model ID includes a provider prefix, the proxy starts automatically:

```bash
# Bedrock Llama
mulder investigate /evidence my-case \
  --model bedrock/meta.llama3-1-70b-instruct-v1:0

# OpenAI
mulder investigate /evidence my-case \
  --model openai/gpt-4o
```

Supported prefixes: `bedrock/`, `openai/`, `vertex_ai/`, `azure/`, `ollama/`.

### Mixing Providers Across Roles

Mulder uses three agent roles (planner, executor, analyst), and each can use a different model. This lets you route expensive reasoning to a stronger model while using a cheaper one for mechanical tool execution:

```bash
mulder investigate /evidence my-case \
  --executor-model bedrock/meta.llama3-1-70b-instruct-v1:0 \
  --planner-model claude-opus-4-6 \
  --analyst-model claude-opus-4-6
```

### Local Models with Ollama

To use a locally hosted model via Ollama, ensure the Ollama server is accessible from inside the container (e.g. via host networking) and pass the `ollama/` prefix:

```bash
mulder investigate /evidence my-case \
  --model ollama/llama3.1:70b
```

### Custom LiteLLM Configuration

For advanced model routing, load balancing, or custom deployments, pass a LiteLLM configuration file:

```bash
mulder investigate /evidence my-case \
  --proxy-config ./litellm_config.yaml \
  --model my-custom-deployment
```

See the [LiteLLM documentation](https://docs.litellm.ai/docs/proxy/configs) for config file format details.

## Case Briefing

You can provide investigation context by placing a `MULDER.md` file in the root of your evidence directory. This is optional but recommended when you have background knowledge about the case.

### What to Include

- **What We Know**: Facts established before the investigation (incident reports, help desk tickets, network topology, known-compromised accounts)
- **What We're Looking For**: Specific questions the investigation should answer (who, what, when, how)
- **Supplementary Context**: Class rosters, org charts, IP ranges, account naming conventions, or anything that helps interpret evidence
- **Constraints**: Timezone information, scope limitations, legal holds

### How It Works

The contents of `MULDER.md` are prepended as an "INVESTIGATOR BRIEFING" to the planner and analyst prompts in every phase. This means:

- The extraction planner uses it to prioritize which tools to run
- The analyst uses it to focus analysis on relevant questions
- The cross-system correlator uses it to understand relationships
- The report writer uses it to frame conclusions around your questions

### Example

```markdown
# Case Briefing

## Background
Employee John Doe (username: jdoe) reported suspicious activity on his
workstation on 2024-03-15. IT observed outbound connections to unknown
IPs. The workstation and a file server were imaged.

## Known Facts
- Affected systems: WKSTN-042 (10.1.2.42), FILE-SRV (10.1.2.10)
- Suspect timeframe: March 14-15, 2024
- jdoe has local admin on WKSTN-042

## Investigation Questions
1. How did the attacker gain access to jdoe's workstation?
2. Did the attacker move laterally to FILE-SRV?
3. Was any data staged or exfiltrated?
4. Are there persistence mechanisms that survive a reboot?
```

If no `MULDER.md` is present, the investigation proceeds without additional context (fully autonomous mode).

## Artifact Awareness

The extraction planner adapts its tool selection based on what the evidence actually contains, not just its type. Standard toolsets (Volatility for memory, Sleuthkit for disk) always run, but the planner also looks for signals that indicate targeted analysis is warranted.

**Windows disk images** automatically trigger registry queries for system metadata (timezone, install date, shutdown time) and NTUSER.DAT parsing for user activity artifacts (TypedURLs, RecentDocs, UserAssist, MRU lists).

**Execution artifacts** (ShimCache, Prefetch, Amcache, UserAssist) are inspected for communication and networking tools. When the planner detects IRC clients, email clients, chat applications, or remote access tools in execution history, it plans `index_app_files` tasks targeting their configuration and data directories. When packet capture tools like Wireshark appear, the planner adds `analyze_disk_pcaps` to discover saved captures on disk.

**Investigator briefing keywords** also influence tool selection. Briefings mentioning hacking or intrusion trigger searches for exploit tool configs and PCAPs. Briefings about insider threats or data theft prioritize USB history and cloud storage artifacts. Briefings about communications prioritize email and chat application data.

The analyst receives complementary guidance: when execution artifacts show communication tools were used, the analyst searches indexed application files for contacts, server addresses, and credentials, then cross-references those with network connection data.

## CLI Reference

### `mulder investigate`

```
mulder investigate <evidence_path> <case_id> [OPTIONS]
```

Runs a full multi-phase forensic investigation.

| Option | Default | Description |
|--------|---------|-------------|
| `--model` | None | Fallback model for all roles |
| `--planner-model` | `claude-opus-4-6` | Model for planner agents |
| `--executor-model` | `claude-haiku-4-5` | Model for executor agents |
| `--analyst-model` | `claude-opus-4-6` | Model for analyst agents |
| `--config` | None | YAML config file for models and settings |
| `--effort` | `max` | Effort level (`max`, `xhigh`, `high`) |
| `--workers` | `3` | Max concurrent extraction sessions |
| `--db-dir` | `~/.mulder/cases` | Case database directory |
| `--cwd` | `/mulder-investigation` | Working directory for agent sessions |
| `--proxy-config` | None | LiteLLM config YAML for custom model routing |

### `mulder serve`

```
mulder serve [OPTIONS]
```

Starts the MCP server standalone. Normally invoked automatically by the orchestrator.

| Option | Default | Description |
|--------|---------|-------------|
| `--case-id` | None | Pre-load an existing case on startup |
| `--db-dir` | `~/.mulder/cases` | Directory for case databases and audit logs |
| `--transport` | `stdio` | MCP transport (`stdio` or `streamable-http`) |
| `--workers` | `8` | Concurrent tool execution threads |
| `--mem-limit` | `90` | Memory usage % threshold (0 to disable) |
| `--cpu-limit` | `90` | CPU usage % threshold (0 to disable) |

### `mulder report`

```
mulder report <case_id> [OPTIONS]
```

Regenerates reports (Markdown, HTML, PDF) offline from an existing case database.

| Option | Default | Description |
|--------|---------|-------------|
| `--db-dir` | `~/.mulder/cases` | Directory containing case databases |

### `mulder export-iocs`

```
mulder export-iocs <case_id> [OPTIONS]
```

Exports IOCs from a completed case.

| Option | Default | Description |
|--------|---------|-------------|
| `--db-dir` | `~/.mulder/cases` | Directory containing case databases |
| `--format` | `stix` | Output format (`stix` or `csv`) |

### `mulder export-navigator`

```
mulder export-navigator <case_id> [OPTIONS]
```

Generates a MITRE ATT&CK Navigator layer from a completed case.

| Option | Default | Description |
|--------|---------|-------------|
| `--db-dir` | `~/.mulder/cases` | Directory containing case databases |

## Understanding the Output

After an investigation completes, all artifacts are written to the cases directory you mounted at `/home/mulder/.mulder/cases` (e.g. `~/mulder-cases` on the host).

### Case Artifacts

| File | Description |
|------|-------------|
| `{case_id}.db` | SQLite database with all indexed evidence, findings, and metadata |
| `{case_id}.audit.jsonl` | Append-only audit log recording every tool invocation with parameters and timestamps |

### Reports

| File | Description |
|------|-------------|
| `{case_id}.report.md` | Markdown report for plain-text review |
| `{case_id}.report.html` | Self-contained HTML report with dark/light theme and sidebar navigation |
| `{case_id}.report.pdf` | PDF report for formal distribution |

All report formats include an executive summary, severity overview, evidence integrity hashes, attack timeline, detailed findings with MITRE ATT&CK mappings, IOC tables, audit metrics, and a sources appendix.

### IOC Exports

| File | Description |
|------|-------------|
| `{case_id}.stix.json` | STIX 2.1 IOC bundle |
| `{case_id}.iocs.csv` | CSV IOC export |
| `{case_id}.navigator.json` | MITRE ATT&CK Navigator layer (load in the [Navigator web app](https://mitre-attack.github.io/attack-navigator/)) |

### Logs

| File | Description |
|------|-------------|
| `mulder.log` | MCP server log |
| `orchestrator.log` | Orchestrator log with phase progress and gate results |

## Building the Image from Source

To customize tools, add new MCP tools, or work from the latest development branch, build the container image locally:

```bash
git clone https://github.com/calebevans/mulder.git
cd mulder
docker build -t mulder:dev .
```

Then run with the same volume mounts, substituting `mulder:dev` for the registry image:

```bash
docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  mulder:dev
```

A `Makefile` is included for convenience. Run `make help` to see available targets.
