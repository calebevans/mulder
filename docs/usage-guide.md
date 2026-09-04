# Usage Guide

Try-it-out instructions for running Mulder, the forensic investigation platform.

## Table of Contents

- [Usage Guide](#usage-guide)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
    - [Common](#common)
    - [Container Install](#container-install)
    - [Native Install](#native-install)
      - [What `mulder setup` installs](#what-mulder-setup-installs)
      - [ALEAPP and iLEAPP dependencies](#aleapp-and-ileapp-dependencies)
      - [What `mulder setup` will not do](#what-mulder-setup-will-not-do)
  - [Installing with pipx](#installing-with-pipx)
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
    - [`mulder setup`](#mulder-setup)
    - [`mulder serve`](#mulder-serve)
    - [`mulder report`](#mulder-report)
    - [`mulder seal-case`](#mulder-seal-case)
    - [`mulder verify-case`](#mulder-verify-case)
    - [`mulder export-iocs`](#mulder-export-iocs)
    - [`mulder export-navigator`](#mulder-export-navigator)
  - [Understanding the Output](#understanding-the-output)
    - [Case Artifacts](#case-artifacts)
    - [Reports](#reports)
    - [IOC Exports](#ioc-exports)
    - [Logs](#logs)
  - [Building the Image from Source](#building-the-image-from-source)

## Prerequisites

Mulder runs two ways: as a **container** with every forensic tool preinstalled, or as a **native install** from PyPI plus one `mulder setup` run. Pick one; the container is a portability choice, not an escape hatch.

### Common

- **Evidence to analyze.** A directory containing disk images, memory dumps, event logs, or other forensic artifacts.
- **An LLM provider account.** One of the following:
  - An Anthropic API key
  - A Google Cloud project with Vertex AI enabled and Claude model access
  - An AWS account with Amazon Bedrock Claude model access
  - Any LiteLLM-supported provider (OpenAI, Ollama, Azure, etc.)
- **Disk space** for case output. Investigations produce databases, audit logs, and reports.

### Container Install

- **Docker or Podman** installed and running. All commands below use `docker`, but `podman` works as a drop-in replacement.
- A host directory to mount for case output, since the container writes to `/home/mulder/.mulder/cases`.

Nothing else. The image ships every tool and data set a native install obtains through
`mulder setup`, already provisioned under `/opt` and pinned there by `MULDER_ASSET_ROOT=/opt`.
Running `mulder setup` *inside* the container therefore exits 1 by design: `/opt` is root-owned
and the process runs as the unprivileged `mulder` user, and there is nothing for it to do.
`mulder setup --verify` works normally there, since it only reads.

### Native Install

```bash
sudo apt install yara            # SIFT ships the python3-yara module, not the binary
pipx install "mulder-dfir[forensics]"
mulder setup                     # everything mulder owns - no sudo
```

- **Python 3.10 or newer**, plus [`pipx`](https://pipx.pypa.io/) (or `uv`).
- **`git`.** `mulder setup` clones six of its assets, and the YARA signature-base needs a real
  `.git` so mulder can keep the rules current.
- **An Anthropic credential** - `ANTHROPIC_API_KEY`, `claude /login`, or the Bedrock / Vertex
  environment variables.
- **The SIFT forensic toolchain** on `$PATH`. SIFT already provides Sleuth Kit, plaso, Zeek,
  Suricata, radare2, bulk_extractor and the .NET runtime; the `yara` binary above is the one
  fatal gap.
- **Node.js is usually _not_ required**: `claude-agent-sdk`'s platform wheels bundle the Claude
  Code CLI. Node 18+ matters only if you install from an sdist or run where no wheel exists.

#### What `mulder setup` installs

Everything mulder owns, in one run: MITRE ATT&CK data, Sigma rules, the YARA signature-base,
the Didier Stevens suite, Chainsaw 2.16.0, Hayabusa 3.8.1, Zircolite 2.20.0, capa 9.4.0,
FLOSS 3.1.0, the six EZ Tools mulder invokes, ALEAPP, iLEAPP, and the Volatility 3 symbol packs.
About **2.2 GB on disk**; it prints the total and asks before downloading more than 1 GB.

Versions are pinned to match the container image exactly, and a test fails the build if the two
drift apart. Release binaries are verified against a SHA-256 recorded in the mulder package;
git clones and unversioned vendor URLs cannot be pinned by digest, so those are validated
structurally (a clone that resolves, an archive that extracts, JSON that parses, a rules tree
that contains rules) and rely on TLS in transit.

Assets go to the first of these that applies:

1. `$MULDER_ASSET_ROOT`, if set. This wins outright - nothing else is searched.
2. `/opt`, if it exists and is writable (this is what the container uses).
3. `~/.local/share/mulder/assets` otherwise.

Mulder *reads* `/opt` first and only then its own directory, so an existing SIFT layout keeps
working untouched and a single-user install needs no `sudo`. If you previously hand-made
`/opt/attack` or `/opt/sigma-rules`, mulder keeps reading those; `mulder setup --verify` reports
each asset as `up-to-date (unmanaged)` or `shadowed by /opt/...` rather than claiming success
while reading something else.

`mulder setup` refuses to run as root: a root-owned `/opt/signature-base` makes git's
dubious-ownership check fail for every later non-root run, which would stop YARA rule updates
permanently and silently.

Re-running is safe - assets already present at the pinned version are skipped, and a version
bump in the manifest is what triggers a re-fetch. `mulder setup --verify` checks an existing
install without touching the network.

The Volatility symbol packs go to `~/.cache/volatility3/symbols` (honouring `XDG_CACHE_HOME`),
where Volatility 3 looks for them - **not** under the mulder asset root, so the platform `vol`
on your `$PATH` finds them.

#### ALEAPP and iLEAPP dependencies

Their Python dependencies are not covered by any mulder extra: the upstream `requirements.txt`
files contain a `git+https://` URL, local `whl_files/*.whl` paths, `pyinstaller`, and mutually
conflicting `packaging` / `numpy` / `protobuf` pins, none of which can be expressed as PyPI
metadata. `mulder setup` clones both; to install their dependencies:

```bash
pipx inject mulder-dfir --requirements ~/.local/share/mulder/assets/aleapp/requirements.txt
pipx inject mulder-dfir --requirements ~/.local/share/mulder/assets/ileapp/requirements.txt
```

The two requirement sets conflict with each other, so installing both can leave the venv in a
state `pip check` considers inconsistent. Mulder probes for any interpreter that can import
them, so installing into the system interpreter instead also works.

#### What `mulder setup` will not do

It never runs a package manager and never asks for `sudo`. Sleuth Kit, `yara`, `git`, `dotnet`,
Zeek, Suricata, plaso and radare2 are your OS's job - on SIFT, all but `yara` are already there.

## Installing with pipx

```bash
pipx install "mulder-dfir[forensics]"
```

`pipx` puts mulder in its own isolated virtualenv and links the `mulder` command onto your PATH. The equivalent with `uv` is:

```bash
uv tool install "mulder-dfir[forensics]"
```

Verify:

```bash
mulder --version
```

### Extras

| Extra | Pulls in | When you need it |
|-------|----------|------------------|
| `forensics` | `orjson`, `xxhash`, `colorama`, `tqdm`, `evtx` | Zircolite's runtime dependencies. Recommended for everyone. |
| `pdf` | `weasyprint` | PDF report rendering via `mulder report` |
| `stix` | `stix2` | STIX 2.1 bundle export via `mulder export-iocs` |

Combine them as `pipx install "mulder-dfir[forensics,pdf,stix]"`, or add one later without reinstalling:

```bash
pipx inject mulder-dfir weasyprint
```

`pipx inject` is also how you add any other Python dependency a forensic tool needs inside mulder's environment - see the ALEAPP/iLEAPP note above.

### Directory Layout

A native install uses two directories under `~/.mulder`, both overridable:

| Directory | Default | Override | Contents |
|-----------|---------|----------|----------|
| Workspace | `~/.mulder/workspace` | `--cwd`, `MULDER_CWD` | Scratch working directory for agent sessions. Mulder writes a default `.mcp.json` here on first run. |
| Cases | `~/.mulder/cases` | `--db-dir` | Case databases, audit logs, and reports |

The container sets `MULDER_CWD=/mulder-investigation`, so its workspace is unchanged from earlier releases.

### Using Mulder as an MCP Server

To expose mulder's tools to Claude Desktop or any other MCP client, add:

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

`uvx mulder-dfir serve` works without installing first.

## Pulling the Container Image

The pre-built container image includes all forensic tools, dependencies, and the Mulder server:

```bash
docker pull ghcr.io/calebevans/mulder:1.4.1
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
  ghcr.io/calebevans/mulder:1.4.1
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
  ghcr.io/calebevans/mulder:1.4.1
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
  ghcr.io/calebevans/mulder:1.4.1
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
| `--cwd` | `~/.mulder/workspace` | Working directory for agent sessions. Also settable via `MULDER_CWD`; the container sets it to `/mulder-investigation`. Created on first use, along with a default `.mcp.json` |
| `--proxy-config` | None | LiteLLM config YAML for custom model routing |

### `mulder setup`

```
mulder setup [OPTIONS]
```

Downloads everything mulder owns that pip cannot ship. Never installs OS packages, never invokes
a package manager, and refuses to run as root.

| Option | Default | Description |
|--------|---------|-------------|
| `--asset-root DIR` | resolved | Override the asset root (env: `MULDER_ASSET_ROOT`). Exclusive: setting it disables the `/opt` search |
| `--dry-run` | off | Print the plan and exit 0. Issues no network requests at all |
| `--verify` | off | Validate what is installed; fetch nothing. **Exits 4** if anything is missing, invalid, or shadowed by a copy mulder does not manage |
| `--json` | off | Emit the result document on stdout (human progress always goes to stderr) |
| `--yes` | off | Skip the confirmation prompt for plans over 1 GB |

Exit codes: `0` everything present, `1` fatal precondition (no `git`, unusable asset root,
missing digest), `2` usage error (running as root), `3` at least one asset failed, `4`
`--verify` found something missing, invalid, or shadowed.

Downloads land in a staging directory on the destination filesystem and are moved into place
only after they validate, so a truncated file is never left where mulder would parse it. An
interrupted download is simply redone on the next run.

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

### `mulder seal-case`

```
mulder seal-case <case_id> [OPTIONS]
```

Creates `{case_id}.manifest.json`, a portable receipt over the case database's complete logical
contents, the exact audit-chain head and entry count, registered original evidence, extractor and
tool metadata, and standard report/export files found beside the database. Use `--artifact PATH`
repeatedly to bind additional generated files. Existing manifests are preserved unless `--force`
is explicit. Run this after the final report/export operation; any later database or audit event is
correctly reported as a post-seal change and requires an explicit re-seal.

The v1 receipt is deliberately marked **unsigned**. It detects changes relative to the retained
manifest but does not establish an examiner identity; examiner-controlled signing is a separate
trust layer. Sealing fails if registered evidence is missing or has already changed, or if the
current audit chain is invalid.

The `sqlite-logical-v1` database commitment includes every non-internal SQLite schema object and
every typed value in every non-internal table, in deterministic value order. It intentionally
excludes physical page layout, WAL/checkpoint layout, file timestamps, and SQLite-maintained
`sqlite_*` implementation tables, so a byte-for-byte copy is not required for a logically identical
case database. Table-level schema, row-count, and content commitments make failures diagnosable.

### `mulder verify-case`

```
mulder verify-case <manifest_path> [--evidence-root PATH] [--json]
```

Verifies a copied case using only local file and SQLite reads: it does not start MCP, call a model,
or use the network. Artifact locations are relative to the manifest, so moving the case and
evidence directories together does not invalidate the receipt. Use `--evidence-root` when the
evidence was moved independently. Diagnostics identify the exact missing/changed evidence,
report, database table, or audit-chain property.

Exit codes are `0` for a fully verified native case, `1` for mutation/corruption/missing material,
`2` for intact but unchained legacy material, and `3` for an unsupported manifest schema. A legacy
audit is reported as `LEGACY UNVERIFIED`, never as corrupt merely because it predates chaining.

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
| `{case_id}.manifest.json` | Relocatable unsigned case receipt produced by `mulder seal-case` |

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
