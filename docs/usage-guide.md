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
    - [`mulder publish`](#mulder-publish)
    - [`mulder review`](#mulder-review)
    - [`mulder review-console`](#mulder-review-console)
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
| `web` | `starlette`, `uvicorn` | Local read-only browser review via `mulder review-console` |

Combine them as `pipx install "mulder-dfir[forensics,pdf,stix,web]"`, or add one later without reinstalling:

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

TSK-first analysis normally needs no mount privilege. Fallback FUSE operations
(`ewfmount`, `guestmount`, or `mount`) run through a separate, closed-protocol
helper process: it accepts only read-only mount and unmount requests, never
arbitrary commands. The long-lived model/MCP process does not execute mount
commands directly.

If `--privileged` is too permissive for your environment, use the narrower capability grant instead:

```bash
--cap-add SYS_ADMIN --device /dev/fuse
```

The container runs as a non-root `mulder` user. An entrypoint script handles credential copying and permission setup automatically.

For stronger isolation, deploy `python -m mulder.execution.mount_helper` as a
separately confined service/process with only the mount capability and image
roots it needs. The built-in subprocess boundary narrows the protocol, but OS
privilege separation still depends on how the container or helper is launched.

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

For collector exports and long investigations, first create an immutable intake
and use a durable run profile:

```bash
mulder intake-collection /exports/host01 my-case --format auto
mulder investigate /exports/host01 my-case --profile full
# The command prints a run handle. After an interruption:
mulder investigate /exports/host01 my-case --resume-run RUN_ID
```

See [Immutable intake and restart-safe runs](intake-and-runs.md) for trust
boundaries, cancellation semantics, archive limits, and quick-mode scope.

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

### Provider-bound data policy and airgap mode

Every model request is authorized before the provider adapter is constructed.
Mulder appends a `<case-id>.outbound.jsonl` record containing field names,
counts, UTF-8 byte sizes, SHA-256 content hashes, provider/model, and the
permit/deny reason. Initial prompt/system fields and dynamic MCP tool-response
fields are recorded at their respective pre-serialization hooks. Field values
and secrets are never written to this manifest.

Choose one case policy:

- `sensitive-approved` preserves the previous provider behavior and permits
  evidence content, including content marked sensitive by the evidence envelope.
- `metadata-only` permits only fields explicitly classified as metadata on
  non-local routes. Normal investigation prompts are content and are denied.
- `local-only` permits model content only on a local route and also disables
  external threat-intelligence calls.

For a zero-egress run, every configured model must use a local `ollama/` route:

```bash
mulder investigate /evidence my-case \
  --model ollama/qwen3 \
  --data-policy local-only \
  --airgap
```

Airgap preflight rejects cloud routes and fallbacks, remote Ollama endpoints,
custom proxy configurations, configured telemetry endpoints, and declared
egress adapters before starting a provider adapter. It also disables telemetry
in the SDK, local LiteLLM proxy, and MCP subprocess, and blocks external threat
intelligence before an HTTP client is constructed. The same settings can be
stored in YAML as `data_policy: local-only` and `zero_egress: true`.

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
| `--data-policy` | `sensitive-approved` | Provider-bound case policy: `local-only`, `metadata-only`, or `sensitive-approved` |
| `--airgap` | off | Require verified local model routes and disable all known runtime egress paths |
| `--profile` | `full` | `quick` sampled triage (35% role budgets) or `full` evidence-bounded workflow |
| `--run-id` | generated | Caller-selected handle for a new durable run |
| `--resume-run RUN_ID` | None | Resume exact-input successful checkpoints from a prior run |
| `--require-healthy` | off | Refuse start when the local capacity forecast reports not ready |

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
| `--airgap` | off | Disable external threat intelligence and telemetry-capable egress paths |

### `mulder report`

```
mulder report <case_id> [OPTIONS]
```

Regenerates reports (Markdown, HTML, PDF) offline from an existing case database.

| Option | Default | Description |
|--------|---------|-------------|
| `--db-dir` | `~/.mulder/cases` | Directory containing case databases |

The static report consumes the same versioned case-review calculation as `mulder review` for
proof cards, receipt/audit/replay state, costs, coverage, and observed phase state.

### `mulder publish`

```
mulder publish <case_id> [--pdf|--no-pdf] [--approve]
```

Renders executive, technical, and examiner views from one immutable `mulder.case-review`
snapshot. Each view includes a fact-model digest, exact epistemic labels, and a proof appendix.
The `{case_id}.publication.json` sidecar commits every rendered byte and records blocking checks
for complete bounded facts, exact anchors, audit integrity, HTML and Markdown proof targets,
visible content, and PDF page geometry where the optional renderer is available.

The default state is `DRAFT`. `--approve` permits the `DRAFT`→`APPROVED` transition only when
all blocking checks pass and `mulder approve` already binds the same current claim set. Changed
case facts or output bytes require a new draft; an approved publication cannot be silently
downgraded. `mulder publication-status CASE` verifies and prints the sidecar self-commitment.

### `mulder review`

```
mulder review <case_id> [--json] [PAGINATION OPTIONS]
```

Projects the authoritative SQLite database, audit log, receipt, and model-usage sidecar into one
transport-neutral, read-only `mulder.case-review` document. Text output is intended for terminals;
`--json` exposes the same bounded facts for automation. The command neither runs migrations nor
starts MCP, a model, a web server, or a network client.

Finding rows, exact evidence anchors, and immutable revision snapshots have independent
offset/limit controls. Defaults are 100 findings, 200 anchors, and 200 revisions; enforced maxima
are 500, 1000, and 1000. Page metadata always reports returned and total counts. Legacy missing
tables remain explicit states, never empty facts interpreted as a completed or clean investigation.
The same document also carries the authoritative competing-hypothesis projection, contradictions,
separate specialist-review seats, and one server-bounded graph query result. Graph results retain
claim, verification, source, window, and anchor selectors. The immutable review path verifies the
persisted graph digest against current verified claims and withholds stale or never-built graph rows
instead of refreshing the projection or presenting them as current.

The database must be quiescent: a non-empty SQLite WAL or rollback journal is rejected. Review
uses immutable read mode so it cannot migrate the schema or create SQLite sidecars.

`mulder review-console` renders those same reasoning and graph fields. Its GET-only JSON routes are
`/api/cases/{case_id}/reasoning` and `/api/cases/{case_id}/graph`; the graph route optionally accepts
an exact `entity_id` plus validated `depth`, `direction`, and `limit` parameters. The browser has no
reasoning write, graph rebuild, arbitrary query-language, or tool-dispatch endpoint.

Review actions are separate append-only events. Record an examiner decision or
follow-up without rewriting a finding:

```bash
mulder review-action CASE comment --subject-type claim --subject-id CLAIM_ID \
  --reviewer examiner@example --comment "Check the parent process"
```

An optional human checkpoint can stop the pipeline after Alternative Narrative:

```bash
mulder investigate /evidence CASE --approval-before-report
mulder approve CASE --decision approve --reviewer examiner@example
mulder investigate /evidence CASE --resume-run RUN_ID --resume-after-approval
```

The request binds the exact active findings, claims, anchors, verification
history, and audit head. Rejection requires the case state to change before a
new request; changed claims make old approvals stale. The resume path validates
the durable checkpoint and runs only the report phase, so a restart does not
repeat extraction. These flags are opt-in; autonomous investigations retain
their existing behavior.

### `mulder review-console`

```
mulder review-console <case_id> [--db-dir PATH] [--host HOST] [--port PORT]
```

Serves a server-rendered browser view, read-only JSON endpoints, exact citation drill-down, proof
cards, and Server-Sent Events over the same `mulder.case-review` calculation used by the CLI and
static report. Install the optional dependency first with
`pipx install "mulder-dfir[forensics,web]"` (or inject `starlette` and `uvicorn`). The default bind
is `127.0.0.1:8765`; it makes no model, MCP, or remote-network calls.

Binding any non-loopback address is rejected unless an examiner supplies `--auth-token` or sets
`MULDER_REVIEW_TOKEN`. JSON clients use `Authorization: Bearer TOKEN`; browser-native HTTP Basic
authentication uses username `mulder` and the token as its password. Tokens are never generated or
written by Mulder. All console routes are GET/HEAD only—there is no evidence mutation, arbitrary
SQL, or generic tool invocation route.

`mulder investigate` appends typed operational observations to the existing case audit chain. Its
durable audit sequence is the SSE event ID. Browsers reconnect with standard `Last-Event-ID`, and
the server replays only later events before following the live tail. These events are operational
observations, not evidence or inferred phase-completion claims. A corrupt audit chain blocks replay.

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

Signing is optional. Pass `--signing-key PATH` to use an existing examiner-owned Ed25519 PEM
private key, with optional `--examiner` and `--key-id` metadata. Mulder never generates a key or
infers an examiner identity. The public key and fingerprint are portable verification metadata;
an examiner label is only a caller assertion. Without `--signing-key`, the receipt remains
explicitly **unsigned**. Sealing fails if registered evidence is missing or has already changed,
or if the current audit chain is invalid.
Pass `--require-approval` to additionally require a current approval. The
manifest then includes the approved claim-set and pre-report audit-head
commitments; the approved head must remain an ancestor of the current verified
audit chain.

Pass `--require-resolved-contradictions` to opt into a stricter local seal policy: any material
contradiction without an appended resolution blocks manifest creation. The flag is off by default
for backward compatibility. Non-material contradictions and independent reviewer concerns remain
visible in the report but do not change deterministic atomic-claim verification.

The `sqlite-logical-v1` database commitment includes every non-internal SQLite schema object and
every typed value in every non-internal table, in deterministic value order. It intentionally
excludes physical page layout, WAL/checkpoint layout, file timestamps, and SQLite-maintained
`sqlite_*` implementation tables, so a byte-for-byte copy is not required for a logically identical
case database. Table-level schema, row-count, and content commitments make failures diagnosable.

### `mulder verify-case`

```
mulder verify-case <manifest_path> [--evidence-root PATH] [--public-key PATH]
                   [--replay-inventory PATH] [--json]
```

Verifies a copied case using only local file and SQLite reads: it does not start MCP, call a model,
or use the network. Artifact locations are relative to the manifest, so moving the case and
evidence directories together does not invalidate the receipt. Use `--evidence-root` when the
evidence was moved independently. Diagnostics identify the exact missing/changed evidence,
report, database table, or audit-chain property.

Signature status is reported independently as `valid`, `invalid`, `unsigned`, or `unverifiable`.
Without `--public-key`, a signed manifest is checked against its embedded key; use an independently
obtained PEM/OpenSSH public key to establish that it matches the examiner key you intended to
trust. Replay is separately classified `EXACT`, `DRIFTED`, `NON_DETERMINISTIC`, or `UNSUPPORTED`
from the recorded tool/parser/extractor/model inputs and an optional JSON inventory. Version drift
does not imply tampering. Reports include per-finding proof cards with atomic claims, exact anchors,
verification history, revisions, linked coverage, and receipt state. Reports generated before
sealing honestly show `pending_seal`, avoiding a circular report/manifest commitment.

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
| `{case_id}.manifest.json` | Relocatable, optionally examiner-signed case receipt produced by `mulder seal-case` |
| `{case_id}.publication.json` | DRAFT/APPROVED publication state, fact digest, render QA, and exact audience-artifact commitments |
| `{case_id}.intake.json` | Immutable KAPE/Velociraptor member inventory and collector provenance |
| `{case_id}.runs.db` | Durable handles, cancellation state, phase attempts, and checkpoints |
| `{case_id}.run.json` | Latest bounded run/profile status projection (not a report binding) |
| `{case_id}.{run_id}.run.json` | Stable per-run profile/status projection |
| `{case_id}.report-run.json` | Hash binding from generated report artifacts to their exact run |

### Reports

| File | Description |
|------|-------------|
| `{case_id}.report.md` | Markdown report for plain-text review |
| `{case_id}.report.html` | Self-contained HTML report with dark/light theme and sidebar navigation |
| `{case_id}.report.pdf` | PDF report for formal distribution |
| `{case_id}.publication.{executive,technical,examiner}.{md,html,pdf}` | State-bound audience views; PDF is optional |

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
