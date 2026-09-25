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
    - [Thinking Through the Proxy](#thinking-through-the-proxy)
    - [Models LiteLLM does not know](#models-litellm-does-not-know)
    - [Custom LiteLLM Configuration](#custom-litellm-configuration)
  - [Case Briefing](#case-briefing)
    - [What to Include](#what-to-include)
    - [How It Works](#how-it-works)
    - [Example](#example)
  - [Artifact Awareness](#artifact-awareness)
  - [NetFlow Evidence](#netflow-evidence)
  - [CLI Reference](#cli-reference)
    - [`mulder investigate`](#mulder-investigate)
    - [`mulder setup`](#mulder-setup)
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
The same applies to the YARA rules: the image pins `/opt/signature-base` to a commit, and the
server logs once per session that it is using that checkout rather than pulling newer rules.

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
- **nfdump 1.7 or newer** on `$PATH` for NetFlow evidence (optional). Ubuntu 22.04 packages
  nfdump 1.6, which cannot read the layout-2 files that 1.7 collectors write, so build 1.7 from
  source as the container image does; see [NetFlow Evidence](#netflow-evidence).
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
docker pull ghcr.io/calebevans/mulder:1.5.2
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

The `--privileged` flag is required for FUSE operations that several forensic tools depend on (`ewfmount` for E01 images, `guestmount` for VM disk images, and the `xmount` + `ntfs-3g`/`fuse2fs` stack that mounts disk images for the MFT, prefetch, Amcache, Shimcache and registry parsers). Mounting is entirely user-space FUSE: it runs as the unprivileged `mulder` user and needs no loop devices.

If `--privileged` is too permissive for your environment, use the narrower capability grant instead:

```bash
--cap-add SYS_ADMIN --device /dev/fuse
```

The container runs as a non-root `mulder` user. An entrypoint script handles credential copying and permission setup automatically.

When entering an existing container, use `docker exec -it -u mulder <container> bash`.
`docker exec` bypasses the entrypoint's user switch; investigations run as root are
rejected by the agent CLI. Add `--show-cli-stderr` to `mulder investigate` to see
the underlying diagnostic if a subprocess exits with a generic error.

### Using an Anthropic API Key

The simplest configuration passes your API key as an environment variable:

```bash
docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  ghcr.io/calebevans/mulder:1.5.2
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
  ghcr.io/calebevans/mulder:1.5.2
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
  -v ~/.aws:/home/mulder/.aws \
  ghcr.io/calebevans/mulder:1.5.2
```

Model IDs are passed through to the SDK exactly as specified, with no automatic translation or mapping. When using Bedrock, you must provide the full Bedrock model ID with the `us.anthropic.` prefix (e.g. `--model us.anthropic.claude-opus-4-6`). If you omit `--model`, the built-in defaults (`claude-opus-4-6` for planner/analyst, `claude-haiku-4-5` for executor) are used.

| Variable | Description |
|----------|-------------|
| `CLAUDE_CODE_USE_BEDROCK` | Set to `1` to enable Bedrock |
| `AWS_REGION` | AWS region with Bedrock Claude model access |
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |

If you prefer file-based credentials, mount your whole `~/.aws` directory read-write at `/home/mulder/.aws` (as in the example above) instead of passing keys. This works for both static profiles in `~/.aws/credentials` and `aws login` sessions from AWS CLI 2.36+: the login token cache lives under `~/.aws/login/cache`, so the mount must be writable for the container to refresh it. The same mount serves `bedrock/` models routed through the LiteLLM proxy (see [Using Non-Anthropic Models via LiteLLM](#using-non-anthropic-models-via-litellm)).

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
  --model ollama/llama3.1:70b --no-thinking
```

Auto-generated proxy configurations preserve the public `ollama/<model>` name
and route it internally through LiteLLM's `ollama_chat/<model>` provider. This
uses Ollama's native chat API so streamed tool calls retain their structure.
Custom proxy YAML is used as supplied; configure its `litellm_params.model` with
`ollama_chat/` too. Set `api_base` there if Ollama is at a different address, such
as `http://host.docker.internal:11434` for a host server accessed from Docker Desktop.

### Thinking Through the Proxy

Thinking is on by default for every proxy-routed model that LiteLLM's model
map says supports reasoning (`bedrock/deepseek.v3.2`, Qwen3, Kimi K2 thinking,
gpt-oss, OpenAI o-series, ...). The auto-generated config adds
`allowed_openai_params: [reasoning_effort]` to those models so the
`reasoning_effort` that LiteLLM derives from Claude Code's `--effort` reaches
the provider unchanged (without it, LiteLLM rewrites it into an Anthropic
`thinking` block that non-Claude models on Bedrock silently ignore). Such models
also get a 32768-token output cap instead of 8192, because reasoning tokens
count against it; so do models LiteLLM's map does not know at all, since they
may reason unasked (see [Models LiteLLM does not know](#models-litellm-does-not-know)). Phase queries run at `--effort` (`max` and `xhigh` reach
Bedrock as `high`); utility queries run at `low`, which DeepSeek treats as
non-reasoning.

In a tool loop Claude Code sends each earlier turn's `thinking` block back in
the assistant history. Bedrock's DeepSeek route returns those blocks without a
signature, and LiteLLM 1.101.0 replays an unsigned thinking block as a plain
assistant `text` block rather than a Bedrock `reasoningContent` block
(`add_thinking_blocks_to_assistant_content` in
`litellm_core_utils/prompt_templates/factory.py`). The loop continues
normally; the cost is that prior reasoning is re-read as visible assistant
prose on every turn.

Models LiteLLM does not list as reasoning-capable are served without it and a
warning is logged at proxy start. A custom `--proxy-config` is used verbatim;
add `allowed_openai_params: [reasoning_effort]` to its `litellm_params` yourself.

To turn thinking off, add `--no-thinking`. This disables thinking for every
phase and utility query, overrides `--effort`, and serves every proxy model
without the reasoning passthrough. The model/provider must support disabling
thinking; this option does not establish that a model can complete an
investigation reliably.

### Models LiteLLM does not know

Mulder asks LiteLLM for each proxy model's context window and reasoning
support. A model absent from LiteLLM's model map (Bedrock's newest releases
often are, e.g. `bedrock/us.moonshotai.kimi-k3`) gets no window, so Claude
Code assumes 200K and never compacts before the provider rejects the request,
and is served without the reasoning passthrough. Override what LiteLLM cannot
tell us in the `--config` YAML: add an entry to `models:` keyed by the model
id exactly as passed to `--model`, with any of `context_window`,
`max_output_tokens` and `reasoning`. Role assignments and per-model entries
share the mapping; a string value names a role's model, a mapping value
describes a model.

```yaml
models:
  planner: bedrock/us.moonshotai.kimi-k3
  executor: bedrock/us.moonshotai.kimi-k3
  analyst: bedrock/us.moonshotai.kimi-k3
  bedrock/us.moonshotai.kimi-k3:
    context_window: 262144
    max_output_tokens: 32768
    reasoning: true
```

Precedence per key is config override, then LiteLLM's value, then the
default (no window, 32768 output tokens, no reasoning; 8192 output tokens
only when LiteLLM positively reports a model as non-reasoning). `reasoning:
true` adds the `reasoning_effort` passthrough exactly as LiteLLM-detected
reasoning does, `max_output_tokens` sets the model's LiteLLM `max_tokens` and
`CLAUDE_CODE_MAX_OUTPUT_TOKENS`, and `context_window` sets
`CLAUDE_CODE_MAX_CONTEXT_TOKENS`. `--no-thinking` still turns reasoning off.
Proxy start logs one line per model with the effective values and where each
came from (`litellm`, `config`, `env` or `default`).

An unknown `bedrock/` model is also served through LiteLLM's explicit
Converse route (`litellm_params.model: bedrock/converse/<id>`, the public
name is unchanged). For an unmapped id LiteLLM 1.101.0 infers the provider
from the id itself (`moonshot` for Kimi) and a streaming request, which is
what Claude Code always sends, comes back as an empty `end_turn` with no
error; the Converse route streams the thinking and text correctly. The same
model also gets `litellm_params.allowed_openai_params: [tools]`: LiteLLM
treats `tools` as supported on Bedrock Converse only for models its map
knows, and otherwise `drop_params` strips them from every request, so an
unmapped model never sees a tool and can only answer in text (issue #207).
Models LiteLLM knows keep their id as given.

Where a config file is awkward, such as a container run, the same three keys
are read from the environment and applied to every proxy model in the run
(a coarse knob meant for single-model runs; env wins over the file):

```bash
docker run ... \
  -e MULDER_MODEL_CONTEXT_WINDOW=262144 \
  -e MULDER_MODEL_MAX_OUTPUT_TOKENS=32768 \
  -e MULDER_MODEL_REASONING=true \
  mulder investigate /evidence my-case --model bedrock/us.moonshotai.kimi-k3
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

**Optical media** (CD/DVD images, UDF or ISO 9660) are recognised at catalog time by their volume recognition sequence and listed with `run_optical_listing` rather than the Sleuth Kit tools, which cannot read optical filesystems. Deleted files from earlier burn sessions on write-once media are listed and can be pulled out with `extract_optical_file`.

**Windows disk images** automatically trigger registry queries for system metadata (timezone, install date, shutdown time) and NTUSER.DAT parsing for user activity artifacts (TypedURLs, RecentDocs, UserAssist, MRU lists).

**Execution artifacts** (ShimCache, Prefetch, Amcache, UserAssist) are inspected for communication and networking tools. When the planner detects IRC clients, email clients, chat applications, or remote access tools in execution history, it plans `index_app_files` tasks targeting their configuration and data directories. When packet capture tools like Wireshark appear, the planner adds `analyze_disk_pcaps` to discover saved captures on disk.

**Investigator briefing keywords** also influence tool selection. Briefings mentioning hacking or intrusion trigger searches for exploit tool configs and PCAPs. Briefings about insider threats or data theft prioritize USB history and cloud storage artifacts. Briefings about communications prioritize email and chat application data.

The analyst receives complementary guidance: when execution artifacts show communication tools were used, the analyst searches indexed application files for contacts, server addresses, and credentials, then cross-references those with network connection data.

## NetFlow Evidence

Mulder reads NetFlow/IPFIX evidence stored by an nfdump collector (`nfcapd.*` files) through six
typed MCP tools: `run_netflow_inventory`, `run_netflow_top`, `run_netflow_host_profile`,
`run_netflow_sweep`, `run_netflow_pair_timeline` and `run_netflow_query`. Like every other
forensic tool in Mulder they take typed parameters, build an argv list (never a shell string),
bound their output, and index every result row in the case database so findings can cite it.

**Evidence layout.** An nfdump collector writes one binary file per rotation interval, usually
below one directory per exporter:

```
evidence/
  netflow/
    edge-router/                  one directory per exporter (router, firewall, probe)
      2001/02/
        nfcapd.200102030000       rotation name nfcapd.YYYYMMDDhhmm[ss]
        nfcapd.200102040000
        nfcapd.current.4242       a collector's live temp file (read like any other)
```

Pass the **directory** (any level: exporter, year, month) as `evidence_path`; the tools walk it
recursively, and a single file also works. Files are admitted by their 4-byte nfdump magic, never
by name: a text file named like a rotation file is excluded, a renamed capture beside
rotation-named siblings is kept, and empty files, symlinks and files without the magic are
reported in `files_excluded` with a reason. The catalog classifies such files as
`netflow_capture` (the exporter directory is the system, platform "Network"), the evidence
context lists each nfcapd directory for the extraction planner, and the coverage audit reports one
item per directory.

**Requirements.** nfdump 1.7 or newer on the server's `PATH`; the container image builds nfdump
1.7.10 from source into `/opt/nfdump`. nfdump 1.7 writes file layout 2 by default and nfdump 1.6
(the version Ubuntu 22.04 packages) cannot read layout-2 files at all, so native installs must
provide 1.7 or later. `prlimit` (util-linux) is also required: every nfdump child runs under a
4 GiB address-space limit. Without nfdump the tools return `error_type: binary_missing` and
nothing else in Mulder changes.

**Bounded outputs.** Every call returns at most `max_inline_rows` rows inline (default 20, max
100) while every row is indexed. Filters are nfdump filter expressions checked against a token
whitelist (ASCII only, at most 1000 characters; quotes, shell metacharacters and hostnames are
rejected before any process starts). Timestamps are UTC (`YYYY-MM-DDTHH:MM:SS`); a flow counts
when it was *active* in the window, and the window also selects the day files read (one day
before `t_start` to eight days after `t_end`, because a record is written when it expires). Over
more than three files `run_netflow_query` refuses a volume ordering without aggregation, or an
aggregation keyed by `srcport` or by both `srcip` and `dstip`, unless a filter narrows it. All
nfdump processes share two slots per server, and any message nfdump prints on stderr (a truncated
or block-corrupt file) fails the call instead of returning an undercount.

**Source names.** Each call indexes its rows under a deterministic name, `netflow.<kind>.<id>`
(`inventory`, `top`, `profile`, `sweep`, `pair` or `query`), where `<id>` is a digest of the
tool, the resolved `evidence_path` and the effective parameters. Repeating an identical call
returns `status: skipped`; `force=True` runs again and registers `<name>-r1`, `<name>-r2`, ...;
a call that matches nothing registers an empty source (`status: indexed_empty`).
`search(source="netflow")` spans every NetFlow source of the case.

**Citation.** Line 1 of every non-empty source is a header row (no event time) naming the tool,
the originating `tool_call_id`, the files read and every effective parameter, so
`get_raw_output('<name>', limit=1)` recovers the provenance of any `netflow.*` source. Every other
row is one line, `<event_time> netflow <kind> key=value ...`, with its own UTC `event_time`, so
`search` with `t_start`/`t_end` and `get_timeline` work on NetFlow rows and phrase searches such
as `search(query='"dport=445"', source='netflow')` hit exactly the rows that carry the value.
`flows=`, `packets=` and `bytes=` sum every exporter record (an exporter can emit one flow more
than once), so cite them as record counts and upper bounds; `run_netflow_pair_timeline` reports
`records_distinct=` and `bytes_distinct=` with exporter copies collapsed.

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
| `--no-thinking` | off | Disable extended thinking for all queries; overrides `--effort` |
| `--workers` | `3` | Max concurrent extraction sessions |
| `--max-compactions` | `3` | Continuation sessions allowed per role session after context exhaustion; `0` disables. Also settable via `MULDER_MAX_COMPACTIONS` (the flag wins) |
| `--db-dir` | `~/.mulder/cases` | Case database directory |
| `--cwd` | `~/.mulder/workspace` | Working directory for agent sessions. Also settable via `MULDER_CWD`; the container sets it to `/mulder-investigation`. Created on first use, along with a default `.mcp.json` |
| `--proxy-config` | None | LiteLLM config YAML for custom model routing |
| `--show-cli-stderr` | off | Stream agent CLI diagnostics to the dashboard and `orchestrator.log` |

For subprocess failures that say "Check stderr output for details", rerun with
`--show-cli-stderr`. This displays diagnostics as they arrive for both investigation
and utility sessions, labeled by worker, model, or utility operation. The same lines
are saved in `<db-dir>/orchestrator.log`. Without the flag, CLI stderr remains suppressed.

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

The `Dockerfile` requires BuildKit. Docker Desktop and docker-ce use it by
default. On Debian/Ubuntu with the distro `docker.io` package, install the
`docker-buildx` plugin (`sudo apt-get install docker-buildx`); if the build
still prints legacy `Step N/M` output, set `DOCKER_BUILDKIT=1 docker build ...`.
Without BuildKit the build fails with
`failed to parse platform : "" is an invalid OS component of ""`.

Then run with the same volume mounts, substituting `mulder:dev` for the registry image:

```bash
docker run -it --privileged \
  -v /path/to/evidence:/evidence:ro \
  -v ~/mulder-cases:/home/mulder/.mulder/cases \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  mulder:dev
```

A `Makefile` is included for convenience. Run `make all` for pre-commit checks
and tests, `make dist-check` to build and validate Python packages, or
`make container-build` to build the image.
