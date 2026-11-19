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
    - [When a Run Ends Early](#when-a-run-ends-early)
    - [When a Session Runs Out of Turns](#when-a-session-runs-out-of-turns)
    - [When Analysis Is Cut Short](#when-analysis-is-cut-short)
    - [One Analyst Session per Question](#one-analyst-session-per-question)
    - [Limiting Token Use](#limiting-token-use)
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
  - [Ransomware Cases](#ransomware-cases)
  - [Cloud Audit Logs](#cloud-audit-logs)
  - [Loose Logs](#loose-logs)
  - [Counting Over Logs](#counting-over-logs)
  - [Triage Collections](#triage-collections)
  - [Linux Disk Images and File Trees](#linux-disk-images-and-file-trees)
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
    - [When No Incident Is Found](#when-no-incident-is-found)
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

- **Python 3.11 or newer**, plus [`pipx`](https://pipx.pypa.io/) (or `uv`).
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
the Didier Stevens suite, Chainsaw 2.16.0, Hayabusa 3.8.1, Zircolite 2.20.0, zizmor 1.32.0, capa 9.4.0,
FLOSS 3.1.0, gitleaks 8.30.1, evtx_dump 0.15.1, the six EZ Tools mulder invokes, ALEAPP, iLEAPP, and the Volatility 3 symbol packs.
It also fetches two small reference data sets for ransomware cases, each pinned to a commit: the LOLRMM remote
access tool catalog (Apache-2.0) and the ThreatLabz ransom note corpus (MIT).
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
docker pull ghcr.io/calebevans/mulder:1.6.1
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
  ghcr.io/calebevans/mulder:1.6.1
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
  ghcr.io/calebevans/mulder:1.6.1
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
  ghcr.io/calebevans/mulder:1.6.1
```

Model IDs are passed through to the SDK exactly as specified, with no automatic translation or mapping. When using Bedrock, you must provide the full Bedrock model ID with the `us.anthropic.` prefix (e.g. `--model us.anthropic.claude-opus-4-6`). If you omit `--model`, the built-in defaults (`claude-opus-4-6` for planner/analyst, `claude-haiku-4-5` for executor) are used.

| Variable | Description |
|----------|-------------|
| `CLAUDE_CODE_USE_BEDROCK` | Set to `1` to enable Bedrock |
| `AWS_REGION` | AWS region with Bedrock Claude model access |
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |

If you prefer file-based credentials, mount your whole `~/.aws` directory read-write at `/home/mulder/.aws` (as in the example above) instead of passing keys. This works for both static profiles in `~/.aws/credentials` and `aws login` sessions from AWS CLI 2.36+: the login token cache lives under `~/.aws/login/cache`, so the mount must be writable for the container to refresh it. The same mount serves `bedrock/` models routed through the LiteLLM proxy (see [Using Non-Anthropic Models via LiteLLM](#using-non-anthropic-models-via-litellm)).

### Using Your Own YARA Rules

Mulder scans with the [signature-base](https://github.com/Neo23x0/signature-base) rules by default. To add your own, point `MULDER_YARA_RULES` at a rule file or a directory of `.yar` / `.yara` files (several paths can be given, separated like `PATH`). Directories are searched recursively.

In the container that variable is already set to `/rules/yara`, so mounting a directory there is enough:

```bash
docker run ... \
  -v /path/to/my-yara-rules:/rules/yara:ro \
  ghcr.io/calebevans/mulder ...
```

On a native install, set the variable before running mulder:

```bash
export MULDER_YARA_RULES=~/rules/yara:/srv/team-rules/apt.yar
```

Your rules are then used alongside signature-base in every YARA scan (files, memory, and per-process with Volatility), and the agent can scan with yours alone by choosing the `custom` ruleset. A rule file that does not compile is left out rather than failing the scan; the others still run. The audit log records how many of your rule files each scan used.

Rule files that happen to be in the evidence directory are never loaded.

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

### When a Run Ends Early

`mulder investigate` exits non-zero whenever it does not finish, and it still leaves a report.

| Exit status | Meaning |
|-------------|---------|
| `0` | Every phase passed its gate and the report was finalized |
| `1` | A phase failed its gate after every retry, the run was interrupted (Ctrl-C, or SIGTERM as sent by `docker stop`), it crashed, or it reached its [token budget](#limiting-token-use) |
| `2` | The run could not continue: authentication failed, the model is not available, or the API account is out of credit |

**Out of credit.** If the provider reports that the account has no credit left or has reached a hard spending limit (for example Anthropic's "credit balance is too low", OpenAI's `insufficient_quota`, HTTP 402, or a LiteLLM budget), the investigation stops at once. No further phases, retries or continuations are started, because each would fail the same way. Ordinary rate limiting (requests or tokens per minute, HTTP 429 "too many requests") is not treated this way and is handled as before.

**Partial report.** When a run ends without a finalized report and the case database already holds at least one indexed source or finding, Mulder renders `{case_id}.report.md` and `{case_id}.report.html` from the database, the way `mulder report` does, and prints where they are. Both open with an **INCOMPLETE INVESTIGATION** banner naming the phase the run stopped in, the reason, and the phases and systems that were not completed (the first ten unfinished systems by name, the rest as a count). When a gate failed and the last session ended on a provider error, such as an ordinary HTTP 429, the reason quotes that error too.

Read a partial report for what it is. Its findings were saved before the run stopped and it has not passed the finalize gates. Evidence the run never reached was not examined, so a finding that is absent is not a clean result.

A partial report never replaces a finished one. A report that was finalized during the same run is left alone and no partial report is written. A report left by an earlier run of the same case is kept as well: the partial report is then written beside it as `{case_id}.partial.report.md` and `{case_id}.partial.report.html`, and its banner says so. Only an earlier partial report is replaced.

The case database and audit log are kept either way.

### When a Session Runs Out of Turns

Each role session has a turn limit. Reaching it is a pause, not a restart. Mulder resumes the same session, with its whole conversation and a fresh turn allowance, and it carries on from where it stopped. Before it continues, the session is asked to save the findings it has already established and to record a progress note, so its progress is in the case database as well as in the conversation. The dashboard shows `Analyst ran out of turns; resuming where it stopped (#1/3)`. This applies to analyst, executor, catalog and report sessions; a planner that runs out of turns is resumed for one turn with its tools off to write its plan.

`--max-compactions` (default 3) is how many times one role session may be continued this way. If the last continuation also runs out of turns, the session gets a final 8 turns with only its saving tools, to save and record a handoff note (`Analyst ran out of turns; saving and handing off`); that wrap-up is not counted, and with `--max-compactions 0` it happens at once.

A new session is started only when the old one cannot go on: the provider rejected its conversation as too long, or it could not be resumed (the reason is in `orchestrator.log`). The new session is given the notes the earlier one recorded, the findings saved since it started and the original task, and is told not to re-run tools that already succeeded or re-submit saved findings. It counts against `--max-compactions` like a resume.

A note is a model's own account of what it did. A new session is told to treat it as a record, not as verified fact: "ruled out" means ruled out in what that session examined, and anything the note does not mention is to be treated as not examined.

A resumed session sends its whole conversation again on every turn, as any session does, so several continuations of one long session cost more input tokens per turn than new sessions would, most of all with a provider that has no prompt caching. To compare the two behaviours, run with `--no-wrapup` (or `MULDER_WRAPUP=0`): no session is resumed, every continuation is a new session with the generic prompt, and analysts and executors are not told their turn budget.

### When Analysis Is Cut Short

A role session that is still unfinished after every continuation `--max-compactions` allows, and after its wrap-up, is cut short: the phase goes on without the rest of that session's work. Mulder records each one in the case database with its phase, role, system and, when the session had one of its own, its investigation question. A planner that runs out of turns and still has no plan after it was asked to write one is recorded the same way. The dashboard shows `Cut short, no continuation left: extraction analyst, system "DC01"`.

You will see the record in four places:

- the run summary on the terminal, in a **Sessions Cut Short** table;
- both reports, in an **Analysis Cut Short** section (the partial report and `mulder report` included);
- `get_investigation_summary`, as one `remaining_work` item, so the later phases know which earlier analysis was not finished;
- the case database itself (`kv_store`, key `cut_short_sessions`).

Read it for what it says. What the session saved or indexed is in the case. What it had not reached may not have been examined, and not examined is not the same as absent, so conclusions about that system or question may be incomplete. The record does not say the session found nothing, and it is not removed when a later retry, follow-up or second run covers the same ground: each entry carries the time it was recorded, so compare it with what ran afterwards. The list keeps the 100 most recent entries and says how many earlier ones were dropped.

To give sessions more room, raise `--max-compactions`.

### One Analyst Session per Question

The extraction planner writes the investigation questions for each system, from the evidence and from your [case briefing](#case-briefing) when there is one. After the executor has finished for a system, the analyst answers them one session at a time:

1. Each investigation question gets its own analyst session, one after another, with 25 turns. Its instruction is that one question: answer it, save the findings, close the question with `resolve_question` (see [When No Incident Is Found](#when-no-incident-is-found)), record a progress note, stop. At most 6 such sessions run for a plan; when the plan has more questions, the sixth takes all that are left, up to 20 questions in all. Questions past the twentieth are not asked, and the dashboard says how many were left out. The planner is told these numbers and to put the most important questions first. A session sees only its own question, so the planner is also told that evidence it has to report as not examined (a cloud audit export too large to read) is named inside every question it bears on, not only in an entry of its own.
2. One consolidation session of 15 turns then looks across what those sessions saved, for duplicate and contradicting findings and for questions left open, and may ask for a follow-up plan. It does not close questions itself: one that is still open after its session is closed by a later analyst that is asked it again, or by the report phase. A follow-up plan has questions of its own and is analysed the same way; its planner is told to ask only what the follow-up's tools could newly settle, not the earlier questions again.

This is how every run works; there is no option for it. Systems still run in parallel under `--workers`. A plan with one question gets one question session and the consolidation session. The cross-system and alternative-narrative analysts, and the session that fixes a failed gate's gaps, are one session each, as before.

**There are always questions.** An extraction plan without a usable investigation question (at least one plain string) is not accepted. The planner is told why and asked for the questions alone, with its tools off: first in its own session, then once in a new one (only the new one when its conversation had been rejected as too long, or when the plan itself had to be written in a new session). An answer that repeats the request's own `<question>` placeholder is not a question. If it still writes none, the dashboard shows `Questions gate failed for <system>` and the plan is dropped with nothing run from it. For a system's first plan, planning starts again, up to three planner sessions in all; after that the extraction for that system has failed: no analysis ran on it, the run goes on with the other systems and the later phases, the summary table shows `extraction FAIL`, and `mulder investigate` exits with status 1. The system is then on record in the case database as not analysed. Every report names it under **Systems Not Analysed**, directly below the executive summary: the finalized report, `mulder report` and the partial report (which also lists it under "Not completed"). While a system is listed there no report says that no incident was found, however the other systems' questions were resolved: a system that was not analysed has not been found clean. A system that is analysed after all, on a later attempt or in a later run of the case, is no longer listed. For a follow-up plan, the follow-up ends and what the earlier sessions saved stands.

A system's analysis takes up to 6 x 25 + 15 = 165 turns before any continuation, in up to seven sessions that each re-read the case context and run one after another. With every continuation `--max-compactions 3` allows, each session's wrap-up and its one nudge, the ceiling is 881 turns for one plan; `--max-tokens` is the way to bound a run. This has not been benchmarked against the single session of 60 turns it replaced.

### Limiting Token Use

`--max-tokens N` (or `MULDER_MAX_TOKENS=N`) caps what one run may use. Without it there is no limit and nothing in this section applies.

```bash
mulder investigate /evidence my-case --max-tokens 20000000
```

**What is counted.** Every token that every session reports when it ends: uncached input, output, cache-write input and cache-read input, summed over all sessions (planner, executor and analyst sessions, continuations, retries and the short utility queries) and over all models. The four kinds are added with equal weight. On Claude models most of the count is cache-read input, because each turn re-reads the conversation so far. A provider behind the LiteLLM proxy may report that replayed context as input or as cache-read input; the sum is the same. Either way the number is how much text the models processed. As a guide, the published GLM-5 runs of the single-host NDLC case used about 9 million tokens counted this way.

**Why tokens and not dollars.** Every provider reports token counts. The dollar figure Claude Code computes is priced from its own table of Claude models and is wrong for any other model, which is why Mulder has no dollar cap.

**What happens when it is reached.** Part of the budget is held back for the report: 15% of it, at least 750,000 tokens, and never more than half. Once what remains is down to that reserve, no new catalog, extraction, cross-system or alternative-narrative session is started, and whatever was left of those phases is skipped. The run goes straight to the report phase, which may spend the reserve. Its prompt says the budget was reached and lists the systems and phases that were not completed, so that the narrative says the investigation is incomplete. If the report phase cannot finalize a report, or the budget is fully spent before it starts, the [partial report](#when-a-run-ends-early) is written instead, with the reason "token budget reached".

Two stops run no report phase at all. A stop during the catalog ends the run there, since nothing was analysed. A stop that leaves the case with fewer findings than `finalize_report` requires also skips it: a report session cannot add findings, so it would spend the reserve and still be refused. The partial report is written in both cases, provided the case holds at least one indexed source or one finding; a case with neither gets no report.

Either way the run exits with status `1` and the end-of-run summary has a `Token budget` line marked REACHED. The one exception is a run that was already complete: if every phase passed and the report was finalized, and only a continuation of that last report session was refused, the run exits `0`. While the run is going, the bottom border of the dashboard header shows `Budget: used / limit`.

After a budget stop the summary's `Turns` counts every session that ran. The phase that was cut short has no row of its own in the phase table; the turns of its sessions are listed there as `(cut short)`.

**The cap can be overshot.** The budget is checked when a session starts. A session that is running is never interrupted, because stopping it would lose its work and its usage report. The final total can therefore end above `--max-tokens` by the sessions that were running when the line was crossed: one in most phases, up to `--workers` during extraction. A long analyst session can use more than a million tokens, so leave headroom.

**What it cannot see.** The count is only what providers report. A session that is killed or crashes before it ends reports nothing. Some proxy routes under-report: in the published Kimi K3 runs LiteLLM reported almost no input tokens, so for such a model the count is close to output tokens only and the budget has to be set with that in mind.

`{case_id}.model_usage.json` and the token table in the report list cache-write and cache-read input beside the input and output counts. "Total tokens" there is still input plus output, as before.

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

The proxy listens on `127.0.0.1` only, and mulder generates a random master key for each run and hands it to the proxy as `LITELLM_MASTER_KEY`. Leave `general_settings.master_key` unset in a custom config (or set it to `os.environ/LITELLM_MASTER_KEY`); the proxy fails to start if it does not accept that key.

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
- The analysts in each phase use it to answer your questions and take its facts (time zone, known accounts, scope) as given
- The cross-system correlator uses it to understand relationships
- The report writer uses it to frame conclusions around your questions

Questions and leads you write here shape the investigation questions the extraction planner asks. For each system it words the ones that system's evidence could answer, next to the questions it derives from the evidence, and the analyst answers those questions [one session at a time](#one-analyst-session-per-question): the first five get a session each and any others share a sixth. `MULDER.md` is the only place to put questions of your own; there is no flag or setting for them.

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

## Ransomware Cases

Say so in the briefing ("ransomware", "encrypted files", "ransom note") and the extraction planner adds the change journal, the logon summary and the shadow copy listing to every Windows image, not only the one the note was found on. The tools below work on what is already parsed and need no network.

| Question | Tool | Reads |
|----------|------|-------|
| When did encryption start and stop, and where first? | `find_encryption_activity` | the change journal (`run_usn_parser`), else the MFT |
| Which family? | `ransomware_family_hints`, and the hints inside the result above | Splunk's extension and note-name lists, the ThreatLabz note corpus |
| Which remote access tool was used, and from where? | `find_remote_access_tools` | the LOLRMM catalog against the file listing, Prefetch, Amcache, ShimCache, registry and DNS; then the tool's own logs |
| Who logged on, how and from where? | `run_hayabusa_logon_summary` | the extracted event logs |
| What left before encryption? | `find_data_exfiltration_indicators`, `find_file_staging` | network and filesystem sources |

What each result does and does not establish:

- **A candidate burst is a lead.** It is a run of minutes in which at least 50 files were renamed to one extension, plus a signal: the extension follows several kinds of data file, a known ransom note name appeared in several directories, or the volume never had the extension before. Compression, backup and bulk renames look the same, and neither the journal nor the MFT names the process or the account. All bursts of one extension on a volume are one candidate, so a run that pauses and resumes is reported from its first burst. Ransomware that overwrites files in place or gives each file its own extension is not flagged; the result lists the busiest periods of any kind for that reason.
- **The change journal is a ring.** It holds only recent changes, attackers delete it, and at most the newest 256 MiB is parsed. When a burst starts where the journal starts, the result says so and gives the earliest change the MFT knows. When the journal holds no candidate the MFT is read as well: that is how encryption older than the journal is found, and ransomware that writes each file under a new name and deletes the original (Dharma, Phobos), which leaves no rename in the journal. Without an indexed MFT neither is flagged.
- **A family hint is a family to check.** Families share extensions, note names and note templates, and the extension list misses several current families.
- **Presence of a remote access tool is not abuse.** AnyDesk, TeamViewer and the like are ordinary IT tools. What makes one part of the intrusion is installation or first run inside the incident window, by a compromised account, or a session in its own log from an address the organisation does not use. AnyDesk's `ad.trace` and `ad_svc.trace` carry the peer's IP address; TeamViewer's logs carry only IDs and host names.
- **The logon summary has counts, not times.** Hayabusa 3.8.1 counts each combination of account, logon type and source over the whole log (`log_period` gives the span the counts cover); search the Security log for when.

## Cloud Audit Logs

Mulder's agents work offline, so it does not call cloud APIs. Export the audit logs yourself, put the files in the evidence directory, and `run_cloud_audit_logs` indexes every event and applies Sigma rules. JSON arrays, JSON lines and CloudTrail `Records` files are all read, with or without a byte-order mark; the log type is recognised from the events. For Microsoft 365 and Entra ID, including the CSV export of the unified audit log, see [Microsoft 365 and Entra ID](#microsoft-365-and-entra-id).

| Log | One way to export it |
|-----|----------------------|
| GitHub organization audit log (Enterprise Cloud) | `gh api --paginate "/orgs/ORG/audit-log?include=all&per_page=100&phrase=created:>=2026-01-01" > github-audit.json` |
| GCP Cloud Audit Logs | `gcloud logging read 'logName:"cloudaudit.googleapis.com"' --project=PROJECT --freshness=30d --format=json > gcp-audit.json` |
| AWS CloudTrail | `aws s3 sync s3://BUCKET/AWSLogs/ACCOUNT/CloudTrail/ cloudtrail/ && gunzip -r cloudtrail/` |

Set the GitHub `created:` date and the gcloud `--freshness` to cover the incident; without a date filter GitHub returns only recent months. `aws cloudtrail lookup-events` output is not recognised; use the S3 log files. Do not put the exports in a directory named `logs` or `log`: mulder treats that as a host log directory and does not look inside for audit logs.

Events land in `cloudlog.github`, `cloudlog.gcp` and `cloudlog.aws`, one per line with time, actor, action, source IP and target ahead of the raw event, so `search` finds them. Sigma matches land in `cloudlog.<type>.detections`. The result names any file that was damaged, truncated or empty. The GitHub, GCP and AWS events are also loaded as rows, so they can be counted as well as searched: see [Counting Over Logs](#counting-over-logs).

GCP token exchanges, service account impersonation and Secret Manager reads appear only if Data Access audit logs were enabled for those APIs before the incident. Any other JSON log is indexed as `cloudlog.generic`; pass `ruleset_path` to scan it with your own Sigma rules.

### Microsoft 365 and Entra ID

For a business email compromise, export three logs for the affected accounts and the incident window, and the mailbox if you can. `run_cloud_audit_logs` reads all three logs as they are exported; nothing needs converting.

| Evidence | Ways to export it | What is read |
|----------|-------------------|--------------|
| Unified audit log (mail, files, directory changes, sign-ins) | Purview portal: **Audit**, run a search, **Export**. PowerShell: `Search-UnifiedAuditLog -StartDate 2026-10-01 -EndDate 2026-10-15 -UserIds alice@contoso.com -SessionId bec1 -SessionCommand ReturnLargeSet -ResultSize 5000 \| Export-Csv ual.csv -NoTypeInformation -Append`, repeated until it returns nothing. Microsoft-Extractor-Suite: `Get-UAL`. | The CSV (each event is the JSON in its `AuditData` column), or JSON / JSON lines of the same records |
| Entra sign-in log | Entra admin center: **Sign-in logs**, **Download**, JSON. Graph PowerShell: `Get-MgBetaAuditLogSignIn -All -Filter "createdDateTime ge 2026-10-01T00:00:00Z" \| ConvertTo-Json -Depth 10 > signins.json`. Microsoft-Extractor-Suite: `Get-GraphEntraSignInLogs`. Log Analytics: `SigninLogs` exported as JSON. | JSON |
| Entra audit log | Entra admin center: **Audit logs**, **Download**, JSON. Graph PowerShell: `Get-MgAuditLogDirectoryAudit -All \| ConvertTo-Json -Depth 10 > directory-audit.json`. Microsoft-Extractor-Suite: `Get-GraphEntraAuditLogs`. Log Analytics: `AuditLogs` exported as JSON. | JSON |
| Mailbox | A `.pst` from a Purview eDiscovery export or from Outlook, or the `.ost` of the user's Outlook profile | `parse_pst` |

Put them together in one directory named for the tenant, and the investigation treats it as one system:

```
evidence/
  contoso-m365/
    ual.csv                  unified audit log
    signins.json             Entra sign-ins
    directory-audit.json     Entra audit log
    alice.pst                mailbox export
```

Things that go wrong when exporting:

- **Exports stop without saying so.** `Search-UnifiedAuditLog` returns 100 results unless `-ResultSize` asks for more, at most 5,000 sorted and 50,000 with `ReturnLargeSet` (10,000 if the two session commands are mixed); a Purview export stops at 50,000 rows, or 1,000,000 with Audit (Premium). Mulder flags a file with exactly such a count (`export_warnings`, and a `WARNING` line in the summary), but cannot tell what is missing. Search shorter time ranges, or fewer users, until each result is below the limit.
- **`ConvertTo-Json` flattens nested objects** below two levels unless you pass `-Depth`; the status, location and device of a sign-in are then lost. Use `-Depth 10`.
- **The sign-in log's CSV download is not read.** Download JSON.
- **Graph v1.0 sign-ins have no user agent and no session id** (`Get-MgAuditLogSignIn`). Use the beta endpoint (`Get-MgBetaAuditLogSignIn`) or Microsoft-Extractor-Suite when you need to follow a session; the summary says when an export has neither.
- **Retention is short.** The unified audit log keeps 180 days by default (90 for records before October 2023, a year with E5 licences); Entra sign-in and audit logs keep 30 days, 7 without a premium licence. Export early, and tell mulder in the briefing what window you exported.
- **Name JSON exports `.json`, `.jsonl` or `.ndjson`.** Sign-in and audit logs routed through Azure Monitor diagnostic settings (a storage account or an event hub) are read as they are, but a file with another suffix, such as `.log`, is not recognised in a directory.
- **One call reads at most 512 MiB of files**, because every event of a call is held in memory (eight to nine times the size of the files: a 533 MB export peaked at 4.4 GB). A directory over the limit is refused whole when it is named in a call, so an investigation plans it file by file instead: the 50 largest files that fit, one call each. Each call then writes a summary of its own file, and only the log tables span them. A single file over the limit, and the files of such a directory beyond those 50, are not read: the planner is told so and the tool coverage audit lists them as gaps. Export a file over the limit again over shorter date ranges, or split it (each part of a CSV needs the header line), and lay a tenant-wide export out in subdirectories of at most 512 MiB each, for example one per month: each subdirectory is then read by one call and gets one summary.
- **Paged and overlapping exports repeat records.** Within one call, a record with the same `Id` and the same content is counted once; `duplicates_skipped` in the result and the first line of the summary say how many repeats there were. A record that two files hold is counted twice when the files are read by separate calls (a directory over the size limit, or files at the top of the evidence directory), so keep overlapping exports together in one directory under the limit.
- Windows PowerShell's `>` writes UTF-16, `Export-Csv` may add a `#TYPE` line, `Export-Csv -UseCulture` separates columns with the host's list separator (a semicolon in much of Europe), and Windows PowerShell 5.1's `ConvertTo-Json` writes a date as `\/Date(1791203595000)\/`. All are read.
- **A symlink is not followed.** Copy an export into the evidence directory rather than linking it.

Events land in `cloudlog.m365`, `cloudlog.entra_signin` and `cloudlog.entra_audit` and in log tables of the same names. Each also gets `cloudlog.<type>.summary`, computed without a model: per user the source IPs, user agents and sessions with first and last seen; sessions seen from more than one source IP; the operations that leave access behind (inbox rules, forwarding, mailbox permissions, application consent and credentials, registered sign-in methods, audit logging changes, transport rules) with their parameters; and, per mailbox, what MailItemsAccessed recorded, sync and bind apart. Eight Sigma rules for those operations run on the unified audit log, with SigmaHQ's rules for raw audit records; the Entra logs have no rules of their own.

What these logs cannot show: a sync of a mail folder means every message in it was copied to a client, whichever were opened; MailItemsAccessed is recorded only for mailboxes licensed and audited for it, so its absence is not evidence that no mail was read; and a location is only what the sign-in record itself says, since mulder looks no address up.

### Laying out cloud and CI evidence

Give each kind of evidence its own directory under the evidence root. Mulder recognises four kinds, lists each for the planner with its path and the tool to run, and checks afterwards that the tool was run:

| Evidence | How it is recognised | Tools planned |
|----------|----------------------|---------------|
| Cloud audit log exports | `.json`, `.jsonl` or `.ndjson` files that carry audit-log keys, and `.csv` files with an `AuditData` column | `run_cloud_audit_logs` |
| Mailbox files | `.pst` and `.ost` files | `parse_pst` |
| Repository checkout | a directory containing `.github/workflows` | `run_workflow_audit`, `run_secret_scan` |
| CI run logs | a directory of GitHub Actions run logs as downloaded (`1_build.txt`, timestamped lines) | `run_secret_scan` |

For example:

```
evidence/
  ws-042.E01                 a host image, as before
  acme-org-audit/            gh api ... > github-audit.json
  acme-prod-gcp/             gcloud logging read ... > gcp-audit.json
  acme-app/                  git clone of the repository
  run-18234/                 unzipped "Download log archive" of a workflow run
```

Each directory becomes its own "system" in the investigation, named after the directory, so name it for what it holds. A zip of any of these works too; it is unpacked first and recognised where it lands. Other CI systems' logs and artifacts are not recognised automatically: name them in the case briefing and the planner can still run `run_secret_scan` on them.

### Collecting with read-only credentials

Instead of exporting by hand, you can give mulder credentials that can only read audit logs and let it fetch them. Two things are yours to get right: create a dedicated identity for this, and grant it nothing but log reading.

| Provider | Create | Set |
|----------|--------|-----|
| GitHub (Enterprise Cloud) | A classic personal access token with **only** the `read:audit_log` scope, from an organization owner | `MULDER_GITHUB_TOKEN`, and `MULDER_GITHUB_ORGS=org1,org2` |
| Google Cloud | A service account with `roles/logging.viewer` on the project, plus `roles/logging.privateLogViewer` if you need Data Access logs (secret reads, token exchanges); download its key file | `MULDER_GCP_CREDENTIALS=/path/key.json`, and optionally `MULDER_GCP_PROJECTS=p1,p2` (default: the key's own project) |

Then either collect before the investigation:

```
mulder collect github --out evidence/acme-org-audit --since 2026-11-01 --until 2026-11-12
mulder collect gcp    --out evidence/acme-prod-gcp  --days 30
mulder investigate evidence case-1
```

or let the investigation collect what it needs, by also setting `MULDER_AGENT_COLLECTION=1`. The planner is then told which organizations and projects it may collect from, and the analyst can ask for a log it finds it needs.

What mulder does to keep this safe:

- **Only `MULDER_*` variables are read.** Your own `gh` or `gcloud` login, `GH_TOKEN` and `GOOGLE_APPLICATION_CREDENTIALS` are never used, since those can usually write.
- **The targets are fixed by you.** An investigation chooses a time window. It cannot name an organization or project that is not in your configuration.
- **Google tokens are requested for log reading only** (`logging.read`), so even an over-privileged service account yields a token that can do nothing else.
- **A GitHub token that can do more than read is called out** in the result, and a fine-grained or app token, whose scopes cannot be checked, is flagged as unverified.
- **Only audit-log read endpoints are called.** The GitHub token is sent to the GitHub API host and nowhere else.
- **Nothing is written to the evidence directory** during an investigation. Collected logs go under the case's own directory. Each export has a manifest beside it with the query, the time, the event count and the SHA-256.

It cannot check that a Google service account or a fine-grained GitHub token is read-only; that part is on you. AWS is not supported yet; export CloudTrail as above.

GitHub keeps audit events for about six months and Git events for seven days, so collect early.

### Evidence that was not provided

When the evidence shows that more evidence exists elsewhere, for example a host image whose user ran a cloud CLI, and the corresponding logs are not in the case, the analyst records it as a `[COLLECT]` finding citing where it saw the trace. These are not counted as findings. The report lists them under **Evidence To Collect**, with the account or project and the time range worth exporting, so you can add the export and run again.

## Loose Logs

The logs that say how an intruder got in rarely come inside a disk image: a VPN or firewall export, a web server's access logs, the output of a Zeek or Suricata sensor, the support bundle of a hypervisor. Put them in the evidence directory and `run_loose_logs` reads them. It recognises each file's format from its content, indexes every line as text, and loads what it can parse into [log tables](#counting-over-logs).

| What you have | Put it | It becomes |
|---------------|--------|------------|
| Web server access logs: Apache or nginx (common or combined format), IIS (`u_ex*.log`) | in a directory of their own, e.g. `web01-iis/` | `logs.web`, with Sigma matches in `logs.web.detections` and web shell candidates in `logs.web.webshell` |
| VPN and firewall logs: FortiGate or SonicWall key=value syslog, Cisco ASA syslog | a file or directory, e.g. `fortigate/` | `logs.firewall`: who logged in, from which address, when, over which kind of tunnel |
| Zeek logs (tab-separated or JSON) and Suricata `eve.json` | the sensor's log directory | `logs.zeek.*` and `logs.suricata.*` |
| An ESXi `vm-support` bundle | the unpacked bundle directory, or the `.tgz` (it is unpacked first) | `logs.esxi`, with the lines that matter in a ransomware case in `logs.esxi.highlights` |
| A Linux host's `/var/log`, or any directory named `log` or `logs` | as it is, e.g. `web01/var/log/` | `logs.syslog`, and whichever of the above its files turn out to be |
| Any other text | | `logs.text`: searchable, nothing parsed |

A directory named `log` or `logs`, a directory under `var/log`, and an ESXi bundle are each read as a whole. Loose `.log` and `.txt` files elsewhere (and rotated ones such as `access.log.1`) are read through the highest directory that holds no other evidence mulder recognises, so a tree with a log in every folder is one run; a log that sits beside, say, a disk image is read by itself. From such a directory only those files are read: a web root or source files beside the logs are left alone and counted as not read. Each directory becomes part of the system named after it, as for cloud evidence; a firewall export or a sensor is a system of its own. Gzip files in a log directory are read as they are; any other archive there (`.zip`, `.7z`, a tarball, a log rotated with `xz` or `zstd`) is unpacked first, like an archive anywhere else. A `Logs` folder that holds only Windows event logs (`.evtx`) is not read by this tool.

A `var/log` that comes with the rest of its system is not planned for this tool. A directory that holds `etc/passwd` (an unpacked root file system), a UAC collection, and the files exported from a Linux disk image are each one [Linux file tree](#linux-disk-images-and-file-trees): nothing inside one is listed as a log directory, and `run_plaso` with `linux_logs` reads its login and system logs into `plaso.timeline`. That preset reads no web server access log and fills no log table. `run_loose_logs` reads the `var/log` of such a tree when it is run on it, which the analyst can ask for; the syslog lines are then in `plaso.timeline` and in `logs.syslog` both.

What to know before relying on the result:

- **Leads, not verdicts.** A Sigma match in `logs.web.detections` is a request that looked like an attack; its status code and what the same address did next say whether it worked. `logs.web.webshell` lists scripts that took a successful POST and that at most three addresses ever requested: a web shell looks like that, and so does an admin page. A shell that was only ever fetched with GET is not listed. `logs.esxi.highlights` matches known ESXi messages (SSH or the shell enabled, logins, shell commands, machines powered off, the execInstalledOnly setting, VIB installs): it says what a line is about, not that it was hostile.
- **Times.** Offsets in the log are applied. A time without one (syslog, ASA, older FortiGate) is read as UTC, and the tool's result names the tables that applies to: if the device kept local time, those times are off by its offset. Syslog lines carry no year; it is taken from the file's modification time, so keep that when you copy logs (`cp -p`, `tar`, `zip`).
- **Coverage.** A table holds the files you provided and nothing else. ESXi and firewalls keep little history, and the period that matters may already be gone. `list_log_tables` shows each table's first and last time. When the logs that would answer a question are missing, the analyst records them as a `[COLLECT]` finding rather than reporting that nothing happened.
- **Not parsed.** Palo Alto CSV, Citrix NetScaler and Ivanti Connect Secure logs, FortiGate CEF or CSV exports, Windows firewall logs, the binary systemd journal and application logs in JSON are not recognised. Text among them is indexed as `logs.text` and can be searched. Ivanti's binary `.vc0` logs are read by Plaso instead: `run_plaso(parsers="ivanti_vc0")`. In a file that mixes formats, such as a syslog server's catch-all file, the lines of the minority format count as not parsed.
- **Limits.** 1 GiB of text per file and 4 GiB and 5,000 files per run; what is cut off is reported, as is a directory the tool was not allowed to list. Split a larger set into directories. Symbolic links are not followed.

The formats, the fields of each table and every limit are in the [Tool Manifest](tool-manifest.md#run_loose_logs).

## Counting Over Logs

Search answers "is this string in the log". It does not answer "which source IPs signed in as this user, and how often" or "how many events per hour": the index keeps a log as windows of text, a few events per window, and counting by paging through hits is where a model with a small context window gives up or miscounts.

Logs that mulder parses into events are therefore also loaded as rows into a **log table** in the case database, and four tools count over them:

| Tool | Answers |
|------|---------|
| `list_log_tables` | which tables exist, their rows, time range and fields |
| `log_top` | the most (or least) frequent values of one to three fields, with count, first seen, last seen and a byte sum where the log has one |
| `log_histogram` | events per minute, hour or day, optionally split by one field |
| `log_rows` | the matching events themselves, a page at a time, in time order |

Today `run_cloud_audit_logs` fills `cloudlog.github`, `cloudlog.gcp`, `cloudlog.aws`, `cloudlog.m365`, `cloudlog.entra_signin` and `cloudlog.entra_audit` (and so does `collect_cloud_audit_logs`, which indexes through it), and `run_loose_logs` fills `logs.web`, `logs.firewall`, `logs.zeek.*`, `logs.suricata.*`, `logs.esxi` and `logs.syslog` (see [Loose Logs](#loose-logs)). For example, on a CloudTrail export:

```
log_top(table="cloudlog.aws", fields=["src_ip"],
        filters=[{"field": "actor", "op": "contains", "value": "user/backup"}])
log_histogram(table="cloudlog.aws", bucket="hour",
              filters=[{"field": "src_ip", "op": "eq", "value": "203.0.113.9"}])
log_rows(table="cloudlog.aws", t_start="2026-11-10T12:00:00Z", t_end="2026-11-10T13:00:00Z",
         filters=[{"field": "status", "op": "ne", "value": "Success"}])
```

The model names fields and gives values; it never writes SQL, and nothing it supplies becomes part of a statement. Every result says which filter was applied, how many rows matched out of how many in the table, how many records could not be parsed, and whether the answer was cut short, and is indexed under its own `logtable.*` source so a finding can cite it. The full reference, with the filter operators, is in the [Tool Manifest](tool-manifest.md#log-tables).

What a count does and does not tell you:

- It counts the records that were exported, parsed and loaded. A service that was not logging, a window the export did not cover, and records listed under `rows_not_parsed` are not in it. `rows_not_parsed` is a lower bound: a truncated or damaged file counts once however many events it lost.
- Values are compared as written: `Alice@example.com` and `alice@example.com` are two actors unless you filter with `contains`. (The Microsoft 365 and Entra tables store a user principal name in lower case, so there they are one.)
- Cloud audit logs are loaded once per evidence path. A path inside one that is already loaded (a subdirectory, or one file of it) adds no rows, a directory replaces the rows of paths inside it, and a forced re-run or another spelling of the same path replaces its rows. The one exception is a file that a directory run does not read (it has no `.json`, `.jsonl` or `.ndjson` suffix and is not a unified audit log `.csv`) and that was run by itself: it keeps its own rows. Copies of a file in two separate directories are still two sets of rows; `list_log_tables` shows each path and its rows under `loaded_from`.
- A stored value is one line of at most 512 characters (a longer one ends in `…`), and times are kept to the second. A time before 1990 or after 2100 (a zeroed or forged timestamp) is kept as no time and counted under `rows_without_time`. The whole event is in the text index: `log_rows` gives its source and line.

## Triage Collections

A triage collection is the set of files a collector copied off a live system. Mulder reads one where it would read a disk image: put the collection in the evidence directory, as a directory or as the archive the collector wrote, and the Windows artifact tools (registry, Prefetch, Amcache, ShimCache, `$MFT`, event logs, application files, browser history) run on the collected files.

| Collection | How it is recognised | What mulder also indexes |
|------------|----------------------|--------------------------|
| KAPE target output | a `C`, `D`, ... (or `VSS<n>`) directory beside KAPE's `..._CopyLog.csv` / `..._ConsoleLog.txt` | the copy log (original path, SHA-1 and timestamps of every file) and the skip log |
| Velociraptor offline collection | `uploads/` or `results/` beside `client_info.json` or `collection_context.json` | each `results/<Artifact>.json` as a searchable source |
| UAC output | `uac.log` beside `[root]`, `live_response` or `bodyfile` | the `live_response` command output per category, and a timeline from the body file (`run_mactime`) |
| A Windows volume directory | it holds `Windows/System32/config` | nothing more: only the files |

```
evidence/
  dc01.E01                              a disk image, as before
  ws-042/                               KAPE --tdest: C/, 2026-..._CopyLog.csv, ...
  Collection-WS-077-2026-11-12.zip      Velociraptor offline collector output
  uac-web01-linux-20261112093000.tar.gz UAC output
```

Each collection is one system, named after the host the collection states (KAPE's console log, Velociraptor's `client_info.json`, the name UAC gives its archive) or else after its directory. Keep other evidence beside a collection's directory rather than inside it: apart from disk images, memory dumps, captures and archives left at its top level, files inside a collection are treated as collected files. Memory and crash dumps the collector copied (`MEMORY.DMP`, `*.dmp`) are still listed as memory dumps for Volatility. The files inside a collection are not hashed into the evidence registry one by one; `scan_evidence` says so, and KAPE's copy log carries the SHA-1 of each file as it was on the system.

`index_triage_collection` writes `triage.summary`, which records which kinds of artifact the collection holds and which it does not. That matters for reading the report:

- **A collection is not a disk.** There is no unallocated space and there are no deleted files, so carving, `bulk_extractor` and deleted-file listing are not run on it. A statement that something was not found means it was not found in what was collected.
- **The timestamps on the copies are not evidence.** Original file times come from `$MFT` when it was collected, from KAPE's copy log, or from Velociraptor's upload metadata.
- **The host name is the collector's own record** of it.

A KAPE `.vhd` or `.vhdx` container is read as a disk image (Sleuth Kit opens both). Paths inside it start with the drive letter, and the container's own file system describes the copies, not the original system. CyLR output is not recognised by name; a tree that holds `C/Windows/System32/config` is treated as a Windows volume directory.

## Linux Disk Images and File Trees

The usual Linux server disk is LVM, often with XFS on top, and the Sleuth Kit packaged for Ubuntu 22.04 (4.11) reads neither: `fls` fails, or lists `/boot` and nothing else. Mulder reads such an image through dfVFS instead, by driving plaso's `log2timeline`, `psort` and `image_export`. Nothing needs installing and nothing needs mounting.

When mulder scans the evidence it looks at the first sectors of each partition. An image that holds an LVM physical volume or an XFS file system is labelled with it (`[disk_image, LVM physical volume at sector 501760, volume group vg0]`), and the planner is told to plan:

| Tool | On | What it gives |
|------|----|---------------|
| `export_linux_files` | the image | `linux.filelist`, a listing of every file on every volume that could be read, and an export directory under the case directory holding `/etc`, cron and systemd units, `/var/log`, `/root`, each user's dotfiles and `.ssh` (shell histories, shell profiles and `.ssh` from any directory, since a service account's home is rarely under `/home`), package manager state, web roots and `/tmp`, each within a size limit |
| `run_plaso` with `parsers="linux_logs"` | the image | who logged in, from where and how: wtmp, btmp, auth.log or secure, the systemd journal, the audit log, apt and dpkg logs |
| `run_linux_persistence` | the export directory | one row per file in the places Linux starts programs from or grants access through, and the accounts with uid 0 or a login shell |
| `index_app_files` | the export directory | the text of a directory (`etc/ssh`, `root`, `home`, `var/www`), whatever the files are called |

`run_mmls` and `run_bulk_extractor` run on the image as usual. The export directory holds ordinary files, so `yara_scan_files`, `run_clamav`, `read_evidence_file` and `triage_binary` can be pointed at it.

What to keep in mind when reading the report:

- **The listing is not the export.** `linux.filelist` shows that a file exists, with its owner, size and four timestamps (modified, changed, created, accessed), whether or not it was exported. To read a listed file that was not exported, the analyst asks for it and `export_linux_files` is run again with `paths`.
- **Password hashes and private keys are not exported, by their well-known names**: `/etc/shadow`, `/etc/gshadow`, Debian's copies under `/var/backups`, SSH host and user private keys, TLS private keys. They are listed, and the report should say "not exported" rather than "absent". A copy under another name is exported like any file; a private key is still kept out of the index by its first line.
- **No deleted files.** dfVFS lists allocated files only, and nothing here reads unallocated space except `run_bulk_extractor`.
- **The export is one tree.** The volume that holds `etc/passwd` is the root. `/home`, `/var`, `/var/log` and `/boot` on a volume of their own are recognised from their top-level names and their files are put at that place in the tree, so `home/alice/.bash_history` is where the tools look for it; the result says that this is a guess, and it takes two such names to make one. Any other separately mounted volume is listed and read as if it were a root volume: the same paths are exported from it, under a directory named after the volume (`p5/lib/systemd/system/` for a `/usr` volume). A file the root volume holds under a mount point, at a path the mounted volume has too, was not what the running system showed: the mounted volume's file is exported and the other is named in `not_exported`, to be asked for by path.
- **An export can be incomplete, and says so.** One file name that is not valid UTF-8 stops dfVFS from reading the rest of its directory. The result then has `status: incomplete`, names the directory under `listing_incomplete` and the files that could not be copied under `not_exported`, and `run_linux_persistence` repeats both. The rest of the volume is listed and exported; only that directory is not examined, and the report should say so.
- **The persistence sweep is an inventory.** Nearly every row is the distribution's own file. It marks nothing as malicious and does not show that anything ran. Every `etc/passwd` in the tree is read, the system's own first; an account row names the file it is from, so a backup copy or a container layer is not taken for the system's accounts.
- **Syslog lines have no year.** plaso takes it from the file's own times; the systemd journal, wtmp and dpkg.log carry full dates.

What cannot be read is said, not skipped: an encrypted (LUKS) volume, btrfs, and a volume group spread over several disks of which the image is one. What is planned then depends on what else the disk holds:

| The image holds | What is planned |
|-----------------|-----------------|
| LVM or XFS, with or without `/boot` or an EFI partition beside it | the four tools above; `run_fls` and the Windows parsers are not planned |
| LVM or XFS beside NTFS or exFAT | the usual disk tools for the rest of the image, and the four tools above for the Linux volume |
| a volume no tool reads, beside a file system Sleuth Kit reads (NTFS, FAT, exFAT, ext2/3/4) | the usual disk tools for the rest of the image; the volume is reported as not examined |
| nothing but a volume no tool reads | `run_mmls` and `run_bulk_extractor` only |

`export_linux_files` and `run_plaso` pass an encrypted partition by and read the others, naming it under `not_read`; when the encrypted volume is all there is, the call is an error that says so.

A Linux image Sleuth Kit can read (ext2/3/4 on a plain partition) is handled as any disk image; `run_linux_persistence`, `index_app_files` and `run_plaso` with `linux_logs` take the image itself. Each image is read through its own file listing: with several images in a case, one never borrows another's.

A directory that holds a Linux file tree is recognised by its `etc/passwd`: an unpacked root file system, the `[root]` of a UAC collection, a Velociraptor collection of a Unix host. It is one evidence item, labelled `Linux file tree` with the name from `etc/hostname`, and the three tools above take the directory. Its `var/log` is read with it, by `run_plaso`, and is not also a log directory for `run_loose_logs` (see [Loose Logs](#loose-logs)); an ESXi support bundle holds `etc/passwd` too and stays a bundle. No file in such a tree changes that: mulder's own exports are told apart by where they are (a hidden directory under the case's extraction directory), never by a file an intruder could have left on the system.

```
evidence/
  web01.E01            LVM: exported to <cases>/extracted/<case>/.linux-exports/web01.E01-<digest>/files/
  db02-rootfs/         a Linux file tree: etc/, var/, home/, ...
  uac-app03-linux-20261112093000.tar.gz
```

Listing and exporting a disk of 85,000 files took about a minute and a half, and `run_plaso` with `linux_logs` about four minutes (a 1.2 GB E01, arm64 container). The listing needs temporary space, about 4 MiB per 1,000 files (345 MiB for that disk), in the directory `TMPDIR` names: `export_linux_files` does not start it with less than 1 GiB free, and says so.

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
| `--max-compactions` | `3` | Continuations allowed per role session after a turn limit (the session is resumed) or context exhaustion (a new session); `0` disables. The extraction analyst runs one session per investigation question and then a consolidation session, and each of those is a role session of its own (see [One Analyst Session per Question](#one-analyst-session-per-question)). Also settable via `MULDER_MAX_COMPACTIONS` (the flag wins) |
| `--wrapup` / `--no-wrapup` | on | At a turn limit, resume the session where it stopped, with its conversation intact, instead of replacing it. `--no-wrapup` restarts cold. Also settable via `MULDER_WRAPUP=0` (the flag wins). See [When a Session Runs Out of Turns](#when-a-session-runs-out-of-turns) |
| `--max-tokens` | None | Token budget for the whole run: input, output, cache-write and cache-read tokens of every session and model. Unset means no limit. Also settable via `MULDER_MAX_TOKENS` (the flag wins). See [Limiting Token Use](#limiting-token-use) |
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
| `--host` | `127.0.0.1` | Bind address for `streamable-http`. Set `MULDER_HTTP_TOKEN` to require `Authorization: Bearer <token>` on every request; without it the HTTP transport is unauthenticated and a warning is logged |
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
| `{case_id}.model_usage.json` | Tokens each model reported during `mulder investigate`: input, output, cache-write input and cache-read input |

### Reports

| File | Description |
|------|-------------|
| `{case_id}.report.md` | Markdown report for plain-text review |
| `{case_id}.report.html` | Self-contained HTML report with dark/light theme and sidebar navigation |
| `{case_id}.report.pdf` | PDF report for formal distribution |

All report formats include an executive summary, severity overview, evidence integrity hashes, attack timeline, detailed findings with MITRE ATT&CK mappings, IOC tables, audit metrics, and a sources appendix.

A report that opens with an **INCOMPLETE INVESTIGATION** banner is a partial one, written because the run ended early. See [When a Run Ends Early](#when-a-run-ends-early).

### When No Incident Is Found

An investigation can end with the conclusion that the evidence shows no incident. Each planner writes down the questions it wants answered. They are stored in the case database, and the analysts close each one:

| Resolution | Meaning | What it must rest on |
|------------|---------|----------------------|
| Answered | The evidence shows what happened | A finding of activity that cites at least one tool call that extracted, searched or read evidence |
| Ruled out | The sources examined do not show it | A `[NEGATIVE]` finding that cites at least one such call |
| Undetermined | The evidence needed is not in the case or could not be read | A stated reason |

A case normally needs three findings before a report is written. A case with fewer passes instead when every recorded question is resolved and both coverage audits have run. If that case also has no finding of medium severity or above, and at least one question was answered or ruled out, the executive summary opens with "No evidence of an incident was found in the evidence examined", then lists what was examined (how many evidence sources there are, how many of them the findings cite, and how many of the tool calls went to tools that extract, search or read evidence, failed calls included) and what was not available: the undetermined questions with their reasons, and any `[COLLECT]` leads. That sentence is never written while a system is listed under **Systems Not Analysed** (its plans had no investigation questions, so it has none on record to be left open).

Read that sentence as written. It is a statement about the sources that were indexed and searched, not proof that nothing happened. A ruled-out question whose finding is later deleted or re-titled is open again, so the conclusion cannot outlive its evidence. The report lists the recorded questions under **Investigation Questions** whichever way the case passed; a case investigated before questions were recorded has none and is reported as before.

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
