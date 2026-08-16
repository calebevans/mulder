# Installing Mulder on the SANS SIFT Workstation

The container image is the portable path and is not going away. This guide covers the
other one: a native install onto a SIFT Workstation, where most of the underlying
forensic toolchain is already present and only the gaps need filling.

`install.sh` builds an isolated virtualenv at `/opt/mulder`, puts a wrapper on `PATH`,
and installs the forensic tools SIFT does not ship. It reproduces the container's
filesystem layout exactly, because Mulder's Python source hardcodes those absolute
paths. No file under `src/` changes.

## Table of Contents

- [Installing Mulder on the SANS SIFT Workstation](#installing-mulder-on-the-sans-sift-workstation)
  - [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
  - [What Mulder Reuses From SIFT](#what-mulder-reuses-from-sift)
  - [What the Installer Adds](#what-the-installer-adds)
  - [Tiers](#tiers)
    - [Tool Availability by Tier](#tool-availability-by-tier)
  - [Disk Footprint](#disk-footprint)
  - [What Gets Installed Where](#what-gets-installed-where)
  - [Options](#options)
  - [Verifying an Install](#verifying-an-install)
  - [Updating](#updating)
  - [Uninstalling](#uninstalling)
  - [Supply Chain](#supply-chain)
  - [Out of Scope](#out-of-scope)
  - [Troubleshooting](#troubleshooting)

## Quick Start

From a checkout, which is the reviewable option:

```bash
git clone https://github.com/calebevans/mulder.git
cd mulder
sudo ./install.sh
```

Or as a one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/calebevans/mulder/main/install.sh | sudo bash
```

Read the script before you pipe it to a root shell. It is a single file at the repo
root and every network fetch, every path it writes, and every `apt-get install` is
visible in it. If you would rather not pipe, use the checkout form above.

The installer is safe to re-run. It reconciles the venv, the wrapper and the
environment file on every run, skips large downloads it has already made, and never
touches an existing investigation workspace.

After it finishes:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
mulder investigate /path/to/evidence my-case-id
```

Run it as your normal SIFT user (`sansforensics`), not as root. The installer needs
root; Mulder does not.

## What Mulder Reuses From SIFT

This is the point of the native install. Everything in this table is already on a
stock SIFT Workstation and the installer leaves it alone.

| Tool | How Mulder reaches it | Where SIFT puts it |
|------|----------------------|--------------------|
| plaso (`log2timeline.py`, `psort.py`) | `shutil.which`, exact names | GIFT PPA `plaso-tools` |
| Sleuth Kit (`fls`, `icat`, `mmls`, `fsstat`, `istat`, `mactime`) | `shutil.which` | SIFT PPA `sleuthkit` |
| bulk_extractor | subprocess | SIFT PPA |
| hindsight | `hindsight.py`, tried first | `/opt/pyhindsight` venv, symlinked |
| MVT (`mvt-android`, `mvt-ios`) | `shutil.which` | `/opt/mvt` venv, symlinked |
| RegRipper (`rip.pl`) | subprocess | `/usr/share/regripper`, symlinked |
| ExifTool | subprocess | apt plus a source build |
| .NET runtime (`dotnet`) | `require_binary` | `dotnet-sdk-9.0` from the backports PPA |
| EZ Tools (5 of the 6 DLLs Mulder invokes) | recursive search under `/opt/zimmermantools` | `/opt/zimmermantools`, net9 channel |
| libesedb, libbde, libvshadow, libfvde, pff/pst | subprocess | GIFT PPA |
| radare2, ClamAV, tshark, java, docker, git, curl, jq | subprocess | apt |

Deliberately **not** installed into Mulder's venv, so SIFT's copies stay
authoritative: **plaso**, **MVT** and **pyhindsight**. The wrapper puts
`/opt/mulder/venv/bin` first on `PATH`, so anything in the venv shadows SIFT's copy —
these three exclusions are load-bearing, not a size optimisation.

## What the Installer Adds

| Component | Version | Why it is needed |
|-----------|---------|------------------|
| Mulder itself | this checkout | virtualenv at `/opt/mulder/venv` |
| `yara` binary | apt | SIFT ships `python3-yara`, the module, but not the CLI Mulder shells out to |
| Chainsaw | 2.16.0 | `run_chainsaw`, plus its `rules/` and `mappings/` |
| Hayabusa | 3.8.1 | `run_hayabusa` (amd64 only) |
| Zircolite | 2.20.0 | `run_zircolite` |
| SigmaHQ rules | r2024-09-02 | Chainsaw and Zircolite rule sources |
| MITRE ATT&CK STIX | upstream `master` | `lookup_attack_technique` |
| PECmd | net9 channel | the one EZ Tool DLL SIFT does not ship |
| CAPA | 9.4.0 | `run_capa` |
| signature-base | upstream `HEAD` | the only YARA rule source `run_yara` uses |
| Volatility 3 symbol packs | upstream current | avoids a per-case symbol download |
| ALEAPP, iLEAPP | upstream `HEAD` | mobile extraction tools |
| DidierStevensSuite | upstream `HEAD` | `pdfid.py`, `pdf-parser.py` |
| FLOSS | 3.1.0 | `run_floss` (amd64 only) |
| Detect-It-Easy | 3.09 | `run_die` (amd64 only) |
| LiteLLM | latest | non-Anthropic models, in its own venv |

Every version pin matches the `Dockerfile`, so a native install and the container run
the same tool versions.

## Tiers

| Flag | Contents |
|------|----------|
| `--minimal` | venv, wrapper, `apt` gaps, workspace. Reuses everything SIFT has. |
| *(default)* | minimal plus Chainsaw (and its `/usr/local/bin` symlink), Hayabusa, Zircolite, Sigma rules, ATT&CK, PECmd, CAPA. |
| `--full` | default plus signature-base, Volatility symbols, ALEAPP/iLEAPP, DidierStevensSuite, FLOSS, Detect-It-Easy, LiteLLM, `libguestfs-tools`, and the `[pdf]` and `[stix]` extras. |

Skipping a tier does not break Mulder. Every tool wrapper checks for its binary and
returns a structured "not found, install with ..." result instead of failing the
investigation. What it does is disable specific MCP tools, and the matrix below says
exactly which.

### Tool Availability by Tier

| MCP tool | `--minimal` | default | `--full` |
|----------|-------------|---------|----------|
| `run_yara` | no rules | no rules | yes |
| `lookup_attack_technique` | no | yes | yes |
| `run_chainsaw`, `run_hayabusa`, `run_zircolite` | no | yes | yes |
| `run_capa` | no | yes | yes |
| `run_floss`, `run_die` | no | no | yes (amd64) |
| ALEAPP / iLEAPP phone tools | no | no | yes |
| PDF tools (`pdfid`, `pdf-parser`) | no | no | yes |
| `run_volatility` | yes, symbols fetched on demand | yes | yes, symbols pre-seeded |
| plaso, Sleuth Kit, hindsight, MVT, RegRipper, EZ Tools | yes (SIFT) | yes | yes |
| Non-Anthropic models via LiteLLM | no | no | yes |

The `run_yara` row is the one that surprises people. The `yara` binary is installed in
every tier, but `tools/yara.py` resolves *every* ruleset level to `/opt/signature-base`,
which is a `--full` component. Without it, every `run_yara` call returns
"No YARA rules available". Use `--full`, or clone signature-base yourself:

```bash
sudo git clone --depth 1 https://github.com/Neo23x0/signature-base.git /opt/signature-base
sudo chown -R "$USER" /opt/signature-base
```

The `chown` matters: Mulder runs `git pull --ff-only` inside that clone on first use,
and a root-owned repository trips git's dubious-ownership guard and fails silently.

## Disk Footprint

Measured inside a bare `ubuntu:24.04` container on arm64, not on a SIFT box. The
`--full` row is the only estimate; everything else is a real `du`. apt packages are
excluded because SIFT already has most of them.

| Path | Size | Tier |
|------|------|------|
| `/opt/mulder` (the venv) | **465 MB** | every tier |
| `/opt/zircolite` | 75 MB | default |
| `/opt/attack` | 56 MB | default |
| `/opt/capa` | 45 MB | default |
| `/opt/sigma-rules` | 25 MB | default |
| `/opt/chainsaw` (binary, rules, mappings) | 9.5 MB | default |
| `/opt/hayabusa` | ~90 MB | default, amd64 only |
| signature-base, symbol packs, LEAPPs, LiteLLM | ~2 GB (estimate) | `--full` |

So the default tier costs roughly **700 MB**, two thirds of it the venv.

The single largest item in the venv is not Mulder and not any forensic library. It is
the native `claude` binary bundled inside the `claude-agent-sdk` wheel:

```
/opt/mulder/venv/lib/python3.12/site-packages/claude_agent_sdk/_bundled/claude
321,771,752 bytes
```

That is 307 MiB, about two thirds of the "minimal" tier, in one file.
`claude-agent-sdk` is a hard dependency in `pyproject.toml`, so the installer cannot
skip it. The orchestrator that uses it *is* imported lazily, so `mulder serve` runs
fine without ever touching that binary; it is needed at install time, not at run time.
Moving `claude-agent-sdk` to an optional extra would shrink the minimal tier by two
thirds and is tracked as a follow-up, since it is a `pyproject.toml` change.

## What Gets Installed Where

```
/opt/mulder/
  venv/                       the Mulder environment
  env.sh                      generated; sourced by the wrapper and by --verify
  uninstall.sh                copy of the repo script
  .mcp.json                   staged copy, used to seed workspaces
  MANIFEST                    every path the installer created
  VERSION                     version, tier, timestamp, target user and home
/usr/local/bin/mulder             bash wrapper
/usr/local/bin/chainsaw           symlink -> /opt/chainsaw/chainsaw
/usr/local/bin/mulder-uninstall   symlink -> /opt/mulder/uninstall.sh
/usr/local/bin/{capa,floss,litellm}
/opt/{chainsaw,hayabusa,zircolite,sigma-rules,attack,signature-base}/
/opt/{aleapp,ileapp,didier-stevens,capa,floss,litellm}/
/opt/zimmermantools/mulder-extra/   additive only; never overwrites SIFT's DLLs
~/.cache/volatility3/symbols/{windows,linux}.zip
/mulder-investigation/              .mcp.json + a git repo, owned by you
```

`/usr/local/bin/mulder` is a wrapper, not a symlink, and that is deliberate. Mulder
shells out to a bare `python3` for ALEAPP, iLEAPP, Zircolite, `pdfid`, `pdf-parser`,
plaso and Volatility. Nothing in the source uses `sys.executable`. The wrapper sources
`/opt/mulder/env.sh`, which puts the venv's `bin/` first on `PATH`, so `python3`
resolves to the interpreter that actually has those dependencies.

`/mulder-investigation` is used verbatim because `mulder investigate` defaults `--cwd`
to it and refuses to start if `.mcp.json` is not there.

## Options

```
install.sh [--minimal|--full] [--prefix DIR] [--user] [--force] [--ref REF]
           [--register-mcp] [--no-vol-symbols] [--no-signature-base]
           [--no-mobile] [--no-litellm] [--verify [--strict]] [--yes] [--help]
```

| Option | Effect |
|--------|--------|
| `--prefix DIR` | install prefix, default `/opt/mulder` |
| `--user` | sudo-free partial install under `~/.local`; see the warning below |
| `--force` | reinstall components that are already present |
| `--ref REF` | git ref to clone when piped to `bash`, default `main` |
| `--register-mcp` | register Mulder with the local Claude Code CLI, user scope |
| `--no-vol-symbols` | skip the Volatility symbol packs; Volatility fetches them on demand |
| `--no-signature-base` | skip the YARA rule clone; `run_yara` will have no rules |
| `--no-mobile` | skip ALEAPP, iLEAPP and `pysqlcipher3` |
| `--no-litellm` | skip the isolated LiteLLM venv |
| `--yes` | never prompt |

**`--user` is a partial install.** Mulder's absolute paths under `/opt` cannot be
relocated, so `--user` gives you the venv, the wrapper and a workspace at
`~/mulder-investigation` and nothing else. Chainsaw, Hayabusa, Zircolite, the Sigma
rules, ATT&CK, signature-base and the mobile tools all report themselves unavailable.
It also means **every** run needs an explicit working directory:

```bash
mulder investigate /evidence my-case --cwd ~/mulder-investigation
```

To register Mulder as an MCP server for a Claude Code CLI that is already on the box —
the Protocol SIFT setup — either pass `--register-mcp` or run it yourself:

```bash
claude mcp add mulder /usr/local/bin/mulder serve --scope user
```

## Verifying an Install

```bash
./install.sh --verify
./install.sh --user --verify     # if you installed with --user
./install.sh --prefix DIR --verify
```

Probes are grouped into three classes and the exit code depends on the first only:

- **REQUIRED** — Mulder's own environment. The wrapper, the venv interpreter, the
  imports that happen at MCP server startup (`volatility3`, `Registry`, `Evtx`), the
  workspace `.mcp.json`, and — when Chainsaw is installed — the
  `/usr/local/bin/chainsaw` symlink. A failure here means Mulder is broken.
- **REUSED** — SIFT-provided tools. Reported, never fatal, because a plain Ubuntu box
  legitimately has none of them. This class also prints the resolved path of each of
  the six EZ Tools DLLs Mulder invokes, so a duplicate or an unexpected nesting is
  visible.
- **OPTIONAL** — the gap tools, whose absence only disables specific MCP tools.

`--verify --strict` also fails on REUSED misses. That is the acceptance check to run
on a real SIFT box; plain `--verify` is what CI runs.

The Chainsaw probe deserves a note. It tests `/usr/local/bin/chainsaw` specifically and
not `command -v chainsaw`, because `tools/chainsaw.py` hardcodes that exact path and
executes it directly, while its *availability* check is `PATH`-aware. Having
`/opt/chainsaw` on `PATH` without the symlink makes Chainsaw look installed while every
invocation fails with a swallowed `ENOENT`.

## Updating

```bash
cd mulder && git pull && sudo ./install.sh
```

The venv step compares the installed `mulder --version` against the checkout's
`pyproject.toml` and reinstalls on a mismatch, so this is a real upgrade and not a
no-op. Large immutable downloads are skipped if already present; pass `--force` to
redo them. Your workspace and case databases are never touched.

## Uninstalling

```bash
sudo mulder-uninstall              # or: sudo ./uninstall.sh
sudo ./uninstall.sh --dry-run      # show what would go
sudo ./uninstall.sh --purge        # also remove case data and the workspace
```

The uninstaller is driven by `/opt/mulder/MANIFEST` and removes only paths recorded
there. It refuses to touch `/opt/volatility3`, `/opt/mvt`, `/opt/pyhindsight` or
`/opt/zimmermantools` itself — only the `mulder-extra/` subdirectory the installer
created inside it. Without `--purge` it keeps `/mulder-investigation`,
`~/.mulder/cases` and the Volatility symbol cache. apt packages are always left
installed.

## Supply Chain

Immutable GitHub release assets are pinned by SHA-256 in a table at the top of
`install.sh`: the Chainsaw tarballs (both architectures), the Hayabusa zip, the CAPA
zips, the FLOSS zip and the Detect-It-Easy `.deb`. A mismatch skips that component with
a warning rather than installing it.

The rest cannot be honestly pinned and is fetched over TLS only:

- the SigmaHQ tag tarball, which is a GitHub auto-generated source archive — GitHub has
  changed its gzip settings before, which changes the digest without the content
  changing;
- the EZ Tools zips, which upstream rebuilds continuously;
- MITRE ATT&CK `master` and the Volatility symbol packs, which are moving targets by
  design;
- git clones, which are pinned by tag where a tag exists (Chainsaw, Zircolite) and
  whose resolved commit is printed during the install.

Python packages are unpinned, exactly as in the `Dockerfile`, which resolves fresh from
PyPI. `uv.lock` is a development lockfile and is not the source of truth for either the
image or this installer.

## Out of Scope

Deliberately not installed, because they are heavy and Mulder degrades cleanly without
them. Install any of them by hand if you need the corresponding tools:

Zeek, Suricata plus the Emerging Threats ruleset, a libewf source build (apt's
`ewf-tools` provides the `ewfmount` Mulder actually calls; Mulder does not import
`pyewf`), a bulk_extractor source build, stegdetect, and radare2 (SIFT already has it).

Two smaller behaviours worth knowing about:

- **`freshclam` does not run on `--minimal`.** Downloading the ClamAV signature database
  costs roughly 300 MB, SIFT already ships a populated one, and `--minimal` exists to stay
  small. The other tiers run it, and only when the database is missing. If `run_clamav`
  reports no signatures on a minimal install, run `sudo freshclam` once.
- **The installer does not write `.bak` copies of the files it generates.** The wrapper,
  `env.sh` and the manifest are installer-owned and are rewritten on every run by design;
  backing them up would litter the prefix on each upgrade without protecting anything a
  user wrote. The one file a user might own, the workspace `.mcp.json`, is only ever
  written when it is absent.

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| `ensurepip is not available` | SIFT installs `python3-virtualenv`, not `python3-venv`. The installer prefers `/usr/bin/virtualenv` for exactly this reason; if you hit it anyway, `sudo apt-get install python3-virtualenv`. |
| `error: externally-managed-environment` | PEP 668. Ubuntu 24.04 marks the system Python externally managed. Never install Mulder into it and never pass `--break-system-packages`; the installer only ever writes to `/opt/mulder/venv`. |
| `yara: command not found` | SIFT ships `python3-yara`, the module, but not the CLI. `sudo apt-get install yara`. A `python3 -c "import yara"` check will wrongly report success. |
| `No YARA rules available` | `/opt/signature-base` is missing, i.e. you used `--minimal`, the default tier, or `--no-signature-base`. Re-run with `--full`. |
| Chainsaw returns "No such file or directory" | `/usr/local/bin/chainsaw` is missing. Re-run the installer, or `sudo ln -sfn /opt/chainsaw/chainsaw /usr/local/bin/chainsaw`. `tools/chainsaw.py` execs that literal path. |
| `dotnet not found on PATH` | EZ Tools operations are disabled. `sudo apt-get install dotnet-sdk-9.0`, then re-run the installer so it can fill in any missing DLLs. |
| EZ Tools work in SIFT but not in Mulder | Check `./install.sh --verify` — it prints the resolved path of each of the six DLLs. Two copies of the same DLL under `/opt/zimmermantools` make the resolution order filesystem-dependent. |
| `psort.py` missing in `--verify` | `tools/plaso.py` needs that literal name on `PATH` and has no module fallback. If your plaso only provides `psort`, symlink it: `sudo ln -s "$(command -v psort)" /usr/local/bin/psort.py`. |
| `mulder: command not found` after `--user` | `~/.local/bin` is not on your `PATH`. Add it in `~/.bashrc`. |
| `MCP configuration not found at .../.mcp.json` | You ran outside `/mulder-investigation`. Pass `--cwd`, or re-run the installer to recreate the workspace. |
| Volatility symbols keep downloading | `--no-vol-symbols` was used, or the packs landed in `/root/.cache`. Check `~/.cache/volatility3/symbols/` for your own user; the installer targets the invoking user, not root. |
| `hayabusa` missing on arm64 | Upstream ships a prebuilt binary for amd64 only, and the container builds it from source with rustup on arm64. The installer will not run a Rust toolchain build unattended; build it yourself into `/opt/hayabusa/hayabusa`. |
| Detect-It-Easy did not install on 24.04 | The `.deb` upstream publishes targets Ubuntu 22.04 and its dependencies may not resolve on noble. `run_die` is the only casualty. |
