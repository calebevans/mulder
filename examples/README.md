# Example Investigation Reports

These are real investigation outputs produced by Mulder running autonomously
against forensic evidence datasets, unmodified from tool output.

## NIST Data Leakage Case on Mulder v1.5.2

The same case, evidence, prompts and tools on the v1.5.2 release image, three
times per model and scored item by item against the
[published NIST answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
(20 ground-truth items). Each directory holds the full report (Markdown and
HTML), the audit log, both execution logs, the scorecard and a README with the
run's settings.

| Model | Provider | Full match | Detection | False positives | Findings | Tool calls | Runtime | Tokens | Report | Scorecard |
|-------|----------|-----------:|----------:|----------------:|---------:|-----------:|--------:|-------:|--------|-----------|
| Claude Opus 4.6, 3 runs: [1](ndlc-v1.5.2/opus-4.6-run1/), [2](ndlc-v1.5.2/opus-4.6-run2/), [3](ndlc-v1.5.2/opus-4.6-run3/) | Anthropic | 45% (45 to 50) | 95% (90 to 95) | 10% (5 to 10) | 23 / 24 / 24 | 596 / 500 / 630 | 68 / 69 / 79 min | 37K / 27K / 56K uncached in, 239K / 189K / 240K out | [1](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/opus-4.6-run1/ndlc.report.html), [2](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/opus-4.6-run2/ndlc.report.html), [3](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/opus-4.6-run3/ndlc.report.html) | [1](ndlc-v1.5.2/opus-4.6-run1/ACCURACY-REPORT.md), [2](ndlc-v1.5.2/opus-4.6-run2/ACCURACY-REPORT.md), [3](ndlc-v1.5.2/opus-4.6-run3/ACCURACY-REPORT.md) |
| Kimi K3, 3 runs: [1](ndlc-v1.5.2/kimi-k3-run1/), [2](ndlc-v1.5.2/kimi-k3-run2/), [3](ndlc-v1.5.2/kimi-k3-run3/) | Bedrock | 35% (35 to 50) | 90% (80 to 95) | 20% (20 to 25) | 12 / 31 / 21 | 827 / 1,271 / 1,063 | 52 / 70 / 60 min | 200K / 180K / 170K out | [1](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/kimi-k3-run1/ndlc.report.html), [2](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/kimi-k3-run2/ndlc.report.html), [3](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/kimi-k3-run3/ndlc.report.html) | [1](ndlc-v1.5.2/kimi-k3-run1/ACCURACY-REPORT.md), [2](ndlc-v1.5.2/kimi-k3-run2/ACCURACY-REPORT.md), [3](ndlc-v1.5.2/kimi-k3-run3/ACCURACY-REPORT.md) |
| GLM-5, 3 runs: [1](ndlc-v1.5.2/glm-5-run1/), [2](ndlc-v1.5.2/glm-5-run2/), [3](ndlc-v1.5.2/glm-5-run3/) | Bedrock | 20% (20 to 25) | 75% (75 to 90) | 20% (10 to 25) | 20 / 22 / 20 | 513 / 454 / 362 | 60 / 63 / 61 min | 9.3M / 9.1M / 8.4M in, 157K / 135K / 143K out | [1](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/glm-5-run1/ndlc.report.html), [2](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/glm-5-run2/ndlc.report.html), [3](https://calebevans.github.io/mulder/examples/ndlc-v1.5.2/glm-5-run3/ndlc.report.html) | [1](ndlc-v1.5.2/glm-5-run1/ACCURACY-REPORT.md), [2](ndlc-v1.5.2/glm-5-run2/ACCURACY-REPORT.md), [3](ndlc-v1.5.2/glm-5-run3/ACCURACY-REPORT.md) |

Each model is listed as the median of three runs with the range in parentheses, and per-run counts in run order. Anthropic token counts exclude prompt-cache reads; the proxy models have no
prompt caching, so their input counts are the full replayed context. LiteLLM
does not report input tokens for Kimi K3.

### Also tried on v1.5.2, not recommended

Run three times each on the same image and scored the same way, but not
published: MiniMax M2.5 (5% full match, 55% detection, 10% false positives),
DeepSeek V3.2 (0% / 60% / 20%) and Qwen3 235B (0% / 35% / 10%). MiniMax stops
after one device and leaves what it saw out of the report; DeepSeek and Qwen
narrate document timestamps as events and read sample-document metadata as
targets.

Tried and dropped: GLM-4.7 (two runs, both collapsed the four images into one
system at the catalog phase; 10% / 40% / 20%), Kimi K2 Thinking (cannot complete
the catalog phase in either thinking mode), Devstral 2 123B (ran the case but a
harness bug, fixed after v1.5.2, blocked its report), Mistral Large 3 (cannot
complete the catalog phase: it emits a tool call with an empty name that
Bedrock then rejects on every replay), Qwen3 Coder 480B (0% / 45% / 15%,
concluded there was no incident), gpt-oss-120b (0% / 20% / 40%, an intrusion
narrative with a host that does not exist in the evidence), Kimi K2.5 (cannot
complete the catalog phase).

## Earlier investigations (Mulder v1.5.1 and before)

Older runs against other datasets, kept for reference. They predate the
optical-media reader, the masquerade detector and the per-image partition
fixes in v1.5.2 and were all run on Claude Opus 4.6.

### Reports

| Case | Systems | Evidence Sources | Tool Calls | Findings | Runtime | Tokens | Model | Report |
|------|---------|-----------------|------------|----------|---------|--------|-------|--------|
| [Rocba](rocba/) | 1 | 67 | 292 | 7 (1 high) | 66 min | 313.1K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/rocba/Rocba.report.html) |
| [SRL-2015](srl-2015/) | 4 | 159 | 610 | 29 (4 critical, 9 high) | 126 min | 299.8K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/srl-2015/SRL-2015.report.html) |
| [SRL-2018](srl-2018/) | 11 | 457 | 1508 | 55 (11 critical, 19 high) | 336 min | 698.4K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html) |
| [NIST Data Leakage](ndlc/) | 4 | 88 | 723 | 33 (15 high) | 102 min | 330.3K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/ndlc/ndlc.report.html) |

## Case Descriptions

### Rocba

- **Scenario:** Sustained RDP brute-force campaign targeting a Windows 10 corporate workstation (SRL-FORGE) at Stark Research Labs over a seventeen-day period from multiple external IPs across five countries
- **Key findings:** No successful breach achieved despite coordinated attacks from 4 IPs in two distinct waves; attacker enumerated default/disabled accounts but never guessed valid credentials for active accounts
- **Files:** [Rocba.report.md](rocba/Rocba.report.md), [Rocba.report.html](https://calebevans.github.io/mulder/examples/rocba/Rocba.report.html)

### SRL-2015

- **Scenario:** Advanced persistent threat intrusion at Stark Research Labs across four Windows systems on 10.3.58.0/24 (domain controller, two Windows 7 workstations, one Windows XP endpoint)
- **Key findings:** Snake/Uroburos APT malware on nromanoff workstation; five web shell families deployed on internet-facing domain controller; vibranium domain account used for cross-system credential abuse and classified data access; C2 toolkit (spinlock.exe, pe.exe) with timestomped binaries on XP system; 25-hour continuous C2 session
- **Files:** [SRL-2015.report.md](srl-2015/SRL-2015.report.md), [SRL-2015.report.html](https://calebevans.github.io/mulder/examples/srl-2015/SRL-2015.report.html), `SRL-2015.audit.jsonl`, `orchestrator.log`, `mulder.log`

### SRL-2018

- **Scenario:** Network intrusion and industrial espionage targeting Stark Research Labs' rare-earth element research, spanning 11 systems across internal network and DMZ over a thirteen-month campaign
- **Key findings:** PowerView/PowerSploit recon from DC; WMI→PowerShell→Rundll32 attack chain across 8+ systems; msadvapi2 backdoor on multiple systems; complete 10-day attack timeline with 6+ compromised systems; environment-wide C2 proxy tunneling via 172.16.4.10:8080; dual intrusion campaigns (msadvapi2 persistent backdoor pre-August, Metasploit PowerShell operations August-September)
- **Files:** [SRL-2018.report.md](srl-2018/SRL-2018.report.md), [SRL-2018.report.html](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html), `SRL-2018.audit.jsonl`, `orchestrator.log`, `mulder.log`

### NIST Data Leakage Case (with Accuracy Report)

- **Scenario:** Insider threat data leakage at a technology company. Employee researched exfiltration methods, copied proprietary research documents to USB media with deliberate file masquerading, deployed cloud sync for secondary exfiltration, burned a final copy to CD-ROM, then deployed anti-forensics tools (Eraser for secure deletion, CCleaner installed but not effectively used per answer key)
- **Key findings:** Five "Secret Project" documents exfiltrated to USB in a 42-second copy window (22 total documents across all media per answer key); documents renamed with false extensions (.gif, .amr, .png, .zip) on FAT32 partition; Google Drive and iCloud deployed as secondary exfiltration channels; premeditated anti-forensics campaign with extensive search history; Eraser used for secure file wiping; complete timeline reconstructed from Oct 2014 through Mar 2015
- **Accuracy:** Has a detailed [accuracy report](ndlc/ACCURACY-REPORT.md) comparing findings against published ground truth (60% full match, 90% detection rate, 5% false positive rate)
- **Validation:** Scored against the [NIST CFReDS Data Leakage Case answer key](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf) (55-page official ground truth)
- **Files:** [ndlc.report.md](ndlc/ndlc.report.md), [ndlc.report.html](https://calebevans.github.io/mulder/examples/ndlc/ndlc.report.html), `ndlc.audit.jsonl`, `orchestrator.log`, `mulder.log`, [README.md](ndlc/README.md)

## File Structure

Each example directory contains:

- `*.report.md` — Markdown investigation report
- `*.report.html` — HTML report with interactive navigation ([live on GitHub Pages](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html); repo copies are under each case directory)
- `*.audit.jsonl` — Structured tool execution audit log
- `orchestrator.log` — Agent phase transitions and decisions
- `mulder.log` — MCP server tool execution log
