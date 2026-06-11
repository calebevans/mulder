# Example Investigation Reports

These are real investigation outputs produced by Mulder running autonomously
against forensic evidence datasets.

**Interactive HTML reports** (sidebar navigation, themes, audit trail) are published on GitHub Pages:

| Report | URL |
|--------|-----|
| Rocba | [Rocba.report.html](https://calebevans.github.io/mulder/examples/rocba/Rocba.report.html) |
| SRL-2015 | [SRL-2015.report.html](https://calebevans.github.io/mulder/examples/srl-2015/SRL-2015.report.html) |
| SRL-2018 | [SRL-2018.report.html](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html) |
| NIST Data Leakage | [ndlc.report.html](https://calebevans.github.io/mulder/examples/ndlc/ndlc.report.html) |

## Investigations

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
