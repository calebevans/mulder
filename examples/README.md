# Example Investigation Reports

These are real investigation outputs produced by Mulder running autonomously
against forensic evidence datasets.

**Interactive HTML reports** (sidebar navigation, themes, audit trail) are published on GitHub Pages:

| Report | URL |
|--------|-----|
| Rocba | [Rocba.report.html](https://calebevans.github.io/mulder/examples/rocba/Rocba.report.html) |
| SRL-2015 | [SRL-2015.report.html](https://calebevans.github.io/mulder/examples/srl-2015/SRL-2015.report.html) |
| SRL-2018 | [SRL-2018.report.html](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html) |
| Szechuan | [szechuan.report.html](https://calebevans.github.io/mulder/examples/szechuan/szechuan.report.html) |

## Investigations

| Case | Systems | Evidence Sources | Tool Calls | Findings | Runtime | Tokens | Model | Report |
|------|---------|-----------------|------------|----------|---------|--------|-------|--------|
| [Rocba](rocba/) | 1 | 85 | 396 | 15 (2 high) | 72 min | 104.0K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/rocba/Rocba.report.html) |
| [SRL-2015](srl-2015/) | 4 | 154 | 614 | 28 (21 high) | 108 min | 216.3K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/srl-2015/SRL-2015.report.html) |
| [SRL-2018](srl-2018/) | 9 | 365 | 1060 | 50 (4 critical, 9 high) | 234 min | 300.7K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html) |
| [Szechuan](szechuan/) | 2 | 115 | 412 | 18 (3 critical, 6 high) | 55 min | 134.4K | opus-4-6 | [HTML](https://calebevans.github.io/mulder/examples/szechuan/szechuan.report.html) |

## Case Descriptions

### Rocba

- **Scenario:** Sustained RDP brute-force campaign targeting a Windows 10 corporate workstation (SRL-FORGE) at Stark Research Labs over a two-week period from multiple external IPs
- **Key findings:** No successful breach achieved despite thousands of authentication attempts; attacker enumerated valid usernames and rotated source IPs but NLA prevented authenticated access
- **Files:** [Rocba.report.md](rocba/Rocba.report.md), [Rocba.report.html](https://calebevans.github.io/mulder/examples/rocba/Rocba.report.html)

### SRL-2015

- **Scenario:** Multi-system intrusion of the SHIELDBASE.LOCAL Active Directory domain targeting four Windows systems, including a domain controller, two workstations, and an XP endpoint
- **Key findings:** Zeus/Zbot rootkit active on XP system with extensive API hooks; Meterpreter detected in memory on workstation; PsExec lateral movement with Group Policy weaponization; classified data accessed via domain admin credentials
- **Files:** [SRL-2015.report.md](srl-2015/SRL-2015.report.md), [SRL-2015.report.html](https://calebevans.github.io/mulder/examples/srl-2015/SRL-2015.report.html), `SRL-2015.audit.jsonl`, `orchestrator.log`, `mulder.log`

### SRL-2018

- **Scenario:** Network intrusion and industrial espionage targeting Stark Research Labs' rare-earth element research, spanning 9 systems across internal network and DMZ
- **Key findings:** WMI-to-PowerShell attack chain propagated across 4+ systems; custom malware implant (p.exe) with massive RWX memory allocation; R&D intellectual property staged for exfiltration via coordinated perfmon directories; concurrent DMZ FTP compromise from external actors
- **Files:** [SRL-2018.report.md](srl-2018/SRL-2018.report.md), [SRL-2018.report.html](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html), `SRL-2018.audit.jsonl`, `orchestrator.log`, `mulder.log`

### Szechuan (with Accuracy Report)

- **Scenario:** APT compromise of the C137.LOCAL domain with NTLM brute-force initial access from Kali Linux, Meterpreter deployment, and lateral movement between domain controller and workstation
- **Key findings:** Successful brute-force against DC01 Administrator; coreupdater.exe (Meterpreter) deployed to both systems with C2 to 203.78.103.109:443; process injection in Print Spooler service; DCSync credential theft detected in network traffic
- **Accuracy:** Has a detailed [accuracy report](szechuan/ACCURACY-REPORT.md) comparing findings against published ground truth (57% full match, 79% detection rate, 0% false positives)
- **Validation:** Used as the validation case for hackathon submission against [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/)
- **Files:** [szechuan.report.md](szechuan/szechuan.report.md), [szechuan.report.html](https://calebevans.github.io/mulder/examples/szechuan/szechuan.report.html), `szechuan.audit.jsonl`, `orchestrator.log`, `mulder.log`, [README.md](szechuan/README.md)

## File Structure

Each example directory contains:

- `*.report.md` — Markdown investigation report
- `*.report.html` — HTML report with interactive navigation ([live on GitHub Pages](https://calebevans.github.io/mulder/examples/srl-2018/SRL-2018.report.html); repo copies are under each case directory)
- `*.audit.jsonl` — Structured tool execution audit log
- `orchestrator.log` — Agent phase transitions and decisions
- `mulder.log` — MCP server tool execution log
