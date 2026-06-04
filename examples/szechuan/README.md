# Szechuan: DFIR Madness Case 001

Mulder's autonomous investigation of [DFIR Madness Case 001: "The Stolen Szechuan Sauce"](https://dfirmadness.com/the-stolen-szechuan-sauce/), an APT compromise of a small Active Directory domain with lateral movement, credential attacks, malware deployment, and data exfiltration.

> **Difficulty: "I'm Too Young to Die"** — disk images, memory dumps, and network capture all available.

## Scenario

An attacker compromises the C137.LOCAL domain through brute-force RDP access to the domain controller, deploys Meterpreter-based malware to both systems, moves laterally via RDP, harvests credentials, and stages data for exfiltration — all within a few hours.

## Key Findings

- **Initial access:** NTLM brute force from workstation "kali" succeeded against Administrator at 03:21 UTC, followed by RDP brute force from 194.61.24.102 with 75+ attempts
- **Malware:** coreupdater.exe deployed to `C:\Windows\System32` on both DC01 and DESKTOP-SDN1RPT, masquerading as a system binary
- **C2:** ESTABLISHED connection from coreupdater.exe (PID 3644) to 203.78.103.109:443
- **Lateral movement:** DC01 → DESKTOP-SDN1RPT via RDP at 03:49 UTC, confirmed by Zeek logs showing anomalous DC-to-workstation direction with empty cookie (programmatic initiation)
- **Process injection:** Meterpreter reflective DLL injection in spoolsv.exe on both systems, with x64 shellcode stubs and ReflectiveLoader confirmed by YARA + Volatility malfind independently
- **Credential theft:** Kerberos escalation chain (machine → mortysmith → Administrator → ricksanchez), Skeleton Key patcher tools, NTLM hash dump output on workstation
- **Correct dismissals:** DCSync (DRSGetNCChanges searched, zero results — only normal DRSCrackNames observed), TA17-293A YARA match (over-matching on "file://" strings)

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 2 (DC01, DESKTOP-SDN1RPT) + PCAP |
| Evidence files | 11 archives (12.9 GB compressed) |
| Evidence sources indexed | 115 (18 memory, 23 disk, 74 other) |
| Extractor types used | 18 |
| Total tool calls | 412 |
| Findings | 18 (3 critical, 6 high, 2 medium, 2 low, 5 info) |
| Confirmed / Inference | 12 / 6 |
| False positives | 0 |
| MITRE ATT&CK techniques | 21 across 10 tactics |
| Runtime | 55 min 24 sec |
| Model | claude-opus-4-6 |
| Total tokens | 134.4K (19.3K input, 115.1K output) |

## Phase Breakdown

| Phase | Duration | Description |
|-------|----------|-------------|
| Catalog | 3 min | Scanned evidence, extracted 11 archives, identified 2 Windows systems + 1 PCAP |
| Extraction | 26 min | Parallel extraction across both hosts (Volatility 14 plugins, YARA, TSK, bulk_extractor, EVTX, registry, MFT, strings) and PCAP (Zeek, tshark, Suricata, tcpflow, tcpxtract) |
| Cross-System | 11 min | 15 parallel correlation tasks, persistence/exfil/defense-evasion composites, deduplication (26 → 18 findings) |
| Counter-Analysis | 10.5 min | 28 challenge tasks testing each finding against alternatives; downgraded 2, adjusted 1, annotated 4 |
| Report | 4 min | Narrative generation, HTML/Markdown output |

## Evidence Dataset

| Field | Value |
|-------|-------|
| **Source** | [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/) |
| **Answer Key** | [Published answers](https://dfirmadness.com/answers-to-szechuan-case-001/) |
| **Accuracy Report** | [ACCURACY-REPORT.md](ACCURACY-REPORT.md) |

### Evidence Files

| File | Type | Size |
|------|------|------|
| DC01-E01.zip | Disk image (E01) | 4.5 GB |
| DC01-memory.zip | Memory dump | 535.4 MB |
| DC01-pagefile.zip | Pagefile | 12.9 MB |
| DC01-ProtectedFiles.zip | Registry hives + DPAPI | 11.7 MB |
| DC01-autorunsc.zip | Sysinternals Autoruns | 173.1 KB |
| DESKTOP-E01.zip | Disk image (E01) | 6.4 GB |
| DESKTOP-SDN1RPT-memory.zip | Memory dump | 765.6 MB |
| Desktop-SDN1RPT-pagefile.zip | Pagefile | 211.8 MB |
| DESKTOP-SDN1RPT-Protected Files.zip | Registry hives + DPAPI | 16.3 MB |
| DESKTOP-SDN1RPT-autorunsc.zip | Sysinternals Autoruns | 272.1 KB |
| case001-pcap.zip | Network capture | 144.6 MB |

## Files in This Directory

| File | Description |
|------|-------------|
| `szechuan.report.md` | Full investigation report (Markdown) |
| `szechuan.report.html` | Investigation report (HTML with navigation) |
| `szechuan.audit.jsonl` | Structured tool execution audit log (442 entries, BLAKE2b hashed) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,262 lines) |
| `mulder.log` | MCP server tool execution log (840 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against published answer key |
