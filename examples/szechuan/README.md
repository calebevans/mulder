# Szechuan: DFIR Madness Case 001

Mulder's autonomous investigation of [DFIR Madness Case 001: "The Stolen Szechuan Sauce"](https://dfirmadness.com/the-stolen-szechuan-sauce/), an APT compromise of a small Active Directory domain with lateral movement, credential attacks, malware deployment, and data exfiltration.

> **Difficulty: "I'm Too Young to Die"** — disk images, memory dumps, and network capture all available.

## Scenario

An attacker compromises the C137.LOCAL domain through brute-force RDP access to the domain controller, deploys Meterpreter-based malware to both systems, moves laterally via RDP, harvests credentials, and stages data for exfiltration — all within a few hours.

## Key Findings

- **Initial access:** NTLM brute force from workstation "kali" succeeded against Administrator at 03:22 UTC, with 194.61.24.102 confirmed as both malware staging server and authentication source (Event 4648)
- **Malware:** coreupdater.exe (7,168 bytes) deployed to `C:\Windows\System32` on both DC01 and DESKTOP-SDN1RPT; Windows Defender blocked it on the workstation but not the DC
- **C2:** ESTABLISHED connection from coreupdater.exe (PID 3644) to 203.78.103.109:443
- **Lateral movement:** Credential-based movement from workstation to DC using three domain accounts (Administrator, ricksanchez, mortysmith) within 18 minutes
- **Process injection:** Meterpreter reflective DLL injection (metsrv.x64.dll + ReflectiveLoader) in spoolsv.exe on both systems, with bind handler on TCP 62475 on DC
- **Credential theft:** NTLM hash dump output (RID 500:aad3b435...) at 6 memory offsets on workstation; Skeleton Key patcher YARA match downgraded after counter-analysis (brute-force would be unnecessary if Skeleton Key was active)
- **Correct dismissals:** CoinMiner/Webshell YARA in MemCompression (Windows Defender definitions), Tofu backdoor (insufficient for attribution)

## Investigation Stats

| Metric | Value |
|--------|-------|
| Systems analyzed | 2 (DC01, DESKTOP-SDN1RPT) |
| Evidence files | 11 archives (12.9 GB compressed) |
| Evidence sources indexed | 89 (19 memory, 23 disk, 47 other) |
| Extractor types used | 14 |
| Total tool calls | 430 |
| Findings | 17 (4 critical, 9 high, 2 medium, 0 low, 2 info) |
| Confirmed / Inference | 12 / 5 |
| False positives | 0 |
| MITRE ATT&CK techniques | 24 across 8 tactics |
| Runtime | 53 min |
| Model | claude-opus-4-6 |
| Total tokens | 199.4K |

## Phase Breakdown

| Phase | Description |
|-------|-------------|
| Catalog | Scanned evidence, extracted 11 archives, identified 2 Windows systems |
| Extraction | Parallel extraction across both hosts (Volatility 17 plugins, YARA raw + per-process VAD, TSK, bulk_extractor, EVTX, registry, MFT, ShimCache, Amcache, Prefetch, pagefile strings) |
| Cross-System | Correlation tasks, persistence/exfil/defense-evasion composites, deduplication |
| Counter-Analysis | Challenge tasks testing each finding against alternatives; downgraded Skeleton Key, dismissed CoinMiner/Webshell YARA |
| Report | Narrative generation, HTML/Markdown output |

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
| `szechuan.audit.jsonl` | Structured tool execution audit log (453 entries, BLAKE2b hashed) |
| `orchestrator.log` | Agent phase transitions and reasoning (1,203 lines) |
| `mulder.log` | MCP server tool execution log (1,003 lines) |
| `ACCURACY-REPORT.md` | Ground truth comparison against published answer key |
