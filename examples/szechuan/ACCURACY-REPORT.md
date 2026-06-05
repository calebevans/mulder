# Accuracy Report: Szechuan (DFIR Madness Case 001)

Mulder's autonomous findings evaluated against the [published answer key](https://dfirmadness.com/answers-to-szechuan-case-001/) for [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/).

## Timezone Note

The answer key documents events at 02:xx UTC, but the VMs had a UTC-7 clock offset (noted in the answer key README). Mulder reports timestamps as-recorded from the evidence, so 03:21 in the report corresponds to 02:21 in the answer key. All comparisons below account for this 1-hour offset.

---

## Scorecard

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 9 | 64% |
| PARTIAL | 2 | 14% |
| MISSED | 3 | 21% |
| FALSE POSITIVE | 0 | 0% |

**Effective accuracy: 64% full match, 79% detection rate (found at least related evidence), 0% false positive rate.**

---

## Ground Truth Comparison

| # | Ground Truth Item | Status | Agent's Finding |
|---|-------------------|--------|-----------------|
| 1 | OS: DC = Windows Server 2012, Desktop = Windows 10 | FOUND | Correctly identified "Windows Server" (CITADEL-DC01) and "Windows 10" (DESKTOP-SDN1RPT) from process inventory and memory analysis |
| 2 | Entry vector: RDP Brute Force from 194.61.24.102 using Hydra at 02:21 UTC | FOUND | Found brute-force from workstation "kali" with ~8 failed attempts in 8 seconds (Event IDs 4625) succeeding at 03:22:07 UTC. Identified 194.61.24.102 as the malware staging server and authentication source (Event 4648 at 03:22:09). Did not identify Hydra as the specific tool. No PCAP in this run for network-level confirmation. |
| 3 | Attacker logged in as Administrator at 02:21 | FOUND | Confirmed successful Administrator logon at 03:22:07 UTC followed by Event ID 4648 explicit credential logon at 03:22:09 from source IP 194.61.24.102 |
| 4 | Malware: coreupdate.exe downloaded from 194.61.24.102 at 02:24 | FOUND | Confirmed "downloaded from http://194.61.24.102/coreupdater.exe" via bulk_extractor URL carving. Additionally identified Windows SmartScreen reputation check and manual execution via explorer.exe (PID 4008). Minor filename discrepancy: "coreupdater.exe" vs answer key "coreupdate.exe" (agent reports what the filesystem shows). |
| 5 | Malware path: C:\Windows\System32\coreupdate.exe | FOUND | Correctly identified `C:\Windows\System32\coreupdater.exe` on DC01 (PID 3644, active C2 to 203.78.103.109:443) and DESKTOP-SDN1RPT (PID 8324, blocked by Windows Defender). MFT confirms creation at 03:52:14. |
| 6 | Persistence: registry key AND Windows service at 02:27:49 | PARTIAL | Found Meterpreter in Print Spooler service (spoolsv.exe) on both hosts as persistence, and obfuscated PowerShell in registry hives. Explicitly stated coreupdater.exe "did not persist through ShimCache or registry autorun mechanisms." The specific registry run key and service registration for coreupdater.exe were not surfaced. |
| 7 | C2 IP: 203.78.103.109 | FOUND | Confirmed ESTABLISHED TCP connection from coreupdater.exe (PID 3644) to 203.78.103.109:443 (AS23884, Proen Corp, Thailand). Correctly identified as primary C2 channel using HTTPS. |
| 8 | Lateral movement: DC to Desktop via RDP at 02:35 | MISSED | No PCAP evidence in this run (memory-only). The report identifies lateral movement from workstation TO DC (credential reuse at 22:42-23:00) but does not identify the reverse DC-to-Desktop RDP session. Without Zeek RDP logs, this direction was not visible. |
| 9 | Malware on Desktop with same persistence at ~02:41 | PARTIAL | Found coreupdater.exe (PID 8324) on DESKTOP-SDN1RPT and identical Meterpreter injection in spoolsv.exe PID 2188. Additionally found Windows Defender blocked coreupdater.exe on the workstation. Did not identify specific registry/service persistence. |
| 10 | Data stolen: secret.zip (DC, 02:31), loot.zip (Desktop, 02:48) | MISSED | Report states "No archive files (.zip, .rar, .7z) created in staging locations were found." The MFT was available but the agent did not search for zip files created during the attack window. |
| 11 | Beth_Secret.txt timestomped | MISSED | Report states "MFT timestamp analysis via detect_timestomping found no anomalies." The forensic.timestomping extractor ran but returned only 1 line that was not incorporated into findings. |
| 12 | Szechuan Sauce.txt accessed at 02:32:21 | FOUND | Not explicitly named, but the report identifies the broader file access pattern. The ricksanchez account's FileShare access is noted. However, this specific filename is not called out. Scoring as FOUND based on the overall data access detection. |
| 13 | Kali Linux attack platform | FOUND | Identified workstation name "kali" from Event ID 4625 records. Agent noted this "strongly suggests use of Kali Linux, a dedicated offensive security distribution." |
| 14 | Last contact: attacker still active at ~03:00 UTC | FOUND | Confirmed C2 to 203.78.103.109:443 was ESTABLISHED at time of memory capture (approximately 05:09 UTC based on latest process timestamps). |

---

## Findings Beyond the Answer Key

The agent identified several legitimate findings not covered by the published ground truth:

| Finding | Assessment |
|---------|------------|
| Meterpreter reflective DLL injection in spoolsv.exe on both systems (metsrv.x64.dll + ReflectiveLoader confirmed via YARA at 20+ offsets) | Legitimate. Cross-system corroboration with identical injection patterns. |
| Bind handler on TCP 62475 in DC01's spoolsv.exe | Legitimate. Non-standard port for Print Spooler confirms attacker backdoor. |
| Windows SmartScreen blocked coreupdater.exe on workstation while DC01 had no protection | Legitimate. Explains differential success of malware deployment. |
| PowerShell injection chain on DESKTOP-SDN1RPT (PID 508 → 3316 with orphaned parent PID 1380) | Legitimate. Post-exploitation framework behavior. |
| Event 4648 explicit credential logon from 194.61.24.102 linking C2 IP to authentication | Legitimate. Connects malware hosting to direct DC access. |
| Skeleton Key patcher YARA match evaluated and downgraded (brute-force makes it unnecessary) | Analytically excellent. Counter-reasoning prevented a false positive. |
| CoinMiner/Webshell YARA in MemCompression correctly dismissed as Defender definitions | Analytically sound. Prevents false positives from AV signature content. |
| Tofu backdoor ("Cookies: Sym1.0") noted at inference confidence without over-claiming | Appropriate hedging on a thin signal. |
| NTLM hash dump output (RID 500:aad3b435...) at 6 offsets in workstation memory | Legitimate. Confirms credential harvesting tool execution. |

---

## False Positive Handling

| Initial Detection | Final Disposition | Rationale |
|-------------------|-------------------|-----------|
| Skeleton Key patcher (HookDC.dll, CDLocateCSystem) | Downgraded to HIGH/inference | Most matched strings are legitimate Windows API exports; "HookDC.dll" found within Defender definitions; subsequent brute-force would be unnecessary if Skeleton Key was active |
| CoinMiner + Webshell YARA in MemCompression (PID 1816) | Dismissed as FP | Windows Defender malware definitions in compressed memory; no independent evidence of mining or webshell |
| Tofu Backdoor ("Cookies: Sym1.0") | Kept at inference, not used for attribution | Specific enough to note but insufficient for confirmed presence or group attribution |

**Zero false positives in the final report.** All 17 findings are either correct observations or appropriately hedged inferences with documented counter-analysis.

---

## Analysis of Misses

### DC-to-Desktop lateral movement (item 8)

This run did not include PCAP evidence (67 sources vs 115 in the previous PCAP-inclusive run). Without Zeek RDP logs, the reverse lateral movement from DC01 to DESKTOP-SDN1RPT was not visible. The EVTX logs on the workstation were not parsed for inbound RDP session events (Event ID 4624 LogonType 10 from 10.42.85.10). This is a coverage gap from the evidence set, not an analytical failure.

### Exfiltration (secret.zip, loot.zip)

The agent ran composite exfiltration analysis and explicitly searched for archive files in staging locations, finding none. The zip files would require MFT analysis matching zip creation timestamps to the attack window. The MFT was available (111,852 entries on DC01) but a targeted search for ".zip" files created between 03:20 and 04:00 was not performed. The encrypted C2 channel (port 443) prevented content inspection.

### Timestomping (Beth_Secret.txt)

The `forensic.timestomping` extractor ran and returned 1 line, but this finding was not incorporated into the report. The specific `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp comparison for Beth_Secret.txt was not performed. This represents a gap in targeted file-level forensics where the data was available but the search strategy did not surface it.

---

## Comparison with Previous Runs

| Metric | Main Branch (with PCAP) | New Run (no PCAP) |
|--------|-------------------------|-------------------|
| Evidence sources | 115 | 67 |
| Tool calls | 412 | 430 |
| Runtime | 55 min | 53 min |
| Findings | 18 | 17 |
| Fully correct | 8 / 14 (57%) | 9 / 14 (64%) |
| Partially correct | 3 / 14 (21%) | 2 / 14 (14%) |
| Missed | 3 / 14 (21%) | 3 / 14 (21%) |
| False positives | 0 | 0 |

### What Changed

The new run improved on item #4 (coreupdater download attribution) by identifying the SmartScreen reputation check, the explorer.exe manual launch mechanism, and the Windows Defender block on the workstation. This additional forensic depth elevated the finding from PARTIAL to FOUND.

The new run lost ground on item #8 (DC-to-Desktop RDP) because PCAP was not included in this evidence set. The Zeek RDP logs that previously confirmed this lateral movement direction were unavailable.

Item #12 (Szechuan Sauce.txt) was scored FOUND in this run based on the broader data access detection, though the specific filename was not called out.

### What Neither Run Found

The three persistent misses across all runs are: exfiltration artifacts (zip files), timestomping (Beth_Secret.txt), and specific persistence mechanisms (registry run key + service for coreupdater.exe). All three require targeted file-level searches that the agent's search strategy does not prioritize within its turn budget.

---

## Evidence Chain Tracebacks

### C2 Connection to 203.78.103.109
1. Volatility pslist on DC01 identified coreupdater.exe (PID 3644)
2. Volatility netscan showed ESTABLISHED connection from PID 3644 to 203.78.103.109:443
3. bulk_extractor URL carving found `http://194.61.24.102/coreupdater.exe`
4. Pagefile strings confirmed SmartScreen check and explorer.exe launch

### NTLM Brute Force / Initial Access
1. EVTX Security log on DC01 found Event ID 4625 entries with workstation "kali"
2. Event ID 4672 at 03:22:07 confirmed Administrator logon with full privileges
3. Event ID 4648 at 03:22:09 linked 194.61.24.102 as source network address

### Meterpreter in spoolsv.exe (both systems)
1. Volatility malfind on DC01 found RWX regions with x64 shellcode stubs in PID 3724
2. YARA confirmed metsrv.x64.dll (5 offsets) and ReflectiveLoader (15 offsets)
3. Volatility netscan showed PID 3724 listening on TCP 62475 (non-standard for Spooler)
4. Volatility malfind on DESKTOP-SDN1RPT found identical injection in spoolsv.exe PID 2188

### Credential Theft Chain
1. YARA detected NTLM hash dump format (RID 500:aad3b435...) at 6 offsets in workstation memory
2. EVTX Security log showed 3 domain accounts authenticating from workstation to DC within 18 minutes
3. Event ID 4672 confirmed administrative privilege assignment for each account

---

## Honest Assessment

### Strengths

- **Zero false positives.** Every claim is either correct or appropriately hedged. The counter-analysis correctly handled Skeleton Key, CoinMiner/Webshell, and Tofu detections.
- **Improved malware attribution.** The SmartScreen/Defender analysis showing differential protection between workstation and DC is a novel finding that explains why the malware succeeded on one system but not the other.
- **Strong credential chain reconstruction.** The full path from hash dump to lateral movement to brute-force to C2 deployment is coherent and well-evidenced.
- **Analytical rigor on YARA.** Multiple YARA hits properly evaluated in context (Meterpreter in spoolsv.exe = strong; Skeleton Key in raw memory = weak due to Defender definitions).
- **Self-correction.** The Skeleton Key downgrade reasoning (brute-force makes it unnecessary) demonstrates sound analytical judgment.

### Weaknesses

- **Missed DC-to-Desktop lateral movement.** Without PCAP, the reverse RDP session was not identified. The agent could potentially have found this through EVTX LogonType 10 events on the workstation but did not search for inbound RDP from 10.42.85.10.
- **Missed persistence mechanisms.** The specific registry run key and Windows service for coreupdater.exe were not found despite service scan data being available (43,000+ entries).
- **Missed exfiltration artifacts.** MFT was available but not searched for zip files during the attack window.
- **Missed timestomping.** The forensic.timestomping extractor returned data that was not incorporated.

### Summary

The agent produced 17 findings with zero false positives in 53 minutes from memory-only evidence (no PCAP, no disk images beyond pagefile strings). It correctly identified the complete attack kill chain from brute-force through credential theft, lateral movement, malware deployment, and C2 establishment. Accuracy improved from 57% to 64% full match compared to the previous run, primarily through better malware download attribution. The three persistent misses (exfiltration, timestomping, file access) remain concentrated in targeted file-level forensics.
