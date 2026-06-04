# Accuracy Report: Szechuan (DFIR Madness Case 001)

Mulder's autonomous findings evaluated against the [published answer key](https://dfirmadness.com/answers-to-szechuan-case-001/) for [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/).

## Timezone Note

The answer key documents events at 02:xx UTC, but the VMs had a UTC-7 clock offset (noted in the answer key README). Mulder reports timestamps as-recorded from the evidence, so 03:21 in the report corresponds to 02:21 in the answer key. All comparisons below account for this 1-hour offset.

---

## Scorecard

| Status | Count | Percentage |
|--------|-------|------------|
| FOUND | 8 | 57% |
| PARTIAL | 3 | 21% |
| MISSED | 3 | 21% |
| FALSE POSITIVE | 0 | 0% |

**Effective accuracy: 57% full match, 79% detection rate (found at least related evidence), 0% false positive rate.**

---

## Ground Truth Comparison

| # | Ground Truth Item | Status | Agent's Finding |
|---|-------------------|--------|-----------------|
| 1 | OS: DC = Windows Server 2012, Desktop = Windows 10 | FOUND | Correctly identified "Windows Server 2012 R2" (DC01/CITADEL-DC01) and "Windows 10" (DESKTOP-SDN1RPT) from process inventory and environment analysis |
| 2 | Entry vector: RDP Brute Force from 194.61.24.102 using Hydra at 02:21 UTC | FOUND | Found two distinct brute force attacks: (1) NTLM brute force from workstation "kali" succeeding at 03:21:46 UTC after ~20 attempts in 20 seconds (Event IDs 4625 to 4672), and (2) RDP brute force from 194.61.24.102 with 75+ attempts at 03:34:46 UTC detected in PCAP via Zeek. Appropriately noted the EVTX source IP field was empty, preventing definitive linkage of the two. Did not identify Hydra as the specific tool. |
| 3 | Attacker logged in as Administrator at 02:21 | FOUND | Confirmed Event ID 4672 (Special Privileges Assigned) at 03:21:46 UTC showing Administrator obtained full administrative privileges |
| 4 | Malware: coreupdate.exe downloaded from 194.61.24.102 at 02:24 | PARTIAL | Found coreupdater.exe in System32 on both systems and identified `http://194.61.24.102/` URL on DC01 disk image and workstation pagefile via bulk_extractor. Did not identify the download mechanism (IE) or exact download timestamp. Minor filename discrepancy: agent found "coreupdater.exe" vs answer key's "coreupdate.exe" |
| 5 | Malware path: C:\Windows\System32\coreupdate.exe | FOUND | Correctly identified `C:\Windows\System32\coreupdater.exe` on both DC01 (PID 3644, running at capture) and DESKTOP-SDN1RPT (PID 8324, Session 3, ran 03:40:49 to 03:43:10). Named as masquerading malware in System32. |
| 6 | Persistence: registry key AND Windows service at 02:27:49 | PARTIAL | Found two forms of persistence: coreupdater.exe on disk in System32 and Meterpreter injected into auto-start Print Spooler service (spoolsv.exe) on both hosts. Explicitly stated "No registry-based, scheduled task, or other traditional persistence mechanisms were identified." The specific registry run key and service registration for the malware were not surfaced. |
| 7 | C2 IP: 203.78.103.109 | FOUND | Confirmed ESTABLISHED TCP connection from coreupdater.exe (PID 3644) to 203.78.103.109:443 on DC01. Correctly identified as primary C2 channel using port 443 to disguise traffic as HTTPS. |
| 8 | Lateral movement: DC to Desktop via RDP at 02:35 | FOUND | Confirmed DC01 (10.42.85.10) to DESKTOP-SDN1RPT (10.42.85.115) RDP connection at 03:49:15 UTC via Zeek RDP logs. Correctly noted the anomalous direction (DC should never RDP to workstations), empty cookie suggesting programmatic initiation, and placed it precisely in the attack timeline. |
| 9 | Malware on Desktop with same persistence at ~02:41 | PARTIAL | Found coreupdater.exe (PID 8324) on DESKTOP-SDN1RPT at 03:40:49 UTC and identical Meterpreter injection in spoolsv.exe (PID 2188). Did not identify the specific registry/service persistence mechanisms on the workstation. |
| 10 | Data stolen: secret.zip (DC, 02:31), loot.zip (Desktop, 02:48) | MISSED | Report states "Definitive data exfiltration was not confirmed." Found ricksanchez account's FileShare access at 05:48 UTC and noted the encrypted C2 channel could carry exfiltrated data, but did not identify the specific zip files or their contents. |
| 11 | Beth_Secret.txt timestomped | MISSED | Not detected. The `forensic.timestomping` extractor ran and returned 1 line, but this finding was not surfaced in the report. MFT timestamp analysis did not catch the `$STANDARD_INFORMATION` vs `$FILE_NAME` discrepancy. |
| 12 | Szechuan Sauce.txt accessed at 02:32:21 | MISSED | Not mentioned in the report. File access to this specific document was not identified. |
| 13 | Kali Linux attack platform | FOUND | Identified workstation name "kali" from Event ID 4625 brute force records. PCAP metadata confirmed "Kali Linux 5.8.0-kali1-amd64" as the capture platform. Agent explicitly noted the "kali" workstation name "strongly indicating Kali Linux, a penetration testing distribution." |
| 14 | Last contact: attacker still active at ~03:00 UTC | FOUND | Confirmed C2 to 203.78.103.109:443 was ESTABLISHED at time of memory capture. Kerberos activity and FileShare access continued through 06:17 UTC, showing the attacker remained active well beyond the answer key's last-contact estimate. |

---

## Findings Beyond the Answer Key

The agent identified several legitimate findings not covered by the published ground truth:

| Finding | Assessment |
|---------|------------|
| Nmap service scan from 194.61.24.102 (cookie "nmap") at 03:32:46 preceding RDP brute force | Legitimate. Reconnaissance phase not in the answer key but clearly visible in PCAP. |
| Meterpreter reflective DLL injection in spoolsv.exe on both systems with x64 shellcode stubs, ReflectiveLoader, and bind handler on TCP 62475 | Legitimate. Cross-system deployment confirmed by independent YARA + Volatility malfind on both hosts. |
| PowerShell injection chain on DESKTOP-SDN1RPT (PID 508 to 3316 with orphaned parent, PNG reference in RWX memory) | Legitimate. Consistent with post-exploitation framework behavior. |
| Kerberos authentication escalation chain: machine to mortysmith to Administrator to ricksanchez with ProtectedStorage TGS | Legitimate. Network-level credential escalation visibility. |
| Suspicious PE file transfers (04:04 and 04:19 UTC) with fabricated metadata: 64-bit binary claiming "Windows 95", disabled ASLR/DEP, non-standard ".lhru" section | Legitimate. Custom tooling indicators not in the answer key. |
| DRSUAPI/DCSync correctly dismissed: DRSGetNCChanges searched and found 0 results; only DRSCrackNames (normal AD behavior) observed | Analytically excellent. Many tools would have flagged this as credential theft. |
| Skeleton Key patcher tool (HookDC.dll) and NTLM hash dump output on DESKTOP-SDN1RPT | Legitimate. Agent correctly distinguished tool presence from confirmed deployment. |
| TA17-293A YARA match on 62.8.193.206 correctly assessed as false positive (single memory offset, zero network corroboration) | Analytically sound. Appropriate dismissal of an over-matching YARA rule. |
| ricksanchez FileShare access at 05:48 UTC as the only FileShare access in 7.7 hours | Legitimate. Anomalous access pattern, though the agent did not connect it to specific exfiltrated files. |

---

## False Positive Handling

| Initial Detection | Final Disposition | Rationale |
|-------------------|-------------------|-----------|
| DRSUAPI/DCSync (T1003.006) | Downgraded to LOW, reclassified as normal AD | DRSGetNCChanges not found; only DRSCrackNames observed, which is standard Group Policy client behavior |
| TA17-293A / IP 62.8.193.206 | Downgraded to LOW, assessed as likely FP | YARA rule over-matches on "file://" strings; single IP at one memory offset with zero network activity |
| Tofu Backdoor / Tonto Team attribution | Marked WEAK, not used for attribution | "Cookies: Sym1.0" at only 2 offsets is a thin, semi-generic signal |
| PrintNightmare speculation | Not claimed | Unlike the previous run, the agent did not speculate about CVE-2021-34527 |

**Zero false positives in the final report.** All 18 findings are either correct observations or appropriately hedged inferences with documented counter-analysis.

---

## Analysis of Misses

### Persistence mechanisms (registry + service)

The agent ran `composite.persistence` (9,383 results), `volatility.svcscan` (886 + 43,222 lines across both systems), and `registry.system` (multiple extractions). With tens of thousands of persistence entries, the specific registry run key and service entry for coreupdater.exe were buried in noise. The agent searched for "coreupdater" in shimcache and amcache (found nothing) and analyzed the DLL list for the process, but did not search the service registry specifically for a service pointing to that binary.

### Exfiltration (secret.zip, loot.zip)

The agent ran `find_data_exfiltration_indicators` (63 results) and `composite.exfil` (380 lines). It correctly identified the ricksanchez FileShare access and the encrypted C2 channel as potential exfiltration paths, but the zip files would require MFT analysis matching zip creation timestamps to the attack window. The encrypted C2 channel (port 443) prevented content inspection. While the MFT was available (111,852 entries), the agent did not search it for ".zip" files created during the attack window.

### Timestomping and file access

The `forensic.timestomping` extractor ran and returned only 1 line. The `find_defense_evasion` composite returned 6 lines focused on hidden processes. The specific `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp comparison for Beth_Secret.txt was not performed. For Szechuan Sauce.txt access, the MFT and disk artifacts were available but the agent did not search for these specific filenames. These represent gaps in targeted file-level forensics.

---

## Comparison with Previous Run

This case was run twice: once without PCAP ("Ultra-Violence" difficulty) and once with all evidence types ("I'm Too Young to Die").

| Metric | Without PCAP | With PCAP |
|--------|-------------|-----------|
| Evidence sources | 67 | 115 (+72%) |
| Tool calls | 345 | 412 (+19%) |
| Runtime | 38 min 35 sec | 55 min 24 sec (+44%) |
| Findings | 15 | 18 (+3) |
| Tokens | 101.3K | 134.4K (+33%) |
| Fully correct | 6 / 13 (46%) | 8 / 14 (57%) |
| Partially correct | 5 / 13 (38%) | 3 / 14 (21%) |
| Missed | 3 / 13 (23%) | 3 / 14 (21%) |
| False positives | 0 | 0 |

### What PCAP Added

1. **RDP brute force from the network:** 75+ automated RDP attempts from 194.61.24.102 visible in Zeek RDP logs, including connection rate (4.5/sec) and sequential source ports. The previous run only had EVTX-side evidence.
2. **Nmap reconnaissance:** Service scan with cookie "nmap" at 03:32:46 preceding the brute force. Not visible without PCAP.
3. **Lateral movement direction:** DC01 to DESKTOP-SDN1RPT RDP confirmed at the network level with source/destination IPs, empty cookie, and HYBRID_EX protocol. The previous run inferred direction from process timestamps; PCAP provided definitive proof.
4. **DRSUAPI counter-analysis:** Searching for DRSGetNCChanges across all network traffic and confirming zero instances was critical to correctly dismissing the DCSync false positive. Without PCAP, this would remain ambiguous.
5. **Kerberos authentication chain:** Full network-level visibility of the machine to mortysmith to Administrator to ricksanchez credential escalation, including ProtectedStorage TGS requests.

### What PCAP Did Not Help With

The three misses (exfiltration specifics, timestomping, file access) remained unchanged. Exfiltration was over the encrypted C2 channel (port 443), making PCAP content inspection impossible. Timestomping and file access are disk/MFT artifacts that PCAP cannot surface.

---

## Evidence Chain Tracebacks

### C2 Connection to 203.78.103.109
1. `tc_f77e6811` — Volatility pslist on DC01 memory identified coreupdater.exe (PID 3644)
2. `tc_c6c7a107` — Volatility netscan showed ESTABLISHED connection from PID 3644 to 203.78.103.109:443
3. `tc_63860be0` — bulk_extractor URL carving found `http://194.61.24.102/` with Administrator context
4. `tc_a4326bfe` — pstree confirmed coreupdater.exe parent PID 2244 (exited)

### NTLM Brute Force / Initial Access
1. `tc_b92e1706` — EVTX parser on DC01 Security log found Event ID 4625 entries with workstation "kali"
2. `tc_31537bbd` — Event ID 4672 at 03:21:46 confirmed Administrator logon with full privileges

### RDP Brute Force from 194.61.24.102
1. `tc_26e12972` — Zeek RDP log analysis found cookie "nmap" at 03:32:46, then 75+ "Administrator" attempts
2. `tc_7f283258` — PCAP conversations confirmed external IP reachability to DC01 port 3389

### Meterpreter in spoolsv.exe (both systems)
1. `tc_2af0d01a` — Volatility malfind on DC01 found 4 RWX regions with x64 Metasploit shellcode stub
2. `tc_923a6c2c` — YARA confirmed metsrv.x64.dll (5 offsets) and ReflectiveLoader (15 offsets)
3. `tc_a091259d` — Volatility malfind on DESKTOP-SDN1RPT found identical injection in spoolsv.exe PID 2188
4. `tc_c185c06e` — YARA on DESKTOP-SDN1RPT confirmed matching pattern

### DC01 to DESKTOP-SDN1RPT Lateral Movement
1. `tc_26e12972` — Zeek RDP log captured outbound RDP from 10.42.85.10 to 10.42.85.115 at 03:49:15

---

## Honest Assessment

### Strengths

- **Zero false positives.** Every claim is either correct or appropriately hedged with inference confidence. The counter-analysis phase actively eliminated two initial detections (DRSUAPI, TA17-293A) before they reached the final report.
- **Network forensics depth.** The PCAP analysis produced 6 new findings and strengthened 3 existing ones. The agent correctly processed 411,797 packets across 18 Zeek protocol log types, Suricata IDS, tcpflow reconstruction, tcpxtract file carving, and tshark analysis.
- **Self-correction.** The counter-analysis phase (10.5 min, 28 challenge tasks) tested each finding against alternative explanations, downgraded 2 findings, adjusted 1 severity level, and annotated 4 with counter-analysis notes.
- **Evidence correlation.** 15 parallel cross-system correlation tasks connected host artifacts with network evidence. Finding deduplication reduced 26 initial detections to 18 consolidated findings.
- **Forensic rigor.** SHA-256 hashes for all 11 evidence files, BLAKE2b output hashes for every tool call, read-only evidence mounts, and an append-only audit log.

### Weaknesses

- **Missed persistence mechanisms.** The specific registry key and Windows service for the malware were not surfaced despite running service scans (43,000+ entries) and registry analysis. The data was available but the search strategy did not sufficiently narrow the persistence composites.
- **Missed exfiltration specifics.** The agent identified the exfiltration path (encrypted C2) and the FileShare access pattern but did not search the MFT for zip file creation during the attack window.
- **Missed timestomping and file access.** The `forensic.timestomping` extractor returned data but it was not incorporated into findings. Specific file access (Beth_Secret.txt, Szechuan Sauce.txt) was not searched for despite disk images being available.
- **Filename discrepancy.** The agent consistently found "coreupdater.exe" while the answer key says "coreupdate.exe." This appears to be the actual filename on disk (the MFT and process list both show "coreupdater"), suggesting the answer key may have a minor error.

### Summary

The agent successfully performed an autonomous forensic investigation across 12.9 GB of evidence (disk images, memory dumps, network capture) in 55 minutes, producing 18 findings with 21 MITRE ATT&CK technique mappings and zero false positives. It correctly identified the full attack lifecycle from brute force initial access through credential theft and lateral movement. The three misses are concentrated in targeted file-level forensics (exfiltration artifacts, timestomping, specific file access), representing the primary area for improvement.
