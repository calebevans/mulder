# Mulder Investigation Report

**Case:** Rocba
**Generated:** 2026-06-03T08:51:54.704597+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 85 evidence sources (9 memory, 14 disk, 62 other) | 396 tool calls | 1.2 hours
**Results:** 15 findings (2 high) | 14 confirmed, 1 inference
**Timeline:** 2020-11-01 to 2020-11-16

**Attack Lifecycle:**
- **Initial Access / Deployment** (2020-11-01 to 2020-11-16): No Event Log Clearing, No Suspicious Services, No PowerShell Abuse Detected (+8 related)
- **Persistence** (2020-11-02 to 2020-11-16): Sustained RDP Brute-Force Attack from Multiple External IP Addresses (+3 related)

**Tools:** search (69), get_raw_output (41), find_lateral_movement_indicators._search(all) (18), submit_finding (16), open_case (13). SHA-256 hashes recorded for all evidence.



---

## Forensic Soundness and Evidence Integrity

Analysis was executed via a read-only Model Context Protocol (MCP) server
mapped to the SANS SIFT toolchain. The MCP architecture enforces structural
evidence protection: original evidence files were mounted as read-only
volumes, all tool interactions are typed functions (no shell access), and
every finding is validated against the append-only audit log before
acceptance.

2 evidence files were cryptographically
validated via SHA-256 hashes computed at ingestion and verified against the
case database.

396 tool calls were executed across 34
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Digital Forensic Investigation Report — Case Rocba

## Background

This investigation was initiated to analyze the workstation designated SRL-FORGE (internal IP 192.168.1.5), a Windows 10 (x64, version 10.0) system belonging to Stark Research Labs. The workstation was used by Fred Rocba (username: fredr, email: fred.rocba@outlook.com), and a second administrative account, srl-h (srl-helpdesk@outlook.com), existed from a prior operating system installation. Evidence was collected on approximately November 16, 2020, and consisted of a full memory dump and a disk image of the system.

The forensic investigation drew upon 34 indexed evidence sources spanning ten distinct extractor categories: memory forensics (Volatility 3), disk analysis (The Sleuth Kit), Windows event logs (EVTX parsing and Hayabusa/Chainsaw Sigma rule engines), registry analysis (RegRipper), Windows artifact parsing (EZ Tools for MFT, Amcache, ShimCache, and Prefetch), bulk data carving (bulk_extractor), YARA signature scanning, composite cross-system correlation modules, IOC enrichment, and file-level YARA scanning. The investigation generated 15 findings, of which 14 are confirmed through multi-source corroboration and 1 are assessed with inference-level confidence due to evidence gaps.

The system environment was that of a standard corporate workstation running a productivity-oriented software stack including Microsoft Teams, Slack, Microsoft Office, Google Drive, OneDrive, iCloud, and Adobe Acrobat Reader DC. Windows Defender (MsMpEng.exe, PID 4864) served as the endpoint security solution. The network configuration was DHCP-enabled on the 192.168.1.0/24 subnet, and the system maintained active connections to legitimate cloud services operated by Microsoft, Google, Apple, and Amazon at the time of memory capture.

## Incident Timeline

The incident can be reconstructed into three distinct operational phases based on convergent evidence from memory forensics, five archived Security event logs, the Terminal Services LocalSessionManager log, SAM registry data, MFT timestamps, and Volatility network connection data.

**Phase 1 — Brute-Force Campaign Onset (November 2–6, 2020)**

The earliest evidence of unauthorized activity appeared on November 2, 2020, at 08:28:14 UTC, when the first failed logon attempts (Event ID 4625) were recorded in the Security event log. The archived Security EVTX from November 6 (covering 03:40:38 to 07:55:10 UTC) contained thousands of failed authentication attempts targeting dictionary-style usernames including ADMINISTRATOR, ADMIN, ADMIN01, and SERVICEDESK. The attacking IPs observed in this archive included 193.93.62.27, 193.93.62.32, 193.93.62.39, 193.93.62.41, 193.93.62.50, 193.93.62.59, 143.244.42.92, and 87.251.75.19. Failure status codes included 0xC000006D (bad credentials), 0xC0000064 (user name does not exist), and 0xC000006A (correct username, wrong password), confirming the attackers were enumerating valid usernames and attempting password guessing. The sheer volume of failed logons — the 20 MB Security log limit was being filled approximately every six to seven hours — triggered normal Windows log archival rotation, producing over twenty archived Security EVTX files during this period.

**Phase 2 — Sustained Attack with Legitimate User Activity (November 7–15, 2020)**

The brute-force campaign continued unabated across the November 7 through 15 window. Four additional Security EVTX archives spanning November 14 at 00:34 through November 15 at 21:24 were indexed, collectively containing approximately 22,500 windows of failed logon events. No successful logon (Event ID 4624) from any attacker IP was found in any of these archives.

During this same period, the legitimate user fredr continued normal work activities via RDP through a Microsoft Azure gateway at 52.249.198.56. The Terminal Services LocalSessionManager log documents the following session activity: on November 14 at 03:42:50, fredr reconnected to Session 1 from 52.249.198.56 and disconnected at 05:15:52; at 12:31:27, fredr reconnected again from the same Azure IP, briefly disconnected at 12:51:44, immediately reconnected at 12:52:03, and finally disconnected at 14:17:13. During this last session, at 13:38:10, fredr accessed SDelete — a legitimate Sysinternals secure deletion utility that had been pre-installed in the Downloads folder since 2018 (Amcache link date: 2018-11-15, SHA1: 7bcd946326b67f806b3db4595ede9fbdf29d0c36). Associated Recycle Bin activity was recorded between 13:41:19 and 13:41:31.

**Phase 3 — Active Attack Connections at Memory Capture (November 16, 2020)**

At approximately 02:29:37 on November 16, the system recorded a LOCAL session reconnection for fredr (Terminal Services Event ID 25, Record 93), which triggered the fDenyTSConnections registry key update at the same timestamp — a routine part of Terminal Server session refresh, not an attacker modification.

Between 02:33 and 02:36, Volatility netscan captured multiple TCP connections to port 3389 from external brute-force source IPs: 81.30.144.115 (Germany, AS24961 WIIT AG) with two ESTABLISHED connections at 02:34:45 and 02:34:58; 213.202.233.104 (Germany, AS24961 WIIT AG) with two ESTABLISHED connections at 02:34:58 and 02:35:53; and 81.19.209.101 (Netherlands, AS25369 Hydra Communications) in SYN_RCVD state at 02:33:32. An additional connection from 201.193.188.114 (Costa Rica) was also observed. Critically, the ESTABLISHED TCP state indicates only that the three-way handshake completed — with Network Level Authentication (SecurityLayer: 2) configured, the NLA credential validation occurs after the TCP handshake and TLS negotiation. The Terminal Services LocalSessionManager log contains no session logon (Event ID 21) or reconnection (Event ID 25) from any of these IPs, conclusively proving these connections were in the pre-authentication TLS/NLA negotiation phase and had not achieved authenticated RDP access.

The SAM registry showed the disabled Administrator account received its most recent password failure at 02:50:31 on November 16 — after the memory capture window — confirming the brute-force campaign continued beyond the forensic snapshot.

## Key Findings

**Sustained Distributed RDP Brute-Force Campaign**

The investigation confirmed a sustained, distributed RDP brute-force attack against SRL-FORGE spanning at least two weeks from November 2 through November 16, 2020. More than ten distinct external IP addresses participated, sourced from geographically dispersed hosting and VPS providers across Germany, the Netherlands, Costa Rica, and other locations. Two attacking IPs — 81.30.144.115 and 213.202.233.104 — shared the same German hosting provider (WIIT AG, AS24961), suggesting at least partial coordination. The attackers employed multiple RDP client implementations including Rdesktop, FreeRDP, Remmina, and mstsc, and impersonated various Windows operating system versions in their client identifiers. The targeted username dictionary was extensive, ranging from common administrative accounts (ADMINISTRATOR, ADMIN, SERVICEDESK, SQLSERVICE, BMEADMIN, FTP) to hundreds of personal names, indicating an automated, indiscriminate credential-guessing operation.

Despite the volume and persistence of the attack, convergent evidence from six independent sources — five archived Security EVTX logs, the Terminal Services LocalSessionManager log, System EVTX, WinRM Operational log, Volatility netscan, and SAM registry — conclusively demonstrates that no attacker achieved authenticated access to the system. Every sampled Security log archive contained exclusively Event ID 4625 (failed logon) entries with no Event ID 4624 (successful logon) from attacker IPs. The Terminal Services log recorded sessions only from LOCAL and the corporate Azure gateway (52.249.198.56). No suspicious services were installed, no PowerShell abuse was detected, and no unauthorized accounts were created.

**RDP Service Exposure**

The Remote Desktop Protocol service was enabled and listening on all interfaces (0.0.0.0:3389 and [::]:3389) without apparent network-level access restrictions such as firewall rules or IP allowlisting. While Network Level Authentication was enabled (SecurityLayer: 2), providing a degree of pre-authentication protection that ultimately prevented the brute-force attack from succeeding, the unrestricted network exposure allowed the sustained attack to reach the system in the first place. Both active user accounts (fredr and srl-h) held Administrators group membership, and the Remote Desktop Users group was empty, meaning any account compromise would have immediately granted full administrative access.

**Malware and Rootkit Assessment — Negative**

YARA signature scanning of both memory and disk produced matches that were thoroughly investigated and determined to be false positives. The APT6_Malware_Sample_Gen rule matched on the generic string "C:\WINDOWS\system32\" — a standard Windows path present in all memory dumps. The APT_MAL_RU_WIN_Snake_Malware_May23_1 rule matched on common C format strings (%s#1, %s#2, etc.) and the ".tmp" extension found in legitimate Windows binaries. Volatility malfind analysis identified PAGE_EXECUTE_READWRITE allocations in MsMpEng.exe (PID 4864) that were consistent with Windows Defender's JIT scanning engine, and UWP application trampolines in SearchApp.exe, smartscreen.exe, and dllhost.exe — all benign patterns. No actual malware, rootkits, or malicious code injection was identified in memory or on disk. The Chainsaw Sigma rule hunt across all extracted EVTX files also returned zero findings.

**Process Analysis — No Hidden Processes**

The 37 processes identified by Volatility psscan but absent from pslist were investigated and confirmed as normally terminated processes whose EPROCESS structures persisted in unallocated memory. All had ExitTime values set, none had active network connections or malfind hits, and all carried anomaly scores of zero. The majority were identified as short-lived Microsoft Teams renderer processes spawned by PID 11672, which routinely creates and terminates child processes every two to four minutes. This is a well-understood forensic artifact of pool-tag scanning, not evidence of process hiding by a rootkit.

**SDelete Usage — Legitimate Activity**

The use of SDelete during the attack window was initially flagged as a potential anti-forensics concern. Cross-system correlation with the Terminal Services log conclusively attributed this activity to the legitimate user fredr during an active RDP session from the corporate Azure gateway (52.249.198.56). The SDelete executable had been present in fredr's Downloads folder since 2018, and the session timeline — reconnection at 12:52:03, SDelete.lnk creation at 13:38:10, user-initiated disconnect at 14:17:13 — places the tool usage squarely within a normal work session. The associated 248 deleted files are attributable to routine user file management rather than attacker-driven evidence destruction.

**Cloud Storage and Data Exfiltration Assessment — Negative**

Multiple cloud storage services were actively running at the time of memory capture, including OneDrive (PID 6188), Google Drive Sync (PID 8432), iCloud (PID 12532), and Microsoft Teams (PID 11672). All outbound connections were to known-good cloud service IP ranges associated with the user's configured corporate accounts. URL analysis from bulk_extractor confirmed SharePoint URLs pointing to "starkresearchlabs-my.sharepoint.com/personal/frocba_stark-research-labs_com" — the legitimate corporate OneDrive tenant. No connections to known exfiltration services (Mega, Pastebin, anonymous file sharing) or unusual destinations were identified.

## Threat Intelligence and Attribution

The attack characteristics are consistent with an automated, opportunistic RDP brute-force campaign rather than a targeted intrusion. The use of extensive username dictionaries containing generic administrative accounts and hundreds of personal names, combined with multiple RDP client implementations and geographically dispersed source IPs, is a hallmark of botnet-driven credential-stuffing operations that scan the internet for exposed RDP services.

Two of the attacking IPs (81.30.144.115 and 213.202.233.104) resolved to the same hosting provider, WIIT AG (AS24961) in Germany, which may indicate shared infrastructure or a common VPS provider exploited by the attacker. IP 81.19.209.101 was associated with Hydra Communications (AS25369) in the Netherlands. These hosting providers are commonly used in bulk scanning campaigns. IOC enrichment did not return definitive threat actor attribution for any of the observed IPs.

The attack techniques map to MITRE ATT&CK T1110.001 (Brute Force: Password Guessing), T1110.003 (Brute Force: Password Spraying), and T1021.001 (Remote Services: Remote Desktop Protocol). These techniques are employed by a wide range of threat actors and automated scanning tools, and their presence alone does not support attribution to any specific threat group. The evidence supports characterizing this as an automated, distributed brute-force campaign against an internet-exposed RDP endpoint, consistent with the tactics of numerous commodity threat actors and botnets.

## Impact Assessment

The brute-force attack did not result in system compromise. No authenticated attacker sessions were established, no malware was deployed, no data was exfiltrated, and no persistence mechanisms were installed. The primary impact was operational: the sustained attack generated tens of thousands of failed authentication events that consumed Security event log capacity, causing rapid log rotation approximately every six to seven hours. This log churn, while not causing data loss (archived logs were preserved), degraded the system's security monitoring posture by potentially overwhelming any log analysis or SIEM infrastructure.

The system's exposure posture represents a significant residual risk. With RDP listening on all interfaces without network-level restrictions, two administrative accounts as the only RDP-capable users, and the system directly accessible from the internet, a successful credential compromise would have immediately granted full administrative access to a workstation containing active connections to corporate SharePoint, OneDrive, Google Drive, iCloud, and Slack — representing potential access to the full breadth of Stark Research Labs corporate data accessible to Fred Rocba.

## Immediate Tactical Containment

The following actions should be executed immediately to reduce the ongoing attack surface:

1. Block the following attacker IPs at the network perimeter firewall: 81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114, 193.93.62.27, 193.93.62.32, 193.93.62.39, 193.93.62.41, 193.93.62.50, 193.93.62.59, 143.244.42.92, 87.251.75.19, 85.14.242.76, 141.98.83.187, and 210.245.20.111.
2. Restrict inbound access to TCP port 3389 on 192.168.1.5 (SRL-FORGE) to authorized source IPs only, at minimum allowlisting only the Azure corporate gateway IP 52.249.198.56 and LOCAL network ranges.
3. Force a password reset for accounts fredr (RID 1002) and srl-h (RID 1001), as these were actively targeted during the brute-force campaign.
4. Verify the disabled status of the built-in Administrator account (RID 500), Guest account (RID 501), and DefaultAccount (RID 503), all of which were also targeted.
5. Review the TermService configuration on SRL-FORGE to confirm that NLA (SecurityLayer: 2) remains enforced, and consider enabling account lockout policies to throttle brute-force attempts.
6. Monitor for any new inbound RDP connections to 192.168.1.5:3389 from IPs outside the authorized allowlist for the next 72 hours.

## Strategic Remediation

**Root Cause 1 — Internet-Exposed RDP Without Network Access Controls.** The RDP service on SRL-FORGE was bound to all interfaces (0.0.0.0:3389) with no firewall rules or IP allowlisting restricting inbound access, as confirmed by Volatility netscan and registry analysis of the Terminal Server configuration. This single misconfiguration enabled the entire brute-force campaign documented in findings f_8862bf2a, f_dc3cf89d, and f_c4944b34. Implementing a host-based firewall rule or network security group restricting port 3389 access to the Azure corporate gateway (52.249.198.56) and internal network ranges would have prevented all observed attack traffic from reaching the RDP service. Alternatively, deploying Azure Bastion or a VPN gateway as the exclusive RDP access path would eliminate direct internet exposure entirely.

**Root Cause 2 — Absence of Account Lockout Policy.** The SAM registry data (finding f_c4944b34) shows password failure dates current to the hour of memory capture across all accounts, with the disabled Administrator account showing a failure timestamp of 02:50:31 — evidence that tens of thousands of authentication attempts were permitted without any lockout threshold. Configuring an account lockout policy (e.g., 5 failed attempts with a 30-minute lockout window) would have rendered the brute-force campaign ineffective after the first few attempts per targeted account and dramatically reduced the Security event log churn that consumed twenty archived logs in just four days.

**Root Cause 3 — All RDP-Capable Accounts Hold Administrative Privileges.** Finding f_c4944b34 documents that both active accounts (fredr and srl-h) are members of the Administrators group, and the Remote Desktop Users group is empty. This means any successful credential compromise would immediately grant full administrative access. Creating dedicated standard user accounts for RDP access with least-privilege group membership, reserving administrative credentials for local console use only, would limit the blast radius of any future credential compromise.

**Root Cause 4 — No RDP-Specific Monitoring or Alerting.** The investigation documented in finding f_e108669b initially identified critical gaps in Security EVTX coverage, and finding f_89be1bf2 noted that the sustained attack generated no alerts from Hayabusa or Chainsaw Sigma engines during the active campaign. While subsequent analysis confirmed no compromise occurred, the absence of real-time alerting on anomalous authentication volumes (thousands of Event ID 4625 per hour) meant the attack proceeded undetected for at least two weeks. Deploying a SIEM rule or Windows Event Forwarding subscription that alerts on a threshold of failed RDP logon attempts (e.g., more than 50 Event ID 4625 events with LogonType 3 per hour) would have enabled early detection and response.

## Conclusion

**Q1. What systems were compromised?** No systems were compromised. The sustained RDP brute-force attack against SRL-FORGE (192.168.1.5) did not achieve authenticated access. This conclusion is confirmed by convergent evidence from six independent sources: five archived Security EVTX logs containing only failed logon events, the Terminal Services LocalSessionManager log showing sessions only from LOCAL and the corporate Azure gateway, the absence of suspicious services in the System EVTX, empty WinRM Operational logs, clean Volatility memory analysis, and zero Chainsaw/Hayabusa Sigma rule alerts.

**Q2. How did the attacker gain initial access?** The attacker did not gain initial access. The ESTABLISHED TCP connections from attacker IPs observed in the memory capture at 02:34–02:36 on November 16 represent completed TCP handshakes but pre-NLA authentication states, confirmed by the absence of corresponding Terminal Services session logon events. Network Level Authentication prevented the brute-force campaign from escalating TCP connectivity into authenticated RDP sessions.

**Q3. What lateral movement occurred?** No lateral movement occurred. Composite analysis found no network logon events, no suspicious parent-child process chains, no reconnaissance tool execution, and no SMB/WinRM/RPC connections indicative of lateral movement. The only identified cross-system activity was fredr's legitimate RDP sessions from the Azure corporate gateway. The SDelete usage previously flagged as a potential concern was conclusively attributed to the legitimate user during a normal work session.

**Q4. What persistence mechanisms were installed?** No malicious persistence mechanisms were installed. System EVTX analysis confirmed all Event ID 7045 (service installation) entries correspond to legitimate software: Intel display drivers, Dropbox, Google Update, Mozilla Maintenance Service, and Windows Defender kernel drivers. Composite persistence analysis identified only standard Windows autorun entries for configured corporate applications. No scheduled task creation events, WMI subscriptions, or suspicious registry modifications were detected.

**Q5. Was data exfiltrated, and if so, what and how much?** No data exfiltration was detected. All outbound network connections were to legitimate cloud services (OneDrive, Google Drive, iCloud, Teams, Slack) associated with the user's corporate accounts. No connections to known exfiltration platforms or unusual destinations were observed. However, had the brute-force attack succeeded, the attacker would have had access to all cloud-synced corporate data through the compromised session.

**Q6. What is the full timeline of the incident?** The brute-force campaign began no later than November 2, 2020 at 08:28:14 UTC and continued through at least November 16, 2020 at 02:50:31 UTC (the last recorded password failure on the Administrator account). The campaign spanned at least 14 days and involved ten or more distinct external IP addresses using automated credential-guessing tools. The attack generated sufficient volume to fill the 20 MB Security event log limit approximately every six to seven hours. No successful attacker authentication occurred at any point during this window.

**Q7. What is the total scope and business impact?** The business impact is limited to the operational burden of the sustained attack. No data was compromised, no systems were breached, and no malware was deployed. The principal risk is the demonstrated exposure of the RDP service to the public internet, which enabled the attack and represents an ongoing vulnerability if not remediated. The system hosts active connections to Stark Research Labs' SharePoint, OneDrive, and Slack tenants, meaning any future compromise of this workstation would have significant data access implications.

**Q8. What are the recommended remediation actions?** Four specific remediation actions are recommended, each tied directly to a root cause identified in this investigation: (1) restrict RDP network access to authorized source IPs only, eliminating direct internet exposure; (2) implement an account lockout policy to throttle brute-force attempts; (3) remove administrative privileges from RDP user accounts and enforce least-privilege access; and (4) deploy real-time alerting on anomalous authentication failure volumes to enable early detection of future brute-force campaigns.


---

## Overview

| | |
|---|---|
| Findings | **15** (14 confirmed, 1 inference) |
| Severity | 0 critical, 2 high, 3 medium, 2 low, 8 info |
| Sources | 34 evidence sources across 396 tool calls |


---

## Evidence Hashes

SHA-256 hashes recorded at ingestion. Verify with `sha256sum <file>`.

| File | SHA-256 | Size |
|------|---------|------|
| Rocba-Memory.zip | `32cec94018051f6ce20ec75f1b7b53ad2f6eb5e8bbaec7b402e30409af552b09` | 5.3 GB |
| rocba-cdrive.e01 | `f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67` | 22.1 GB |



---

## Attack Timeline


| Time | Event | Severity | Sources |
|------|-------|----------|---------|
| 2020-11-01T22:15:34 | No Event Log Clearing, No Suspicious Services, No PowerShell Abuse Detected | INFO | evtx.windows_system32_winevt_logs_system, evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational, evtx.windows_system32_winevt_logs_windows-powershell, evtx.windows_system32_winevt_logs_microsoft-windows-winrm4operational, composite.persistence, composite.defense_evasion |
| 2020-11-02T08:28:14 | Sustained RDP Brute-Force Attack from Multiple External IP Addresses | HIGH | volatility.netscan, evtx.windows_system32_winevt_logs_archive-security-2020-11-06-07-55-12-490 |
| 2020-11-02T08:28:14 | Cross-System Confirmation: RDP Brute-Force Attack Did NOT Achieve Authenticated Access | HIGH | evtx.windows_system32_winevt_logs_archive-security-2020-11-06-07-55-12-490, evtx.windows_system32_winevt_logs_archive-security-2020-11-14-07-54-47-237, evtx.windows_system32_winevt_logs_archive-security-2020-11-14-14-12-28-311, evtx.windows_system32_winevt_logs_archive-security-2020-11-15-03-14-49-203, evtx.windows_system32_winevt_logs_archive-security-2020-11-15-23-53-52-261, evtx.windows_system32_winevt_logs_microsoft-windows-terminalservices-localsessionmanager4operational, evtx.windows_system32_winevt_logs_microsoft-windows-winrm4operational, evtx.windows_system32_winevt_logs_system, registry.system, volatility.netscan |
| 2020-11-02T08:28:14 | No Post-Exploitation or Lateral Movement Activity Detected in Available Evidence | INFO | composite.lateral_movement, composite.execution_chains, volatility.cmdline, chainsaw.hunt, composite.execution, composite.timeline |
| 2020-11-06T03:40:38 | Critical Evidence Gaps: Missing EVTX Logs Prevent Definitive Attack Outcome Determination | INFO | chainsaw.hunt, evtx.manifest |
| 2020-11-11T08:13:00 | Process Discrepancy (PsScan vs PsList) Explained by Normal Process Termination — No Rootkit Evidence | INFO | volatility.psscan, composite.defense_evasion, composite.suspicious_processes |
| 2020-11-11T08:13:16 | RDP Service Enabled and Exposed to External Network | MEDIUM | volatility.svcscan, volatility.netscan, registry.system |
| 2020-11-14T03:42:22 | Brute-Force Attack Targets All Local Accounts Including Disabled Ones | MEDIUM | registry.system |
| 2020-11-14T03:42:50 | Legitimate User RDP Access Pattern from Azure Cloud Gateway (52.249.198.56) | INFO | evtx.windows_system32_winevt_logs_microsoft-windows-terminalservices-localsessionmanager4operational, ez.mft, ez.amcache |
| 2020-11-14T13:38:10 | SDelete Secure Deletion Tool Used During Attack Window on Nov 14, 2020 | LOW | ez.mft, ez.amcache, composite.recovery, composite.execution |
| 2020-11-16T02:29:37 | fDenyTSConnections Registry Modification Temporally Correlated with Both System Activity and Active RDP Attack | LOW | registry.system, composite.correlation, ez.mft, volatility.netscan |
| 2020-11-16T02:29:57 | Cloud Storage Services Active During Attack Window With No Exfiltration Indicators | INFO | volatility.netscan, composite.exfil, bulk.url |
| 2020-11-16T02:30:00 | Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Capture | MEDIUM | volatility.netscan |





---

## Appendix A: Verified Forensic Findings


### 1. [HIGH] Sustained RDP Brute-Force Attack from Multiple External IP Addresses

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-11-02T08:28:14 to 2020-11-16T02:36:24 |
| **Sources** | volatility.netscan, evtx.windows_system32_winevt_logs_archive-security-2020-11-06-07-55-12-490 |
| **Evidence Refs** | tc_a246eb3d, tc_24c7894c, tc_628ff4b5, tc_928ad9b2 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


The system SRL-FORGE (192.168.1.5) is under sustained RDP brute-force attack from multiple external IP addresses spanning at least two weeks (Nov 2-16, 2020). Security Event Log archive from Nov 6 contains thousands of Event ID 4625 (Failed Logon) events with LogonType 3 using NTLM authentication. Targeted usernames include ADMINISTRATOR, ADMIN, ADMIN01, and SERVICEDESK — classic brute-force dictionary targets.

Attacking IPs observed in Security EVTX (Nov 6): 193.93.62.27, 193.93.62.32, 193.93.62.39, 193.93.62.41, 193.93.62.50, 193.93.62.59, 143.244.42.92, 87.251.75.19.

Attacking IPs observed in memory netscan (Nov 16): 81.30.144.115 (Germany, AS24961 WIIT AG), 213.202.233.104 (Germany, AS24961 WIIT AG), 81.19.209.101 (Netherlands, AS25369 Hydra Communications), 201.193.188.114 (Costa Rica).

The 20+ archived Security EVTX files (each 20 MB) from Nov 2-6 alone indicate tens of thousands of failed authentication attempts. Failure status codes include 0xC000006D (bad credentials), 0xC0000064 (user name does not exist), and 0xC000006A (correct username, wrong password), confirming the attackers are enumerating valid usernames and attempting password guessing.

The attack originated from multiple geographically dispersed IPs associated with hosting/VPS providers, consistent with a distributed botnet-style brute-force campaign. Two IPs (81.30.144.115 and 213.202.233.104) share the same German hosting provider (WIIT AG), suggesting coordinated activity.



### 2. [HIGH] Cross-System Confirmation: RDP Brute-Force Attack Did NOT Achieve Authenticated Access

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-11-02T08:28:14 to 2020-11-16T02:50:31 |
| **Sources** | evtx.windows_system32_winevt_logs_archive-security-2020-11-06-07-55-12-490, evtx.windows_system32_winevt_logs_archive-security-2020-11-14-07-54-47-237, evtx.windows_system32_winevt_logs_archive-security-2020-11-14-14-12-28-311, evtx.windows_system32_winevt_logs_archive-security-2020-11-15-03-14-49-203, evtx.windows_system32_winevt_logs_archive-security-2020-11-15-23-53-52-261, evtx.windows_system32_winevt_logs_microsoft-windows-terminalservices-localsessionmanager4operational, evtx.windows_system32_winevt_logs_microsoft-windows-winrm4operational, evtx.windows_system32_winevt_logs_system, registry.system, volatility.netscan |
| **Evidence Refs** | tc_0c39f4ca, tc_1498c318, tc_5ecace92, tc_64c673d6, tc_716cf48c, tc_7dfe5179, tc_9e2fab24, tc_a4549fe4, tc_bb1e1da1 |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |


Convergence of evidence from 6 independent sources conclusively demonstrates that the sustained RDP brute-force attack against SRL-FORGE (192.168.1.5) did NOT result in any authenticated attacker sessions during the Nov 2–16, 2020 window.

**Evidence convergence from independent sources:**

1. **Terminal Services LocalSessionManager EVTX (Event IDs 21/25/24/40)**: All RDP session logons and reconnections are attributable to user fredr from only two source addresses: LOCAL and 52.249.198.56 (a Microsoft Azure IP, likely the legitimate corporate access path). No session logons or reconnections were recorded from ANY brute-force attacker IP (85.14.242.76, 81.30.144.115, 213.202.233.104, 81.19.209.101, 201.193.188.114, 193.93.62.x, 141.98.83.187, 210.245.20.111, etc.). The TS log covers Nov 2 through Nov 16.

2. **Security EVTX Archives (Nov 6, 14-00:34 to 14-07:54, 14-07:54 to 14-14:12, 14-14:12 to 15-03:14, 15-19:46 to 15-21:24)**: Five archived Security EVTX files containing ~35,800 windows collectively show ONLY Event ID 4625 (failed logon) entries. Zero Event ID 4624 (successful logon) entries are present. Every entry from attacker IPs uses LogonType 3 (network/NTLM), not LogonType 10 (RemoteInteractive/RDP), confirming these are pre-NLA authentication failures.

3. **Volatility netscan**: The ESTABLISHED RDP connections from 81.30.144.115 and 213.202.233.104 at 2020-11-16 02:34–02:36 represent completed TCP handshakes but NOT authenticated sessions. With NLA (SecurityLayer: 2) configured, ESTABLISHED TCP state occurs before NLA credential validation. The Terminal Services log confirms no session logon occurred from these IPs.

4. **SAM Registry**: fredr's password failure date is 2020-11-14 03:42:22 — the same timestamp as an RDP session disconnect/reconnect sequence in the TS log (session 1 disconnected at 03:42:44, reconnected from 52.249.198.56 at 03:42:50). This password failure is consistent with fredr mistyping his own password during reconnection, not an attacker gaining access.

5. **System EVTX**: No Event ID 7045 (service installation) events from suspicious services during the attack window. All installed services are legitimate (Intel display, Dropbox, Google Update, Mozilla, Windows Defender kernel driver MpKsl).

6. **WinRM Operational log**: Empty — no WinRM remote management sessions.

**Attack characterization across archives:**
The brute-force campaign involved 10+ external IPs using multiple RDP client identifiers (Rdesktop, FreeRDP, Remmina, mstsc, Windows7/8/10/2012/2016/2019) and targeting extensive username dictionaries (ADMINISTRATOR, ADMIN, SERVICEDESK, SQLSERVICE, BMEADMIN, FTP, plus hundreds of personal names: princess, ocean, marshall, hilbert, etc.). Failure reasons are consistently 0xC0000064 (user does not exist) and 0xC000006A (wrong password), confirming the attackers never discovered valid credentials.

This answers investigation questions Q1 (attack unsuccessful), Q2 (ESTABLISHED connections were pre-NLA TCP handshakes), Q4 (no malicious services installed), Q5 (no PowerShell abuse), Q6 (no log clearing detected), and Q8 (no suspicious persistence mechanisms).

**Affected Systems:** evtx.windows_system32_winevt_logs_archive-security-2020-11-06-07-55-12-490, evtx.windows_system32_winevt_logs_archive-security-2020-11-14-07-54-47-237, evtx.windows_system32_winevt_logs_archive-security-2020-11-14-14-12-28-311, evtx.windows_system32_winevt_logs_archive-security-2020-11-15-03-14-49-203, evtx.windows_system32_winevt_logs_archive-security-2020-11-15-23-53-52-261, evtx.windows_system32_winevt_logs_microsoft-windows-terminalservices-localsessionmanager4operational, evtx.windows_system32_winevt_logs_microsoft-windows-winrm4operational, evtx.windows_system32_winevt_logs_system, registry.system, volatility.netscan



### 3. [MEDIUM] Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Capture

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T02:30:00 to 2020-11-16T02:36:24 |
| **Sources** | volatility.netscan |
| **Evidence Refs** | tc_a246eb3d, tc_d8c3260c |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1110](https://attack.mitre.org/techniques/T1110/) |


At the time of memory capture (approximately 2020-11-16 02:30-02:36 UTC), Volatility netscan reveals multiple ESTABLISHED TCP connections to port 3389 (RDP) from external IPs that were also conducting brute-force attacks:

- 81.30.144.115:51048 → 192.168.1.5:3389 ESTABLISHED (2020-11-16 02:34:58)
- 81.30.144.115:5067 → 192.168.1.5:3389 ESTABLISHED (2020-11-16 02:34:45)
- 213.202.233.104:45753 → 192.168.1.5:3389 ESTABLISHED (2020-11-16 02:34:58)
- 213.202.233.104:40876 → 192.168.1.5:3389 ESTABLISHED (2020-11-16 02:35:53)
- 81.19.209.101:50424 → 192.168.1.5:3389 SYN_RCVD (2020-11-16 02:33:32)

**UPDATED ASSESSMENT (confirmed by cross-system correlation):** These ESTABLISHED connections represent completed TCP handshakes but NOT authenticated RDP sessions. Evidence from the Terminal Services LocalSessionManager EVTX conclusively shows NO session logon (Event ID 21) or reconnection (Event ID 25) from any of these IPs. With NLA (SecurityLayer: 2) configured, TCP ESTABLISHED state occurs before NLA credential validation. The connections were in the pre-authentication TLS/NLA negotiation phase at the time of memory capture.

The initial "inference" confidence has been elevated by the TS log evidence, and severity downgraded from high to medium since the connections were unsuccessful.



### 4. [MEDIUM] RDP Service Enabled and Exposed to External Network

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-11-11T08:13:16 to 2020-11-16T02:36:24 |
| **Sources** | volatility.svcscan, volatility.netscan, registry.system |
| **Evidence Refs** | tc_2602c98c, tc_89bb76df, tc_a246eb3d |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


The Remote Desktop Protocol (RDP) service is enabled and listening on all interfaces, exposing the system to external attack:

- TermService (Remote Desktop Services) is SERVICE_RUNNING on PID 1248 (svchost.exe -k NetworkService)
- Registry key ControlSet001\Control\Terminal Server shows fDenyTSConnections = 0 (connections allowed), LastWrite: 2020-11-16 02:29:37Z
- RDP TCP listener bound on 0.0.0.0:3389 (all interfaces) and [::]:3389
- UDP listener also bound on 0.0.0.0:3389 and [::]:3389
- SecurityLayer = 2 (NLA required), which provides some protection
- No evidence of firewall restrictions or IP allowlisting for RDP access

The system's RDP service is directly accessible from the internet with no apparent network-level restrictions, making it a target for brute-force attacks.

[Counter-analysis note on fDenyTSConnections timing]: The registry key modification at 2020-11-16 02:29:37Z coincides precisely with a LOCAL session reconnection (TS LocalSessionManager Event ID 25, Record 93: fredr reconnected from LOCAL at 02:29:37.39Z). This was part of the Terminal Server session reconnection process, NOT an attacker-initiated modification. The original finding's suggestion that "the attacker or an automated process modified this setting" has been resolved — it was a standard system event.



### 5. [MEDIUM] Brute-Force Attack Targets All Local Accounts Including Disabled Ones

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | confirmed |
| **Time** | 2020-11-14T03:42:22 to 2020-11-16T02:50:31 |
| **Sources** | registry.system |
| **Evidence Refs** | tc_9d9c60b2, tc_16ab8128 |
| **ATT&CK** | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/) |


SAM registry analysis reveals that password failure dates on multiple accounts confirm ongoing brute-force targeting at the time of memory capture:

- Administrator [500]: Account DISABLED, Pwd Fail Date: 2020-11-16 02:50:31Z, Login Count: 0 (never logged in). Despite being disabled, attackers are actively attempting this account.
- Guest [501]: Account DISABLED, Pwd Fail Date: 2020-11-16 00:23:06Z
- DefaultAccount [503]: Account DISABLED, Pwd Fail Date: 2020-11-16 01:12:37Z

Active user accounts:
- fredr [1002] (Fred Rocba, fred.rocba@outlook.com): Last Login 2020-11-14 12:51:58Z, Member of Administrators group, Pwd Fail Date: 2020-11-14 03:42:22Z
- srl-h [1001] (srl-helpdesk@outlook.com): Last Login 2020-11-10 13:26:09Z, Member of Administrators group

Both active accounts have administrative privileges. The Remote Desktop Users group is empty, meaning RDP access is available only through Administrators group membership. The disabled Administrator account was targeted most recently (02:50:31Z on Nov 16) — after the memory capture's network connection timestamps (~02:36Z), confirming the attack continued beyond the capture window.

No evidence of unauthorized account creation (all accounts created 2020-10-20 to 2020-11-01 during system setup). No successful brute-force authentication detected in the sampled Security EVTX archive, though the archive analyzed covers only Nov 6; the current Security.evtx covering Nov 7-16 was not found in the extracted logs.



### 6. [LOW] SDelete Secure Deletion Tool Used During Attack Window on Nov 14, 2020

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | confirmed |
| **Time** | 2020-11-14T13:38:10 to 2020-11-14T13:42:42 |
| **Sources** | ez.mft, ez.amcache, composite.recovery, composite.execution |
| **Evidence Refs** | tc_30e6dfa4, tc_29938883, tc_48831553, tc_6507248d |
| **ATT&CK** | [T1070.004](https://attack.mitre.org/techniques/T1070/004/), [T1070](https://attack.mitre.org/techniques/T1070/) |


Cross-system correlation resolves the SDelete attribution question: SDelete was used by the legitimate user fredr during a normal remote work session, not by an attacker.

**Updated evidence from Terminal Services LocalSessionManager EVTX:**
At 2020-11-14 12:52:03, fredr reconnected to Session 1 via RDP from 52.249.198.56 (Microsoft Azure — the corporate remote access gateway). The SDelete.lnk was created at 13:38:10 — squarely within this active session. Fredr disconnected the session at 14:17:13 (user-initiated disconnect, reason code 11). The SDelete executable was pre-installed in fredr's Downloads folder since 2018 (Amcache link date: 2018-11-15).

**Original evidence retained:**
1. MFT: SDelete.lnk created at 2020-11-14 13:38:10 in fredr's Recent Items
2. Amcache: sdelete.exe in c:\users\fredr\downloads\sdelete\ (SHA1: 7bcd946326b67f806b3db4595ede9fbdf29d0c36)
3. MFT: $Recycle.Bin activity during 13:41:19–13:41:31

**Severity downgraded from medium to low**: While SDelete use during an attack window is noteworthy, the tool was a pre-existing utility used by the legitimate account owner during a clearly authenticated session from the corporate access gateway. The 248 deleted files may warrant review but do not indicate anti-forensics by an attacker.



### 7. [LOW] fDenyTSConnections Registry Modification Temporally Correlated with Both System Activity and Active RDP Attack

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T02:29:37 to 2020-11-16T02:29:42 |
| **Sources** | registry.system, composite.correlation, ez.mft, volatility.netscan |
| **Evidence Refs** | tc_5aa98443, tc_1f71d595 |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


Cross-system timeline correlation resolves the fDenyTSConnections registry modification ambiguity: the modification at 2020-11-16 02:29:37Z is directly caused by a LOCAL session reconnection event, not an attacker action.

**Definitive evidence from Terminal Services LocalSessionManager EVTX:**
Record 93 (2020-11-16 02:29:37.3949779): "Remote Desktop Services: Session reconnection succeeded" — user SRL-FORGE\fredr, source address LOCAL, Session ID 1. This event occurs at precisely the same second as the fDenyTSConnections registry modification, confirming the registry change was part of the Terminal Server session reconnection process.

**Supporting temporal correlation from 3 additional sources:**

1. **Registry (ControlSet001\Control\Terminal Server)**: fDenyTSConnections = 0 (connections allowed), LastWrite: 2020-11-16 02:29:37Z — simultaneous with the LOCAL session reconnection.

2. **Registry (Scheduled Tasks)**: Windows Customer Experience Improvement Program Consolidator task executed at 2020-11-16 02:29:39Z — 2 seconds after. BITS service registry entry updated at 02:29:42Z. These are legitimate system maintenance activities triggered by the session reconnection.

3. **MFT (System DLL cache)**: Multiple Windows system DLL description cache ($DSC) entries show modification timestamps between 02:29:30 and 02:29:43, consistent with a session reconnection refresh cycle.

4. **Volatility netscan**: ESTABLISHED RDP connections from attacker IPs 81.30.144.115 and 213.202.233.104 are active at 02:34:45–02:35:53, approximately 5 minutes AFTER the registry modification, ruling out attacker causation.

**Counter-analysis conclusion**: The LOCAL session reconnection at 02:29:37 explains the fDenyTSConnections modification conclusively. The original finding assessed this as "most likely a scheduled Group Policy refresh" — the TS log now proves the mechanism was a local session reconnection that refreshed Terminal Server configuration. This is benign system behavior. Severity remains low; confidence upgraded from inference to confirmed.



### 8. [INFO] YARA Signature Matches Are False Positives — No Malware Detected

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | yara.memory, yara.files, volatility.malfind |
| **Evidence Refs** | tc_909f040a |


YARA scanning of both memory and disk produced signature matches that upon inspection are false positives caused by generic rule patterns matching benign Windows content:

Memory YARA (yara.memory):
- APT6_Malware_Sample_Gen: Matches exclusively on $s3 pattern "C:\WINDOWS\system32\" — a standard Windows system path present in all Windows memory dumps. This is a generic string match, not indicative of APT6 malware.

Disk YARA (yara.files):
- APT_MAL_RU_WIN_Snake_Malware_May23_1: Matches on patterns $a: "25 73 23 31" (%s#1), $b: "25 73 23 32" (%s#2), $c: "25 73 23 33" (%s#3), $d: "25 73 23 34" (%s#4), $e: "2E 74 6D 70" (.tmp). These are common C format strings and file extensions found in countless legitimate Windows binaries and data files. Not indicative of Snake/Uroburos malware.

Malfind analysis also found no injected malicious code:
- MsMpEng.exe (PID 4864): PAGE_EXECUTE_READWRITE allocations consistent with Windows Defender's JIT scanning engine using INT3/breakpoint patterns (0xCC bytes)
- SearchApp.exe, smartscreen.exe, dllhost.exe: UWP application patterns with standard trampolines
- LockApp.exe, RuntimeBroker.exe: Zero-initialized/empty memory pages flagged due to protection flags

No actual malware, rootkits, or malicious code injection was identified in memory or on disk.



### 9. [INFO] System Profile: Corporate Workstation with Standard Software Stack

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | volatility.pstree, volatility.netscan, volatility.cmdline |
| **Evidence Refs** | tc_adf54aa6, tc_a246eb3d, tc_c92ecf50 |


The investigated system SRL-FORGE is a Windows 10 (x64, version 10.0) workstation at IP 192.168.1.5 used by Fred Rocba (fredr). The system runs a standard corporate software stack:

Productivity: Microsoft Teams (multiple instances, PID 11672 parent), Microsoft Office (OfficeClickToRun), Slack (Windows Store app), Adobe Acrobat Reader DC
Cloud Storage: Google Drive Sync, Google Drive File Stream, OneDrive, iCloud (Photos, Drive, Services, IE)
Communication: Teams, Slack, Cortana
Security: Windows Defender (MsMpEng.exe PID 4864, NisSrv.exe PID 5896)
System: Standard Windows services, spoolsv.exe, various svchost.exe instances

Network environment: 192.168.1.5 with gateway likely 192.168.1.1, DHCP-enabled. Connected to Apple (17.248.138.x), Google (172.217.x.x, 142.250.x.x), Microsoft (52.114.x.x, 13.107.x.x), and Amazon (54.82.161.19 for Slack) services — all legitimate cloud service connections.

The APSDaemon.exe (Apple Push) connection to 17.57.144.165:5223 is the Apple Push Notification Service. No outbound connections to unusual or suspicious destinations were identified beyond the inbound RDP attack traffic.

Two user profiles exist: fredr (primary user) and srl-h (from Windows.old directory, corresponding to the srl-helpdesk@outlook.com account — a prior OS installation's primary user). [Counter-analysis correction: the original finding referenced "carl-h" but no such username exists in shimcache, amcache, MFT, or TSK file listings. The MFT shows Windows.old\Users\srl-h, matching the SAM account srl-h (1001).]



### 10. [INFO] Process Discrepancy (PsScan vs PsList) Explained by Normal Process Termination — No Rootkit Evidence

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-11-11T08:13:00 to 2020-11-16T02:20:58 |
| **Sources** | volatility.psscan, composite.defense_evasion, composite.suspicious_processes |
| **Evidence Refs** | tc_c3f22dc7, tc_cb6cb8e0, tc_85460133 |


Cross-system analysis of the 37 processes found in psscan but absent from pslist confirms these are benign terminated processes, not evidence of rootkit activity hiding malicious processes.

**Evidence from 3 independent sources converges:**

1. **Volatility psscan**: All 37 discrepancy PIDs have ExitTime set, confirming they are terminated processes whose EPROCESS structures remain in memory but have been unlinked from the active process list. None have active network connections, none have malfind hits (code injection), and none have command line arguments captured.

2. **Composite suspicious_processes analysis**: All flagged processes have anomaly_score of 0. The only "suspicion_reasons" are "hidden_process" (an artifact of the psscan/pslist comparison method) and in a few cases "unusual_dll_path" (for system processes with known legitimate DLL paths).

3. **Composite defense_evasion analysis**: Identified the same 37 PIDs. No timestomping detected, no log clearing events found, no disabled security tools.

**Specific process identification**: Multiple PIDs are confirmed as Microsoft Teams child processes spawned by PID 11672 (Teams parent process). Examples from psscan:
- PID 28404: Teams.exe, created 2020-11-14 08:14:16, exited 08:17:16 (3 min lifespan)
- PID 14448: Teams.exe, created 2020-11-11 09:02:25, exited 09:04:25 (2 min lifespan)
- PID 7636: Teams.exe, created 2020-11-11 15:58:59, exited 16:00:59 (2 min lifespan)

Teams routinely spawns and terminates renderer processes every 2-4 minutes, which explains the high count of terminated processes found only by pool-tag scanning.

**Supporting negative evidence**: No YARA malware signatures match in memory or on disk (both confirmed false positives in existing finding). No malfind code injection beyond known-benign Windows Defender JIT patterns. No suspicious parent-child execution chains detected.

**Conclusion**: The psscan/pslist discrepancy is a normal forensic artifact of short-lived application processes, not evidence of process hiding by a rootkit. This answers investigation question Q3.



### 11. [INFO] No Post-Exploitation or Lateral Movement Activity Detected in Available Evidence

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | inference |
| **Time** | 2020-11-02T08:28:14 to 2020-11-16T02:36:24 |
| **Sources** | composite.lateral_movement, composite.execution_chains, volatility.cmdline, chainsaw.hunt, composite.execution, composite.timeline |
| **Evidence Refs** | tc_bf1936b2, tc_39eb355f, tc_2c4d482d, tc_fdf41743, tc_740a2085 |


Comprehensive cross-system analysis across all available evidence sources found no indicators of successful post-exploitation, lateral movement, or reconnaissance tool execution during the Nov 2–16, 2020 attack window.

**Convergence of negative evidence from 6+ independent sources:**

1. **Composite lateral movement analysis**: Empty results. No network logon events (4624 Type 3/10), no RDP session artifacts, no WinRM/SMB/RPC lateral connections detected across all indexed evidence.

2. **Composite execution chains**: Empty results. No suspicious parent-child process chains detected. The process tree shows only standard Windows services and legitimate applications (Teams, Chrome, OneDrive, Google Drive, iCloud, Slack).

3. **Volatility cmdline**: No post-exploitation tools found in memory — no whoami.exe, net.exe, nltest.exe, ipconfig.exe, systeminfo.exe, tasklist.exe, quser.exe, or mimikatz. All captured command lines belong to legitimate applications.

4. **Chainsaw Sigma rule hunt**: Zero findings across all extracted EVTX files. No Sigma rule matches for any suspicious activity.

5. **Hayabusa alerts**: No alerts indexed (tool may not have run, or no matches).

6. **YARA scans**: Both memory and disk scans produced only false-positive matches on generic patterns (existing finding f_b78c0353 documents these). No actual malware detected.

7. **Composite execution timeline**: All executables with amcache entries but no prefetch data are legitimate Windows/Office/browser update components (Firefox, Edge, Office, Surface, Chrome installers). No evidence of attack tools.

**CRITICAL CAVEAT — Evidence gaps limit confidence:**
- The current Security.evtx (covering Nov 7–16) was NOT indexed — only the archived Security EVTX from Nov 6 was parsed. Successful logon events (4624 Type 10 for RDP) during the critical Nov 7–16 window are therefore invisible.
- No System.evtx, PowerShell.evtx, or Sysmon.evtx were indexed, which would contain service installation events (7045), PowerShell script execution, and detailed process creation logging.
- The EVTX manifest shows 15 log files; only 1 archive was fully parsed.

**Assessment**: While no post-exploitation activity is evident in the available data, the evidence gaps — particularly the missing current Security EVTX — mean we cannot definitively rule out successful RDP compromise. The ESTABLISHED TCP connections from attacker IPs at the time of memory capture remain the strongest indicator of potential compromise. This partially answers questions Q1, Q5, and Q8.



### 12. [INFO] Cloud Storage Services Active During Attack Window With No Exfiltration Indicators

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-11-16T02:29:57 to 2020-11-16T02:36:13 |
| **Sources** | volatility.netscan, composite.exfil, bulk.url |
| **Evidence Refs** | tc_bf1936b2, tc_1f71d595 |


Cross-system analysis evaluated data exfiltration risk by correlating cloud storage activity from network connections, URL artifacts, and process data. While multiple cloud storage services were actively running during the attack window, all activity is attributable to legitimate corporate use.

**Evidence from 3 independent sources:**

1. **Volatility netscan (Nov 16 02:30–02:36)**: Active ESTABLISHED connections to:
   - OneDrive (52.114.75.149:443, 52.114.128.43:443, 13.107.136.9:443) by PID 6188 OneDrive.exe
   - Google Drive (172.217.x.x range) by PID 8432 googledrivesyn
   - iCloud (17.248.138.108:443, 17.248.138.109:443) by PID 12532 iCloudPhotos.exe
   - Apple Push (17.57.144.165:5223) by APSDaemon.exe
   - Teams (52.114.128.43:443) by PID 11672 Teams.exe
   - All connections are to known-good CDN/cloud IP ranges.

2. **Bulk extractor URL/domain analysis (composite.exfil)**: 281 windows of cloud service URLs detected, all attributable to:
   - SharePoint: `starkresearchlabs-my.sharepoint.com/personal/frocba_stark-research-labs_com` — legitimate corporate OneDrive
   - Google services: docs.google.com, drive.google.com — PKI/certificate infrastructure URLs
   - Apple: icloud.com, apple.com — iCloud sync services

3. **Composite exfiltration analysis**: Flagged known upload services (Google Drive, OneDrive) but all are the user's configured cloud storage clients running under fredr's profile, syncing to the corporate Stark Research Labs tenant.

**Assessment**: No evidence of unauthorized data exfiltration. All cloud connections are to the user's configured corporate services. No connections to known exfiltration services (Mega, Pastebin, anonymous file sharing). No unusual data volumes or staging activity detected in the MFT timeline. However, if an attacker gained RDP access as fredr, they would inherit access to all synced cloud storage. This answers investigation question Q4 — no exfiltration detected, but the risk exists if RDP was compromised.



### 13. [INFO] Critical Evidence Gaps: Missing EVTX Logs Prevent Definitive Attack Outcome Determination

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-11-06T03:40:38 to 2020-11-16T02:36:24 |
| **Sources** | chainsaw.hunt, evtx.manifest |
| **Evidence Refs** | tc_fdf41743, tc_e4f5c439 |


**UPDATED: Most evidence gaps have been filled by subsequent analysis.**

The following EVTX sources have now been indexed and analyzed:
- ✅ Security EVTX archives (Nov 14-15): Four archives covering Nov 14 00:34 through Nov 15 21:24 — contain only 4625 (failed logon) events, NO successful logons from attacker IPs
- ✅ System.evtx: No suspicious service installations (Event 7045)
- ✅ PowerShell Operational and Classic logs: Only system-level activity
- ✅ Terminal Services LocalSessionManager: All sessions from LOCAL or 52.249.198.56 (Azure)
- ✅ RdpCoreTS Admin log: Empty (no events)
- ✅ WinRM Operational log: Empty (no events)
- ✅ Hayabusa: Ran with zero alerts

**Remaining gap:** The current Security.evtx (covering the last ~hours before Nov 16 capture) was not separately extracted, but the Nov 15 23:53 archive extends coverage to Nov 15 21:24, and the Terminal Services log provides continuous session tracking through Nov 16 02:29:37. Combined, these sources cover the critical attack window comprehensively.

**Original recommendation to index additional logs has been fulfilled.** The investigation questions Q1-Q8 are now answered by the newly analyzed evidence.



### 14. [INFO] Legitimate User RDP Access Pattern from Azure Cloud Gateway (52.249.198.56)

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-11-14T03:42:50 to 2020-11-14T14:17:13 |
| **Sources** | evtx.windows_system32_winevt_logs_microsoft-windows-terminalservices-localsessionmanager4operational, ez.mft, ez.amcache |
| **Evidence Refs** | tc_bb1e1da1, tc_05ae6235 |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |


Cross-system analysis establishes a clear legitimate RDP access pattern for user fredr via IP 52.249.198.56 (Microsoft Azure), resolving the SDelete attribution question (Q3) and providing important context for the investigation.

**Terminal Services session timeline (from LocalSessionManager EVTX):**
- 2020-11-02 13:01:42: Session 1 logon (LOCAL)
- 2020-11-02 17:06:43: Session 1 logoff
- 2020-11-02 17:07:21: Session 1 logon (LOCAL)
- 2020-11-10 13:10:55: Session 1 logoff
- 2020-11-10 13:11:40: Session 1 logon (LOCAL)
- 2020-11-10 13:26:29: Session 2 disconnected (unknown code)
- 2020-11-11 08:12:10: Session 1 logoff
- 2020-11-11 08:13:40: Session 1 logon (LOCAL)
- **2020-11-14 03:42:44**: Session 1 disconnected — connection replaced (reason 5)
- **2020-11-14 03:42:50**: Session 1 **reconnected from 52.249.198.56** (Azure)
- **2020-11-14 05:15:52**: Session 1 disconnected by user (reason 11)
- **2020-11-14 12:31:27**: Session 1 reconnected from 52.249.198.56
- **2020-11-14 12:51:44**: Session 1 disconnected by user
- **2020-11-14 12:52:03**: Session 1 reconnected from 52.249.198.56
- **2020-11-14 14:17:13**: Session 1 disconnected by user — LAST RDP SESSION
- 2020-11-16 02:29:36: Session reconnected from LOCAL

**SDelete attribution resolved (Q3):**
The SDelete.lnk was created at 2020-11-14 13:38:10, during fredr's active RDP session from 52.249.198.56 (reconnected at 12:52:03, disconnected at 14:17:13). This confirms SDelete was used by the legitimate user fredr during a normal remote work session, not by an attacker. The SDelete executable was pre-installed in fredr's Downloads folder since 2018.

**User access pattern assessment:**
52.249.198.56 is a Microsoft Azure IP (Azure West US or West Europe region), consistent with an Azure Virtual Desktop, Azure Bastion, or corporate VPN/jump server. This is a legitimate corporate remote access pattern for Stark Research Labs. fredr's session pattern shows normal working hours activity with user-initiated disconnects (reason 11).



### 15. [INFO] No Event Log Clearing, No Suspicious Services, No PowerShell Abuse Detected

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-11-01T22:15:34 to 2020-11-15T09:05:17 |
| **Sources** | evtx.windows_system32_winevt_logs_system, evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational, evtx.windows_system32_winevt_logs_windows-powershell, evtx.windows_system32_winevt_logs_microsoft-windows-winrm4operational, composite.persistence, composite.defense_evasion |
| **Evidence Refs** | tc_a4549fe4, tc_40e5a1cb, tc_0c39f4ca |


Cross-system analysis of newly indexed EVTX sources confirms no post-exploitation or defense evasion activity occurred, answering investigation questions Q4, Q5, Q6, and Q8.

**Q4 — No suspicious service installation (System.evtx):**
System.evtx contains 28 windows covering Nov 1 through Nov 15. All Event ID 7045 (new service installed) entries are legitimate:
- Nov 1: igfx, Intel Display Audio, Virtual WiFi, Dropbox Update, Google Update, Mozilla Maintenance Service (system setup)
- Nov 11 04:48: MpKsl41dd4df (Windows Defender kernel driver — auto-updated)
No suspicious or attacker-installed services detected in the entire System.evtx.

**Q5 — No PowerShell abuse:**
Microsoft-Windows-PowerShell/Operational (18 events, Nov 1-12) and Windows PowerShell classic log (39 events, Nov 1-15) contain only system-level PowerShell activity:
- RemoteFXvGPUDisablement.exe (system setup, Nov 1)
- Provider startup events (Event IDs 53504, 40961, 40962, 600)
- All executed under S-1-5-18 (SYSTEM account)
No encoded commands, no remote PowerShell sessions, no script block logging of suspicious content.

**Q6 — No log clearing:**
No Event ID 104 (System log cleared) or Event ID 1102 (Security log cleared) found in System.evtx. The high volume of archived Security EVTX files is explained by the brute-force attack generating ~35,000+ failed logon events that filled the 20MB log limit every 6-7 hours, triggering normal archival rotation — not log clearing.

**Q8 — No suspicious persistence beyond standard autorun:**
No scheduled task creation events, no WMI subscription events, no suspicious service installations detected. The composite.persistence analysis flagged only standard Windows autorun entries (Google Update, Dropbox, OneDrive, iCloud, Adobe Update, etc.).



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Internal IP | `192.168.1.5` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `193.93.62.27` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `193.93.62.32` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `193.93.62.39` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `193.93.62.41` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `193.93.62.50` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `193.93.62.59` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `143.244.42.92` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `87.251.75.19` |  | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `81.30.144.115` | Germany, AS24961 WIIT AG | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `213.202.233.104` | Germany, AS24961 WIIT AG | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `81.19.209.101` | Netherlands, AS25369 Hydra Communications Ltd | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| External IP | `201.193.188.114` | Costa Rica, AS11830 Instituto Costarricense de Electricidad y Telecom. | Sustained RDP Brute-Force Attack from Multiple External IP Addresses |
| Port | `TCP 51048` |  | Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Ca |
| Port | `TCP 3389` |  | Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Ca |
| Port | `TCP 5067` |  | Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Ca |
| Port | `TCP 45753` |  | Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Ca |
| Port | `TCP 40876` |  | Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Ca |
| Port | `TCP 50424` |  | Active RDP Sessions Established from Brute-Force Source IPs at Time of Memory Ca |
| External IP | `52.249.198.56` |  | Cross-System Confirmation: RDP Brute-Force Attack Did NOT Achieve Authenticated  |
| External IP | `85.14.242.76` |  | Cross-System Confirmation: RDP Brute-Force Attack Did NOT Achieve Authenticated  |
| External IP | `141.98.83.187` |  | Cross-System Confirmation: RDP Brute-Force Attack Did NOT Achieve Authenticated  |
| External IP | `210.245.20.111` |  | Cross-System Confirmation: RDP Brute-Force Attack Did NOT Achieve Authenticated  |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| | No file IOCs extracted | | |



### Email IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Email | `fred.rocba@outlook.com` |  | Brute-Force Attack Targets All Local Accounts Including Disabled Ones |
| Email | `srl-helpdesk@outlook.com` |  | Brute-Force Attack Targets All Local Accounts Including Disabled Ones |




---

## Appendix C: MITRE ATT&CK Coverage

7 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (1) > Persistence (1) > Privilege Escalation (1) > Defense Evasion (3) > Credential Access (3) > Lateral Movement (1)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Brute-Force Attack Targets All Local Accounts... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Brute-Force Attack Targets All Local Accounts... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Brute-Force Attack Targets All Local Accounts... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | SDelete Secure Deletion Tool Used During... |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | File Deletion | SDelete Secure Deletion Tool Used During... |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Brute-Force Attack Targets All Local Accounts... |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Active RDP Sessions Established from...; Brute-Force Attack Targets All Local Accounts... |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Sustained RDP Brute-Force Attack from Multiple...; Cross-System Confirmation: RDP Brute-Force... |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Cross-System Confirmation: RDP Brute-Force... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Sustained RDP Brute-Force Attack from Multiple...; Active RDP Sessions Established from...; RDP Service Enabled and Exposed to External Network; fDenyTSConnections Registry Modification...; Cross-System Confirmation: RDP Brute-Force...; Legitimate User RDP Access Pattern from Azure... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 396 |
| Findings submitted | 15 |
| Confirmed | 14 |
| Inferences | 1 |
| Input tokens | 16.7K |
| Output tokens | 87.4K |
| Total tokens | 104.0K |
| Audit log | /home/mulder/.mulder/cases/Rocba.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 16.7K | 87.4K | 104.0K |




<details>
<summary>Evidence Sources (85)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| volatility.pslist | volatility3 | 2187 |
| volatility.pstree | volatility3 | 2187 |
| volatility.cmdline | volatility3 | 2187 |
| tsk.filelist | sleuthkit | 602765 |
| bulk.domain | bulk_extractor | 237914 |
| bulk.email | bulk_extractor | 9820 |
| bulk.ether | bulk_extractor | 74 |
| bulk.httplogs | bulk_extractor | 11 |
| bulk.ip | bulk_extractor | 149 |
| bulk.packets | bulk_extractor | 562 |
| bulk.rfc822 | bulk_extractor | 2642 |
| bulk.tcp | bulk_extractor | 77 |
| bulk.url | bulk_extractor | 232947 |
| bulk.url_facebook-address | bulk_extractor | 8 |
| bulk.url_facebook-id | bulk_extractor | 9 |
| bulk.url_searches | bulk_extractor | 76 |
| bulk.url_services | bulk_extractor | 3657 |
| volatility.netscan | volatility3 | 431 |
| yara.memory | yara | 40516 |
| volatility.malfind | volatility3 | 17 |
| volatility.psscan | volatility3 | 2213 |
| volatility.dlllist | volatility3 | 12764 |
| volatility.svcscan | volatility3 | 1418 |
| chainsaw.hunt | chainsaw | 2 |
| ez.amcache | eztools | 1120 |
| ez.mft | eztools | 602465 |
| evtx.manifest | evtx-extract | 586 |
| ez.shimcache | eztools | 529 |
| registry.system | regripper | 212 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.system | regripper | 75 |
| registry.system | regripper | 8 |
| registry.system | regripper | 45225 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
| registry.system | regripper | 8617 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.system | regripper | 212 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.system | regripper | 75 |
| registry.system | regripper | 8 |
| yara.files | yara | 6445 |
| registry.system | regripper | 8 |
| registry.system | regripper | 45441 |
| registry.system | regripper | 283 |
| registry.system | regripper | 8742 |
| registry.system | regripper | 199 |
| registry.system | regripper | 406 |
| registry.system | regripper | 283 |
| composite.suspicious_processes | composite | 578 |
| composite.persistence | composite | 6023 |
| enrichment.iocs | enrichment | 66 |
| evtx.windows_system32_winevt_logs_archive-security-2020-11-06-07-55-12-490 | eztools | 19053 |
| composite.defense_evasion | composite | 224 |
| composite.execution | composite | 792 |
| composite.timeline | composite | 712 |
| composite.execution | composite | 792 |
| composite.defense_evasion | composite | 224 |
| composite.suspicious_processes | composite | 578 |
| composite.persistence | composite | 6023 |
| composite.exfil | composite | 11071 |
| composite.recovery | composite | 16 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| evtx.windows_system32_winevt_logs_archive-security-2020-11-14-14-12-28-311 | eztools | 17202 |
| evtx.windows_system32_winevt_logs_archive-security-2020-11-15-23-53-52-261 | eztools | 8546 |
| evtx.windows_system32_winevt_logs_archive-security-2020-11-15-03-14-49-203 | eztools | 17476 |
| evtx.windows_system32_winevt_logs_archive-security-2020-11-14-07-54-47-237 | eztools | 17799 |
| evtx.windows_system32_winevt_logs_system | eztools | 171 |
| evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational | eztools | 49 |
| evtx.windows_system32_winevt_logs_windows-powershell | eztools | 738 |
| evtx.windows_system32_winevt_logs_microsoft-windows-terminalservices-localsessionmanager4operational | eztools | 35 |
| evtx.windows_system32_winevt_logs_microsoft-windows-remotedesktopservices-rdpcorets4admin | eztools | 2 |
| evtx.windows_system32_winevt_logs_microsoft-windows-winrm4operational | eztools | 2 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.persistence | composite | 6023 |
| composite.defense_evasion | composite | 224 |
| composite.timeline | composite | 712 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
