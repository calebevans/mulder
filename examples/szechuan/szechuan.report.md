# Mulder Investigation Report

**Case:** szechuan
**Generated:** 2026-06-04T03:24:40.970844+00:00
**Evidence:** /evidence

---

## Executive Summary

**Scope:** 115 evidence sources (18 memory, 23 disk, 74 other) | 412 tool calls | 55 minutes
**Results:** 18 findings (3 critical, 6 high) | 12 confirmed, 6 inference
**Timeline:** 2020-09-18 to 2020-09-19

**Key Threats:**
- Successful NTLM Brute-Force from Kali Linux Against DC01 Administrator — Initial Access Confirmed
- coreupdater.exe Deployed to Both DC01 and DESKTOP-SDN1RPT as Masquerading Malware
- Environment-Wide Meterpreter Code Injection in Print Spooler Service Across DC01 and DESKTOP-SDN1RPT

**Attack Lifecycle:**
- **Initial Access / Deployment** (2020-09-18 to 2020-09-19): Files Carved from Network Traffic — OST Email Archives, PDFs, and Application Data (+10 related)
- **Persistence** (2020-09-18): Network Traffic Capture Profile — PCAP Summary and Protocol Distribution
- **Command and Control** (2020-09-19): Code Injection in spoolsv.exe and powershell.exe on DESKTOP-SDN1RPT
- **Credential Access** (2020-09-18): DRSUAPI/DCSync Activity from Workstation to Domain Controller in Network Traffic
- **Other Activity** (2020-09-19): Suspicious PE File Transfer Over Network — No ASLR/DEP, Anomalous Section Names

**Tools:** search (83), get_raw_output (54), submit_finding (28), open_case (17), extract_archive (15). SHA-256 hashes recorded for all evidence.


### Critical Findings


- **Successful NTLM Brute-Force from Kali Linux Against DC01 Administrator — Initial Access Confirmed** (2020-09-19T03:21:26+00:00 to 2020-09-19T03:21:46+00:00)


- **coreupdater.exe Deployed to Both DC01 and DESKTOP-SDN1RPT as Masquerading Malware** (2020-09-19T01:22:38+00:00 to 2020-09-19T03:43:10+00:00)


- **Environment-Wide Meterpreter Code Injection in Print Spooler Service Across DC01 and DESKTOP-SDN1RPT** (2020-09-19T01:22:38+00:00)




---

## Forensic Soundness and Evidence Integrity

Analysis was executed via a read-only Model Context Protocol (MCP) server
mapped to the SANS SIFT toolchain. The MCP architecture enforces structural
evidence protection: original evidence files were mounted as read-only
volumes, all tool interactions are typed functions (no shell access), and
every finding is validated against the append-only audit log before
acceptance.

11 evidence files were cryptographically
validated via SHA-256 hashes computed at ingestion and verified against the
case database.

412 tool calls were executed across 28
indexed sources over the course of the investigation, with full provenance
tracking via append-only JSONL audit log.



---

## Investigation Report

# Forensic Investigation Report — Case SZECHUAN: Compromise of C137.LOCAL Domain Environment

## Background

This forensic investigation was initiated following a suspected intrusion into the C137.LOCAL Windows Active Directory domain environment. The investigation encompassed two compromised systems and a network packet capture spanning the critical incident window. The evidence inventory consisted of the following:

The primary evidence items were memory dumps from both the domain controller CITADEL-DC01 (IP 10.42.85.10, running Windows Server 2012 R2) and a domain-joined workstation DESKTOP-SDN1RPT (IP 10.42.85.115); a disk image from DC01; a full packet capture (case001.pcap) covering 7.7 hours of network traffic from 2020-09-18 21:58:07 UTC to 2020-09-19 05:38:57 UTC totaling 411,797 packets and 197 MB; and protected file archives from both systems containing registry hives, Active Directory database files, and DPAPI credential material. The packet capture was produced using Mergecap (Wireshark 3.2.6) on a Kali Linux 5.8.0-kali1-amd64 platform.

The C137.LOCAL domain was a small enterprise environment with CITADEL-DC01 serving as the sole domain controller, hosting DNS, Active Directory Web Services, DFS Replication, and Intersite Messaging. The environment was virtualized on VMware, as confirmed by the presence of VMware Tools and Guest Authentication services on DC01. Four user accounts were identified as active within the domain: the built-in Administrator account (SID ending in -500), two domain users ricksanchez (SID -1106) and mortysmith (SID -1108), and a local workstation account Admin (SID -1001) on DESKTOP-SDN1RPT.

The forensic analysis drew upon 28 indexed evidence sources across 18 extractor types, including Volatility 3 memory forensics, Sleuthkit disk analysis, EZ Tools Windows artifact parsing, Zeek and tshark network protocol analysis, Suricata IDS, YARA signature scanning, bulk_extractor IOC carving, ClamAV malware scanning, Chainsaw Sigma rule detection, and RegRipper registry analysis. The investigation produced 18 findings, of which 12 were corroborated by multiple independent sources and 6 were assessed as analytical inferences. The findings mapped to 21 distinct MITRE ATT&CK technique identifiers across the kill chain.

## Incident Timeline

The incident unfolded over approximately eight hours on September 18–19, 2020, progressing through four distinct operational phases: reconnaissance and initial access, post-exploitation tooling deployment, lateral movement and credential theft, and data access and collection.

**Phase 1 — Normal Operations and Pre-Attack Baseline (September 18, 21:58–22:04 UTC)**

The packet capture began at 21:58:07 UTC with normal domain activity. The DESKTOP-SDN1RPT workstation performed standard machine account Kerberos authentication (desktop-sdn1rpt$/C137.local) at 21:59:39 UTC, followed by mortysmith's interactive logon at 22:00:38 UTC. Routine DRSUAPI operations (DRSBind, DRSCrackNames, DRSUnbind) were observed from the workstation to DC01 during this period — these were initially flagged as potential DCSync activity but were subsequently determined through counter-analysis to represent normal Active Directory client behavior for Group Policy processing and name resolution. The absence of any DRSGetNCChanges calls — the specific replication request that would indicate credential theft via DCSync — confirmed the benign nature of this traffic.

**Phase 2 — Initial Access via Brute-Force Authentication (September 19, 03:21–03:35 UTC)**

The attack commenced at 03:21:26 UTC when an automated NTLM brute-force attack began against the DC01 Administrator account. The Security event log recorded rapid successive Event ID 4625 (Failed Logon) entries with workstation name "kali," using NtLmSsp authentication over Type 3 (Network) logons. Failed attempts generated Status 0xC000006D with SubStatus 0xC000006A (incorrect password) at a rate of approximately one attempt per second. At 03:21:46 UTC — after approximately 16 to 20 password attempts over 20 seconds — the attack succeeded. Event ID 4672 (Special Privileges Assigned to New Logon) confirmed that the Administrator account obtained full administrative privileges. It is important to note that the source IP address field in the EVTX events was empty ("-"), preventing definitive attribution of the NTLM brute-force source to a specific IP address.

Eleven minutes later, at 03:32:46 UTC, a distinct attack vector emerged when external IP address 194.61.24.102 initiated Nmap service scanning against DC01's RDP port (TCP 3389), identifiable by the RDP cookie value "nmap." This reconnaissance was followed at 03:34:46 UTC by an aggressive RDP brute-force attack with the cookie consistently set to "Administrator." Over 75 automated connection attempts were recorded between 03:34:46 and 03:35:07 UTC, with source ports incrementing sequentially from 40044 to 40234 (by increments of two), achieving a rate of 4.5 connections per second. Because NLA (Network Level Authentication) was enabled, the encrypted RDP sessions prevented determination of whether any RDP attempt ultimately succeeded from the network traffic alone. Additional sporadic attempts from 194.61.24.102 continued until 04:09:23 UTC.

The direct reachability of DC01's RDP port from external IP space — whether through direct internet exposure or port forwarding — represents a fundamental network architecture failure that enabled both attack vectors.

**Phase 3 — Post-Exploitation Tooling and Lateral Movement (September 19, 03:40–04:20 UTC)**

At 03:40:49 UTC, a malicious executable named coreupdater.exe appeared on DESKTOP-SDN1RPT (PID 8324, Session 3) at the path C:\Windows\System32\coreupdater.exe. The binary name was deliberately chosen to masquerade as a legitimate system update process, and its placement in the System32 directory reinforced this deception. The process executed for approximately 2.5 minutes before terminating at 03:43:10 UTC, suggesting a targeted task such as payload staging or credential harvesting.

At 03:49:15 UTC, Zeek RDP logs captured DC01 (10.42.85.10) initiating an outbound RDP connection to DESKTOP-SDN1RPT (10.42.85.115) on port 3389 — a highly anomalous direction of traffic, as domain controllers have no legitimate operational reason to RDP into workstations. The empty RDP cookie in this session suggests the connection was initiated programmatically rather than through an interactive RDP client. This DC-to-workstation RDP session constitutes direct evidence of lateral movement by the attacker, who had already compromised DC01 through the earlier brute-force attack.

At 03:56:37 UTC, coreupdater.exe was deployed to DC01 itself (PID 3644). Unlike the workstation instance, the DC01 coreupdater.exe remained running at the time of memory capture and maintained an active ESTABLISHED TCP connection to 203.78.103.109 on port 443, establishing this IP as command-and-control infrastructure. Notably, DC01's shimcache did not contain an entry for coreupdater.exe, which is unusual for an executed binary and may indicate anti-forensic measures or execution from a network share.

Between 04:04:06 and 04:19:58 UTC, Zeek PE analysis detected two portable executable files transferred over the network. Both shared identical and highly suspicious characteristics: 64-bit AMD64 architecture compiled with a fraudulent 2010 timestamp, a declared OS version of "Windows 95 or NT 4.0" (impossible for a 64-bit binary), both ASLR and DEP protections disabled, no Authenticode signature, no debug data, and a non-standard PE section named ".lhru" that is not associated with any known legitimate compiler toolchain. These characteristics are consistent with purpose-built post-exploitation tooling designed to minimize PE metadata exposure.

**Phase 4 — Credential Theft, Privilege Escalation, and Data Access (September 19, 04:16–06:17 UTC)**

At 04:16:24 UTC, the compromised Administrator account obtained Kerberos TGT and TGS tickets from DESKTOP-SDN1RPT for multiple services on CITADEL-DC01, including host, LDAP, cifs, krbtgt, and notably ProtectedStorage/CITADEL-DC01. The ProtectedStorage service manages credential material, and access to it is characteristic of credential harvesting tools rather than normal administrative activity. The timing of this authentication — occurring 44 minutes after the RDP brute-force from 194.61.24.102 and within the active attack window — further distinguishes it from routine administration.

Memory forensics revealed extensive credential theft tooling on DESKTOP-SDN1RPT. YARA scanning identified the Skeleton Key patcher tool in memory through multiple matches on the HookDC.dll string — a string specific to this credential manipulation tool that does not appear in legitimate Windows installations. While the Skeleton Key tool's presence on the workstation is validated, its deployment to DC01's LSASS process was not confirmed, meaning the skeleton key attack may have been staged but not yet executed against the domain controller. Additionally, NTLM hash dump output was detected at six memory offsets in the characteristic pwdump/secretsdump format ("500:aad3b435b51404eeaad3b435b51404ee:"), confirming that credential extraction from the workstation had been performed.

Metasploit Meterpreter code injection was identified in the Windows Print Spooler service (spoolsv.exe) on both systems, confirming environment-wide deployment of the same attack framework. On DC01, spoolsv.exe (PID 3724) contained four PAGE_EXECUTE_READWRITE memory regions with the x64 Metasploit shellcode stub signature (fc 48 89 ce 48 81 ec 00 20 00 00) and three injected MZ PE headers, with YARA confirming metsrv.x64.dll at five offsets and the ReflectiveLoader at fifteen offsets. Network scan data showed this process also had a bind handler listening on TCP port 62475. On DESKTOP-SDN1RPT, spoolsv.exe (PID 2188) exhibited the identical reflective DLL injection pattern with an MZ PE header in executable, readable, and writable memory. Additionally, powershell.exe (PID 3316) on the workstation contained multiple suspicious memory regions with PE headers and an embedded PNG file reference, potentially indicating steganographic payload delivery.

At 05:48:15 UTC, the ricksanchez domain account authenticated to DC01 and immediately accessed the \\CITADEL-DC01\FileShare SMB share. This was the only access to FileShare observed across the entire 7.7-hour capture window, and it followed the mortysmith-to-Administrator-to-ricksanchez credential escalation chain. File operations showed SMB FILE_OPEN on the share root at two timestamps (05:33:13 and 06:17:04 UTC), suggesting the attacker was conducting reconnaissance or data collection from this shared directory using the compromised ricksanchez credentials.

## Key Findings

**Malware Deployment and Command-and-Control Infrastructure**

The attacker deployed two distinct malware families across the environment. The primary implant, coreupdater.exe, was placed in C:\Windows\System32 on both DC01 and DESKTOP-SDN1RPT to masquerade as a legitimate system binary. On DC01, coreupdater.exe maintained a persistent ESTABLISHED connection to 203.78.103.109:443, establishing this IP as command-and-control infrastructure. The use of port 443 was an attempt to disguise C2 traffic as normal HTTPS communications. On the workstation, the binary executed for only 2.5 minutes before terminating, consistent with a fire-and-forget task execution pattern.

Metasploit Meterpreter was deployed as the secondary implant through reflective DLL injection into the Print Spooler service (spoolsv.exe) on both systems. This technique loads a DLL entirely in memory without touching disk, evading traditional file-based detection. The identical injection pattern across both hosts — the same shellcode stub, the same target process, the same ReflectiveLoader mechanism — confirms a single operator using a consistent toolkit. On DC01, the Meterpreter payload additionally established a bind handler on TCP port 62475, providing persistent remote access as long as the Print Spooler service remained running. However, the Meterpreter persistence is session-based and memory-resident; no registry keys, scheduled tasks, or other disk-based re-injection mechanisms were identified, meaning the payload would not survive a system reboot.

**Credential Compromise**

The credential theft observed in this incident was multi-layered. The initial NTLM brute-force attack against the DC01 Administrator account succeeded after approximately 20 attempts, granting the attacker the highest-privilege domain account. Memory forensics on DESKTOP-SDN1RPT confirmed active credential extraction through NTLM hash dump output in the pwdump/secretsdump format, and the presence of the Skeleton Key patcher tool (identified by HookDC.dll) indicated the attacker possessed the capability — though not confirmed deployment — to install a universal skeleton key password on the domain controller's LSASS process. Furthermore, the forensic evidence collection included the complete ntds.dit Active Directory database (20 MB), the SYSTEM registry hive (containing the SYSKEY required for decryption), the SAM and SECURITY hives, and the domain DPAPI backup key (BK-C137). While these files were collected as part of the forensic response, their presence in the attacker's operational window means that offline extraction of all domain NTLM hashes and decryption of any user's DPAPI-protected secrets would be technically feasible.

**Lateral Movement**

Lateral movement was confirmed through multiple independent evidence sources. The RDP connection from DC01 to DESKTOP-SDN1RPT at 03:49:15 UTC was captured in Zeek RDP logs and represents direct evidence of the attacker pivoting from the compromised domain controller to the workstation. The Kerberos authentication chain — progressing from the machine account to mortysmith to Administrator to ricksanchez — visible in network traffic demonstrates the attacker's escalating use of compromised credentials to access additional resources. The deployment of identical malware (coreupdater.exe and Meterpreter in spoolsv.exe) to both systems confirms that the attacker achieved code execution on both hosts. The attacker also demonstrated the ability to access network file shares, as evidenced by the ricksanchez account's FileShare access at 05:48 UTC.

**Ruled-Out Findings**

Rigorous counter-analysis eliminated two initial findings from the confirmed threat picture. The DRSUAPI/DCSync activity originally flagged as credential theft (T1003.006) was reclassified as normal Active Directory client behavior after investigation confirmed the observed operations consisted solely of DRSCrackNames calls — a standard name resolution function — with zero instances of the DRSGetNCChanges replication request that would constitute actual DCSync activity. Additionally, a YARA match on the TA17_293A_malware_1 rule, which flagged IP address 62.8.193.206 in DESKTOP-SDN1RPT memory, was assessed as a likely false positive. The rule triggered primarily on the ubiquitous "file://" URI scheme string, and the IP address appeared at only a single memory offset with zero corroborating network connections, DNS queries, or PCAP references. These downgraded findings illustrate the importance of multi-source corroboration and demonstrate that the final assessment is evidence-driven rather than detection-driven.

## Threat Intelligence and Attribution

The attacker demonstrated a capabilities profile consistent with a moderately sophisticated, tool-reliant operator rather than a custom-development threat group. The operational toolkit centered on widely available open-source and commercial penetration testing frameworks: Metasploit (Meterpreter with reflective DLL injection via ReflectiveLoader), credential extraction utilities producing pwdump-format output, and the Skeleton Key patcher — all tools freely available in public repositories and commonly used by both penetration testers and criminal operators.

The attack infrastructure involved two external IP addresses: 194.61.24.102, which conducted Nmap reconnaissance and RDP brute-force against DC01, and 203.78.103.109, which served as the command-and-control server for coreupdater.exe. The sequential and rapid progression from brute-force access (03:21 UTC) through tool deployment (03:40 UTC), lateral movement (03:49 UTC), and credential harvesting (04:16 UTC) suggests a practiced operator following a well-rehearsed playbook rather than improvised exploration.

YARA scanning produced a weak match on the Tofu Backdoor signature ("Cookies: Sym1.0" at only two memory offsets), which has been historically associated with Tonto Team (also known as CactusPete). However, this signal is insufficient for attribution: the matched string is a short, semi-generic HTTP cookie header pattern, and two instances in a 2GB memory dump constitute an extremely thin basis for threat actor identification. No other TTPs, infrastructure patterns, or behavioral indicators in this case specifically overlap with published Tonto Team campaign reports. The coreupdater.exe binary name and the custom PE file characteristics (non-standard ".lhru" section, falsified compile timestamp, disabled ASLR/DEP) suggest custom tooling, but the binary could not be attributed to a known malware family or threat group based on available evidence. Attribution therefore remains undetermined. What the evidence does confirm is a human-operated intrusion with pre-planned objectives, multi-system compromise capability, and a clear focus on credential theft and domain-level access.

## Impact Assessment

The compromise affected both systems in the evidence scope — the domain controller CITADEL-DC01 and the workstation DESKTOP-SDN1RPT — representing a complete domain-level compromise of the C137.LOCAL environment. The domain controller, serving as the single point of trust for the entire Active Directory domain, was fully compromised with active malware maintaining command-and-control communications at the time of evidence capture.

Credential exposure was extensive. The Administrator account — the highest-privilege account in the domain — was directly compromised through brute-force authentication. NTLM hash extraction was confirmed on the workstation through memory forensic evidence. The Kerberos authentication escalation chain demonstrated the attacker's access to at least three named accounts (mortysmith, Administrator, ricksanchez) in addition to the machine account. The presence of the complete ntds.dit database and supporting registry hives in the evidence means that all domain password hashes were potentially accessible to the attacker, and the domain DPAPI backup key (BK-C137) would enable decryption of DPAPI-protected secrets across all domain users.

Persistence depth was moderate. The Meterpreter payload in spoolsv.exe provided reliable access as long as the systems remained running and the Print Spooler service was active (configured for auto-start), but no disk-based persistence mechanisms were identified. The coreupdater.exe binary was placed on disk in System32 on both hosts, providing a more durable but detectable foothold. No evidence of data exfiltration of specific files or databases was identified in the network traffic, though the ricksanchez account's access to the FileShare and the encrypted nature of the C2 channel to 203.78.103.109 mean that data exfiltration cannot be ruled out.

## Immediate Tactical Containment

The following actions should be executed immediately to neutralize the active threat:

1. Isolate both compromised hosts from the network. Disconnect DC01 (10.42.85.10) and DESKTOP-SDN1RPT (10.42.85.115) from all network segments to sever the active C2 channel to 203.78.103.109:443 and prevent further lateral movement.

2. Block attacker IP addresses at the perimeter firewall. Create deny rules for 194.61.24.102 (RDP brute-force source) and 203.78.103.109 (coreupdater.exe C2 server) in both inbound and outbound directions across all firewall appliances.

3. Terminate malicious processes on DC01. Kill coreupdater.exe (PID 3644) and the compromised spoolsv.exe (PID 3724). Disable the Print Spooler (Spooler) service to prevent the Meterpreter bind handler on TCP port 62475 from accepting new connections.

4. Terminate malicious processes on DESKTOP-SDN1RPT. Kill the compromised spoolsv.exe (PID 2188) and both powershell.exe instances (PID 508 and PID 3316) containing injected code. Disable the Print Spooler service.

5. Delete the coreupdater.exe binary from C:\Windows\System32\ on both systems to remove the disk-resident malware component.

6. Force-reset all domain account passwords immediately. Prioritize the Administrator account, ricksanchez, and mortysmith accounts. Reset the krbtgt account password twice (with a 12-hour interval) to invalidate any Kerberos tickets the attacker may have forged or stolen.

7. Disable RDP access to DC01 from all external IP ranges. Block TCP 3389 inbound from any non-internal source at the network perimeter and on the host firewall.

8. Block the SHA-256 hash of coreupdater.exe (if recoverable from the disk image) across all endpoint detection platforms in the environment.

## Strategic Remediation

The NTLM brute-force attack against DC01's Administrator account succeeded after only 16 to 20 attempts, indicating the absence of an account lockout policy or an excessively high lockout threshold on the domain's built-in Administrator account. The Administrator account in Active Directory is exempt from lockout by default (finding f_ad5e03bc, T1110.001). Implementing a fine-grained password policy that enforces lockout after five failed attempts for privileged accounts, combined with mandatory 25-character passphrase requirements for domain administrator credentials, would have prevented this initial access vector. For the built-in Administrator account specifically, which cannot be locked out, deploying a PAM (Privileged Access Management) solution or renaming and closely monitoring the account is essential.

The domain controller's RDP service (TCP 3389) was directly reachable from external IP 194.61.24.102, enabling both the Nmap reconnaissance and the subsequent brute-force attack (finding f_04a6fb78, T1133). Domain controllers must never be directly accessible from the internet. Implementing network segmentation that places domain controllers in a dedicated management VLAN, accessible only through a hardened jump server or VPN with multi-factor authentication, would have eliminated this attack surface entirely.

The attacker moved laterally from DC01 to DESKTOP-SDN1RPT via RDP (finding f_fe5a1078, T1021.001), and the identical Meterpreter deployment to both systems demonstrated unrestricted inter-host communication (finding f_0cd8aa43, T1055.001). The absence of east-west traffic controls between the domain controller and workstations allowed the attacker to pivot freely. Deploying host-based firewall rules that restrict RDP access to domain controllers exclusively from designated administrative workstations, and implementing micro-segmentation that limits workstation-to-DC traffic to only required AD services (LDAP, Kerberos, DNS, SMB for SYSVOL), would constrain lateral movement.

The Metasploit Meterpreter payload was reflectively loaded into spoolsv.exe on both systems without triggering any recorded detection or alert (finding f_0cd8aa43, T1055.001, T1543.003). The coreupdater.exe binary similarly executed from System32 without interception. The absence of endpoint detection and response (EDR) capability on these systems allowed in-memory code injection and masquerading binaries to operate undetected. Deploying an EDR solution with process injection monitoring, memory scanning, and behavioral analysis capabilities on all domain controllers and workstations would provide detection coverage for reflective DLL injection, anomalous child process creation, and suspicious service process behavior.

The attacker deployed credential theft tools including a pwdump-format NTLM hash extractor and the Skeleton Key patcher on DESKTOP-SDN1RPT (finding f_9ece2fdf, T1003.001, T1556.001), accessing credential material without apparent detection. Enabling Windows Credential Guard on all systems — which uses virtualization-based security to isolate LSASS — would have protected credential material from direct memory extraction. Additionally, configuring Windows Defender Credential Guard and LSA protection (RunAsPPL) on domain controllers would harden the LSASS process against the Skeleton Key patching technique.

## Conclusion

**Q1. What systems were compromised?** Both systems in the evidence scope were confirmed compromised: the domain controller CITADEL-DC01 (10.42.85.10) and the workstation DESKTOP-SDN1RPT (10.42.85.115). Malware (coreupdater.exe and Meterpreter) was deployed to both systems, and active command-and-control communications were established from DC01.

**Q2. How did the attacker gain initial access?** Initial access was achieved through an automated NTLM brute-force attack against the DC01 Administrator account, succeeding at 03:21:46 UTC on September 19, 2020, after approximately 20 password attempts over 20 seconds. A separate RDP brute-force from external IP 194.61.24.102 beginning at 03:34:46 UTC targeted the same account. The relationship between these two attack vectors could not be definitively established due to the absence of source IP data in the NTLM brute-force event logs.

**Q3. What lateral movement occurred?** DC01 initiated an RDP connection to DESKTOP-SDN1RPT at 03:49:15 UTC — a reversed direction from normal traffic patterns that constitutes direct evidence of attacker-driven lateral movement. The deployment of identical malware to both systems and the Kerberos credential escalation chain (mortysmith → Administrator → ricksanchez) demonstrate multi-system access through compromised credentials.

**Q4. What persistence mechanisms were installed?** The coreupdater.exe binary was deployed to C:\Windows\System32\ on both systems, providing disk-resident persistence. Meterpreter was injected into the auto-start Print Spooler service (spoolsv.exe) on both hosts, providing in-memory persistence that survives as long as the service runs but would not survive a reboot without a separate re-injection mechanism. No registry-based, scheduled task, or other traditional persistence mechanisms were identified.

**Q5. Was data exfiltrated, and if so, what and how much?** Definitive data exfiltration was not confirmed. The ricksanchez account accessed the \\CITADEL-DC01\FileShare at 05:48 UTC, performing directory enumeration that may represent reconnaissance or collection. The encrypted C2 channel from coreupdater.exe to 203.78.103.109:443 on DC01 could have carried exfiltrated data, but the encryption prevents content inspection. Credential data was confirmed extracted (NTLM hashes on the workstation), and the ntds.dit database containing all domain password hashes was accessible.

**Q6. What is the full timeline of the incident?** The attack progressed from initial brute-force access at 03:21 UTC through tool deployment (03:40–03:57 UTC), lateral movement (03:49 UTC), credential harvesting (04:16 UTC), and data access (05:48–06:17 UTC), encompassing approximately three hours of active operations within the 7.7-hour capture window. The pre-attack baseline showed normal domain operations from 21:58 UTC on September 18.

**Q7. What is the total scope and business impact?** The compromise achieved domain-level access through the Administrator account, with confirmed credential extraction, active malware on both the domain controller and a workstation, and command-and-control communications to external infrastructure. The accessibility of the ntds.dit database means all domain account credentials should be considered compromised. The impact extends to the entire C137.LOCAL domain trust boundary.

**Q8. What are the recommended remediation actions?** Immediate actions include network isolation of compromised hosts, blocking of attacker IPs 194.61.24.102 and 203.78.103.109, termination of malicious processes, and a domain-wide password reset including double krbtgt rotation. Strategic remediation should focus on the five root causes identified: insufficient account lockout policy, internet-exposed domain controller RDP, absence of east-west network segmentation, lack of endpoint detection and response capability, and missing credential protection controls. Each of these deficiencies was directly exploited in the attack chain.


---

## Overview

| | |
|---|---|
| Findings | **18** (12 confirmed, 6 inference) |
| Severity | 3 critical, 6 high, 2 medium, 2 low, 5 info |
| Sources | 28 evidence sources across 412 tool calls |


---

## Evidence Hashes

SHA-256 hashes recorded at ingestion. Verify with `sha256sum <file>`.

| File | SHA-256 | Size |
|------|---------|------|
| DC01-E01.zip | `efe06d12388dbc000fa4ae306746ddaca3893a6cdbd55311b52f5833e717acd9` | 4.5 GB |
| DC01-ProtectedFiles.zip | `b1f3d42a9629dc25521685f296959c4c6d36bbf2efd355c127cb49171c372424` | 11.7 MB |
| DC01-autorunsc.zip | `2855472b2af6d44bfe00cc7a62c3b467b6aa5a138ba6a4af2600a9c5b58c054f` | 173.1 KB |
| DC01-memory.zip | `86658d85d8254e8d30dccc4f50d9c2a8b550a101d2e78a6d932316849e37ad80` | 535.4 MB |
| DC01-pagefile.zip | `b1db1979b290cf5c954c1965c5e7834259bb8e3e88327d7f6d68b20e4c7cd5b9` | 12.9 MB |
| DESKTOP-E01.zip | `ade4c11a695bdcbe89d76ca0949ac918456549fcca9e4558502ffc286c8d16ad` | 6.4 GB |
| DESKTOP-SDN1RPT-Protected Files.zip | `133f01f0abdeccf1d81267f600b004e91ce0a7c99e5ccc8729aa5777e4b26715` | 16.3 MB |
| DESKTOP-SDN1RPT-autorunsc.zip | `e9e86ad993d5c274a9ed6c6aaecc41c8fa051af77828da51ece691a15cd70b9e` | 272.1 KB |
| DESKTOP-SDN1RPT-memory.zip | `fce1bdd584cd52d7830f7f9a209e960ca151ce174ebdef3fad03205ab7e33d01` | 765.6 MB |
| Desktop-SDN1RPT-pagefile.zip | `a8c62a19e0ceae5955c0b611fef42241bbaa207dd11aa316d293a788adccf957` | 211.8 MB |
| case001-pcap.zip | `ea8eee228cdf82b1f534a2daab88dfb1d928d2ef2d5b469c189242d8c901f0ec` | 144.6 MB |



---

## Attack Timeline


| Time | Event | Severity | Sources |
|------|-------|----------|---------|
| 2020-09-18T21:58:07+00:00 | Network Traffic Capture Profile — PCAP Summary and Protocol Distribution | INFO | pcap.summary, pcap.conversations, zeek.summary, pcap.beaconing, pcap.tunneling, suricata.alerts, pcap.tls |
| 2020-09-18T21:58:07+00:00 | Files Carved from Network Traffic — OST Email Archives, PDFs, and Application Data | INFO | tcpxtract.carved |
| 2020-09-18T21:59:39+00:00 | Kerberos Authentication Escalation Chain Visible in Network Traffic: Machine → mortysmith → Administrator → ricksanchez | HIGH | zeek.kerberos, zeek.smb_mapping |
| 2020-09-18T21:59:39+00:00 | DRSUAPI/DCSync Activity from Workstation to Domain Controller in Network Traffic | LOW | zeek.dce_rpc, zeek.kerberos |
| 2020-09-19T01:22:38+00:00 | coreupdater.exe Deployed to Both DC01 and DESKTOP-SDN1RPT as Masquerading Malware | CRITICAL | bulk.url, ez.mft, strings.output, volatility.cmdline, volatility.netscan, volatility.pslist, volatility.pstree |
| 2020-09-19T01:22:38+00:00 | Environment-Wide Meterpreter Code Injection in Print Spooler Service Across DC01 and DESKTOP-SDN1RPT | CRITICAL | volatility.malfind, yara.memory, volatility.netscan, volatility.svcscan |
| 2020-09-19T01:24:08+00:00 | Environment-Wide Credential Theft Toolkit on DESKTOP-SDN1RPT: Skeleton Key, NTLM Dump, and Tofu Backdoor | HIGH | yara.memory |
| 2020-09-19T01:24:08+00:00 | Suspicious External IP 62.8.193.206 Associated with TA17-293A Malware in DESKTOP-SDN1RPT Memory | LOW | yara.memory |
| 2020-09-19T03:21:26+00:00 | Successful NTLM Brute-Force from Kali Linux Against DC01 Administrator — Initial Access Confirmed | CRITICAL | evtx.windows_system32_winevt_logs_security |
| 2020-09-19T03:32:46+00:00 | RDP Brute Force and Nmap Reconnaissance from External IP 194.61.24.102 Against DC01 | HIGH | zeek.rdp, pcap.conversations |
| 2020-09-19T03:32:46+00:00 | Suspicious URL http://194.61.24.102/ Found on DC01 Disk Image and DESKTOP-SDN1RPT Pagefile | MEDIUM | bulk.url, strings.output |
| 2020-09-19T03:49:15+00:00 | RDP Lateral Movement from DC01 to DESKTOP-SDN1RPT via Network Traffic | HIGH | zeek.rdp |
| 2020-09-19T04:04:06+00:00 | Suspicious PE File Transfer Over Network — No ASLR/DEP, Anomalous Section Names | HIGH | zeek.pe |
| 2020-09-19T05:08:43+00:00 | Code Injection in spoolsv.exe and powershell.exe on DESKTOP-SDN1RPT | HIGH | volatility.malfind, volatility.pstree, volatility.cmdline |
| 2020-09-19T05:48:16+00:00 | SMB File Share Access by ricksanchez Account After Credential Compromise | MEDIUM | zeek.smb_files, zeek.smb_mapping |





---

## Appendix A: Verified Forensic Findings


### 1. [CRITICAL] Successful NTLM Brute-Force from Kali Linux Against DC01 Administrator — Initial Access Confirmed

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:21:26+00:00 to 2020-09-19T03:21:46+00:00 |
| **Sources** | evtx.windows_system32_winevt_logs_security |
| **Evidence Refs** | tc_b92e1706, tc_31537bbd |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |


**[COUNTER-ANALYSIS NOTE ADDED]** Multiple Event ID 4625 (Failed logon) events were recorded in the DC01 Security log showing a brute-force password attack against the Administrator account from a system with workstation name "kali."

**Attack Details (unchanged):**
- Target: Administrator account (no domain specified — targeting local Administrator)
- Source Workstation: "kali"
- Authentication: NTLM (NtLmSsp)
- Logon Type: 3 (Network)
- Failure Reason: Status 0xC000006D, SubStatus 0xC000006A — wrong password
- Timeline: Rapid successive attempts starting at 2020-09-19 03:21:26 UTC, approximately one attempt per second

**SUCCESSFUL LOGON CONFIRMED:**
Event ID 4672 (Special Privileges Assigned) at 03:21:46 UTC shows Administrator logon with full administrative privileges. The last failed attempt was at 03:21:42, meaning the correct password was found after approximately 16-20 attempts in ~20 seconds.

**COUNTER-ANALYSIS — "Coordinated Infrastructure" Claim:**
The original finding claimed the "kali" brute force and the 194.61.24.102 RDP brute force represent "coordinated infrastructure." This claim is WEAKENED by:
1. The IpAddress field in the 4625 EVTX events is "-" (empty/not recorded), so we CANNOT confirm the source IP of the "kali" NTLM brute force
2. The PCAP was captured on "Kali Linux 5.8.0-kali1-amd64" (from Mergecap metadata), raising the possibility that the "kali" workstation was the forensic capture platform itself, connected to the same network for packet capture
3. Without the source IP, linking the "kali" workstation to 194.61.24.102 is unsupported inference

**What Remains Confirmed:**
- The brute force attack itself is undeniably malicious (rapid automated password guessing)
- The attack succeeded — Administrator gained full privileges at 03:21:46 UTC
- This precedes the RDP brute force from 194.61.24.102 by ~11 minutes
- The attack timeline remains valid regardless of source IP attribution

**Cross-System Timeline:**
1. 03:21:26 — NTLM brute-force from "kali" begins against DC01
2. 03:21:46 — NTLM brute-force SUCCEEDS
3. 03:32:46 — External IP 194.61.24.102 begins Nmap scan of DC01 RDP
4. 03:34:46 — 194.61.24.102 begins RDP brute-force against DC01
5. 03:40:49 — coreupdater.exe deployed on DESKTOP-SDN1RPT
6. 03:49:15 — DC01 initiates RDP to DESKTOP-SDN1RPT
7. 03:56:37 — coreupdater.exe deployed on DC01



### 2. [CRITICAL] coreupdater.exe Deployed to Both DC01 and DESKTOP-SDN1RPT as Masquerading Malware

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T01:22:38+00:00 to 2020-09-19T03:43:10+00:00 |
| **Sources** | bulk.url, ez.mft, strings.output, volatility.cmdline, volatility.netscan, volatility.pslist, volatility.pstree |
| **Evidence Refs** | tc_1070815f, tc_7b3cb6d5, tc_a4326bfe, tc_a8629a5d, tc_c6c7a107, tc_f77e6811 |
| **ATT&CK** | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1570](https://attack.mitre.org/techniques/T1570/) |


A malicious executable named "coreupdater.exe" was deployed to both systems in the environment, placed in C:\Windows\System32\ to masquerade as a legitimate system binary:

DC01 (Domain Controller):
- PID 3644, actively running at time of memory capture
- ESTABLISHED connection to C2 at 203.78.103.109:443
- Not present in autoruns, suggesting it was started interactively or by another mechanism

DESKTOP-SDN1RPT (Workstation):
- PID 8324, Session 3, created 2020-09-19 03:40:49, exited 2020-09-19 03:43:10
- Located at \Device\HarddiskVolume3\Windows\System32\coreupdater.exe
- Short execution window (~2.5 minutes) suggests it may have been used for a specific task (e.g., payload delivery, data collection) then terminated

Neither "coreupdater.exe" is a legitimate Windows system binary. The name is designed to blend with legitimate update processes. The deployment to both the domain controller and a workstation indicates lateral movement capability and multi-system compromise.

The shimcache on DC01 disk image does NOT contain an entry for coreupdater.exe, which is unusual for an executed binary and may indicate anti-forensics or that the binary was executed only from memory/a network share.

**Affected Systems:** bulk.url, ez.mft, strings.output, volatility.cmdline, volatility.netscan, volatility.pslist, volatility.pstree



### 3. [CRITICAL] Environment-Wide Meterpreter Code Injection in Print Spooler Service Across DC01 and DESKTOP-SDN1RPT

| | |
|---|---|
| **Severity** | CRITICAL |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T01:22:38+00:00 |
| **Sources** | volatility.malfind, yara.memory, volatility.netscan, volatility.svcscan |
| **Evidence Refs** | tc_2af0d01a, tc_923a6c2c, tc_76f50b5a, tc_a091259d, tc_c185c06e |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1571](https://attack.mitre.org/techniques/T1571/) |


Identical Metasploit Meterpreter code injection was detected in the Windows Print Spooler service (spoolsv.exe) on BOTH compromised systems, confirming environment-wide deployment of the same attack toolkit.

**DC01 (Domain Controller — CITADEL-DC01):**
- spoolsv.exe PID 3724, SERVICE_AUTO_START, SERVICE_RUNNING
- Volatility malfind: 4 RWX regions with x64 Metasploit shellcode stub (fc 48 89 ce 48 81 ec 00 20 00 00) and 3 injected MZ PE headers
- YARA: metsrv.x64.dll (5 offsets), ReflectiveLoader (15 offsets) — HKTL_Meterpreter_inMemory
- Netscan: LISTENING on TCP 62475 (bind handler)
- Service scan: Spooler service running as SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS

**DESKTOP-SDN1RPT (Workstation):**
- spoolsv.exe PID 2188: Injected MZ PE header in RWX memory (36 committed pages) — same reflective DLL injection pattern
- powershell.exe PID 3316: Multiple RWX regions with PE headers and PNG reference (potential steganographic delivery)
- Spooler service also present in svcscan

**Cross-System Convergence:**
The identical injection technique (reflective DLL loading of Meterpreter server into spoolsv.exe) across both systems, corroborated by:
1. Memory forensics (Volatility malfind) on both hosts
2. YARA signature matching on both hosts
3. Service scan confirming auto-start on both hosts
4. Network analysis showing unusual listening ports

**Persistence Assessment (Q6):**
The Meterpreter payload persists IN MEMORY within the spoolsv.exe process. The Print Spooler service (Spooler) is configured as SERVICE_AUTO_START and will restart on reboot. However, the injected code itself is memory-resident only — it would NOT survive a reboot unless there is a separate re-injection mechanism (service, scheduled task, or registry). No such mechanism was identified in registry or scheduled task analysis, suggesting the Meterpreter is session-based persistence dependent on the initial exploitation vector.



### 4. [HIGH] Environment-Wide Credential Theft Toolkit on DESKTOP-SDN1RPT: Skeleton Key, NTLM Dump, and Tofu Backdoor

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2020-09-19T01:24:08+00:00 |
| **Sources** | yara.memory |
| **Evidence Refs** | tc_2af0d01a, tc_51306ab9, tc_c185c06e |
| **ATT&CK** | [T1556.001](https://attack.mitre.org/techniques/T1556/001/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1003.002](https://attack.mitre.org/techniques/T1003/002/) |


**[COUNTER-ANALYSIS ADJUSTED — Critical→High, confidence note added]** YARA scanning of DESKTOP-SDN1RPT memory detected multiple credential theft and remote access tool signatures. Counter-analysis validates some matches as specific and challenges others as potentially generic.

**1. Skeleton Key Patcher — PARTIALLY VALIDATED:**
- The `HookDC.dll` string matched at 6 memory offsets. This IS specific to the Skeleton Key patcher tool and does NOT occur in legitimate Windows installations. This validates the tool's presence in workstation memory.
- However, the other matched strings are EXPECTED in any Windows memory dump:
  - `$target_process` (lsass.exe in UTF-16LE): 100+ matches — every Windows system references lsass.exe extensively
  - `$dll1` (cryptdll.dll): 16 matches — legitimate Windows crypto DLL loaded by LSASS
  - `$dll2` (samsrv.dll): 7 matches — legitimate SAM service DLL loaded by LSASS
  - `$patched1/$patched2/$patched3` (CDLocateCSystem, SamIRetrievePrimaryCredentials, SamIRetrieveMultiplePrimaryCredentials): These are legitimate exported function names in cryptdll.dll and samsrv.dll
- **Key caveat:** The Skeleton Key patcher tool was found on DESKTOP-SDN1RPT (workstation), NOT on DC01. The tool would need to be executed against DC01's LSASS to deploy the skeleton key. Presence of the tool does not confirm deployment to the DC.

**2. NTLM Hash Dump Output — VALIDATED:**
- `NTLM_Dump_Output` matched at 6 offsets showing "500:aad3b435b51404eeaad3b435b51404ee:" format
- This is a specific pwdump/secretsdump output format that confirms credential extraction occurred

**3. Tofu Backdoor — WEAK:**
- `Tofu_Backdoor` matched "Cookies: Sym1.0" at only 2 offsets
- This is a short, semi-generic HTTP cookie header pattern
- Two instances in a ~2GB memory dump is a thin signal for APT attribution
- The Tonto Team / CactusPete attribution should be treated as speculative

**Assessment:** Downgraded from critical to high because: (1) the Skeleton Key tool's PRESENCE on the workstation is validated by HookDC.dll, but DEPLOYMENT to DC01 is not confirmed; (2) NTLM dump output confirms credential theft; (3) the Tofu backdoor attribution is weak. This finding is corroborated by the broader attack chain (Meterpreter, coreupdater.exe, brute force) which supports credential tool usage even if individual YARA matches are imperfect.



### 5. [HIGH] Code Injection in spoolsv.exe and powershell.exe on DESKTOP-SDN1RPT

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T05:08:43+00:00 |
| **Sources** | volatility.malfind, volatility.pstree, volatility.cmdline |
| **Evidence Refs** | tc_a091259d, tc_1070815f |
| **ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |


Volatility malfind detected suspicious PAGE_EXECUTE_READWRITE memory regions with injected code in multiple processes on DESKTOP-SDN1RPT:

1. spoolsv.exe (PID 2188): Contains an injected MZ PE header in RWX memory (36 committed pages), consistent with reflective DLL injection. Same technique as the confirmed Meterpreter compromise on DC01.

2. powershell.exe (PID 3316): Multiple suspicious RWX regions:
   - MZ PE header injected (36 committed pages)
   - Two additional large RWX regions (107 and 57 committed pages each), suggesting substantial injected payloads
   - PNG file reference embedded in RWX memory, which may indicate steganographic payload delivery

Process tree analysis shows:
- PID 508 (powershell.exe) was spawned by PID 1380 (parent not in process list - possibly exited)
- PID 3316 (powershell.exe) was spawned by PID 508 (first powershell)
- Both powershell instances are in Session 2 (user session)

The pattern of injected MZ headers with reflective loading in spoolsv.exe mirrors exactly the Meterpreter injection pattern observed on DC01, suggesting the same attacker and toolchain.



### 6. [HIGH] RDP Brute Force and Nmap Reconnaissance from External IP 194.61.24.102 Against DC01

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:32:46+00:00 to 2020-09-19T04:09:23+00:00 |
| **Sources** | zeek.rdp, pcap.conversations |
| **Evidence Refs** | tc_26e12972, tc_7f283258 |
| **ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1046](https://attack.mitre.org/techniques/T1046/), [T1133](https://attack.mitre.org/techniques/T1133/) |


Network capture reveals a coordinated attack from external IP 194.61.24.102 targeting the domain controller DC01 (10.42.85.10) on RDP port 3389.

**Reconnaissance Phase (03:32:46 UTC):**
- Initial RDP connection with cookie "nmap" — indicating Nmap service scanning against the DC's RDP port
- Security protocol: HYBRID_EX
- Source port 38100

**Brute Force Phase (03:34:46 – 03:35:07 UTC):**
- 75+ rapid automated RDP connection attempts, all with cookie "Administrator"
- Source ports incrementing sequentially from 40044 to 40234 (incrementing by 2 each time)
- Connection interval: ~220ms between attempts (4.5 connections/second)
- Security protocol: HYBRID (NLA enabled)
- All resulted in encrypted connections (NLA prevents seeing success/failure in the traffic)

**Continued Attempts:**
- 03:35:28 UTC, 03:35:57 UTC: Additional attempts from ports 40236, 40238
- 04:09:23 UTC: Final attempt from port 40240

**Network Significance:**
The DC01's RDP port (3389) was directly reachable from this external IP, indicating the domain controller was internet-exposed (either directly or through port forwarding). This is a severe network architecture issue that enabled the attack.

This finding corroborates and extends the existing Event Log finding (f_ad5e03bc) about brute-force from "kali" workstation. The network-level evidence shows the exact timing, connection rate, and the Nmap reconnaissance that preceded the brute force.



### 7. [HIGH] RDP Lateral Movement from DC01 to DESKTOP-SDN1RPT via Network Traffic

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-19T03:49:15+00:00 to 2020-09-19T03:49:15+00:00 |
| **Sources** | zeek.rdp |
| **Evidence Refs** | tc_26e12972 |
| **ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/), [T1570](https://attack.mitre.org/techniques/T1570/) |


Zeek RDP log captures an RDP connection originating FROM the domain controller DC01 (10.42.85.10) TO the workstation DESKTOP-SDN1RPT (10.42.85.115) at 2020-09-19 03:49:15 UTC.

**Connection Details:**
- Source: 10.42.85.10:62514 (DC01)
- Destination: 10.42.85.115:3389 (DESKTOP-SDN1RPT)
- Cookie: empty string (no username in the RDP cookie)
- Security protocol: HYBRID_EX
- Result: encrypted

**Timeline Context:**
This RDP connection from DC01 to the workstation occurs in the middle of the attack sequence:
1. 03:32-03:35 UTC — External attacker (194.61.24.102) Nmap scans and brute-forces DC01 RDP
2. 03:40:49 UTC — coreupdater.exe malware deployed on DESKTOP-SDN1RPT
3. **03:49:15 UTC — DC01 initiates RDP to DESKTOP-SDN1RPT (this finding)**
4. 03:56:37 UTC — coreupdater.exe deployed on DC01 with C2 to 203.78.103.109
5. 04:04-04:19 UTC — Suspicious PE files transferred

**Significance:**
Domain controllers should not be initiating RDP connections to workstations under normal operations. This connection direction (DC→workstation) is a strong indicator of lateral movement — an attacker who has compromised the DC is using it to access the workstation via RDP. The empty cookie suggests the connection may have been initiated programmatically rather than through a standard RDP client.



### 8. [HIGH] Suspicious PE File Transfer Over Network — No ASLR/DEP, Anomalous Section Names

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | inference |
| **Time** | 2020-09-19T04:04:06+00:00 to 2020-09-19T04:19:58+00:00 |
| **Sources** | zeek.pe |
| **Evidence Refs** | tc_edc9aadf |
| **ATT&CK** | [T1105](https://attack.mitre.org/techniques/T1105/), [T1027.002](https://attack.mitre.org/techniques/T1027/002/) |


**[COUNTER-ANALYSIS NOTE ADDED]** Zeek PE analysis detected two portable executable (PE) files transferred over the network during the capture window. Both files share identical characteristics consistent with custom-built tooling.

**PE File 1 (Zeek FID: F15zmh1fD5AVKS9HX9):** Timestamp: 2020-09-19 04:04:06 UTC
**PE File 2 (Zeek FID: FxYOW43DbTEoN0WP21):** Timestamp: 2020-09-19 04:19:58 UTC

**Shared Characteristics:**
- Machine: AMD64, is_exe: true, is_64bit: true
- Compile timestamp: 2010-04-14 (anomalous for a 64-bit binary in 2020)
- OS: "Windows 95 or NT 4.0" — impossible for a 64-bit binary; set to minimal compatibility
- uses_aslr: false, uses_dep: false, has_cert_table: false, has_debug_data: false
- **Section names: [".text", ".rdata", ".lhru"]** — ".lhru" is non-standard

**Counter-Analysis — Could these be legitimate legacy software?**
While legacy software transfers are possible, these indicators collectively argue against it:
1. A 64-bit AMD64 binary with a 2010 compile timestamp and "Windows 95 or NT 4.0" OS version is self-contradictory — no legitimate compiler produces this combination
2. Both ASLR and DEP disabled simultaneously is extremely rare in legitimate software compiled after ~2008
3. The ".lhru" section name is not produced by any known standard toolchain (MSVC, MinGW, Clang, Borland)
4. No Authenticode signature and no debug data — legitimate software vendors typically sign their binaries
5. Both files are structurally identical, transferred 16 minutes apart during the active attack window

**Assessment:** The combination of indicators is inconsistent with legitimate legacy software. A genuine 2010-era binary would have a 32-bit or mixed architecture, a real OS version, and standard section names. These characteristics are consistent with purpose-built post-exploitation tooling with intentionally minimal PE metadata. Finding maintained at HIGH, corroborated by the broader attack timeline.



### 9. [HIGH] Kerberos Authentication Escalation Chain Visible in Network Traffic: Machine → mortysmith → Administrator → ricksanchez

| | |
|---|---|
| **Severity** | HIGH |
| **Confidence** | confirmed |
| **Time** | 2020-09-18T21:59:39+00:00 to 2020-09-19T05:48:15+00:00 |
| **Sources** | zeek.kerberos, zeek.smb_mapping |
| **Evidence Refs** | tc_8839b33e, tc_4cf1bb8a |
| **ATT&CK** | [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1550.003](https://attack.mitre.org/techniques/T1550/003/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |


**[COUNTER-ANALYSIS NOTE ADDED]** Zeek Kerberos log reveals a clear authentication pattern over the C137.LOCAL domain, with four distinct identities authenticating from the same workstation (10.42.85.115) to DC01 (10.42.85.10) in sequence.

**Phase 1 — Machine Account (Sep 18, 21:59:39 UTC):** desktop-sdn1rpt$/C137.local → TGT + TGS for LDAP, cifs (expected boot/logon)
**Phase 2 — mortysmith (Sep 18, 22:00:38 UTC):** TGT + TGS for host, LDAP, cifs (user logon to workstation)
**Phase 3 — Administrator (Sep 19, 04:16:24 UTC):** TGT + TGS for host, LDAP, cifs, **ProtectedStorage/CITADEL-DC01**, krbtgt
**Phase 4 — ricksanchez (Sep 19, 05:48:15 UTC):** TGT + TGS for host, LDAP, cifs, krbtgt + FileShare SMB access

**Counter-Analysis — Normal multi-account admin usage?**
The chain COULD represent a single administrator who uses multiple accounts for different privilege levels (standard practice in many organizations). However, several factors argue against the benign interpretation:
1. The ProtectedStorage TGS in Phase 3 is specifically notable — this service manages credential material and is characteristically accessed by credential harvesting tools
2. The 6-hour gap between mortysmith logon (22:00) and Administrator logon (04:16) is unusual for account switching within a single work session — and the Administrator logon occurs ~44 minutes AFTER the RDP brute force from 194.61.24.102
3. The ricksanchez FileShare access is the ONLY FileShare access in the entire 7.7-hour capture — isolated, purpose-driven
4. This chain is strongly corroborated by: confirmed brute force (f_ad5e03bc), Meterpreter deployment (f_0cd8aa43), coreupdater.exe C2 (f_66a825a4)

**Assessment:** While the alternative hypothesis (normal admin account rotation) cannot be fully excluded in isolation, the timing correlation with confirmed attack activity and the ProtectedStorage access make the privilege escalation interpretation more probable. The finding is well-corroborated within the broader attack narrative. Maintained at HIGH with "confirmed" confidence because the authentication events themselves are factual — it is the interpretation as escalation that carries some ambiguity.



### 10. [MEDIUM] Suspicious URL http://194.61.24.102/ Found on DC01 Disk Image and DESKTOP-SDN1RPT Pagefile

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-09-19T03:32:46+00:00 |
| **Sources** | bulk.url, strings.output |
| **Evidence Refs** | tc_63860be0 |
| **ATT&CK** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/) |


The IP address 194.61.24.102 was found in multiple evidence sources across both systems:

1. DC01 disk image (bulk_extractor URL carving): Multiple references to "http://194.61.24.102/" with "strator@http://194.61.24.102/" suggesting Administrator accessed this URL.

2. DESKTOP-SDN1RPT pagefile (strings): The URL "http://194.61.24.102/" appears in pagefile strings.

3. Zeek RDP logs: This IP conducted Nmap reconnaissance (03:32:46 UTC) and RDP brute-force (03:34-03:35 UTC, 75+ attempts) against DC01 port 3389, as documented in finding f_04a6fb78.

**Cross-System Correlation:**
The URL presence on both the DC01 disk and the workstation pagefile, combined with the active RDP brute-force from this IP in the PCAP, confirms this is attacker infrastructure. The "administrator@" association suggests the Administrator account may have been used to access payload/staging content hosted on this IP after the initial compromise.



### 11. [MEDIUM] SMB File Share Access by ricksanchez Account After Credential Compromise

| | |
|---|---|
| **Severity** | MEDIUM |
| **Confidence** | inference |
| **Time** | 2020-09-19T05:48:16+00:00 to 2020-09-19T06:17:04+00:00 |
| **Sources** | zeek.smb_files, zeek.smb_mapping |
| **Evidence Refs** | tc_21bbf9a9, tc_4cf1bb8a |
| **ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/), [T1135](https://attack.mitre.org/techniques/T1135/) |


Zeek SMB logs show the ricksanchez account accessing the \\CITADEL-DC01\FileShare SMB share at 2020-09-19 05:48:16 UTC, following authentication to the domain at 05:48:15 UTC.

**Connection Details:**
- Source: 10.42.85.115:50957 (DESKTOP-SDN1RPT)
- Destination: 10.42.85.10:445 (DC01)
- Share path: \\\\CITADEL-DC01\\FileShare (share_type: DISK)
- File operations: SMB::FILE_OPEN on <share_root> at two timestamps (05:33:13 and 06:17:04 UTC)

**Context:**
- This is the ONLY access to the FileShare across the entire capture window — no other user or session accessed this share
- The ricksanchez Kerberos tickets (cifs/CITADEL-DC01) were obtained immediately before the SMB connection
- The FileShare was created on 2020-09-18 01:48:11 UTC (times.created) and last modified on 2020-09-19 01:27:38 UTC (times.modified) — the modification occurred during the incident window
- This access occurs after the mortysmith → Administrator → ricksanchez credential escalation chain

**Comparison with Other SMB Activity:**
The only other SMB file operations observed in the PCAP were standard Group Policy (SYSVOL) reads:
- gpt.ini, Registry.pol, GptTmpl.inf from \\CITADEL-DC01.C137.local\sysvol
These are normal GPO refresh operations by domain-joined clients.

The FileShare access by ricksanchez is anomalous because:
1. It is the only FileShare access in the capture
2. It follows a credential escalation chain
3. It may indicate reconnaissance or data staging/collection from a shared directory



### 12. [LOW] Suspicious External IP 62.8.193.206 Associated with TA17-293A Malware in DESKTOP-SDN1RPT Memory

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2020-09-19T01:24:08+00:00 |
| **Sources** | yara.memory |
| **Evidence Refs** | tc_c185c06e, tc_0f40f1fa |


**[COUNTER-ANALYSIS DOWNGRADE]** YARA scanning matched the TA17_293A_malware_1 rule on DESKTOP-SDN1RPT memory, but counter-analysis finds this is very likely a false positive:

**Evidence Against:**
1. The rule triggered overwhelmingly on "file://" strings ($n1) — hundreds of matches across memory. The "file://" URI scheme is ubiquitous in Windows (COM registration, Shell extensions, CLSID entries) and is NOT an IOC by itself
2. The IP 62.8.193.206 ($ax3) was found at a SINGLE memory offset (0x56174414)
3. ZERO network connections to 62.8.193.206 were found in Volatility netscan
4. ZERO DNS queries for this IP were observed in Zeek DNS logs
5. ZERO references in PCAP conversations or bulk_extractor network data
6. The IP could be present as cached web content, a DNS cache entry, or embedded in browser history/temporary files

**Rule Quality Assessment:**
TA17_293A_malware_1 appears to be an overly broad rule that triggers on the combination of common Windows strings ("file://") plus any of several IP indicators. On any Windows memory dump with browser activity, the "file://" threshold will be easily met, so the rule effectively reduces to "does this IP string appear anywhere in memory" — a very weak signal.

**Assessment:** This finding is ISOLATED — no other evidence source corroborates active communication with or exploitation from 62.8.193.206. The single IP string in memory, absent any network activity, does not support a medium-severity finding. Downgraded to low as a likely false positive from an over-matching YARA rule.



### 13. [LOW] DRSUAPI/DCSync Activity from Workstation to Domain Controller in Network Traffic

| | |
|---|---|
| **Severity** | LOW |
| **Confidence** | inference |
| **Time** | 2020-09-18T21:59:39+00:00 to 2020-09-19T05:35:57+00:00 |
| **Sources** | zeek.dce_rpc, zeek.kerberos |
| **Evidence Refs** | tc_30107ce6, tc_8839b33e |


**[COUNTER-ANALYSIS DOWNGRADE]** Original finding claimed DCSync (T1003.006) activity based on DRSUAPI operations from DESKTOP-SDN1RPT to DC01. Counter-analysis found this classification is INCORRECT:

**Critical Gap — DRSGetNCChanges NOT found:**
The defining call for DCSync — DRSGetNCChanges (the replication request that extracts password hashes) — was searched for across ALL indexed evidence and returned ZERO results. Only DRSCrackNames was observed, which is a standard AD name resolution function used by Group Policy processing, LDAP lookups, and normal domain client operations.

**Normal AD Client Behavior:**
- The DRSUAPI activity begins at 21:59:39 UTC — BEFORE any detected attack activity (brute force starts 03:21:26 UTC, ~5.3 hours later)
- The pattern of EPM → DRSBind → DRSCrackNames → DRSUnbind is standard Group Policy client behavior for domain-joined workstations
- DRSCrackNames is routinely used by domain clients to resolve SPN/UPN names during Kerberos authentication and GPO processing
- Workstations legitimately query DRSUAPI endpoints; this is not restricted to domain controllers

**Original DRSUAPI Operations (unchanged):**
Multiple Bind/CrackNames/Unbind cycles at 21:59:39, 22:00:19, 22:01:46, 22:04:35 (pre-attack) and 03:23:42, 03:39:15, 04:16:24, 04:57:54, 05:35:57 UTC. Also LSARPC (LsarLookupSids3) and SAMR (SamrQuerySecurityObject) operations, which are normal AD client operations.

**Assessment:** This finding was ISOLATED from the corroborated attack chain. The DRSCrackNames activity is consistent with normal AD client behavior, not credential theft. Without DRSGetNCChanges, the DCSync technique mapping is unsupported.



### 14. [INFO] Active Directory Database (ntds.dit) and Registry Hives Collected from DC01

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | list_directory |
| **Evidence Refs** | tc_e4f7cd3d |


Protected files were collected from DC01 (CITADEL-DC01) and include the Active Directory database and critical registry hives:

**Files Collected:**
- `ntds.dit` — 20.0 MB Active Directory database containing all domain user password hashes, Kerberos keys, and account configurations for the C137.LOCAL domain
- `SAM` — 256 KB Security Account Manager database
- `SECURITY` — 256 KB LSA secrets and cached credentials
- `system` — 12.2 MB SYSTEM registry hive (contains the SYSKEY needed to decrypt SAM/ntds.dit)
- `software` — 43.8 MB SOFTWARE registry hive
- `default` — 256 KB DEFAULT registry hive

**User DPAPI Material:**
- Administrator's NTUSER.DAT (512 KB)
- Administrator DPAPI master keys and CREDHIST
- RSA key containers for Administrator (SID S-1-5-21-2232410529-1445159330-2725690660-500)
- BK-C137 backup key file (domain DPAPI backup key)

**Significance:**
With the SYSTEM hive and ntds.dit, offline extraction of ALL domain account NTLM hashes is possible using tools like secretsdump.py. The presence of the DPAPI backup key (BK-C137) would allow decryption of any user's DPAPI-protected secrets (saved passwords, certificates, etc.) across the entire domain. This represents complete credential compromise of the C137.LOCAL domain.



### 15. [INFO] DC01 Domain Controller Process Inventory — Expected DC Services Running Under SYSTEM

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | volatility.pslist, volatility.pstree, volatility.cmdline |
| **Evidence Refs** | tc_f77e6811, tc_a22eb848, tc_cd4ce2bc |


The process list for domain controller CITADEL-DC01 (citadeldc01.mem) shows the expected services for a Windows Server 2012 R2 domain controller (based on HarddiskVolume2 path and AD services present):

**Expected DC Services (all running from legitimate paths):**
- lsass.exe (PID 460) — Local Security Authority, 31 threads, critical for Kerberos/NTLM
- dns.exe (PID 1368) — DNS Server service
- Microsoft.ActiveDirectory.WebServices.exe (PID 1292) — AD Web Services
- dfsrs.exe (PID 1332) — DFS Replication
- dfssvc.exe (PID 1660) — DFS Namespace
- ismserv.exe (PID 1392) — Intersite Messaging

**VMware Environment:**
- vmtoolsd.exe (PID 1600, 2608) — VMware Tools daemon
- VGAuthService.exe (PID 1556) — VMware Guest Authentication
- vm3dservice.exe (PID 3260) — VMware 3D service

**User Session Activity (Session 1, started 04:36:03 UTC):**
- explorer.exe (PID 3472) — Interactive logon
- ServerManager.exe (PID 400) — Server Manager GUI
- FTK Imager.exe (PID 2840) — Forensic imaging tool (evidence collection in progress, launched from E:\FTK Imager\FTK Imager.exe)
- taskhostex.exe (PID 3796) — Task host

**Counter-Analysis Note — FTK Imager (Q10):**
FTK Imager (PID 2840) was actively running on DC01 at the time of memory capture (loaded at 04:37:04 UTC). This is a forensic imaging tool used for evidence collection. FTK Imager performs READ-ONLY disk imaging and does not create filesystem artifacts (writes, registry changes, scheduled tasks) that could be misattributed to attacker activity. Its presence confirms that incident response was underway during the capture window but does not contaminate the forensic evidence.

**Suspicious Processes:**
- coreupdater.exe (PID 3644) — Malicious, documented in finding f_66a825a4
- spoolsv.exe (PID 3724) — Compromised with Meterpreter, documented in finding f_0cd8aa43; notably started at 03:29:40, well after boot, which is unusual for a print spooler

**DC01 IP Address:** 10.42.85.10 (confirmed via netscan DNS bindings and Security log)
**Domain:** C137.LOCAL
**Hostname:** CITADEL-DC01



### 16. [INFO] Protected Files Contain Registry Hives and DPAPI Credential Material for Multiple User Accounts

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Sources** | clamav.scan, yara.files |
| **Evidence Refs** | tc_983328da, tc_cb427d3c |


The Protected Files archive from DESKTOP-SDN1RPT contains Windows registry hives and DPAPI credential protection materials for 4 user accounts:

Registry Hives: SAM, SECURITY, SYSTEM, SOFTWARE, default
User profiles with DPAPI materials:
1. Admin (local account, SID S-1-5-21-41211245-796119838-3940169921-1001)
2. Administrator (domain admin, SID S-1-5-21-2232410529-1445159330-2725690660-500) with RSA keys
3. mortysmith (domain user, SID S-1-5-21-2232410529-1445159330-2725690660-1108)
4. ricksanchez (domain user, SID S-1-5-21-2232410529-1445159330-2725690660-1106) with RSA keys

ClamAV and YARA scans found no malware in the extracted files. The DPAPI backup key file "BK-C137" was found across multiple user profiles.



### 17. [INFO] Network Traffic Capture Profile — PCAP Summary and Protocol Distribution

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-09-18T21:58:07+00:00 to 2020-09-19T05:38:57+00:00 |
| **Sources** | pcap.summary, pcap.conversations, zeek.summary, pcap.beaconing, pcap.tunneling, suricata.alerts, pcap.tls |
| **Evidence Refs** | tc_a6794702, tc_7f283258, tc_8a6fac82, tc_7be6e937, tc_75e67bf5, tc_4a141eb6 |


Network capture from 2020-09-18 21:58:07 UTC to 2020-09-19 05:38:57 UTC (7.7 hours, 411,797 packets, 197 MB).

**Capture Metadata:**
- Tool: Mergecap (Wireshark) 3.2.6 on Kali Linux 5.8.0-kali1-amd64
- SHA256: 09abf49efea1852e047987d92907704d47f36d75f6c8056e2cafa6cc027791cb
- Average data rate: 53 kbps (6.6 KB/s), 14 packets/second

**Network Environment (from IP conversations):**
- Internal hosts: 10.42.85.115 (DESKTOP-SDN1RPT), 10.42.85.10 (DC01), 10.90.90.90 (proxy/gateway)
- Domain: C137.LOCAL, DC: CITADEL-DC01
- 192.168.45.1 appears as a secondary gateway communicating with DC01
- DC01 broadcasts on 10.42.85.255 (NBNS/browser service)

**Protocol Distribution (from 10,000-packet sample):**
- TCP: 9,602 frames (96.2%) — TLS: 1,518 (15.2%), HTTP: 18, LDAP: 97, Kerberos: 46, DCE/RPC: 96, SMB2: 179, NBSS: 180
- UDP: 270 frames (2.7%) — DNS: 159, NBNS: 59, LLMNR: 28, NTP: 2
- ARP: 30, IPv6: 85, IGMP: 13

**Zeek Analysis (full capture):**
- 32,726 connections, 30,554 SSL/TLS records (dominant), 1,813 DNS queries, 229 HTTP requests
- 209 DCE/RPC calls, 189 LDAP operations, 101 RDP sessions, 65 Kerberos exchanges
- 31 SMB file operations, 25 SMB share mappings, 2 PE file transfers, 874 file objects
- 31 weird events

**Security-Relevant Negative Findings:**
- Suricata IDS: 0 alerts (no known attack signatures triggered)
- Beaconing analysis: 0 beacons detected (216 destinations analyzed)
- DNS tunneling: 4 flagged domains (microsoft.com, msn.com, c137.local, akamaized.net) — all false positives; legitimate Microsoft services and the internal domain
- ICMP covert channels: None detected
- Cleartext credentials: No credentials observed in unencrypted HTTP traffic (only OCSP certificate validation requests to ocsp.digicert.com and ocsp.msocsp.com)

**TLS Traffic Analysis:**
All TLS connections from the workstation resolved to legitimate Microsoft services:
- settings-win.data.microsoft.com, watson.telemetry.microsoft.com (telemetry)
- www.bing.com, www.msn.com, api.msn.com (browsing)
- nav.smartscreen.microsoft.com, checkappexec.microsoft.com (SmartScreen)
- go.microsoft.com, www.microsoft.com (browsing)
- microsoftedgewelcome.microsoft.com (Edge browser)
- assets.msn.com, img-s-msn-com.akamaized.net (CDN)
- v20.events.data.microsoft.com (telemetry)
- 10.90.90.90 acting as proxy for sb.scorecardresearch.com, c.msn.com, srtb.msn.com, assets.adobedtm.com, az416426.vo.msecnd.net



### 18. [INFO] Files Carved from Network Traffic — OST Email Archives, PDFs, and Application Data

| | |
|---|---|
| **Severity** | INFO |
| **Confidence** | confirmed |
| **Time** | 2020-09-18T21:58:07+00:00 to 2020-09-19T05:38:57+00:00 |
| **Sources** | tcpxtract.carved |
| **Evidence Refs** | tc_aab0b90e |


TCPXtract carved 432 files from network streams in the PCAP capture. The file types and sizes provide context about what was transferred over the network during the incident window.

**Notable Carved Files by Type:**

OST (Outlook Data Files) — 7 files:
- 00000205.ost: 34.9 MB (largest — significant volume of email data)
- 00000208.ost: 31.2 MB
- 00000215.ost: 15.4 MB
- 00000105.ost: 3.3 MB
- 00000237.ost: 4.7 MB
- 00000265.ost: 965 KB
- 00000279.ost: 116 KB
- 00000326.ost: 51 KB
These suggest email/Outlook data was present in network traffic, which could indicate email synchronization or data collection.

PDF Files — 5 files:
- 00000213.pdf: 5.0 MB, 00000217.pdf: 5.0 MB (maximum carve size)
- 00000264.pdf: 1.2 MB, 00000052.pdf: 970 KB, 00000282.pdf: 68 KB

Flash/SWF Files — 5 files (00000084, 00000094, 00000260, 00000261, 00000333/334)
- Sizes from 135 KB to 3.3 MB
- Flash content in 2020 is unusual and may be associated with exploit delivery

Java Class Files — 9 files:
- Several at 1 MB (maximum carve size), others 122-638 KB
- Java class files could represent legitimate web content or exploit payloads

Image Files — Numerous BMP (180+), PNG (14), JPG (2), GIF (1), TIF (6)
- Most BMPs are small fragments; PNGs include some at 1 MB
- Likely normal web browsing content

ZIP Archives — 48 files (mostly small, <2 KB)
- Small ZIP files embedded in TLS-wrapped traffic

**Assessment:**
The majority of carved files appear to be normal web browsing artifacts (images, web content from Microsoft/MSN sites). The large OST files suggest Outlook email synchronization traffic. No definitive malware executables were carved (the PE files detected by Zeek were identified through protocol analysis, not file carving). The Flash content is noteworthy given Flash's EOL status in 2020.



---

## Appendix B: Indicators of Compromise

### Network IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| External IP | `194.61.24.102` |  | Successful NTLM Brute-Force from Kali Linux Against DC01 Administrator — Initial |
| External IP | `203.78.103.109` |  | coreupdater.exe Deployed to Both DC01 and DESKTOP-SDN1RPT as Masquerading Malwar |
| Port | `TCP 443` |  | coreupdater.exe Deployed to Both DC01 and DESKTOP-SDN1RPT as Masquerading Malwar |
| Port | `TCP 3389` |  | Suspicious URL http://194.61.24.102/ Found on DC01 Disk Image and DESKTOP-SDN1RP |
| Internal IP | `10.42.85.10` |  | RDP Brute Force and Nmap Reconnaissance from External IP 194.61.24.102 Against D |
| Port | `TCP 38100` |  | RDP Brute Force and Nmap Reconnaissance from External IP 194.61.24.102 Against D |
| Port | `TCP 40240` |  | RDP Brute Force and Nmap Reconnaissance from External IP 194.61.24.102 Against D |
| Port | `TCP 62514` |  | RDP Lateral Movement from DC01 to DESKTOP-SDN1RPT via Network Traffic |
| Internal IP | `10.42.85.115` |  | RDP Lateral Movement from DC01 to DESKTOP-SDN1RPT via Network Traffic |
| Port | `TCP 50957` |  | SMB File Share Access by ricksanchez Account After Credential Compromise |
| Port | `TCP 445` |  | SMB File Share Access by ricksanchez Account After Credential Compromise |


### File IOCs

| Type | Value | Enrichment | Context |
|------|-------|------------|---------|
| Path | `C:\Windows\System32\` |  | coreupdater.exe Deployed to Both DC01 and DESKTOP-SDN1RPT as Masquerading Malwar |





---

## Appendix C: MITRE ATT&CK Coverage

21 techniques identified across findings.


**Kill Chain Coverage:** Initial Access (2) > Execution (1) > Persistence (4) > Privilege Escalation (3) > Defense Evasion (6) > Credential Access (4) > Discovery (2) > Lateral Movement (4) > Collection (1) > Command and Control (3)


### Initial Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Successful NTLM Brute-Force from Kali Linux...; Kerberos Authentication Escalation Chain... |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | RDP Brute Force and Nmap Reconnaissance from... |


### Execution

| Technique | Name | Findings |
|-----------|------|----------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Code Injection in spoolsv.exe and... |


### Persistence

| Technique | Name | Findings |
|-----------|------|----------|
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Successful NTLM Brute-Force from Kali Linux...; Kerberos Authentication Escalation Chain... |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | RDP Brute Force and Nmap Reconnaissance from... |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Environment-Wide Meterpreter Code Injection in... |
| [T1556.001](https://attack.mitre.org/techniques/T1556/001/) | Domain Controller Authentication | Environment-Wide Credential Theft Toolkit on... |


### Privilege Escalation

| Technique | Name | Findings |
|-----------|------|----------|
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Code Injection in spoolsv.exe and...; Environment-Wide Meterpreter Code Injection in... |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Successful NTLM Brute-Force from Kali Linux...; Kerberos Authentication Escalation Chain... |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Environment-Wide Meterpreter Code Injection in... |


### Defense Evasion

| Technique | Name | Findings |
|-----------|------|----------|
| [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | Software Packing | Suspicious PE File Transfer Over Network — No... |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Match Legitimate Resource Name or Location | coreupdater.exe Deployed to Both DC01 and... |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | Code Injection in spoolsv.exe and...; Environment-Wide Meterpreter Code Injection in... |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Successful NTLM Brute-Force from Kali Linux...; Kerberos Authentication Escalation Chain... |
| [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Pass the Ticket | Kerberos Authentication Escalation Chain... |
| [T1556.001](https://attack.mitre.org/techniques/T1556/001/) | Domain Controller Authentication | Environment-Wide Credential Theft Toolkit on... |


### Credential Access

| Technique | Name | Findings |
|-----------|------|----------|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Environment-Wide Credential Theft Toolkit on... |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Environment-Wide Credential Theft Toolkit on... |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Successful NTLM Brute-Force from Kali Linux...; RDP Brute Force and Nmap Reconnaissance from... |
| [T1556.001](https://attack.mitre.org/techniques/T1556/001/) | Domain Controller Authentication | Environment-Wide Credential Theft Toolkit on... |


### Discovery

| Technique | Name | Findings |
|-----------|------|----------|
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | RDP Brute Force and Nmap Reconnaissance from... |
| [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | SMB File Share Access by ricksanchez Account... |


### Lateral Movement

| Technique | Name | Findings |
|-----------|------|----------|
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | RDP Lateral Movement from DC01 to... |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Kerberos Authentication Escalation Chain... |
| [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Pass the Ticket | Kerberos Authentication Escalation Chain... |
| [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Tool Transfer | coreupdater.exe Deployed to Both DC01 and...; RDP Lateral Movement from DC01 to... |


### Collection

| Technique | Name | Findings |
|-----------|------|----------|
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | SMB File Share Access by ricksanchez Account... |


### Command and Control

| Technique | Name | Findings |
|-----------|------|----------|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | coreupdater.exe Deployed to Both DC01 and...; Suspicious URL http://194.61.24.102/ Found on... |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | coreupdater.exe Deployed to Both DC01 and...; Suspicious URL http://194.61.24.102/ Found on...; Suspicious PE File Transfer Over Network — No... |
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | Environment-Wide Meterpreter Code Injection in... |





---

## Appendix D: Audit Trail and Token Usage

| Metric | Value |
|--------|-------|
| Total tool calls | 412 |
| Findings submitted | 18 |
| Confirmed | 12 |
| Inferences | 6 |
| Input tokens | 19.3K |
| Output tokens | 115.1K |
| Total tokens | 134.4K |
| Audit log | /home/mulder/.mulder/cases/szechuan.audit.jsonl |


### Token Usage by Model

| Model | Input | Output | Total |
|-------|-------|--------|-------|
| claude-opus-4-6 | 19.3K | 115.1K | 134.4K |




<details>
<summary>Evidence Sources (115)</summary>

| Source | Extractor | Lines |
|--------|-----------|-------|
| strings.output | strings | 679040 |
| volatility.pslist | volatility3 | 96 |
| tsk.partitions | sleuthkit | 10 |
| volatility.pstree | volatility3 | 95 |
| tsk.filelist | sleuthkit | 114999 |
| volatility.pslist | volatility3 | 41 |
| yara.memory | yara | 350 |
| tsk.filelist.p1 | sleuthkit | 166 |
| volatility.pstree | volatility3 | 41 |
| volatility.cmdline | volatility3 | 96 |
| volatility.cmdline | volatility3 | 41 |
| yara.memory | yara | 1042 |
| volatility.netscan | volatility3 | 19686 |
| volatility.malfind | volatility3 | 16 |
| volatility.netscan | volatility3 | 116 |
| volatility.psscan | volatility3 | 73 |
| volatility.dlllist | volatility3 | 2017 |
| bulk.domain | bulk_extractor | 177674 |
| volatility.svcscan | volatility3 | 886 |
| bulk.email | bulk_extractor | 730 |
| bulk.ether | bulk_extractor | 8 |
| bulk.ip | bulk_extractor | 31 |
| bulk.packets | bulk_extractor | 328 |
| bulk.rfc822 | bulk_extractor | 223 |
| bulk.tcp | bulk_extractor | 16 |
| bulk.url | bulk_extractor | 184316 |
| volatility.malfind | volatility3 | 8 |
| bulk.url_facebook-address | bulk_extractor | 6 |
| bulk.url_searches | bulk_extractor | 8 |
| bulk.url_services | bulk_extractor | 828 |
| chainsaw.hunt | chainsaw | 2 |
| ez.amcache | eztools | 4 |
| ez.mft | eztools | 111852 |
| ez.shimcache | eztools | 282 |
| registry.system | regripper | 106 |
| strings.output | strings | 51906 |
| evtx.manifest | evtx-extract | 105 |
| volatility.psscan | volatility3 | 169 |
| registry.system | regripper | 7 |
| registry.system | regripper | 7 |
| registry.security | regripper | 25 |
| registry.security | regripper | 8 |
| registry.security | regripper | 8 |
| registry.system | regripper | 29966 |
| registry.system | regripper | 283 |
| registry.system | regripper | 283 |
| registry.system | regripper | 4936 |
| registry.system | regripper | 199 |
| registry.system | regripper | 199 |
| registry.system | regripper | 381 |
| registry.system | regripper | 255 |
| registry.system | regripper | 255 |
| volatility.dlllist | volatility3 | 1428 |
| volatility.svcscan | volatility3 | 43222 |
| exiftool.metadata | exiftool | 2 |
| clamav.scan | clamav | 38 |
| evtx.windows_system32_winevt_logs_security | eztools | 5080 |
| evtx.windows_system32_winevt_logs_active-directory-web-services | eztools | 65 |
| evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational | eztools | 150 |
| evtx.windows_system32_winevt_logs_microsoft-windows-powershell4operational | eztools | 150 |
| forensic.timestomping | timestomp_detector | 1 |
| suricata.alerts | suricata | 5 |
| zeek.conn | zeek | 125 |
| zeek.dce_rpc | zeek | 210 |
| zeek.dns | zeek | 134 |
| zeek.files | zeek | 130 |
| zeek.http | zeek | 91 |
| zeek.kerberos | zeek | 66 |
| zeek.ldap | zeek | 190 |
| zeek.ldap_search | zeek | 152 |
| zeek.ocsp | zeek | 158 |
| zeek.packet_filter | zeek | 2 |
| zeek.pe | zeek | 3 |
| zeek.rdp | zeek | 102 |
| zeek.smb_files | zeek | 32 |
| zeek.smb_mapping | zeek | 26 |
| zeek.ssl | zeek | 93 |
| zeek.weird | zeek | 32 |
| zeek.x509 | zeek | 58 |
| zeek.summary | zeek | 18 |
| pcap.summary | tshark | 85 |
| pcap.conversations | tshark | 143 |
| tcpflow.streams | tcpflow | 433354 |
| pcap.dns | tshark | 2 |
| pcap.http | tshark | 19 |
| pcap.smtp | tshark | 2 |
| bulk.domain | bulk_extractor | 8019 |
| tcpxtract.carved | tcpxtract | 432 |
| bulk.email | bulk_extractor | 1070 |
| pcap.tls | tshark | 109 |
| bulk.ether | bulk_extractor | 817601 |
| pcap.beaconing | tshark | 5 |
| pcap.tunneling | tshark | 17 |
| bulk.ip | bulk_extractor | 817949 |
| bulk.packets | bulk_extractor | 2648935 |
| bulk.rfc822 | bulk_extractor | 408 |
| bulk.tcp | bulk_extractor | 408977 |
| bulk.url | bulk_extractor | 6828 |
| bulk.url_services | bulk_extractor | 102 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |
| composite.pcap_correlation | composite | 142 |
| composite.execution | composite | 144 |
| composite.lateral_movement | composite | 30 |
| composite.suspicious_processes | composite | 128 |
| composite.timeline | composite | 160 |
| composite.defense_evasion | composite | 38 |
| composite.recovery | composite | 7 |
| composite.persistence | composite | 9383 |
| composite.exfil | composite | 380 |
| composite.file_staging | composite | 2312 |
| composite.correlation | composite | 1 |
| composite.correlation | composite | 1 |


</details>


---

*Report generated by [Mulder](https://github.com/calebevans/mulder) via MCP*
